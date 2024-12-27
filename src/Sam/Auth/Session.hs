{- |
Module                  : Sam.Auth.Session
Copyright               : (c) 2024-2025 Samuel Evans-Powell
SPDX-License-Identifier : MPL-2.0
Maintainer              : Samuel Evans-Powell <mail@sevanspowell.net>
Stability               : experimental
-}

module Sam.Auth.Session where

import Chronos (Time)
import Control.Monad.IO.Class (MonadIO)
import Control.Monad.Reader (ReaderT)
import Data.Maybe (fromJust, fromMaybe)
import Database.Esqueleto.Experimental ((=.), (==.), (^.))
import Database.Persist.Sql (SqlBackend)
import Sam.Auth.JWT.Types (UserClaims(..), userClaimsSub, userClaimsEmail, userClaimsName, userClaimsEmailVerified)
import Sam.Auth.Session.Types (sessionTimeoutIdle, SessionConfig (..), SessionStore (..), Anonymous (..), Authenticated (Authenticated), SessionData (..), NewSession (..), SessionId (SessionId), SessionResult (..), Session (..), EndSession (..), authUserClaims, GetSession (..), isExpired, getSessionData)
import Sam.Util.URI (parseURI, uriToStr)
import qualified Chronos
import qualified Data.Aeson as Aeson
import qualified Data.ByteString.Lazy as BSL
import qualified Data.Text.Encoding as T
import qualified Database.Esqueleto.Experimental as Db
import qualified Database.Persist.Class as P
import qualified Debug.Trace as Debug
import qualified Sam.Auth.Database.Schema as Db
import qualified Torsor

mkSessionStoreDb
  :: MonadIO m
  => SessionStore (ReaderT SqlBackend m) Anonymous Authenticated
mkSessionStoreDb =
  SessionStore { newSession = newSessionDb
               , authenticateSession = authenticateSessionDb
               , getSession = getSessionDb
               , endSession = endSessionDb
               }

newSessionDb
  :: MonadIO m
  => SessionConfig
  -> NewSession Anonymous
  -> ReaderT SqlBackend m (Maybe (SessionData Anonymous))
newSessionDb cfg ns = do
  let
    createdAt = newSessionCreatedAt ns
    expiresAt = Torsor.add (sessionTimeoutIdle cfg) createdAt
    seshId = newSessionId ns
    anonData = newSessionData ns
    codeVerifierTxt = anonSessionCodeVerifier anonData
  mExisting <- Db.get (toDbSessionId seshId)
  case mExisting of
    Just _  -> pure Nothing
    Nothing -> do
      Db.insertKey (toDbSessionId seshId) $
        Db.Session
          (Just codeVerifierTxt)
          (uriToStr <$> anonSessionRedirect anonData)
          Nothing
          (Chronos.getTime createdAt)
          (Chronos.getTime expiresAt)
      pure $ Just $ SessionData { sessionId = newSessionId ns
                                , sessionExpiresAt = expiresAt
                                , sessionCreatedAt = createdAt
                                , sessionData = anonData
                                }

authenticateSessionDb
  :: MonadIO m
  => SessionConfig
  -> SessionId
  -> NewSession Authenticated
  -> ReaderT SqlBackend m (Maybe (SessionResult (SessionData Authenticated)))
authenticateSessionDb cfg oldSessionId ns = do
  let newSessionKey = toDbSessionId $ newSessionId ns
  mExisting <- Db.get newSessionKey
  case mExisting of
    Just _ -> pure Nothing
    Nothing -> do
      let
        createdAt = newSessionCreatedAt ns
        expiresAt = Torsor.add (sessionTimeoutIdle cfg) createdAt

      sr <- getSessionDb cfg $ GetSession { getSessionId = oldSessionId
                                          , getSessionAt = createdAt
                                          }
      case sr of
        SessionExpired ->
          pure $ Just SessionExpired
        SessionNotFound ->
          pure $ Just SessionNotFound
        SessionFound _oldSession -> do
          -- End anonymous session at same time we authenticate the session
          endSessionDb cfg $ EndSession { endSessionId = oldSessionId
                                        , endSessionAt = createdAt
                                        }

          let authData = newSessionData ns

          userId <- upsertUser $ authUserClaims authData

          -- Create a new, authenticated session
          Db.insertKey newSessionKey $
            Db.Session
              Nothing
              Nothing
              (Just userId)
              (Chronos.getTime createdAt)
              (Chronos.getTime expiresAt)

          pure $ Just $ SessionFound $
            SessionData { sessionId = newSessionId ns
                        , sessionExpiresAt = expiresAt
                        , sessionCreatedAt = createdAt
                        , sessionData = authData
                        }


getSessionDb
  :: MonadIO m
  => SessionConfig
  -> GetSession
  -> ReaderT SqlBackend m (SessionResult (Session Anonymous Authenticated))
getSessionDb cfg gs = do
  mSession <- P.getEntity (toDbSessionId $ getSessionId gs)
  case mSession of
    Nothing -> pure SessionNotFound
    Just sessionDb -> do
      let session = sessionFromDb sessionDb
      let currentTime = getSessionAt gs
      if isExpired cfg currentTime (getSessionData session)
      then do
        endSessionDb cfg (EndSession { endSessionId = getSessionId gs
                                     , endSessionAt = currentTime
                                     }
                         )
        pure SessionExpired
      else do
        touchSession cfg currentTime (getSessionId gs)
        case session of
          SessionAnonymous sd -> do
            pure $ SessionFound $ SessionAnonymous sd {
              sessionExpiresAt = Torsor.add (sessionTimeoutIdle cfg) currentTime
            }
          SessionAuthenticated sd -> do
            let userId = sessionData sd
            mUser <- Db.get userId
            case mUser of
              Nothing -> pure SessionNotFound
              Just user -> pure $
                SessionFound $ SessionAuthenticated sd
                  { sessionData =
                      Authenticated $ userFromDb (Db.Entity userId user)
                  , sessionExpiresAt = Torsor.add (sessionTimeoutIdle cfg) currentTime
                  }

endSessionDb
  :: MonadIO m
  => SessionConfig
  -> EndSession
  -> ReaderT SqlBackend m ()
endSessionDb _ sesh = P.delete (toDbSessionId $ endSessionId sesh)

toDbSessionId :: SessionId -> Db.SessionId
toDbSessionId (SessionId sid) = Db.SessionKey sid

upsertUser :: MonadIO m => UserClaims -> ReaderT SqlBackend m Db.UserId
upsertUser userClaims = do
  let
    userId = Db.UserKey $ userClaimsSub userClaims
    name = userClaimsName userClaims
    email = userClaimsEmail userClaims
    emailVerified = userClaimsEmailVerified userClaims
    claimsJSON = T.decodeUtf8 . BSL.toStrict . Aeson.encode $ jwtClaims userClaims
    user = Db.User name email emailVerified claimsJSON
  Db.repsert userId user
  pure userId

sessionFromDb
  :: Db.Entity Db.Session
  -> Session Anonymous Db.UserId
sessionFromDb (Db.Entity (Db.SessionKey sid) sessionDb) = do
  let
    mkSessionData a =
      SessionData { sessionId = SessionId sid
                  , sessionExpiresAt = Chronos.Time $ Db.sessionExpiresAt sessionDb
                  , sessionCreatedAt = Chronos.Time $ Db.sessionCreatedAt sessionDb
                  , sessionData = a
                  }
  case Db.sessionUser sessionDb of
    Nothing ->
      let
        redirect = do
          uriStr <- Debug.trace ("AAA: " <> show sessionDb) $ Db.sessionRedirectTo sessionDb
          case Debug.trace ("BBB: " <> show (parseURI (T.encodeUtf8 uriStr))) (parseURI (T.encodeUtf8 uriStr)) of
            Left _ -> Nothing
            Right uri -> Just uri
        codeVerifier =
          fromMaybe "" $ Db.sessionCodeVerifier sessionDb
      in
        SessionAnonymous $ mkSessionData
          Anonymous { anonSessionRedirect = redirect
                    , anonSessionCodeVerifier = codeVerifier
                    }
    Just userId ->
      SessionAuthenticated $ mkSessionData userId

userFromDb :: Db.Entity Db.User -> UserClaims
userFromDb (Db.Entity (Db.UserKey userId) user) = do
  let
    claims =
        fromJust
        $ Aeson.decode
        $ BSL.fromStrict
        $ T.encodeUtf8
        $ Db.userClaims user
  UserClaims { jwtClaims = claims
             , userClaimsEmail = Db.userEmail user
             , userClaimsEmailVerified = Db.userEmailVerified user
             , userClaimsName = Db.userName user
             , userClaimsSub = userId
             }

touchSession
  :: MonadIO m
  => SessionConfig
  -> Time
  -> SessionId
  -> ReaderT SqlBackend m ()
touchSession cfg currentTime sid = do
  let t = Torsor.add (sessionTimeoutIdle cfg) currentTime
  Db.update $ \s -> do
    Db.set s [ Db.SessionExpiresAt =. Db.val (Chronos.getTime t) ]
    Db.where_ $ (s ^. Db.SessionId) ==. Db.val (toDbSessionId sid)
