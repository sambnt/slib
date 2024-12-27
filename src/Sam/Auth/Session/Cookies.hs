{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE TupleSections #-}

{- |
Module                  : Sam.Auth.Session.Cookies
Copyright               : (c) 2024-2025 Samuel Evans-Powell
SPDX-License-Identifier : MPL-2.0
Maintainer              : Samuel Evans-Powell <mail@sevanspowell.net>
Stability               : experimental
-}

module Sam.Auth.Session.Cookies where

-- TODO: Explicit import
import Control.Monad.IO.Class (MonadIO, liftIO)
import Control.Monad.Reader (ReaderT)
import Crypto.Random.Entropy as Random
import Data.Maybe (fromMaybe)
import Data.Text (Text)
import Database.Persist.Sql (SqlBackend)
import Sam.Auth.Config.Session (IsSecure, ConfigSession(..), isSecure)
import Sam.Auth.JWT.Types (UserClaims)
import Sam.Auth.Session (mkSessionStoreDb)
import Sam.Auth.Session.Types (SessionConfig(..), SessionStore, Anonymous, Authenticated(..), Session(..), SessionResult(..), GetSession(..), SessionId(SessionId), sessionData, authUserClaims, SessionData(..), NewSession(..), EndSession(..))
import Web.Cookie (SetCookie (..), parseCookies, defaultSetCookie, sameSiteLax)
import Web.HttpApiData (FromHttpApiData, parseHeader, parseQueryParam)
import qualified Chronos
import qualified Data.ByteString.Base64 as Base64
import qualified Data.Text.Encoding as TE
import qualified Sam.Auth.Session.Types as Store
import qualified Web.Cookie as Web

data SessionCookies m
  = SessionCookies { sessionSecureCookies :: IsSecure
                   , sessionCookieName    :: Text
                   , sessionStoreConfig   :: SessionConfig
                   , sessionStore         :: SessionStore m Anonymous Authenticated
                   }

newtype Cookies = Cookies Web.Cookies -- type Cookies = [(BS.ByteString, BS.ByteString)]
  deriving newtype Show

instance FromHttpApiData Cookies where
  parseHeader = return . Cookies . parseCookies
  parseQueryParam = return . Cookies . parseCookies . TE.encodeUtf8

getCookies :: Cookies -> Web.Cookies
getCookies (Cookies cs) = cs

mkSessionCookies :: MonadIO m => ConfigSession -> m (SessionCookies (ReaderT SqlBackend m))
mkSessionCookies cfg = do
  let
    store = mkSessionStoreDb
    storeConfig =
      SessionConfig { sessionTimeoutAbsolute = cfgSessionTimeoutAbsolute cfg
                    , sessionTimeoutIdle = cfgSessionTimeoutIdle cfg
                    }
  pure $ SessionCookies { sessionStoreConfig = storeConfig
                        , sessionStore = store
                        , sessionCookieName = cfgSessionCookieName cfg
                        , sessionSecureCookies = cfgSessionSecureCookies cfg
                        }

getUser
  :: MonadIO m
  => SessionCookies m
  -> Maybe Cookies
  -> m (SessionResult (Maybe UserClaims))
getUser sessions mcs = do
  result <- getSession sessions mcs

  pure $ case result of
    SessionNotFound                        -> SessionNotFound
    SessionExpired                         -> SessionExpired
    SessionFound (SessionAnonymous _)      -> SessionFound Nothing
    SessionFound (SessionAuthenticated sd) ->
      SessionFound $ Just (authUserClaims $ sessionData sd)

getSession
  :: MonadIO m
  => SessionCookies m
  -> Maybe Cookies
  -> m (SessionResult (Session Anonymous Authenticated))
getSession sessions mcs = do
  let
    cs = fromMaybe (Cookies []) mcs
    cfg = sessionStoreConfig sessions
    store = sessionStore sessions
  t <- liftIO Chronos.now

  case getSessionCookie sessions cs of
    Nothing ->
      pure SessionNotFound
    Just sid -> do
      Store.getSession store cfg $ GetSession { getSessionId = sid
                                              , getSessionAt = t
                                              }

-- TODO: Test user's previous session is destroyed
newSession
  :: MonadIO m
  => SessionCookies m
  -> Maybe Cookies
  -> Anonymous
  -> m (SessionData Anonymous, SetCookie)
newSession sessions mcs anon = do
  let
    cfg = sessionStoreConfig sessions
    store = sessionStore sessions
    loopUntilUniqueSession = do
      t <- liftIO Chronos.now
      sid <- liftIO $
        TE.decodeUtf8Lenient . Base64.encode <$> Random.getEntropy 32
      result <- Store.newSession store cfg $
        NewSession { newSessionId = SessionId sid
                   , newSessionCreatedAt = t
                   , newSessionData = anon
                   }
      case result of
        Nothing -> loopUntilUniqueSession
        Just r  -> pure r

  -- End previous session, if it exists.
  _ <- endSession sessions mcs
  -- Create new session.
  sd <- loopUntilUniqueSession
  pure ( sd
       , newSessionCookie sessions (sessionId sd)
       )

authenticateSession
  :: MonadIO m
  => SessionCookies m
  -> SessionId
  -> UserClaims
  -> m (SessionResult (SessionData Authenticated, SetCookie))
authenticateSession sessions oldSessionId usr = do
  let
    cfg = sessionStoreConfig sessions
    store = sessionStore sessions
    loopUntilUniqueSession = do
      t <- liftIO Chronos.now
      sid <- liftIO $
        TE.decodeUtf8Lenient . Base64.encode <$> Random.getEntropy 32
      result <- Store.authenticateSession store cfg oldSessionId $
        NewSession { newSessionId = SessionId sid
                   , newSessionCreatedAt = t
                   , newSessionData = Authenticated usr
                   }
      maybe loopUntilUniqueSession pure result
  fmap (\sd -> (sd , newSessionCookie sessions (sessionId sd)))
    <$> loopUntilUniqueSession

endSession :: MonadIO m => SessionCookies m -> Maybe Cookies -> m SetCookie
endSession sessions mcs = do
  let
    cs = fromMaybe (Cookies []) mcs
    cfg = sessionStoreConfig sessions
    store = sessionStore sessions
  t <- liftIO Chronos.now

  case getSessionCookie sessions cs of
    Nothing ->
      pure $ expireSessionCookie sessions
    Just sid -> do
      Store.endSession store cfg $ EndSession { endSessionId = sid
                                              , endSessionAt = t
                                              }
      pure $ expireSessionCookie sessions

getSessionCookie :: SessionCookies m -> Cookies -> Maybe SessionId
getSessionCookie sessions =
  fmap (SessionId . TE.decodeUtf8Lenient)
  . lookup (TE.encodeUtf8 $ sessionCookieName sessions)
  . getCookies

newSessionCookie :: SessionCookies m -> SessionId -> SetCookie
newSessionCookie sessions (SessionId sid) =
  (defaultSessionCookie sessions)
    { setCookieValue = TE.encodeUtf8 sid
    }

expireSessionCookie :: SessionCookies m -> SetCookie
expireSessionCookie sessions =
  (defaultSessionCookie sessions)
    { setCookieValue = ""
    , setCookieMaxAge = Just (-1)
    }

defaultSessionCookie :: SessionCookies m -> SetCookie
defaultSessionCookie sessions =
  defaultSetCookie { setCookieName = TE.encodeUtf8 $ sessionCookieName sessions
                   -- Not available to Javascript
                   , setCookieHttpOnly = True
                   , setCookieSameSite = Just sameSiteLax
                   -- Restrict cookie to just this server
                   , setCookieDomain = Nothing
                   -- Expire after 1 hour
                   , setCookieMaxAge = Just 3600
                   -- TODO: Give option for these
                   , setCookieSecure = isSecure $ sessionSecureCookies sessions
                   , setCookiePath = Just "/"
                   }