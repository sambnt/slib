{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE TypeOperators #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

{-|
Module                  : Sam.Auth.Api
Copyright               : (c) 2024-2025 Samuel Evans-Powell
SPDX-License-Identifier : MPL-2.0
Maintainer              : Samuel Evans-Powell <mail@sevanspowell.net>
Stability               : experimental
-}
module Sam.Auth.Api where

import Control.Monad.Except (runExceptT)
import Control.Monad.IO.Class (liftIO)
import Control.Monad.Reader (ReaderT)
import qualified Data.ByteString.Lazy.UTF8 as BSLU
import Data.Pool (Pool)
import Data.Text (Text)
import Database.Persist.Sql (SqlBackend, runSqlPool)
import GHC.Generics (Generic)
import Lucid (Html)
import Network.OAuth.OAuth2 (idToken)
import Network.Wai (Request, rawPathInfo, requestHeaders)
import Sam.Auth.JWT (JWKSCache, verifyToken)
import Sam.Auth.JWT.Types (UserClaims)
import Sam.Auth.OAuth (OAuth, logoutURI, pkceTokenRequest, startOAuth)
import Sam.Auth.Session.Cookies (
  Cookies (..),
  SessionCookies,
  authenticateSession,
  endSession,
  getSession,
  getUser,
  newSession,
 )
import Sam.Auth.Session.Types (
  Session (..),
  SessionResult (..),
  anonSessionRedirect,
  sessionData,
  sessionId,
 )
import Sam.Util.URI (URI, parseURI, uriToStr)
import Servant (
  Get,
  Handler,
  Header,
  Proxy (Proxy),
  Server,
  err302,
  err404,
  err500,
  errBody,
  errHeaders,
  throwError,
  (:>),
 )
import Servant.API (
  AuthProtect,
  NamedRoutes,
  QueryParam',
  Required,
  Strict,
  (:-),
 )
import Servant.API.ContentTypes.Lucid (HTML)
import Servant.Server (err400)
import Servant.Server.Experimental.Auth (
  AuthHandler,
  AuthServerData,
  mkAuthHandler,
 )
import Web.Cookie (parseCookies, renderSetCookieBS)

-- TODO: Test redirects
-- TODO: Test SetCookie behaviour

type OAuthCode = Text

type AuthAPI = NamedRoutes AuthAPI'

data AuthAPI' mode = AuthAPI'
  { callback
      :: mode
        :- "auth"
          :> "callback"
          :> Header "Cookie" Cookies
          :> QueryParam' '[Required, Strict] "code" OAuthCode
          :> Get '[HTML] (Html ())
  , logout
      :: mode
        :- "auth"
          :> "logout"
          :> Header "Cookie" Cookies
          :> Get '[HTML] (Html ())
  , login
      :: mode
        :- "auth"
          :> "login"
          :> Header "Cookie" Cookies
          :> Get '[HTML] (Html ())
  }
  deriving (Generic)

type instance AuthServerData (AuthProtect "cookie-auth") = UserClaims

api :: Proxy AuthAPI
api = Proxy

apiServer
  :: OAuth
  -> SessionCookies (ReaderT SqlBackend IO)
  -> JWKSCache
  -> Pool SqlBackend
  -> Server AuthAPI
apiServer oauth sessions jwks pool =
  AuthAPI'
    { callback = callbackHandler oauth sessions jwks pool
    , logout = logoutHandler oauth sessions pool
    , login = loginHandler oauth sessions pool
    }

loginHandler
  :: OAuth
  -> SessionCookies (ReaderT SqlBackend IO)
  -> Pool SqlBackend
  -> Maybe Cookies
  -> Handler (Html ())
loginHandler oauth sessions pool cs = do
  beginSession oauth sessions pool cs Nothing

logoutHandler
  :: OAuth
  -> SessionCookies (ReaderT SqlBackend IO)
  -> Pool SqlBackend
  -> Maybe Cookies
  -> Handler (Html ())
logoutHandler oauth sessions pool cs = do
  setCookie <- liftIO $ flip runSqlPool pool $ endSession sessions cs
  throwError $
    err302
      { errHeaders =
          [ ("Location", maybe "/" uriToStr $ logoutURI oauth)
          , ("Set-Cookie", renderSetCookieBS setCookie)
          ]
      }

-- TODO: Logout of AWS too

callbackHandler
  :: OAuth
  -> SessionCookies (ReaderT SqlBackend IO)
  -> JWKSCache
  -> Pool SqlBackend
  -> Maybe Cookies
  -> OAuthCode
  -> Handler (Html ())
callbackHandler oauth sessions jwks pool cs code = do
  mSesh <- liftIO $ flip runSqlPool pool $ getSession sessions cs
  case mSesh of
    SessionNotFound ->
      -- Bad session ID, try again
      -- TODO: Throw alert
      beginSession oauth sessions pool cs Nothing
    SessionExpired ->
      -- Expired session ID, try again
      beginSession oauth sessions pool cs Nothing
    SessionFound (SessionAuthenticated _) -> do
      throwError $
        err302
          { errHeaders =
              [ ("Location", "/")
              ]
          }
    SessionFound (SessionAnonymous sd) -> do
      eToken <- pkceTokenRequest oauth (sessionData sd) code
      case eToken of
        Left err ->
          throwError $
            err500
              { errBody =
                  "Unable to exchange token with OAuth2 server: " <> BSLU.fromString (show err)
              }
        Right token -> do
          case idToken token of
            Nothing -> do
              throwError $
                err500
                  { errBody =
                      "OAuth2 server did not return 'idToken' in: " <> BSLU.fromString (show token)
                  }
            Just idT -> do
              -- Verify token is from AWS.
              eUserClaims <- liftIO $ runExceptT $ verifyToken jwks idT
              case eUserClaims of
                Left err ->
                  throwError $
                    err400
                      { errBody = "Unable to verify OAuth token: " <> BSLU.fromString (show err)
                      }
                Right userClaims -> do
                  sr <-
                    liftIO $
                      flip runSqlPool pool $
                        authenticateSession sessions (sessionId sd) userClaims
                  case sr of
                    SessionFound (_auth, setCookie) -> do
                      let redirectUri = maybe "/" uriToStr (anonSessionRedirect $ sessionData sd)
                      throwError $
                        err302
                          { errHeaders =
                              [ ("Location", redirectUri)
                              , ("Set-Cookie", renderSetCookieBS setCookie)
                              ]
                          }
                    _ -> do
                      throwError $
                        err400
                          { errBody = "Session doesn't exist or is expired."
                          }

beginSession
  :: OAuth
  -> SessionCookies (ReaderT SqlBackend IO)
  -> Pool SqlBackend
  -> Maybe Cookies
  -> Maybe URI
  -> Handler a
beginSession oauth sessions pool mcs redirectTo = do
  (signInURI, anonData) <- startOAuth oauth redirectTo
  (_sessionData, setCookie) <-
    liftIO $ flip runSqlPool pool $ newSession sessions mcs anonData
  throwError $
    err302
      { errHeaders =
          [ ("Location", uriToStr signInURI)
          , ("Set-Cookie", renderSetCookieBS setCookie)
          ]
      }

authHandler
  :: OAuth
  -> SessionCookies (ReaderT SqlBackend IO)
  -> Pool SqlBackend
  -> AuthHandler Request UserClaims
authHandler oauth sessions pool =
  let
    getCookies req = do
      case lookup "cookie" $ requestHeaders req of
        Nothing -> pure $ Nothing
        Just cs -> pure $ Just $ Cookies $ parseCookies cs
    handler req = do
      let
        uri =
          case parseURI (rawPathInfo req) of
            Left _ -> Nothing
            Right x -> Just x
      -- liftIO $ putStrLn $ "raw URI " <> show (rawPathInfo req)
      -- liftIO $ putStrLn $ "URI received " <> show uri
      cookies <- getCookies req
      mUser <- liftIO $ flip runSqlPool pool $ getUser sessions cookies
      case mUser of
        SessionNotFound ->
          -- Alert: Tried to craft session id
          beginSession oauth sessions pool cookies uri
        SessionExpired ->
          beginSession oauth sessions pool cookies uri
        SessionFound Nothing -> do
          throwError err404
        SessionFound (Just user) -> do
          pure user
   in
    mkAuthHandler handler
