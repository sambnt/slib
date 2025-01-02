{-|
Module                  : Sam.Auth.Middleware.Authentication
Copyright               : (c) 2024-2025 Samuel Evans-Powell
SPDX-License-Identifier : MPL-2.0
Maintainer              : Samuel Evans-Powell <mail@sevanspowell.net>
Stability               : experimental
-}
module Sam.Auth.Middleware.Authentication where

import Control.Monad.Except (runExceptT)
import Control.Monad.IO.Class (MonadIO, liftIO)
import Control.Monad.Reader (ReaderT)
import Data.ByteString.Lazy.UTF8 qualified as BSLU
import Data.Function ((&))
import Data.Map.Strict qualified as Map
import Data.Maybe (fromMaybe)
import Data.Pool (Pool)
import Data.Text.Encoding qualified as T
import Database.Persist.Postgresql (SqlBackend, runSqlPool)
import Network.HTTP.Types (status302, status400, status500)
import Network.OAuth.OAuth2 (idToken)
import Network.Wai (
  Middleware,
  Response,
  pathInfo,
  queryString,
  requestHeaders,
  responseLBS,
 )
import Sam.Auth.Api (OAuthCode)
import Sam.Auth.JWT (JWKSCache, verifyToken)
import Sam.Auth.OAuth (
  OAuth,
  logoutURI,
  pkceTokenRequest,
  startOAuth,
 )
import Sam.Auth.Session.Cookies (
  Cookies (..),
  SessionCookies,
  authenticateSession,
  endSession,
  getSession,
  newSession,
 )
import Sam.Auth.Session.Types (
  Session (..),
  SessionResult (..),
  anonSessionRedirect,
  unSessionId,
  sessionData,
  sessionId,
 )
import Sam.Util.URI (URI, uriToStr)
import Web.Cookie (parseCookies, renderSetCookieBS)

-- | Authenticates a raw request, adding an Authorization header with the user's
-- ID (sub) if it authenticates successfully.
authenticationMiddleware
  :: OAuth
  -> SessionCookies (ReaderT SqlBackend IO)
  -> JWKSCache
  -> Pool SqlBackend
  -> Middleware
authenticationMiddleware oauth sessions jwks pool app req respond = do
  let
    getCookies = do
      case lookup "cookie" $ requestHeaders req of
        Nothing -> pure Nothing
        Just cs -> pure $ Just $ Cookies $ parseCookies cs

  cookies <- getCookies

  case pathInfo req of
    ["auth", "logout"] ->
      respond =<< logout oauth sessions pool cookies
    ["auth", "login"] ->
      respond =<< login oauth sessions pool cookies
    ["auth", "callback"] ->
      case lookup "code" $ queryString req of
        Nothing ->
          respond $
            responseLBS
              status400
              []
              "Missing OAuth2 code query parameter"
        Just code ->
          respond
            =<< callback
              oauth
              sessions
              jwks
              pool
              cookies
              (T.decodeUtf8 $ fromMaybe "" code)
    _ -> do
      mSession <- liftIO $ flip runSqlPool pool $ getSession sessions cookies
      case mSession of
        SessionFound (SessionAuthenticated sd) -> do
          let
            newRequestHeaders =
              requestHeaders req
                & Map.fromList
                & Map.insert "Authorization" (T.encodeUtf8 $ unSessionId $ sessionId sd)
                & Map.toList
          app (req{requestHeaders = newRequestHeaders}) respond
        _ -> do
          let
            newRequestHeaders =
              requestHeaders req
                & Map.fromList
                & Map.delete "Authorization"
                & Map.toList
          app (req{requestHeaders = newRequestHeaders}) respond

beginSession
  :: (MonadIO m)
  => OAuth
  -> SessionCookies (ReaderT SqlBackend IO)
  -> Pool SqlBackend
  -> Maybe Cookies
  -> Maybe URI
  -> m Response
beginSession oauth sessions pool mcs redirectTo = do
  (signInURI, anonData) <- startOAuth oauth redirectTo
  (_sessionData, setCookie) <-
    liftIO $ flip runSqlPool pool $ newSession sessions mcs anonData
  -- Temporary redirect
  pure $
    responseLBS
      status302
      [ ("Location", uriToStr signInURI)
      , ("Set-Cookie", renderSetCookieBS setCookie)
      ]
      ""

logout
  :: (MonadIO m)
  => OAuth
  -> SessionCookies (ReaderT SqlBackend IO)
  -> Pool SqlBackend
  -> Maybe Cookies
  -> m Response
logout oauth sessions pool cs = do
  setCookie <- liftIO $ flip runSqlPool pool $ endSession sessions cs
  pure $
    responseLBS
      status302
      [ ("Location", maybe "/" uriToStr $ logoutURI oauth)
      , ("Set-Cookie", renderSetCookieBS setCookie)
      ]
      ""

login
  :: (MonadIO m)
  => OAuth
  -> SessionCookies (ReaderT SqlBackend IO)
  -> Pool SqlBackend
  -> Maybe Cookies
  -> m Response
login oauth sessions pool cs = do
  beginSession oauth sessions pool cs Nothing

callback
  :: (MonadIO m)
  => OAuth
  -> SessionCookies (ReaderT SqlBackend IO)
  -> JWKSCache
  -> Pool SqlBackend
  -> Maybe Cookies
  -> OAuthCode
  -> m Response
callback oauth sessions jwks pool cs code = do
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
      pure $
        responseLBS
          status302
          [ ("Location", "/")
          ]
          ""
    SessionFound (SessionAnonymous sd) -> do
      eToken <- pkceTokenRequest oauth (sessionData sd) code
      case eToken of
        Left err ->
          pure $
            responseLBS
              status500
              []
              ("Unable to exchange token with OAuth2 server: " <> BSLU.fromString (show err))
        Right token -> do
          case idToken token of
            Nothing -> do
              pure $
                responseLBS
                  status500
                  []
                  ("OAuth2 server did not return 'idToken' in: " <> BSLU.fromString (show token))
            Just idT -> do
              -- Verify token is from AWS.
              eUserClaims <- liftIO $ runExceptT $ verifyToken jwks idT
              case eUserClaims of
                Left err ->
                  pure $
                    responseLBS
                      status400
                      []
                      ("Unable to verify OAuth token: " <> BSLU.fromString (show err))
                Right userClaims -> do
                  sr <-
                    liftIO $
                      flip runSqlPool pool $
                        authenticateSession sessions (sessionId sd) userClaims
                  case sr of
                    SessionFound (_auth, setCookie) -> do
                      let redirectUri = maybe "/" uriToStr (anonSessionRedirect $ sessionData sd)
                      pure $
                        responseLBS
                          status302
                          [ ("Location", redirectUri)
                          , ("Set-Cookie", renderSetCookieBS setCookie)
                          ]
                          ""
                    _ -> do
                      pure $
                        responseLBS
                          status400
                          []
                          "Session doesn't exist or is expired."
