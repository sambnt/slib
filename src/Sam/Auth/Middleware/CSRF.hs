{-|
Module                  : Sam.Auth.Database.CSRF
Copyright               : (c) 2024-2025 Samuel Evans-Powell
SPDX-License-Identifier : MPL-2.0
Maintainer              : Samuel Evans-Powell <mail@sevanspowell.net>
Stability               : experimental
-}
module Sam.Auth.Middleware.CSRF where

import Control.Monad.IO.Class (liftIO)
import Control.Monad.Reader (ReaderT)
import Data.Pool (Pool)
import Data.Text.Encoding qualified as T
import Database.Persist.Postgresql (SqlBackend, runSqlPool)
import Network.HTTP.Types (
  HeaderName,
  methodDelete,
  methodPatch,
  methodPost,
  methodPut,
  status403,
 )
import Network.HTTP.Types.Method (Method)
import Network.Wai (
  Middleware,
  Response,
  requestHeaders,
  requestMethod,
  responseLBS,
 )
import Sam.Auth.Session.Cookies (
  Cookies (..),
  SessionCookies,
  getSession,
 )
import Sam.Auth.Session.Types (
  SessionResult (..),
  getSessionData,
  sessionCSRF,
 )
import Web.Cookie (parseCookies)

data CSRFPolicy = CSRFPolicy
  { csrfCheckMethods :: [Method]
  , csrfCheckHeader :: HeaderName
  }
  deriving (Eq, Show)

-- https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html#javascript-automatically-including-csrf-tokens-as-an-ajax-request-header
defaultCSRFPolicy :: CSRFPolicy
defaultCSRFPolicy =
  CSRFPolicy
    { csrfCheckMethods =
        [ methodPost
        , methodPut
        , methodDelete
        , methodPatch
        ]
    , csrfCheckHeader = defaultCSRFHeader
    }

defaultCSRFHeader :: HeaderName
defaultCSRFHeader = "X-CSRF-TOKEN"

csrfMiddleware
  :: CSRFPolicy
  -> SessionCookies (ReaderT SqlBackend IO)
  -> Pool SqlBackend
  -> Middleware
csrfMiddleware policy sessions pool app req respond = do
  -- See if we should check the request (is the request state-changing?)
  if requestMethod req `elem` csrfCheckMethods policy
    then do
      -- If so, find the CSRF header or fail
      case lookup (csrfCheckHeader policy) $ requestHeaders req of
        Nothing ->
          respond forbidden
        Just csrf -> do
          let
            getCookies = do
              case lookup "cookie" $ requestHeaders req of
                Nothing -> pure Nothing
                Just cs -> pure $ Just $ Cookies $ parseCookies cs
          cookies <- getCookies
          mSesh <- liftIO $ flip runSqlPool pool $ getSession sessions cookies
          case mSesh of
            SessionNotFound -> respond forbidden
            SessionExpired -> respond forbidden
            SessionFound session -> do
              let storedCSRF = sessionCSRF $ getSessionData session
              if T.decodeUtf8 csrf == storedCSRF
                then app req respond
                else respond forbidden
    else app req respond

forbidden :: Response
forbidden = responseLBS status403 [] "Forbidden"

-- TODO WWW-Authenticate header
-- See https://www.rfc-editor.org/rfc/rfc6750#section-3
-- expired :: Response
-- expired = responseLBS status401 [ ("WWW-Authenticate", "Bearer error=")
--                                 ] "Expired"
-- WWW-Authenticate: Bearer realm="example",
--                   error="invalid_token",
--                   error_description="The access token expired"
