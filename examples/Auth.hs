{-# LANGUAGE DataKinds #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeOperators #-}
{-# LANGUAGE DeriveAnyClass #-}

{-|
Module                  : Main
Copyright               : (c) 2024-2025 Samuel Evans-Powell
SPDX-License-Identifier : MPL-2.0
Maintainer              : Samuel Evans-Powell <mail@sevanspowell.net>
Stability               : experimental

An example demonstrating use of slibs session cookie auth. The following
environment variables should be set:

export OAUTH_CLIENT_ID=""
export OAUTH_CLIENT_SECRET=""
export OAUTH_REDIRECT_URI="http://localhost:8082/auth/callback"
export OAUTH_AUTHORIZE_URI=".../oauth2/authorize"
export OAUTH_TOKEN_URI=".../oauth2/token"
export OAUTH_USERINFO_URI=".../oauth2/userInfo"
export OAUTH_LOGOUT_URI=".../logout?client_id=$OAUTH_CLIENT_ID&response_type=code&redirect_uri=http://localhost:8082"
export JWT_ISSUER="..."
export JWT_AUD="$OAUTH_CLIENT_ID"
export JWT_JWKS_URI=".../.well-known/jwks.json"
export SESSION_TIMEOUT_SECONDS_ABSOLUTE="7200"
export SESSION_TIMEOUT_SECONDS_IDLE="1800"
export SESSION_INSECURE="true"
-}
module Main where

import Control.Monad.IO.Class (liftIO)
import Control.Monad.Logger (runStdoutLoggingT)
import Control.Monad.Reader (ReaderT)
import Data.Pool (Pool)
import Data.String (fromString)
import Database.Persist.Postgresql (withPostgresqlPool)
import Database.Persist.Sql (SqlBackend, runSqlPool)
import GHC.Generics (Generic)
import Lucid (
  Html,
  a_,
  body_,
  input_,
  type_,
  id_,
  form_,
  placeholder_,
  required_,
  button_,
  charset_,
  content_,
  doctype_,
  h1_,
  head_,
  header_,
  href_,
  html_,
  main_,
  meta_,
  name_,
  p_,
  title_, h3_,
 )
import Network.HTTP.Client.TLS (newTlsManagerWith, tlsManagerSettings)
import Network.Wai (Application, Request, requestHeaders)
import Network.Wai.Handler.Warp (run)
import Sam.Auth.Config.JWT (envConfigJWT)
import Sam.Auth.Config.OAuth (envConfigOAuth)
import Sam.Util.Htmx (hxHeaders_, useHtmxVersion, useHtmxJsExt, hxPut_, hxExt_)
import Sam.Auth.Config.Session (envConfigSession)
import Sam.Auth.Database.Schema qualified as Db
import Sam.Auth.JWT (mkJWKSCache)
import Sam.Auth.OAuth (mkOAuth)
import Sam.Auth.Middleware.CSRF (csrfMiddleware, defaultCSRFPolicy)
import Sam.Auth.Middleware.Authentication (authenticationMiddleware)
import Data.Function ((&))
import Sam.Auth.Session.Cookies (
  Cookies (..),
  SessionCookies,
  getUser,
  mkSessionCookies,
 )
import Sam.Auth.Session.Types (Session (SessionAnonymous, SessionAuthenticated), SessionResult (SessionNotFound, SessionExpired, SessionFound), SessionId(SessionId), SessionData(sessionData, sessionCSRF), Authenticated)
import Sam.Util.Postgres (withTemporaryDatabase)
import Servant (
  Context (EmptyContext, (:.)),
  Get,
  Handler,
  Header,
  Proxy (Proxy),
  (:>), throwError,
 )
import Servant.API (AuthProtect, NamedRoutes, ToServantApi, genericApi, (:-), ReqBody, JSON, Put)
import Servant.API.ContentTypes.Lucid (HTML)
import Data.Text (Text)
import Data.Aeson (ToJSON, FromJSON)
import Servant.Server.Experimental.Auth (AuthHandler, mkAuthHandler)
import Servant.Server.Generic (AsServer, genericServeTWithContext)
import Servant.Server (err404)
import qualified Data.Text.Encoding as T
import Sam.Auth.Session.Cookies (getSessionBySessionId)

data Routes mode = Routes
  { publicRoutes :: mode :- NamedRoutes PublicRoutes
  , protectedRoutes
      :: mode :- AuthProtect "cookie-auth" :> NamedRoutes ProtectedRoutes
  }
  deriving (Generic)

data PublicRoutes mode = PublicRoutes
  { home :: mode :- Header "Cookie" Cookies :> Get '[HTML] (Html ())
  }
  deriving (Generic)

data ProtectedRoutes mode = ProtectedRoutes
  { treasure :: mode :- "treasure" :> Get '[HTML] (Html ())
  , form :: mode :- "form" :> ReqBody '[JSON] FormBody :> Put '[HTML] (Html ())
  }
  deriving (Generic)

data FormBody = FormBody { name :: Text }
  deriving (Eq, Show, Generic, ToJSON, FromJSON)

apiServer
  :: SessionCookies (ReaderT SqlBackend IO)
  -> Pool SqlBackend
  -> Routes AsServer
apiServer sessions pool =
  Routes
    { publicRoutes =
        PublicRoutes
          { home = homeHandler pool sessions
          }
    , protectedRoutes = \session ->
        ProtectedRoutes
          { treasure = treasureHandler pool session
          , form = formHandler pool session
          }
    }

api :: Proxy (ToServantApi Routes)
api = genericApi (Proxy :: Proxy Routes)

homeHandler
  :: Pool SqlBackend
  -> SessionCookies (ReaderT SqlBackend IO)
  -> Maybe Cookies
  -> Handler (Html ())
homeHandler pool sessions cs = do
  mUser <- liftIO $ flip runSqlPool pool $ getUser sessions cs
  case mUser of
    SessionFound (Just _user) ->
      pure $ page $ do
        p_ $ a_ [href_ "/auth/logout"] "Logout"
        p_ $ a_ [href_ "/treasure"] "Get Treasure"
    _ ->
      pure $ page (a_ [href_ "/auth/login"] "Login")

page :: Html () -> Html ()
page p = do
  doctype_
  html_ $ do
    head_ $ do
      title_ "slib OAuth Example"
      meta_ [charset_ "UTF-8"]
      meta_ [name_ "viewport", content_ "width=device-width, initial-scale=1.0"]
      useHtmxVersion (2, 0, 2)
      useHtmxJsExt
    body_ $ do
      main_ $ do
        header_ $ do
          h1_ "slib OAuthExample"
        p

treasureHandler
  :: Pool SqlBackend
  -> SessionData Authenticated
  -> Handler (Html ())
treasureHandler _pool session =
  pure $ page $ do
    p_ [] (fromString $ "Treasure for " <> show (sessionData session))
    h3_ [] "Form with CSRF:"
    form_ [ hxPut_ "/form"
          , hxHeaders_ $ "{\"X-CSRF-TOKEN\": \"" <> sessionCSRF session <> "\"}"
          , hxExt_ "json-enc"
          ] $ do
      input_
        [ type_ "text"
        , name_ "name"
        , id_ "name"
        , placeholder_ "Type name"
        , required_ ""
        ]
      button_
        [ type_ "submit"
        ]
        "Submit"
    h3_ [] "Form without CSRF:"
    form_ [ hxPut_ "/form"
          , hxExt_ "json-enc"
          ] $ do
      input_
        [ type_ "text"
        , name_ "name"
        , id_ "name"
        , placeholder_ "Type name"
        , required_ ""
        ]
      button_
        [ type_ "submit"
        ]
        "Submit"

formHandler
  :: Pool SqlBackend
  -> SessionData Authenticated
  -> FormBody
  -> Handler (Html ())
formHandler _pool _session fb =
  pure $ "Form submitted successfully with: " <> fromString (show fb)

app
  :: SessionCookies (ReaderT SqlBackend IO)
  -> Pool SqlBackend
  -> Application
app sessionCookies pool = do
  let
    ctx :: Context (AuthHandler Request (SessionData Authenticated) ': '[])
    ctx = authHandler sessionCookies pool :. EmptyContext

  genericServeTWithContext
    id
    (apiServer sessionCookies pool)
    ctx

authHandler
  :: SessionCookies (ReaderT SqlBackend IO)
  -> Pool SqlBackend
  -> AuthHandler Request (SessionData Authenticated)
authHandler sessions pool =
  let
    handler req = do
      case lookup "Authorization" $ requestHeaders req of
        Nothing -> do
          throwError err404
        Just sessionId -> do
          mUser <- liftIO $ flip runSqlPool pool $
            getSessionBySessionId sessions (SessionId $ T.decodeUtf8 sessionId)
          case mUser of
            SessionNotFound ->
              throwError err404
            SessionExpired ->
              throwError err404
            SessionFound (SessionAnonymous _) ->
              throwError err404
            SessionFound (SessionAuthenticated sd) -> do
              -- If you have your own User type, here is where you can add that
              -- user to the database, using the UserClaims in the SessionData.
              pure sd
  in
    mkAuthHandler handler

main :: IO ()
main = do
  cfgOAuth <- envConfigOAuth
  cfgJWT <- envConfigJWT
  cfgSession <- envConfigSession

  manager <- newTlsManagerWith tlsManagerSettings

  jwks <- mkJWKSCache cfgJWT manager
  sessionCookies <- mkSessionCookies cfgSession
  let oauth = mkOAuth cfgOAuth manager

  withTemporaryDatabase Db.migrateAll $ \conn ->
    runStdoutLoggingT $
      withPostgresqlPool conn 3 $ \pool -> do
        liftIO $ run 8082 $
          app sessionCookies pool
          & csrfMiddleware defaultCSRFPolicy sessionCookies pool
          & authenticationMiddleware oauth sessionCookies jwks pool
