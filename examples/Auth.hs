{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeOperators #-}

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
import Control.Monad.Reader (ReaderT)
import Data.Pool (Pool)
import Data.String (fromString)
import Database.Persist.Sql (SqlBackend, runSqlPool)
import GHC.Generics (Generic)
import Lucid (
  Html,
  a_,
  body_,
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
  title_,
 )
import Network.HTTP.Client.TLS (newTlsManagerWith, tlsManagerSettings)
import Network.Wai (Application, Request)
import Network.Wai.Handler.Warp (run)
import Sam.Auth.Api (AuthRoutes (..))
import Sam.Auth.Api qualified as Auth
import Sam.Auth.Config.JWT (envConfigJWT)
import Sam.Auth.Config.OAuth (envConfigOAuth)
import Sam.Auth.Config.Session (envConfigSession)
import Sam.Auth.Database.Schema qualified as Db
import Sam.Auth.JWT (JWKSCache, mkJWKSCache)
import Sam.Auth.JWT.Types (UserClaims)
import Sam.Auth.OAuth (OAuth, mkOAuth)
import Sam.Auth.Session.Cookies (
  Cookies (..),
  SessionCookies,
  getUser,
  mkSessionCookies,
 )
import Sam.Auth.Session.Types (SessionResult (SessionFound))
import Sam.Util.Postgres (withTemporaryDatabase)
import Servant (
  Context (EmptyContext, (:.)),
  Get,
  Handler,
  Header,
  Proxy (Proxy),
  (:>),
 )
import Servant.API (AuthProtect, NamedRoutes, ToServantApi, genericApi, (:-))
import Servant.API.ContentTypes.Lucid (HTML)
import Servant.Server.Experimental.Auth (AuthHandler)
import Servant.Server.Generic (AsServer, genericServeTWithContext)

data Routes mode = Routes
  { authRoutes :: mode :- NamedRoutes AuthRoutes
  , publicRoutes :: mode :- NamedRoutes PublicRoutes
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
  }
  deriving (Generic)

apiServer
  :: OAuth
  -> SessionCookies (ReaderT SqlBackend IO)
  -> JWKSCache
  -> Pool SqlBackend
  -> Routes AsServer
apiServer oauth sessions jwks pool =
  Routes
    { authRoutes = Auth.apiServer oauth sessions jwks pool
    , publicRoutes =
        PublicRoutes
          { home = homeHandler pool sessions
          }
    , protectedRoutes = \usr ->
        ProtectedRoutes
          { treasure = treasureHandler pool usr
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
    body_ $ do
      main_ $ do
        header_ $ do
          h1_ "slib OAuthExample"
        p

treasureHandler
  :: Pool SqlBackend
  -> UserClaims
  -> Handler (Html ())
treasureHandler _pool u =
  pure $ p_ [] (fromString $ "Treasure for " <> show u)

app
  :: OAuth
  -> SessionCookies (ReaderT SqlBackend IO)
  -> JWKSCache
  -> Pool SqlBackend
  -> Application
app oauth sessionCookies jwks pool = do
  let
    ctx :: Context (AuthHandler Request UserClaims ': '[])
    ctx = Auth.authHandler oauth sessionCookies pool :. EmptyContext

  genericServeTWithContext
    id
    (apiServer oauth sessionCookies jwks pool)
    ctx

main :: IO ()
main = do
  cfgOAuth <- envConfigOAuth
  cfgJWT <- envConfigJWT
  cfgSession <- envConfigSession

  manager <- newTlsManagerWith tlsManagerSettings

  jwks <- mkJWKSCache cfgJWT manager
  sessionCookies <- mkSessionCookies cfgSession
  let oauth = mkOAuth cfgOAuth manager

  withTemporaryDatabase Db.migrateAll $ \pool ->
    liftIO $ run 8082 $ app oauth sessionCookies jwks pool
