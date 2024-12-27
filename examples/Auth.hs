{-# LANGUAGE TypeOperators #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DataKinds #-}

{- |
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

import Sam.Auth.Api (AuthAPI)
import qualified Sam.Auth.Api as Auth
import qualified Sam.Auth.Database.Schema as Db
import Control.Monad.Reader (ReaderT)
import Servant.API.ContentTypes.Lucid (HTML)
import Control.Monad.IO.Class (liftIO)
import Network.HTTP.Client.TLS (newTlsManagerWith, tlsManagerSettings)
import Network.Wai (Request, Application)
import Network.Wai.Handler.Warp (run)
import Sam.Auth.JWT (mkJWKSCache, JWKSCache)
import Sam.Auth.JWT.Types (UserClaims)
import Sam.Auth.OAuth (mkOAuth, OAuth)
import Sam.Auth.Session.Cookies (mkSessionCookies, SessionCookies)
import Sam.Util.Postgres (withTemporaryDatabase)
import Servant (serveWithContext, Context (EmptyContext, (:.)))
import Servant.Server.Experimental.Auth (AuthHandler)
import Data.Pool (Pool)
import Database.Persist.Sql (SqlBackend, runSqlPool)
import Sam.Auth.Config.JWT (envConfigJWT)
import Sam.Auth.Config.OAuth (envConfigOAuth)
import Sam.Auth.Config.Session (envConfigSession)
import Sam.Auth.Session.Cookies (Cookies(..), getUser)
import Sam.Auth.Session.Types (SessionResult(SessionFound))
import Servant ((:>), Header, Get, Handler, Proxy(Proxy))
import Servant.API (AuthProtect, (:-), NamedRoutes)
import GHC.Generics (Generic)
import Lucid (Html, a_, href_, p_, html_, head_, title_, body_, h1_, header_, main_, doctype_, meta_, charset_, name_, content_)
import Data.String (fromString)

type API = NamedRoutes API'

data API' mode = API'
  { authAPI :: mode :- AuthAPI
  , publicAPI :: mode :- NamedRoutes PublicAPI
  , protectedAPI :: mode :- AuthProtect "cookie-auth" :> NamedRoutes ProtectedAPI
  }
  deriving Generic

data PublicAPI mode = PublicAPI
  { home :: mode :- Header "Cookie" Cookies :> Get '[HTML] (Html ())
  }
  deriving Generic

data ProtectedAPI mode = ProtectedAPI
  { treasure :: mode :- "treasure" :> Get '[HTML] (Html())
  }
  deriving Generic

apiServer oauth sessions jwks pool =
  API' { authAPI = Auth.apiServer oauth sessions jwks pool
       , publicAPI =
           PublicAPI { home = homeHandler pool sessions
                     }
       , protectedAPI = \usr ->
             ProtectedAPI { treasure = treasureHandler pool usr
                          }
       }

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

  serveWithContext
    (Proxy @API)
    ctx
    (apiServer oauth sessionCookies jwks pool)

main :: IO ()
main = do
  cfgOAuth   <- envConfigOAuth
  cfgJWT     <- envConfigJWT
  cfgSession <- envConfigSession

  manager        <- newTlsManagerWith tlsManagerSettings

  jwks           <- mkJWKSCache cfgJWT manager
  sessionCookies <- mkSessionCookies cfgSession
  let oauth       = mkOAuth cfgOAuth manager

  withTemporaryDatabase Db.migrateAll $ \pool ->
    liftIO $ run 8082 $ app oauth sessionCookies jwks pool
