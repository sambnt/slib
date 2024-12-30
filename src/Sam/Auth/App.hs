{-# LANGUAGE DataKinds #-}
{-# LANGUAGE TypeOperators #-}

module Sam.Auth.App where

import Control.Monad.IO.Class (liftIO)
import Control.Monad.Reader (ReaderT)
import Data.Pool (Pool)
import Database.Persist.Sql (SqlBackend)
import Network.HTTP.Client.TLS (newTlsManagerWith, tlsManagerSettings)
import Network.Wai (Application, Request, requestHeaders)
import Network.Wai.Handler.Warp (run)
import Sam.Auth.Api (api, apiServer, authHandler)
import Sam.Auth.Config.JWT (ConfigJWT, envConfigJWT)
import Sam.Auth.Config.OAuth (ConfigOAuth, envConfigOAuth)
import Sam.Auth.Config.Session (ConfigSession, envConfigSession)
import qualified Sam.Auth.Database.Schema as Db
import Sam.Auth.JWT (JWKSCache, mkJWKSCache)
import Sam.Auth.JWT.Types (UserClaims)
import Sam.Auth.OAuth (OAuth, mkOAuth)
import Sam.Auth.Session.Cookies (SessionCookies, mkSessionCookies)
import Sam.Util.Postgres (withTemporaryDatabase)
import Servant (Context (EmptyContext, (:.)), serveWithContext)
import Servant.Server.Experimental.Auth (AuthHandler)

app
  :: OAuth
  -> SessionCookies (ReaderT SqlBackend IO)
  -> JWKSCache
  -> Pool SqlBackend
  -> Application
app oauth sessionCookies jwks pool = do
  let
    ctx :: Context (AuthHandler Request UserClaims ': '[])
    ctx = authHandler oauth sessionCookies pool :. EmptyContext

  serveWithContext
    api
    ctx
    (apiServer oauth sessionCookies jwks pool)

runApp :: ConfigOAuth -> ConfigJWT -> ConfigSession -> IO ()
runApp cfgOAuth cfgJWT cfgSession = do
  manager <- newTlsManagerWith tlsManagerSettings

  jwks <- mkJWKSCache cfgJWT manager
  sessionCookies <- mkSessionCookies cfgSession
  let oauth = mkOAuth cfgOAuth manager

  -- TODO: Accept argument for "withSetup", so we can use this in a production
  -- setting too. Maybe accept 'ENV' environment variable, to differentiate
  -- between local and production contexts. Or, if user hasn't provided
  -- PGCONNSTR, then use temporary database.
  withTemporaryDatabase Db.migrateAll $ \pool ->
    liftIO $
      run 8082 $
        logRequestHeaders $
          app oauth sessionCookies jwks pool

main :: IO ()
main = do
  cfgOAuth <- envConfigOAuth
  cfgJWT <- envConfigJWT
  cfgSession <- envConfigSession

  runApp cfgOAuth cfgJWT cfgSession

logRequestHeaders :: Application -> Application
logRequestHeaders incoming request outgoing = do
  let headerList = requestHeaders request
  liftIO $ mapM_ print headerList
  incoming request outgoing
