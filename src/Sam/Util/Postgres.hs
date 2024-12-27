{- |
Module                  : Sam.Util.Postgres
Copyright               : (c) 2024-2025 Samuel Evans-Powell
SPDX-License-Identifier : MPL-2.0
Maintainer              : Samuel Evans-Powell <mail@sevanspowell.net>
Stability               : experimental
-}

module Sam.Util.Postgres ( withTemporaryDatabase
                         , getMigrationHash
                         , inTransaction
                         , abort
                         ) where

import Control.Monad.IO.Class (liftIO, MonadIO)
import qualified Database.Postgres.Temp as Temp
import qualified Data.Text as T
import qualified Data.Text.Encoding as T
import Data.Pool (Pool)
import Control.Exception.Safe (throwIO, bracket_, MonadMask)
import Database.Persist.Postgresql (withPostgresqlConn, runSqlConn, runMigration, withPostgresqlPool, SqlBackend, rawExecute, runSqlPool, Migration, showMigration)
import Control.Monad.Logger (runNoLoggingT, runStdoutLoggingT)
import qualified Crypto.Hash.SHA256 as SHA256
import qualified Data.ByteString.Base64 as Base64
import Control.Monad.Reader (ReaderT)
import Control.Monad.Trans.Resource (MonadUnliftIO)

inTransaction
  :: (MonadMask m, MonadUnliftIO m)
  => Pool SqlBackend
  -> ReaderT SqlBackend m a
  -> m a
inTransaction pool = (`runSqlPool` pool) . abort

abort
  :: (MonadMask m, MonadIO m)
  => ReaderT SqlBackend m a
  -> ReaderT SqlBackend m a
abort =
  bracket_
  (rawExecute "BEGIN" [])
  (rawExecute "ROLLBACK" [])

-- | Setup a temporary Postgres database.
--
-- The database setup (slow) will only happen once for each database schema.
-- That is, the database schema is cached.
withTemporaryDatabase :: Migration -> (Pool SqlBackend -> IO a) -> IO a
withTemporaryDatabase migration f = do
  -- Helper to throw exceptions
  let throwE x = either throwIO pure =<< x

  throwE $ Temp.withDbCache $ \dbCache -> do
    let
      combinedConfig = Temp.defaultConfig <> Temp.cacheConfig dbCache
    hash <- getMigrationHash migration
    migratedConfig <- throwE $
      Temp.cacheAction
        ("~/.tmp-postgres/" <> hash)
        (migrateDb hash migration)
        combinedConfig
    Temp.withConfig migratedConfig $ \db ->
      runNoLoggingT $
        withPostgresqlPool (Temp.toConnectionString db) 2 $ \pool ->
          liftIO $ f pool

migrateDb :: String -> Migration -> Temp.DB -> IO ()
migrateDb hash migration db = do
  print $ "Migrating database schema with hash: " <> hash
  let theConnectionString = Temp.toConnectionString db

  runStdoutLoggingT $ withPostgresqlConn theConnectionString $ \sqlBackend ->
    flip runSqlConn sqlBackend $
      runMigration migration

-- | Get the SHA256, Base64-encoded hash of the given database migration.
getMigrationHash :: Migration -> IO String
getMigrationHash migration = do
   (either throwIO pure =<<) $ Temp.with $ \db -> do
    let connStr = Temp.toConnectionString db
    runStdoutLoggingT $ withPostgresqlConn connStr $ \sqlBackend ->
      flip runSqlConn sqlBackend $ do
        ls <- showMigration migration
        pure $ T.unpack . T.decodeUtf8 $ Base64.encode $ SHA256.hash $
          foldMap T.encodeUtf8 ls
