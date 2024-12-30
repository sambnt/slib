{-|
Module                  : Sam.Util.Postgres
Copyright               : (c) 2024-2025 Samuel Evans-Powell
SPDX-License-Identifier : MPL-2.0
Maintainer              : Samuel Evans-Powell <mail@sevanspowell.net>
Stability               : experimental
-}
module Sam.Util.Postgres (
  withTemporaryDatabase,
  getMigrationHash,
  inTransaction,
  abort,
) where

import Control.Exception.Safe (MonadMask, bracket, bracket_, throwIO)
import Control.Monad.IO.Class (MonadIO, liftIO)
import Control.Monad.Logger (runStdoutLoggingT)
import Control.Monad.Reader (ReaderT)
import Control.Monad.Trans.Resource (MonadUnliftIO)
import Crypto.Hash.SHA256 qualified as SHA256
import Data.ByteString.Base64 qualified as Base64
import Data.Pool (Pool)
import Data.Text qualified as T
import Data.Text.Encoding qualified as T
import Database.Persist.Postgresql (
  ConnectionString,
  Migration,
  SqlBackend,
  rawExecute,
  runMigration,
  runSqlConn,
  runSqlPool,
  showMigration,
  withPostgresqlConn,
 )
import Database.Postgres.Temp qualified as Temp

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
withTemporaryDatabase
  :: ( MonadMask m
     , MonadIO m
     )
  => Migration
  -> (ConnectionString -> m a)
  -> m a
withTemporaryDatabase migration f = do
  -- Helper to throw exceptions
  let throwE x = either (liftIO . throwIO) pure =<< x

  throwE $ withDbCacheConfig Temp.defaultCacheConfig $ \dbCache -> do
    let
      combinedConfig = Temp.defaultConfig <> Temp.cacheConfig dbCache
    hash <- liftIO $ getMigrationHash migration
    migratedConfig <-
      liftIO $
        throwE $
          Temp.cacheAction
            ("~/.tmp-postgres/" <> hash)
            (migrateDb hash migration)
            combinedConfig
    withConfig migratedConfig $ \db ->
      f (Temp.toConnectionString db)

withConfig
  :: (MonadMask m, MonadIO m)
  => Temp.Config
  -> (Temp.DB -> m b)
  -> m (Either Temp.StartError b)
withConfig extra f =
  bracket
    (liftIO $ Temp.startConfig extra)
    (either (const $ pure ()) (liftIO . Temp.stop))
    $ either (pure . Left) (fmap Right . f)

withDbCacheConfig
  :: (MonadMask m, MonadIO m)
  => Temp.CacheConfig
  -- ^ Configuration
  -> (Temp.Cache -> m a)
  -- ^ action for which caching is enabled
  -> m a
withDbCacheConfig config =
  bracket
    (liftIO $ Temp.setupInitDbCache config)
    (liftIO . Temp.cleanupInitDbCache)

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
        pure $
          T.unpack . T.decodeUtf8 $
            Base64.encode $
              SHA256.hash $
                foldMap T.encodeUtf8 ls
