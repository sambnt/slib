{-# LANGUAGE ScopedTypeVariables #-}

{- |
Module                  : Sam.Auth.Config.Session
Copyright               : (c) 2024-2025 Samuel Evans-Powell
SPDX-License-Identifier : MPL-2.0
Maintainer              : Samuel Evans-Powell <mail@sevanspowell.net>
Stability               : experimental
-}

module Sam.Auth.Config.Session where

import Control.Monad.IO.Class (MonadIO, liftIO)
import Data.Int (Int64)
import Chronos (Timespan)
import Data.Text (Text)
import qualified Chronos
import qualified Torsor
import Text.Read (readMaybe)
import qualified Data.Text as T
import System.Environment (lookupEnv, getEnv)
import Data.Maybe (fromMaybe)

import Sam.Auth.Session.Types (TimeoutSecondsAbsolute, TimeoutSecondsIdle)

data IsSecure = Secure
              | NotSecure
  deriving (Eq, Show)

isSecure :: IsSecure -> Bool
isSecure Secure    = True
isSecure NotSecure = False

data ConfigSession
  = ConfigSession { cfgSessionSecureCookies   :: IsSecure
                  , cfgSessionCookieName      :: Text
                  , cfgSessionTimeoutIdle     :: TimeoutSecondsIdle
                  , cfgSessionTimeoutAbsolute :: TimeoutSecondsAbsolute
                  }
  deriving (Eq, Show)

envConfigSession :: MonadIO m => m ConfigSession
envConfigSession = liftIO $ do
  timeoutAbsolute <-
    parseTimespanSeconds =<< getEnv "SESSION_TIMEOUT_SECONDS_ABSOLUTE"
  timeoutIdle <-
    parseTimespanSeconds =<< getEnv "SESSION_TIMEOUT_SECONDS_IDLE"
  secure <-
    maybe Secure (const NotSecure) <$> lookupEnv "SESSION_INSECURE"
  cookieName <-
    fromMaybe "id" <$> lookupEnv "SESSION_COOKIE_NAME"

  pure $ ConfigSession { cfgSessionSecureCookies = secure
                       , cfgSessionCookieName = T.pack cookieName
                       , cfgSessionTimeoutIdle = timeoutIdle
                       , cfgSessionTimeoutAbsolute = timeoutAbsolute
                       }

parseTimespanSeconds :: MonadIO m => String -> m Timespan
parseTimespanSeconds str = do
  case readMaybe str of
    Nothing -> error $ "Couldn't parse Int64 from '" <> str <> "'."
    Just (t :: Int64) -> pure $ Torsor.scale t Chronos.second
