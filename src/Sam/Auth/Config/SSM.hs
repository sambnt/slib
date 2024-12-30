{-# LANGUAGE TupleSections #-}

{-|
Module                  : Sam.Auth.Config.SSM
Copyright               : (c) 2024-2025 Samuel Evans-Powell
SPDX-License-Identifier : MPL-2.0
Maintainer              : Samuel Evans-Powell <mail@sevanspowell.net>
Stability               : experimental

This module provides a mechanism for the value of environment variables to be
read from the AWS SSM (AWS Systems Manager) Parameter Store.

Environment variables prefixed with "SSM_", e.g. "SSM_DB_PASSWORD" have their
values interpreted as a Parameter Store path, are read from AWS SSM, and then
we set the environment variable "DB_PASSWORD" with the secret read from the
Parameter Store.

Make sure to call "getSSMEnvironment" before using any code that depends on
finding the decoded SSM environment variables.
-}
module Sam.Auth.Config.SSM (
  getSSMEnvironment,
) where

import Amazonka qualified as AWS
import Amazonka.SSM (newGetParameter)
import Amazonka.SSM.GetParameter (
  getParameterResponse_parameter,
  getParameter_withDecryption,
 )
import Amazonka.SSM.Lens (parameter_value)
import Control.Lens ((&), (?~), (^.))
import Control.Monad (forM_)
import Data.List (stripPrefix)
import Data.Maybe (mapMaybe)
import Data.Text (Text)
import Data.Text qualified as T
import System.Environment (getEnvironment, setEnv)
import System.IO qualified as IO

getSSMEnvironment :: IO ()
getSSMEnvironment = do
  kvs <- mapMaybe (\(k, v) -> (,v) <$> "SSM_" `stripPrefix` k) <$> getEnvironment
  forM_ kvs $ \(k, v) -> do
    let param = T.pack v
    secret <- doGetParameter param
    setEnv k (T.unpack secret)

awsEnvIdentity :: IO AWS.Env
awsEnvIdentity = do
  logger <- AWS.newLogger AWS.Debug IO.stdout
  discoveredEnv <- AWS.newEnv AWS.discover
  let env =
        discoveredEnv
          { AWS.logger = logger
          -- AWS.region = AWS.Sydney
          }
  pure env

doGetParameter :: Text -> IO Text
doGetParameter paramName = do
  env <- awsEnvIdentity
  AWS.runResourceT $ do
    result <-
      AWS.send env $
        newGetParameter paramName
          & getParameter_withDecryption ?~ True
    let param = result ^. getParameterResponse_parameter
    let pVal = param ^. parameter_value
    pure pVal

-- SecureString
