{-|
Module                  : Sam.Auth.Config.JWT
Copyright               : (c) 2024-2025 Samuel Evans-Powell
SPDX-License-Identifier : MPL-2.0
Maintainer              : Samuel Evans-Powell <mail@sevanspowell.net>
Stability               : experimental
-}
module Sam.Auth.Config.JWT where

import Control.Monad.IO.Class (MonadIO, liftIO)
import Data.Text (Text)
import Data.Text qualified as T
import Data.Text.Encoding qualified as T
import Sam.Util.URI (URI, parseURI)
import System.Environment (getEnv)

data ConfigJWT = ConfigJWT
  { cfgJWTIss :: Text
  , cfgJWTAud :: Text
  , cfgJWTJWKSURL :: URI
  }
  deriving (Eq, Show)

envConfigJWT :: (MonadIO m) => m ConfigJWT
envConfigJWT = liftIO $ do
  iss <- getEnv "JWT_ISSUER"
  aud <- getEnv "JWT_AUD"
  jwksURITxt <- getEnv "JWT_JWKS_URI"

  jwksURI <-
    case parseURI (T.encodeUtf8 $ T.pack jwksURITxt) of
      Left err ->
        error $ "Unable to parse URI from 'JWT_JWKS_URI': " <> show err
      Right uri ->
        pure uri

  pure $
    ConfigJWT
      { cfgJWTAud = T.pack aud
      , cfgJWTIss = T.pack iss
      , cfgJWTJWKSURL = jwksURI
      }
