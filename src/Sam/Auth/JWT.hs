{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE FlexibleContexts #-}

{- |
Module                  : Sam.Auth.JWT
Copyright               : (c) 2024-2025 Samuel Evans-Powell
SPDX-License-Identifier : MPL-2.0
Maintainer              : Samuel Evans-Powell <mail@sevanspowell.net>
Stability               : experimental
-}

module Sam.Auth.JWT where

import Control.Concurrent.STM.TVar (TVar, newTVarIO, readTVarIO)
import Control.Lens ((.~), (^?), (^.))
import Control.Lens.Prism (_Just)
import Control.Monad.Except (MonadError)
import Control.Monad.IO.Class (MonadIO, liftIO)
import Control.Monad.Time (MonadTime)
import Crypto.JOSE (decodeCompact, HeaderParam (HeaderParam), runJOSE, signatures, header, kid, jwkKid, JWKSet(JWKSet))
import Crypto.JWT (SignedJWT, JWTError, JWK, StringOrURI, defaultJWTValidationSettings, jwtValidationSettingsIssuerPredicate, verifyJWT)
import Data.Function ((&))
import Data.List (find)
import Data.String (fromString)
import Data.Text (Text)
import Network.HTTP.Client (httpLbs, responseBody)
import Network.OAuth.OAuth2 (IdToken, idtoken)
import Sam.Auth.Config.JWT (ConfigJWT, cfgJWTJWKSURL, cfgJWTAud, cfgJWTIss)
import Sam.Auth.JWT.Types (UserClaims)
import Sam.Util.URI (uriToStr, URI)
import Servant (throwError)
import qualified Control.Concurrent.STM as STM
import qualified Data.Aeson as Aeson
import qualified Data.ByteString.Lazy as BSL
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import qualified Network.HTTP.Client as HTTP

data VerifyError = VerifyError Text
                 | VerifyJWTError JWTError
                 deriving (Eq, Show)

data JWKSCache = JWKSCache { jwksCache   :: TVar (Maybe JWKSet)
                           , jwksManager :: HTTP.Manager
                           , jwksURI     :: URI
                           , jwksIss     :: Text
                           , jwksAud     :: Text
                           }

mkJWKSCache
  :: MonadIO m
  => ConfigJWT
  -> HTTP.Manager
  -> m JWKSCache
mkJWKSCache cfg manager = liftIO $ do
  let
    uri = cfgJWTJWKSURL cfg
  eJwks <- fetchJWKS manager (mkRequest uri)
  cache <- case eJwks of
    Left _ -> newTVarIO Nothing
    Right jwks -> newTVarIO (Just jwks)
  pure $ JWKSCache { jwksCache   = cache
                   , jwksManager = manager
                   , jwksURI     = uri
                   , jwksIss     = cfgJWTIss cfg
                   , jwksAud     = cfgJWTAud cfg
                   }

mkRequest :: URI -> HTTP.Request
mkRequest = uriToStr

verifyToken
  :: ( MonadError VerifyError m
     , MonadIO m
     , MonadTime m
     )
  => JWKSCache
  -> IdToken
  -> m UserClaims
verifyToken jwks idToken = do
  jwt <- case decodeCompact $ BSL.fromStrict . TE.encodeUtf8 $ idtoken idToken of
    Left (err :: JWTError) -> throwError $ VerifyJWTError err
    Right jwt -> pure jwt
  eJwk <- retrieveJWK jwks jwt
  case eJwk of
    Left err ->
      throwError $ VerifyError $ "Unable to verify OAuth token: " <> T.pack err
    Right jwk -> do
      let
        iss = fromString $ T.unpack $ jwksIss jwks
        aud = fromString $ T.unpack $ jwksAud jwks
      doJwtVerify jwk aud iss jwt

doJwtVerify
  :: ( MonadTime m
     , MonadError VerifyError m
     )
  => JWK
  -> StringOrURI
  -> StringOrURI
  -> SignedJWT
  -> m UserClaims
doJwtVerify jwk aud iss jwt = do
  let
    config =
      defaultJWTValidationSettings (== aud)
      & jwtValidationSettingsIssuerPredicate .~ (== iss)
  eUserClaims <- runJOSE $ verifyJWT config jwk jwt
  case eUserClaims of
    Left err -> throwError $ VerifyJWTError err
    Right userClaims -> pure userClaims

getJWKForKid :: MonadIO m => JWKSCache -> Text -> m (Maybe JWK)
getJWKForKid jwks vkid = liftIO $ do
  mJWKSet <- readTVarIO $ jwksCache jwks
  case mJWKSet of
    Nothing -> pure Nothing
    Just (JWKSet vjwks) ->
      pure $ find (\jwk -> jwk ^. jwkKid == Just vkid) vjwks

cacheJWKS :: MonadIO m => JWKSCache -> JWKSet -> m ()
cacheJWKS jwks jwkSet = liftIO $
  STM.atomically $ STM.writeTVar (jwksCache jwks) (Just jwkSet)

retrieveJWK
  :: MonadIO m
  => JWKSCache
  -> SignedJWT
  -> m (Either String JWK)
retrieveJWK jwks jwt = do
  case jwt ^? signatures . header . kid . _Just of
    Nothing -> pure $ Left "JWT missing 'kid' header param."
    Just (HeaderParam _ jwtKid) -> do
      mJwk <- getJWKForKid jwks jwtKid
      case mJwk of
        Just jwk -> pure $ Right jwk
        Nothing -> do
          eJwks <- fetchJWKS (jwksManager jwks) (mkRequest $ jwksURI jwks)
          case eJwks of
            Left err -> pure $ Left err
            Right jwkSet -> do
              cacheJWKS jwks jwkSet
              mFinalJwk <- getJWKForKid jwks jwtKid
              case mFinalJwk of
                Nothing -> pure $ Left "No JWK matching JWT"
                Just jwk -> pure $ Right jwk

fetchJWKS
  :: MonadIO m
  => HTTP.Manager
  -> HTTP.Request
  -> m (Either String JWKSet)
fetchJWKS manager request = liftIO $ do
  response <- httpLbs request manager

  let body = responseBody response
  print $ responseBody response

  pure $ Aeson.eitherDecode body
