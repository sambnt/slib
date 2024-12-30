{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE ScopedTypeVariables #-}

{-|
Module                  : Sam.Auth.Config.OAuth
Copyright               : (c) 2024-2025 Samuel Evans-Powell
SPDX-License-Identifier : MPL-2.0
Maintainer              : Samuel Evans-Powell <mail@sevanspowell.net>
Stability               : experimental
-}
module Sam.Auth.Config.OAuth where

import Control.Monad.IO.Class (MonadIO, liftIO)
import qualified Data.ByteString.UTF8 as BSU
import qualified Data.Map as Map
import qualified Data.Set as Set
import qualified Data.Text.Lazy as TL
import Network.OAuth2.Experiment (
  AuthorizationCodeApplication (AuthorizationCodeApplication),
  ClientAuthenticationMethod (ClientSecretPost),
  ClientId (ClientId),
  ClientSecret (ClientSecret),
  Idp (..),
  IdpApplication (IdpApplication),
 )
import Sam.Util.URI (URI, fromURIByteString)
import System.Environment (getEnv, lookupEnv)
import URI.ByteString (laxURIParserOptions, parseURI)
import qualified URI.ByteString as U

data ConfigOAuth
  = ConfigOAuth
  { cfgOAuthApp :: forall i. IdpApplication i AuthorizationCodeApplication
  , cfgOAuthLogoutURI :: Maybe URI
  }

parseURI' :: (MonadIO m) => String -> m U.URI
parseURI' str =
  case parseURI laxURIParserOptions (BSU.fromString str) of
    Left err ->
      error $ show err
    Right uri ->
      pure uri

envConfigOAuth :: (MonadIO m) => m ConfigOAuth
envConfigOAuth = liftIO $ do
  clientId <- ClientId . TL.pack <$> getEnv "OAUTH_CLIENT_ID"
  clientSecret <- ClientSecret . TL.pack <$> getEnv "OAUTH_CLIENT_SECRET"
  redirectURI <- parseURI' =<< getEnv "OAUTH_REDIRECT_URI"
  authURI <- parseURI' =<< getEnv "OAUTH_AUTHORIZE_URI"
  tokenURI <- parseURI' =<< getEnv "OAUTH_TOKEN_URI"
  userInfoURI <- parseURI' =<< getEnv "OAUTH_USERINFO_URI"
  logoutURI <- do
    mUri <- lookupEnv "OAUTH_LOGOUT_URI"
    case mUri of
      Nothing -> pure Nothing
      Just u -> Just <$> parseURI' u

  let
    idProvider =
      Idp
        { idpUserInfoEndpoint = userInfoURI
        , idpAuthorizeEndpoint = authURI
        , idpTokenEndpoint = tokenURI
        , idpDeviceAuthorizationEndpoint = Nothing -- Not using device code flow
        }
    appName = ""
    requiredScopes = Set.empty
    -- Use PKCE instead of state, it already protects against CSRF https://danielfett.de/2020/05/16/pkce-vs-nonce-equivalent-or-not/
    state = ""
    app =
      AuthorizationCodeApplication
        appName
        clientId
        clientSecret
        requiredScopes
        redirectURI
        state
        Map.empty
        ClientSecretPost
  pure $
    ConfigOAuth
      { cfgOAuthApp = IdpApplication idProvider app
      , cfgOAuthLogoutURI = fromURIByteString <$> logoutURI
      }
