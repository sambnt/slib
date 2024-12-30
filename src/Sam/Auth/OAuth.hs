{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE TupleSections #-}

{-|
Module                  : Sam.Auth.OAuth
Copyright               : (c) 2024-2025 Samuel Evans-Powell
SPDX-License-Identifier : MPL-2.0
Maintainer              : Samuel Evans-Powell <mail@sevanspowell.net>
Stability               : experimental
-}
module Sam.Auth.OAuth where

import Control.Monad.Except (runExceptT)
import Control.Monad.IO.Class (MonadIO)
import Data.Text (Text)
import Network.HTTP.Client qualified as HTTP
import Network.OAuth.OAuth2 (
  ExchangeToken (ExchangeToken),
  OAuth2Token,
  TokenResponseError,
 )
import Network.OAuth2.Experiment (
  AuthorizationCodeApplication,
  CodeVerifier (CodeVerifier),
  IdpApplication,
  conduitPkceTokenRequest,
  mkPkceAuthorizeRequest,
 )
import Sam.Auth.Config.OAuth (ConfigOAuth, cfgOAuthApp, cfgOAuthLogoutURI)
import Sam.Auth.Session.Types (Anonymous (..))
import Sam.Util.URI (URI, fromURIByteString)

data OAuth = OAuth
  { oauthApp :: forall i. IdpApplication i AuthorizationCodeApplication
  , oauthManager :: HTTP.Manager
  , oauthLogoutURI :: Maybe URI
  }

mkOAuth
  :: ConfigOAuth
  -> HTTP.Manager
  -> OAuth
mkOAuth cfg manager =
  OAuth
    { oauthApp = cfgOAuthApp cfg
    , oauthManager = manager
    , oauthLogoutURI = cfgOAuthLogoutURI cfg
    }

startOAuth :: (MonadIO m) => OAuth -> Maybe URI -> m (URI, Anonymous)
startOAuth oauth redirectTo = do
  (signInURI, (CodeVerifier codeVerifier)) <-
    mkPkceAuthorizeRequest $ oauthApp oauth
  pure $
    (fromURIByteString signInURI,) $
      Anonymous
        { anonSessionCodeVerifier = codeVerifier
        , anonSessionRedirect = redirectTo
        }

pkceTokenRequest
  :: (MonadIO m)
  => OAuth
  -> Anonymous
  -> Text
  -> m (Either TokenResponseError OAuth2Token)
pkceTokenRequest oauth anon code =
  runExceptT $
    conduitPkceTokenRequest
      (oauthApp oauth)
      (oauthManager oauth)
      (ExchangeToken code, CodeVerifier $ anonSessionCodeVerifier anon)

logoutURI :: OAuth -> Maybe URI
logoutURI oauth = oauthLogoutURI oauth
