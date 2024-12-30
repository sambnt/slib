{-|
Module                  : Sam.Auth.JWT.Types
Copyright               : (c) 2024-2025 Samuel Evans-Powell
SPDX-License-Identifier : MPL-2.0
Maintainer              : Samuel Evans-Powell <mail@sevanspowell.net>
Stability               : experimental
-}
module Sam.Auth.JWT.Types where

import Crypto.JWT (ClaimsSet, HasClaimsSet, claimsSet, emptyClaimsSet)
import Data.Aeson (FromJSON, ToJSON, parseJSON, toJSON, (.:))
import qualified Data.Aeson as Aeson
import qualified Data.Aeson.KeyMap as M
import Data.Function ((&))
import Data.Text (Text)

data UserClaims = UserClaims
  { jwtClaims :: ClaimsSet
  , userClaimsEmail :: Text
  , userClaimsEmailVerified :: Bool
  , userClaimsName :: Text
  , userClaimsSub :: Text
  }
  deriving (Eq, Show)

instance HasClaimsSet UserClaims where
  claimsSet f s = fmap (\a' -> s{jwtClaims = a'}) (f (jwtClaims s))

instance FromJSON UserClaims where
  parseJSON = Aeson.withObject "UserClaims" $ \o ->
    UserClaims
      <$> Aeson.parseJSON (Aeson.Object o)
      <*> o .: "email"
      <*> o .: "email_verified"
      <*> o .: "name"
      <*> o .: "sub"

instance ToJSON UserClaims where
  toJSON s =
    Aeson.toJSON (jwtClaims s)
      & ins "email" (userClaimsEmail s)
      & ins "email_verified" (userClaimsEmailVerified s)
      & ins "name" (userClaimsName s)
      & ins "sub" (userClaimsSub s)
   where
    ins k v (Aeson.Object o) = Aeson.Object $ M.insert k (Aeson.toJSON v) o
    ins _ _ a = a

emptyUserClaims :: UserClaims
emptyUserClaims =
  UserClaims
    { jwtClaims = emptyClaimsSet
    , userClaimsEmail = ""
    , userClaimsEmailVerified = False
    , userClaimsName = ""
    , userClaimsSub = ""
    }
