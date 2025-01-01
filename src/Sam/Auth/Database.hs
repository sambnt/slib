{-|
Module                  : Sam.Auth.Database
Copyright               : (c) 2024-2025 Samuel Evans-Powell
SPDX-License-Identifier : MPL-2.0
Maintainer              : Samuel Evans-Powell <mail@sevanspowell.net>
Stability               : experimental
-}
module Sam.Auth.Database where

import Sam.Auth.Database.Schema qualified as Db
import Database.Esqueleto.Experimental qualified as Db
import Data.Aeson qualified as Aeson
import Data.ByteString.Lazy qualified as BSL
import Data.Text.Encoding qualified as T
import Sam.Auth.JWT.Types (
  UserClaims (..),
  userClaimsEmail,
  userClaimsEmailVerified,
  userClaimsName,
  userClaimsSub,
 )
import Control.Monad.IO.Class (MonadIO)
import Control.Monad.Reader (ReaderT)
import Database.Persist.Postgresql (SqlBackend)
import Data.Maybe (fromJust)

userClaimsFromDb :: Db.Entity Db.UserClaims -> UserClaims
userClaimsFromDb (Db.Entity (Db.UserClaimsKey userId) user) = do
  let
    claims =
      fromJust $
        Aeson.decode $
          BSL.fromStrict $
            T.encodeUtf8 $
              Db.userClaimsClaims user
  UserClaims
    { jwtClaims = claims
    , userClaimsEmail = Db.userClaimsEmail user
    , userClaimsEmailVerified = Db.userClaimsEmailVerified user
    , userClaimsName = Db.userClaimsName user
    , userClaimsSub = userId
    }

upsertUserClaims
  :: MonadIO m
  => UserClaims
  -> ReaderT SqlBackend m Db.UserClaimsId
upsertUserClaims userClaims = do
  let
    userId = Db.UserClaimsKey $ userClaimsSub userClaims
    name = userClaimsName userClaims
    email = userClaimsEmail userClaims
    emailVerified = userClaimsEmailVerified userClaims
    claimsJSON = T.decodeUtf8 . BSL.toStrict . Aeson.encode $ jwtClaims userClaims
    user = Db.UserClaims name email emailVerified claimsJSON
  Db.repsert userId user
  pure userId