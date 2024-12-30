{-# LANGUAGE DataKinds #-}
{-# LANGUAGE GADTs #-}

{-|
Module                  : Sam.Auth.Session.Types
Copyright               : (c) 2024-2025 Samuel Evans-Powell
SPDX-License-Identifier : MPL-2.0
Maintainer              : Samuel Evans-Powell <mail@sevanspowell.net>
Stability               : experimental
-}
module Sam.Auth.Session.Types where

import Chronos (Time, Timespan)
import Data.Text (Text)
import Sam.Auth.JWT.Types (UserClaims)
import Sam.Util.URI (URI)
import qualified Torsor

type TimeoutSecondsAbsolute = Timespan
type TimeoutSecondsIdle = Timespan

newtype SessionId = SessionId Text
  deriving (Eq, Show)

data SessionResult a
  = SessionExpired
  | SessionNotFound
  | SessionFound a
  deriving (Eq, Ord, Show)

instance Functor SessionResult where
  fmap _ SessionExpired = SessionExpired
  fmap _ SessionNotFound = SessionNotFound
  fmap f (SessionFound a) = SessionFound $ f a

-- TODO: TimeoutFunc = UTCTime -> UTCTime
data SessionConfig
  = SessionConfig
  { sessionTimeoutIdle :: TimeoutSecondsIdle
  , sessionTimeoutAbsolute :: TimeoutSecondsAbsolute
  }

isExpired :: SessionConfig -> Time -> SessionData a -> Bool
isExpired cfg currentTime session =
  let
    idleExpired =
      currentTime
        >= Torsor.add
          (sessionTimeoutAbsolute cfg)
          (sessionCreatedAt session)
    absoluteExpired = currentTime >= sessionExpiresAt session
   in
    idleExpired || absoluteExpired

data SessionData a = SessionData
  { sessionId :: SessionId
  , sessionExpiresAt :: Time
  , sessionCreatedAt :: Time
  , sessionData :: a
  }
  deriving (Eq, Show)

data NewSession a = NewSession
  { newSessionId :: SessionId
  , newSessionCreatedAt :: Time
  , newSessionData :: a
  }
  deriving (Eq, Show)

data GetSession = GetSession
  { getSessionId :: SessionId
  , getSessionAt :: Time
  }
  deriving (Eq, Show)

data EndSession = EndSession
  { endSessionId :: SessionId
  , endSessionAt :: Time
  }
  deriving (Eq, Show)

data Session a b
  = SessionAnonymous (SessionData a)
  | SessionAuthenticated (SessionData b)
  deriving (Eq, Show)

getSessionData :: Session a b -> SessionData ()
getSessionData (SessionAnonymous sd) = sd{sessionData = ()}
getSessionData (SessionAuthenticated sd) = sd{sessionData = ()}

data SessionStore m anon auth
  = SessionStore
  { newSession
      :: SessionConfig
      -> NewSession anon
      -> m (Maybe (SessionData anon))
  , authenticateSession
      :: SessionConfig
      -> SessionId
      -> NewSession auth
      -> m (Maybe (SessionResult (SessionData auth)))
  , getSession
      :: SessionConfig
      -> GetSession
      -> m (SessionResult (Session anon auth))
  , endSession :: SessionConfig -> EndSession -> m ()
  }

data Anonymous = Anonymous
  { anonSessionRedirect :: Maybe URI
  , anonSessionCodeVerifier :: Text
  }
  deriving (Eq, Show)

data Authenticated = Authenticated
  { authUserClaims :: UserClaims
  }
  deriving (Eq, Show)
