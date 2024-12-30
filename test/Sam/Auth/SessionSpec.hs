{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RankNTypes #-}

module Sam.Auth.SessionSpec where

import Chronos (Time)
import Chronos qualified
import Control.Exception.Safe (MonadMask)
import Control.Monad (join)
import Control.Monad.Logger (runNoLoggingT)
import Control.Monad.Morph (lift)
import Control.Monad.Trans.Resource (MonadUnliftIO)
import Data.Maybe (fromJust)
import Data.Pool (Pool)
import Data.Time.Clock (UTCTime)
import Data.Time.Clock.POSIX (POSIXTime, posixSecondsToUTCTime)
import Database.Persist.Postgresql (SqlBackend, withPostgresqlPool)
import Hedgehog (
  Gen,
  PropertyT,
  Range,
  evalIO,
  forAll,
  (/==),
  (===),
 )
import Hedgehog.Gen qualified as Gen
import Hedgehog.Range qualified as Range
import Sam.Auth.Database.Schema qualified as Db
import Sam.Auth.JWT.Types (UserClaims (..), emptyUserClaims)
import Sam.Auth.Session (mkSessionStoreDb)
import Sam.Auth.Session.Types (
  Anonymous (Anonymous),
  Authenticated (Authenticated),
  EndSession (..),
  GetSession (..),
  NewSession (..),
  Session (..),
  SessionConfig (..),
  SessionData (..),
  SessionId (SessionId),
  SessionResult (..),
  SessionStore (..),
 )
import Sam.Util.Postgres (
  inTransaction,
  withTemporaryDatabase,
 )
import Test.Hspec (Spec, aroundAll, describe, it)
import Test.Hspec.Hedgehog (hedgehog)
import Torsor qualified

-- act :: Applicative f => a -> f a
-- act = pure

assert :: (Applicative m) => PropertyT IO a -> m (PropertyT IO a)
assert = pure

act :: m (PropertyT IO a) -> PropertyT IO (m (PropertyT IO a))
act = pure

arrange
  :: (forall x. m x -> IO x)
  -> PropertyT IO (m (PropertyT IO a))
  -> PropertyT IO a
arrange unlift mkAction = do
  action <- mkAction
  join (evalIO (unlift action))

genUTCTime :: Range POSIXTime -> Gen UTCTime
genUTCTime r = posixSecondsToUTCTime <$> Gen.realFrac_ r

genUTCTime' :: Gen UTCTime
genUTCTime' = genUTCTime $ Range.linearFrac 0 2734487041

genTime :: Gen Time
genTime = Chronos.Time <$> Gen.integral Range.linearBounded

withDatabase
  :: ( MonadMask m
     , MonadUnliftIO m
     )
  => (Pool SqlBackend -> m a)
  -> m a
withDatabase f = withTemporaryDatabase Db.migrateAll $ \conn ->
  runNoLoggingT $ withPostgresqlPool conn 3 (lift . f)

spec :: Spec
spec = do
  aroundAll withDatabase $ do
    describe "SessionStore" $ do
      it "Re-using a session ID to create a new session fails" $ \pool -> do
        arrange (inTransaction pool) $ do
          t <- forAll genTime
          rawId <- forAll $ Gen.text (Range.singleton 64) Gen.unicodeAll
          act $ do
            let
              cfg =
                SessionConfig (Torsor.scale 3 Chronos.second) (Torsor.scale 30 Chronos.second)
              store = mkSessionStoreDb
              anon = Anonymous Nothing "foo"
              sessionId = SessionId rawId
              session1 =
                NewSession
                  { newSessionId = sessionId
                  , newSessionCreatedAt = t
                  , newSessionData = anon
                  }
              session2 = session1
            session1Result <- newSession store cfg session1
            session2Result <- newSession store cfg session2

            assert $ do
              session1Result
                === Just
                  (SessionData sessionId (Torsor.add (Torsor.scale 3 Chronos.second) t) t anon)
              session2Result === Nothing
      it "Authenticating a session changes session ID" $ \pool -> do
        arrange (inTransaction pool) $ do
          t <- forAll genTime
          act $ do
            let
              cfg =
                SessionConfig (Torsor.scale 3 Chronos.second) (Torsor.scale 30 Chronos.second)
              store = mkSessionStoreDb
              anon = Anonymous Nothing "foo"
              sessionId = SessionId "1"
              session1 =
                NewSession
                  { newSessionId = sessionId
                  , newSessionCreatedAt = t
                  , newSessionData = anon
                  }
              session2 = session1
              auth =
                Authenticated $
                  emptyUserClaims
                    { userClaimsSub = "1"
                    }
            anonSession <- newSession store cfg session1

            authSession1 <-
              authenticateSession store cfg sessionId $
                NewSession
                  { newSessionId = sessionId
                  , newSessionCreatedAt = t
                  , newSessionData = auth
                  }
            authSession2 <-
              authenticateSession store cfg sessionId $
                NewSession
                  { newSessionId = SessionId "2"
                  , newSessionCreatedAt = t
                  , newSessionData = auth
                  }

            assert $ do
              authSession1 === Nothing
              authSession2
                === Just
                  ( SessionFound $
                      SessionData
                        (SessionId "2")
                        (Torsor.add (Torsor.scale 3 Chronos.second) t)
                        t
                        auth
                  )
      it "Ending a session removes id from store" $ \pool -> do
        arrange (inTransaction pool) $ do
          t <- forAll genTime
          act $ do
            let
              cfg =
                SessionConfig (Torsor.scale 3 Chronos.second) (Torsor.scale 30 Chronos.second)
              store = mkSessionStoreDb
              anon = Anonymous Nothing "foo"
              sessionId = SessionId "1"
              session1 =
                NewSession
                  { newSessionId = sessionId
                  , newSessionCreatedAt = t
                  , newSessionData = anon
                  }
              session2 = session1
              auth =
                Authenticated $
                  emptyUserClaims
                    { userClaimsSub = "1"
                    }
            anonSession <- newSession store cfg session1
            endSession store cfg $
              EndSession
                { endSessionId = sessionId
                , endSessionAt = t
                }
            sr <-
              getSession store cfg $
                GetSession
                  { getSessionId = sessionId
                  , getSessionAt = t
                  }
            assert $ do
              sr === SessionNotFound
      it "An ended session cannot be authenticated" $ \pool -> do
        arrange (inTransaction pool) $ do
          t <- forAll genTime
          act $ do
            let
              cfg =
                SessionConfig (Torsor.scale 3 Chronos.second) (Torsor.scale 30 Chronos.second)
              store = mkSessionStoreDb
              anon = Anonymous Nothing "foo"
              sessionId = SessionId "1"
              session1 =
                NewSession
                  { newSessionId = sessionId
                  , newSessionCreatedAt = t
                  , newSessionData = anon
                  }
              session2 = session1
              auth =
                Authenticated $
                  emptyUserClaims
                    { userClaimsSub = "1"
                    }
            anonSession <- newSession store cfg session1
            endSession store cfg $
              EndSession
                { endSessionId = sessionId
                , endSessionAt = t
                }
            authSession <-
              authenticateSession store cfg sessionId $
                NewSession
                  { newSessionId = SessionId "2"
                  , newSessionCreatedAt = t
                  , newSessionData = auth
                  }
            oldSession <-
              getSession store cfg $
                GetSession
                  { getSessionId = sessionId
                  , getSessionAt = t
                  }
            assert $ do
              authSession === Nothing
              oldSession === SessionNotFound
      it "An expired session cannot be authenticated" $ \pool -> do
        arrange (inTransaction pool) $ do
          t <- forAll genTime
          act $ do
            let
              cfg =
                SessionConfig (Torsor.scale 3 Chronos.second) (Torsor.scale 30 Chronos.second)
              store = mkSessionStoreDb
              anon = Anonymous Nothing "foo"
              sessionId = SessionId "1"
              session1 =
                NewSession
                  { newSessionId = sessionId
                  , newSessionCreatedAt = t
                  , newSessionData = anon
                  }
              session2 = session1
              auth =
                Authenticated $
                  emptyUserClaims
                    { userClaimsSub = "1"
                    }
            anonSession <- newSession store cfg session1
            authSession <-
              authenticateSession store cfg sessionId $
                NewSession
                  { newSessionId = SessionId "2"
                  , newSessionCreatedAt = Torsor.add (Torsor.scale 4 Chronos.second) t
                  , newSessionData = auth
                  }
            assert $ do
              authSession === Nothing
      it "Getting session increases idle timeout" $ \pool -> do
        arrange (inTransaction pool) $ do
          t <- forAll genTime
          act $ do
            let
              cfg =
                SessionConfig (Torsor.scale 3 Chronos.second) (Torsor.scale 30 Chronos.second)
              store = mkSessionStoreDb
              anon = Anonymous Nothing "foo"
              sessionId = SessionId "1"
              session1 =
                NewSession
                  { newSessionId = sessionId
                  , newSessionCreatedAt = t
                  , newSessionData = anon
                  }
              session2 = session1
              auth =
                Authenticated $
                  emptyUserClaims
                    { userClaimsSub = "1"
                    }
            anonSession <- newSession store cfg session1
            anonSession' <-
              getSession store cfg $
                GetSession
                  { getSessionId = sessionId
                  , getSessionAt = Torsor.add (Torsor.scale 2 Chronos.second) t
                  }
            assert $ do
              let sessionData = fromJust anonSession
              anonSession'
                === ( SessionFound $
                        SessionAnonymous $
                          sessionData
                            { sessionExpiresAt = Torsor.add (Torsor.scale 5 Chronos.second) t
                            }
                    )
      it "Session always expires after absolute timeout" $ \pool -> do
        arrange (inTransaction pool) $ do
          t <- forAll genTime
          act $ do
            let
              cfg =
                SessionConfig (Torsor.scale 10 Chronos.second) (Torsor.scale 30 Chronos.second)
              store = mkSessionStoreDb
              anon = Anonymous Nothing "foo"
              sessionId = SessionId "1"
              session1 =
                NewSession
                  { newSessionId = sessionId
                  , newSessionCreatedAt = t
                  , newSessionData = anon
                  }
              session2 = session1
              auth =
                Authenticated $
                  emptyUserClaims
                    { userClaimsSub = "1"
                    }
            anonSession <- newSession store cfg session1
            s1 <-
              getSession store cfg $
                GetSession
                  { getSessionId = sessionId
                  , getSessionAt = Torsor.add (Torsor.scale 9 Chronos.second) t
                  }
            s2 <-
              getSession store cfg $
                GetSession
                  { getSessionId = sessionId
                  , getSessionAt = Torsor.add (Torsor.scale 18 Chronos.second) t
                  }
            s3 <-
              getSession store cfg $
                GetSession
                  { getSessionId = sessionId
                  , getSessionAt = Torsor.add (Torsor.scale 26 Chronos.second) t
                  }
            anonSession' <-
              getSession store cfg $
                GetSession
                  { getSessionId = sessionId
                  , getSessionAt = Torsor.add (Torsor.scale 30 Chronos.second) t
                  }
            assert $ do
              let sessionData = fromJust anonSession
              s1 /== SessionExpired
              s2 /== SessionExpired
              s3 /== SessionExpired
              anonSession' === SessionExpired
      it "Can end a session multiple times" $ \pool -> do
        arrange (inTransaction pool) $ do
          t <- forAll genTime
          act $ do
            let
              cfg =
                SessionConfig (Torsor.scale 10 Chronos.second) (Torsor.scale 30 Chronos.second)
              store = mkSessionStoreDb
              anon = Anonymous Nothing "foo"
              sessionId = SessionId "1"
              session1 =
                NewSession
                  { newSessionId = sessionId
                  , newSessionCreatedAt = t
                  , newSessionData = anon
                  }
              session2 = session1
              auth =
                Authenticated $
                  emptyUserClaims
                    { userClaimsSub = "1"
                    }
            anonSession <- newSession store cfg session1
            endSession store cfg $
              EndSession
                { endSessionId = sessionId
                , endSessionAt = Torsor.add (Torsor.scale 1 Chronos.second) t
                }
            endSession store cfg $
              EndSession
                { endSessionId = sessionId
                , endSessionAt = Torsor.add (Torsor.scale 100 Chronos.second) t
                }
            assert $ do
              pure ()
      it "Authenticating a session removes old session" $ \pool -> do
        arrange (inTransaction pool) $ do
          t <- forAll genTime
          act $ do
            let
              cfg =
                SessionConfig (Torsor.scale 10 Chronos.second) (Torsor.scale 30 Chronos.second)
              store = mkSessionStoreDb
              anon = Anonymous Nothing "foo"
              sessionId = SessionId "1"
              session1 =
                NewSession
                  { newSessionId = sessionId
                  , newSessionCreatedAt = t
                  , newSessionData = anon
                  }
              session2 = session1
              auth =
                Authenticated $
                  emptyUserClaims
                    { userClaimsSub = "1"
                    }
            anonSession <- newSession store cfg session1
            authSession <-
              authenticateSession store cfg sessionId $
                NewSession
                  { newSessionId = SessionId "2"
                  , newSessionCreatedAt = Torsor.add (Torsor.scale 4 Chronos.second) t
                  , newSessionData = auth
                  }
            anonSession' <-
              getSession store cfg $
                GetSession
                  { getSessionId = sessionId
                  , getSessionAt = Torsor.add (Torsor.scale 5 Chronos.second) t
                  }
            assert $ do
              anonSession' === SessionNotFound
      it "Can't authenticate a non-pre-existing session" $ \pool -> do
        arrange (inTransaction pool) $ do
          t <- forAll genTime
          act $ do
            let
              cfg =
                SessionConfig (Torsor.scale 10 Chronos.second) (Torsor.scale 30 Chronos.second)
              store = mkSessionStoreDb
              anon = Anonymous Nothing "foo"
              sessionId = SessionId "1"
              session1 =
                NewSession
                  { newSessionId = sessionId
                  , newSessionCreatedAt = t
                  , newSessionData = anon
                  }
              session2 = session1
              auth =
                Authenticated $
                  emptyUserClaims
                    { userClaimsSub = "1"
                    }
            authSession <-
              authenticateSession store cfg (SessionId "3") $
                NewSession
                  { newSessionId = SessionId "2"
                  , newSessionCreatedAt = Torsor.add (Torsor.scale 4 Chronos.second) t
                  , newSessionData = auth
                  }
            assert $ do
              authSession === Nothing
