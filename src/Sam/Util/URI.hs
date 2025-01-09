{-# LANGUAGE GADTs #-}

{-|
Module                  : Sam.Util.URI
Copyright               : (c) 2024-2025 Samuel Evans-Powell
SPDX-License-Identifier : MPL-2.0
Maintainer              : Samuel Evans-Powell <mail@sevanspowell.net>
Stability               : experimental
-}
module Sam.Util.URI (
  URI,
  uriToStr,
  parseURI,
  fromURIByteString,
) where

import Data.Aeson (FromJSON, ToJSON, parseJSON, toJSON, withText)
import Data.ByteString (ByteString)
import Data.ByteString.Char8 qualified as BC8
import Data.String (IsString, fromString)
import Data.Text.Encoding qualified as T
import URI.ByteString (URIParseError)
import URI.ByteString qualified as U

data URI
  = URI (U.URIRef U.Absolute)
  | URIRef (U.URIRef U.Relative)
  deriving (Eq, Show)

instance ToJSON URI where
  toJSON = uriToStr

instance FromJSON URI where
  parseJSON = withText "URI" $ \t ->
    case parseURI (T.encodeUtf8 t) of
      Left e -> fail $ show e
      Right uri -> pure uri

uriToStr :: (IsString a) => URI -> a
uriToStr (URI r) = fromString . BC8.unpack . U.serializeURIRef' $ r
uriToStr (URIRef r) = fromString . BC8.unpack . U.serializeURIRef' $ r

parseURI :: ByteString -> Either URIParseError URI
parseURI bs =
  fmap URI (U.parseURI U.laxURIParserOptions bs)
    <> fmap URIRef (U.parseRelativeRef U.laxURIParserOptions bs)

fromURIByteString :: U.URIRef a -> URI
fromURIByteString uri@(U.URI{}) = URI uri
fromURIByteString uri@(U.RelativeRef{}) = URIRef uri
