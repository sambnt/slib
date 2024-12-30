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

import Data.ByteString (ByteString)
import qualified Data.ByteString.Char8 as BC8
import Data.String (IsString, fromString)
import URI.ByteString (URIParseError)
import qualified URI.ByteString as U

data URI
  = URI (U.URIRef U.Absolute)
  | URIRef (U.URIRef U.Relative)
  deriving (Eq, Show)

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
