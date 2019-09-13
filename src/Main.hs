{-# LANGUAGE LambdaCase, OverloadedStrings #-}

module Main where

import           Control.Concurrent.STM
import           Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as Char8 (pack, snoc, unpack)
import           Data.ByteString.Lex.Fractional (readDecimal)
import           Data.IntMap.Strict (IntMap)
import qualified Data.IntMap.Strict as M
import           Data.Maybe (fromMaybe)
import           Data.Time.Clock
import           Data.Time.Clock.POSIX (posixSecondsToUTCTime)
import           Data.Time.Format
import           Data.Time.LocalTime
import           Data.Word (Word32)
import           System.IO.Streams (InputStream)
import qualified System.IO.Streams as Streams
import           Network.Pcap
import           System.Console.GetOpt
import           System.Environment
import           System.Exit
import           Text.Printf

type RawPacket = (UTCTime, ByteString)

data Packet = Packet { time  :: UTCTime
                     , quote :: Quote } deriving Show

data Quote = Quote { issueCode       :: ByteString
                   , bidsAndAsks     :: ByteString
                   , quoteAcceptTime :: UTCTime } deriving Show

streamPackets :: PcapHandle -> IO (InputStream RawPacket)
streamPackets handle = Streams.makeInputStream (nextBS handle >>= toRawPacket)
  where
    toRawPacket :: (PktHdr, ByteString) -> IO (Maybe RawPacket)
    toRawPacket (PktHdr 0 0 0 0, _) = return Nothing
    toRawPacket (header, content)   = return $ Just (mkTuple header content)

    mkTuple :: PktHdr -> ByteString -> RawPacket
    mkTuple header raw =
      ( formatPTime (hdrSeconds header) (hdrUseconds header)
      , BS.init $ BS.drop (BS.length raw - 215) raw )

    formatPTime :: Word32 -> Word32 -> UTCTime
    formatPTime s ms = addUTCTime (fromIntegral ms / 1000000)
                                  (posixSecondsToUTCTime $ fromIntegral s)

filterQuotePackets :: InputStream RawPacket -> IO (InputStream RawPacket)
filterQuotePackets = Streams.filter (\(_, raw) -> BS.isPrefixOf "B6034" raw)

convert2QuotePacket :: InputStream RawPacket -> IO (InputStream Packet)
convert2QuotePacket src = Streams.makeInputStream (Streams.read src >>= go)  
  where    
    go Nothing = return Nothing
    go (Just rawPacket@(_, raw)) =
      if isValidPacket raw
        then return (Just $ mkPacket rawPacket)
        else do
          putStrLn "Malformed packet: "
          Streams.write (Just (raw `Char8.snoc` '\n')) Streams.stderr
          return Nothing

    isValidPacket :: ByteString -> Bool
    isValidPacket raw =  all isValid
                      $  toDouble . slice raw
                     <$> tail quotePacketFormat

    toDouble :: ByteString -> Maybe (Double, ByteString)
    toDouble = readDecimal

    isValid :: Maybe (Double, ByteString) -> Bool
    isValid Nothing       = False
    isValid (Just (_, b)) = BS.null b

    mkPacket :: RawPacket -> Packet
    mkPacket (pTime, raw) = Packet pTime (mkQuote raw)

quotePacketFormat :: [(Int, Int)]
quotePacketFormat = [ (5,  12),(29, 5),(34, 7),(41, 5),(46, 7),(53, 5),(58, 7)
                    , (65,  5),(70, 7),(77, 5),(82, 7),(96, 5),(101,7),(108,5)
                    , (113, 7),(120,5),(125,7),(132,5),(137,7),(144,5),(149,7)
                    , (206, 8) ]

mkQuote :: ByteString -> Quote
mkQuote raw = Quote mkIssueCode (mkBidsAndAsks raw) mkQuoteAcceptTime
  where
    mkIssueCode :: ByteString
    mkIssueCode = slice raw $ head quotePacketFormat

    mkBidsAndAsks :: ByteString -> ByteString
    mkBidsAndAsks raw' =
      let vs   = (formatAmount . slice raw') <$> (init . tail) quotePacketFormat
          bids = BS.intercalate " " $ reverse $ glue [] $ take 10 vs
          asks = BS.intercalate " " $ glue [] $ drop 10 vs
      in BS.concat [bids, asks]

    mkQuoteAcceptTime :: UTCTime
    mkQuoteAcceptTime = (formatHHMMSSuu . slice raw) $ last quotePacketFormat

    formatAmount :: ByteString -> ByteString
    formatAmount a =
      let mv = readDecimal a :: Maybe (Double, ByteString)
      in case mv of
          Nothing     -> "NaN" -- can't happen: already checked above
          Just (v, _) -> Char8.pack $ printf "%.2f" $ twoDigits v

    twoDigits :: Double -> Double
    twoDigits d = fromInteger (round (d * 100)) / 100

    glue :: [ByteString] -> [ByteString] -> [ByteString]
    glue result [] = result
    glue result vs =
      let [quantity, price] = take 2 vs
      in glue (BS.concat [quantity, "@", price] : result) (drop 2 vs)

    formatHHMMSSuu :: ByteString -> UTCTime
    formatHHMMSSuu raw' =
      let t  = Char8.unpack $ BS.concat [BS.take 6 raw', ".", BS.drop 6 raw']
          mt = parseTimeM False defaultTimeLocale "%H%M%S%Q" t :: Maybe UTCTime
      in fromMaybe (posixSecondsToUTCTime 0) mt

slice :: ByteString -> (Int, Int) -> ByteString
slice raw (start, fieldLength) = let (_, match) = BS.splitAt start raw
                                 in BS.take fieldLength match

format :: Packet -> ByteString
format packet =
  BS.intercalate " " [ formatPacketTime $ time packet
                     , Char8.pack $ formatTime defaultTimeLocale "%T%2Q"
                                  $ quoteAcceptTime $ quote packet
                     , issueCode $ quote packet
                     , bidsAndAsks $ quote packet ]
  where
    formatPacketTime :: UTCTime -> ByteString
    formatPacketTime pTime =
        Char8.pack
      -- packet time is formatted with 6 digits to show ordering
      $ formatTime defaultTimeLocale "%T%6Q"
      -- Japan is GMT+9 => 9*60 = 540
      $ utcToLocalTime (minutesToTimeZone 540) pTime

type Buffer = IntMap (IntMap Packet)

orderByQAT :: TVar Buffer -> InputStream Packet -> IO (InputStream ByteString)
orderByQAT tvar src = Streams.makeInputStream (Streams.read src >>= go)
  where
    go Nothing = do
      buffer <- atomically (readTVar tvar)
      if M.null buffer
        then return Nothing
        else do
          atomically $ modifyTVar' tvar (const M.empty)
          _ <- Streams.nullInput
          return $ Just $ flush buffer
    go (Just packet) = do
      buffer <- atomically (readTVar tvar)
      let buffer' = insert packet buffer
      buffer'' <- peek (\a -> a < qatPlus3Seconds buffer')
                       (deleteFirst buffer')
      atomically $ modifyTVar' tvar (const buffer'')
      return $ Just
             $ BS.intercalate "\n" (format <$> M.elems (head $ M.elems buffer'))

    flush :: Buffer -> ByteString
    flush b = BS.init
          $ foldMap (foldMap (\ packet -> format packet `Char8.snoc` '\n')) b

    insert :: Packet -> Buffer -> Buffer
    insert packet buffer =
      let (pt, qat) = keys packet
          innerMap  = M.lookup qat buffer
      in case innerMap of
        Nothing -> M.insert qat (M.singleton pt packet) buffer
        Just im -> M.adjust (const $ M.insert pt packet im) qat buffer

    keys :: Packet -> (Int, Int)
    keys p = ( floor $ (* 1000000) $ utctDayTime (time p)
             , floor $ (* 100) $ utctDayTime $ quoteAcceptTime (quote p) )

    getFirst :: Buffer -> Packet
    getFirst = head . M.elems . head . M.elems

    deleteFirst :: Buffer -> Buffer
    deleteFirst b = M.delete (head $ M.keys b) b

    peek :: (Int -> Bool) -> Buffer -> IO Buffer
    peek p buffer = Streams.read src >>= \case
      Nothing     -> return buffer
      Just packet -> if p (toInt $ quoteAcceptTime $ quote packet)
        then peek p (insert packet buffer)
        else do
          Streams.unRead packet src
          return buffer

    qatPlus3Seconds :: Buffer -> Int
    qatPlus3Seconds buffer =
      toInt $ addUTCTime 3 (quoteAcceptTime $ quote $ getFirst buffer)

    toInt :: UTCTime -> Int
    toInt = floor . (* 100) . utctDayTime

options :: [OptDescr (Bool -> Bool)]
options = [Option "r" [] (NoArg $ const True) "order by quote accept time"]

main :: IO ()
main = getOpt Permute options <$> getArgs >>= \case
  (fs, [file], []) -> do
    let order = foldl (flip id) False fs
    h <- openOffline file
    let ipmask = 0 :: Word32
    setFilter h "len >= 215" True ipmask -- 215: Quote Packet payload
    tvar <- newTVarIO M.empty
    is <- streamPackets h     >>=
          filterQuotePackets  >>=
          convert2QuotePacket >>=
          (\is -> if order
            then orderByQAT tvar is
            else Streams.map format is)
    os <- Streams.unlines Streams.stdout
    Streams.connect is os

  (_, _, es) -> do
    name <- getProgName
    die $ unlines ((name ++ " [-r] PCAP_FILE") : es) ++ usageInfo name options
