{-# LANGUAGE GADTs #-}
{-# LANGUAGE FlexibleContexts #-}

module QRRepa where

import Data.Aeson
import Data.QRCode
import Data.Word (Word8)
import Data.ByteString.Lazy (toStrict)
import qualified Data.ByteString as BS
import Data.List (replicate)
import Data.Char (toLower)
import Prelude as P
import Crypto.PubKey.RSA as Cr
import Jose.Jws
import System.Directory (doesFileExist)
import Control.Lens.Tuple
import Control.Lens (view)
import Jose.Jwt (unJwt)
import Jose.Jwa (JwsAlg (RS512))
import Data.Either (either)
import Jose.Jwt (JwtError)
import Jose.Jws (rsaDecode)
import Data.Bits ((.&.))
import Data.Array.Repa as R
import Data.Array.Repa.IO.DevIL
import Data.Array.Repa.Eval (fromList)
import Data.Array.Repa.Repr.ForeignPtr (F)
import Data.Array.Repa.Repr.ByteString (fromByteString)
import Control.Monad ((>=>))
import Data.Int (Word8)

checkSig :: BS.ByteString -> IO (Either JwtError BS.ByteString)
checkSig tok = do
    key <- fmap read $ readFile ".key.hk"
    let jws = rsaDecode key tok
    return $ (fmap (view _2)) jws

createSecureQRCode :: (ToJSON a) => a -> FilePath -> IO ()
createSecureQRCode object filepath = make
    where make = do
                    switch <- doesFileExist ".key.hk"
                    if not switch then do
                        putStrLn "generating key..."
                        key <- Cr.generate 512 0x10001
                        writeFile ".key.hk" (show key)
                    else
                        return ()
                    key' <- fmap read $ readFile ".key.hk" :: IO (Cr.PublicKey, Cr.PrivateKey)
                    signedToken <- rsaEncode RS512 (view _2 key') (toStrict $ encode object)
                    let signed = fmap (unJwt) signedToken
                    output <- liftEither id $ fmap (flip byteStringToQR filepath) signed
                    putStrLn $ show output

-- | Lifts IO Either to plain IO and throws exception on a `Left` value.
liftEither :: (Show b, Monad m) => (t -> m a) -> Either b t -> m a
liftEither = either (fail . show)

-- | Enables quick switching between parallel/sequential computations
--consider making this controllable with a command-line flag? i.e. -s for sequential idk
compute = return . computeS --computeP

-- | Write a byteString to file as a .png qr code
byteStringToQR :: BS.ByteString -> FilePath -> IO ()
byteStringToQR input filepath = do
    --smolMatrix <- (fmap toMatrix) $ encodeByteString input Nothing QR_ECLEVEL_H QR_MODE_EIGHT False
    --let qrMatrix = encodePng' smolMatrix
    qrMatrix <- (flip (>>=)) toMatrix' $ encodeByteString input Nothing QR_ECLEVEL_H QR_MODE_EIGHT False
    toWrite <- (scale . fatten . flipper) qrMatrix
    runIL $ writeImage filepath (Grey toWrite)

-- | Scales our array by an integer factor to make the .png useful
scale :: R.Array D DIM2 Word8 -> IO (R.Array F DIM2 Word8)
scale smol = fromFunction sh (\(Z:.x:.y) -> ((view _2) (toFunction smol)) (Z:.(x `div` 8):.(y `div` 8)))
    where sh = (\(Z:.x:.y) -> Z:.((*8) x):.((*8) y)) (extent smol)

-- | Swap black and white, plus make them dark enough ('fatten' the color?)
fatten :: R.Array D DIM2 Word8 -> R.Array D DIM2 Word8
fatten = (R.map ((*255) . swapWord))

-- | Reflects vertically; since otherwise our QR code is upside down
flipper :: R.Array F DIM2 Word8 ->  R.Array D DIM2 Word8
flipper = (\arr -> let l = head . listOfShape $ extent arr in backpermute (extent arr) (\(Z:.x:.y) -> (Z:.(l-x-1):.y)) arr)

-- | Given an object of type QRCode, return an array with its 
--QRCode -> Array F DIM2 Word8
toMatrix' code = copyP $ fromByteString sh (BS.map tobin (getQRCodeString code))
    where sh      = (Z:.dim:.dim)
          dim     = (getQRCodeWidth code)
          tobin c = c .&. 1

--p sure we should delete this, yeah?
--encodePng' :: [[Word8]] -> R.Array U DIM2 Word8
--encodePng' list = fromList sh (concat list)
--    where dim = length list
--          sh  = (Z:.dim:.dim)

-- | Helper function that swaps words so we don't have black/white inverted
swapWord :: Word8 -> Word8
swapWord 1 = 0
swapWord 0 = 1
