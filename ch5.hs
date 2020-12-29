{-# LANGUAGE RecordWildCards #-}

import Data.Char (chr, ord)
import Data.List (unfoldr)
import Data.Maybe (catMaybes, isJust)
import Data.Word (Word8)
import Ourlude

-- | Represents an alphabetical character, in a way we can easily manipulate.
data Alpha = Alpha Word8 deriving (Show)

instance Num Alpha where
  Alpha m + Alpha n = Alpha ((m + n) `mod` 26)
  Alpha m * Alpha n = Alpha ((m * n) `mod` 26)
  negate (Alpha m) = Alpha ((26 - m) `mod` 26)
  fromInteger n = Alpha (fromIntegral (mod (mod n 26 + 26) 26))
  abs = id
  signum _ = Alpha 1

alphaFromBase :: Char -> Char -> Maybe Alpha
alphaFromBase base c =
  let a = ord c - ord base
   in if a >= 0 && a < 26
        then Just (Alpha (fromIntegral a))
        else Nothing

alphaToBase :: Char -> Alpha -> Char
alphaToBase base (Alpha c) =
  let a = fromIntegral c + ord base
   in chr a

-- | Represents a some data that we want to encrypt
newtype Plaintext = Plaintext [Alpha]

showPlaintext :: Char -> Plaintext -> String
showPlaintext base (Plaintext alphas) = map (alphaToBase base) alphas

-- | Represents some encrypted data
newtype Ciphertext = Ciphertext [Alpha]

showCiphertext :: Char -> Ciphertext -> String
showCiphertext base (Ciphertext alphas) = map (alphaToBase base) alphas

-- | Represents a method of encryption
newtype Encryption k = Encryption {runEncryption :: k -> Plaintext -> Ciphertext}

-- | Represents a method of descryption
newtype Decryption k = Decryption {runDecryption :: k -> Ciphertext -> Plaintext}

-- | Represents a cryptographic scheme
--
-- A scheme provides us with a way of encrypting and decrypting data
data Scheme k = Scheme
  { key :: k,
    encryption :: Encryption k,
    decryption :: Decryption k
  }

withFormatting :: Bool -> Scheme k -> String -> String
withFormatting encrypt Scheme {..} text = output
  where
    (baseFrom, run) =
      if encrypt
        then ('a', Plaintext >>> runEncryption encryption key >>> showCiphertext 'A')
        else ('A', Ciphertext >>> runDecryption decryption key >>> showPlaintext 'a')

    converted = map (alphaFromBase baseFrom) text
    runs = getRuns (zip text (map isJust converted))
    output = insertRuns runs (run (catMaybes converted))

    getRuns :: [(Char, Bool)] -> [Either Int String]
    getRuns = (('\NUL', False) :) >>> foldr go (False, "", 0, []) >>> (\(_, _, _, acc) -> acc)
      where
        go (c, isAlpha) (wasAlpha, insert, count, acc) = case (isAlpha, wasAlpha) of
          (False, False) -> (False, c : insert, count, acc)
          (True, True) -> (True, insert, count + 1, acc)
          (True, False) -> (True, "", 1, Right insert : acc)
          (False, True) -> (False, [c], 0, Left count : acc)

    insertRuns :: [Either Int String] -> String -> String
    insertRuns runs input = unfoldr go (runs, input) |> concat
      where
        go :: ([Either Int String], String) -> Maybe (String, ([Either Int String], String))
        go ([], "") = Nothing
        go ([], rest) = Just (rest, ([], ""))
        go (Left i : xs, acc) =
          let produced = take i acc
              st = (xs, drop i acc)
           in Just (produced, st)
        go (Right str : xs, acc) =
          let produced = str
              st = (xs, acc)
           in Just (produced, st)

enc :: Scheme k -> String -> String
enc = withFormatting True

dec :: Scheme k -> String -> String
dec = withFormatting False

emptyScheme :: Scheme ()
emptyScheme = Scheme {..}
  where
    key = ()
    encryption = Encryption (\_ (Plaintext alphas) -> Ciphertext alphas)
    decryption = Decryption (\_ (Ciphertext alphas) -> Plaintext alphas)

caesarScheme :: Alpha -> Scheme Alpha
caesarScheme key = Scheme {..}
  where
    encryption = Encryption (\k (Plaintext alphas) -> Ciphertext (map (+ k) alphas))
    decryption = Decryption (\k (Ciphertext alphas) -> Plaintext (map (\x -> x - k) alphas))