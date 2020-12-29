{-# LANGUAGE RecordWildCards #-}

import Data.Char (chr, ord)
import Data.List (unfoldr)
import Data.Maybe (catMaybes, isJust)
import Data.Word (Word8)
import Ourlude

-- | Represents an alphabetical character, in a way we can easily manipulate.
data Alpha = Alpha Word8

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
  { encryption :: Encryption k,
    decryption :: Decryption k
  }

emptyScheme :: Scheme ()
emptyScheme = Scheme {..}
  where
    encryption = Encryption (\_ (Plaintext alphas) -> Ciphertext alphas)
    decryption = Decryption (\_ (Ciphertext alphas) -> Plaintext alphas)

withFormatting :: Bool -> Scheme k -> k -> String -> String
withFormatting encrypt Scheme {..} k text = output
  where
    (baseFrom, run) =
      if encrypt
        then ('a', Plaintext >>> runEncryption encryption k >>> showCiphertext 'A')
        else ('A', Ciphertext >>> runDecryption decryption k >>> showPlaintext 'a')

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

formattedEncrypt :: Scheme k -> k -> String -> String
formattedEncrypt = withFormatting True

formattedDecrypt :: Scheme k -> k -> String -> String
formattedDecrypt = withFormatting False