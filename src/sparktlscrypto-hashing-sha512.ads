--  SHA-512: instantiation of the SHA-512-family streaming generic with
--  the FIPS 180-4 5.3.5 initial hash value (first 64 bits of the
--  fractional parts of the square roots of the first eight primes).
--  Added for the TLS 1.2 CertificateVerify sha512-family signature
--  schemes (0x0601/0x0806) under the streaming transcript.

with SPARKTLSCrypto.Hashing.SHA512_Family_G;

package SPARKTLSCrypto.Hashing.SHA512 is new
  SPARKTLSCrypto.Hashing.SHA512_Family_G
    (Digest_Bytes => 64,
     IV0 => 16#6A09E667F3BCC908#, IV1 => 16#BB67AE8584CAA73B#,
     IV2 => 16#3C6EF372FE94F82B#, IV3 => 16#A54FF53A5F1D36F1#,
     IV4 => 16#510E527FADE682D1#, IV5 => 16#9B05688C2B3E6C1F#,
     IV6 => 16#1F83D9ABFB41BD6B#, IV7 => 16#5BE0CD19137E2179#);
