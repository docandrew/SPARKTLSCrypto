--  SHA-384: instantiation of the SHA-512-family streaming generic with
--  the FIPS 180-4 5.3.4 initial hash value. KATs: 8/8, see
--  tests/unit/test_sha384_streaming_kat.adb.

with SPARKTLSCrypto.Hashing.SHA512_Family_G;

package SPARKTLSCrypto.Hashing.SHA384 is new
  SPARKTLSCrypto.Hashing.SHA512_Family_G
    (Digest_Bytes => 48,
     IV0 => 16#CBBB9D5DC1059ED8#, IV1 => 16#629A292A367CD507#,
     IV2 => 16#9159015A3070DD17#, IV3 => 16#152FECD8F70E5939#,
     IV4 => 16#67332667FFC00B31#, IV5 => 16#8EB44A8768581511#,
     IV6 => 16#DB0C2E0D64F98FA7#, IV7 => 16#47B5481DBEFA4FA4#);
