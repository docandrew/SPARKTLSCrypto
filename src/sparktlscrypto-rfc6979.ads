--  RFC 6979 deterministic ECDSA nonce generation.
--
--  Replaces the per-signature CSPRNG nonce with a deterministic K
--  derived from HMAC_DRBG(private_key || message_hash). This is what
--  every modern ECDSA implementation does (libsecp256k1, BoringSSL,
--  OpenSSL ≥ 1.1). Three benefits:
--
--    1. K is always in [1, q-1] by construction → no validation
--       branch in ECDSA.Sign → no constant-time leak of K's range.
--    2. No CSPRNG dependency per signature — a CSPRNG failure can't
--       cause repeated nonces (the Sony PS3 / Bitcoin wallet class
--       of disaster).
--    3. Reproducible signatures simplify testing and debugging.
--
--  This module exposes one derivation function per supported curve.
--  The output K is in [1, q-1] when OK is True; callers should abort
--  signing when OK is False. Internally, candidate selection is
--  bounded and branchless to avoid leaking retry decisions.

with SPARKNaCl; use SPARKNaCl;

package SPARKTLSCrypto.RFC6979 with
   SPARK_Mode => On
is

   --  Derive the per-signature nonce K for ECDSA-P-256.
   --    D : private key scalar (32 bytes, big-endian, in [1, n-1])
   --    H : message digest (32 bytes — typically SHA-256 of message)
   --    K : output nonce, big-endian, in [1, n-1]
   --  Internally uses HMAC-SHA-256 as the DRBG primitive.
   procedure Derive_K_P256
     (D :     Bytes_32;
      H :     Bytes_32;
      K : out Bytes_32;
      OK : out Boolean);

   --  Derive the per-signature nonce K for ECDSA-P-384.
   --    D : private key scalar (48 bytes, big-endian, in [1, n-1])
   --    H : message digest (48 bytes — typically SHA-384 of message)
   --    K : output nonce, big-endian, in [1, n-1]
   --  Internally uses HMAC-SHA-384 as the DRBG primitive.
   procedure Derive_K_P384
     (D :     Bytes_48;
      H :     Bytes_48;
      K : out Bytes_48;
      OK : out Boolean);

end SPARKTLSCrypto.RFC6979;
