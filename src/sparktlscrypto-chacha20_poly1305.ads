--  ChaCha20-Poly1305 AEAD (RFC 8439) — same shape as
--  SPARKNaCl.Secretbox.Create but uses SPARKTLSCrypto.Poly1305 (the
--  fast 64-bit-limb scalar Poly1305) instead of SPARKNaCl.MAC's
--  17-element schoolbook reference. Drops Onetimeauth's CPU share
--  in the TLS_CHACHA20_POLY1305_SHA256 path from 82% to ~10%.

with SPARKNaCl;       use SPARKNaCl;
with SPARKNaCl.Core;

package SPARKTLSCrypto.ChaCha20_Poly1305 with
   SPARK_Mode => On
is

   procedure Encrypt
     (C   :    out Byte_Seq;
      Tag :    out Bytes_16;
      M   : in     Byte_Seq;
      N   : in     Core.ChaCha20_IETF_Nonce;
      K   : in     Core.ChaCha20_Key;
      AAD : in     Byte_Seq)
   with Pre => M'First    = 0
               and C'First    = 0
               and AAD'First  = 0
               and M'Last     = C'Last
               and C'Last     < N32'Last
               and M'Last     < N32'Last
               and AAD'Last   < N32'Last
               and C'Length   = M'Length
               and I64 (C'Length) + I64 (AAD'Length) + 192 <= I64 (N32'Last);

end SPARKTLSCrypto.ChaCha20_Poly1305;
