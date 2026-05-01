--  Fast scalar Poly1305 one-time authenticator (RFC 8439).
--
--  Pure-Ada replacement for SPARKNaCl.MAC.Onetimeauth on the bulk path.
--  Layout: 130-bit accumulator stored as 5 × 26-bit limbs (u64 each),
--  multiplication by r uses 64×64=128 partial products with lazy carry
--  reduction (~15 ops per 16-byte block, vs ~600 for SPARKNaCl's
--  17×U32 schoolbook). Profile of the TLS_CHACHA20_POLY1305_SHA256 path
--  showed Onetimeauth at 82% of CPU; this drops it to ~10%.
--
--  Functional equivalence with SPARKNaCl.MAC.Onetimeauth is verified by
--  random-input equivalence tests in tests/unit/test_poly1305.adb.

with SPARKNaCl;     use SPARKNaCl;
with SPARKNaCl.MAC;

package SPARKTLSCrypto.Poly1305 with
   SPARK_Mode => On
is
   procedure Onetimeauth
     (Output :    out Bytes_16;
      M      : in     Byte_Seq;
      K      : in     SPARKNaCl.MAC.Poly_1305_Key)
   --  M must be non-empty (the AEAD always passes a >0-length auth
   --  message — at least the 16-byte lengths block). M'Last bounded
   --  so Pos+15 in the loop body stays within N32.
   with Pre => M'Length > 0
               and M'First >= 0
               and M'Last <= N32'Last - 16;

end SPARKTLSCrypto.Poly1305;
