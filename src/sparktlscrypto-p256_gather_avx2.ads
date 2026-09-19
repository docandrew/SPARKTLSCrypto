--  Constant-time fixed-base table lookup for P-256 on AVX2.
--
--  An accelerated tier for the table scan in SPARKTLSCrypto.P256.Point.
--  P256_Mulgen: for one window of SPARKTLSCrypto.P256.Fixed_Base.Fixed_G
--  it reads all 64 entries and keeps the one whose index equals Mag - 1,
--  the selection being a vector compare-and-mask, never an address. Mag
--  is 0 .. 64; for Mag = 0 the result is all zero (the caller treats that
--  window as the identity). Selected only when SPARKTLSCrypto.CPU.Has_AVX2
--  is True; the SPARK scan in P256_Mulgen is the fallback and the
--  reference, and the smoke tests compare the two on every window and
--  magnitude. The body is SPARK_Mode Off (inline assembly).

with SPARKTLSCrypto.P256.Fixed_Base; use SPARKTLSCrypto.P256.Fixed_Base;
with Interfaces;                     use Interfaces;

package SPARKTLSCrypto.P256_Gather_AVX2 with
   SPARK_Mode => On
is
   procedure Gather
     (Dst : out Affine_Mont;
      Row : in  Window_Row;
      Mag : in  Unsigned_32)
   with Pre => Mag <= 64,
        Always_Terminates;

end SPARKTLSCrypto.P256_Gather_AVX2;
