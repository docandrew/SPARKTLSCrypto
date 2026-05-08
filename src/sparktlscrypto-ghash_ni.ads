--  PCLMULQDQ-accelerated GF(2^128) multiplication for GHASH (x86_64).
--
--  GHASH (NIST SP 800-38D) requires GF(2^128) multiplication mod
--  P(x) = x^128 + x^7 + x^2 + x + 1. The portable bit-by-bit
--  implementation in SPARKTLSCrypto.AES_GCM does 128 iterations
--  per block — perf-record on a 1 MB AES-128-GCM bulk transfer
--  showed it at 94% of CPU time.  This module replaces it with
--  PCLMULQDQ (Intel CLMUL extension, available since 2010 on
--  Westmere+ x86_64), which does one carry-less 64-bit multiply
--  per instruction and can do a full 128-bit GF mul + reduction
--  in 6 instructions.
--
--  This module is OUT-OF-SCOPE for SPARK formal verification: it
--  uses inline assembly to issue PCLMULQDQ / PSHUFB / PXOR
--  instructions.  Functional equivalence with the bit-by-bit
--  reference is validated via KAT vectors and a 1024-case random
--  equivalence test (tests/unit/test_ghash_ni.adb).
--
--  Has_PCLMULQDQ is a Constant_After_Elaboration boolean set by a
--  CPUID probe in the body. The dispatch in SPARKTLSCrypto.GHASH
--  picks the PCLMULQDQ path when this is True and falls back to
--  AES_GCM.GF128_Mul (the proven bit-by-bit reference) otherwise.

with SPARKNaCl; use SPARKNaCl;

package SPARKTLSCrypto.GHASH_NI with
   SPARK_Mode => On,
   Elaborate_Body
is
   --  True iff the running CPU advertises PCLMULQDQ (CPUID.01h:ECX[1]).
   --  Set once at elaboration; Constant_After_Elaboration lets SPARK
   --  treat reads from SPARK_Mode=>On callers as side-effect-free.
   Has_PCLMULQDQ : Boolean := False with Constant_After_Elaboration;

   --  Hardware GF(2^128) multiplication: Z = X * Y mod P(x).
   --  X, Y, Z stored in NIST GHASH byte order (byte 0 holds the
   --  highest-degree coefficients).
   function GF128_Mul (X : Bytes_16; Y : Bytes_16) return Bytes_16;

   --================================================================
   --  Aggregated 4-block GHASH ("Algorithm 5" from Gueron's paper)
   --================================================================
   --  Per-block GHASH today is "X' = (X ^ C_i) * H mod P". For long
   --  ciphertexts we can fuse 4 multiplications into one reduction:
   --    X_4 = X_0 * H^4 ^ C1 * H^4 ^ C2 * H^3 ^ C3 * H^2 ^ C4 * H
   --  Pre-compute H, H^2, H^3, H^4 once per AEAD setup; the inner
   --  loop then runs 16 PCLMULQDQ + 1 reduction per 4 blocks instead
   --  of 4 × (4 PCLMULQDQ + reduction) = 16 PCLMULQDQ + 4 reductions.

   --  Layout: H^4 at offset 0, H^3 at 16, H^2 at 32, H at 48.
   --  Each power is stored byte-reversed (PSHUFB-applied) so the
   --  inner loop loads them straight into PCLMULQDQ.
   subtype Pre_H_Powers is Byte_Seq (0 .. 63);

   procedure Compute_H_Powers
     (H        : in     Bytes_16;
      H_Powers :    out Pre_H_Powers);

   --  S := ((S ^ B0) * H^4) ^ (B1 * H^3) ^ (B2 * H^2) ^ (B3 * H)
   --  Blocks must contain exactly 64 bytes (4 ciphertext blocks).
   procedure GHASH_4_Blocks
     (S        : in out Bytes_16;
      Blocks   : in     Byte_Seq;
      H_Powers : in     Pre_H_Powers)
   with Pre => Blocks'Length = 64;

end SPARKTLSCrypto.GHASH_NI;
