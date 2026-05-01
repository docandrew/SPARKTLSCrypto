--  GHASH GF(2^128) multiplication dispatcher.
--
--  Picks the fastest available GHASH path for the running CPU. Today
--  there are two backends:
--    * x86_64 PCLMULQDQ (CPUID.01h:ECX[1])  -> SPARKTLSCrypto.GHASH_NI
--    * portable bit-by-bit fallback         -> AES_GCM.GF128_Mul
--
--  Future backends (ARMv8 PMULL, RISC-V Zk) plug in here without
--  disturbing AES_GCM.  See SPARKTLSCrypto.AES_Dispatch for the
--  parallel pattern used for AES block encryption.
--
--  Functional equivalence with the bit-by-bit reference is verified
--  by tests/unit/test_ghash_ni.adb (NIST KAT + 1024 random
--  equivalence cases).

with SPARKNaCl; use SPARKNaCl;

package SPARKTLSCrypto.GHASH_Dispatch with
   SPARK_Mode => On,
   Elaborate_Body
is

   --  Z = X * Y mod (x^128 + x^7 + x^2 + x + 1).  Inputs/output in
   --  NIST SP 800-38D §6.2 byte ordering (byte 0 holds the low-degree
   --  coefficients).
   function GF128_Mul (X : Bytes_16; Y : Bytes_16) return Bytes_16;
   pragma Inline (GF128_Mul);

end SPARKTLSCrypto.GHASH_Dispatch;
