--  AES block-cipher dispatcher.
--
--  Picks the fastest available AES path for the running CPU.  Today
--  there are two backends:
--    * x86_64 AES-NI  (CPUID.01h:ECX[25])  -> SPARKTLSCrypto.AES_NI
--    * portable software fallback           -> SPARKNaCl.AES (proven)
--
--  Future backends (ARMv8 Crypto Extensions, RISC-V Zkne) plug in
--  here without disturbing consumers.  All callers (AES_GCM, ...)
--  go through this dispatcher rather than SPARKNaCl.AES directly,
--  so the underlying choice is invisible at the call site and
--  SPARKNaCl stays untouched and pure.
--
--  Functional equivalence with the software path is verified by
--  tests/unit/test_aes_ni.adb (FIPS 197 KAT + 1024 random
--  equivalence cases per key size).

with SPARKNaCl;       use SPARKNaCl;
with SPARKNaCl.AES;

package SPARKTLSCrypto.AES_Dispatch with
   SPARK_Mode => On,
   Elaborate_Body
is

   procedure Cipher
     (Output     :    out Bytes_16;
      Input      : in     Bytes_16;
      Round_Keys : in     SPARKNaCl.AES.AES128_Round_Keys)
   with Inline;

   procedure Cipher
     (Output     :    out Bytes_16;
      Input      : in     Bytes_16;
      Round_Keys : in     SPARKNaCl.AES.AES256_Round_Keys)
   with Inline;

end SPARKTLSCrypto.AES_Dispatch;
