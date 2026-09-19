--  CPU feature flags for the accelerated tiers of SPARKTLSCrypto.
--
--  Every hand-written x86_64 tier in this crate (AES-NI, PCLMULQDQ GHASH,
--  the AVX-512 AEAD units, the BMI2/ADX Montgomery multiply) is selected at
--  run time from CPUID and falls back to the proven SPARK implementation
--  when the feature is absent. Portable_Only is the one switch that turns
--  all of them off together; it is a build-time constant (gpr scenario
--  variable SPARKTLSCRYPTO_ASM=disabled, see SPARKTLSCrypto.Tier_Config),
--  so a build either dispatches or runs only the proven code, and which
--  one is visible in the build, not in the process environment. The
--  library reads nothing at run time to decide.
--
--  The CPUID results are captured once at elaboration and never change
--  afterwards (Constant_After_Elaboration), which is what lets SPARK code
--  read them. The body is SPARK_Mode Off: it executes CPUID.

with SPARKTLSCrypto.Tier_Config;

package SPARKTLSCrypto.CPU with
   SPARK_Mode => On,
   Elaborate_Body
is
   --  True in a SPARKTLSCRYPTO_ASM=disabled build: proven code only.
   Portable_Only : constant Boolean := Tier_Config.Portable_Only;

   --  CPUID.(EAX=07H,ECX=0):EBX bit 8 (BMI2: mulx) and bit 19 (ADX:
   --  adcx/adox), both present, and not Portable_Only.
   Has_BMI2_ADX : Boolean := False with Constant_After_Elaboration;

   --  CPUID.(EAX=07H,ECX=0):EBX bit 5 (AVX2), with the OS having enabled
   --  YMM state (CPUID.01H:ECX bit 27 OSXSAVE and XGETBV(0) bits 1..2),
   --  and not Portable_Only. Used by the fixed-base table gather.
   Has_AVX2 : Boolean := False with Constant_After_Elaboration;

end SPARKTLSCrypto.CPU;
