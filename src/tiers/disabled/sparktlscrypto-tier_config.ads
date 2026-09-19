--  Build-time tier configuration, selected by the gpr scenario variable
--  SPARKTLSCRYPTO_ASM through the source directory it adds:
--    enabled          src/tiers/enabled          (default) CPUID dispatch
--    disabled         src/tiers/disabled         proven SPARK code only
--    assume_bmi2_adx  src/tiers/assume_bmi2_adx  test lanes: report the
--                     BMI2/ADX tier present without asking CPUID, so that
--                     Valgrind (whose CPUID lacks the bits) exercises it
--  The library reads nothing at run time to make this decision: no
--  environment, no files, no Ada runtime beyond what the crypto itself
--  needs. The choice is compiled in and auditable in the build.

package SPARKTLSCrypto.Tier_Config with
   SPARK_Mode => On, Pure
is
   Portable_Only   : constant Boolean := True;
   Assume_BMI2_ADX : constant Boolean := False;
end SPARKTLSCrypto.Tier_Config;
