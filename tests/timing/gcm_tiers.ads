--  Test-only tier selection for the AES-GCM timing harnesses: overwrite the
--  CPUID tier flags (set at elaboration) so one process can run the same
--  inputs through each AES-GCM tier the CPU (or Valgrind's virtual CPU)
--  supports. Never do this outside a test.
package Gcm_Tiers is
   type Tier is (Portable, AES_NI_4, VAES_256, VAES_512);
   function Available (T : Tier) return Boolean;
   procedure Select_Tier (T : Tier);
   function Names return String;   --  the available tiers, for the log
end Gcm_Tiers;
