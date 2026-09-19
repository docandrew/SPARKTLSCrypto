--  CPU feature detection (body). See sparktlscrypto-cpu.ads.
--  SPARK_Mode is Off: CPUID.

with Interfaces;          use Interfaces;
with System.Machine_Code; use System.Machine_Code;

package body SPARKTLSCrypto.CPU with
   SPARK_Mode => Off
is
   procedure CPUID (Leaf, Sub : in Unsigned_32;
                    EAX, EBX, ECX, EDX : out Unsigned_32) is
   begin
      Asm ("cpuid",
           Outputs  => (Unsigned_32'Asm_Output ("=a", EAX),
                        Unsigned_32'Asm_Output ("=b", EBX),
                        Unsigned_32'Asm_Output ("=c", ECX),
                        Unsigned_32'Asm_Output ("=d", EDX)),
           Inputs   => (Unsigned_32'Asm_Input ("a", Leaf),
                        Unsigned_32'Asm_Input ("c", Sub)),
           Volatile => True);
   end CPUID;

   function Detect_BMI2_ADX return Boolean is
      EAX, EBX, ECX, EDX : Unsigned_32;
   begin
      --  Highest basic leaf must reach 7 before leaf 7 means anything.
      CPUID (0, 0, EAX, EBX, ECX, EDX);
      if EAX < 7 then
         return False;
      end if;
      CPUID (7, 0, EAX, EBX, ECX, EDX);
      return (EBX and 16#0000_0100#) /= 0      --  bit 8: BMI2
        and then (EBX and 16#0008_0000#) /= 0; --  bit 19: ADX
   end Detect_BMI2_ADX;

   function Detect_AVX2 return Boolean is
      EAX, EBX, ECX, EDX : Unsigned_32;
      XCR0_Lo, XCR0_Hi   : Unsigned_32;
   begin
      CPUID (0, 0, EAX, EBX, ECX, EDX);
      if EAX < 7 then
         return False;
      end if;
      CPUID (1, 0, EAX, EBX, ECX, EDX);
      if (ECX and 16#0800_0000#) = 0 then   --  OSXSAVE
         return False;
      end if;
      Asm ("xgetbv",
           Outputs  => (Unsigned_32'Asm_Output ("=a", XCR0_Lo),
                        Unsigned_32'Asm_Output ("=d", XCR0_Hi)),
           Inputs   => Unsigned_32'Asm_Input ("c", 0),
           Volatile => True);
      pragma Unreferenced (XCR0_Hi);
      if (XCR0_Lo and 16#06#) /= 16#06# then  --  SSE and AVX state enabled
         return False;
      end if;
      CPUID (7, 0, EAX, EBX, ECX, EDX);
      return (EBX and 16#0000_0020#) /= 0;   --  bit 5: AVX2
   end Detect_AVX2;

begin
   Has_AVX2 := (not Portable_Only) and then Detect_AVX2;
   --  Tier_Config.Assume_BMI2_ADX is the test-lane build that skips CPUID
   --  (Valgrind does not advertise the bits but executes the code).
   Has_BMI2_ADX := (not Portable_Only)
     and then (Tier_Config.Assume_BMI2_ADX or else Detect_BMI2_ADX);
end SPARKTLSCrypto.CPU;
