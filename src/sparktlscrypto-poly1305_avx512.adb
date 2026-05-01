--  AVX-512 Poly1305 — body. See spec.
--
--  STATUS: scaffolding tier in place. Implementation strategy is the
--  standard 8-block batched Poly1305 (Goll & Gueron 2015):
--    * Precompute r¹..r⁸ (radix 2⁴⁴ with IFMA, or 2²⁶ with vpmuludq).
--    * For each 8-block batch, compute the 8 contributions
--      h*r⁸ + B0*r⁸ + B1*r⁷ + … + B7*r¹ in parallel using zmm.
--    * Cross-lane horizontal sum to fold the 8 partial accumulators.
--
--  For now `Onetimeauth` defers to the fast scalar path so the
--  dispatch tier is correct; the SIMD body is a TODO.

with System.Machine_Code; use System.Machine_Code;
with Interfaces;          use Interfaces;
with SPARKTLSCrypto.Poly1305;

package body SPARKTLSCrypto.Poly1305_AVX512 with
   SPARK_Mode => Off
is

   --================================================================
   --  CPUID detection: AVX-512F (CPUID.7.0.EBX[16]) +
   --  AVX-512 IFMA52  (CPUID.7.0.EBX[21]).
   --================================================================
   function Detect_AVX512_Poly1305 return Boolean is
      EAX, EBX, ECX, EDX : Unsigned_32;
   begin
      Asm ("cpuid",
           Outputs  => (Unsigned_32'Asm_Output ("=a", EAX),
                        Unsigned_32'Asm_Output ("=b", EBX),
                        Unsigned_32'Asm_Output ("=c", ECX),
                        Unsigned_32'Asm_Output ("=d", EDX)),
           Inputs   => (Unsigned_32'Asm_Input ("a", 7),
                        Unsigned_32'Asm_Input ("c", 0)),
           Volatile => True);
      pragma Unreferenced (EAX, ECX, EDX);
      --  AVX-512F (bit 16) AND AVX-512 IFMA52 (bit 21).
      return (EBX and 16#0001_0000#) /= 0
         and (EBX and 16#0020_0000#) /= 0;
   end Detect_AVX512_Poly1305;

   procedure Onetimeauth
     (Output :    out Bytes_16;
      M      : in     Byte_Seq;
      K      : in     SPARKNaCl.MAC.Poly_1305_Key)
   is
   begin
      --  TODO: replace with batched 8-block AVX-512 IFMA Poly1305.
      --  Current placeholder forwards to the fast scalar
      --  implementation, so the dispatch path is functional and
      --  correct even though the SIMD speedup is not yet realized.
      SPARKTLSCrypto.Poly1305.Onetimeauth (Output, M, K);
   end Onetimeauth;

begin
   Has_AVX512_Poly1305 := Detect_AVX512_Poly1305;
end SPARKTLSCrypto.Poly1305_AVX512;
