--  AVX-512 IFMA Poly1305 — radix-2⁴⁴, 3-limb representation.
--
--  Top tier of the Poly1305 dispatch ladder. Uses the AVX-512 IFMA52
--  instructions (vpmadd52luq / vpmadd52huq) introduced on Intel
--  Cannon Lake / Ice Lake (2018-19) and AMD Zen 4+ (2022).
--
--  Why IFMA + radix-2⁴⁴ together: at the radix-2²⁶ used by the
--  vpmuludq backend, the wraparound products h_i·s_j are 54 bits,
--  exceeding what vpmadd52luq can deliver (it returns the low 52
--  bits and silently truncates). Switching to radix-2⁴⁴ — 3 limbs
--  of 44 bits — keeps every partial product within the IFMA window
--  (88 bits = 52 low + 36 high), so vpmadd52luq + vpmadd52huq
--  together carry the full product. The schoolbook also shrinks
--  from 5×5=25 mul-adds to 3×3=9 — at the cost of a more involved
--  carry chain (d_hi has to be re-aligned with d_lo at the 52-vs-44
--  bit offset).
--
--  Functional equivalence with SPARKNaCl.MAC.Onetimeauth verified
--  by RFC 8439 §2.5.2 KAT and a 256-case randomized equivalence test
--  (tests/unit/test_poly1305_ifma.adb).

with SPARKNaCl;       use SPARKNaCl;
with SPARKNaCl.MAC;
with System;

package SPARKTLSCrypto.Poly1305_AVX512_IFMA with
   SPARK_Mode => On,
   Elaborate_Body
is
   --  True iff the running CPU advertises both AVX-512F (CPUID.7.0.EBX[16])
   --  and AVX-512 IFMA52 (CPUID.7.0.EBX[21]).
   Has_AVX512_IFMA_Poly1305 : Boolean := False with
     Constant_After_Elaboration;

   --  Same signature as SPARKTLSCrypto.Poly1305.Onetimeauth so the
   --  dispatcher can swap in transparently.
   procedure Onetimeauth
     (Output :    out Bytes_16;
      M      : in     Byte_Seq;
      K      : in     SPARKNaCl.MAC.Poly_1305_Key)
   with Pre => M'Last < N32'Last;

   --  Diagnostic: takes a 128-byte message, runs only the asm-side
   --  unpack+limb-extract, writes 3 × 8 × U64 lane-major into M_Out.
   procedure Debug_Unpack
     (Msg   : in  System.Address;
      M_Out : in  System.Address);

end SPARKTLSCrypto.Poly1305_AVX512_IFMA;
