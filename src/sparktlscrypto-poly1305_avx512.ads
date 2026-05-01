--  AVX-512 Poly1305 (RFC 8439).
--
--  Higher-throughput tier above SPARKTLSCrypto.Poly1305 (the fast
--  scalar 5-limb radix-2²⁶). When the CPU advertises AVX-512F +
--  AVX-512 IFMA, this module takes over the bulk Poly1305 path.
--
--  Strategy: 8 parallel multiplications per round using zmm registers
--  (8 × u64 lanes), precomputed r¹..r⁸. Each batch processes 8 blocks
--  at once. For the first cut we keep the scalar fallback inline so
--  the dispatch is in place; the SIMD backend is filled in
--  incrementally.
--
--  Functional equivalence with SPARKNaCl.MAC.Onetimeauth is verified
--  against the same test vectors used for the scalar fast path
--  (RFC 8439 §2.5.2 KAT + 256 random equivalence cases).

with SPARKNaCl;       use SPARKNaCl;
with SPARKNaCl.MAC;

package SPARKTLSCrypto.Poly1305_AVX512 with
   SPARK_Mode => On,
   Elaborate_Body
is
   --  True iff the running CPU advertises AVX-512F (CPUID.7.0.EBX[16]).
   --  Initialised once at elaboration; SPARK treats reads as
   --  side-effect-free thanks to Constant_After_Elaboration.
   Has_AVX512_Poly1305 : Boolean := False with Constant_After_Elaboration;

   --  True iff the running CPU advertises AVX-512 IFMA52 (CPUID.7.0.EBX[21]).
   --  When true, the 8-block batch dispatches to the IFMA fast path
   --  using vpmadd52luq (one fused multiply-add per limb-row, replacing
   --  vpmuludq+vpaddq pairs).
   Has_AVX512_IFMA     : Boolean := False with Constant_After_Elaboration;

   --  Same signature as the scalar SPARKTLSCrypto.Poly1305.Onetimeauth
   --  so the dispatcher can swap in transparently.
   procedure Onetimeauth
     (Output :    out Bytes_16;
      M      : in     Byte_Seq;
      K      : in     SPARKNaCl.MAC.Poly_1305_Key)
   with Pre => M'Last < N32'Last;

end SPARKTLSCrypto.Poly1305_AVX512;
