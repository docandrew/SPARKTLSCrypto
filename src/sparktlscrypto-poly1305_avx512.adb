--  AVX-512 Poly1305 — 8-block batched, lane-major SIMD.
--
--  Strategy (Goll & Gueron 2015, "Vectorization of Poly1305 MAC"):
--  Pre-compute r¹..r⁸. For each batch of 8 blocks B0..B7, compute in
--  parallel across 8 zmm lanes:
--    lane 0 = (h_prev + B0) * r⁸
--    lane 1 = B1 * r⁷
--    lane 2 = B2 * r⁶
--    ...
--    lane 7 = B7 * r¹
--  Horizontal sum across the 8 lanes gives the new h_prev. Folded
--  with the standard rolling-accumulator identity:
--    h_new = ((((h_prev + B0)*r + B1)*r + ... + B7)*r
--          = h_prev*r⁸ + B0*r⁸ + B1*r⁷ + … + B7*r¹
--
--  Tail (< 128 bytes) defers to scalar Poly1305.Process_Block — but
--  rather than re-implement that here we just hand the residual chunk
--  to the scalar fast Poly1305 with a starting accumulator. That keeps
--  this module focused on the bulk SIMD path.
--
--  Multiplications use vpmuludq (AVX-512F, no IFMA needed) — each
--  scalar 26-bit × 26-bit → 52-bit fits in u64. 25 vpmuludq + 20
--  vpaddq + carry chain per 8-block batch ≈ 70 SIMD ops / 128 bytes
--  ≈ 0.5 cycle/byte ≈ 6+ GB/s for Poly1305 alone (sufficient to
--  match OpenSSL on TLS_CHACHA20_POLY1305_SHA256).

with System.Machine_Code; use System.Machine_Code;
with Interfaces;          use Interfaces;
with SPARKNaCl.MAC;
with SPARKTLSCrypto.Poly1305;

package body SPARKTLSCrypto.Poly1305_AVX512 with
   SPARK_Mode => Off
is

   subtype U64 is Unsigned_64;
   subtype U32 is Unsigned_32;

   --  Mask for one 26-bit limb.
   M26 : constant U64 := 16#03FF_FFFF#;

   --================================================================
   --  CPUID detection: returns (Has_AVX512F, Has_AVX512_IFMA).
   --  AVX-512F bit = CPUID.7.0.EBX[16]; IFMA bit = CPUID.7.0.EBX[21].
   --================================================================
   procedure Detect_AVX512_Poly1305 (F, IFMA : out Boolean) is
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
      F    := (EBX and 16#0001_0000#) /= 0;  --  AVX-512F bit 16
      IFMA := (EBX and 16#0020_0000#) /= 0;  --  AVX-512_IFMA bit 21
   end Detect_AVX512_Poly1305;

   --================================================================
   --  Single 5-limb multiply mod 2^130-5 (used to compute r^k).
   --================================================================
   procedure Mul_5limb
     (h0, h1, h2, h3, h4 : in out U64;
      r0, r1, r2, r3, r4 : in     U64)
   is
      s1 : constant U64 := r1 * 5;
      s2 : constant U64 := r2 * 5;
      s3 : constant U64 := r3 * 5;
      s4 : constant U64 := r4 * 5;

      d0, d1, d2, d3, d4, c : U64;
   begin
      d0 := h0*r0 + h1*s4 + h2*s3 + h3*s2 + h4*s1;
      d1 := h0*r1 + h1*r0 + h2*s4 + h3*s3 + h4*s2;
      d2 := h0*r2 + h1*r1 + h2*r0 + h3*s4 + h4*s3;
      d3 := h0*r3 + h1*r2 + h2*r1 + h3*r0 + h4*s4;
      d4 := h0*r4 + h1*r3 + h2*r2 + h3*r1 + h4*r0;

      c  := Shift_Right (d0, 26); h0 := d0 and M26;
      d1 := d1 + c;
      c  := Shift_Right (d1, 26); h1 := d1 and M26;
      d2 := d2 + c;
      c  := Shift_Right (d2, 26); h2 := d2 and M26;
      d3 := d3 + c;
      c  := Shift_Right (d3, 26); h3 := d3 and M26;
      d4 := d4 + c;
      c  := Shift_Right (d4, 26); h4 := d4 and M26;
      h0 := h0 + c * 5;
      c  := Shift_Right (h0, 26); h0 := h0 and M26;
      h1 := h1 + c;
   end Mul_5limb;

   --================================================================
   --  Extract clamped r limbs from key bytes 0..15.
   --================================================================
   procedure Extract_R
     (Key_Bytes : in  Bytes_32;
      r0, r1, r2, r3, r4 : out U64)
   is
      function Le32 (P : in N32) return U32 is
      begin
         return Unsigned_32 (Key_Bytes (P))
              or Shift_Left (Unsigned_32 (Key_Bytes (P + 1)),  8)
              or Shift_Left (Unsigned_32 (Key_Bytes (P + 2)), 16)
              or Shift_Left (Unsigned_32 (Key_Bytes (P + 3)), 24);
      end Le32;
   begin
      r0 := U64 (Le32 (0))                   and 16#03FF_FFFF#;
      r1 := Shift_Right (U64 (Le32 (3)), 2)  and 16#03FF_FF03#;
      r2 := Shift_Right (U64 (Le32 (6)), 4)  and 16#03FF_C0FF#;
      r3 := Shift_Right (U64 (Le32 (9)), 6)  and 16#03F0_3FFF#;
      r4 := Shift_Right (U64 (Le32 (12)), 8) and 16#000F_FFFF#;
   end Extract_R;

   --================================================================
   --  Convert one 16-byte block to 5 × 26-bit limbs (radix 2²⁶).
   --  The high "1" bit is folded into limb 4 (bit 24) by the caller.
   --================================================================
   procedure Block_To_Limbs
     (M     : in  Byte_Seq;
      Pos   : in  N32;
      Hi_Bit : in U64;
      l0, l1, l2, l3, l4 : out U64)
   is
      function Le32 (P : in N32) return U32 is
      begin
         return Unsigned_32 (M (P))
              or Shift_Left (Unsigned_32 (M (P + 1)),  8)
              or Shift_Left (Unsigned_32 (M (P + 2)), 16)
              or Shift_Left (Unsigned_32 (M (P + 3)), 24);
      end Le32;
      t0 : constant U32 := Le32 (Pos +  0);
      t1 : constant U32 := Le32 (Pos +  4);
      t2 : constant U32 := Le32 (Pos +  8);
      t3 : constant U32 := Le32 (Pos + 12);
   begin
      l0 := U64 (t0) and M26;
      l1 := (Shift_Right (U64 (t0), 26) or Shift_Left (U64 (t1),  6)) and M26;
      l2 := (Shift_Right (U64 (t1), 20) or Shift_Left (U64 (t2), 12)) and M26;
      l3 := (Shift_Right (U64 (t2), 14) or Shift_Left (U64 (t3), 18)) and M26;
      l4 := Shift_Right (U64 (t3), 8) + Shift_Left (Hi_Bit, 24);
   end Block_To_Limbs;

   --================================================================
   --  Process one block scalar (used for tail).
   --================================================================
   procedure Process_Block_Scalar
     (h0, h1, h2, h3, h4 : in out U64;
      r0, r1, r2, r3, r4 : in     U64;
      M     : in     Byte_Seq;
      Pos   : in     N32;
      Hi_Bit : in    U64)
   is
      s1 : constant U64 := r1 * 5;
      s2 : constant U64 := r2 * 5;
      s3 : constant U64 := r3 * 5;
      s4 : constant U64 := r4 * 5;
      l0, l1, l2, l3, l4 : U64;
      d0, d1, d2, d3, d4, c : U64;
   begin
      Block_To_Limbs (M, Pos, Hi_Bit, l0, l1, l2, l3, l4);
      h0 := h0 + l0;
      h1 := h1 + l1;
      h2 := h2 + l2;
      h3 := h3 + l3;
      h4 := h4 + l4;
      d0 := h0*r0 + h1*s4 + h2*s3 + h3*s2 + h4*s1;
      d1 := h0*r1 + h1*r0 + h2*s4 + h3*s3 + h4*s2;
      d2 := h0*r2 + h1*r1 + h2*r0 + h3*s4 + h4*s3;
      d3 := h0*r3 + h1*r2 + h2*r1 + h3*r0 + h4*s4;
      d4 := h0*r4 + h1*r3 + h2*r2 + h3*r1 + h4*r0;
      c  := Shift_Right (d0, 26); h0 := d0 and M26;
      d1 := d1 + c;
      c  := Shift_Right (d1, 26); h1 := d1 and M26;
      d2 := d2 + c;
      c  := Shift_Right (d2, 26); h2 := d2 and M26;
      d3 := d3 + c;
      c  := Shift_Right (d3, 26); h3 := d3 and M26;
      d4 := d4 + c;
      c  := Shift_Right (d4, 26); h4 := d4 and M26;
      h0 := h0 + c * 5;
      c  := Shift_Right (h0, 26); h0 := h0 and M26;
      h1 := h1 + c;
   end Process_Block_Scalar;

   --================================================================
   --  Process 8 blocks in parallel using AVX-512 lane-major SIMD.
   --
   --  Inputs:
   --    h0..h4   — current scalar accumulator (in/out, 5 × U64)
   --    Msg_Lanes — pre-laid-out 5 zmm regs of message limbs
   --                (5 × 8 = 40 U64s, lane-major)
   --    R_Powers  — 5 zmm regs of r¹..r⁸ limbs
   --                (lane 0 = r⁸_lk, lane 1 = r⁷_lk, ..., lane 7 = r¹_lk)
   --    S_Powers  — 4 zmm regs of 5*r¹..5*r⁸ limbs (l1..l4)
   --================================================================

   --  Layout: 9 zmm-aligned vectors (5 r-powers + 4 s-powers) = 576 bytes.
   --  Plus 5 zmm of message limbs per batch = 320 bytes scratch.

   type Lane_8 is array (0 .. 7) of U64;

   --================================================================
   --  Asm fragments — common scaffolding plus two interchangeable
   --  multiply phases (vpmuludq baseline vs vpmadd52luq IFMA).
   --
   --  Conventions: zmm0..zmm4 hold message limbs (h_scalar pre-added
   --  to lane 0); zmm5..zmm9 hold r⁸..r¹ packed lane-major across 8
   --  lanes; zmm10..zmm13 hold s1..s4 = 5*r1..5*r4; zmm14..zmm18 hold
   --  the d0..d4 accumulators; zmm19..zmm21 are temporaries.
   --================================================================
   Setup_Loads : constant String :=
        --  Load 5 zmm regs of message limbs (one per limb position).
        "vmovdqu64    (%0), %%zmm0"          & ASCII.LF & ASCII.HT &
        "vmovdqu64  64(%0), %%zmm1"          & ASCII.LF & ASCII.HT &
        "vmovdqu64 128(%0), %%zmm2"          & ASCII.LF & ASCII.HT &
        "vmovdqu64 192(%0), %%zmm3"          & ASCII.LF & ASCII.HT &
        "vmovdqu64 256(%0), %%zmm4"          & ASCII.LF & ASCII.HT &
        --  Add scalar h to lane 0 (only) — H_Lanes has h in lane 0,
        --  zeros elsewhere, so we vpaddq the whole vector.
        "vpaddq    (%4), %%zmm0, %%zmm0"     & ASCII.LF & ASCII.HT &
        "vpaddq  64(%4), %%zmm1, %%zmm1"     & ASCII.LF & ASCII.HT &
        "vpaddq 128(%4), %%zmm2, %%zmm2"     & ASCII.LF & ASCII.HT &
        "vpaddq 192(%4), %%zmm3, %%zmm3"     & ASCII.LF & ASCII.HT &
        "vpaddq 256(%4), %%zmm4, %%zmm4"     & ASCII.LF & ASCII.HT &
        --  Load r-powers (zmm5..zmm9) and s-powers (zmm10..zmm13).
        "vmovdqu64    (%1), %%zmm5"          & ASCII.LF & ASCII.HT &
        "vmovdqu64  64(%1), %%zmm6"          & ASCII.LF & ASCII.HT &
        "vmovdqu64 128(%1), %%zmm7"          & ASCII.LF & ASCII.HT &
        "vmovdqu64 192(%1), %%zmm8"          & ASCII.LF & ASCII.HT &
        "vmovdqu64 256(%1), %%zmm9"          & ASCII.LF & ASCII.HT &
        "vmovdqu64    (%2), %%zmm10"         & ASCII.LF & ASCII.HT &
        "vmovdqu64  64(%2), %%zmm11"         & ASCII.LF & ASCII.HT &
        "vmovdqu64 128(%2), %%zmm12"         & ASCII.LF & ASCII.HT &
        "vmovdqu64 192(%2), %%zmm13"         & ASCII.LF & ASCII.HT;

   --  vpmuludq baseline: 25 mul + 20 add. Schoolbook 5×5 over the
   --    d0 = h0*r0 + h1*s4 + h2*s3 + h3*s2 + h4*s1
   --    d1 = h0*r1 + h1*r0 + h2*s4 + h3*s3 + h4*s2
   --    d2 = h0*r2 + h1*r1 + h2*r0 + h3*s4 + h4*s3
   --    d3 = h0*r3 + h1*r2 + h2*r1 + h3*r0 + h4*s4
   --    d4 = h0*r4 + h1*r3 + h2*r2 + h3*r1 + h4*r0
   --  pattern. zmm19 is reused as the per-product temp.
   Multiply_VPMUL : constant String :=
        --  Row 0 (h0): five seed products initialise d0..d4.
        "vpmuludq  %%zmm5,  %%zmm0, %%zmm14"  & ASCII.LF & ASCII.HT &
        "vpmuludq  %%zmm6,  %%zmm0, %%zmm15"  & ASCII.LF & ASCII.HT &
        "vpmuludq  %%zmm7,  %%zmm0, %%zmm16"  & ASCII.LF & ASCII.HT &
        "vpmuludq  %%zmm8,  %%zmm0, %%zmm17"  & ASCII.LF & ASCII.HT &
        "vpmuludq  %%zmm9,  %%zmm0, %%zmm18"  & ASCII.LF & ASCII.HT &
        --  Row 1 (h1): mul-then-add into d0..d4.
        "vpmuludq  %%zmm13, %%zmm1, %%zmm19"  & ASCII.LF & ASCII.HT &
        "vpaddq    %%zmm19, %%zmm14, %%zmm14" & ASCII.LF & ASCII.HT &
        "vpmuludq  %%zmm5,  %%zmm1, %%zmm19"  & ASCII.LF & ASCII.HT &
        "vpaddq    %%zmm19, %%zmm15, %%zmm15" & ASCII.LF & ASCII.HT &
        "vpmuludq  %%zmm6,  %%zmm1, %%zmm19"  & ASCII.LF & ASCII.HT &
        "vpaddq    %%zmm19, %%zmm16, %%zmm16" & ASCII.LF & ASCII.HT &
        "vpmuludq  %%zmm7,  %%zmm1, %%zmm19"  & ASCII.LF & ASCII.HT &
        "vpaddq    %%zmm19, %%zmm17, %%zmm17" & ASCII.LF & ASCII.HT &
        "vpmuludq  %%zmm8,  %%zmm1, %%zmm19"  & ASCII.LF & ASCII.HT &
        "vpaddq    %%zmm19, %%zmm18, %%zmm18" & ASCII.LF & ASCII.HT &
        --  Row 2 (h2).
        "vpmuludq  %%zmm12, %%zmm2, %%zmm19"  & ASCII.LF & ASCII.HT &
        "vpaddq    %%zmm19, %%zmm14, %%zmm14" & ASCII.LF & ASCII.HT &
        "vpmuludq  %%zmm13, %%zmm2, %%zmm19"  & ASCII.LF & ASCII.HT &
        "vpaddq    %%zmm19, %%zmm15, %%zmm15" & ASCII.LF & ASCII.HT &
        "vpmuludq  %%zmm5,  %%zmm2, %%zmm19"  & ASCII.LF & ASCII.HT &
        "vpaddq    %%zmm19, %%zmm16, %%zmm16" & ASCII.LF & ASCII.HT &
        "vpmuludq  %%zmm6,  %%zmm2, %%zmm19"  & ASCII.LF & ASCII.HT &
        "vpaddq    %%zmm19, %%zmm17, %%zmm17" & ASCII.LF & ASCII.HT &
        "vpmuludq  %%zmm7,  %%zmm2, %%zmm19"  & ASCII.LF & ASCII.HT &
        "vpaddq    %%zmm19, %%zmm18, %%zmm18" & ASCII.LF & ASCII.HT &
        --  Row 3 (h3).
        "vpmuludq  %%zmm11, %%zmm3, %%zmm19"  & ASCII.LF & ASCII.HT &
        "vpaddq    %%zmm19, %%zmm14, %%zmm14" & ASCII.LF & ASCII.HT &
        "vpmuludq  %%zmm12, %%zmm3, %%zmm19"  & ASCII.LF & ASCII.HT &
        "vpaddq    %%zmm19, %%zmm15, %%zmm15" & ASCII.LF & ASCII.HT &
        "vpmuludq  %%zmm13, %%zmm3, %%zmm19"  & ASCII.LF & ASCII.HT &
        "vpaddq    %%zmm19, %%zmm16, %%zmm16" & ASCII.LF & ASCII.HT &
        "vpmuludq  %%zmm5,  %%zmm3, %%zmm19"  & ASCII.LF & ASCII.HT &
        "vpaddq    %%zmm19, %%zmm17, %%zmm17" & ASCII.LF & ASCII.HT &
        "vpmuludq  %%zmm6,  %%zmm3, %%zmm19"  & ASCII.LF & ASCII.HT &
        "vpaddq    %%zmm19, %%zmm18, %%zmm18" & ASCII.LF & ASCII.HT &
        --  Row 4 (h4).
        "vpmuludq  %%zmm10, %%zmm4, %%zmm19"  & ASCII.LF & ASCII.HT &
        "vpaddq    %%zmm19, %%zmm14, %%zmm14" & ASCII.LF & ASCII.HT &
        "vpmuludq  %%zmm11, %%zmm4, %%zmm19"  & ASCII.LF & ASCII.HT &
        "vpaddq    %%zmm19, %%zmm15, %%zmm15" & ASCII.LF & ASCII.HT &
        "vpmuludq  %%zmm12, %%zmm4, %%zmm19"  & ASCII.LF & ASCII.HT &
        "vpaddq    %%zmm19, %%zmm16, %%zmm16" & ASCII.LF & ASCII.HT &
        "vpmuludq  %%zmm13, %%zmm4, %%zmm19"  & ASCII.LF & ASCII.HT &
        "vpaddq    %%zmm19, %%zmm17, %%zmm17" & ASCII.LF & ASCII.HT &
        "vpmuludq  %%zmm5,  %%zmm4, %%zmm19"  & ASCII.LF & ASCII.HT &
        "vpaddq    %%zmm19, %%zmm18, %%zmm18" & ASCII.LF & ASCII.HT;

   --  IFMA path: 5 vpxorq + 25 vpmadd52luq.
   --  vpmadd52luq dst, src1, src2 (AT&T): dst += low_52(src1*src2).
   --  Each h_i, r_j is 26 bits; product is exactly 52 bits, fits in
   --  the low half (vpmadd52huq would return 0). Up to 5 mul-adds per
   --  accumulator = max value ~5·2^52 < 2^55, well within 64-bit lanes.
   Multiply_IFMA : constant String :=
        --  Zero d0..d4. (vpxorq to self is renamed to a zero-idiom on
        --  modern x86, so these are essentially free.)
        "vpxorq    %%zmm14, %%zmm14, %%zmm14" & ASCII.LF & ASCII.HT &
        "vpxorq    %%zmm15, %%zmm15, %%zmm15" & ASCII.LF & ASCII.HT &
        "vpxorq    %%zmm16, %%zmm16, %%zmm16" & ASCII.LF & ASCII.HT &
        "vpxorq    %%zmm17, %%zmm17, %%zmm17" & ASCII.LF & ASCII.HT &
        "vpxorq    %%zmm18, %%zmm18, %%zmm18" & ASCII.LF & ASCII.HT &
        --  Row 0 (h0).
        "vpmadd52luq %%zmm5,  %%zmm0, %%zmm14" & ASCII.LF & ASCII.HT &
        "vpmadd52luq %%zmm6,  %%zmm0, %%zmm15" & ASCII.LF & ASCII.HT &
        "vpmadd52luq %%zmm7,  %%zmm0, %%zmm16" & ASCII.LF & ASCII.HT &
        "vpmadd52luq %%zmm8,  %%zmm0, %%zmm17" & ASCII.LF & ASCII.HT &
        "vpmadd52luq %%zmm9,  %%zmm0, %%zmm18" & ASCII.LF & ASCII.HT &
        --  Row 1 (h1).
        "vpmadd52luq %%zmm13, %%zmm1, %%zmm14" & ASCII.LF & ASCII.HT &
        "vpmadd52luq %%zmm5,  %%zmm1, %%zmm15" & ASCII.LF & ASCII.HT &
        "vpmadd52luq %%zmm6,  %%zmm1, %%zmm16" & ASCII.LF & ASCII.HT &
        "vpmadd52luq %%zmm7,  %%zmm1, %%zmm17" & ASCII.LF & ASCII.HT &
        "vpmadd52luq %%zmm8,  %%zmm1, %%zmm18" & ASCII.LF & ASCII.HT &
        --  Row 2 (h2).
        "vpmadd52luq %%zmm12, %%zmm2, %%zmm14" & ASCII.LF & ASCII.HT &
        "vpmadd52luq %%zmm13, %%zmm2, %%zmm15" & ASCII.LF & ASCII.HT &
        "vpmadd52luq %%zmm5,  %%zmm2, %%zmm16" & ASCII.LF & ASCII.HT &
        "vpmadd52luq %%zmm6,  %%zmm2, %%zmm17" & ASCII.LF & ASCII.HT &
        "vpmadd52luq %%zmm7,  %%zmm2, %%zmm18" & ASCII.LF & ASCII.HT &
        --  Row 3 (h3).
        "vpmadd52luq %%zmm11, %%zmm3, %%zmm14" & ASCII.LF & ASCII.HT &
        "vpmadd52luq %%zmm12, %%zmm3, %%zmm15" & ASCII.LF & ASCII.HT &
        "vpmadd52luq %%zmm13, %%zmm3, %%zmm16" & ASCII.LF & ASCII.HT &
        "vpmadd52luq %%zmm5,  %%zmm3, %%zmm17" & ASCII.LF & ASCII.HT &
        "vpmadd52luq %%zmm6,  %%zmm3, %%zmm18" & ASCII.LF & ASCII.HT &
        --  Row 4 (h4).
        "vpmadd52luq %%zmm10, %%zmm4, %%zmm14" & ASCII.LF & ASCII.HT &
        "vpmadd52luq %%zmm11, %%zmm4, %%zmm15" & ASCII.LF & ASCII.HT &
        "vpmadd52luq %%zmm12, %%zmm4, %%zmm16" & ASCII.LF & ASCII.HT &
        "vpmadd52luq %%zmm13, %%zmm4, %%zmm17" & ASCII.LF & ASCII.HT &
        "vpmadd52luq %%zmm5,  %%zmm4, %%zmm18" & ASCII.LF & ASCII.HT;

   --  Carry chain + store. zmm20 holds broadcast M26; zmm19/zmm21 are
   --  carry temps. d0..d4 must hold values < 2^60 on entry (true for
   --  both VPMUL and IFMA paths above).
   Carry_And_Store : constant String :=
        "vpbroadcastq  %3, %%zmm20"           & ASCII.LF & ASCII.HT &
        "vpsrlq    $26, %%zmm14, %%zmm19"     & ASCII.LF & ASCII.HT &
        "vpandq    %%zmm20, %%zmm14, %%zmm14" & ASCII.LF & ASCII.HT &
        "vpaddq    %%zmm19, %%zmm15, %%zmm15" & ASCII.LF & ASCII.HT &
        "vpsrlq    $26, %%zmm15, %%zmm19"     & ASCII.LF & ASCII.HT &
        "vpandq    %%zmm20, %%zmm15, %%zmm15" & ASCII.LF & ASCII.HT &
        "vpaddq    %%zmm19, %%zmm16, %%zmm16" & ASCII.LF & ASCII.HT &
        "vpsrlq    $26, %%zmm16, %%zmm19"     & ASCII.LF & ASCII.HT &
        "vpandq    %%zmm20, %%zmm16, %%zmm16" & ASCII.LF & ASCII.HT &
        "vpaddq    %%zmm19, %%zmm17, %%zmm17" & ASCII.LF & ASCII.HT &
        "vpsrlq    $26, %%zmm17, %%zmm19"     & ASCII.LF & ASCII.HT &
        "vpandq    %%zmm20, %%zmm17, %%zmm17" & ASCII.LF & ASCII.HT &
        "vpaddq    %%zmm19, %%zmm18, %%zmm18" & ASCII.LF & ASCII.HT &
        "vpsrlq    $26, %%zmm18, %%zmm19"     & ASCII.LF & ASCII.HT &
        "vpandq    %%zmm20, %%zmm18, %%zmm18" & ASCII.LF & ASCII.HT &
        "vpsllq    $2,  %%zmm19, %%zmm21"     & ASCII.LF & ASCII.HT &
        "vpaddq    %%zmm19, %%zmm21, %%zmm19" & ASCII.LF & ASCII.HT &
        "vpaddq    %%zmm19, %%zmm14, %%zmm14" & ASCII.LF & ASCII.HT &
        "vpsrlq    $26, %%zmm14, %%zmm19"     & ASCII.LF & ASCII.HT &
        "vpandq    %%zmm20, %%zmm14, %%zmm14" & ASCII.LF & ASCII.HT &
        "vpaddq    %%zmm19, %%zmm15, %%zmm15" & ASCII.LF & ASCII.HT &
        "vmovdqu64 %%zmm14,    (%5)"          & ASCII.LF & ASCII.HT &
        "vmovdqu64 %%zmm15,  64(%5)"          & ASCII.LF & ASCII.HT &
        "vmovdqu64 %%zmm16, 128(%5)"          & ASCII.LF & ASCII.HT &
        "vmovdqu64 %%zmm17, 192(%5)"          & ASCII.LF & ASCII.HT &
        "vmovdqu64 %%zmm18, 256(%5)"          & ASCII.LF & ASCII.HT &
        "vzeroupper";

   --  Process one 8-block batch. Updates h0..h4 in place.
   procedure Process_8_Block_Batch
     (h0, h1, h2, h3, h4 : in out U64;
      M_Limbs    : in     System.Address;  -- 5 × 8 × U64 lane-major
      R_Powers   : in     System.Address;  -- 5 × 8 × U64
      S_Powers   : in     System.Address)  -- 4 × 8 × U64
   is
      --  Output scratch: 5 × 8 × U64 = 320 bytes lane-major for d0..d4.
      type U64_Lane is array (0 .. 7) of U64;
      type Out_Buf is array (0 .. 4) of U64_Lane;
      Out_Lanes : Out_Buf;
      for Out_Lanes'Alignment use 64;

      --  H scratch: load h_scalar into lane 0, zero the rest.
      H_Lanes : Out_Buf := (others => (others => 0));
      for H_Lanes'Alignment use 64;
   begin
      H_Lanes (0) (0) := h0;
      H_Lanes (1) (0) := h1;
      H_Lanes (2) (0) := h2;
      H_Lanes (3) (0) := h3;
      H_Lanes (4) (0) := h4;

      --  IFMA dispatch is currently disabled. The radix-2²⁶ IFMA body
      --  (Multiply_IFMA, retained below for reference) is incorrect:
      --  for wraparound products h_i * s_j where s_j = 5·r_j is up to
      --  ~29 bits, the product is up to 54 bits and vpmadd52luq drops
      --  the top 2 bits. A correct IFMA path either pairs vpmadd52luq
      --  with vpmadd52huq for wraparound terms (modest ~9% win) or
      --  switches to radix-2⁴⁴ (the OpenSSL approach, ~25% win, much
      --  more code). For now we always take the vpmuludq path.
      Asm
        (Setup_Loads & Multiply_VPMUL & Carry_And_Store,
         Inputs => (System.Address'Asm_Input ("r", M_Limbs),         -- %0
                    System.Address'Asm_Input ("r", R_Powers),         -- %1
                    System.Address'Asm_Input ("r", S_Powers),         -- %2
                    U64'Asm_Input            ("r", M26),              -- %3
                    System.Address'Asm_Input ("r", H_Lanes'Address),  -- %4
                    System.Address'Asm_Input ("r", Out_Lanes'Address) -- %5
                   ),
         Clobber => "xmm0,xmm1,xmm2,xmm3,xmm4,xmm5,xmm6,xmm7,xmm8," &
                    "xmm9,xmm10,xmm11,xmm12,xmm13,xmm14,xmm15,xmm16," &
                    "xmm17,xmm18,xmm19,xmm20,xmm21,memory",
         Volatile => True);

      --  Horizontal sum: collapse 8 lanes per d_j to scalar h_j.
      h0 := Out_Lanes (0) (0) + Out_Lanes (0) (1) + Out_Lanes (0) (2)
          + Out_Lanes (0) (3) + Out_Lanes (0) (4) + Out_Lanes (0) (5)
          + Out_Lanes (0) (6) + Out_Lanes (0) (7);
      h1 := Out_Lanes (1) (0) + Out_Lanes (1) (1) + Out_Lanes (1) (2)
          + Out_Lanes (1) (3) + Out_Lanes (1) (4) + Out_Lanes (1) (5)
          + Out_Lanes (1) (6) + Out_Lanes (1) (7);
      h2 := Out_Lanes (2) (0) + Out_Lanes (2) (1) + Out_Lanes (2) (2)
          + Out_Lanes (2) (3) + Out_Lanes (2) (4) + Out_Lanes (2) (5)
          + Out_Lanes (2) (6) + Out_Lanes (2) (7);
      h3 := Out_Lanes (3) (0) + Out_Lanes (3) (1) + Out_Lanes (3) (2)
          + Out_Lanes (3) (3) + Out_Lanes (3) (4) + Out_Lanes (3) (5)
          + Out_Lanes (3) (6) + Out_Lanes (3) (7);
      h4 := Out_Lanes (4) (0) + Out_Lanes (4) (1) + Out_Lanes (4) (2)
          + Out_Lanes (4) (3) + Out_Lanes (4) (4) + Out_Lanes (4) (5)
          + Out_Lanes (4) (6) + Out_Lanes (4) (7);

      --  Re-carry the scalar h after the horizontal sum (each h_j may
      --  exceed 26 bits since we summed 8 26-bit values).
      declare
         c : U64;
      begin
         c  := Shift_Right (h0, 26); h0 := h0 and M26;
         h1 := h1 + c;
         c  := Shift_Right (h1, 26); h1 := h1 and M26;
         h2 := h2 + c;
         c  := Shift_Right (h2, 26); h2 := h2 and M26;
         h3 := h3 + c;
         c  := Shift_Right (h3, 26); h3 := h3 and M26;
         h4 := h4 + c;
         c  := Shift_Right (h4, 26); h4 := h4 and M26;
         h0 := h0 + c * 5;
         c  := Shift_Right (h0, 26); h0 := h0 and M26;
         h1 := h1 + c;
      end;
   end Process_8_Block_Batch;

   --================================================================
   --  Onetimeauth: 8-block batched bulk + scalar tail.
   --================================================================

   procedure Onetimeauth
     (Output :    out Bytes_16;
      M      : in     Byte_Seq;
      K      : in     SPARKNaCl.MAC.Poly_1305_Key)
   is
   begin
      --  Below ~128 bytes the SIMD overhead (compute 8 r-powers, set
      --  up tables) outweighs the gain. Defer to the scalar fast path.
      if M'Length < 128 then
         SPARKTLSCrypto.Poly1305.Onetimeauth (Output, M, K);
         return;
      end if;

      declare
         Key_Bytes : constant Bytes_32 := SPARKNaCl.MAC.Serialize (K);

         --  r¹..r⁸ — each is 5 limbs.
         type R_Power is record
            l0, l1, l2, l3, l4 : U64;
         end record;
         R_Pwrs : array (1 .. 8) of R_Power;

         --  Lane-major tables for the asm.
         --  R_Tab[k][lane] holds limb k of the r-power assigned to lane.
         --  Lane i (i=0..7) holds r^(8-i).
         R_Tab : array (0 .. 4) of Lane_8 := (others => (others => 0));
         S_Tab : array (0 .. 3) of Lane_8 := (others => (others => 0));
         for R_Tab'Alignment use 64;
         for S_Tab'Alignment use 64;

         --  Message limbs scratch: 5 × 8 × U64 lane-major.
         M_Tab : array (0 .. 4) of Lane_8 := (others => (others => 0));
         for M_Tab'Alignment use 64;

         h0, h1, h2, h3, h4 : U64 := 0;
         r0, r1, r2, r3, r4 : U64;

         Pos       : N32 := M'First;
         End_Last  : constant N32 := M'Last;
      begin
         --  Always-init Output (SPARK-friendly + safety).
         Output := (others => 0);

         --  Setup: extract clamped r, compute r¹..r⁸.
         Extract_R (Key_Bytes, r0, r1, r2, r3, r4);
         R_Pwrs (1) := (r0, r1, r2, r3, r4);
         for K_Idx in 2 .. 8 loop
            declare
               t0 : U64 := R_Pwrs (K_Idx - 1).l0;
               t1 : U64 := R_Pwrs (K_Idx - 1).l1;
               t2 : U64 := R_Pwrs (K_Idx - 1).l2;
               t3 : U64 := R_Pwrs (K_Idx - 1).l3;
               t4 : U64 := R_Pwrs (K_Idx - 1).l4;
            begin
               Mul_5limb (t0, t1, t2, t3, t4, r0, r1, r2, r3, r4);
               R_Pwrs (K_Idx) := (t0, t1, t2, t3, t4);
            end;
         end loop;

         --  Lay out R_Tab so lane i (0..7) gets r^(8-i).
         for I in 0 .. 7 loop
            R_Tab (0) (I) := R_Pwrs (8 - I).l0;
            R_Tab (1) (I) := R_Pwrs (8 - I).l1;
            R_Tab (2) (I) := R_Pwrs (8 - I).l2;
            R_Tab (3) (I) := R_Pwrs (8 - I).l3;
            R_Tab (4) (I) := R_Pwrs (8 - I).l4;
            S_Tab (0) (I) := R_Pwrs (8 - I).l1 * 5;
            S_Tab (1) (I) := R_Pwrs (8 - I).l2 * 5;
            S_Tab (2) (I) := R_Pwrs (8 - I).l3 * 5;
            S_Tab (3) (I) := R_Pwrs (8 - I).l4 * 5;
         end loop;

         --  Bulk loop: process 8-block (128-byte) batches.
         while Pos + 127 <= End_Last loop
            --  Build M_Tab from 8 consecutive 16-byte blocks.
            for I in 0 .. 7 loop
               declare
                  l0, l1, l2, l3, l4 : U64;
               begin
                  Block_To_Limbs
                    (M, Pos + N32 (I) * 16, 1, l0, l1, l2, l3, l4);
                  M_Tab (0) (I) := l0;
                  M_Tab (1) (I) := l1;
                  M_Tab (2) (I) := l2;
                  M_Tab (3) (I) := l3;
                  M_Tab (4) (I) := l4;
               end;
            end loop;
            Process_8_Block_Batch
              (h0, h1, h2, h3, h4,
               M_Tab'Address, R_Tab'Address, S_Tab'Address);
            Pos := Pos + 128;
         end loop;

         --  Tail: process remaining < 128 bytes one block at a time.
         while Pos + 15 <= End_Last loop
            Process_Block_Scalar
              (h0, h1, h2, h3, h4, r0, r1, r2, r3, r4,
               M, Pos, 1);
            Pos := Pos + 16;
         end loop;

         --  Final partial block (if any).
         if Pos <= End_Last then
            declare
               Remaining : constant N32 := End_Last - Pos + 1;
               Block     : Bytes_16 := (others => 0);
               l0, l1, l2, l3, l4 : U64;
               s1 : constant U64 := r1 * 5;
               s2 : constant U64 := r2 * 5;
               s3 : constant U64 := r3 * 5;
               s4 : constant U64 := r4 * 5;
               d0, d1, d2, d3, d4, c : U64;
               t0, t1, t2, t3 : U32;
            begin
               for I in 0 .. Remaining - 1 loop
                  Block (I) := M (Pos + I);
               end loop;
               Block (Remaining) := 1;
               --  Process in-block.
               t0 := Unsigned_32 (Block (0))
                   or Shift_Left (Unsigned_32 (Block (1)),  8)
                   or Shift_Left (Unsigned_32 (Block (2)), 16)
                   or Shift_Left (Unsigned_32 (Block (3)), 24);
               t1 := Unsigned_32 (Block (4))
                   or Shift_Left (Unsigned_32 (Block (5)),  8)
                   or Shift_Left (Unsigned_32 (Block (6)), 16)
                   or Shift_Left (Unsigned_32 (Block (7)), 24);
               t2 := Unsigned_32 (Block (8))
                   or Shift_Left (Unsigned_32 (Block (9)),  8)
                   or Shift_Left (Unsigned_32 (Block (10)), 16)
                   or Shift_Left (Unsigned_32 (Block (11)), 24);
               t3 := Unsigned_32 (Block (12))
                   or Shift_Left (Unsigned_32 (Block (13)),  8)
                   or Shift_Left (Unsigned_32 (Block (14)), 16)
                   or Shift_Left (Unsigned_32 (Block (15)), 24);
               l0 := U64 (t0) and M26;
               l1 := (Shift_Right (U64 (t0), 26)
                       or Shift_Left (U64 (t1), 6)) and M26;
               l2 := (Shift_Right (U64 (t1), 20)
                       or Shift_Left (U64 (t2), 12)) and M26;
               l3 := (Shift_Right (U64 (t2), 14)
                       or Shift_Left (U64 (t3), 18)) and M26;
               l4 := Shift_Right (U64 (t3), 8);  -- no Hi_Bit fold
               h0 := h0 + l0;
               h1 := h1 + l1;
               h2 := h2 + l2;
               h3 := h3 + l3;
               h4 := h4 + l4;
               d0 := h0*r0 + h1*s4 + h2*s3 + h3*s2 + h4*s1;
               d1 := h0*r1 + h1*r0 + h2*s4 + h3*s3 + h4*s2;
               d2 := h0*r2 + h1*r1 + h2*r0 + h3*s4 + h4*s3;
               d3 := h0*r3 + h1*r2 + h2*r1 + h3*r0 + h4*s4;
               d4 := h0*r4 + h1*r3 + h2*r2 + h3*r1 + h4*r0;
               c  := Shift_Right (d0, 26); h0 := d0 and M26;
               d1 := d1 + c;
               c  := Shift_Right (d1, 26); h1 := d1 and M26;
               d2 := d2 + c;
               c  := Shift_Right (d2, 26); h2 := d2 and M26;
               d3 := d3 + c;
               c  := Shift_Right (d3, 26); h3 := d3 and M26;
               d4 := d4 + c;
               c  := Shift_Right (d4, 26); h4 := d4 and M26;
               h0 := h0 + c * 5;
               c  := Shift_Right (h0, 26); h0 := h0 and M26;
               h1 := h1 + c;
            end;
         end if;

         --  Final reduction: subtract p = 2^130 - 5 if h >= p, then add s.
         declare
            c : U64;
            g0, g1, g2, g3, g4, mask : U64;
            f0, f1, f2, f3, u : U64;
            function Le32_Key (P : N32) return U32 is
            begin
               return Unsigned_32 (Key_Bytes (P))
                    or Shift_Left (Unsigned_32 (Key_Bytes (P + 1)),  8)
                    or Shift_Left (Unsigned_32 (Key_Bytes (P + 2)), 16)
                    or Shift_Left (Unsigned_32 (Key_Bytes (P + 3)), 24);
            end Le32_Key;
         begin
            c  := Shift_Right (h1, 26); h1 := h1 and M26;
            h2 := h2 + c;
            c  := Shift_Right (h2, 26); h2 := h2 and M26;
            h3 := h3 + c;
            c  := Shift_Right (h3, 26); h3 := h3 and M26;
            h4 := h4 + c;
            c  := Shift_Right (h4, 26); h4 := h4 and M26;
            h0 := h0 + c * 5;
            c  := Shift_Right (h0, 26); h0 := h0 and M26;
            h1 := h1 + c;

            g0 := h0 + 5;
            c  := Shift_Right (g0, 26); g0 := g0 and M26;
            g1 := h1 + c;
            c  := Shift_Right (g1, 26); g1 := g1 and M26;
            g2 := h2 + c;
            c  := Shift_Right (g2, 26); g2 := g2 and M26;
            g3 := h3 + c;
            c  := Shift_Right (g3, 26); g3 := g3 and M26;
            g4 := h4 + c - Shift_Left (U64 (1), 26);

            mask := 0 - Shift_Right (g4, 63);  -- 0xFF... if h<p else 0
            h0 := (h0 and mask) or (g0 and not mask);
            h1 := (h1 and mask) or (g1 and not mask);
            h2 := (h2 and mask) or (g2 and not mask);
            h3 := (h3 and mask) or (g3 and not mask);
            h4 := (h4 and mask) or (g4 and not mask);

            f0 := (h0 or Shift_Left (h1, 26))           and 16#FFFF_FFFF#;
            f1 := (Shift_Right (h1,  6) or Shift_Left (h2, 20)) and 16#FFFF_FFFF#;
            f2 := (Shift_Right (h2, 12) or Shift_Left (h3, 14)) and 16#FFFF_FFFF#;
            f3 := (Shift_Right (h3, 18) or Shift_Left (h4,  8)) and 16#FFFF_FFFF#;

            u := f0 + U64 (Le32_Key (16));
            f0 := u and 16#FFFF_FFFF#;
            u := f1 + U64 (Le32_Key (20)) + Shift_Right (u, 32);
            f1 := u and 16#FFFF_FFFF#;
            u := f2 + U64 (Le32_Key (24)) + Shift_Right (u, 32);
            f2 := u and 16#FFFF_FFFF#;
            u := f3 + U64 (Le32_Key (28)) + Shift_Right (u, 32);
            f3 := u and 16#FFFF_FFFF#;

            for I in 0 .. 3 loop
               Output (N32 (I))      := Byte (Shift_Right (f0, 8 * I) and 16#FF#);
               Output (N32 (4 + I))  := Byte (Shift_Right (f1, 8 * I) and 16#FF#);
               Output (N32 (8 + I))  := Byte (Shift_Right (f2, 8 * I) and 16#FF#);
               Output (N32 (12 + I)) := Byte (Shift_Right (f3, 8 * I) and 16#FF#);
            end loop;
         end;
      end;
   end Onetimeauth;

begin
   Detect_AVX512_Poly1305 (Has_AVX512_Poly1305, Has_AVX512_IFMA);
end SPARKTLSCrypto.Poly1305_AVX512;
