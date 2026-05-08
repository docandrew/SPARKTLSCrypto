--  AVX-512 IFMA Poly1305 — radix-2⁴⁴, 3-limb representation. Body.
--
--  Bulk path: 8-block batches where each lane processes one block in
--  3 × 44-bit limbs. Multiply phase is 9 vpmadd52luq + 9 vpmadd52huq
--  (compared to 25 vpmuludq + 20 vpaddq in the radix-2²⁶ backend).
--  Carry chain absorbs d_hi[k] into d_lo[k+1] (with an 8-bit shift to
--  align 52-vs-44 bit offsets) and folds d_hi[2] into d_lo[0] via the
--  2¹⁴⁰ ≡ 5120 (mod p) wraparound.
--
--  Scalar paths (r-power generation, tail blocks, final reduction)
--  use the GNAT-supported 128-bit modular type so the math stays
--  readable; this code runs at most a handful of times per Onetimeauth
--  call so the overhead is negligible.
--
--  Note: SPARK_Mode is Off in the body because of the inline asm and
--  the U128 modular type. The spec is SPARK_Mode On so callers retain
--  Constant_After_Elaboration on the CPUID flag.

with System;
with System.Machine_Code; use System.Machine_Code;
with Interfaces;          use Interfaces;
with SPARKNaCl.MAC;
with SPARKTLSCrypto.Poly1305;

package body SPARKTLSCrypto.Poly1305_AVX512_IFMA with
   SPARK_Mode => Off
is

   subtype U64 is Unsigned_64;
   subtype U32 is Unsigned_32;
   type U128 is mod 2**128;

   --  44-bit limb mask.
   M44 : constant U64 := 16#0FFF_FFFF_FFFF#;

   --================================================================
   --  CPUID detection: AVX-512F (EBX[16]) + AVX-512_IFMA (EBX[21]),
   --  plus XCR0 OS state-save enablement (XMM/YMM/Opmask/ZMM bits).
   --================================================================
   function Detect_AVX512_IFMA return Boolean is
      Mask : constant Unsigned_32 := 16#0001_0000# or 16#0020_0000#;
   begin
      declare
         EAX, EBX, ECX, EDX : Unsigned_32;
      begin
         Asm ("cpuid",
              Outputs  => (Unsigned_32'Asm_Output ("=a", EAX),
                           Unsigned_32'Asm_Output ("=b", EBX),
                           Unsigned_32'Asm_Output ("=c", ECX),
                           Unsigned_32'Asm_Output ("=d", EDX)),
              Inputs   => (Unsigned_32'Asm_Input ("a", 1),
                           Unsigned_32'Asm_Input ("c", 0)),
              Volatile => True);
         pragma Unreferenced (EAX, EBX, EDX);
         if (ECX and 16#0800_0000#) = 0 then return False; end if;
      end;
      declare
         XCR0_Lo, XCR0_Hi : Unsigned_32;
      begin
         Asm ("xgetbv",
              Outputs => (Unsigned_32'Asm_Output ("=a", XCR0_Lo),
                          Unsigned_32'Asm_Output ("=d", XCR0_Hi)),
              Inputs  => Unsigned_32'Asm_Input ("c", 0),
              Volatile => True);
         pragma Unreferenced (XCR0_Hi);
         if (XCR0_Lo and 16#E6#) /= 16#E6# then return False; end if;
      end;
      declare
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
         return (EBX and Mask) = Mask;
      end;
   end Detect_AVX512_IFMA;

   --================================================================
   --  Extract clamped r in 3 × 44-bit limbs from 16 key bytes.
   --================================================================
   procedure Extract_R_44
     (Key_Bytes : in  Bytes_32;
      r0, r1, r2 : out U64)
   is
      function Le32 (P : N32) return U32 is
      begin
         return Unsigned_32 (Key_Bytes (P))
              or Shift_Left (Unsigned_32 (Key_Bytes (P + 1)),  8)
              or Shift_Left (Unsigned_32 (Key_Bytes (P + 2)), 16)
              or Shift_Left (Unsigned_32 (Key_Bytes (P + 3)), 24);
      end Le32;

      --  Per RFC 8439 §2.5.2, clamp r:
      --    bytes 3, 7, 11, 15 &= 0x0F  (clear top 4 bits)
      --    bytes 4, 8, 12     &= 0xFC  (clear bottom 2 bits)
      --  Combined per 32-bit word:
      --    t0 (bytes 0..3): clear top 4 bits of byte 3 → mask 0x0FFF_FFFF
      --    t1 (bytes 4..7): clear top 4 of byte 7 + bottom 2 of byte 4 → 0x0FFF_FFFC
      --    t2 (bytes 8..11): same → 0x0FFF_FFFC
      --    t3 (bytes 12..15): same → 0x0FFF_FFFC
      t0 : constant U32 := Le32 (0)  and 16#0FFF_FFFF#;
      t1 : constant U32 := Le32 (4)  and 16#0FFF_FFFC#;
      t2 : constant U32 := Le32 (8)  and 16#0FFF_FFFC#;
      t3 : constant U32 := Le32 (12) and 16#0FFF_FFFC#;
   begin
      --  Repack the four 32-bit clamped words as 3 × 44-bit limbs.
      --  bits 0..43  → r0
      --  bits 44..87 → r1
      --  bits 88..127 → r2
      r0 :=  U64 (t0)
           or Shift_Left (U64 (t1) and 16#FFF#, 32);
      r1 :=  Shift_Right (U64 (t1), 12)
           or Shift_Left (U64 (t2) and 16#00FF_FFFF#, 20);
      r2 :=  Shift_Right (U64 (t2), 24)
           or Shift_Left (U64 (t3), 8);
   end Extract_R_44;

   --================================================================
   --  Convert one 16-byte block to 3 × 44-bit limbs (radix 2⁴⁴),
   --  with the high "1" bit at position 128 baked into limb 2 (bit 40).
   --================================================================
   procedure Block_To_Limbs_44
     (M     : in  Byte_Seq;
      Pos   : in  N32;
      Hi_Bit : in U64;  -- 1 for full block, 0 for the explicit-byte tail
      l0, l1, l2 : out U64)
   is
      function Le32 (P : N32) return U32 is
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
      l0 :=  U64 (t0) or Shift_Left (U64 (t1) and 16#FFF#, 32);
      l1 :=  Shift_Right (U64 (t1), 12)
           or Shift_Left (U64 (t2) and 16#00FF_FFFF#, 20);
      l2 :=  Shift_Right (U64 (t2), 24)
           or Shift_Left (U64 (t3), 8)
           or Shift_Left (Hi_Bit, 40);
   end Block_To_Limbs_44;

   --================================================================
   --  Scalar 3-limb multiply mod 2¹³⁰−5 (radix 2⁴⁴), using U128 for
   --  the partial products. Used for r-power generation and the tail
   --  block scalar fallback. Not perf-critical.
   --================================================================
   procedure Mul_3limb_44
     (h0, h1, h2 : in out U64;
      r0, r1, r2 : in     U64)
   is
      s1 : constant U64 := r1 * 20;
      s2 : constant U64 := r2 * 20;

      d0, d1, d2 : U128;
      h0_in : constant U64 := h0;
      h1_in : constant U64 := h1;
      h2_in : constant U64 := h2;

      c : U64;
   begin
      d0 :=  U128 (h0_in) * U128 (r0)
           + U128 (h1_in) * U128 (s2)
           + U128 (h2_in) * U128 (s1);
      d1 :=  U128 (h0_in) * U128 (r1)
           + U128 (h1_in) * U128 (r0)
           + U128 (h2_in) * U128 (s2);
      d2 :=  U128 (h0_in) * U128 (r2)
           + U128 (h1_in) * U128 (r1)
           + U128 (h2_in) * U128 (r0);

      --  Carry chain: extract 44-bit limbs, fold the limb-3 overflow
      --  back via 2¹³² ≡ 20 (mod p).
      h0 := U64 (d0 and U128 (M44));
      d1 := d1 + (d0 / U128 (2 ** 44));
      h1 := U64 (d1 and U128 (M44));
      d2 := d2 + (d1 / U128 (2 ** 44));
      h2 := U64 (d2 and U128 (M44));
      c  := U64 (d2 / U128 (2 ** 44));   -- limb-3 overflow
      h0 := h0 + c * 20;
      --  Carry h0 into h1.
      c  := Shift_Right (h0, 44);
      h0 := h0 and M44;
      h1 := h1 + c;
      --  Fold h2's bits 42..43 → h0 with multiplier 5 (2¹³⁰ ≡ 5 mod p),
      --  ensuring h2 < 2⁴² and total value < 2¹³⁰. Without this the
      --  caller can see h ≥ 2*p and the final reduction (which only
      --  subtracts p once) gives a wrong result.
      declare
         hi : constant U64 := Shift_Right (h2, 42);
      begin
         h2 := h2 and (Shift_Left (U64 (1), 42) - 1);
         h0 := h0 + hi * 5;
         c  := Shift_Right (h0, 44);
         h0 := h0 and M44;
         h1 := h1 + c;
      end;
   end Mul_3limb_44;

   --================================================================
   --  Process one block scalar (used for tail). Adds (block + Hi_Bit·2¹²⁸)
   --  to h, then multiplies by r mod p.
   --================================================================
   procedure Process_Block_Scalar_44
     (h0, h1, h2 : in out U64;
      r0, r1, r2 : in     U64;
      M          : in     Byte_Seq;
      Pos        : in     N32;
      Hi_Bit     : in     U64)
   is
      l0, l1, l2 : U64;
   begin
      Block_To_Limbs_44 (M, Pos, Hi_Bit, l0, l1, l2);
      h0 := h0 + l0;
      h1 := h1 + l1;
      h2 := h2 + l2;
      Mul_3limb_44 (h0, h1, h2, r0, r1, r2);
   end Process_Block_Scalar_44;

   --================================================================
   --  Asm-side constants for the deinterleave step.
   --  vpermt2q takes 4-bit lane indexes (low 3 = lane within source,
   --  high 1 = which source). For 8 blocks of 16 bytes loaded into
   --  two zmms, the low and high u64s of each block live at
   --  alternating lane positions; these indexes gather them into
   --  contiguous lanes.
   --================================================================
   Lo_Idx : constant array (0 .. 7) of U64 :=
     (0, 2, 4, 6, 8, 10, 12, 14);
   Hi_Idx : constant array (0 .. 7) of U64 :=
     (1, 3, 5, 7, 9, 11, 13, 15);
   for Lo_Idx'Alignment use 64;
   for Hi_Idx'Alignment use 64;

   --================================================================
   --  Asm fragments for the IFMA 8-block batch.
   --
   --  Register map (after the unpack step):
   --    zmm0..zmm2   message limbs (h_scalar pre-added to lane 0)
   --    zmm3..zmm5   r-powers r0..r2 packed lane-major (lane i = r^(8-i))
   --    zmm6..zmm7   s-powers s1..s2 = 20*r1, 20*r2
   --    zmm8..zmm10  d_lo[0..2] accumulators (low 52 bits per limb)
   --    zmm11..zmm13 d_hi[0..2] accumulators (high 52 bits per limb)
   --    zmm14        M44 mask (broadcast)
   --    zmm15..zmm17 carry temps
   --================================================================

   --  Setup that performs message unpacking inside the asm. %0 points
   --  at 128 bytes of message; %6 / %7 hold addresses of pre-built
   --  Lo_Idx / Hi_Idx tables for vpermt2q deinterleave. Output:
   --  zmm0 = m_limb_0, zmm1 = m_limb_1, zmm2 = m_limb_2 with h_scalar
   --  pre-added to lane 0.
   IFMA_Setup : constant String :=
        --  Load 128 bytes of message into zmm0 (blocks 0..3) and zmm1
        --  (blocks 4..7). Each block's low/high u64 occupy adjacent lanes.
        "vmovdqu64    (%0), %%zmm0"          & ASCII.LF & ASCII.HT &
        "vmovdqu64  64(%0), %%zmm1"          & ASCII.LF & ASCII.HT &
        --  Deinterleave to (block_lo) lane-major in zmm15, (block_hi)
        --  lane-major in zmm16. vpermi2q reads idx from DEST and
        --  picks from SRC1/SRC2 — the form we want here. (vpermt2q
        --  is the dual: idx in SRC1, picks from DEST/SRC2; using it
        --  here would treat the message as the index, which is the
        --  bug I had on the first attempt.)
        "vmovdqu64 (%6), %%zmm15"            & ASCII.LF & ASCII.HT &
        "vpermi2q  %%zmm1, %%zmm0, %%zmm15"  & ASCII.LF & ASCII.HT &
        "vmovdqu64 (%7), %%zmm16"            & ASCII.LF & ASCII.HT &
        "vpermi2q  %%zmm1, %%zmm0, %%zmm16"  & ASCII.LF & ASCII.HT &
        --  Broadcast M44 mask into zmm14.
        "vpbroadcastq  %3, %%zmm14"          & ASCII.LF & ASCII.HT &
        --  Extract 3 × 44-bit limbs:
        --    m_limb_0 = block_lo & M44                              (zmm0)
        --    m_limb_1 = ((block_lo>>44) | (block_hi<<20)) & M44     (zmm1)
        --    m_limb_2 = (block_hi>>24) | (1<<40)                    (zmm2)
        "vpandq    %%zmm15, %%zmm14, %%zmm0" & ASCII.LF & ASCII.HT &
        "vpsrlq    $44, %%zmm15, %%zmm17"    & ASCII.LF & ASCII.HT &
        "vpsllq    $20, %%zmm16, %%zmm15"    & ASCII.LF & ASCII.HT &
        "vporq     %%zmm17, %%zmm15, %%zmm1" & ASCII.LF & ASCII.HT &
        "vpandq    %%zmm14, %%zmm1, %%zmm1"  & ASCII.LF & ASCII.HT &
        "vpsrlq    $24, %%zmm16, %%zmm2"     & ASCII.LF & ASCII.HT &
        --  Set bit 40 of every lane (= the implicit "1" at position 128).
        "movabs    $0x10000000000, %%rax"    & ASCII.LF & ASCII.HT &
        "vpbroadcastq %%rax, %%zmm15"        & ASCII.LF & ASCII.HT &
        "vporq     %%zmm15, %%zmm2, %%zmm2"  & ASCII.LF & ASCII.HT &
        --  Add scalar h to lane 0 (H_Lanes has h in lane 0, zeros elsewhere).
        "vpaddq    (%4), %%zmm0, %%zmm0"     & ASCII.LF & ASCII.HT &
        "vpaddq  64(%4), %%zmm1, %%zmm1"     & ASCII.LF & ASCII.HT &
        "vpaddq 128(%4), %%zmm2, %%zmm2"     & ASCII.LF & ASCII.HT &
        --  Load r-powers (3 zmms) and s-powers (2 zmms).
        "vmovdqu64    (%1), %%zmm3"          & ASCII.LF & ASCII.HT &
        "vmovdqu64  64(%1), %%zmm4"          & ASCII.LF & ASCII.HT &
        "vmovdqu64 128(%1), %%zmm5"          & ASCII.LF & ASCII.HT &
        "vmovdqu64    (%2), %%zmm6"          & ASCII.LF & ASCII.HT &
        "vmovdqu64  64(%2), %%zmm7"          & ASCII.LF & ASCII.HT &
        --  Zero d_lo[0..2] and d_hi[0..2].
        "vpxorq    %%zmm8,  %%zmm8,  %%zmm8"  & ASCII.LF & ASCII.HT &
        "vpxorq    %%zmm9,  %%zmm9,  %%zmm9"  & ASCII.LF & ASCII.HT &
        "vpxorq    %%zmm10, %%zmm10, %%zmm10" & ASCII.LF & ASCII.HT &
        "vpxorq    %%zmm11, %%zmm11, %%zmm11" & ASCII.LF & ASCII.HT &
        "vpxorq    %%zmm12, %%zmm12, %%zmm12" & ASCII.LF & ASCII.HT &
        "vpxorq    %%zmm13, %%zmm13, %%zmm13" & ASCII.LF & ASCII.HT;

   --  Multiply phase: 9 schoolbook products, each contributing one
   --  vpmadd52luq into d_lo[k] and one vpmadd52huq into d_hi[k]. The
   --  schoolbook is:
   --    P0 = h0*r0 + h1*s2 + h2*s1
   --    P1 = h0*r1 + h1*r0 + h2*s2
   --    P2 = h0*r2 + h1*r1 + h2*r0
   --
   --  Interleaving order: group by h_i (the source operand changes
   --  every 6 ops), and within each h_i group, hit d_lo[0..2] /
   --  d_hi[0..2] in order. This breaks the back-to-back dependency
   --  chain on each d_lo[k] (3 vpmadd52luq's into the same register
   --  serializing at 4-cycle latency = 12 cycles). With this layout,
   --  consecutive ops touch different destinations so the OOO engine
   --  can pipeline them; the same-destination ops are spaced 6 slots
   --  apart, well past the 4-cycle latency.
   IFMA_Multiply : constant String :=
        --  Row 0 (h0): three lo's into d_lo[0..2], three hi's into d_hi[0..2].
        "vpmadd52luq %%zmm3, %%zmm0, %%zmm8"   & ASCII.LF & ASCII.HT &
        "vpmadd52luq %%zmm4, %%zmm0, %%zmm9"   & ASCII.LF & ASCII.HT &
        "vpmadd52luq %%zmm5, %%zmm0, %%zmm10"  & ASCII.LF & ASCII.HT &
        "vpmadd52huq %%zmm3, %%zmm0, %%zmm11"  & ASCII.LF & ASCII.HT &
        "vpmadd52huq %%zmm4, %%zmm0, %%zmm12"  & ASCII.LF & ASCII.HT &
        "vpmadd52huq %%zmm5, %%zmm0, %%zmm13"  & ASCII.LF & ASCII.HT &
        --  Row 1 (h1).
        "vpmadd52luq %%zmm7, %%zmm1, %%zmm8"   & ASCII.LF & ASCII.HT &
        "vpmadd52luq %%zmm3, %%zmm1, %%zmm9"   & ASCII.LF & ASCII.HT &
        "vpmadd52luq %%zmm4, %%zmm1, %%zmm10"  & ASCII.LF & ASCII.HT &
        "vpmadd52huq %%zmm7, %%zmm1, %%zmm11"  & ASCII.LF & ASCII.HT &
        "vpmadd52huq %%zmm3, %%zmm1, %%zmm12"  & ASCII.LF & ASCII.HT &
        "vpmadd52huq %%zmm4, %%zmm1, %%zmm13"  & ASCII.LF & ASCII.HT &
        --  Row 2 (h2).
        "vpmadd52luq %%zmm6, %%zmm2, %%zmm8"   & ASCII.LF & ASCII.HT &
        "vpmadd52luq %%zmm7, %%zmm2, %%zmm9"   & ASCII.LF & ASCII.HT &
        "vpmadd52luq %%zmm3, %%zmm2, %%zmm10"  & ASCII.LF & ASCII.HT &
        "vpmadd52huq %%zmm6, %%zmm2, %%zmm11"  & ASCII.LF & ASCII.HT &
        "vpmadd52huq %%zmm7, %%zmm2, %%zmm12"  & ASCII.LF & ASCII.HT &
        "vpmadd52huq %%zmm3, %%zmm2, %%zmm13"  & ASCII.LF & ASCII.HT;

   --  Carry chain. After mul:
   --    d_lo[k] holds low 52 bits of accumulator at limb position k
   --    d_hi[k] holds the high half (bits 52..) at the same position
   --  In radix-2⁴⁴, d_hi[k] * 2⁵² aligns with limb (k+1) shifted by 8 bits
   --  (52 = 44 + 8). So we absorb d_hi[k] into d_lo[k+1] as (d_hi[k]<<8).
   --  d_hi[2] aligns with "limb 3" (position 132+8=140), which wraps mod p
   --  via 2¹⁴⁰ ≡ 5·2¹⁰ = 5120, contributing 5120·d_hi[2] to limb 0.
   --  Then a 5-step carry chain produces 44-bit limbs.
   IFMA_Carry_And_Store : constant String :=
        --  Phase 1: absorb d_hi into d_lo (with shift/wrap).
        --  d_lo[1] += d_hi[0] << 8
        "vpsllq    $8,  %%zmm11, %%zmm15"     & ASCII.LF & ASCII.HT &
        "vpaddq    %%zmm15, %%zmm9, %%zmm9"   & ASCII.LF & ASCII.HT &
        --  d_lo[2] += d_hi[1] << 8
        "vpsllq    $8,  %%zmm12, %%zmm15"     & ASCII.LF & ASCII.HT &
        "vpaddq    %%zmm15, %%zmm10, %%zmm10" & ASCII.LF & ASCII.HT &
        --  d_lo[0] += d_hi[2] * 5120 = (d_hi[2]<<12) + (d_hi[2]<<10)
        "vpsllq    $12, %%zmm13, %%zmm15"     & ASCII.LF & ASCII.HT &
        "vpsllq    $10, %%zmm13, %%zmm16"     & ASCII.LF & ASCII.HT &
        "vpaddq    %%zmm15, %%zmm16, %%zmm15" & ASCII.LF & ASCII.HT &
        "vpaddq    %%zmm15, %%zmm8, %%zmm8"   & ASCII.LF & ASCII.HT &

        --  Phase 2: 5-step carry chain to produce 44-bit limbs.
        --  Broadcast M44 into zmm14.
        "vpbroadcastq  %3, %%zmm14"           & ASCII.LF & ASCII.HT &
        --  Step 1: c = d_lo[0]>>44; d_lo[0]&=M44; d_lo[1] += c
        "vpsrlq    $44, %%zmm8,  %%zmm15"     & ASCII.LF & ASCII.HT &
        "vpandq    %%zmm14, %%zmm8, %%zmm8"   & ASCII.LF & ASCII.HT &
        "vpaddq    %%zmm15, %%zmm9, %%zmm9"   & ASCII.LF & ASCII.HT &
        --  Step 2: same for d_lo[1] -> d_lo[2]
        "vpsrlq    $44, %%zmm9,  %%zmm15"     & ASCII.LF & ASCII.HT &
        "vpandq    %%zmm14, %%zmm9, %%zmm9"   & ASCII.LF & ASCII.HT &
        "vpaddq    %%zmm15, %%zmm10, %%zmm10" & ASCII.LF & ASCII.HT &
        --  Step 3: c = d_lo[2]>>44; d_lo[2]&=M44; d_lo[0] += c*20
        --  c*20 = (c<<4)+(c<<2)
        "vpsrlq    $44, %%zmm10, %%zmm15"     & ASCII.LF & ASCII.HT &
        "vpandq    %%zmm14, %%zmm10, %%zmm10" & ASCII.LF & ASCII.HT &
        "vpsllq    $4,  %%zmm15, %%zmm16"     & ASCII.LF & ASCII.HT &
        "vpsllq    $2,  %%zmm15, %%zmm17"     & ASCII.LF & ASCII.HT &
        "vpaddq    %%zmm16, %%zmm17, %%zmm15" & ASCII.LF & ASCII.HT &
        "vpaddq    %%zmm15, %%zmm8, %%zmm8"   & ASCII.LF & ASCII.HT &
        --  Step 4: clean d_lo[0] (could be ~45 bits after the c*20 add)
        "vpsrlq    $44, %%zmm8,  %%zmm15"     & ASCII.LF & ASCII.HT &
        "vpandq    %%zmm14, %%zmm8, %%zmm8"   & ASCII.LF & ASCII.HT &
        "vpaddq    %%zmm15, %%zmm9, %%zmm9"   & ASCII.LF & ASCII.HT &

        --  Store d_lo[0..2] for horizontal sum in Ada.
        "vmovdqu64 %%zmm8,    (%5)"           & ASCII.LF & ASCII.HT &
        "vmovdqu64 %%zmm9,  64(%5)"           & ASCII.LF & ASCII.HT &
        "vmovdqu64 %%zmm10,128(%5)"           & ASCII.LF & ASCII.HT &
        "vzeroupper";

   --  Diagnostic: run only the unpack+limb-extraction portion of the
   --  IFMA asm body, store the resulting m_limb_0/1/2 to memory so
   --  the test can compare against an Ada-side Block_To_Limbs_44.
   procedure Debug_Unpack
     (Msg     : in     Byte_Seq;       -- exactly 128 bytes
      M_Out   :    out Byte_Seq)       -- exactly 192 bytes
   is
      Msg_Addr   : constant System.Address := Msg (Msg'First)'Address;
      M_Out_Addr : constant System.Address := M_Out (M_Out'First)'Address;
      Dummy_R, Dummy_S, Dummy_H : System.Address;
      type U64_Lane is array (0 .. 7) of U64;
      type Triplet is array (0 .. 2) of U64_Lane;
      Z3 : Triplet := (others => (others => 0));
      for Z3'Alignment use 64;
   begin
      M_Out := (others => 0);  -- baseline init; asm overwrites
      Dummy_R := Z3'Address;
      Dummy_S := Z3'Address;
      Dummy_H := Z3'Address;

      Asm
       (-- Load 128 bytes
        "vmovdqu64    (%0), %%zmm0"          & ASCII.LF & ASCII.HT &
        "vmovdqu64  64(%0), %%zmm1"          & ASCII.LF & ASCII.HT &
        -- Deinterleave with vpermi2q (idx in DEST, sources in SRC1/SRC2).
        "vmovdqu64 (%1), %%zmm15"            & ASCII.LF & ASCII.HT &
        "vpermi2q  %%zmm1, %%zmm0, %%zmm15"  & ASCII.LF & ASCII.HT &
        "vmovdqu64 (%2), %%zmm16"            & ASCII.LF & ASCII.HT &
        "vpermi2q  %%zmm1, %%zmm0, %%zmm16"  & ASCII.LF & ASCII.HT &
        -- Extract
        "vpbroadcastq  %3, %%zmm14"          & ASCII.LF & ASCII.HT &
        "vpandq    %%zmm15, %%zmm14, %%zmm10" & ASCII.LF & ASCII.HT &
        "vpsrlq    $44, %%zmm15, %%zmm17"    & ASCII.LF & ASCII.HT &
        "vpsllq    $20, %%zmm16, %%zmm15"    & ASCII.LF & ASCII.HT &
        "vporq     %%zmm17, %%zmm15, %%zmm11" & ASCII.LF & ASCII.HT &
        "vpandq    %%zmm14, %%zmm11, %%zmm11"  & ASCII.LF & ASCII.HT &
        "vpsrlq    $24, %%zmm16, %%zmm12"     & ASCII.LF & ASCII.HT &
        "movabs    $0x10000000000, %%rax"    & ASCII.LF & ASCII.HT &
        "vpbroadcastq %%rax, %%zmm15"        & ASCII.LF & ASCII.HT &
        "vporq     %%zmm15, %%zmm12, %%zmm12"  & ASCII.LF & ASCII.HT &
        -- Store
        "vmovdqu64 %%zmm10,    (%4)"          & ASCII.LF & ASCII.HT &
        "vmovdqu64 %%zmm11,  64(%4)"          & ASCII.LF & ASCII.HT &
        "vmovdqu64 %%zmm12, 128(%4)"          & ASCII.LF & ASCII.HT &
        "vzeroupper",
        Inputs => (System.Address'Asm_Input ("r", Msg_Addr),
                   System.Address'Asm_Input ("r", Lo_Idx'Address),
                   System.Address'Asm_Input ("r", Hi_Idx'Address),
                   U64'Asm_Input ("r", M44),
                   System.Address'Asm_Input ("r", M_Out_Addr)),
        Clobber => "rax,xmm0,xmm1,xmm10,xmm11,xmm12,xmm14,xmm15,xmm16,xmm17,memory",
        Volatile => True);
      pragma Unreferenced (Dummy_R, Dummy_S, Dummy_H);
   end Debug_Unpack;

   --  Process one 8-block batch. Updates h0..h2 in place. The first
   --  argument is now the *raw* 128-byte message — the asm setup
   --  above unpacks it directly, eliminating the per-batch Ada-side
   --  Block_To_Limbs_44 loop.
   procedure Process_8_Block_Batch
     (h0, h1, h2 : in out U64;
      Msg        : in     System.Address;  -- 128 raw bytes
      R_Powers   : in     System.Address;  -- 3 × 8 × U64
      S_Powers   : in     System.Address)  -- 2 × 8 × U64
   is
      type U64_Lane is array (0 .. 7) of U64;
      type Out_Buf is array (0 .. 2) of U64_Lane;
      Out_Lanes : Out_Buf;
      for Out_Lanes'Alignment use 64;
      H_Lanes : Out_Buf := (others => (others => 0));
      for H_Lanes'Alignment use 64;
   begin
      H_Lanes (0) (0) := h0;
      H_Lanes (1) (0) := h1;
      H_Lanes (2) (0) := h2;

      Asm
        (IFMA_Setup & IFMA_Multiply & IFMA_Carry_And_Store,
         Inputs => (System.Address'Asm_Input ("r", Msg),              -- %0
                    System.Address'Asm_Input ("r", R_Powers),         -- %1
                    System.Address'Asm_Input ("r", S_Powers),         -- %2
                    U64'Asm_Input            ("r", M44),              -- %3
                    System.Address'Asm_Input ("r", H_Lanes'Address),  -- %4
                    System.Address'Asm_Input ("r", Out_Lanes'Address),-- %5
                    System.Address'Asm_Input ("r", Lo_Idx'Address),   -- %6
                    System.Address'Asm_Input ("r", Hi_Idx'Address)),  -- %7
         Clobber => "rax,xmm0,xmm1,xmm2,xmm3,xmm4,xmm5,xmm6,xmm7,xmm8," &
                    "xmm9,xmm10,xmm11,xmm12,xmm13,xmm14,xmm15,xmm16," &
                    "xmm17,memory",
         Volatile => True);

      --  Horizontal sum across 8 lanes.
      h0 := Out_Lanes (0) (0) + Out_Lanes (0) (1) + Out_Lanes (0) (2)
          + Out_Lanes (0) (3) + Out_Lanes (0) (4) + Out_Lanes (0) (5)
          + Out_Lanes (0) (6) + Out_Lanes (0) (7);
      h1 := Out_Lanes (1) (0) + Out_Lanes (1) (1) + Out_Lanes (1) (2)
          + Out_Lanes (1) (3) + Out_Lanes (1) (4) + Out_Lanes (1) (5)
          + Out_Lanes (1) (6) + Out_Lanes (1) (7);
      h2 := Out_Lanes (2) (0) + Out_Lanes (2) (1) + Out_Lanes (2) (2)
          + Out_Lanes (2) (3) + Out_Lanes (2) (4) + Out_Lanes (2) (5)
          + Out_Lanes (2) (6) + Out_Lanes (2) (7);

      --  Re-carry the scalar h after the horizontal sum (each h_j may
      --  exceed 44 bits since we summed 8 ~45-bit values). The standard
      --  *20 fold handles overflow from limb 3, but we additionally fold
      --  h2's bits 42..43 (which represent values 2^130, 2^131) back to
      --  limb 0 with multiplier 5 (since 2^130 ≡ 5 mod p). Without this
      --  step h could exceed 2*p and the final-reduction's single
      --  subtract would be insufficient.
      declare
         c, hi : U64;
      begin
         c  := Shift_Right (h0, 44); h0 := h0 and M44;
         h1 := h1 + c;
         c  := Shift_Right (h1, 44); h1 := h1 and M44;
         h2 := h2 + c;
         c  := Shift_Right (h2, 44); h2 := h2 and M44;
         h0 := h0 + c * 20;
         c  := Shift_Right (h0, 44); h0 := h0 and M44;
         h1 := h1 + c;
         --  Fold h2's bits 42..43 → h0 with multiplier 5.
         hi := Shift_Right (h2, 42);
         h2 := h2 and (Shift_Left (U64 (1), 42) - 1);
         h0 := h0 + hi * 5;
         c  := Shift_Right (h0, 44); h0 := h0 and M44;
         h1 := h1 + c;
      end;
   end Process_8_Block_Batch;

   --================================================================
   --  Onetimeauth: 8-block batched IFMA bulk + scalar tail.
   --================================================================

   procedure Onetimeauth
     (Output :    out Bytes_16;
      M      : in     Byte_Seq;
      K      : in     SPARKNaCl.MAC.Poly_1305_Key)
   is
      type Lane_8 is array (0 .. 7) of U64;
   begin
      --  Below ~128 bytes the SIMD overhead outweighs the gain.
      if M'Length < 128 then
         SPARKTLSCrypto.Poly1305.Onetimeauth (Output, M, K);
         return;
      end if;

      declare
         Key_Bytes : constant Bytes_32 := SPARKNaCl.MAC.Serialize (K);

         --  r¹..r⁸ — each is 3 × 44-bit limbs.
         type R_Power is record
            l0, l1, l2 : U64;
         end record;
         R_Pwrs : array (1 .. 8) of R_Power;

         R_Tab : array (0 .. 2) of Lane_8 := (others => (others => 0));
         S_Tab : array (0 .. 1) of Lane_8 := (others => (others => 0));
         for R_Tab'Alignment use 64;
         for S_Tab'Alignment use 64;

         h0, h1, h2 : U64 := 0;
         r0, r1, r2 : U64;

         Pos       : N32 := M'First;
         End_Last  : constant N32 := M'Last;
      begin
         Output := (others => 0);

         --  Setup: extract clamped r in radix-2⁴⁴, compute r¹..r⁸.
         Extract_R_44 (Key_Bytes, r0, r1, r2);
         R_Pwrs (1) := (r0, r1, r2);
         for K_Idx in 2 .. 8 loop
            declare
               t0 : U64 := R_Pwrs (K_Idx - 1).l0;
               t1 : U64 := R_Pwrs (K_Idx - 1).l1;
               t2 : U64 := R_Pwrs (K_Idx - 1).l2;
            begin
               Mul_3limb_44 (t0, t1, t2, r0, r1, r2);
               R_Pwrs (K_Idx) := (t0, t1, t2);
            end;
         end loop;

         --  Lay out R_Tab so lane i (0..7) gets r^(8-i) — same convention
         --  as the radix-2²⁶ backend so the asm "rolling-accumulator"
         --  identity h_new = h*r⁸ + B0·r⁸ + B1·r⁷ + … + B7·r¹ holds.
         for I in 0 .. 7 loop
            R_Tab (0) (I) := R_Pwrs (8 - I).l0;
            R_Tab (1) (I) := R_Pwrs (8 - I).l1;
            R_Tab (2) (I) := R_Pwrs (8 - I).l2;
            S_Tab (0) (I) := R_Pwrs (8 - I).l1 * 20;
            S_Tab (1) (I) := R_Pwrs (8 - I).l2 * 20;
         end loop;

         --  Bulk loop: process 8-block (128-byte) batches. The asm
         --  setup unpacks the raw 128-byte message into 3 lane-major
         --  limb zmms internally — no per-batch Ada-side Block_To_Limbs.
         while Pos + 127 <= End_Last loop
            Process_8_Block_Batch
              (h0, h1, h2,
               M (Pos)'Address, R_Tab'Address, S_Tab'Address);
            Pos := Pos + 128;
         end loop;

         --  Tail: process remaining < 128 bytes one block at a time.
         while Pos + 15 <= End_Last loop
            Process_Block_Scalar_44
              (h0, h1, h2, r0, r1, r2, M, Pos, 1);
            Pos := Pos + 16;
         end loop;

         --  Final partial block (if any).
         if Pos <= End_Last then
            declare
               Remaining : constant N32 := End_Last - Pos + 1;
               Block     : Bytes_16 := (others => 0);
               l0, l1, l2 : U64;
            begin
               for I in 0 .. Remaining - 1 loop
                  Block (I) := M (Pos + I);
               end loop;
               Block (Remaining) := 1;  -- explicit "1" terminator
               --  Hi_Bit = 0 since the explicit byte does it.
               Block_To_Limbs_44 (Byte_Seq (Block), 0, 0, l0, l1, l2);
               h0 := h0 + l0;
               h1 := h1 + l1;
               h2 := h2 + l2;
               Mul_3limb_44 (h0, h1, h2, r0, r1, r2);
            end;
         end if;

         --  Final reduction in radix-2⁴⁴: subtract p = 2¹³⁰−5 if h ≥ p.
         --  After all carry passes, each h_j fits in 44 bits with h2 ≤ 2⁴².
         declare
            c, mask : U64;
            g0, g1, g2 : U64;
            f0, f1, f2, f3 : U64;
            u : U64;
            function Le32_Key (P : N32) return U32 is
            begin
               return Unsigned_32 (Key_Bytes (P))
                    or Shift_Left (Unsigned_32 (Key_Bytes (P + 1)),  8)
                    or Shift_Left (Unsigned_32 (Key_Bytes (P + 2)), 16)
                    or Shift_Left (Unsigned_32 (Key_Bytes (P + 3)), 24);
            end Le32_Key;
         begin
            --  Final carry chain to canonicalize h. Includes the
            --  h2-bits-42..43 → h0 fold so h2 ends < 2⁴² and the
            --  single-subtract g check works for h < 2*p.
            c  := Shift_Right (h0, 44); h0 := h0 and M44;
            h1 := h1 + c;
            c  := Shift_Right (h1, 44); h1 := h1 and M44;
            h2 := h2 + c;
            c  := Shift_Right (h2, 44); h2 := h2 and M44;
            h0 := h0 + c * 20;
            c  := Shift_Right (h0, 44); h0 := h0 and M44;
            h1 := h1 + c;
            declare
               hi : constant U64 := Shift_Right (h2, 42);
            begin
               h2 := h2 and (Shift_Left (U64 (1), 42) - 1);
               h0 := h0 + hi * 5;
               c  := Shift_Right (h0, 44); h0 := h0 and M44;
               h1 := h1 + c;
            end;

            --  Compute g = h + 5 - 2¹³⁰. If g ≥ 0 (no underflow) then
            --  h ≥ p, so use g; otherwise use h.
            g0 := h0 + 5;
            c  := Shift_Right (g0, 44); g0 := g0 and M44;
            g1 := h1 + c;
            c  := Shift_Right (g1, 44); g1 := g1 and M44;
            g2 := h2 + c - Shift_Left (U64 (1), 42);
            --  h2 < 2⁴² in canonical form; subtracting 2⁴² gives a
            --  64-bit value whose top bit is the underflow indicator.

            mask := 0 - Shift_Right (g2, 63);  -- 0xFF... if h<p else 0
            h0 := (h0 and mask) or (g0 and not mask);
            h1 := (h1 and mask) or (g1 and not mask);
            h2 := (h2 and mask) or (g2 and not mask);

            --  Pack h (3 × 44-bit) back to 4 × 32-bit words for the +s step.
            --  Total bits 0..127 of h:
            --    f0 (bits 0..31)   = bits 0..31 of (h0)
            --    f1 (bits 32..63)  = bits 32..43 of h0 + bits 0..19 of h1
            --    f2 (bits 64..95)  = bits 20..43 of h1 + bits 0..7 of h2
            --    f3 (bits 96..127) = bits 8..39 of h2
            f0 := h0 and 16#FFFF_FFFF#;
            f1 := (Shift_Right (h0, 32) or Shift_Left (h1, 12)) and 16#FFFF_FFFF#;
            f2 := (Shift_Right (h1, 20) or Shift_Left (h2, 24)) and 16#FFFF_FFFF#;
            f3 := Shift_Right (h2, 8)                          and 16#FFFF_FFFF#;

            --  Add s = K[16..31] (the second half of the Poly1305 key).
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
   Has_AVX512_IFMA_Poly1305 := Detect_AVX512_IFMA;
end SPARKTLSCrypto.Poly1305_AVX512_IFMA;
