--  AVX-512 VAES + VPCLMULQDQ AES-GCM accelerator (body).
--  See sparktlscrypto-aes_gcm_avx512.ads.

with System.Machine_Code; use System.Machine_Code;
with Interfaces;          use Interfaces;
with SPARKNaCl;           use SPARKNaCl;
with SPARKTLSCrypto.GHASH_NI;

package body SPARKTLSCrypto.AES_GCM_AVX512 with
   SPARK_Mode => Off
is

   --================================================================
   --  Constants used by the 16-block counter generator
   --================================================================

   --  Per-lane PSHUFB mask: identity for bytes 0..11 (IV), reverses
   --  bytes 12..15 (BE counter -> LE for PADDD). 4 copies for zmm.
   Reverse_Ctr_Mask_ZMM : constant array (0 .. 63) of Unsigned_8 :=
     (0,1,2,3, 4,5,6,7, 8,9,10,11, 15,14,13,12,
      0,1,2,3, 4,5,6,7, 8,9,10,11, 15,14,13,12,
      0,1,2,3, 4,5,6,7, 8,9,10,11, 15,14,13,12,
      0,1,2,3, 4,5,6,7, 8,9,10,11, 15,14,13,12);
   for Reverse_Ctr_Mask_ZMM'Alignment use 64;

   --  Per-lane increment vectors. Each 64-byte block holds 4 deltas
   --  (one per zmm lane), placed at bytes 12..15 of each lane as a
   --  little-endian u32 (which is what PADDD adds after PSHUFB).
   Ctr_Inc_0_3 : constant array (0 .. 63) of Unsigned_8 :=
     (0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,    --  +0
      0,0,0,0, 0,0,0,0, 0,0,0,0, 1,0,0,0,    --  +1
      0,0,0,0, 0,0,0,0, 0,0,0,0, 2,0,0,0,    --  +2
      0,0,0,0, 0,0,0,0, 0,0,0,0, 3,0,0,0);   --  +3
   for Ctr_Inc_0_3'Alignment use 64;
   Ctr_Inc_4_7 : constant array (0 .. 63) of Unsigned_8 :=
     (0,0,0,0, 0,0,0,0, 0,0,0,0, 4,0,0,0,
      0,0,0,0, 0,0,0,0, 0,0,0,0, 5,0,0,0,
      0,0,0,0, 0,0,0,0, 0,0,0,0, 6,0,0,0,
      0,0,0,0, 0,0,0,0, 0,0,0,0, 7,0,0,0);
   for Ctr_Inc_4_7'Alignment use 64;
   Ctr_Inc_8_11 : constant array (0 .. 63) of Unsigned_8 :=
     (0,0,0,0, 0,0,0,0, 0,0,0,0, 8,0,0,0,
      0,0,0,0, 0,0,0,0, 0,0,0,0, 9,0,0,0,
      0,0,0,0, 0,0,0,0, 0,0,0,0, 10,0,0,0,
      0,0,0,0, 0,0,0,0, 0,0,0,0, 11,0,0,0);
   for Ctr_Inc_8_11'Alignment use 64;
   Ctr_Inc_12_15 : constant array (0 .. 63) of Unsigned_8 :=
     (0,0,0,0, 0,0,0,0, 0,0,0,0, 12,0,0,0,
      0,0,0,0, 0,0,0,0, 0,0,0,0, 13,0,0,0,
      0,0,0,0, 0,0,0,0, 0,0,0,0, 14,0,0,0,
      0,0,0,0, 0,0,0,0, 0,0,0,0, 15,0,0,0);
   for Ctr_Inc_12_15'Alignment use 64;

   --  Single-lane CB advance by 16 (used at end of Build_Ctr_Block_16).
   Ctr_Inc_16 : constant array (0 .. 15) of Unsigned_8 :=
     (0,0,0,0, 0,0,0,0, 0,0,0,0, 16,0,0,0);
   for Ctr_Inc_16'Alignment use 16;

   --  16-byte half of Reverse_Ctr_Mask_ZMM, for the trailing CB update.
   Reverse_Ctr_Mask_XMM : constant array (0 .. 15) of Unsigned_8 :=
     (0,1,2,3, 4,5,6,7, 8,9,10,11, 15,14,13,12);
   for Reverse_Ctr_Mask_XMM'Alignment use 16;

   --  Full byte-reverse mask (NIST GHASH <-> PCLMULQDQ orientation).
   --  Single 16-byte version + 64-byte broadcast for zmm.
   Bswap_Mask_XMM : constant array (0 .. 15) of Unsigned_8 :=
     (15,14,13,12, 11,10,9,8, 7,6,5,4, 3,2,1,0);
   for Bswap_Mask_XMM'Alignment use 16;
   Bswap_Mask_ZMM : constant array (0 .. 63) of Unsigned_8 :=
     (15,14,13,12, 11,10,9,8, 7,6,5,4, 3,2,1,0,
      15,14,13,12, 11,10,9,8, 7,6,5,4, 3,2,1,0,
      15,14,13,12, 11,10,9,8, 7,6,5,4, 3,2,1,0,
      15,14,13,12, 11,10,9,8, 7,6,5,4, 3,2,1,0);
   for Bswap_Mask_ZMM'Alignment use 64;

   --================================================================
   --  CPUID detection (run once at elaboration)
   --================================================================
   --  Required features (all in CPUID.7.0):
   --    EBX[16] = AVX512F           (basic AVX-512 foundation)
   --    ECX[9]  = VAES              (AES on ymm/zmm)
   --    ECX[10] = VPCLMULQDQ        (carry-less multiply on ymm/zmm)
   --  Plus OS enablement (XCR0): bits 1,2,5,6,7 — XMM, YMM, Opmask,
   --  ZMM_Hi256, Hi16_ZMM. Without these the OS won't save zmm state
   --  on context switch and VAES/etc would #UD. Some VMs and seccomp
   --  policies leave AVX-512 OS state disabled even when the CPU
   --  exposes it; we must check XCR0 explicitly to avoid SIGILL.

   function Detect_AVX512_AES_GCM return Boolean is
   begin
      --  CPUID.1.ECX[27] = OSXSAVE: OS supports XGETBV/XSETBV.
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
      --  XGETBV ECX=0: XCR0 → EDX:EAX.
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
      --  CPUID.7.0 feature bits.
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
         pragma Unreferenced (EAX, EDX);
         return (EBX and 16#0001_0000#) /= 0   -- AVX-512F
            and (ECX and 16#0000_0200#) /= 0   -- VAES
            and (ECX and 16#0000_0400#) /= 0;  -- VPCLMULQDQ
      end;
   end Detect_AVX512_AES_GCM;

   --================================================================
   --  16-block AES-128 cipher
   --================================================================
   --  Layout:
   --    zmm0..zmm3 = state (each holds 4 blocks → 16 blocks total)
   --    zmm4       = round-key broadcast loader
   --
   --  Per round: vbroadcasti64x2 loads one 16-byte RK and broadcasts
   --  it into all 4 lanes of zmm4. Then 4 vaesenc instructions issue
   --  back-to-back (port 0 on Zen 5, 1/cycle throughput).

   procedure Cipher_16x_128_VAES
     (Output : out Bytes_256;
      Input  : in     Bytes_256;
      Pre_RK : in     SPARKTLSCrypto.AES_NI.Pre_Swapped_RKs_128)
   is
   begin
      Asm
       (--  Load 4 zmm regs from Input (4 × 64 bytes).
        "vmovdqu64    (%0), %%zmm0"          & ASCII.LF & ASCII.HT &
        "vmovdqu64  64(%0), %%zmm1"          & ASCII.LF & ASCII.HT &
        "vmovdqu64 128(%0), %%zmm2"          & ASCII.LF & ASCII.HT &
        "vmovdqu64 192(%0), %%zmm3"          & ASCII.LF & ASCII.HT &
        --  Round 0: broadcast RK[0] and XOR into all 4 zmms.
        "vbroadcasti64x2    (%1), %%zmm4"    & ASCII.LF & ASCII.HT &
        "vpxorq    %%zmm4, %%zmm0, %%zmm0"   & ASCII.LF & ASCII.HT &
        "vpxorq    %%zmm4, %%zmm1, %%zmm1"   & ASCII.LF & ASCII.HT &
        "vpxorq    %%zmm4, %%zmm2, %%zmm2"   & ASCII.LF & ASCII.HT &
        "vpxorq    %%zmm4, %%zmm3, %%zmm3"   & ASCII.LF & ASCII.HT &
        --  Rounds 1..9: VAESENC on shared round key.
        "vbroadcasti64x2  16(%1), %%zmm4"    & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm0, %%zmm0"   & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm1, %%zmm1"   & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm2, %%zmm2"   & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm3, %%zmm3"   & ASCII.LF & ASCII.HT &
        "vbroadcasti64x2  32(%1), %%zmm4"    & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm0, %%zmm0"   & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm1, %%zmm1"   & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm2, %%zmm2"   & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm3, %%zmm3"   & ASCII.LF & ASCII.HT &
        "vbroadcasti64x2  48(%1), %%zmm4"    & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm0, %%zmm0"   & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm1, %%zmm1"   & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm2, %%zmm2"   & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm3, %%zmm3"   & ASCII.LF & ASCII.HT &
        "vbroadcasti64x2  64(%1), %%zmm4"    & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm0, %%zmm0"   & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm1, %%zmm1"   & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm2, %%zmm2"   & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm3, %%zmm3"   & ASCII.LF & ASCII.HT &
        "vbroadcasti64x2  80(%1), %%zmm4"    & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm0, %%zmm0"   & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm1, %%zmm1"   & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm2, %%zmm2"   & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm3, %%zmm3"   & ASCII.LF & ASCII.HT &
        "vbroadcasti64x2  96(%1), %%zmm4"    & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm0, %%zmm0"   & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm1, %%zmm1"   & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm2, %%zmm2"   & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm3, %%zmm3"   & ASCII.LF & ASCII.HT &
        "vbroadcasti64x2 112(%1), %%zmm4"    & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm0, %%zmm0"   & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm1, %%zmm1"   & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm2, %%zmm2"   & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm3, %%zmm3"   & ASCII.LF & ASCII.HT &
        "vbroadcasti64x2 128(%1), %%zmm4"    & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm0, %%zmm0"   & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm1, %%zmm1"   & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm2, %%zmm2"   & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm3, %%zmm3"   & ASCII.LF & ASCII.HT &
        "vbroadcasti64x2 144(%1), %%zmm4"    & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm0, %%zmm0"   & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm1, %%zmm1"   & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm2, %%zmm2"   & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm3, %%zmm3"   & ASCII.LF & ASCII.HT &
        --  Round 10: VAESENCLAST.
        "vbroadcasti64x2 160(%1), %%zmm4"    & ASCII.LF & ASCII.HT &
        "vaesenclast %%zmm4, %%zmm0, %%zmm0" & ASCII.LF & ASCII.HT &
        "vaesenclast %%zmm4, %%zmm1, %%zmm1" & ASCII.LF & ASCII.HT &
        "vaesenclast %%zmm4, %%zmm2, %%zmm2" & ASCII.LF & ASCII.HT &
        "vaesenclast %%zmm4, %%zmm3, %%zmm3" & ASCII.LF & ASCII.HT &
        --  Store 4 zmm to Output, then VZEROUPPER to clean state.
        "vmovdqu64 %%zmm0,    (%2)"          & ASCII.LF & ASCII.HT &
        "vmovdqu64 %%zmm1,  64(%2)"          & ASCII.LF & ASCII.HT &
        "vmovdqu64 %%zmm2, 128(%2)"          & ASCII.LF & ASCII.HT &
        "vmovdqu64 %%zmm3, 192(%2)"          & ASCII.LF & ASCII.HT &
        "vzeroupper",
        Inputs  => (System.Address'Asm_Input ("r", Input'Address),
                    System.Address'Asm_Input ("r", Pre_RK'Address),
                    System.Address'Asm_Input ("r", Output'Address)),
        Clobber => "xmm0,xmm1,xmm2,xmm3,xmm4,memory",
        Volatile => True);
   end Cipher_16x_128_VAES;

   --================================================================
   --  16-block AES-256 cipher (14 rounds)
   --================================================================

   procedure Cipher_16x_256_VAES
     (Output : out Bytes_256;
      Input  : in     Bytes_256;
      Pre_RK : in     SPARKTLSCrypto.AES_NI.Pre_Swapped_RKs_256)
   is
   begin
      Asm
       ("vmovdqu64    (%0), %%zmm0"          & ASCII.LF & ASCII.HT &
        "vmovdqu64  64(%0), %%zmm1"          & ASCII.LF & ASCII.HT &
        "vmovdqu64 128(%0), %%zmm2"          & ASCII.LF & ASCII.HT &
        "vmovdqu64 192(%0), %%zmm3"          & ASCII.LF & ASCII.HT &
        "vbroadcasti64x2    (%1), %%zmm4"    & ASCII.LF & ASCII.HT &
        "vpxorq    %%zmm4, %%zmm0, %%zmm0"   & ASCII.LF & ASCII.HT &
        "vpxorq    %%zmm4, %%zmm1, %%zmm1"   & ASCII.LF & ASCII.HT &
        "vpxorq    %%zmm4, %%zmm2, %%zmm2"   & ASCII.LF & ASCII.HT &
        "vpxorq    %%zmm4, %%zmm3, %%zmm3"   & ASCII.LF & ASCII.HT &
        "vbroadcasti64x2  16(%1), %%zmm4"    & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm0, %%zmm0"   & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm1, %%zmm1"   & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm2, %%zmm2"   & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm3, %%zmm3"   & ASCII.LF & ASCII.HT &
        "vbroadcasti64x2  32(%1), %%zmm4"    & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm0, %%zmm0"   & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm1, %%zmm1"   & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm2, %%zmm2"   & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm3, %%zmm3"   & ASCII.LF & ASCII.HT &
        "vbroadcasti64x2  48(%1), %%zmm4"    & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm0, %%zmm0"   & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm1, %%zmm1"   & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm2, %%zmm2"   & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm3, %%zmm3"   & ASCII.LF & ASCII.HT &
        "vbroadcasti64x2  64(%1), %%zmm4"    & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm0, %%zmm0"   & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm1, %%zmm1"   & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm2, %%zmm2"   & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm3, %%zmm3"   & ASCII.LF & ASCII.HT &
        "vbroadcasti64x2  80(%1), %%zmm4"    & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm0, %%zmm0"   & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm1, %%zmm1"   & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm2, %%zmm2"   & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm3, %%zmm3"   & ASCII.LF & ASCII.HT &
        "vbroadcasti64x2  96(%1), %%zmm4"    & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm0, %%zmm0"   & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm1, %%zmm1"   & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm2, %%zmm2"   & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm3, %%zmm3"   & ASCII.LF & ASCII.HT &
        "vbroadcasti64x2 112(%1), %%zmm4"    & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm0, %%zmm0"   & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm1, %%zmm1"   & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm2, %%zmm2"   & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm3, %%zmm3"   & ASCII.LF & ASCII.HT &
        "vbroadcasti64x2 128(%1), %%zmm4"    & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm0, %%zmm0"   & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm1, %%zmm1"   & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm2, %%zmm2"   & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm3, %%zmm3"   & ASCII.LF & ASCII.HT &
        "vbroadcasti64x2 144(%1), %%zmm4"    & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm0, %%zmm0"   & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm1, %%zmm1"   & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm2, %%zmm2"   & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm3, %%zmm3"   & ASCII.LF & ASCII.HT &
        "vbroadcasti64x2 160(%1), %%zmm4"    & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm0, %%zmm0"   & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm1, %%zmm1"   & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm2, %%zmm2"   & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm3, %%zmm3"   & ASCII.LF & ASCII.HT &
        "vbroadcasti64x2 176(%1), %%zmm4"    & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm0, %%zmm0"   & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm1, %%zmm1"   & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm2, %%zmm2"   & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm3, %%zmm3"   & ASCII.LF & ASCII.HT &
        "vbroadcasti64x2 192(%1), %%zmm4"    & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm0, %%zmm0"   & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm1, %%zmm1"   & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm2, %%zmm2"   & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm3, %%zmm3"   & ASCII.LF & ASCII.HT &
        "vbroadcasti64x2 208(%1), %%zmm4"    & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm0, %%zmm0"   & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm1, %%zmm1"   & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm2, %%zmm2"   & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm3, %%zmm3"   & ASCII.LF & ASCII.HT &
        "vbroadcasti64x2 224(%1), %%zmm4"    & ASCII.LF & ASCII.HT &
        "vaesenclast %%zmm4, %%zmm0, %%zmm0" & ASCII.LF & ASCII.HT &
        "vaesenclast %%zmm4, %%zmm1, %%zmm1" & ASCII.LF & ASCII.HT &
        "vaesenclast %%zmm4, %%zmm2, %%zmm2" & ASCII.LF & ASCII.HT &
        "vaesenclast %%zmm4, %%zmm3, %%zmm3" & ASCII.LF & ASCII.HT &
        "vmovdqu64 %%zmm0,    (%2)"          & ASCII.LF & ASCII.HT &
        "vmovdqu64 %%zmm1,  64(%2)"          & ASCII.LF & ASCII.HT &
        "vmovdqu64 %%zmm2, 128(%2)"          & ASCII.LF & ASCII.HT &
        "vmovdqu64 %%zmm3, 192(%2)"          & ASCII.LF & ASCII.HT &
        "vzeroupper",
        Inputs  => (System.Address'Asm_Input ("r", Input'Address),
                    System.Address'Asm_Input ("r", Pre_RK'Address),
                    System.Address'Asm_Input ("r", Output'Address)),
        Clobber => "xmm0,xmm1,xmm2,xmm3,xmm4,memory",
        Volatile => True);
   end Cipher_16x_256_VAES;

   --================================================================
   --  16-block counter generator
   --================================================================

   procedure Build_Ctr_Block_16
     (CB      : in out Bytes_16;
      Counter :    out Bytes_256)
   is
   begin
      Asm
       (--  zmm14 = per-lane reverse-counter mask.
        "vmovdqa64  (%2), %%zmm14"          & ASCII.LF & ASCII.HT &
        --  Broadcast CB to all 4 lanes of zmm0.
        "vbroadcasti64x2  (%0), %%zmm0"     & ASCII.LF & ASCII.HT &
        "vpshufb   %%zmm14, %%zmm0, %%zmm0" & ASCII.LF & ASCII.HT &
        "vmovdqa64 %%zmm0, %%zmm1"          & ASCII.LF & ASCII.HT &
        "vmovdqa64 %%zmm0, %%zmm2"          & ASCII.LF & ASCII.HT &
        "vmovdqa64 %%zmm0, %%zmm3"          & ASCII.LF & ASCII.HT &
        --  Per-lane PADDD with the 4 increment tables.
        "vpaddd    (%3), %%zmm0, %%zmm0"    & ASCII.LF & ASCII.HT &  --  +0..+3
        "vpaddd    (%4), %%zmm1, %%zmm1"    & ASCII.LF & ASCII.HT &  --  +4..+7
        "vpaddd    (%5), %%zmm2, %%zmm2"    & ASCII.LF & ASCII.HT &  --  +8..+11
        "vpaddd    (%6), %%zmm3, %%zmm3"    & ASCII.LF & ASCII.HT &  --  +12..+15
        --  PSHUFB back to BE per lane.
        "vpshufb   %%zmm14, %%zmm0, %%zmm0" & ASCII.LF & ASCII.HT &
        "vpshufb   %%zmm14, %%zmm1, %%zmm1" & ASCII.LF & ASCII.HT &
        "vpshufb   %%zmm14, %%zmm2, %%zmm2" & ASCII.LF & ASCII.HT &
        "vpshufb   %%zmm14, %%zmm3, %%zmm3" & ASCII.LF & ASCII.HT &
        --  Store the 16 counter blocks.
        "vmovdqu64 %%zmm0,    (%1)"         & ASCII.LF & ASCII.HT &
        "vmovdqu64 %%zmm1,  64(%1)"         & ASCII.LF & ASCII.HT &
        "vmovdqu64 %%zmm2, 128(%1)"         & ASCII.LF & ASCII.HT &
        "vmovdqu64 %%zmm3, 192(%1)"         & ASCII.LF & ASCII.HT &
        --  Advance CB by 16 (using xmm5 to save register space).
        "vmovdqu   (%0), %%xmm5"            & ASCII.LF & ASCII.HT &
        "vpshufb   (%7), %%xmm5, %%xmm5"    & ASCII.LF & ASCII.HT &
        "vpaddd    (%8), %%xmm5, %%xmm5"    & ASCII.LF & ASCII.HT &
        "vpshufb   (%7), %%xmm5, %%xmm5"    & ASCII.LF & ASCII.HT &
        "vmovdqu   %%xmm5, (%0)"            & ASCII.LF & ASCII.HT &
        "vzeroupper",
        Inputs => (System.Address'Asm_Input ("r", CB'Address),
                   System.Address'Asm_Input ("r", Counter'Address),
                   System.Address'Asm_Input ("r", Reverse_Ctr_Mask_ZMM'Address),
                   System.Address'Asm_Input ("r", Ctr_Inc_0_3'Address),
                   System.Address'Asm_Input ("r", Ctr_Inc_4_7'Address),
                   System.Address'Asm_Input ("r", Ctr_Inc_8_11'Address),
                   System.Address'Asm_Input ("r", Ctr_Inc_12_15'Address),
                   System.Address'Asm_Input ("r", Reverse_Ctr_Mask_XMM'Address),
                   System.Address'Asm_Input ("r", Ctr_Inc_16'Address)),
        Clobber => "xmm0,xmm1,xmm2,xmm3,xmm5,xmm14,memory",
        Volatile => True);
   end Build_Ctr_Block_16;

   --================================================================
   --  16-block fused CTR-encrypt + XOR (AES-128)
   --================================================================
   --  Same body as Cipher_16x_128_VAES with an extra XOR-and-store
   --  phase at the end.

   procedure Cipher_16x_128_VAES_XOR
     (Buf     : in out Byte_Seq;
      Counter : in     Bytes_256;
      Pre_RK  : in     SPARKTLSCrypto.AES_NI.Pre_Swapped_RKs_128)
   is
   begin
      Asm
       ("vmovdqu64    (%0), %%zmm0"          & ASCII.LF & ASCII.HT &
        "vmovdqu64  64(%0), %%zmm1"          & ASCII.LF & ASCII.HT &
        "vmovdqu64 128(%0), %%zmm2"          & ASCII.LF & ASCII.HT &
        "vmovdqu64 192(%0), %%zmm3"          & ASCII.LF & ASCII.HT &
        "vbroadcasti64x2    (%1), %%zmm4"    & ASCII.LF & ASCII.HT &
        "vpxorq    %%zmm4, %%zmm0, %%zmm0"   & ASCII.LF & ASCII.HT &
        "vpxorq    %%zmm4, %%zmm1, %%zmm1"   & ASCII.LF & ASCII.HT &
        "vpxorq    %%zmm4, %%zmm2, %%zmm2"   & ASCII.LF & ASCII.HT &
        "vpxorq    %%zmm4, %%zmm3, %%zmm3"   & ASCII.LF & ASCII.HT &
        "vbroadcasti64x2  16(%1), %%zmm4"    & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm0, %%zmm0"   & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm1, %%zmm1"   & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm2, %%zmm2"   & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm3, %%zmm3"   & ASCII.LF & ASCII.HT &
        "vbroadcasti64x2  32(%1), %%zmm4"    & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm0, %%zmm0"   & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm1, %%zmm1"   & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm2, %%zmm2"   & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm3, %%zmm3"   & ASCII.LF & ASCII.HT &
        "vbroadcasti64x2  48(%1), %%zmm4"    & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm0, %%zmm0"   & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm1, %%zmm1"   & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm2, %%zmm2"   & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm3, %%zmm3"   & ASCII.LF & ASCII.HT &
        "vbroadcasti64x2  64(%1), %%zmm4"    & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm0, %%zmm0"   & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm1, %%zmm1"   & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm2, %%zmm2"   & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm3, %%zmm3"   & ASCII.LF & ASCII.HT &
        "vbroadcasti64x2  80(%1), %%zmm4"    & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm0, %%zmm0"   & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm1, %%zmm1"   & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm2, %%zmm2"   & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm3, %%zmm3"   & ASCII.LF & ASCII.HT &
        "vbroadcasti64x2  96(%1), %%zmm4"    & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm0, %%zmm0"   & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm1, %%zmm1"   & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm2, %%zmm2"   & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm3, %%zmm3"   & ASCII.LF & ASCII.HT &
        "vbroadcasti64x2 112(%1), %%zmm4"    & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm0, %%zmm0"   & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm1, %%zmm1"   & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm2, %%zmm2"   & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm3, %%zmm3"   & ASCII.LF & ASCII.HT &
        "vbroadcasti64x2 128(%1), %%zmm4"    & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm0, %%zmm0"   & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm1, %%zmm1"   & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm2, %%zmm2"   & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm3, %%zmm3"   & ASCII.LF & ASCII.HT &
        "vbroadcasti64x2 144(%1), %%zmm4"    & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm0, %%zmm0"   & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm1, %%zmm1"   & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm2, %%zmm2"   & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm3, %%zmm3"   & ASCII.LF & ASCII.HT &
        "vbroadcasti64x2 160(%1), %%zmm4"    & ASCII.LF & ASCII.HT &
        "vaesenclast %%zmm4, %%zmm0, %%zmm0" & ASCII.LF & ASCII.HT &
        "vaesenclast %%zmm4, %%zmm1, %%zmm1" & ASCII.LF & ASCII.HT &
        "vaesenclast %%zmm4, %%zmm2, %%zmm2" & ASCII.LF & ASCII.HT &
        "vaesenclast %%zmm4, %%zmm3, %%zmm3" & ASCII.LF & ASCII.HT &
        --  XOR keystream with plaintext (in-place), then store.
        "vmovdqu64    (%2), %%zmm4"          & ASCII.LF & ASCII.HT &
        "vpxorq    %%zmm4, %%zmm0, %%zmm0"   & ASCII.LF & ASCII.HT &
        "vmovdqu64  64(%2), %%zmm4"          & ASCII.LF & ASCII.HT &
        "vpxorq    %%zmm4, %%zmm1, %%zmm1"   & ASCII.LF & ASCII.HT &
        "vmovdqu64 128(%2), %%zmm4"          & ASCII.LF & ASCII.HT &
        "vpxorq    %%zmm4, %%zmm2, %%zmm2"   & ASCII.LF & ASCII.HT &
        "vmovdqu64 192(%2), %%zmm4"          & ASCII.LF & ASCII.HT &
        "vpxorq    %%zmm4, %%zmm3, %%zmm3"   & ASCII.LF & ASCII.HT &
        "vmovdqu64 %%zmm0,    (%2)"          & ASCII.LF & ASCII.HT &
        "vmovdqu64 %%zmm1,  64(%2)"          & ASCII.LF & ASCII.HT &
        "vmovdqu64 %%zmm2, 128(%2)"          & ASCII.LF & ASCII.HT &
        "vmovdqu64 %%zmm3, 192(%2)"          & ASCII.LF & ASCII.HT &
        "vzeroupper",
        Inputs  => (System.Address'Asm_Input ("r", Counter'Address),
                    System.Address'Asm_Input ("r", Pre_RK'Address),
                    System.Address'Asm_Input ("r", Buf'Address)),
        Clobber => "xmm0,xmm1,xmm2,xmm3,xmm4,memory",
        Volatile => True);
   end Cipher_16x_128_VAES_XOR;

   --================================================================
   --  16-block fused CTR-encrypt + XOR (AES-256, 14 rounds)
   --================================================================

   procedure Cipher_16x_256_VAES_XOR
     (Buf     : in out Byte_Seq;
      Counter : in     Bytes_256;
      Pre_RK  : in     SPARKTLSCrypto.AES_NI.Pre_Swapped_RKs_256)
   is
   begin
      Asm
       ("vmovdqu64    (%0), %%zmm0"          & ASCII.LF & ASCII.HT &
        "vmovdqu64  64(%0), %%zmm1"          & ASCII.LF & ASCII.HT &
        "vmovdqu64 128(%0), %%zmm2"          & ASCII.LF & ASCII.HT &
        "vmovdqu64 192(%0), %%zmm3"          & ASCII.LF & ASCII.HT &
        "vbroadcasti64x2    (%1), %%zmm4"    & ASCII.LF & ASCII.HT &
        "vpxorq    %%zmm4, %%zmm0, %%zmm0"   & ASCII.LF & ASCII.HT &
        "vpxorq    %%zmm4, %%zmm1, %%zmm1"   & ASCII.LF & ASCII.HT &
        "vpxorq    %%zmm4, %%zmm2, %%zmm2"   & ASCII.LF & ASCII.HT &
        "vpxorq    %%zmm4, %%zmm3, %%zmm3"   & ASCII.LF & ASCII.HT &
        "vbroadcasti64x2  16(%1), %%zmm4"    & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm0, %%zmm0"   & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm1, %%zmm1"   & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm2, %%zmm2"   & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm3, %%zmm3"   & ASCII.LF & ASCII.HT &
        "vbroadcasti64x2  32(%1), %%zmm4"    & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm0, %%zmm0"   & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm1, %%zmm1"   & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm2, %%zmm2"   & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm3, %%zmm3"   & ASCII.LF & ASCII.HT &
        "vbroadcasti64x2  48(%1), %%zmm4"    & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm0, %%zmm0"   & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm1, %%zmm1"   & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm2, %%zmm2"   & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm3, %%zmm3"   & ASCII.LF & ASCII.HT &
        "vbroadcasti64x2  64(%1), %%zmm4"    & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm0, %%zmm0"   & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm1, %%zmm1"   & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm2, %%zmm2"   & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm3, %%zmm3"   & ASCII.LF & ASCII.HT &
        "vbroadcasti64x2  80(%1), %%zmm4"    & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm0, %%zmm0"   & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm1, %%zmm1"   & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm2, %%zmm2"   & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm3, %%zmm3"   & ASCII.LF & ASCII.HT &
        "vbroadcasti64x2  96(%1), %%zmm4"    & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm0, %%zmm0"   & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm1, %%zmm1"   & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm2, %%zmm2"   & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm3, %%zmm3"   & ASCII.LF & ASCII.HT &
        "vbroadcasti64x2 112(%1), %%zmm4"    & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm0, %%zmm0"   & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm1, %%zmm1"   & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm2, %%zmm2"   & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm3, %%zmm3"   & ASCII.LF & ASCII.HT &
        "vbroadcasti64x2 128(%1), %%zmm4"    & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm0, %%zmm0"   & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm1, %%zmm1"   & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm2, %%zmm2"   & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm3, %%zmm3"   & ASCII.LF & ASCII.HT &
        "vbroadcasti64x2 144(%1), %%zmm4"    & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm0, %%zmm0"   & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm1, %%zmm1"   & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm2, %%zmm2"   & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm3, %%zmm3"   & ASCII.LF & ASCII.HT &
        "vbroadcasti64x2 160(%1), %%zmm4"    & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm0, %%zmm0"   & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm1, %%zmm1"   & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm2, %%zmm2"   & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm3, %%zmm3"   & ASCII.LF & ASCII.HT &
        "vbroadcasti64x2 176(%1), %%zmm4"    & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm0, %%zmm0"   & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm1, %%zmm1"   & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm2, %%zmm2"   & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm3, %%zmm3"   & ASCII.LF & ASCII.HT &
        "vbroadcasti64x2 192(%1), %%zmm4"    & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm0, %%zmm0"   & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm1, %%zmm1"   & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm2, %%zmm2"   & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm3, %%zmm3"   & ASCII.LF & ASCII.HT &
        "vbroadcasti64x2 208(%1), %%zmm4"    & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm0, %%zmm0"   & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm1, %%zmm1"   & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm2, %%zmm2"   & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm3, %%zmm3"   & ASCII.LF & ASCII.HT &
        "vbroadcasti64x2 224(%1), %%zmm4"    & ASCII.LF & ASCII.HT &
        "vaesenclast %%zmm4, %%zmm0, %%zmm0" & ASCII.LF & ASCII.HT &
        "vaesenclast %%zmm4, %%zmm1, %%zmm1" & ASCII.LF & ASCII.HT &
        "vaesenclast %%zmm4, %%zmm2, %%zmm2" & ASCII.LF & ASCII.HT &
        "vaesenclast %%zmm4, %%zmm3, %%zmm3" & ASCII.LF & ASCII.HT &
        "vmovdqu64    (%2), %%zmm4"          & ASCII.LF & ASCII.HT &
        "vpxorq    %%zmm4, %%zmm0, %%zmm0"   & ASCII.LF & ASCII.HT &
        "vmovdqu64  64(%2), %%zmm4"          & ASCII.LF & ASCII.HT &
        "vpxorq    %%zmm4, %%zmm1, %%zmm1"   & ASCII.LF & ASCII.HT &
        "vmovdqu64 128(%2), %%zmm4"          & ASCII.LF & ASCII.HT &
        "vpxorq    %%zmm4, %%zmm2, %%zmm2"   & ASCII.LF & ASCII.HT &
        "vmovdqu64 192(%2), %%zmm4"          & ASCII.LF & ASCII.HT &
        "vpxorq    %%zmm4, %%zmm3, %%zmm3"   & ASCII.LF & ASCII.HT &
        "vmovdqu64 %%zmm0,    (%2)"          & ASCII.LF & ASCII.HT &
        "vmovdqu64 %%zmm1,  64(%2)"          & ASCII.LF & ASCII.HT &
        "vmovdqu64 %%zmm2, 128(%2)"          & ASCII.LF & ASCII.HT &
        "vmovdqu64 %%zmm3, 192(%2)"          & ASCII.LF & ASCII.HT &
        "vzeroupper",
        Inputs  => (System.Address'Asm_Input ("r", Counter'Address),
                    System.Address'Asm_Input ("r", Pre_RK'Address),
                    System.Address'Asm_Input ("r", Buf'Address)),
        Clobber => "xmm0,xmm1,xmm2,xmm3,xmm4,memory",
        Volatile => True);
   end Cipher_16x_256_VAES_XOR;

   --================================================================
   --  Compute_H_Powers_16: H, H², ..., H^16 in zmm-friendly layout
   --================================================================
   --  For 16-block aggregated GHASH we need 16 powers of H, each
   --  byte-reversed (PCLMULQDQ orientation) and arranged so a single
   --  zmm load covers (H^k, H^k-1, H^k-2, H^k-3) — these match the
   --  4 ciphertext blocks at the same offset.

   procedure Compute_H_Powers_16
     (H        : in     Bytes_16;
      H_Powers :    out Pre_H_Powers_16)
   is
      H_Pow : array (1 .. 16) of Bytes_16;
   begin
      H_Pow (1) := H;
      for K in 2 .. 16 loop
         H_Pow (K) := SPARKTLSCrypto.GHASH_NI.GF128_Mul (H, H_Pow (K - 1));
      end loop;
      --  Layout chunks of 4 powers, descending. Each H power stored
      --  byte-reversed (16 bytes per lane).
      for Chunk in 0 .. 3 loop
         for Lane in 0 .. 3 loop
            declare
               P : constant Natural := 16 - (Chunk * 4 + Lane);
               --  Base offset of this 16-byte slot in H_Powers.
               Off : constant N32 := N32 (Chunk * 64 + Lane * 16);
            begin
               for I in 0 .. 15 loop
                  H_Powers (Off + N32 (I)) := H_Pow (P) (N32 (15 - I));
               end loop;
            end;
         end loop;
      end loop;
   end Compute_H_Powers_16;

   --================================================================
   --  16-block aggregated GHASH using VPCLMULQDQ on zmm
   --================================================================
   --  Same algebra as GHASH_NI.GHASH_4_Blocks, scaled to 16 blocks
   --  using zmm registers. 4 chunks × (4 vpclmulqdq + accum) +
   --  horizontal reduce + bit-shift correction + reduction.

   procedure GHASH_16_Blocks
     (S        : in out Bytes_16;
      Blocks   : in     Byte_Seq;
      H_Powers : in     Pre_H_Powers_16)
   is
   begin
      Asm
       (--  zmm15 = byte-swap mask broadcast to 4 lanes.
        "vmovdqa64 (%3), %%zmm15"           & ASCII.LF & ASCII.HT &

        --  Load 16 ciphertext blocks, byte-reverse each.
        "vmovdqu64    (%1), %%zmm0"         & ASCII.LF & ASCII.HT &
        "vmovdqu64  64(%1), %%zmm1"         & ASCII.LF & ASCII.HT &
        "vmovdqu64 128(%1), %%zmm2"         & ASCII.LF & ASCII.HT &
        "vmovdqu64 192(%1), %%zmm3"         & ASCII.LF & ASCII.HT &
        "vpshufb   %%zmm15, %%zmm0, %%zmm0" & ASCII.LF & ASCII.HT &
        "vpshufb   %%zmm15, %%zmm1, %%zmm1" & ASCII.LF & ASCII.HT &
        "vpshufb   %%zmm15, %%zmm2, %%zmm2" & ASCII.LF & ASCII.HT &
        "vpshufb   %%zmm15, %%zmm3, %%zmm3" & ASCII.LF & ASCII.HT &

        --  XOR S into block 0 (lane 0 of zmm0, multiplied by H^16).
        "vmovdqu   (%0), %%xmm4"            & ASCII.LF & ASCII.HT &
        "vpshufb   (%4), %%xmm4, %%xmm4"    & ASCII.LF & ASCII.HT &
        "vpxorq    %%zmm14, %%zmm14, %%zmm14" & ASCII.LF & ASCII.HT &
        "vinserti64x2 $0, %%xmm4, %%zmm14, %%zmm14" & ASCII.LF & ASCII.HT &
        "vpxorq    %%zmm14, %%zmm0, %%zmm0" & ASCII.LF & ASCII.HT &

        --  Chunk 0: zmm0 (B0..B3) × zmm4 (H^16..H^13) → init lo/hi/mid.
        "vmovdqu64    (%2), %%zmm4"         & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x00, %%zmm4, %%zmm0, %%zmm5" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x11, %%zmm4, %%zmm0, %%zmm6" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x10, %%zmm4, %%zmm0, %%zmm7" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x01, %%zmm4, %%zmm0, %%zmm0" & ASCII.LF & ASCII.HT &
        "vpxorq    %%zmm0, %%zmm7, %%zmm7"  & ASCII.LF & ASCII.HT &

        --  Chunk 1: zmm1 (B4..B7) × zmm4 (H^12..H^9).
        "vmovdqu64  64(%2), %%zmm4"         & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x00, %%zmm4, %%zmm1, %%zmm0" & ASCII.LF & ASCII.HT &
        "vpxorq    %%zmm0, %%zmm5, %%zmm5"  & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x11, %%zmm4, %%zmm1, %%zmm0" & ASCII.LF & ASCII.HT &
        "vpxorq    %%zmm0, %%zmm6, %%zmm6"  & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x10, %%zmm4, %%zmm1, %%zmm0" & ASCII.LF & ASCII.HT &
        "vpxorq    %%zmm0, %%zmm7, %%zmm7"  & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x01, %%zmm4, %%zmm1, %%zmm1" & ASCII.LF & ASCII.HT &
        "vpxorq    %%zmm1, %%zmm7, %%zmm7"  & ASCII.LF & ASCII.HT &

        --  Chunk 2: zmm2 (B8..B11) × zmm4 (H^8..H^5).
        "vmovdqu64 128(%2), %%zmm4"         & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x00, %%zmm4, %%zmm2, %%zmm0" & ASCII.LF & ASCII.HT &
        "vpxorq    %%zmm0, %%zmm5, %%zmm5"  & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x11, %%zmm4, %%zmm2, %%zmm0" & ASCII.LF & ASCII.HT &
        "vpxorq    %%zmm0, %%zmm6, %%zmm6"  & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x10, %%zmm4, %%zmm2, %%zmm0" & ASCII.LF & ASCII.HT &
        "vpxorq    %%zmm0, %%zmm7, %%zmm7"  & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x01, %%zmm4, %%zmm2, %%zmm2" & ASCII.LF & ASCII.HT &
        "vpxorq    %%zmm2, %%zmm7, %%zmm7"  & ASCII.LF & ASCII.HT &

        --  Chunk 3: zmm3 (B12..B15) × zmm4 (H^4..H^1).
        "vmovdqu64 192(%2), %%zmm4"         & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x00, %%zmm4, %%zmm3, %%zmm0" & ASCII.LF & ASCII.HT &
        "vpxorq    %%zmm0, %%zmm5, %%zmm5"  & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x11, %%zmm4, %%zmm3, %%zmm0" & ASCII.LF & ASCII.HT &
        "vpxorq    %%zmm0, %%zmm6, %%zmm6"  & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x10, %%zmm4, %%zmm3, %%zmm0" & ASCII.LF & ASCII.HT &
        "vpxorq    %%zmm0, %%zmm7, %%zmm7"  & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x01, %%zmm4, %%zmm3, %%zmm3" & ASCII.LF & ASCII.HT &
        "vpxorq    %%zmm3, %%zmm7, %%zmm7"  & ASCII.LF & ASCII.HT &

        --  Horizontal reduce 4 lanes → 1 (zmm → ymm → xmm).
        --  zmm5 = lo, zmm6 = hi, zmm7 = mid.
        "vextracti64x4 $1, %%zmm5, %%ymm0"  & ASCII.LF & ASCII.HT &
        "vpxor     %%ymm0, %%ymm5, %%ymm5"  & ASCII.LF & ASCII.HT &
        "vextracti64x4 $1, %%zmm6, %%ymm0"  & ASCII.LF & ASCII.HT &
        "vpxor     %%ymm0, %%ymm6, %%ymm6"  & ASCII.LF & ASCII.HT &
        "vextracti64x4 $1, %%zmm7, %%ymm0"  & ASCII.LF & ASCII.HT &
        "vpxor     %%ymm0, %%ymm7, %%ymm7"  & ASCII.LF & ASCII.HT &
        "vextracti128 $1, %%ymm5, %%xmm0"   & ASCII.LF & ASCII.HT &
        "vpxor     %%xmm0, %%xmm5, %%xmm5"  & ASCII.LF & ASCII.HT &
        "vextracti128 $1, %%ymm6, %%xmm0"   & ASCII.LF & ASCII.HT &
        "vpxor     %%xmm0, %%xmm6, %%xmm6"  & ASCII.LF & ASCII.HT &
        "vextracti128 $1, %%ymm7, %%xmm0"   & ASCII.LF & ASCII.HT &
        "vpxor     %%xmm0, %%xmm7, %%xmm7"  & ASCII.LF & ASCII.HT &
        --  Now xmm5=lo, xmm6=hi, xmm7=mid (128-bit each).

        --  Combine cross terms: lo += (mid << 64), hi += (mid >> 64).
        "vmovdqa   %%xmm7, %%xmm0"          & ASCII.LF & ASCII.HT &
        "vpslldq   $8, %%xmm0, %%xmm0"      & ASCII.LF & ASCII.HT &
        "vpsrldq   $8, %%xmm7, %%xmm7"      & ASCII.LF & ASCII.HT &
        "vpxor     %%xmm0, %%xmm5, %%xmm5"  & ASCII.LF & ASCII.HT &
        "vpxor     %%xmm7, %%xmm6, %%xmm6"  & ASCII.LF & ASCII.HT &

        --  Bit-shift correction: (xmm6:xmm5) <<= 1 (32-bit-lane carry).
        "vmovdqa   %%xmm5, %%xmm0"          & ASCII.LF & ASCII.HT &
        "vmovdqa   %%xmm6, %%xmm1"          & ASCII.LF & ASCII.HT &
        "vpsrld    $31, %%xmm0, %%xmm0"     & ASCII.LF & ASCII.HT &
        "vpsrld    $31, %%xmm1, %%xmm1"     & ASCII.LF & ASCII.HT &
        "vpslld    $1, %%xmm5, %%xmm5"      & ASCII.LF & ASCII.HT &
        "vpslld    $1, %%xmm6, %%xmm6"      & ASCII.LF & ASCII.HT &
        "vmovdqa   %%xmm0, %%xmm2"          & ASCII.LF & ASCII.HT &
        "vpsrldq   $12, %%xmm2, %%xmm2"     & ASCII.LF & ASCII.HT &
        "vpslldq   $4, %%xmm0, %%xmm0"      & ASCII.LF & ASCII.HT &
        "vpslldq   $4, %%xmm1, %%xmm1"      & ASCII.LF & ASCII.HT &
        "vpor      %%xmm0, %%xmm5, %%xmm5"  & ASCII.LF & ASCII.HT &
        "vpor      %%xmm1, %%xmm6, %%xmm6"  & ASCII.LF & ASCII.HT &
        "vpor      %%xmm2, %%xmm6, %%xmm6"  & ASCII.LF & ASCII.HT &

        --  Reduction first fold.
        "vmovdqa   %%xmm5, %%xmm0"          & ASCII.LF & ASCII.HT &
        "vmovdqa   %%xmm5, %%xmm1"          & ASCII.LF & ASCII.HT &
        "vmovdqa   %%xmm5, %%xmm2"          & ASCII.LF & ASCII.HT &
        "vpslld    $31, %%xmm0, %%xmm0"     & ASCII.LF & ASCII.HT &
        "vpslld    $30, %%xmm1, %%xmm1"     & ASCII.LF & ASCII.HT &
        "vpslld    $25, %%xmm2, %%xmm2"     & ASCII.LF & ASCII.HT &
        "vpxor     %%xmm1, %%xmm0, %%xmm0"  & ASCII.LF & ASCII.HT &
        "vpxor     %%xmm2, %%xmm0, %%xmm0"  & ASCII.LF & ASCII.HT &
        "vmovdqa   %%xmm0, %%xmm3"          & ASCII.LF & ASCII.HT &
        "vpsrldq   $4, %%xmm3, %%xmm3"      & ASCII.LF & ASCII.HT &
        "vpslldq   $12, %%xmm0, %%xmm0"     & ASCII.LF & ASCII.HT &
        "vpxor     %%xmm0, %%xmm5, %%xmm5"  & ASCII.LF & ASCII.HT &

        --  Reduction second fold (final tag in xmm6).
        "vmovdqa   %%xmm5, %%xmm0"          & ASCII.LF & ASCII.HT &
        "vmovdqa   %%xmm5, %%xmm1"          & ASCII.LF & ASCII.HT &
        "vmovdqa   %%xmm5, %%xmm2"          & ASCII.LF & ASCII.HT &
        "vpsrld    $1, %%xmm0, %%xmm0"      & ASCII.LF & ASCII.HT &
        "vpsrld    $2, %%xmm1, %%xmm1"      & ASCII.LF & ASCII.HT &
        "vpsrld    $7, %%xmm2, %%xmm2"      & ASCII.LF & ASCII.HT &
        "vpxor     %%xmm1, %%xmm6, %%xmm6"  & ASCII.LF & ASCII.HT &
        "vpxor     %%xmm2, %%xmm6, %%xmm6"  & ASCII.LF & ASCII.HT &
        "vpxor     %%xmm0, %%xmm6, %%xmm6"  & ASCII.LF & ASCII.HT &
        "vpxor     %%xmm3, %%xmm6, %%xmm6"  & ASCII.LF & ASCII.HT &
        "vpxor     %%xmm5, %%xmm6, %%xmm6"  & ASCII.LF & ASCII.HT &

        --  Convert tag to NIST byte order, store to S.
        "vpshufb   (%4), %%xmm6, %%xmm6"    & ASCII.LF & ASCII.HT &
        "vmovdqu   %%xmm6, (%0)"            & ASCII.LF & ASCII.HT &
        "vzeroupper",
        Inputs => (System.Address'Asm_Input ("r", S'Address),
                   System.Address'Asm_Input ("r", Blocks'Address),
                   System.Address'Asm_Input ("r", H_Powers'Address),
                   System.Address'Asm_Input ("r", Bswap_Mask_ZMM'Address),
                   System.Address'Asm_Input ("r", Bswap_Mask_XMM'Address)),
        Clobber => "xmm0,xmm1,xmm2,xmm3,xmm4,xmm5,xmm6,xmm7," &
                   "xmm14,xmm15,memory",
        Volatile => True);
   end GHASH_16_Blocks;

begin
   Has_AVX512_AES_GCM := Detect_AVX512_AES_GCM;
end SPARKTLSCrypto.AES_GCM_AVX512;
