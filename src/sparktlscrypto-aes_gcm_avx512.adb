--  AVX-512 VAES + VPCLMULQDQ AES-GCM accelerator (body).
--  See sparktlscrypto-aes_gcm_avx512.ads.

with System.Machine_Code; use System.Machine_Code;
with SPARKTLSCrypto.CPU;
pragma Elaborate_All (SPARKTLSCrypto.CPU);
with Interfaces;          use Interfaces;
with SPARKNaCl;           use SPARKNaCl;
with SPARKTLSCrypto.GHASH_NI;

package body SPARKTLSCrypto.AES_GCM_AVX512 with
   SPARK_Mode => Off
is

   ----------------------------------------------------------------------------
   --  Constants used by the 16-block counter generator
   ----------------------------------------------------------------------------

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

   --  Upper half of Q(x) = x^128 + x^127 + x^126 + x^121 + 1.
   --  The lower half is 1. Two 64-bit Montgomery folds cancel the
   --  low 128 bits; the existing one-bit correction accounts for the
   --  reflected GHASH representation. H_Powers keeps its original format.
   Reduction_Poly : constant array (0 .. 15) of Unsigned_8 :=
     (0 .. 14 => 0, 15 => 16#C2#);
   for Reduction_Poly'Alignment use 16;

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

   ----------------------------------------------------------------------------
   --  CPUID detection (run once at elaboration)
   ----------------------------------------------------------------------------
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
      --  CPUID leaf 7 carries the AVX-512/VAES/VPCLMUL feature bits.
      --  Do not query it unless the CPU reports that it exists.
      declare
         EAX, EBX, ECX, EDX : Unsigned_32;
      begin
         Asm ("cpuid",
              Outputs  => (Unsigned_32'Asm_Output ("=a", EAX),
                           Unsigned_32'Asm_Output ("=b", EBX),
                           Unsigned_32'Asm_Output ("=c", ECX),
                           Unsigned_32'Asm_Output ("=d", EDX)),
              Inputs   => (Unsigned_32'Asm_Input ("a", 0),
                           Unsigned_32'Asm_Input ("c", 0)),
              Volatile => True);
         pragma Unreferenced (EBX, ECX, EDX);
         if EAX < 7 then return False; end if;
      end;

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
         --  The kernel also uses vbroadcasti64x2 / vinserti64x2 (AVX512DQ)
         --  and vpshufb on zmm (AVX512BW); a part with F+VAES+VPCLMULQDQ
         --  but not DQ/BW (Knights-class, or a hypervisor mask) would #UD
         --  on the first of them.
         return (EBX and 16#0001_0000#) /= 0   -- AVX-512F
            and (EBX and 16#0002_0000#) /= 0   -- AVX512DQ
            and (EBX and 16#4000_0000#) /= 0   -- AVX512BW
            and (ECX and 16#0000_0200#) /= 0   -- VAES
            and (ECX and 16#0000_0400#) /= 0;  -- VPCLMULQDQ
      end;
   end Detect_AVX512_AES_GCM;

   ----------------------------------------------------------------------------
   --  16-block AES-128 cipher
   ----------------------------------------------------------------------------
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

   ----------------------------------------------------------------------------
   --  16-block AES-256 cipher (14 rounds)
   ----------------------------------------------------------------------------

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

   ----------------------------------------------------------------------------
   --  16-block counter generator
   ----------------------------------------------------------------------------

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

   ----------------------------------------------------------------------------
   --  16-block fused CTR-encrypt + XOR (AES-128)
   ----------------------------------------------------------------------------
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

   ----------------------------------------------------------------------------
   --  16-block fused CTR-encrypt + XOR (AES-256, 14 rounds)
   ----------------------------------------------------------------------------

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

   ----------------------------------------------------------------------------
   --  Compute_H_Powers_16: H, H², ..., H^16 in zmm-friendly layout
   ----------------------------------------------------------------------------
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

   ----------------------------------------------------------------------------
   --  16-block aggregated GHASH using VPCLMULQDQ on zmm
   ----------------------------------------------------------------------------
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

        --  Combine cross terms within each 128-bit lane before the
        --  horizontal XOR. Both operations are linear, so this avoids
        --  a separate horizontal reduction of the middle product.
        "vpslldq   $8, %%zmm7, %%zmm0"      & ASCII.LF & ASCII.HT &
        "vpsrldq   $8, %%zmm7, %%zmm7"      & ASCII.LF & ASCII.HT &
        "vpxorq    %%zmm0, %%zmm5, %%zmm5"  & ASCII.LF & ASCII.HT &
        "vpxorq    %%zmm7, %%zmm6, %%zmm6"  & ASCII.LF & ASCII.HT &

        --  Horizontal reduce 4 lanes → 1 (zmm → ymm → xmm).
        --  zmm5 = lo, zmm6 = hi, with cross terms already combined.
        "vextracti64x4 $1, %%zmm5, %%ymm0"  & ASCII.LF & ASCII.HT &
        "vpxor     %%ymm0, %%ymm5, %%ymm5"  & ASCII.LF & ASCII.HT &
        "vextracti64x4 $1, %%zmm6, %%ymm0"  & ASCII.LF & ASCII.HT &
        "vpxor     %%ymm0, %%ymm6, %%ymm6"  & ASCII.LF & ASCII.HT &
        "vextracti128 $1, %%ymm5, %%xmm0"   & ASCII.LF & ASCII.HT &
        "vpxor     %%xmm0, %%xmm5, %%xmm5"  & ASCII.LF & ASCII.HT &
        "vextracti128 $1, %%ymm6, %%xmm0"   & ASCII.LF & ASCII.HT &
        "vpxor     %%xmm0, %%xmm6, %%xmm6"  & ASCII.LF & ASCII.HT &
        --  Now xmm5=lo, xmm6=hi (128-bit each).

        --  Bit-shift correction: (xmm6:xmm5) <<= 1 (32-bit-lane carry).
        "vpsrld    $31, %%xmm5, %%xmm0"     & ASCII.LF & ASCII.HT &
        "vpsrld    $31, %%xmm6, %%xmm1"     & ASCII.LF & ASCII.HT &
        "vpslld    $1, %%xmm5, %%xmm5"      & ASCII.LF & ASCII.HT &
        "vpslld    $1, %%xmm6, %%xmm6"      & ASCII.LF & ASCII.HT &
        "vpsrldq   $12, %%xmm0, %%xmm2"     & ASCII.LF & ASCII.HT &
        "vpslldq   $4, %%xmm0, %%xmm0"      & ASCII.LF & ASCII.HT &
        "vpslldq   $4, %%xmm1, %%xmm1"      & ASCII.LF & ASCII.HT &
        "vpor      %%xmm0, %%xmm5, %%xmm5"  & ASCII.LF & ASCII.HT &
        "vpor      %%xmm1, %%xmm6, %%xmm6"  & ASCII.LF & ASCII.HT &
        "vpor      %%xmm2, %%xmm6, %%xmm6"  & ASCII.LF & ASCII.HT &

        --  Montgomery reduction modulo the reflected polynomial Q.
        --  For low-half L=(L_hi:L_lo), each fold is
        --    L := swap64(L) xor CLMUL(L_lo, 0xc200000000000000).
        --  Since Q's low 64 bits equal 1, this cancels one low limb
        --  and divides by x^64. Two folds, XORed with the high half,
        --  yield T*x^-128 mod Q. The one-bit correction above makes
        --  this the same GHASH result as the former shift reduction.
        "vmovdqa   (%5), %%xmm4"            & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x10, %%xmm4, %%xmm5, %%xmm0" & ASCII.LF & ASCII.HT &
        "vpshufd   $0x4e, %%xmm5, %%xmm5"  & ASCII.LF & ASCII.HT &
        "vpxor     %%xmm0, %%xmm5, %%xmm5"  & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x10, %%xmm4, %%xmm5, %%xmm0" & ASCII.LF & ASCII.HT &
        "vpshufd   $0x4e, %%xmm5, %%xmm5"  & ASCII.LF & ASCII.HT &
        "vpxor     %%xmm0, %%xmm5, %%xmm5"  & ASCII.LF & ASCII.HT &
        "vpxor     %%xmm5, %%xmm6, %%xmm6"  & ASCII.LF & ASCII.HT &

        --  Convert tag to NIST byte order, store to S.
        "vpshufb   (%4), %%xmm6, %%xmm6"    & ASCII.LF & ASCII.HT &
        "vmovdqu   %%xmm6, (%0)"            & ASCII.LF & ASCII.HT &
        "vzeroupper",
        Inputs => (System.Address'Asm_Input ("r", S'Address),
                   System.Address'Asm_Input ("r", Blocks'Address),
                   System.Address'Asm_Input ("r", H_Powers'Address),
                   System.Address'Asm_Input ("r", Bswap_Mask_ZMM'Address),
                   System.Address'Asm_Input ("r", Bswap_Mask_XMM'Address),
                   System.Address'Asm_Input ("r", Reduction_Poly'Address)),
        Clobber => "xmm0,xmm1,xmm2,xmm3,xmm4,xmm5,xmm6,xmm7," &
                   "xmm14,xmm15,memory",
        Volatile => True);
   end GHASH_16_Blocks;

   --  Fused encryption and authentication of one sixteen-block stripe.

   procedure Encrypt_GCM_Stripe_16_128
     (Buf      : in out Byte_Seq;
      S        : in out Bytes_16;
      Counter  : in     Bytes_256;
      Pre_RK   : in     AES_NI.Pre_Swapped_RKs_128;
      H_Powers : in     Pre_H_Powers_16)
   is
   begin
      --  Ciphertext stays in zmm0..zmm3 through authentication.
      --  Counter generation and all GHASH arithmetic are unchanged.
      Asm
       ("vmovdqu64    (%0), %%zmm0" & ASCII.LF & ASCII.HT &
        "vmovdqu64  64(%0), %%zmm1" & ASCII.LF & ASCII.HT &
        "vmovdqu64 128(%0), %%zmm2" & ASCII.LF & ASCII.HT &
        "vmovdqu64 192(%0), %%zmm3" & ASCII.LF & ASCII.HT &
        "vbroadcasti64x2    (%1), %%zmm4" & ASCII.LF & ASCII.HT &
        "vpxorq    %%zmm4, %%zmm0, %%zmm0" & ASCII.LF & ASCII.HT &
        "vpxorq    %%zmm4, %%zmm1, %%zmm1" & ASCII.LF & ASCII.HT &
        "vpxorq    %%zmm4, %%zmm2, %%zmm2" & ASCII.LF & ASCII.HT &
        "vpxorq    %%zmm4, %%zmm3, %%zmm3" & ASCII.LF & ASCII.HT &
        "vbroadcasti64x2  16(%1), %%zmm4" & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm0, %%zmm0" & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm1, %%zmm1" & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm2, %%zmm2" & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm3, %%zmm3" & ASCII.LF & ASCII.HT &
        "vbroadcasti64x2  32(%1), %%zmm4" & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm0, %%zmm0" & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm1, %%zmm1" & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm2, %%zmm2" & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm3, %%zmm3" & ASCII.LF & ASCII.HT &
        "vbroadcasti64x2  48(%1), %%zmm4" & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm0, %%zmm0" & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm1, %%zmm1" & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm2, %%zmm2" & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm3, %%zmm3" & ASCII.LF & ASCII.HT &
        "vbroadcasti64x2  64(%1), %%zmm4" & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm0, %%zmm0" & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm1, %%zmm1" & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm2, %%zmm2" & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm3, %%zmm3" & ASCII.LF & ASCII.HT &
        "vbroadcasti64x2  80(%1), %%zmm4" & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm0, %%zmm0" & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm1, %%zmm1" & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm2, %%zmm2" & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm3, %%zmm3" & ASCII.LF & ASCII.HT &
        "vbroadcasti64x2  96(%1), %%zmm4" & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm0, %%zmm0" & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm1, %%zmm1" & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm2, %%zmm2" & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm3, %%zmm3" & ASCII.LF & ASCII.HT &
        "vbroadcasti64x2 112(%1), %%zmm4" & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm0, %%zmm0" & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm1, %%zmm1" & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm2, %%zmm2" & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm3, %%zmm3" & ASCII.LF & ASCII.HT &
        "vbroadcasti64x2 128(%1), %%zmm4" & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm0, %%zmm0" & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm1, %%zmm1" & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm2, %%zmm2" & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm3, %%zmm3" & ASCII.LF & ASCII.HT &
        "vbroadcasti64x2 144(%1), %%zmm4" & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm0, %%zmm0" & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm1, %%zmm1" & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm2, %%zmm2" & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm3, %%zmm3" & ASCII.LF & ASCII.HT &
        "vbroadcasti64x2 160(%1), %%zmm4" & ASCII.LF & ASCII.HT &
        "vaesenclast %%zmm4, %%zmm0, %%zmm0" & ASCII.LF & ASCII.HT &
        "vaesenclast %%zmm4, %%zmm1, %%zmm1" & ASCII.LF & ASCII.HT &
        "vaesenclast %%zmm4, %%zmm2, %%zmm2" & ASCII.LF & ASCII.HT &
        "vaesenclast %%zmm4, %%zmm3, %%zmm3" & ASCII.LF & ASCII.HT &
        "vmovdqu64    (%2), %%zmm4" & ASCII.LF & ASCII.HT &
        "vpxorq    %%zmm4, %%zmm0, %%zmm0" & ASCII.LF & ASCII.HT &
        "vmovdqu64  64(%2), %%zmm4" & ASCII.LF & ASCII.HT &
        "vpxorq    %%zmm4, %%zmm1, %%zmm1" & ASCII.LF & ASCII.HT &
        "vmovdqu64 128(%2), %%zmm4" & ASCII.LF & ASCII.HT &
        "vpxorq    %%zmm4, %%zmm2, %%zmm2" & ASCII.LF & ASCII.HT &
        "vmovdqu64 192(%2), %%zmm4" & ASCII.LF & ASCII.HT &
        "vpxorq    %%zmm4, %%zmm3, %%zmm3" & ASCII.LF & ASCII.HT &
        "vmovdqu64 %%zmm0,    (%2)" & ASCII.LF & ASCII.HT &
        "vmovdqu64 %%zmm1,  64(%2)" & ASCII.LF & ASCII.HT &
        "vmovdqu64 %%zmm2, 128(%2)" & ASCII.LF & ASCII.HT &
        "vmovdqu64 %%zmm3, 192(%2)" & ASCII.LF & ASCII.HT &
        "vmovdqa64 (%5), %%zmm15" & ASCII.LF & ASCII.HT &
        "vpshufb   %%zmm15, %%zmm0, %%zmm0" & ASCII.LF & ASCII.HT &
        "vpshufb   %%zmm15, %%zmm1, %%zmm1" & ASCII.LF & ASCII.HT &
        "vpshufb   %%zmm15, %%zmm2, %%zmm2" & ASCII.LF & ASCII.HT &
        "vpshufb   %%zmm15, %%zmm3, %%zmm3" & ASCII.LF & ASCII.HT &
        "vmovdqu   (%3), %%xmm4" & ASCII.LF & ASCII.HT &
        "vpshufb   (%6), %%xmm4, %%xmm4" & ASCII.LF & ASCII.HT &
        "vpxorq    %%zmm14, %%zmm14, %%zmm14" & ASCII.LF & ASCII.HT &
        "vinserti64x2 $0, %%xmm4, %%zmm14, %%zmm14" & ASCII.LF & ASCII.HT &
        "vpxorq    %%zmm14, %%zmm0, %%zmm0" & ASCII.LF & ASCII.HT &
        "vmovdqu64    (%4), %%zmm4" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x00, %%zmm4, %%zmm0, %%zmm5" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x11, %%zmm4, %%zmm0, %%zmm6" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x10, %%zmm4, %%zmm0, %%zmm7" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x01, %%zmm4, %%zmm0, %%zmm0" & ASCII.LF & ASCII.HT &
        "vpxorq    %%zmm0, %%zmm7, %%zmm7" & ASCII.LF & ASCII.HT &
        "vmovdqu64  64(%4), %%zmm4" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x00, %%zmm4, %%zmm1, %%zmm0" & ASCII.LF & ASCII.HT &
        "vpxorq    %%zmm0, %%zmm5, %%zmm5" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x11, %%zmm4, %%zmm1, %%zmm0" & ASCII.LF & ASCII.HT &
        "vpxorq    %%zmm0, %%zmm6, %%zmm6" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x10, %%zmm4, %%zmm1, %%zmm0" & ASCII.LF & ASCII.HT &
        "vpxorq    %%zmm0, %%zmm7, %%zmm7" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x01, %%zmm4, %%zmm1, %%zmm1" & ASCII.LF & ASCII.HT &
        "vpxorq    %%zmm1, %%zmm7, %%zmm7" & ASCII.LF & ASCII.HT &
        "vmovdqu64 128(%4), %%zmm4" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x00, %%zmm4, %%zmm2, %%zmm0" & ASCII.LF & ASCII.HT &
        "vpxorq    %%zmm0, %%zmm5, %%zmm5" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x11, %%zmm4, %%zmm2, %%zmm0" & ASCII.LF & ASCII.HT &
        "vpxorq    %%zmm0, %%zmm6, %%zmm6" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x10, %%zmm4, %%zmm2, %%zmm0" & ASCII.LF & ASCII.HT &
        "vpxorq    %%zmm0, %%zmm7, %%zmm7" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x01, %%zmm4, %%zmm2, %%zmm2" & ASCII.LF & ASCII.HT &
        "vpxorq    %%zmm2, %%zmm7, %%zmm7" & ASCII.LF & ASCII.HT &
        "vmovdqu64 192(%4), %%zmm4" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x00, %%zmm4, %%zmm3, %%zmm0" & ASCII.LF & ASCII.HT &
        "vpxorq    %%zmm0, %%zmm5, %%zmm5" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x11, %%zmm4, %%zmm3, %%zmm0" & ASCII.LF & ASCII.HT &
        "vpxorq    %%zmm0, %%zmm6, %%zmm6" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x10, %%zmm4, %%zmm3, %%zmm0" & ASCII.LF & ASCII.HT &
        "vpxorq    %%zmm0, %%zmm7, %%zmm7" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x01, %%zmm4, %%zmm3, %%zmm3" & ASCII.LF & ASCII.HT &
        "vpxorq    %%zmm3, %%zmm7, %%zmm7" & ASCII.LF & ASCII.HT &
        "vpslldq   $8, %%zmm7, %%zmm0" & ASCII.LF & ASCII.HT &
        "vpsrldq   $8, %%zmm7, %%zmm7" & ASCII.LF & ASCII.HT &
        "vpxorq    %%zmm0, %%zmm5, %%zmm5" & ASCII.LF & ASCII.HT &
        "vpxorq    %%zmm7, %%zmm6, %%zmm6" & ASCII.LF & ASCII.HT &
        "vextracti64x4 $1, %%zmm5, %%ymm0" & ASCII.LF & ASCII.HT &
        "vpxor     %%ymm0, %%ymm5, %%ymm5" & ASCII.LF & ASCII.HT &
        "vextracti64x4 $1, %%zmm6, %%ymm0" & ASCII.LF & ASCII.HT &
        "vpxor     %%ymm0, %%ymm6, %%ymm6" & ASCII.LF & ASCII.HT &
        "vextracti128 $1, %%ymm5, %%xmm0" & ASCII.LF & ASCII.HT &
        "vpxor     %%xmm0, %%xmm5, %%xmm5" & ASCII.LF & ASCII.HT &
        "vextracti128 $1, %%ymm6, %%xmm0" & ASCII.LF & ASCII.HT &
        "vpxor     %%xmm0, %%xmm6, %%xmm6" & ASCII.LF & ASCII.HT &
        "vpsrld    $31, %%xmm5, %%xmm0" & ASCII.LF & ASCII.HT &
        "vpsrld    $31, %%xmm6, %%xmm1" & ASCII.LF & ASCII.HT &
        "vpslld    $1, %%xmm5, %%xmm5" & ASCII.LF & ASCII.HT &
        "vpslld    $1, %%xmm6, %%xmm6" & ASCII.LF & ASCII.HT &
        "vpsrldq   $12, %%xmm0, %%xmm2" & ASCII.LF & ASCII.HT &
        "vpslldq   $4, %%xmm0, %%xmm0" & ASCII.LF & ASCII.HT &
        "vpslldq   $4, %%xmm1, %%xmm1" & ASCII.LF & ASCII.HT &
        "vpor      %%xmm0, %%xmm5, %%xmm5" & ASCII.LF & ASCII.HT &
        "vpor      %%xmm1, %%xmm6, %%xmm6" & ASCII.LF & ASCII.HT &
        "vpor      %%xmm2, %%xmm6, %%xmm6" & ASCII.LF & ASCII.HT &
        "vmovdqa   (%7), %%xmm4" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x10, %%xmm4, %%xmm5, %%xmm0" & ASCII.LF & ASCII.HT &
        "vpshufd   $0x4e, %%xmm5, %%xmm5" & ASCII.LF & ASCII.HT &
        "vpxor     %%xmm0, %%xmm5, %%xmm5" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x10, %%xmm4, %%xmm5, %%xmm0" & ASCII.LF & ASCII.HT &
        "vpshufd   $0x4e, %%xmm5, %%xmm5" & ASCII.LF & ASCII.HT &
        "vpxor     %%xmm0, %%xmm5, %%xmm5" & ASCII.LF & ASCII.HT &
        "vpxor     %%xmm5, %%xmm6, %%xmm6" & ASCII.LF & ASCII.HT &
        "vpshufb   (%6), %%xmm6, %%xmm6" & ASCII.LF & ASCII.HT &
        "vmovdqu   %%xmm6, (%3)" & ASCII.LF & ASCII.HT &
        "vzeroupper",
        Inputs => (System.Address'Asm_Input ("r", Counter'Address),
                   System.Address'Asm_Input ("r", Pre_RK'Address),
                   System.Address'Asm_Input ("r", Buf'Address),
                   System.Address'Asm_Input ("r", S'Address),
                   System.Address'Asm_Input ("r", H_Powers'Address),
                   System.Address'Asm_Input ("r", Bswap_Mask_ZMM'Address),
                   System.Address'Asm_Input ("r", Bswap_Mask_XMM'Address),
                   System.Address'Asm_Input ("r", Reduction_Poly'Address)),
        Clobber => "xmm0,xmm1,xmm2,xmm3,xmm4,xmm5,xmm6,xmm7," &
                   "xmm14,xmm15,memory",
        Volatile => True);
   end Encrypt_GCM_Stripe_16_128;

   procedure Encrypt_GCM_Stripe_16_256
     (Buf      : in out Byte_Seq;
      S        : in out Bytes_16;
      Counter  : in     Bytes_256;
      Pre_RK   : in     AES_NI.Pre_Swapped_RKs_256;
      H_Powers : in     Pre_H_Powers_16)
   is
   begin
      --  Ciphertext stays in zmm0..zmm3 through authentication.
      --  Counter generation and all GHASH arithmetic are unchanged.
      Asm
       ("vmovdqu64    (%0), %%zmm0" & ASCII.LF & ASCII.HT &
        "vmovdqu64  64(%0), %%zmm1" & ASCII.LF & ASCII.HT &
        "vmovdqu64 128(%0), %%zmm2" & ASCII.LF & ASCII.HT &
        "vmovdqu64 192(%0), %%zmm3" & ASCII.LF & ASCII.HT &
        "vbroadcasti64x2    (%1), %%zmm4" & ASCII.LF & ASCII.HT &
        "vpxorq    %%zmm4, %%zmm0, %%zmm0" & ASCII.LF & ASCII.HT &
        "vpxorq    %%zmm4, %%zmm1, %%zmm1" & ASCII.LF & ASCII.HT &
        "vpxorq    %%zmm4, %%zmm2, %%zmm2" & ASCII.LF & ASCII.HT &
        "vpxorq    %%zmm4, %%zmm3, %%zmm3" & ASCII.LF & ASCII.HT &
        "vbroadcasti64x2  16(%1), %%zmm4" & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm0, %%zmm0" & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm1, %%zmm1" & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm2, %%zmm2" & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm3, %%zmm3" & ASCII.LF & ASCII.HT &
        "vbroadcasti64x2  32(%1), %%zmm4" & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm0, %%zmm0" & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm1, %%zmm1" & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm2, %%zmm2" & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm3, %%zmm3" & ASCII.LF & ASCII.HT &
        "vbroadcasti64x2  48(%1), %%zmm4" & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm0, %%zmm0" & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm1, %%zmm1" & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm2, %%zmm2" & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm3, %%zmm3" & ASCII.LF & ASCII.HT &
        "vbroadcasti64x2  64(%1), %%zmm4" & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm0, %%zmm0" & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm1, %%zmm1" & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm2, %%zmm2" & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm3, %%zmm3" & ASCII.LF & ASCII.HT &
        "vbroadcasti64x2  80(%1), %%zmm4" & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm0, %%zmm0" & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm1, %%zmm1" & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm2, %%zmm2" & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm3, %%zmm3" & ASCII.LF & ASCII.HT &
        "vbroadcasti64x2  96(%1), %%zmm4" & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm0, %%zmm0" & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm1, %%zmm1" & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm2, %%zmm2" & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm3, %%zmm3" & ASCII.LF & ASCII.HT &
        "vbroadcasti64x2 112(%1), %%zmm4" & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm0, %%zmm0" & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm1, %%zmm1" & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm2, %%zmm2" & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm3, %%zmm3" & ASCII.LF & ASCII.HT &
        "vbroadcasti64x2 128(%1), %%zmm4" & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm0, %%zmm0" & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm1, %%zmm1" & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm2, %%zmm2" & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm3, %%zmm3" & ASCII.LF & ASCII.HT &
        "vbroadcasti64x2 144(%1), %%zmm4" & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm0, %%zmm0" & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm1, %%zmm1" & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm2, %%zmm2" & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm3, %%zmm3" & ASCII.LF & ASCII.HT &
        "vbroadcasti64x2 160(%1), %%zmm4" & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm0, %%zmm0" & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm1, %%zmm1" & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm2, %%zmm2" & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm3, %%zmm3" & ASCII.LF & ASCII.HT &
        "vbroadcasti64x2 176(%1), %%zmm4" & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm0, %%zmm0" & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm1, %%zmm1" & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm2, %%zmm2" & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm3, %%zmm3" & ASCII.LF & ASCII.HT &
        "vbroadcasti64x2 192(%1), %%zmm4" & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm0, %%zmm0" & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm1, %%zmm1" & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm2, %%zmm2" & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm3, %%zmm3" & ASCII.LF & ASCII.HT &
        "vbroadcasti64x2 208(%1), %%zmm4" & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm0, %%zmm0" & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm1, %%zmm1" & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm2, %%zmm2" & ASCII.LF & ASCII.HT &
        "vaesenc   %%zmm4, %%zmm3, %%zmm3" & ASCII.LF & ASCII.HT &
        "vbroadcasti64x2 224(%1), %%zmm4" & ASCII.LF & ASCII.HT &
        "vaesenclast %%zmm4, %%zmm0, %%zmm0" & ASCII.LF & ASCII.HT &
        "vaesenclast %%zmm4, %%zmm1, %%zmm1" & ASCII.LF & ASCII.HT &
        "vaesenclast %%zmm4, %%zmm2, %%zmm2" & ASCII.LF & ASCII.HT &
        "vaesenclast %%zmm4, %%zmm3, %%zmm3" & ASCII.LF & ASCII.HT &
        "vmovdqu64    (%2), %%zmm4" & ASCII.LF & ASCII.HT &
        "vpxorq    %%zmm4, %%zmm0, %%zmm0" & ASCII.LF & ASCII.HT &
        "vmovdqu64  64(%2), %%zmm4" & ASCII.LF & ASCII.HT &
        "vpxorq    %%zmm4, %%zmm1, %%zmm1" & ASCII.LF & ASCII.HT &
        "vmovdqu64 128(%2), %%zmm4" & ASCII.LF & ASCII.HT &
        "vpxorq    %%zmm4, %%zmm2, %%zmm2" & ASCII.LF & ASCII.HT &
        "vmovdqu64 192(%2), %%zmm4" & ASCII.LF & ASCII.HT &
        "vpxorq    %%zmm4, %%zmm3, %%zmm3" & ASCII.LF & ASCII.HT &
        "vmovdqu64 %%zmm0,    (%2)" & ASCII.LF & ASCII.HT &
        "vmovdqu64 %%zmm1,  64(%2)" & ASCII.LF & ASCII.HT &
        "vmovdqu64 %%zmm2, 128(%2)" & ASCII.LF & ASCII.HT &
        "vmovdqu64 %%zmm3, 192(%2)" & ASCII.LF & ASCII.HT &
        "vmovdqa64 (%5), %%zmm15" & ASCII.LF & ASCII.HT &
        "vpshufb   %%zmm15, %%zmm0, %%zmm0" & ASCII.LF & ASCII.HT &
        "vpshufb   %%zmm15, %%zmm1, %%zmm1" & ASCII.LF & ASCII.HT &
        "vpshufb   %%zmm15, %%zmm2, %%zmm2" & ASCII.LF & ASCII.HT &
        "vpshufb   %%zmm15, %%zmm3, %%zmm3" & ASCII.LF & ASCII.HT &
        "vmovdqu   (%3), %%xmm4" & ASCII.LF & ASCII.HT &
        "vpshufb   (%6), %%xmm4, %%xmm4" & ASCII.LF & ASCII.HT &
        "vpxorq    %%zmm14, %%zmm14, %%zmm14" & ASCII.LF & ASCII.HT &
        "vinserti64x2 $0, %%xmm4, %%zmm14, %%zmm14" & ASCII.LF & ASCII.HT &
        "vpxorq    %%zmm14, %%zmm0, %%zmm0" & ASCII.LF & ASCII.HT &
        "vmovdqu64    (%4), %%zmm4" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x00, %%zmm4, %%zmm0, %%zmm5" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x11, %%zmm4, %%zmm0, %%zmm6" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x10, %%zmm4, %%zmm0, %%zmm7" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x01, %%zmm4, %%zmm0, %%zmm0" & ASCII.LF & ASCII.HT &
        "vpxorq    %%zmm0, %%zmm7, %%zmm7" & ASCII.LF & ASCII.HT &
        "vmovdqu64  64(%4), %%zmm4" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x00, %%zmm4, %%zmm1, %%zmm0" & ASCII.LF & ASCII.HT &
        "vpxorq    %%zmm0, %%zmm5, %%zmm5" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x11, %%zmm4, %%zmm1, %%zmm0" & ASCII.LF & ASCII.HT &
        "vpxorq    %%zmm0, %%zmm6, %%zmm6" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x10, %%zmm4, %%zmm1, %%zmm0" & ASCII.LF & ASCII.HT &
        "vpxorq    %%zmm0, %%zmm7, %%zmm7" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x01, %%zmm4, %%zmm1, %%zmm1" & ASCII.LF & ASCII.HT &
        "vpxorq    %%zmm1, %%zmm7, %%zmm7" & ASCII.LF & ASCII.HT &
        "vmovdqu64 128(%4), %%zmm4" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x00, %%zmm4, %%zmm2, %%zmm0" & ASCII.LF & ASCII.HT &
        "vpxorq    %%zmm0, %%zmm5, %%zmm5" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x11, %%zmm4, %%zmm2, %%zmm0" & ASCII.LF & ASCII.HT &
        "vpxorq    %%zmm0, %%zmm6, %%zmm6" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x10, %%zmm4, %%zmm2, %%zmm0" & ASCII.LF & ASCII.HT &
        "vpxorq    %%zmm0, %%zmm7, %%zmm7" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x01, %%zmm4, %%zmm2, %%zmm2" & ASCII.LF & ASCII.HT &
        "vpxorq    %%zmm2, %%zmm7, %%zmm7" & ASCII.LF & ASCII.HT &
        "vmovdqu64 192(%4), %%zmm4" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x00, %%zmm4, %%zmm3, %%zmm0" & ASCII.LF & ASCII.HT &
        "vpxorq    %%zmm0, %%zmm5, %%zmm5" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x11, %%zmm4, %%zmm3, %%zmm0" & ASCII.LF & ASCII.HT &
        "vpxorq    %%zmm0, %%zmm6, %%zmm6" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x10, %%zmm4, %%zmm3, %%zmm0" & ASCII.LF & ASCII.HT &
        "vpxorq    %%zmm0, %%zmm7, %%zmm7" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x01, %%zmm4, %%zmm3, %%zmm3" & ASCII.LF & ASCII.HT &
        "vpxorq    %%zmm3, %%zmm7, %%zmm7" & ASCII.LF & ASCII.HT &
        "vpslldq   $8, %%zmm7, %%zmm0" & ASCII.LF & ASCII.HT &
        "vpsrldq   $8, %%zmm7, %%zmm7" & ASCII.LF & ASCII.HT &
        "vpxorq    %%zmm0, %%zmm5, %%zmm5" & ASCII.LF & ASCII.HT &
        "vpxorq    %%zmm7, %%zmm6, %%zmm6" & ASCII.LF & ASCII.HT &
        "vextracti64x4 $1, %%zmm5, %%ymm0" & ASCII.LF & ASCII.HT &
        "vpxor     %%ymm0, %%ymm5, %%ymm5" & ASCII.LF & ASCII.HT &
        "vextracti64x4 $1, %%zmm6, %%ymm0" & ASCII.LF & ASCII.HT &
        "vpxor     %%ymm0, %%ymm6, %%ymm6" & ASCII.LF & ASCII.HT &
        "vextracti128 $1, %%ymm5, %%xmm0" & ASCII.LF & ASCII.HT &
        "vpxor     %%xmm0, %%xmm5, %%xmm5" & ASCII.LF & ASCII.HT &
        "vextracti128 $1, %%ymm6, %%xmm0" & ASCII.LF & ASCII.HT &
        "vpxor     %%xmm0, %%xmm6, %%xmm6" & ASCII.LF & ASCII.HT &
        "vpsrld    $31, %%xmm5, %%xmm0" & ASCII.LF & ASCII.HT &
        "vpsrld    $31, %%xmm6, %%xmm1" & ASCII.LF & ASCII.HT &
        "vpslld    $1, %%xmm5, %%xmm5" & ASCII.LF & ASCII.HT &
        "vpslld    $1, %%xmm6, %%xmm6" & ASCII.LF & ASCII.HT &
        "vpsrldq   $12, %%xmm0, %%xmm2" & ASCII.LF & ASCII.HT &
        "vpslldq   $4, %%xmm0, %%xmm0" & ASCII.LF & ASCII.HT &
        "vpslldq   $4, %%xmm1, %%xmm1" & ASCII.LF & ASCII.HT &
        "vpor      %%xmm0, %%xmm5, %%xmm5" & ASCII.LF & ASCII.HT &
        "vpor      %%xmm1, %%xmm6, %%xmm6" & ASCII.LF & ASCII.HT &
        "vpor      %%xmm2, %%xmm6, %%xmm6" & ASCII.LF & ASCII.HT &
        "vmovdqa   (%7), %%xmm4" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x10, %%xmm4, %%xmm5, %%xmm0" & ASCII.LF & ASCII.HT &
        "vpshufd   $0x4e, %%xmm5, %%xmm5" & ASCII.LF & ASCII.HT &
        "vpxor     %%xmm0, %%xmm5, %%xmm5" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x10, %%xmm4, %%xmm5, %%xmm0" & ASCII.LF & ASCII.HT &
        "vpshufd   $0x4e, %%xmm5, %%xmm5" & ASCII.LF & ASCII.HT &
        "vpxor     %%xmm0, %%xmm5, %%xmm5" & ASCII.LF & ASCII.HT &
        "vpxor     %%xmm5, %%xmm6, %%xmm6" & ASCII.LF & ASCII.HT &
        "vpshufb   (%6), %%xmm6, %%xmm6" & ASCII.LF & ASCII.HT &
        "vmovdqu   %%xmm6, (%3)" & ASCII.LF & ASCII.HT &
        "vzeroupper",
        Inputs => (System.Address'Asm_Input ("r", Counter'Address),
                   System.Address'Asm_Input ("r", Pre_RK'Address),
                   System.Address'Asm_Input ("r", Buf'Address),
                   System.Address'Asm_Input ("r", S'Address),
                   System.Address'Asm_Input ("r", H_Powers'Address),
                   System.Address'Asm_Input ("r", Bswap_Mask_ZMM'Address),
                   System.Address'Asm_Input ("r", Bswap_Mask_XMM'Address),
                   System.Address'Asm_Input ("r", Reduction_Poly'Address)),
        Clobber => "xmm0,xmm1,xmm2,xmm3,xmm4,xmm5,xmm6,xmm7," &
                   "xmm14,xmm15,memory",
        Volatile => True);
   end Encrypt_GCM_Stripe_16_256;

   ----------------------------------------------------------------------------
   --  Stitched sixteen-block decryption (generated; see the specification)
   ----------------------------------------------------------------------------

   --  BEGIN GENERATED avx512 constants
   --  Constants of the generated kernels. Gen_Bswap_Mask reverses each
   --  16-byte lane (NIST GHASH <-> PCLMULQDQ order); Gen_Reverse_Ctr_Mask
   --  reverses only the big-endian counter word of each lane so PADDD can
   --  add to it; entry k of Gen_Ctr_Steps adds k to that word (inc32 mod
   --  2**32, as Increment_Counter); Gen_Reduction_Poly is the upper half
   --  of the reflected reduction polynomial, 0xC2 << 56.
   Gen_Bswap_Mask : constant array (0 .. 63) of Unsigned_8 :=
     (15,14,13,12, 11,10,9,8, 7,6,5,4, 3,2,1,0,
      15,14,13,12, 11,10,9,8, 7,6,5,4, 3,2,1,0,
      15,14,13,12, 11,10,9,8, 7,6,5,4, 3,2,1,0,
      15,14,13,12, 11,10,9,8, 7,6,5,4, 3,2,1,0);
   for Gen_Bswap_Mask'Alignment use 64;
   Gen_Reverse_Ctr_Mask : constant array (0 .. 63) of Unsigned_8 :=
     (0,1,2,3, 4,5,6,7, 8,9,10,11, 15,14,13,12,
      0,1,2,3, 4,5,6,7, 8,9,10,11, 15,14,13,12,
      0,1,2,3, 4,5,6,7, 8,9,10,11, 15,14,13,12,
      0,1,2,3, 4,5,6,7, 8,9,10,11, 15,14,13,12);
   for Gen_Reverse_Ctr_Mask'Alignment use 64;
   Gen_Ctr_Steps : constant array (0 .. 527) of Unsigned_8 :=
     (0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,
      0,0,0,0, 0,0,0,0, 0,0,0,0, 1,0,0,0,
      0,0,0,0, 0,0,0,0, 0,0,0,0, 2,0,0,0,
      0,0,0,0, 0,0,0,0, 0,0,0,0, 3,0,0,0,
      0,0,0,0, 0,0,0,0, 0,0,0,0, 4,0,0,0,
      0,0,0,0, 0,0,0,0, 0,0,0,0, 5,0,0,0,
      0,0,0,0, 0,0,0,0, 0,0,0,0, 6,0,0,0,
      0,0,0,0, 0,0,0,0, 0,0,0,0, 7,0,0,0,
      0,0,0,0, 0,0,0,0, 0,0,0,0, 8,0,0,0,
      0,0,0,0, 0,0,0,0, 0,0,0,0, 9,0,0,0,
      0,0,0,0, 0,0,0,0, 0,0,0,0, 10,0,0,0,
      0,0,0,0, 0,0,0,0, 0,0,0,0, 11,0,0,0,
      0,0,0,0, 0,0,0,0, 0,0,0,0, 12,0,0,0,
      0,0,0,0, 0,0,0,0, 0,0,0,0, 13,0,0,0,
      0,0,0,0, 0,0,0,0, 0,0,0,0, 14,0,0,0,
      0,0,0,0, 0,0,0,0, 0,0,0,0, 15,0,0,0,
      0,0,0,0, 0,0,0,0, 0,0,0,0, 16,0,0,0,
      0,0,0,0, 0,0,0,0, 0,0,0,0, 17,0,0,0,
      0,0,0,0, 0,0,0,0, 0,0,0,0, 18,0,0,0,
      0,0,0,0, 0,0,0,0, 0,0,0,0, 19,0,0,0,
      0,0,0,0, 0,0,0,0, 0,0,0,0, 20,0,0,0,
      0,0,0,0, 0,0,0,0, 0,0,0,0, 21,0,0,0,
      0,0,0,0, 0,0,0,0, 0,0,0,0, 22,0,0,0,
      0,0,0,0, 0,0,0,0, 0,0,0,0, 23,0,0,0,
      0,0,0,0, 0,0,0,0, 0,0,0,0, 24,0,0,0,
      0,0,0,0, 0,0,0,0, 0,0,0,0, 25,0,0,0,
      0,0,0,0, 0,0,0,0, 0,0,0,0, 26,0,0,0,
      0,0,0,0, 0,0,0,0, 0,0,0,0, 27,0,0,0,
      0,0,0,0, 0,0,0,0, 0,0,0,0, 28,0,0,0,
      0,0,0,0, 0,0,0,0, 0,0,0,0, 29,0,0,0,
      0,0,0,0, 0,0,0,0, 0,0,0,0, 30,0,0,0,
      0,0,0,0, 0,0,0,0, 0,0,0,0, 31,0,0,0,
      0,0,0,0, 0,0,0,0, 0,0,0,0, 32,0,0,0);
   for Gen_Ctr_Steps'Alignment use 64;
   Gen_Reduction_Poly : constant array (0 .. 15) of Unsigned_8 :=
     (0 .. 14 => 0, 15 => 16#C2#);
   for Gen_Reduction_Poly'Alignment use 16;
   --  END GENERATED avx512 constants

   --  BEGIN GENERATED avx512 decrypt 128
   --  Decrypt one stripe in place: GHASH the ciphertext into S,
   --  interleaved with AES-CTR from CB; CB advances by the stripe.
   procedure Decrypt_GCM_Stripe_16_128
     (Buf      : in out Byte_Seq;
      S        : in out Bytes_16;
      CB       : in out Bytes_16;
      Pre_RK   : in     AES_NI.Pre_Swapped_RKs_128;
      H_Powers : in     Pre_H_Powers_16)
   is
   begin
      Asm
       ("vbroadcasti32x4 (%0), %%zmm11" & ASCII.LF & ASCII.HT &
        "vmovdqa64 (%6), %%zmm12" & ASCII.LF & ASCII.HT &
        "vpshufb %%zmm12, %%zmm11, %%zmm11" & ASCII.LF & ASCII.HT &
        "vpaddd (%7), %%zmm11, %%zmm0" & ASCII.LF & ASCII.HT &
        "vpshufb %%zmm12, %%zmm0, %%zmm0" & ASCII.LF & ASCII.HT &
        "vpaddd 64(%7), %%zmm11, %%zmm1" & ASCII.LF & ASCII.HT &
        "vpshufb %%zmm12, %%zmm1, %%zmm1" & ASCII.LF & ASCII.HT &
        "vpaddd 128(%7), %%zmm11, %%zmm2" & ASCII.LF & ASCII.HT &
        "vpshufb %%zmm12, %%zmm2, %%zmm2" & ASCII.LF & ASCII.HT &
        "vpaddd 192(%7), %%zmm11, %%zmm3" & ASCII.LF & ASCII.HT &
        "vpshufb %%zmm12, %%zmm3, %%zmm3" & ASCII.LF & ASCII.HT &
        "vpaddd 256(%7), %%xmm11, %%xmm13" & ASCII.LF & ASCII.HT &
        "vpshufb %%xmm12, %%xmm13, %%xmm13" & ASCII.LF & ASCII.HT &
        "vmovdqu %%xmm13, (%0)" & ASCII.LF & ASCII.HT &
        "vbroadcasti32x4 (%1), %%zmm4" & ASCII.LF & ASCII.HT &
        "vpxorq %%zmm4, %%zmm0, %%zmm0" & ASCII.LF & ASCII.HT &
        "vpxorq %%zmm4, %%zmm1, %%zmm1" & ASCII.LF & ASCII.HT &
        "vpxorq %%zmm4, %%zmm2, %%zmm2" & ASCII.LF & ASCII.HT &
        "vpxorq %%zmm4, %%zmm3, %%zmm3" & ASCII.LF & ASCII.HT &
        "vbroadcasti32x4 16(%1), %%zmm4" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm4, %%zmm0, %%zmm0" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm4, %%zmm1, %%zmm1" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm4, %%zmm2, %%zmm2" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm4, %%zmm3, %%zmm3" & ASCII.LF & ASCII.HT &
        "vmovdqa64 (%5), %%zmm15" & ASCII.LF & ASCII.HT &
        "vmovdqu64 (%2), %%zmm8" & ASCII.LF & ASCII.HT &
        "vpshufb %%zmm15, %%zmm8, %%zmm8" & ASCII.LF & ASCII.HT &
        "vmovdqu (%3), %%xmm10" & ASCII.LF & ASCII.HT &
        "vpshufb %%xmm15, %%xmm10, %%xmm10" & ASCII.LF & ASCII.HT &
        "vbroadcasti32x4 32(%1), %%zmm4" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm4, %%zmm0, %%zmm0" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm4, %%zmm1, %%zmm1" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm4, %%zmm2, %%zmm2" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm4, %%zmm3, %%zmm3" & ASCII.LF & ASCII.HT &
        "vpxorq %%zmm10, %%zmm8, %%zmm8" & ASCII.LF & ASCII.HT &
        "vmovdqu64 (%4), %%zmm9" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x00, %%zmm9, %%zmm8, %%zmm5" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x11, %%zmm9, %%zmm8, %%zmm6" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x10, %%zmm9, %%zmm8, %%zmm7" & ASCII.LF & ASCII.HT &
        "vbroadcasti32x4 48(%1), %%zmm4" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm4, %%zmm0, %%zmm0" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm4, %%zmm1, %%zmm1" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm4, %%zmm2, %%zmm2" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm4, %%zmm3, %%zmm3" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x01, %%zmm9, %%zmm8, %%zmm8" & ASCII.LF & ASCII.HT &
        "vpxorq %%zmm8, %%zmm7, %%zmm7" & ASCII.LF & ASCII.HT &
        "vmovdqu64 64(%2), %%zmm8" & ASCII.LF & ASCII.HT &
        "vpshufb %%zmm15, %%zmm8, %%zmm8" & ASCII.LF & ASCII.HT &
        "vmovdqu64 64(%4), %%zmm9" & ASCII.LF & ASCII.HT &
        "vbroadcasti32x4 64(%1), %%zmm4" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm4, %%zmm0, %%zmm0" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm4, %%zmm1, %%zmm1" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm4, %%zmm2, %%zmm2" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm4, %%zmm3, %%zmm3" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x00, %%zmm9, %%zmm8, %%zmm10" & ASCII.LF & ASCII.HT &
        "vpxorq %%zmm10, %%zmm5, %%zmm5" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x11, %%zmm9, %%zmm8, %%zmm10" & ASCII.LF & ASCII.HT &
        "vpxorq %%zmm10, %%zmm6, %%zmm6" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x10, %%zmm9, %%zmm8, %%zmm10" & ASCII.LF & ASCII.HT &
        "vbroadcasti32x4 80(%1), %%zmm4" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm4, %%zmm0, %%zmm0" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm4, %%zmm1, %%zmm1" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm4, %%zmm2, %%zmm2" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm4, %%zmm3, %%zmm3" & ASCII.LF & ASCII.HT &
        "vpxorq %%zmm10, %%zmm7, %%zmm7" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x01, %%zmm9, %%zmm8, %%zmm8" & ASCII.LF & ASCII.HT &
        "vpxorq %%zmm8, %%zmm7, %%zmm7" & ASCII.LF & ASCII.HT &
        "vmovdqu64 128(%2), %%zmm8" & ASCII.LF & ASCII.HT &
        "vpshufb %%zmm15, %%zmm8, %%zmm8" & ASCII.LF & ASCII.HT &
        "vbroadcasti32x4 96(%1), %%zmm4" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm4, %%zmm0, %%zmm0" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm4, %%zmm1, %%zmm1" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm4, %%zmm2, %%zmm2" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm4, %%zmm3, %%zmm3" & ASCII.LF & ASCII.HT &
        "vmovdqu64 128(%4), %%zmm9" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x00, %%zmm9, %%zmm8, %%zmm10" & ASCII.LF & ASCII.HT &
        "vpxorq %%zmm10, %%zmm5, %%zmm5" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x11, %%zmm9, %%zmm8, %%zmm10" & ASCII.LF & ASCII.HT &
        "vpxorq %%zmm10, %%zmm6, %%zmm6" & ASCII.LF & ASCII.HT &
        "vbroadcasti32x4 112(%1), %%zmm4" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm4, %%zmm0, %%zmm0" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm4, %%zmm1, %%zmm1" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm4, %%zmm2, %%zmm2" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm4, %%zmm3, %%zmm3" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x10, %%zmm9, %%zmm8, %%zmm10" & ASCII.LF & ASCII.HT &
        "vpxorq %%zmm10, %%zmm7, %%zmm7" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x01, %%zmm9, %%zmm8, %%zmm8" & ASCII.LF & ASCII.HT &
        "vpxorq %%zmm8, %%zmm7, %%zmm7" & ASCII.LF & ASCII.HT &
        "vmovdqu64 192(%2), %%zmm8" & ASCII.LF & ASCII.HT &
        "vbroadcasti32x4 128(%1), %%zmm4" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm4, %%zmm0, %%zmm0" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm4, %%zmm1, %%zmm1" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm4, %%zmm2, %%zmm2" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm4, %%zmm3, %%zmm3" & ASCII.LF & ASCII.HT &
        "vpshufb %%zmm15, %%zmm8, %%zmm8" & ASCII.LF & ASCII.HT &
        "vmovdqu64 192(%4), %%zmm9" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x00, %%zmm9, %%zmm8, %%zmm10" & ASCII.LF & ASCII.HT &
        "vpxorq %%zmm10, %%zmm5, %%zmm5" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x11, %%zmm9, %%zmm8, %%zmm10" & ASCII.LF & ASCII.HT &
        "vbroadcasti32x4 144(%1), %%zmm4" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm4, %%zmm0, %%zmm0" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm4, %%zmm1, %%zmm1" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm4, %%zmm2, %%zmm2" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm4, %%zmm3, %%zmm3" & ASCII.LF & ASCII.HT &
        "vpxorq %%zmm10, %%zmm6, %%zmm6" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x10, %%zmm9, %%zmm8, %%zmm10" & ASCII.LF & ASCII.HT &
        "vpxorq %%zmm10, %%zmm7, %%zmm7" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x01, %%zmm9, %%zmm8, %%zmm8" & ASCII.LF & ASCII.HT &
        "vpxorq %%zmm8, %%zmm7, %%zmm7" & ASCII.LF & ASCII.HT &
        "vbroadcasti32x4 160(%1), %%zmm4" & ASCII.LF & ASCII.HT &
        "vaesenclast %%zmm4, %%zmm0, %%zmm0" & ASCII.LF & ASCII.HT &
        "vaesenclast %%zmm4, %%zmm1, %%zmm1" & ASCII.LF & ASCII.HT &
        "vaesenclast %%zmm4, %%zmm2, %%zmm2" & ASCII.LF & ASCII.HT &
        "vaesenclast %%zmm4, %%zmm3, %%zmm3" & ASCII.LF & ASCII.HT &
        "vpxorq (%2), %%zmm0, %%zmm0" & ASCII.LF & ASCII.HT &
        "vmovdqu64 %%zmm0, (%2)" & ASCII.LF & ASCII.HT &
        "vpxorq 64(%2), %%zmm1, %%zmm1" & ASCII.LF & ASCII.HT &
        "vmovdqu64 %%zmm1, 64(%2)" & ASCII.LF & ASCII.HT &
        "vpxorq 128(%2), %%zmm2, %%zmm2" & ASCII.LF & ASCII.HT &
        "vmovdqu64 %%zmm2, 128(%2)" & ASCII.LF & ASCII.HT &
        "vpxorq 192(%2), %%zmm3, %%zmm3" & ASCII.LF & ASCII.HT &
        "vmovdqu64 %%zmm3, 192(%2)" & ASCII.LF & ASCII.HT &
        "vpslldq $8, %%zmm7, %%zmm10" & ASCII.LF & ASCII.HT &
        "vpsrldq $8, %%zmm7, %%zmm7" & ASCII.LF & ASCII.HT &
        "vpxorq %%zmm10, %%zmm5, %%zmm5" & ASCII.LF & ASCII.HT &
        "vpxorq %%zmm7, %%zmm6, %%zmm6" & ASCII.LF & ASCII.HT &
        "vextracti64x4 $1, %%zmm5, %%ymm10" & ASCII.LF & ASCII.HT &
        "vpxor %%ymm10, %%ymm5, %%ymm5" & ASCII.LF & ASCII.HT &
        "vextracti64x4 $1, %%zmm6, %%ymm10" & ASCII.LF & ASCII.HT &
        "vpxor %%ymm10, %%ymm6, %%ymm6" & ASCII.LF & ASCII.HT &
        "vextracti128 $1, %%ymm5, %%xmm10" & ASCII.LF & ASCII.HT &
        "vpxor %%xmm10, %%xmm5, %%xmm5" & ASCII.LF & ASCII.HT &
        "vextracti128 $1, %%ymm6, %%xmm10" & ASCII.LF & ASCII.HT &
        "vpxor %%xmm10, %%xmm6, %%xmm6" & ASCII.LF & ASCII.HT &
        "vpsrld $31, %%xmm5, %%xmm0" & ASCII.LF & ASCII.HT &
        "vpsrld $31, %%xmm6, %%xmm1" & ASCII.LF & ASCII.HT &
        "vpslld $1, %%xmm5, %%xmm5" & ASCII.LF & ASCII.HT &
        "vpslld $1, %%xmm6, %%xmm6" & ASCII.LF & ASCII.HT &
        "vpsrldq $12, %%xmm0, %%xmm2" & ASCII.LF & ASCII.HT &
        "vpslldq $4, %%xmm0, %%xmm0" & ASCII.LF & ASCII.HT &
        "vpslldq $4, %%xmm1, %%xmm1" & ASCII.LF & ASCII.HT &
        "vpor %%xmm0, %%xmm5, %%xmm5" & ASCII.LF & ASCII.HT &
        "vpor %%xmm1, %%xmm6, %%xmm6" & ASCII.LF & ASCII.HT &
        "vpor %%xmm2, %%xmm6, %%xmm6" & ASCII.LF & ASCII.HT &
        "vmovdqa (%8), %%xmm3" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x10, %%xmm3, %%xmm5, %%xmm0" & ASCII.LF & ASCII.HT &
        "vpshufd $0x4e, %%xmm5, %%xmm5" & ASCII.LF & ASCII.HT &
        "vpxor %%xmm0, %%xmm5, %%xmm5" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x10, %%xmm3, %%xmm5, %%xmm0" & ASCII.LF & ASCII.HT &
        "vpshufd $0x4e, %%xmm5, %%xmm5" & ASCII.LF & ASCII.HT &
        "vpxor %%xmm0, %%xmm5, %%xmm5" & ASCII.LF & ASCII.HT &
        "vpxor %%xmm5, %%xmm6, %%xmm6" & ASCII.LF & ASCII.HT &
        "vpshufb %%xmm15, %%xmm6, %%xmm6" & ASCII.LF & ASCII.HT &
        "vmovdqu %%xmm6, (%3)" & ASCII.LF & ASCII.HT &
        "vzeroupper",
        Inputs => (System.Address'Asm_Input ("r", CB'Address),
                   System.Address'Asm_Input ("r", Pre_RK'Address),
                   System.Address'Asm_Input ("r", Buf'Address),
                   System.Address'Asm_Input ("r", S'Address),
                   System.Address'Asm_Input ("r", H_Powers'Address),
                   System.Address'Asm_Input ("r", Gen_Bswap_Mask'Address),
                   System.Address'Asm_Input ("r", Gen_Reverse_Ctr_Mask'Address),
                   System.Address'Asm_Input ("r", Gen_Ctr_Steps'Address),
                   System.Address'Asm_Input ("r", Gen_Reduction_Poly'Address)),
        Clobber => "xmm0,xmm1,xmm2,xmm3,xmm4,xmm5,xmm6,xmm7,xmm8,xmm9,xmm10,xmm11,xmm12,xmm13,xmm15,memory",
        Volatile => True);
   end Decrypt_GCM_Stripe_16_128;
   --  END GENERATED avx512 decrypt 128

   --  BEGIN GENERATED avx512 decrypt 256
   --  Decrypt one stripe in place: GHASH the ciphertext into S,
   --  interleaved with AES-CTR from CB; CB advances by the stripe.
   procedure Decrypt_GCM_Stripe_16_256
     (Buf      : in out Byte_Seq;
      S        : in out Bytes_16;
      CB       : in out Bytes_16;
      Pre_RK   : in     AES_NI.Pre_Swapped_RKs_256;
      H_Powers : in     Pre_H_Powers_16)
   is
   begin
      Asm
       ("vbroadcasti32x4 (%0), %%zmm11" & ASCII.LF & ASCII.HT &
        "vmovdqa64 (%6), %%zmm12" & ASCII.LF & ASCII.HT &
        "vpshufb %%zmm12, %%zmm11, %%zmm11" & ASCII.LF & ASCII.HT &
        "vpaddd (%7), %%zmm11, %%zmm0" & ASCII.LF & ASCII.HT &
        "vpshufb %%zmm12, %%zmm0, %%zmm0" & ASCII.LF & ASCII.HT &
        "vpaddd 64(%7), %%zmm11, %%zmm1" & ASCII.LF & ASCII.HT &
        "vpshufb %%zmm12, %%zmm1, %%zmm1" & ASCII.LF & ASCII.HT &
        "vpaddd 128(%7), %%zmm11, %%zmm2" & ASCII.LF & ASCII.HT &
        "vpshufb %%zmm12, %%zmm2, %%zmm2" & ASCII.LF & ASCII.HT &
        "vpaddd 192(%7), %%zmm11, %%zmm3" & ASCII.LF & ASCII.HT &
        "vpshufb %%zmm12, %%zmm3, %%zmm3" & ASCII.LF & ASCII.HT &
        "vpaddd 256(%7), %%xmm11, %%xmm13" & ASCII.LF & ASCII.HT &
        "vpshufb %%xmm12, %%xmm13, %%xmm13" & ASCII.LF & ASCII.HT &
        "vmovdqu %%xmm13, (%0)" & ASCII.LF & ASCII.HT &
        "vbroadcasti32x4 (%1), %%zmm4" & ASCII.LF & ASCII.HT &
        "vpxorq %%zmm4, %%zmm0, %%zmm0" & ASCII.LF & ASCII.HT &
        "vpxorq %%zmm4, %%zmm1, %%zmm1" & ASCII.LF & ASCII.HT &
        "vpxorq %%zmm4, %%zmm2, %%zmm2" & ASCII.LF & ASCII.HT &
        "vpxorq %%zmm4, %%zmm3, %%zmm3" & ASCII.LF & ASCII.HT &
        "vbroadcasti32x4 16(%1), %%zmm4" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm4, %%zmm0, %%zmm0" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm4, %%zmm1, %%zmm1" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm4, %%zmm2, %%zmm2" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm4, %%zmm3, %%zmm3" & ASCII.LF & ASCII.HT &
        "vmovdqa64 (%5), %%zmm15" & ASCII.LF & ASCII.HT &
        "vmovdqu64 (%2), %%zmm8" & ASCII.LF & ASCII.HT &
        "vpshufb %%zmm15, %%zmm8, %%zmm8" & ASCII.LF & ASCII.HT &
        "vmovdqu (%3), %%xmm10" & ASCII.LF & ASCII.HT &
        "vbroadcasti32x4 32(%1), %%zmm4" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm4, %%zmm0, %%zmm0" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm4, %%zmm1, %%zmm1" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm4, %%zmm2, %%zmm2" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm4, %%zmm3, %%zmm3" & ASCII.LF & ASCII.HT &
        "vpshufb %%xmm15, %%xmm10, %%xmm10" & ASCII.LF & ASCII.HT &
        "vpxorq %%zmm10, %%zmm8, %%zmm8" & ASCII.LF & ASCII.HT &
        "vmovdqu64 (%4), %%zmm9" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x00, %%zmm9, %%zmm8, %%zmm5" & ASCII.LF & ASCII.HT &
        "vbroadcasti32x4 48(%1), %%zmm4" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm4, %%zmm0, %%zmm0" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm4, %%zmm1, %%zmm1" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm4, %%zmm2, %%zmm2" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm4, %%zmm3, %%zmm3" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x11, %%zmm9, %%zmm8, %%zmm6" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x10, %%zmm9, %%zmm8, %%zmm7" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x01, %%zmm9, %%zmm8, %%zmm8" & ASCII.LF & ASCII.HT &
        "vpxorq %%zmm8, %%zmm7, %%zmm7" & ASCII.LF & ASCII.HT &
        "vbroadcasti32x4 64(%1), %%zmm4" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm4, %%zmm0, %%zmm0" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm4, %%zmm1, %%zmm1" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm4, %%zmm2, %%zmm2" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm4, %%zmm3, %%zmm3" & ASCII.LF & ASCII.HT &
        "vmovdqu64 64(%2), %%zmm8" & ASCII.LF & ASCII.HT &
        "vpshufb %%zmm15, %%zmm8, %%zmm8" & ASCII.LF & ASCII.HT &
        "vmovdqu64 64(%4), %%zmm9" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x00, %%zmm9, %%zmm8, %%zmm10" & ASCII.LF & ASCII.HT &
        "vbroadcasti32x4 80(%1), %%zmm4" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm4, %%zmm0, %%zmm0" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm4, %%zmm1, %%zmm1" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm4, %%zmm2, %%zmm2" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm4, %%zmm3, %%zmm3" & ASCII.LF & ASCII.HT &
        "vpxorq %%zmm10, %%zmm5, %%zmm5" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x11, %%zmm9, %%zmm8, %%zmm10" & ASCII.LF & ASCII.HT &
        "vpxorq %%zmm10, %%zmm6, %%zmm6" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x10, %%zmm9, %%zmm8, %%zmm10" & ASCII.LF & ASCII.HT &
        "vbroadcasti32x4 96(%1), %%zmm4" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm4, %%zmm0, %%zmm0" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm4, %%zmm1, %%zmm1" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm4, %%zmm2, %%zmm2" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm4, %%zmm3, %%zmm3" & ASCII.LF & ASCII.HT &
        "vpxorq %%zmm10, %%zmm7, %%zmm7" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x01, %%zmm9, %%zmm8, %%zmm8" & ASCII.LF & ASCII.HT &
        "vpxorq %%zmm8, %%zmm7, %%zmm7" & ASCII.LF & ASCII.HT &
        "vmovdqu64 128(%2), %%zmm8" & ASCII.LF & ASCII.HT &
        "vbroadcasti32x4 112(%1), %%zmm4" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm4, %%zmm0, %%zmm0" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm4, %%zmm1, %%zmm1" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm4, %%zmm2, %%zmm2" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm4, %%zmm3, %%zmm3" & ASCII.LF & ASCII.HT &
        "vpshufb %%zmm15, %%zmm8, %%zmm8" & ASCII.LF & ASCII.HT &
        "vmovdqu64 128(%4), %%zmm9" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x00, %%zmm9, %%zmm8, %%zmm10" & ASCII.LF & ASCII.HT &
        "vpxorq %%zmm10, %%zmm5, %%zmm5" & ASCII.LF & ASCII.HT &
        "vbroadcasti32x4 128(%1), %%zmm4" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm4, %%zmm0, %%zmm0" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm4, %%zmm1, %%zmm1" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm4, %%zmm2, %%zmm2" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm4, %%zmm3, %%zmm3" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x11, %%zmm9, %%zmm8, %%zmm10" & ASCII.LF & ASCII.HT &
        "vpxorq %%zmm10, %%zmm6, %%zmm6" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x10, %%zmm9, %%zmm8, %%zmm10" & ASCII.LF & ASCII.HT &
        "vpxorq %%zmm10, %%zmm7, %%zmm7" & ASCII.LF & ASCII.HT &
        "vbroadcasti32x4 144(%1), %%zmm4" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm4, %%zmm0, %%zmm0" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm4, %%zmm1, %%zmm1" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm4, %%zmm2, %%zmm2" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm4, %%zmm3, %%zmm3" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x01, %%zmm9, %%zmm8, %%zmm8" & ASCII.LF & ASCII.HT &
        "vpxorq %%zmm8, %%zmm7, %%zmm7" & ASCII.LF & ASCII.HT &
        "vmovdqu64 192(%2), %%zmm8" & ASCII.LF & ASCII.HT &
        "vpshufb %%zmm15, %%zmm8, %%zmm8" & ASCII.LF & ASCII.HT &
        "vbroadcasti32x4 160(%1), %%zmm4" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm4, %%zmm0, %%zmm0" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm4, %%zmm1, %%zmm1" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm4, %%zmm2, %%zmm2" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm4, %%zmm3, %%zmm3" & ASCII.LF & ASCII.HT &
        "vmovdqu64 192(%4), %%zmm9" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x00, %%zmm9, %%zmm8, %%zmm10" & ASCII.LF & ASCII.HT &
        "vpxorq %%zmm10, %%zmm5, %%zmm5" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x11, %%zmm9, %%zmm8, %%zmm10" & ASCII.LF & ASCII.HT &
        "vbroadcasti32x4 176(%1), %%zmm4" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm4, %%zmm0, %%zmm0" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm4, %%zmm1, %%zmm1" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm4, %%zmm2, %%zmm2" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm4, %%zmm3, %%zmm3" & ASCII.LF & ASCII.HT &
        "vpxorq %%zmm10, %%zmm6, %%zmm6" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x10, %%zmm9, %%zmm8, %%zmm10" & ASCII.LF & ASCII.HT &
        "vpxorq %%zmm10, %%zmm7, %%zmm7" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x01, %%zmm9, %%zmm8, %%zmm8" & ASCII.LF & ASCII.HT &
        "vbroadcasti32x4 192(%1), %%zmm4" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm4, %%zmm0, %%zmm0" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm4, %%zmm1, %%zmm1" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm4, %%zmm2, %%zmm2" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm4, %%zmm3, %%zmm3" & ASCII.LF & ASCII.HT &
        "vpxorq %%zmm8, %%zmm7, %%zmm7" & ASCII.LF & ASCII.HT &
        "vbroadcasti32x4 208(%1), %%zmm4" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm4, %%zmm0, %%zmm0" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm4, %%zmm1, %%zmm1" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm4, %%zmm2, %%zmm2" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm4, %%zmm3, %%zmm3" & ASCII.LF & ASCII.HT &
        "vbroadcasti32x4 224(%1), %%zmm4" & ASCII.LF & ASCII.HT &
        "vaesenclast %%zmm4, %%zmm0, %%zmm0" & ASCII.LF & ASCII.HT &
        "vaesenclast %%zmm4, %%zmm1, %%zmm1" & ASCII.LF & ASCII.HT &
        "vaesenclast %%zmm4, %%zmm2, %%zmm2" & ASCII.LF & ASCII.HT &
        "vaesenclast %%zmm4, %%zmm3, %%zmm3" & ASCII.LF & ASCII.HT &
        "vpxorq (%2), %%zmm0, %%zmm0" & ASCII.LF & ASCII.HT &
        "vmovdqu64 %%zmm0, (%2)" & ASCII.LF & ASCII.HT &
        "vpxorq 64(%2), %%zmm1, %%zmm1" & ASCII.LF & ASCII.HT &
        "vmovdqu64 %%zmm1, 64(%2)" & ASCII.LF & ASCII.HT &
        "vpxorq 128(%2), %%zmm2, %%zmm2" & ASCII.LF & ASCII.HT &
        "vmovdqu64 %%zmm2, 128(%2)" & ASCII.LF & ASCII.HT &
        "vpxorq 192(%2), %%zmm3, %%zmm3" & ASCII.LF & ASCII.HT &
        "vmovdqu64 %%zmm3, 192(%2)" & ASCII.LF & ASCII.HT &
        "vpslldq $8, %%zmm7, %%zmm10" & ASCII.LF & ASCII.HT &
        "vpsrldq $8, %%zmm7, %%zmm7" & ASCII.LF & ASCII.HT &
        "vpxorq %%zmm10, %%zmm5, %%zmm5" & ASCII.LF & ASCII.HT &
        "vpxorq %%zmm7, %%zmm6, %%zmm6" & ASCII.LF & ASCII.HT &
        "vextracti64x4 $1, %%zmm5, %%ymm10" & ASCII.LF & ASCII.HT &
        "vpxor %%ymm10, %%ymm5, %%ymm5" & ASCII.LF & ASCII.HT &
        "vextracti64x4 $1, %%zmm6, %%ymm10" & ASCII.LF & ASCII.HT &
        "vpxor %%ymm10, %%ymm6, %%ymm6" & ASCII.LF & ASCII.HT &
        "vextracti128 $1, %%ymm5, %%xmm10" & ASCII.LF & ASCII.HT &
        "vpxor %%xmm10, %%xmm5, %%xmm5" & ASCII.LF & ASCII.HT &
        "vextracti128 $1, %%ymm6, %%xmm10" & ASCII.LF & ASCII.HT &
        "vpxor %%xmm10, %%xmm6, %%xmm6" & ASCII.LF & ASCII.HT &
        "vpsrld $31, %%xmm5, %%xmm0" & ASCII.LF & ASCII.HT &
        "vpsrld $31, %%xmm6, %%xmm1" & ASCII.LF & ASCII.HT &
        "vpslld $1, %%xmm5, %%xmm5" & ASCII.LF & ASCII.HT &
        "vpslld $1, %%xmm6, %%xmm6" & ASCII.LF & ASCII.HT &
        "vpsrldq $12, %%xmm0, %%xmm2" & ASCII.LF & ASCII.HT &
        "vpslldq $4, %%xmm0, %%xmm0" & ASCII.LF & ASCII.HT &
        "vpslldq $4, %%xmm1, %%xmm1" & ASCII.LF & ASCII.HT &
        "vpor %%xmm0, %%xmm5, %%xmm5" & ASCII.LF & ASCII.HT &
        "vpor %%xmm1, %%xmm6, %%xmm6" & ASCII.LF & ASCII.HT &
        "vpor %%xmm2, %%xmm6, %%xmm6" & ASCII.LF & ASCII.HT &
        "vmovdqa (%8), %%xmm3" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x10, %%xmm3, %%xmm5, %%xmm0" & ASCII.LF & ASCII.HT &
        "vpshufd $0x4e, %%xmm5, %%xmm5" & ASCII.LF & ASCII.HT &
        "vpxor %%xmm0, %%xmm5, %%xmm5" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x10, %%xmm3, %%xmm5, %%xmm0" & ASCII.LF & ASCII.HT &
        "vpshufd $0x4e, %%xmm5, %%xmm5" & ASCII.LF & ASCII.HT &
        "vpxor %%xmm0, %%xmm5, %%xmm5" & ASCII.LF & ASCII.HT &
        "vpxor %%xmm5, %%xmm6, %%xmm6" & ASCII.LF & ASCII.HT &
        "vpshufb %%xmm15, %%xmm6, %%xmm6" & ASCII.LF & ASCII.HT &
        "vmovdqu %%xmm6, (%3)" & ASCII.LF & ASCII.HT &
        "vzeroupper",
        Inputs => (System.Address'Asm_Input ("r", CB'Address),
                   System.Address'Asm_Input ("r", Pre_RK'Address),
                   System.Address'Asm_Input ("r", Buf'Address),
                   System.Address'Asm_Input ("r", S'Address),
                   System.Address'Asm_Input ("r", H_Powers'Address),
                   System.Address'Asm_Input ("r", Gen_Bswap_Mask'Address),
                   System.Address'Asm_Input ("r", Gen_Reverse_Ctr_Mask'Address),
                   System.Address'Asm_Input ("r", Gen_Ctr_Steps'Address),
                   System.Address'Asm_Input ("r", Gen_Reduction_Poly'Address)),
        Clobber => "xmm0,xmm1,xmm2,xmm3,xmm4,xmm5,xmm6,xmm7,xmm8,xmm9,xmm10,xmm11,xmm12,xmm13,xmm15,memory",
        Volatile => True);
   end Decrypt_GCM_Stripe_16_256;
   --  END GENERATED avx512 decrypt 256

   --  BEGIN GENERATED avx512 decrypt32 128
   --  Decrypt one stripe in place: GHASH the ciphertext into S,
   --  interleaved with AES-CTR from CB; CB advances by the stripe.
   procedure Decrypt_GCM_Stripe_32_128
     (Buf      : in out Byte_Seq;
      S        : in out Bytes_16;
      CB       : in out Bytes_16;
      Pre_RK   : in     AES_NI.Pre_Swapped_RKs_128;
      H_Powers : in     Pre_H_Powers_32)
   is
   begin
      Asm
       ("vbroadcasti32x4 (%0), %%zmm9" & ASCII.LF & ASCII.HT &
        "vmovdqa64 (%6), %%zmm10" & ASCII.LF & ASCII.HT &
        "vpshufb %%zmm10, %%zmm9, %%zmm9" & ASCII.LF & ASCII.HT &
        "vpaddd (%7), %%zmm9, %%zmm0" & ASCII.LF & ASCII.HT &
        "vpshufb %%zmm10, %%zmm0, %%zmm0" & ASCII.LF & ASCII.HT &
        "vpaddd 64(%7), %%zmm9, %%zmm1" & ASCII.LF & ASCII.HT &
        "vpshufb %%zmm10, %%zmm1, %%zmm1" & ASCII.LF & ASCII.HT &
        "vpaddd 128(%7), %%zmm9, %%zmm2" & ASCII.LF & ASCII.HT &
        "vpshufb %%zmm10, %%zmm2, %%zmm2" & ASCII.LF & ASCII.HT &
        "vpaddd 192(%7), %%zmm9, %%zmm3" & ASCII.LF & ASCII.HT &
        "vpshufb %%zmm10, %%zmm3, %%zmm3" & ASCII.LF & ASCII.HT &
        "vpaddd 256(%7), %%zmm9, %%zmm4" & ASCII.LF & ASCII.HT &
        "vpshufb %%zmm10, %%zmm4, %%zmm4" & ASCII.LF & ASCII.HT &
        "vpaddd 320(%7), %%zmm9, %%zmm5" & ASCII.LF & ASCII.HT &
        "vpshufb %%zmm10, %%zmm5, %%zmm5" & ASCII.LF & ASCII.HT &
        "vpaddd 384(%7), %%zmm9, %%zmm6" & ASCII.LF & ASCII.HT &
        "vpshufb %%zmm10, %%zmm6, %%zmm6" & ASCII.LF & ASCII.HT &
        "vpaddd 448(%7), %%zmm9, %%zmm7" & ASCII.LF & ASCII.HT &
        "vpshufb %%zmm10, %%zmm7, %%zmm7" & ASCII.LF & ASCII.HT &
        "vpaddd 512(%7), %%xmm9, %%xmm11" & ASCII.LF & ASCII.HT &
        "vpshufb %%xmm10, %%xmm11, %%xmm11" & ASCII.LF & ASCII.HT &
        "vmovdqu %%xmm11, (%0)" & ASCII.LF & ASCII.HT &
        "vbroadcasti32x4 (%1), %%zmm8" & ASCII.LF & ASCII.HT &
        "vpxorq %%zmm8, %%zmm0, %%zmm0" & ASCII.LF & ASCII.HT &
        "vpxorq %%zmm8, %%zmm1, %%zmm1" & ASCII.LF & ASCII.HT &
        "vpxorq %%zmm8, %%zmm2, %%zmm2" & ASCII.LF & ASCII.HT &
        "vpxorq %%zmm8, %%zmm3, %%zmm3" & ASCII.LF & ASCII.HT &
        "vpxorq %%zmm8, %%zmm4, %%zmm4" & ASCII.LF & ASCII.HT &
        "vpxorq %%zmm8, %%zmm5, %%zmm5" & ASCII.LF & ASCII.HT &
        "vpxorq %%zmm8, %%zmm6, %%zmm6" & ASCII.LF & ASCII.HT &
        "vpxorq %%zmm8, %%zmm7, %%zmm7" & ASCII.LF & ASCII.HT &
        "vbroadcasti32x4 16(%1), %%zmm8" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm0, %%zmm0" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm1, %%zmm1" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm2, %%zmm2" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm3, %%zmm3" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm4, %%zmm4" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm5, %%zmm5" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm6, %%zmm6" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm7, %%zmm7" & ASCII.LF & ASCII.HT &
        "vmovdqa64 (%5), %%zmm15" & ASCII.LF & ASCII.HT &
        "vmovdqu64 (%2), %%zmm12" & ASCII.LF & ASCII.HT &
        "vpshufb %%zmm15, %%zmm12, %%zmm12" & ASCII.LF & ASCII.HT &
        "vmovdqu (%3), %%xmm14" & ASCII.LF & ASCII.HT &
        "vpshufb %%xmm15, %%xmm14, %%xmm14" & ASCII.LF & ASCII.HT &
        "vpxorq %%zmm14, %%zmm12, %%zmm12" & ASCII.LF & ASCII.HT &
        "vmovdqu64 (%4), %%zmm13" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x00, %%zmm13, %%zmm12, %%zmm9" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x11, %%zmm13, %%zmm12, %%zmm10" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x10, %%zmm13, %%zmm12, %%zmm11" & ASCII.LF & ASCII.HT &
        "vbroadcasti32x4 32(%1), %%zmm8" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm0, %%zmm0" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm1, %%zmm1" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm2, %%zmm2" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm3, %%zmm3" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm4, %%zmm4" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm5, %%zmm5" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm6, %%zmm6" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm7, %%zmm7" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x01, %%zmm13, %%zmm12, %%zmm12" & ASCII.LF & ASCII.HT &
        "vpxorq %%zmm12, %%zmm11, %%zmm11" & ASCII.LF & ASCII.HT &
        "vmovdqu64 64(%2), %%zmm12" & ASCII.LF & ASCII.HT &
        "vpshufb %%zmm15, %%zmm12, %%zmm12" & ASCII.LF & ASCII.HT &
        "vmovdqu64 64(%4), %%zmm13" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x00, %%zmm13, %%zmm12, %%zmm14" & ASCII.LF & ASCII.HT &
        "vpxorq %%zmm14, %%zmm9, %%zmm9" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x11, %%zmm13, %%zmm12, %%zmm14" & ASCII.LF & ASCII.HT &
        "vpxorq %%zmm14, %%zmm10, %%zmm10" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x10, %%zmm13, %%zmm12, %%zmm14" & ASCII.LF & ASCII.HT &
        "vbroadcasti32x4 48(%1), %%zmm8" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm0, %%zmm0" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm1, %%zmm1" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm2, %%zmm2" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm3, %%zmm3" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm4, %%zmm4" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm5, %%zmm5" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm6, %%zmm6" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm7, %%zmm7" & ASCII.LF & ASCII.HT &
        "vpxorq %%zmm14, %%zmm11, %%zmm11" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x01, %%zmm13, %%zmm12, %%zmm12" & ASCII.LF & ASCII.HT &
        "vpxorq %%zmm12, %%zmm11, %%zmm11" & ASCII.LF & ASCII.HT &
        "vmovdqu64 128(%2), %%zmm12" & ASCII.LF & ASCII.HT &
        "vpshufb %%zmm15, %%zmm12, %%zmm12" & ASCII.LF & ASCII.HT &
        "vmovdqu64 128(%4), %%zmm13" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x00, %%zmm13, %%zmm12, %%zmm14" & ASCII.LF & ASCII.HT &
        "vpxorq %%zmm14, %%zmm9, %%zmm9" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x11, %%zmm13, %%zmm12, %%zmm14" & ASCII.LF & ASCII.HT &
        "vpxorq %%zmm14, %%zmm10, %%zmm10" & ASCII.LF & ASCII.HT &
        "vbroadcasti32x4 64(%1), %%zmm8" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm0, %%zmm0" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm1, %%zmm1" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm2, %%zmm2" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm3, %%zmm3" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm4, %%zmm4" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm5, %%zmm5" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm6, %%zmm6" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm7, %%zmm7" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x10, %%zmm13, %%zmm12, %%zmm14" & ASCII.LF & ASCII.HT &
        "vpxorq %%zmm14, %%zmm11, %%zmm11" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x01, %%zmm13, %%zmm12, %%zmm12" & ASCII.LF & ASCII.HT &
        "vpxorq %%zmm12, %%zmm11, %%zmm11" & ASCII.LF & ASCII.HT &
        "vmovdqu64 192(%2), %%zmm12" & ASCII.LF & ASCII.HT &
        "vpshufb %%zmm15, %%zmm12, %%zmm12" & ASCII.LF & ASCII.HT &
        "vmovdqu64 192(%4), %%zmm13" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x00, %%zmm13, %%zmm12, %%zmm14" & ASCII.LF & ASCII.HT &
        "vpxorq %%zmm14, %%zmm9, %%zmm9" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x11, %%zmm13, %%zmm12, %%zmm14" & ASCII.LF & ASCII.HT &
        "vbroadcasti32x4 80(%1), %%zmm8" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm0, %%zmm0" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm1, %%zmm1" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm2, %%zmm2" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm3, %%zmm3" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm4, %%zmm4" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm5, %%zmm5" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm6, %%zmm6" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm7, %%zmm7" & ASCII.LF & ASCII.HT &
        "vpxorq %%zmm14, %%zmm10, %%zmm10" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x10, %%zmm13, %%zmm12, %%zmm14" & ASCII.LF & ASCII.HT &
        "vpxorq %%zmm14, %%zmm11, %%zmm11" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x01, %%zmm13, %%zmm12, %%zmm12" & ASCII.LF & ASCII.HT &
        "vpxorq %%zmm12, %%zmm11, %%zmm11" & ASCII.LF & ASCII.HT &
        "vmovdqu64 256(%2), %%zmm12" & ASCII.LF & ASCII.HT &
        "vpshufb %%zmm15, %%zmm12, %%zmm12" & ASCII.LF & ASCII.HT &
        "vmovdqu64 256(%4), %%zmm13" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x00, %%zmm13, %%zmm12, %%zmm14" & ASCII.LF & ASCII.HT &
        "vpxorq %%zmm14, %%zmm9, %%zmm9" & ASCII.LF & ASCII.HT &
        "vbroadcasti32x4 96(%1), %%zmm8" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm0, %%zmm0" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm1, %%zmm1" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm2, %%zmm2" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm3, %%zmm3" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm4, %%zmm4" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm5, %%zmm5" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm6, %%zmm6" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm7, %%zmm7" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x11, %%zmm13, %%zmm12, %%zmm14" & ASCII.LF & ASCII.HT &
        "vpxorq %%zmm14, %%zmm10, %%zmm10" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x10, %%zmm13, %%zmm12, %%zmm14" & ASCII.LF & ASCII.HT &
        "vpxorq %%zmm14, %%zmm11, %%zmm11" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x01, %%zmm13, %%zmm12, %%zmm12" & ASCII.LF & ASCII.HT &
        "vpxorq %%zmm12, %%zmm11, %%zmm11" & ASCII.LF & ASCII.HT &
        "vmovdqu64 320(%2), %%zmm12" & ASCII.LF & ASCII.HT &
        "vpshufb %%zmm15, %%zmm12, %%zmm12" & ASCII.LF & ASCII.HT &
        "vmovdqu64 320(%4), %%zmm13" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x00, %%zmm13, %%zmm12, %%zmm14" & ASCII.LF & ASCII.HT &
        "vbroadcasti32x4 112(%1), %%zmm8" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm0, %%zmm0" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm1, %%zmm1" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm2, %%zmm2" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm3, %%zmm3" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm4, %%zmm4" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm5, %%zmm5" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm6, %%zmm6" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm7, %%zmm7" & ASCII.LF & ASCII.HT &
        "vpxorq %%zmm14, %%zmm9, %%zmm9" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x11, %%zmm13, %%zmm12, %%zmm14" & ASCII.LF & ASCII.HT &
        "vpxorq %%zmm14, %%zmm10, %%zmm10" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x10, %%zmm13, %%zmm12, %%zmm14" & ASCII.LF & ASCII.HT &
        "vpxorq %%zmm14, %%zmm11, %%zmm11" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x01, %%zmm13, %%zmm12, %%zmm12" & ASCII.LF & ASCII.HT &
        "vpxorq %%zmm12, %%zmm11, %%zmm11" & ASCII.LF & ASCII.HT &
        "vmovdqu64 384(%2), %%zmm12" & ASCII.LF & ASCII.HT &
        "vpshufb %%zmm15, %%zmm12, %%zmm12" & ASCII.LF & ASCII.HT &
        "vmovdqu64 384(%4), %%zmm13" & ASCII.LF & ASCII.HT &
        "vbroadcasti32x4 128(%1), %%zmm8" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm0, %%zmm0" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm1, %%zmm1" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm2, %%zmm2" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm3, %%zmm3" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm4, %%zmm4" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm5, %%zmm5" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm6, %%zmm6" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm7, %%zmm7" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x00, %%zmm13, %%zmm12, %%zmm14" & ASCII.LF & ASCII.HT &
        "vpxorq %%zmm14, %%zmm9, %%zmm9" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x11, %%zmm13, %%zmm12, %%zmm14" & ASCII.LF & ASCII.HT &
        "vpxorq %%zmm14, %%zmm10, %%zmm10" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x10, %%zmm13, %%zmm12, %%zmm14" & ASCII.LF & ASCII.HT &
        "vpxorq %%zmm14, %%zmm11, %%zmm11" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x01, %%zmm13, %%zmm12, %%zmm12" & ASCII.LF & ASCII.HT &
        "vpxorq %%zmm12, %%zmm11, %%zmm11" & ASCII.LF & ASCII.HT &
        "vmovdqu64 448(%2), %%zmm12" & ASCII.LF & ASCII.HT &
        "vpshufb %%zmm15, %%zmm12, %%zmm12" & ASCII.LF & ASCII.HT &
        "vbroadcasti32x4 144(%1), %%zmm8" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm0, %%zmm0" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm1, %%zmm1" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm2, %%zmm2" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm3, %%zmm3" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm4, %%zmm4" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm5, %%zmm5" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm6, %%zmm6" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm7, %%zmm7" & ASCII.LF & ASCII.HT &
        "vmovdqu64 448(%4), %%zmm13" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x00, %%zmm13, %%zmm12, %%zmm14" & ASCII.LF & ASCII.HT &
        "vpxorq %%zmm14, %%zmm9, %%zmm9" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x11, %%zmm13, %%zmm12, %%zmm14" & ASCII.LF & ASCII.HT &
        "vpxorq %%zmm14, %%zmm10, %%zmm10" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x10, %%zmm13, %%zmm12, %%zmm14" & ASCII.LF & ASCII.HT &
        "vpxorq %%zmm14, %%zmm11, %%zmm11" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x01, %%zmm13, %%zmm12, %%zmm12" & ASCII.LF & ASCII.HT &
        "vpxorq %%zmm12, %%zmm11, %%zmm11" & ASCII.LF & ASCII.HT &
        "vbroadcasti32x4 160(%1), %%zmm8" & ASCII.LF & ASCII.HT &
        "vaesenclast %%zmm8, %%zmm0, %%zmm0" & ASCII.LF & ASCII.HT &
        "vaesenclast %%zmm8, %%zmm1, %%zmm1" & ASCII.LF & ASCII.HT &
        "vaesenclast %%zmm8, %%zmm2, %%zmm2" & ASCII.LF & ASCII.HT &
        "vaesenclast %%zmm8, %%zmm3, %%zmm3" & ASCII.LF & ASCII.HT &
        "vaesenclast %%zmm8, %%zmm4, %%zmm4" & ASCII.LF & ASCII.HT &
        "vaesenclast %%zmm8, %%zmm5, %%zmm5" & ASCII.LF & ASCII.HT &
        "vaesenclast %%zmm8, %%zmm6, %%zmm6" & ASCII.LF & ASCII.HT &
        "vaesenclast %%zmm8, %%zmm7, %%zmm7" & ASCII.LF & ASCII.HT &
        "vpxorq (%2), %%zmm0, %%zmm0" & ASCII.LF & ASCII.HT &
        "vmovdqu64 %%zmm0, (%2)" & ASCII.LF & ASCII.HT &
        "vpxorq 64(%2), %%zmm1, %%zmm1" & ASCII.LF & ASCII.HT &
        "vmovdqu64 %%zmm1, 64(%2)" & ASCII.LF & ASCII.HT &
        "vpxorq 128(%2), %%zmm2, %%zmm2" & ASCII.LF & ASCII.HT &
        "vmovdqu64 %%zmm2, 128(%2)" & ASCII.LF & ASCII.HT &
        "vpxorq 192(%2), %%zmm3, %%zmm3" & ASCII.LF & ASCII.HT &
        "vmovdqu64 %%zmm3, 192(%2)" & ASCII.LF & ASCII.HT &
        "vpxorq 256(%2), %%zmm4, %%zmm4" & ASCII.LF & ASCII.HT &
        "vmovdqu64 %%zmm4, 256(%2)" & ASCII.LF & ASCII.HT &
        "vpxorq 320(%2), %%zmm5, %%zmm5" & ASCII.LF & ASCII.HT &
        "vmovdqu64 %%zmm5, 320(%2)" & ASCII.LF & ASCII.HT &
        "vpxorq 384(%2), %%zmm6, %%zmm6" & ASCII.LF & ASCII.HT &
        "vmovdqu64 %%zmm6, 384(%2)" & ASCII.LF & ASCII.HT &
        "vpxorq 448(%2), %%zmm7, %%zmm7" & ASCII.LF & ASCII.HT &
        "vmovdqu64 %%zmm7, 448(%2)" & ASCII.LF & ASCII.HT &
        "vpslldq $8, %%zmm11, %%zmm14" & ASCII.LF & ASCII.HT &
        "vpsrldq $8, %%zmm11, %%zmm11" & ASCII.LF & ASCII.HT &
        "vpxorq %%zmm14, %%zmm9, %%zmm9" & ASCII.LF & ASCII.HT &
        "vpxorq %%zmm11, %%zmm10, %%zmm10" & ASCII.LF & ASCII.HT &
        "vextracti64x4 $1, %%zmm9, %%ymm14" & ASCII.LF & ASCII.HT &
        "vpxor %%ymm14, %%ymm9, %%ymm9" & ASCII.LF & ASCII.HT &
        "vextracti64x4 $1, %%zmm10, %%ymm14" & ASCII.LF & ASCII.HT &
        "vpxor %%ymm14, %%ymm10, %%ymm10" & ASCII.LF & ASCII.HT &
        "vextracti128 $1, %%ymm9, %%xmm14" & ASCII.LF & ASCII.HT &
        "vpxor %%xmm14, %%xmm9, %%xmm9" & ASCII.LF & ASCII.HT &
        "vextracti128 $1, %%ymm10, %%xmm14" & ASCII.LF & ASCII.HT &
        "vpxor %%xmm14, %%xmm10, %%xmm10" & ASCII.LF & ASCII.HT &
        "vpsrld $31, %%xmm9, %%xmm0" & ASCII.LF & ASCII.HT &
        "vpsrld $31, %%xmm10, %%xmm1" & ASCII.LF & ASCII.HT &
        "vpslld $1, %%xmm9, %%xmm9" & ASCII.LF & ASCII.HT &
        "vpslld $1, %%xmm10, %%xmm10" & ASCII.LF & ASCII.HT &
        "vpsrldq $12, %%xmm0, %%xmm2" & ASCII.LF & ASCII.HT &
        "vpslldq $4, %%xmm0, %%xmm0" & ASCII.LF & ASCII.HT &
        "vpslldq $4, %%xmm1, %%xmm1" & ASCII.LF & ASCII.HT &
        "vpor %%xmm0, %%xmm9, %%xmm9" & ASCII.LF & ASCII.HT &
        "vpor %%xmm1, %%xmm10, %%xmm10" & ASCII.LF & ASCII.HT &
        "vpor %%xmm2, %%xmm10, %%xmm10" & ASCII.LF & ASCII.HT &
        "vmovdqa (%8), %%xmm3" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x10, %%xmm3, %%xmm9, %%xmm0" & ASCII.LF & ASCII.HT &
        "vpshufd $0x4e, %%xmm9, %%xmm9" & ASCII.LF & ASCII.HT &
        "vpxor %%xmm0, %%xmm9, %%xmm9" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x10, %%xmm3, %%xmm9, %%xmm0" & ASCII.LF & ASCII.HT &
        "vpshufd $0x4e, %%xmm9, %%xmm9" & ASCII.LF & ASCII.HT &
        "vpxor %%xmm0, %%xmm9, %%xmm9" & ASCII.LF & ASCII.HT &
        "vpxor %%xmm9, %%xmm10, %%xmm10" & ASCII.LF & ASCII.HT &
        "vpshufb %%xmm15, %%xmm10, %%xmm10" & ASCII.LF & ASCII.HT &
        "vmovdqu %%xmm10, (%3)" & ASCII.LF & ASCII.HT &
        "vzeroupper",
        Inputs => (System.Address'Asm_Input ("r", CB'Address),
                   System.Address'Asm_Input ("r", Pre_RK'Address),
                   System.Address'Asm_Input ("r", Buf'Address),
                   System.Address'Asm_Input ("r", S'Address),
                   System.Address'Asm_Input ("r", H_Powers'Address),
                   System.Address'Asm_Input ("r", Gen_Bswap_Mask'Address),
                   System.Address'Asm_Input ("r", Gen_Reverse_Ctr_Mask'Address),
                   System.Address'Asm_Input ("r", Gen_Ctr_Steps'Address),
                   System.Address'Asm_Input ("r", Gen_Reduction_Poly'Address)),
        Clobber => "xmm0,xmm1,xmm2,xmm3,xmm4,xmm5,xmm6,xmm7,xmm8,xmm9,xmm10,xmm11,xmm12,xmm13,xmm14,xmm15,memory",
        Volatile => True);
   end Decrypt_GCM_Stripe_32_128;
   --  END GENERATED avx512 decrypt32 128

   --  BEGIN GENERATED avx512 decrypt32 256
   --  Decrypt one stripe in place: GHASH the ciphertext into S,
   --  interleaved with AES-CTR from CB; CB advances by the stripe.
   procedure Decrypt_GCM_Stripe_32_256
     (Buf      : in out Byte_Seq;
      S        : in out Bytes_16;
      CB       : in out Bytes_16;
      Pre_RK   : in     AES_NI.Pre_Swapped_RKs_256;
      H_Powers : in     Pre_H_Powers_32)
   is
   begin
      Asm
       ("vbroadcasti32x4 (%0), %%zmm9" & ASCII.LF & ASCII.HT &
        "vmovdqa64 (%6), %%zmm10" & ASCII.LF & ASCII.HT &
        "vpshufb %%zmm10, %%zmm9, %%zmm9" & ASCII.LF & ASCII.HT &
        "vpaddd (%7), %%zmm9, %%zmm0" & ASCII.LF & ASCII.HT &
        "vpshufb %%zmm10, %%zmm0, %%zmm0" & ASCII.LF & ASCII.HT &
        "vpaddd 64(%7), %%zmm9, %%zmm1" & ASCII.LF & ASCII.HT &
        "vpshufb %%zmm10, %%zmm1, %%zmm1" & ASCII.LF & ASCII.HT &
        "vpaddd 128(%7), %%zmm9, %%zmm2" & ASCII.LF & ASCII.HT &
        "vpshufb %%zmm10, %%zmm2, %%zmm2" & ASCII.LF & ASCII.HT &
        "vpaddd 192(%7), %%zmm9, %%zmm3" & ASCII.LF & ASCII.HT &
        "vpshufb %%zmm10, %%zmm3, %%zmm3" & ASCII.LF & ASCII.HT &
        "vpaddd 256(%7), %%zmm9, %%zmm4" & ASCII.LF & ASCII.HT &
        "vpshufb %%zmm10, %%zmm4, %%zmm4" & ASCII.LF & ASCII.HT &
        "vpaddd 320(%7), %%zmm9, %%zmm5" & ASCII.LF & ASCII.HT &
        "vpshufb %%zmm10, %%zmm5, %%zmm5" & ASCII.LF & ASCII.HT &
        "vpaddd 384(%7), %%zmm9, %%zmm6" & ASCII.LF & ASCII.HT &
        "vpshufb %%zmm10, %%zmm6, %%zmm6" & ASCII.LF & ASCII.HT &
        "vpaddd 448(%7), %%zmm9, %%zmm7" & ASCII.LF & ASCII.HT &
        "vpshufb %%zmm10, %%zmm7, %%zmm7" & ASCII.LF & ASCII.HT &
        "vpaddd 512(%7), %%xmm9, %%xmm11" & ASCII.LF & ASCII.HT &
        "vpshufb %%xmm10, %%xmm11, %%xmm11" & ASCII.LF & ASCII.HT &
        "vmovdqu %%xmm11, (%0)" & ASCII.LF & ASCII.HT &
        "vbroadcasti32x4 (%1), %%zmm8" & ASCII.LF & ASCII.HT &
        "vpxorq %%zmm8, %%zmm0, %%zmm0" & ASCII.LF & ASCII.HT &
        "vpxorq %%zmm8, %%zmm1, %%zmm1" & ASCII.LF & ASCII.HT &
        "vpxorq %%zmm8, %%zmm2, %%zmm2" & ASCII.LF & ASCII.HT &
        "vpxorq %%zmm8, %%zmm3, %%zmm3" & ASCII.LF & ASCII.HT &
        "vpxorq %%zmm8, %%zmm4, %%zmm4" & ASCII.LF & ASCII.HT &
        "vpxorq %%zmm8, %%zmm5, %%zmm5" & ASCII.LF & ASCII.HT &
        "vpxorq %%zmm8, %%zmm6, %%zmm6" & ASCII.LF & ASCII.HT &
        "vpxorq %%zmm8, %%zmm7, %%zmm7" & ASCII.LF & ASCII.HT &
        "vbroadcasti32x4 16(%1), %%zmm8" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm0, %%zmm0" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm1, %%zmm1" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm2, %%zmm2" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm3, %%zmm3" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm4, %%zmm4" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm5, %%zmm5" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm6, %%zmm6" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm7, %%zmm7" & ASCII.LF & ASCII.HT &
        "vmovdqa64 (%5), %%zmm15" & ASCII.LF & ASCII.HT &
        "vmovdqu64 (%2), %%zmm12" & ASCII.LF & ASCII.HT &
        "vpshufb %%zmm15, %%zmm12, %%zmm12" & ASCII.LF & ASCII.HT &
        "vmovdqu (%3), %%xmm14" & ASCII.LF & ASCII.HT &
        "vpshufb %%xmm15, %%xmm14, %%xmm14" & ASCII.LF & ASCII.HT &
        "vpxorq %%zmm14, %%zmm12, %%zmm12" & ASCII.LF & ASCII.HT &
        "vmovdqu64 (%4), %%zmm13" & ASCII.LF & ASCII.HT &
        "vbroadcasti32x4 32(%1), %%zmm8" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm0, %%zmm0" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm1, %%zmm1" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm2, %%zmm2" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm3, %%zmm3" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm4, %%zmm4" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm5, %%zmm5" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm6, %%zmm6" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm7, %%zmm7" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x00, %%zmm13, %%zmm12, %%zmm9" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x11, %%zmm13, %%zmm12, %%zmm10" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x10, %%zmm13, %%zmm12, %%zmm11" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x01, %%zmm13, %%zmm12, %%zmm12" & ASCII.LF & ASCII.HT &
        "vpxorq %%zmm12, %%zmm11, %%zmm11" & ASCII.LF & ASCII.HT &
        "vmovdqu64 64(%2), %%zmm12" & ASCII.LF & ASCII.HT &
        "vpshufb %%zmm15, %%zmm12, %%zmm12" & ASCII.LF & ASCII.HT &
        "vbroadcasti32x4 48(%1), %%zmm8" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm0, %%zmm0" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm1, %%zmm1" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm2, %%zmm2" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm3, %%zmm3" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm4, %%zmm4" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm5, %%zmm5" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm6, %%zmm6" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm7, %%zmm7" & ASCII.LF & ASCII.HT &
        "vmovdqu64 64(%4), %%zmm13" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x00, %%zmm13, %%zmm12, %%zmm14" & ASCII.LF & ASCII.HT &
        "vpxorq %%zmm14, %%zmm9, %%zmm9" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x11, %%zmm13, %%zmm12, %%zmm14" & ASCII.LF & ASCII.HT &
        "vpxorq %%zmm14, %%zmm10, %%zmm10" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x10, %%zmm13, %%zmm12, %%zmm14" & ASCII.LF & ASCII.HT &
        "vpxorq %%zmm14, %%zmm11, %%zmm11" & ASCII.LF & ASCII.HT &
        "vbroadcasti32x4 64(%1), %%zmm8" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm0, %%zmm0" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm1, %%zmm1" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm2, %%zmm2" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm3, %%zmm3" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm4, %%zmm4" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm5, %%zmm5" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm6, %%zmm6" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm7, %%zmm7" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x01, %%zmm13, %%zmm12, %%zmm12" & ASCII.LF & ASCII.HT &
        "vpxorq %%zmm12, %%zmm11, %%zmm11" & ASCII.LF & ASCII.HT &
        "vmovdqu64 128(%2), %%zmm12" & ASCII.LF & ASCII.HT &
        "vpshufb %%zmm15, %%zmm12, %%zmm12" & ASCII.LF & ASCII.HT &
        "vmovdqu64 128(%4), %%zmm13" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x00, %%zmm13, %%zmm12, %%zmm14" & ASCII.LF & ASCII.HT &
        "vpxorq %%zmm14, %%zmm9, %%zmm9" & ASCII.LF & ASCII.HT &
        "vbroadcasti32x4 80(%1), %%zmm8" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm0, %%zmm0" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm1, %%zmm1" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm2, %%zmm2" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm3, %%zmm3" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm4, %%zmm4" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm5, %%zmm5" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm6, %%zmm6" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm7, %%zmm7" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x11, %%zmm13, %%zmm12, %%zmm14" & ASCII.LF & ASCII.HT &
        "vpxorq %%zmm14, %%zmm10, %%zmm10" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x10, %%zmm13, %%zmm12, %%zmm14" & ASCII.LF & ASCII.HT &
        "vpxorq %%zmm14, %%zmm11, %%zmm11" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x01, %%zmm13, %%zmm12, %%zmm12" & ASCII.LF & ASCII.HT &
        "vpxorq %%zmm12, %%zmm11, %%zmm11" & ASCII.LF & ASCII.HT &
        "vmovdqu64 192(%2), %%zmm12" & ASCII.LF & ASCII.HT &
        "vbroadcasti32x4 96(%1), %%zmm8" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm0, %%zmm0" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm1, %%zmm1" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm2, %%zmm2" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm3, %%zmm3" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm4, %%zmm4" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm5, %%zmm5" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm6, %%zmm6" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm7, %%zmm7" & ASCII.LF & ASCII.HT &
        "vpshufb %%zmm15, %%zmm12, %%zmm12" & ASCII.LF & ASCII.HT &
        "vmovdqu64 192(%4), %%zmm13" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x00, %%zmm13, %%zmm12, %%zmm14" & ASCII.LF & ASCII.HT &
        "vpxorq %%zmm14, %%zmm9, %%zmm9" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x11, %%zmm13, %%zmm12, %%zmm14" & ASCII.LF & ASCII.HT &
        "vpxorq %%zmm14, %%zmm10, %%zmm10" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x10, %%zmm13, %%zmm12, %%zmm14" & ASCII.LF & ASCII.HT &
        "vbroadcasti32x4 112(%1), %%zmm8" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm0, %%zmm0" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm1, %%zmm1" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm2, %%zmm2" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm3, %%zmm3" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm4, %%zmm4" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm5, %%zmm5" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm6, %%zmm6" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm7, %%zmm7" & ASCII.LF & ASCII.HT &
        "vpxorq %%zmm14, %%zmm11, %%zmm11" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x01, %%zmm13, %%zmm12, %%zmm12" & ASCII.LF & ASCII.HT &
        "vpxorq %%zmm12, %%zmm11, %%zmm11" & ASCII.LF & ASCII.HT &
        "vmovdqu64 256(%2), %%zmm12" & ASCII.LF & ASCII.HT &
        "vpshufb %%zmm15, %%zmm12, %%zmm12" & ASCII.LF & ASCII.HT &
        "vmovdqu64 256(%4), %%zmm13" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x00, %%zmm13, %%zmm12, %%zmm14" & ASCII.LF & ASCII.HT &
        "vbroadcasti32x4 128(%1), %%zmm8" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm0, %%zmm0" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm1, %%zmm1" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm2, %%zmm2" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm3, %%zmm3" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm4, %%zmm4" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm5, %%zmm5" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm6, %%zmm6" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm7, %%zmm7" & ASCII.LF & ASCII.HT &
        "vpxorq %%zmm14, %%zmm9, %%zmm9" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x11, %%zmm13, %%zmm12, %%zmm14" & ASCII.LF & ASCII.HT &
        "vpxorq %%zmm14, %%zmm10, %%zmm10" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x10, %%zmm13, %%zmm12, %%zmm14" & ASCII.LF & ASCII.HT &
        "vpxorq %%zmm14, %%zmm11, %%zmm11" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x01, %%zmm13, %%zmm12, %%zmm12" & ASCII.LF & ASCII.HT &
        "vpxorq %%zmm12, %%zmm11, %%zmm11" & ASCII.LF & ASCII.HT &
        "vbroadcasti32x4 144(%1), %%zmm8" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm0, %%zmm0" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm1, %%zmm1" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm2, %%zmm2" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm3, %%zmm3" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm4, %%zmm4" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm5, %%zmm5" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm6, %%zmm6" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm7, %%zmm7" & ASCII.LF & ASCII.HT &
        "vmovdqu64 320(%2), %%zmm12" & ASCII.LF & ASCII.HT &
        "vpshufb %%zmm15, %%zmm12, %%zmm12" & ASCII.LF & ASCII.HT &
        "vmovdqu64 320(%4), %%zmm13" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x00, %%zmm13, %%zmm12, %%zmm14" & ASCII.LF & ASCII.HT &
        "vpxorq %%zmm14, %%zmm9, %%zmm9" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x11, %%zmm13, %%zmm12, %%zmm14" & ASCII.LF & ASCII.HT &
        "vpxorq %%zmm14, %%zmm10, %%zmm10" & ASCII.LF & ASCII.HT &
        "vbroadcasti32x4 160(%1), %%zmm8" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm0, %%zmm0" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm1, %%zmm1" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm2, %%zmm2" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm3, %%zmm3" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm4, %%zmm4" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm5, %%zmm5" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm6, %%zmm6" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm7, %%zmm7" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x10, %%zmm13, %%zmm12, %%zmm14" & ASCII.LF & ASCII.HT &
        "vpxorq %%zmm14, %%zmm11, %%zmm11" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x01, %%zmm13, %%zmm12, %%zmm12" & ASCII.LF & ASCII.HT &
        "vpxorq %%zmm12, %%zmm11, %%zmm11" & ASCII.LF & ASCII.HT &
        "vmovdqu64 384(%2), %%zmm12" & ASCII.LF & ASCII.HT &
        "vpshufb %%zmm15, %%zmm12, %%zmm12" & ASCII.LF & ASCII.HT &
        "vmovdqu64 384(%4), %%zmm13" & ASCII.LF & ASCII.HT &
        "vbroadcasti32x4 176(%1), %%zmm8" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm0, %%zmm0" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm1, %%zmm1" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm2, %%zmm2" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm3, %%zmm3" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm4, %%zmm4" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm5, %%zmm5" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm6, %%zmm6" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm7, %%zmm7" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x00, %%zmm13, %%zmm12, %%zmm14" & ASCII.LF & ASCII.HT &
        "vpxorq %%zmm14, %%zmm9, %%zmm9" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x11, %%zmm13, %%zmm12, %%zmm14" & ASCII.LF & ASCII.HT &
        "vpxorq %%zmm14, %%zmm10, %%zmm10" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x10, %%zmm13, %%zmm12, %%zmm14" & ASCII.LF & ASCII.HT &
        "vpxorq %%zmm14, %%zmm11, %%zmm11" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x01, %%zmm13, %%zmm12, %%zmm12" & ASCII.LF & ASCII.HT &
        "vbroadcasti32x4 192(%1), %%zmm8" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm0, %%zmm0" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm1, %%zmm1" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm2, %%zmm2" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm3, %%zmm3" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm4, %%zmm4" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm5, %%zmm5" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm6, %%zmm6" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm7, %%zmm7" & ASCII.LF & ASCII.HT &
        "vpxorq %%zmm12, %%zmm11, %%zmm11" & ASCII.LF & ASCII.HT &
        "vmovdqu64 448(%2), %%zmm12" & ASCII.LF & ASCII.HT &
        "vpshufb %%zmm15, %%zmm12, %%zmm12" & ASCII.LF & ASCII.HT &
        "vmovdqu64 448(%4), %%zmm13" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x00, %%zmm13, %%zmm12, %%zmm14" & ASCII.LF & ASCII.HT &
        "vpxorq %%zmm14, %%zmm9, %%zmm9" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x11, %%zmm13, %%zmm12, %%zmm14" & ASCII.LF & ASCII.HT &
        "vbroadcasti32x4 208(%1), %%zmm8" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm0, %%zmm0" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm1, %%zmm1" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm2, %%zmm2" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm3, %%zmm3" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm4, %%zmm4" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm5, %%zmm5" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm6, %%zmm6" & ASCII.LF & ASCII.HT &
        "vaesenc %%zmm8, %%zmm7, %%zmm7" & ASCII.LF & ASCII.HT &
        "vpxorq %%zmm14, %%zmm10, %%zmm10" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x10, %%zmm13, %%zmm12, %%zmm14" & ASCII.LF & ASCII.HT &
        "vpxorq %%zmm14, %%zmm11, %%zmm11" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x01, %%zmm13, %%zmm12, %%zmm12" & ASCII.LF & ASCII.HT &
        "vpxorq %%zmm12, %%zmm11, %%zmm11" & ASCII.LF & ASCII.HT &
        "vbroadcasti32x4 224(%1), %%zmm8" & ASCII.LF & ASCII.HT &
        "vaesenclast %%zmm8, %%zmm0, %%zmm0" & ASCII.LF & ASCII.HT &
        "vaesenclast %%zmm8, %%zmm1, %%zmm1" & ASCII.LF & ASCII.HT &
        "vaesenclast %%zmm8, %%zmm2, %%zmm2" & ASCII.LF & ASCII.HT &
        "vaesenclast %%zmm8, %%zmm3, %%zmm3" & ASCII.LF & ASCII.HT &
        "vaesenclast %%zmm8, %%zmm4, %%zmm4" & ASCII.LF & ASCII.HT &
        "vaesenclast %%zmm8, %%zmm5, %%zmm5" & ASCII.LF & ASCII.HT &
        "vaesenclast %%zmm8, %%zmm6, %%zmm6" & ASCII.LF & ASCII.HT &
        "vaesenclast %%zmm8, %%zmm7, %%zmm7" & ASCII.LF & ASCII.HT &
        "vpxorq (%2), %%zmm0, %%zmm0" & ASCII.LF & ASCII.HT &
        "vmovdqu64 %%zmm0, (%2)" & ASCII.LF & ASCII.HT &
        "vpxorq 64(%2), %%zmm1, %%zmm1" & ASCII.LF & ASCII.HT &
        "vmovdqu64 %%zmm1, 64(%2)" & ASCII.LF & ASCII.HT &
        "vpxorq 128(%2), %%zmm2, %%zmm2" & ASCII.LF & ASCII.HT &
        "vmovdqu64 %%zmm2, 128(%2)" & ASCII.LF & ASCII.HT &
        "vpxorq 192(%2), %%zmm3, %%zmm3" & ASCII.LF & ASCII.HT &
        "vmovdqu64 %%zmm3, 192(%2)" & ASCII.LF & ASCII.HT &
        "vpxorq 256(%2), %%zmm4, %%zmm4" & ASCII.LF & ASCII.HT &
        "vmovdqu64 %%zmm4, 256(%2)" & ASCII.LF & ASCII.HT &
        "vpxorq 320(%2), %%zmm5, %%zmm5" & ASCII.LF & ASCII.HT &
        "vmovdqu64 %%zmm5, 320(%2)" & ASCII.LF & ASCII.HT &
        "vpxorq 384(%2), %%zmm6, %%zmm6" & ASCII.LF & ASCII.HT &
        "vmovdqu64 %%zmm6, 384(%2)" & ASCII.LF & ASCII.HT &
        "vpxorq 448(%2), %%zmm7, %%zmm7" & ASCII.LF & ASCII.HT &
        "vmovdqu64 %%zmm7, 448(%2)" & ASCII.LF & ASCII.HT &
        "vpslldq $8, %%zmm11, %%zmm14" & ASCII.LF & ASCII.HT &
        "vpsrldq $8, %%zmm11, %%zmm11" & ASCII.LF & ASCII.HT &
        "vpxorq %%zmm14, %%zmm9, %%zmm9" & ASCII.LF & ASCII.HT &
        "vpxorq %%zmm11, %%zmm10, %%zmm10" & ASCII.LF & ASCII.HT &
        "vextracti64x4 $1, %%zmm9, %%ymm14" & ASCII.LF & ASCII.HT &
        "vpxor %%ymm14, %%ymm9, %%ymm9" & ASCII.LF & ASCII.HT &
        "vextracti64x4 $1, %%zmm10, %%ymm14" & ASCII.LF & ASCII.HT &
        "vpxor %%ymm14, %%ymm10, %%ymm10" & ASCII.LF & ASCII.HT &
        "vextracti128 $1, %%ymm9, %%xmm14" & ASCII.LF & ASCII.HT &
        "vpxor %%xmm14, %%xmm9, %%xmm9" & ASCII.LF & ASCII.HT &
        "vextracti128 $1, %%ymm10, %%xmm14" & ASCII.LF & ASCII.HT &
        "vpxor %%xmm14, %%xmm10, %%xmm10" & ASCII.LF & ASCII.HT &
        "vpsrld $31, %%xmm9, %%xmm0" & ASCII.LF & ASCII.HT &
        "vpsrld $31, %%xmm10, %%xmm1" & ASCII.LF & ASCII.HT &
        "vpslld $1, %%xmm9, %%xmm9" & ASCII.LF & ASCII.HT &
        "vpslld $1, %%xmm10, %%xmm10" & ASCII.LF & ASCII.HT &
        "vpsrldq $12, %%xmm0, %%xmm2" & ASCII.LF & ASCII.HT &
        "vpslldq $4, %%xmm0, %%xmm0" & ASCII.LF & ASCII.HT &
        "vpslldq $4, %%xmm1, %%xmm1" & ASCII.LF & ASCII.HT &
        "vpor %%xmm0, %%xmm9, %%xmm9" & ASCII.LF & ASCII.HT &
        "vpor %%xmm1, %%xmm10, %%xmm10" & ASCII.LF & ASCII.HT &
        "vpor %%xmm2, %%xmm10, %%xmm10" & ASCII.LF & ASCII.HT &
        "vmovdqa (%8), %%xmm3" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x10, %%xmm3, %%xmm9, %%xmm0" & ASCII.LF & ASCII.HT &
        "vpshufd $0x4e, %%xmm9, %%xmm9" & ASCII.LF & ASCII.HT &
        "vpxor %%xmm0, %%xmm9, %%xmm9" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x10, %%xmm3, %%xmm9, %%xmm0" & ASCII.LF & ASCII.HT &
        "vpshufd $0x4e, %%xmm9, %%xmm9" & ASCII.LF & ASCII.HT &
        "vpxor %%xmm0, %%xmm9, %%xmm9" & ASCII.LF & ASCII.HT &
        "vpxor %%xmm9, %%xmm10, %%xmm10" & ASCII.LF & ASCII.HT &
        "vpshufb %%xmm15, %%xmm10, %%xmm10" & ASCII.LF & ASCII.HT &
        "vmovdqu %%xmm10, (%3)" & ASCII.LF & ASCII.HT &
        "vzeroupper",
        Inputs => (System.Address'Asm_Input ("r", CB'Address),
                   System.Address'Asm_Input ("r", Pre_RK'Address),
                   System.Address'Asm_Input ("r", Buf'Address),
                   System.Address'Asm_Input ("r", S'Address),
                   System.Address'Asm_Input ("r", H_Powers'Address),
                   System.Address'Asm_Input ("r", Gen_Bswap_Mask'Address),
                   System.Address'Asm_Input ("r", Gen_Reverse_Ctr_Mask'Address),
                   System.Address'Asm_Input ("r", Gen_Ctr_Steps'Address),
                   System.Address'Asm_Input ("r", Gen_Reduction_Poly'Address)),
        Clobber => "xmm0,xmm1,xmm2,xmm3,xmm4,xmm5,xmm6,xmm7,xmm8,xmm9,xmm10,xmm11,xmm12,xmm13,xmm14,xmm15,memory",
        Volatile => True);
   end Decrypt_GCM_Stripe_32_256;
   --  END GENERATED avx512 decrypt32 256

begin
   Has_AVX512_AES_GCM := (not SPARKTLSCrypto.CPU.Portable_Only) and then Detect_AVX512_AES_GCM;
end SPARKTLSCrypto.AES_GCM_AVX512;
