--  VAES + VPCLMULQDQ (256-bit) AES-GCM tier (body).
--  See sparktlscrypto-aes_gcm_avx2.ads.

with System.Machine_Code; use System.Machine_Code;
with Interfaces;          use Interfaces;
with SPARKTLSCrypto.CPU;
pragma Elaborate_All (SPARKTLSCrypto.CPU);
with SPARKTLSCrypto.AES_NI;
pragma Elaborate_All (SPARKTLSCrypto.AES_NI);
with SPARKTLSCrypto.GHASH_NI;
pragma Elaborate_All (SPARKTLSCrypto.GHASH_NI);

package body SPARKTLSCrypto.AES_GCM_AVX2 with
   SPARK_Mode => Off
is

   ----------------------------------------------------------------------------
   --  CPUID detection (run once at elaboration)
   ----------------------------------------------------------------------------
   --  CPU.Has_AVX2 already checks leaf 7 exists, OSXSAVE and that XCR0
   --  enables SSE and AVX (YMM) state, and Portable_Only. Here: leaf 7
   --  ECX bit 9 (VAES) and bit 10 (VPCLMULQDQ), Intel SDM Vol. 2A CPUID
   --  and the Optimization Reference Manual 248966, section 5.1.10
   --  "Detection of VEX-Encoded AES and VPCLMULQDQ".

   function Detect_VAES_VPCLMULQDQ return Boolean is
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
      pragma Unreferenced (EAX, EBX, EDX);
      return (ECX and 16#0000_0200#) /= 0      --  bit 9: VAES
        and then (ECX and 16#0000_0400#) /= 0; --  bit 10: VPCLMULQDQ
   end Detect_VAES_VPCLMULQDQ;

   ----------------------------------------------------------------------------
   --  Generated kernels (tools/generate_gcm_kernels.py)
   ----------------------------------------------------------------------------

   --  BEGIN GENERATED avx2 constants
   --  Constants of the generated kernels. Gen_Bswap_Mask reverses each
   --  16-byte lane (NIST GHASH <-> PCLMULQDQ order); Gen_Reverse_Ctr_Mask
   --  reverses only the big-endian counter word of each lane so PADDD can
   --  add to it; entry k of Gen_Ctr_Steps adds k to that word (inc32 mod
   --  2**32, as Increment_Counter); Gen_Reduction_Poly is the upper half
   --  of the reflected reduction polynomial, 0xC2 << 56.
   Gen_Bswap_Mask : constant array (0 .. 31) of Unsigned_8 :=
     (15,14,13,12, 11,10,9,8, 7,6,5,4, 3,2,1,0,
      15,14,13,12, 11,10,9,8, 7,6,5,4, 3,2,1,0);
   for Gen_Bswap_Mask'Alignment use 32;
   Gen_Reverse_Ctr_Mask : constant array (0 .. 31) of Unsigned_8 :=
     (0,1,2,3, 4,5,6,7, 8,9,10,11, 15,14,13,12,
      0,1,2,3, 4,5,6,7, 8,9,10,11, 15,14,13,12);
   for Gen_Reverse_Ctr_Mask'Alignment use 32;
   Gen_Ctr_Steps : constant array (0 .. 271) of Unsigned_8 :=
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
      0,0,0,0, 0,0,0,0, 0,0,0,0, 16,0,0,0);
   for Gen_Ctr_Steps'Alignment use 64;
   Gen_Reduction_Poly : constant array (0 .. 15) of Unsigned_8 :=
     (0 .. 14 => 0, 15 => 16#C2#);
   for Gen_Reduction_Poly'Alignment use 16;
   --  END GENERATED avx2 constants

   --  BEGIN GENERATED avx2 decrypt 128
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
       ("vbroadcasti128 (%0), %%ymm9" & ASCII.LF & ASCII.HT &
        "vmovdqa (%6), %%ymm10" & ASCII.LF & ASCII.HT &
        "vpshufb %%ymm10, %%ymm9, %%ymm9" & ASCII.LF & ASCII.HT &
        "vpaddd (%7), %%ymm9, %%ymm0" & ASCII.LF & ASCII.HT &
        "vpshufb %%ymm10, %%ymm0, %%ymm0" & ASCII.LF & ASCII.HT &
        "vpaddd 32(%7), %%ymm9, %%ymm1" & ASCII.LF & ASCII.HT &
        "vpshufb %%ymm10, %%ymm1, %%ymm1" & ASCII.LF & ASCII.HT &
        "vpaddd 64(%7), %%ymm9, %%ymm2" & ASCII.LF & ASCII.HT &
        "vpshufb %%ymm10, %%ymm2, %%ymm2" & ASCII.LF & ASCII.HT &
        "vpaddd 96(%7), %%ymm9, %%ymm3" & ASCII.LF & ASCII.HT &
        "vpshufb %%ymm10, %%ymm3, %%ymm3" & ASCII.LF & ASCII.HT &
        "vpaddd 128(%7), %%ymm9, %%ymm4" & ASCII.LF & ASCII.HT &
        "vpshufb %%ymm10, %%ymm4, %%ymm4" & ASCII.LF & ASCII.HT &
        "vpaddd 160(%7), %%ymm9, %%ymm5" & ASCII.LF & ASCII.HT &
        "vpshufb %%ymm10, %%ymm5, %%ymm5" & ASCII.LF & ASCII.HT &
        "vpaddd 192(%7), %%ymm9, %%ymm6" & ASCII.LF & ASCII.HT &
        "vpshufb %%ymm10, %%ymm6, %%ymm6" & ASCII.LF & ASCII.HT &
        "vpaddd 224(%7), %%ymm9, %%ymm7" & ASCII.LF & ASCII.HT &
        "vpshufb %%ymm10, %%ymm7, %%ymm7" & ASCII.LF & ASCII.HT &
        "vpaddd 256(%7), %%xmm9, %%xmm11" & ASCII.LF & ASCII.HT &
        "vpshufb %%xmm10, %%xmm11, %%xmm11" & ASCII.LF & ASCII.HT &
        "vmovdqu %%xmm11, (%0)" & ASCII.LF & ASCII.HT &
        "vbroadcasti128 (%1), %%ymm8" & ASCII.LF & ASCII.HT &
        "vpxor %%ymm8, %%ymm0, %%ymm0" & ASCII.LF & ASCII.HT &
        "vpxor %%ymm8, %%ymm1, %%ymm1" & ASCII.LF & ASCII.HT &
        "vpxor %%ymm8, %%ymm2, %%ymm2" & ASCII.LF & ASCII.HT &
        "vpxor %%ymm8, %%ymm3, %%ymm3" & ASCII.LF & ASCII.HT &
        "vpxor %%ymm8, %%ymm4, %%ymm4" & ASCII.LF & ASCII.HT &
        "vpxor %%ymm8, %%ymm5, %%ymm5" & ASCII.LF & ASCII.HT &
        "vpxor %%ymm8, %%ymm6, %%ymm6" & ASCII.LF & ASCII.HT &
        "vpxor %%ymm8, %%ymm7, %%ymm7" & ASCII.LF & ASCII.HT &
        "vbroadcasti128 16(%1), %%ymm8" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm0, %%ymm0" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm1, %%ymm1" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm2, %%ymm2" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm3, %%ymm3" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm4, %%ymm4" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm5, %%ymm5" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm6, %%ymm6" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm7, %%ymm7" & ASCII.LF & ASCII.HT &
        "vmovdqa (%5), %%ymm15" & ASCII.LF & ASCII.HT &
        "vmovdqu (%2), %%ymm12" & ASCII.LF & ASCII.HT &
        "vpshufb %%ymm15, %%ymm12, %%ymm12" & ASCII.LF & ASCII.HT &
        "vmovdqu (%3), %%xmm14" & ASCII.LF & ASCII.HT &
        "vpshufb %%xmm15, %%xmm14, %%xmm14" & ASCII.LF & ASCII.HT &
        "vpxor %%ymm14, %%ymm12, %%ymm12" & ASCII.LF & ASCII.HT &
        "vmovdqu (%4), %%ymm13" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x00, %%ymm13, %%ymm12, %%ymm9" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x11, %%ymm13, %%ymm12, %%ymm10" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x10, %%ymm13, %%ymm12, %%ymm11" & ASCII.LF & ASCII.HT &
        "vbroadcasti128 32(%1), %%ymm8" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm0, %%ymm0" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm1, %%ymm1" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm2, %%ymm2" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm3, %%ymm3" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm4, %%ymm4" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm5, %%ymm5" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm6, %%ymm6" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm7, %%ymm7" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x01, %%ymm13, %%ymm12, %%ymm12" & ASCII.LF & ASCII.HT &
        "vpxor %%ymm12, %%ymm11, %%ymm11" & ASCII.LF & ASCII.HT &
        "vmovdqu 32(%2), %%ymm12" & ASCII.LF & ASCII.HT &
        "vpshufb %%ymm15, %%ymm12, %%ymm12" & ASCII.LF & ASCII.HT &
        "vmovdqu 32(%4), %%ymm13" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x00, %%ymm13, %%ymm12, %%ymm14" & ASCII.LF & ASCII.HT &
        "vpxor %%ymm14, %%ymm9, %%ymm9" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x11, %%ymm13, %%ymm12, %%ymm14" & ASCII.LF & ASCII.HT &
        "vpxor %%ymm14, %%ymm10, %%ymm10" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x10, %%ymm13, %%ymm12, %%ymm14" & ASCII.LF & ASCII.HT &
        "vbroadcasti128 48(%1), %%ymm8" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm0, %%ymm0" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm1, %%ymm1" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm2, %%ymm2" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm3, %%ymm3" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm4, %%ymm4" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm5, %%ymm5" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm6, %%ymm6" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm7, %%ymm7" & ASCII.LF & ASCII.HT &
        "vpxor %%ymm14, %%ymm11, %%ymm11" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x01, %%ymm13, %%ymm12, %%ymm12" & ASCII.LF & ASCII.HT &
        "vpxor %%ymm12, %%ymm11, %%ymm11" & ASCII.LF & ASCII.HT &
        "vmovdqu 64(%2), %%ymm12" & ASCII.LF & ASCII.HT &
        "vpshufb %%ymm15, %%ymm12, %%ymm12" & ASCII.LF & ASCII.HT &
        "vmovdqu 64(%4), %%ymm13" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x00, %%ymm13, %%ymm12, %%ymm14" & ASCII.LF & ASCII.HT &
        "vpxor %%ymm14, %%ymm9, %%ymm9" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x11, %%ymm13, %%ymm12, %%ymm14" & ASCII.LF & ASCII.HT &
        "vpxor %%ymm14, %%ymm10, %%ymm10" & ASCII.LF & ASCII.HT &
        "vbroadcasti128 64(%1), %%ymm8" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm0, %%ymm0" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm1, %%ymm1" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm2, %%ymm2" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm3, %%ymm3" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm4, %%ymm4" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm5, %%ymm5" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm6, %%ymm6" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm7, %%ymm7" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x10, %%ymm13, %%ymm12, %%ymm14" & ASCII.LF & ASCII.HT &
        "vpxor %%ymm14, %%ymm11, %%ymm11" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x01, %%ymm13, %%ymm12, %%ymm12" & ASCII.LF & ASCII.HT &
        "vpxor %%ymm12, %%ymm11, %%ymm11" & ASCII.LF & ASCII.HT &
        "vmovdqu 96(%2), %%ymm12" & ASCII.LF & ASCII.HT &
        "vpshufb %%ymm15, %%ymm12, %%ymm12" & ASCII.LF & ASCII.HT &
        "vmovdqu 96(%4), %%ymm13" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x00, %%ymm13, %%ymm12, %%ymm14" & ASCII.LF & ASCII.HT &
        "vpxor %%ymm14, %%ymm9, %%ymm9" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x11, %%ymm13, %%ymm12, %%ymm14" & ASCII.LF & ASCII.HT &
        "vbroadcasti128 80(%1), %%ymm8" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm0, %%ymm0" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm1, %%ymm1" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm2, %%ymm2" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm3, %%ymm3" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm4, %%ymm4" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm5, %%ymm5" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm6, %%ymm6" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm7, %%ymm7" & ASCII.LF & ASCII.HT &
        "vpxor %%ymm14, %%ymm10, %%ymm10" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x10, %%ymm13, %%ymm12, %%ymm14" & ASCII.LF & ASCII.HT &
        "vpxor %%ymm14, %%ymm11, %%ymm11" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x01, %%ymm13, %%ymm12, %%ymm12" & ASCII.LF & ASCII.HT &
        "vpxor %%ymm12, %%ymm11, %%ymm11" & ASCII.LF & ASCII.HT &
        "vmovdqu 128(%2), %%ymm12" & ASCII.LF & ASCII.HT &
        "vpshufb %%ymm15, %%ymm12, %%ymm12" & ASCII.LF & ASCII.HT &
        "vmovdqu 128(%4), %%ymm13" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x00, %%ymm13, %%ymm12, %%ymm14" & ASCII.LF & ASCII.HT &
        "vpxor %%ymm14, %%ymm9, %%ymm9" & ASCII.LF & ASCII.HT &
        "vbroadcasti128 96(%1), %%ymm8" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm0, %%ymm0" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm1, %%ymm1" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm2, %%ymm2" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm3, %%ymm3" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm4, %%ymm4" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm5, %%ymm5" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm6, %%ymm6" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm7, %%ymm7" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x11, %%ymm13, %%ymm12, %%ymm14" & ASCII.LF & ASCII.HT &
        "vpxor %%ymm14, %%ymm10, %%ymm10" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x10, %%ymm13, %%ymm12, %%ymm14" & ASCII.LF & ASCII.HT &
        "vpxor %%ymm14, %%ymm11, %%ymm11" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x01, %%ymm13, %%ymm12, %%ymm12" & ASCII.LF & ASCII.HT &
        "vpxor %%ymm12, %%ymm11, %%ymm11" & ASCII.LF & ASCII.HT &
        "vmovdqu 160(%2), %%ymm12" & ASCII.LF & ASCII.HT &
        "vpshufb %%ymm15, %%ymm12, %%ymm12" & ASCII.LF & ASCII.HT &
        "vmovdqu 160(%4), %%ymm13" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x00, %%ymm13, %%ymm12, %%ymm14" & ASCII.LF & ASCII.HT &
        "vbroadcasti128 112(%1), %%ymm8" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm0, %%ymm0" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm1, %%ymm1" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm2, %%ymm2" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm3, %%ymm3" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm4, %%ymm4" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm5, %%ymm5" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm6, %%ymm6" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm7, %%ymm7" & ASCII.LF & ASCII.HT &
        "vpxor %%ymm14, %%ymm9, %%ymm9" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x11, %%ymm13, %%ymm12, %%ymm14" & ASCII.LF & ASCII.HT &
        "vpxor %%ymm14, %%ymm10, %%ymm10" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x10, %%ymm13, %%ymm12, %%ymm14" & ASCII.LF & ASCII.HT &
        "vpxor %%ymm14, %%ymm11, %%ymm11" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x01, %%ymm13, %%ymm12, %%ymm12" & ASCII.LF & ASCII.HT &
        "vpxor %%ymm12, %%ymm11, %%ymm11" & ASCII.LF & ASCII.HT &
        "vmovdqu 192(%2), %%ymm12" & ASCII.LF & ASCII.HT &
        "vpshufb %%ymm15, %%ymm12, %%ymm12" & ASCII.LF & ASCII.HT &
        "vmovdqu 192(%4), %%ymm13" & ASCII.LF & ASCII.HT &
        "vbroadcasti128 128(%1), %%ymm8" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm0, %%ymm0" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm1, %%ymm1" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm2, %%ymm2" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm3, %%ymm3" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm4, %%ymm4" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm5, %%ymm5" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm6, %%ymm6" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm7, %%ymm7" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x00, %%ymm13, %%ymm12, %%ymm14" & ASCII.LF & ASCII.HT &
        "vpxor %%ymm14, %%ymm9, %%ymm9" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x11, %%ymm13, %%ymm12, %%ymm14" & ASCII.LF & ASCII.HT &
        "vpxor %%ymm14, %%ymm10, %%ymm10" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x10, %%ymm13, %%ymm12, %%ymm14" & ASCII.LF & ASCII.HT &
        "vpxor %%ymm14, %%ymm11, %%ymm11" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x01, %%ymm13, %%ymm12, %%ymm12" & ASCII.LF & ASCII.HT &
        "vpxor %%ymm12, %%ymm11, %%ymm11" & ASCII.LF & ASCII.HT &
        "vmovdqu 224(%2), %%ymm12" & ASCII.LF & ASCII.HT &
        "vpshufb %%ymm15, %%ymm12, %%ymm12" & ASCII.LF & ASCII.HT &
        "vbroadcasti128 144(%1), %%ymm8" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm0, %%ymm0" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm1, %%ymm1" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm2, %%ymm2" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm3, %%ymm3" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm4, %%ymm4" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm5, %%ymm5" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm6, %%ymm6" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm7, %%ymm7" & ASCII.LF & ASCII.HT &
        "vmovdqu 224(%4), %%ymm13" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x00, %%ymm13, %%ymm12, %%ymm14" & ASCII.LF & ASCII.HT &
        "vpxor %%ymm14, %%ymm9, %%ymm9" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x11, %%ymm13, %%ymm12, %%ymm14" & ASCII.LF & ASCII.HT &
        "vpxor %%ymm14, %%ymm10, %%ymm10" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x10, %%ymm13, %%ymm12, %%ymm14" & ASCII.LF & ASCII.HT &
        "vpxor %%ymm14, %%ymm11, %%ymm11" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x01, %%ymm13, %%ymm12, %%ymm12" & ASCII.LF & ASCII.HT &
        "vpxor %%ymm12, %%ymm11, %%ymm11" & ASCII.LF & ASCII.HT &
        "vbroadcasti128 160(%1), %%ymm8" & ASCII.LF & ASCII.HT &
        "vaesenclast %%ymm8, %%ymm0, %%ymm0" & ASCII.LF & ASCII.HT &
        "vaesenclast %%ymm8, %%ymm1, %%ymm1" & ASCII.LF & ASCII.HT &
        "vaesenclast %%ymm8, %%ymm2, %%ymm2" & ASCII.LF & ASCII.HT &
        "vaesenclast %%ymm8, %%ymm3, %%ymm3" & ASCII.LF & ASCII.HT &
        "vaesenclast %%ymm8, %%ymm4, %%ymm4" & ASCII.LF & ASCII.HT &
        "vaesenclast %%ymm8, %%ymm5, %%ymm5" & ASCII.LF & ASCII.HT &
        "vaesenclast %%ymm8, %%ymm6, %%ymm6" & ASCII.LF & ASCII.HT &
        "vaesenclast %%ymm8, %%ymm7, %%ymm7" & ASCII.LF & ASCII.HT &
        "vpxor (%2), %%ymm0, %%ymm0" & ASCII.LF & ASCII.HT &
        "vmovdqu %%ymm0, (%2)" & ASCII.LF & ASCII.HT &
        "vpxor 32(%2), %%ymm1, %%ymm1" & ASCII.LF & ASCII.HT &
        "vmovdqu %%ymm1, 32(%2)" & ASCII.LF & ASCII.HT &
        "vpxor 64(%2), %%ymm2, %%ymm2" & ASCII.LF & ASCII.HT &
        "vmovdqu %%ymm2, 64(%2)" & ASCII.LF & ASCII.HT &
        "vpxor 96(%2), %%ymm3, %%ymm3" & ASCII.LF & ASCII.HT &
        "vmovdqu %%ymm3, 96(%2)" & ASCII.LF & ASCII.HT &
        "vpxor 128(%2), %%ymm4, %%ymm4" & ASCII.LF & ASCII.HT &
        "vmovdqu %%ymm4, 128(%2)" & ASCII.LF & ASCII.HT &
        "vpxor 160(%2), %%ymm5, %%ymm5" & ASCII.LF & ASCII.HT &
        "vmovdqu %%ymm5, 160(%2)" & ASCII.LF & ASCII.HT &
        "vpxor 192(%2), %%ymm6, %%ymm6" & ASCII.LF & ASCII.HT &
        "vmovdqu %%ymm6, 192(%2)" & ASCII.LF & ASCII.HT &
        "vpxor 224(%2), %%ymm7, %%ymm7" & ASCII.LF & ASCII.HT &
        "vmovdqu %%ymm7, 224(%2)" & ASCII.LF & ASCII.HT &
        "vpslldq $8, %%ymm11, %%ymm14" & ASCII.LF & ASCII.HT &
        "vpsrldq $8, %%ymm11, %%ymm11" & ASCII.LF & ASCII.HT &
        "vpxor %%ymm14, %%ymm9, %%ymm9" & ASCII.LF & ASCII.HT &
        "vpxor %%ymm11, %%ymm10, %%ymm10" & ASCII.LF & ASCII.HT &
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
   end Decrypt_GCM_Stripe_16_128;
   --  END GENERATED avx2 decrypt 128

   --  BEGIN GENERATED avx2 decrypt 256
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
       ("vbroadcasti128 (%0), %%ymm9" & ASCII.LF & ASCII.HT &
        "vmovdqa (%6), %%ymm10" & ASCII.LF & ASCII.HT &
        "vpshufb %%ymm10, %%ymm9, %%ymm9" & ASCII.LF & ASCII.HT &
        "vpaddd (%7), %%ymm9, %%ymm0" & ASCII.LF & ASCII.HT &
        "vpshufb %%ymm10, %%ymm0, %%ymm0" & ASCII.LF & ASCII.HT &
        "vpaddd 32(%7), %%ymm9, %%ymm1" & ASCII.LF & ASCII.HT &
        "vpshufb %%ymm10, %%ymm1, %%ymm1" & ASCII.LF & ASCII.HT &
        "vpaddd 64(%7), %%ymm9, %%ymm2" & ASCII.LF & ASCII.HT &
        "vpshufb %%ymm10, %%ymm2, %%ymm2" & ASCII.LF & ASCII.HT &
        "vpaddd 96(%7), %%ymm9, %%ymm3" & ASCII.LF & ASCII.HT &
        "vpshufb %%ymm10, %%ymm3, %%ymm3" & ASCII.LF & ASCII.HT &
        "vpaddd 128(%7), %%ymm9, %%ymm4" & ASCII.LF & ASCII.HT &
        "vpshufb %%ymm10, %%ymm4, %%ymm4" & ASCII.LF & ASCII.HT &
        "vpaddd 160(%7), %%ymm9, %%ymm5" & ASCII.LF & ASCII.HT &
        "vpshufb %%ymm10, %%ymm5, %%ymm5" & ASCII.LF & ASCII.HT &
        "vpaddd 192(%7), %%ymm9, %%ymm6" & ASCII.LF & ASCII.HT &
        "vpshufb %%ymm10, %%ymm6, %%ymm6" & ASCII.LF & ASCII.HT &
        "vpaddd 224(%7), %%ymm9, %%ymm7" & ASCII.LF & ASCII.HT &
        "vpshufb %%ymm10, %%ymm7, %%ymm7" & ASCII.LF & ASCII.HT &
        "vpaddd 256(%7), %%xmm9, %%xmm11" & ASCII.LF & ASCII.HT &
        "vpshufb %%xmm10, %%xmm11, %%xmm11" & ASCII.LF & ASCII.HT &
        "vmovdqu %%xmm11, (%0)" & ASCII.LF & ASCII.HT &
        "vbroadcasti128 (%1), %%ymm8" & ASCII.LF & ASCII.HT &
        "vpxor %%ymm8, %%ymm0, %%ymm0" & ASCII.LF & ASCII.HT &
        "vpxor %%ymm8, %%ymm1, %%ymm1" & ASCII.LF & ASCII.HT &
        "vpxor %%ymm8, %%ymm2, %%ymm2" & ASCII.LF & ASCII.HT &
        "vpxor %%ymm8, %%ymm3, %%ymm3" & ASCII.LF & ASCII.HT &
        "vpxor %%ymm8, %%ymm4, %%ymm4" & ASCII.LF & ASCII.HT &
        "vpxor %%ymm8, %%ymm5, %%ymm5" & ASCII.LF & ASCII.HT &
        "vpxor %%ymm8, %%ymm6, %%ymm6" & ASCII.LF & ASCII.HT &
        "vpxor %%ymm8, %%ymm7, %%ymm7" & ASCII.LF & ASCII.HT &
        "vbroadcasti128 16(%1), %%ymm8" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm0, %%ymm0" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm1, %%ymm1" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm2, %%ymm2" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm3, %%ymm3" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm4, %%ymm4" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm5, %%ymm5" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm6, %%ymm6" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm7, %%ymm7" & ASCII.LF & ASCII.HT &
        "vmovdqa (%5), %%ymm15" & ASCII.LF & ASCII.HT &
        "vmovdqu (%2), %%ymm12" & ASCII.LF & ASCII.HT &
        "vpshufb %%ymm15, %%ymm12, %%ymm12" & ASCII.LF & ASCII.HT &
        "vmovdqu (%3), %%xmm14" & ASCII.LF & ASCII.HT &
        "vpshufb %%xmm15, %%xmm14, %%xmm14" & ASCII.LF & ASCII.HT &
        "vpxor %%ymm14, %%ymm12, %%ymm12" & ASCII.LF & ASCII.HT &
        "vmovdqu (%4), %%ymm13" & ASCII.LF & ASCII.HT &
        "vbroadcasti128 32(%1), %%ymm8" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm0, %%ymm0" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm1, %%ymm1" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm2, %%ymm2" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm3, %%ymm3" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm4, %%ymm4" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm5, %%ymm5" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm6, %%ymm6" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm7, %%ymm7" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x00, %%ymm13, %%ymm12, %%ymm9" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x11, %%ymm13, %%ymm12, %%ymm10" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x10, %%ymm13, %%ymm12, %%ymm11" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x01, %%ymm13, %%ymm12, %%ymm12" & ASCII.LF & ASCII.HT &
        "vpxor %%ymm12, %%ymm11, %%ymm11" & ASCII.LF & ASCII.HT &
        "vmovdqu 32(%2), %%ymm12" & ASCII.LF & ASCII.HT &
        "vpshufb %%ymm15, %%ymm12, %%ymm12" & ASCII.LF & ASCII.HT &
        "vbroadcasti128 48(%1), %%ymm8" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm0, %%ymm0" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm1, %%ymm1" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm2, %%ymm2" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm3, %%ymm3" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm4, %%ymm4" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm5, %%ymm5" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm6, %%ymm6" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm7, %%ymm7" & ASCII.LF & ASCII.HT &
        "vmovdqu 32(%4), %%ymm13" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x00, %%ymm13, %%ymm12, %%ymm14" & ASCII.LF & ASCII.HT &
        "vpxor %%ymm14, %%ymm9, %%ymm9" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x11, %%ymm13, %%ymm12, %%ymm14" & ASCII.LF & ASCII.HT &
        "vpxor %%ymm14, %%ymm10, %%ymm10" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x10, %%ymm13, %%ymm12, %%ymm14" & ASCII.LF & ASCII.HT &
        "vpxor %%ymm14, %%ymm11, %%ymm11" & ASCII.LF & ASCII.HT &
        "vbroadcasti128 64(%1), %%ymm8" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm0, %%ymm0" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm1, %%ymm1" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm2, %%ymm2" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm3, %%ymm3" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm4, %%ymm4" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm5, %%ymm5" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm6, %%ymm6" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm7, %%ymm7" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x01, %%ymm13, %%ymm12, %%ymm12" & ASCII.LF & ASCII.HT &
        "vpxor %%ymm12, %%ymm11, %%ymm11" & ASCII.LF & ASCII.HT &
        "vmovdqu 64(%2), %%ymm12" & ASCII.LF & ASCII.HT &
        "vpshufb %%ymm15, %%ymm12, %%ymm12" & ASCII.LF & ASCII.HT &
        "vmovdqu 64(%4), %%ymm13" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x00, %%ymm13, %%ymm12, %%ymm14" & ASCII.LF & ASCII.HT &
        "vpxor %%ymm14, %%ymm9, %%ymm9" & ASCII.LF & ASCII.HT &
        "vbroadcasti128 80(%1), %%ymm8" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm0, %%ymm0" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm1, %%ymm1" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm2, %%ymm2" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm3, %%ymm3" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm4, %%ymm4" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm5, %%ymm5" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm6, %%ymm6" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm7, %%ymm7" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x11, %%ymm13, %%ymm12, %%ymm14" & ASCII.LF & ASCII.HT &
        "vpxor %%ymm14, %%ymm10, %%ymm10" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x10, %%ymm13, %%ymm12, %%ymm14" & ASCII.LF & ASCII.HT &
        "vpxor %%ymm14, %%ymm11, %%ymm11" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x01, %%ymm13, %%ymm12, %%ymm12" & ASCII.LF & ASCII.HT &
        "vpxor %%ymm12, %%ymm11, %%ymm11" & ASCII.LF & ASCII.HT &
        "vmovdqu 96(%2), %%ymm12" & ASCII.LF & ASCII.HT &
        "vbroadcasti128 96(%1), %%ymm8" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm0, %%ymm0" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm1, %%ymm1" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm2, %%ymm2" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm3, %%ymm3" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm4, %%ymm4" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm5, %%ymm5" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm6, %%ymm6" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm7, %%ymm7" & ASCII.LF & ASCII.HT &
        "vpshufb %%ymm15, %%ymm12, %%ymm12" & ASCII.LF & ASCII.HT &
        "vmovdqu 96(%4), %%ymm13" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x00, %%ymm13, %%ymm12, %%ymm14" & ASCII.LF & ASCII.HT &
        "vpxor %%ymm14, %%ymm9, %%ymm9" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x11, %%ymm13, %%ymm12, %%ymm14" & ASCII.LF & ASCII.HT &
        "vpxor %%ymm14, %%ymm10, %%ymm10" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x10, %%ymm13, %%ymm12, %%ymm14" & ASCII.LF & ASCII.HT &
        "vbroadcasti128 112(%1), %%ymm8" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm0, %%ymm0" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm1, %%ymm1" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm2, %%ymm2" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm3, %%ymm3" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm4, %%ymm4" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm5, %%ymm5" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm6, %%ymm6" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm7, %%ymm7" & ASCII.LF & ASCII.HT &
        "vpxor %%ymm14, %%ymm11, %%ymm11" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x01, %%ymm13, %%ymm12, %%ymm12" & ASCII.LF & ASCII.HT &
        "vpxor %%ymm12, %%ymm11, %%ymm11" & ASCII.LF & ASCII.HT &
        "vmovdqu 128(%2), %%ymm12" & ASCII.LF & ASCII.HT &
        "vpshufb %%ymm15, %%ymm12, %%ymm12" & ASCII.LF & ASCII.HT &
        "vmovdqu 128(%4), %%ymm13" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x00, %%ymm13, %%ymm12, %%ymm14" & ASCII.LF & ASCII.HT &
        "vbroadcasti128 128(%1), %%ymm8" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm0, %%ymm0" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm1, %%ymm1" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm2, %%ymm2" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm3, %%ymm3" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm4, %%ymm4" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm5, %%ymm5" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm6, %%ymm6" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm7, %%ymm7" & ASCII.LF & ASCII.HT &
        "vpxor %%ymm14, %%ymm9, %%ymm9" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x11, %%ymm13, %%ymm12, %%ymm14" & ASCII.LF & ASCII.HT &
        "vpxor %%ymm14, %%ymm10, %%ymm10" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x10, %%ymm13, %%ymm12, %%ymm14" & ASCII.LF & ASCII.HT &
        "vpxor %%ymm14, %%ymm11, %%ymm11" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x01, %%ymm13, %%ymm12, %%ymm12" & ASCII.LF & ASCII.HT &
        "vpxor %%ymm12, %%ymm11, %%ymm11" & ASCII.LF & ASCII.HT &
        "vbroadcasti128 144(%1), %%ymm8" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm0, %%ymm0" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm1, %%ymm1" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm2, %%ymm2" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm3, %%ymm3" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm4, %%ymm4" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm5, %%ymm5" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm6, %%ymm6" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm7, %%ymm7" & ASCII.LF & ASCII.HT &
        "vmovdqu 160(%2), %%ymm12" & ASCII.LF & ASCII.HT &
        "vpshufb %%ymm15, %%ymm12, %%ymm12" & ASCII.LF & ASCII.HT &
        "vmovdqu 160(%4), %%ymm13" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x00, %%ymm13, %%ymm12, %%ymm14" & ASCII.LF & ASCII.HT &
        "vpxor %%ymm14, %%ymm9, %%ymm9" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x11, %%ymm13, %%ymm12, %%ymm14" & ASCII.LF & ASCII.HT &
        "vpxor %%ymm14, %%ymm10, %%ymm10" & ASCII.LF & ASCII.HT &
        "vbroadcasti128 160(%1), %%ymm8" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm0, %%ymm0" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm1, %%ymm1" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm2, %%ymm2" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm3, %%ymm3" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm4, %%ymm4" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm5, %%ymm5" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm6, %%ymm6" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm7, %%ymm7" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x10, %%ymm13, %%ymm12, %%ymm14" & ASCII.LF & ASCII.HT &
        "vpxor %%ymm14, %%ymm11, %%ymm11" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x01, %%ymm13, %%ymm12, %%ymm12" & ASCII.LF & ASCII.HT &
        "vpxor %%ymm12, %%ymm11, %%ymm11" & ASCII.LF & ASCII.HT &
        "vmovdqu 192(%2), %%ymm12" & ASCII.LF & ASCII.HT &
        "vpshufb %%ymm15, %%ymm12, %%ymm12" & ASCII.LF & ASCII.HT &
        "vmovdqu 192(%4), %%ymm13" & ASCII.LF & ASCII.HT &
        "vbroadcasti128 176(%1), %%ymm8" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm0, %%ymm0" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm1, %%ymm1" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm2, %%ymm2" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm3, %%ymm3" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm4, %%ymm4" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm5, %%ymm5" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm6, %%ymm6" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm7, %%ymm7" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x00, %%ymm13, %%ymm12, %%ymm14" & ASCII.LF & ASCII.HT &
        "vpxor %%ymm14, %%ymm9, %%ymm9" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x11, %%ymm13, %%ymm12, %%ymm14" & ASCII.LF & ASCII.HT &
        "vpxor %%ymm14, %%ymm10, %%ymm10" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x10, %%ymm13, %%ymm12, %%ymm14" & ASCII.LF & ASCII.HT &
        "vpxor %%ymm14, %%ymm11, %%ymm11" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x01, %%ymm13, %%ymm12, %%ymm12" & ASCII.LF & ASCII.HT &
        "vbroadcasti128 192(%1), %%ymm8" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm0, %%ymm0" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm1, %%ymm1" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm2, %%ymm2" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm3, %%ymm3" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm4, %%ymm4" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm5, %%ymm5" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm6, %%ymm6" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm7, %%ymm7" & ASCII.LF & ASCII.HT &
        "vpxor %%ymm12, %%ymm11, %%ymm11" & ASCII.LF & ASCII.HT &
        "vmovdqu 224(%2), %%ymm12" & ASCII.LF & ASCII.HT &
        "vpshufb %%ymm15, %%ymm12, %%ymm12" & ASCII.LF & ASCII.HT &
        "vmovdqu 224(%4), %%ymm13" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x00, %%ymm13, %%ymm12, %%ymm14" & ASCII.LF & ASCII.HT &
        "vpxor %%ymm14, %%ymm9, %%ymm9" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x11, %%ymm13, %%ymm12, %%ymm14" & ASCII.LF & ASCII.HT &
        "vbroadcasti128 208(%1), %%ymm8" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm0, %%ymm0" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm1, %%ymm1" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm2, %%ymm2" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm3, %%ymm3" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm4, %%ymm4" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm5, %%ymm5" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm6, %%ymm6" & ASCII.LF & ASCII.HT &
        "vaesenc %%ymm8, %%ymm7, %%ymm7" & ASCII.LF & ASCII.HT &
        "vpxor %%ymm14, %%ymm10, %%ymm10" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x10, %%ymm13, %%ymm12, %%ymm14" & ASCII.LF & ASCII.HT &
        "vpxor %%ymm14, %%ymm11, %%ymm11" & ASCII.LF & ASCII.HT &
        "vpclmulqdq $0x01, %%ymm13, %%ymm12, %%ymm12" & ASCII.LF & ASCII.HT &
        "vpxor %%ymm12, %%ymm11, %%ymm11" & ASCII.LF & ASCII.HT &
        "vbroadcasti128 224(%1), %%ymm8" & ASCII.LF & ASCII.HT &
        "vaesenclast %%ymm8, %%ymm0, %%ymm0" & ASCII.LF & ASCII.HT &
        "vaesenclast %%ymm8, %%ymm1, %%ymm1" & ASCII.LF & ASCII.HT &
        "vaesenclast %%ymm8, %%ymm2, %%ymm2" & ASCII.LF & ASCII.HT &
        "vaesenclast %%ymm8, %%ymm3, %%ymm3" & ASCII.LF & ASCII.HT &
        "vaesenclast %%ymm8, %%ymm4, %%ymm4" & ASCII.LF & ASCII.HT &
        "vaesenclast %%ymm8, %%ymm5, %%ymm5" & ASCII.LF & ASCII.HT &
        "vaesenclast %%ymm8, %%ymm6, %%ymm6" & ASCII.LF & ASCII.HT &
        "vaesenclast %%ymm8, %%ymm7, %%ymm7" & ASCII.LF & ASCII.HT &
        "vpxor (%2), %%ymm0, %%ymm0" & ASCII.LF & ASCII.HT &
        "vmovdqu %%ymm0, (%2)" & ASCII.LF & ASCII.HT &
        "vpxor 32(%2), %%ymm1, %%ymm1" & ASCII.LF & ASCII.HT &
        "vmovdqu %%ymm1, 32(%2)" & ASCII.LF & ASCII.HT &
        "vpxor 64(%2), %%ymm2, %%ymm2" & ASCII.LF & ASCII.HT &
        "vmovdqu %%ymm2, 64(%2)" & ASCII.LF & ASCII.HT &
        "vpxor 96(%2), %%ymm3, %%ymm3" & ASCII.LF & ASCII.HT &
        "vmovdqu %%ymm3, 96(%2)" & ASCII.LF & ASCII.HT &
        "vpxor 128(%2), %%ymm4, %%ymm4" & ASCII.LF & ASCII.HT &
        "vmovdqu %%ymm4, 128(%2)" & ASCII.LF & ASCII.HT &
        "vpxor 160(%2), %%ymm5, %%ymm5" & ASCII.LF & ASCII.HT &
        "vmovdqu %%ymm5, 160(%2)" & ASCII.LF & ASCII.HT &
        "vpxor 192(%2), %%ymm6, %%ymm6" & ASCII.LF & ASCII.HT &
        "vmovdqu %%ymm6, 192(%2)" & ASCII.LF & ASCII.HT &
        "vpxor 224(%2), %%ymm7, %%ymm7" & ASCII.LF & ASCII.HT &
        "vmovdqu %%ymm7, 224(%2)" & ASCII.LF & ASCII.HT &
        "vpslldq $8, %%ymm11, %%ymm14" & ASCII.LF & ASCII.HT &
        "vpsrldq $8, %%ymm11, %%ymm11" & ASCII.LF & ASCII.HT &
        "vpxor %%ymm14, %%ymm9, %%ymm9" & ASCII.LF & ASCII.HT &
        "vpxor %%ymm11, %%ymm10, %%ymm10" & ASCII.LF & ASCII.HT &
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
   end Decrypt_GCM_Stripe_16_256;
   --  END GENERATED avx2 decrypt 256

begin
   --  CPU.Has_AVX2 is False in a Portable_Only build.
   Has_VAES_AVX2 := SPARKTLSCrypto.CPU.Has_AVX2
     and then SPARKTLSCrypto.AES_NI.Has_AESNI
     and then SPARKTLSCrypto.GHASH_NI.Has_PCLMULQDQ
     and then Detect_VAES_VPCLMULQDQ;
end SPARKTLSCrypto.AES_GCM_AVX2;
