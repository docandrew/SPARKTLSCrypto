--  AVX-512 ChaCha20 16-block batch (RFC 8439). Body — see spec.
--
--  Algorithm: Initialize 16 ChaCha20 states in zmm0..zmm15
--  (lane-major: each zmm = same state word across 16 streams).
--  Run 20 rounds = 10 × (column-round + diagonal-round). Add original
--  state. Then a 4-stage 16×16 u32 transpose (vpunpck + vshufi32x4)
--  flips lane-major → stream-major in zmm0..zmm15, after which 16
--  vpxorq+vmovdqu64 pairs XOR each 64-byte stream into Buf in place.
--  Uses zmm16..zmm31 as transpose scratch (the rounds only touch
--  zmm0..zmm15, so the upper bank is free).

with System.Machine_Code; use System.Machine_Code;
with Interfaces;          use Interfaces;
with SPARKNaCl;           use SPARKNaCl;

package body SPARKTLSCrypto.ChaCha20_AVX512 with
   SPARK_Mode => Off
is

   ----------------------------------------------------------------------------
   --  CPUID detection: AVX-512F (CPUID.7.0.EBX[16]) plus OS state-save
   --  enablement via XCR0 — without it AVX-512 instructions #UD.
   ----------------------------------------------------------------------------
   function Detect_AVX512F return Boolean is
   begin
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
         return (EBX and 16#0001_0000#) /= 0;
      end;
   end Detect_AVX512F;

   ----------------------------------------------------------------------------
   --  Constants — 64-byte aligned for vmovdqa64.
   ----------------------------------------------------------------------------
   Sigma0_BC : constant array (0 .. 15) of Unsigned_32 :=
                  (others => 16#61707865#);
   Sigma1_BC : constant array (0 .. 15) of Unsigned_32 :=
                  (others => 16#3320646e#);
   Sigma2_BC : constant array (0 .. 15) of Unsigned_32 :=
                  (others => 16#79622d32#);
   Sigma3_BC : constant array (0 .. 15) of Unsigned_32 :=
                  (others => 16#6b206574#);
   Counter_Offsets : constant array (0 .. 15) of Unsigned_32 :=
                  (0, 1, 2, 3, 4, 5, 6, 7,
                   8, 9, 10, 11, 12, 13, 14, 15);
   for Sigma0_BC'Alignment       use 64;
   for Sigma1_BC'Alignment       use 64;
   for Sigma2_BC'Alignment       use 64;
   for Sigma3_BC'Alignment       use 64;
   for Counter_Offsets'Alignment use 64;

   ----------------------------------------------------------------------------
   --  Round-pair string fragment (column round + diagonal round).
   --  Used 10 times in the asm body to make 20 rounds total.
   ----------------------------------------------------------------------------
   --  Column round: QR(0,4,8,12), QR(1,5,9,13), QR(2,6,10,14), QR(3,7,11,15)
   --  Diagonal round: QR(0,5,10,15), QR(1,6,11,12), QR(2,7,8,13), QR(3,4,9,14)

   Round_Pair : constant String :=
        --  Column step 1: a += b; d ^= a; d <<<= 16
        "vpaddd  %%zmm4,  %%zmm0,  %%zmm0"   & ASCII.LF & ASCII.HT &
        "vpaddd  %%zmm5,  %%zmm1,  %%zmm1"   & ASCII.LF & ASCII.HT &
        "vpaddd  %%zmm6,  %%zmm2,  %%zmm2"   & ASCII.LF & ASCII.HT &
        "vpaddd  %%zmm7,  %%zmm3,  %%zmm3"   & ASCII.LF & ASCII.HT &
        "vpxord  %%zmm0,  %%zmm12, %%zmm12"  & ASCII.LF & ASCII.HT &
        "vpxord  %%zmm1,  %%zmm13, %%zmm13"  & ASCII.LF & ASCII.HT &
        "vpxord  %%zmm2,  %%zmm14, %%zmm14"  & ASCII.LF & ASCII.HT &
        "vpxord  %%zmm3,  %%zmm15, %%zmm15"  & ASCII.LF & ASCII.HT &
        "vprold  $16, %%zmm12, %%zmm12"      & ASCII.LF & ASCII.HT &
        "vprold  $16, %%zmm13, %%zmm13"      & ASCII.LF & ASCII.HT &
        "vprold  $16, %%zmm14, %%zmm14"      & ASCII.LF & ASCII.HT &
        "vprold  $16, %%zmm15, %%zmm15"      & ASCII.LF & ASCII.HT &
        --  Column step 2: c += d; b ^= c; b <<<= 12
        "vpaddd  %%zmm12, %%zmm8,  %%zmm8"   & ASCII.LF & ASCII.HT &
        "vpaddd  %%zmm13, %%zmm9,  %%zmm9"   & ASCII.LF & ASCII.HT &
        "vpaddd  %%zmm14, %%zmm10, %%zmm10"  & ASCII.LF & ASCII.HT &
        "vpaddd  %%zmm15, %%zmm11, %%zmm11"  & ASCII.LF & ASCII.HT &
        "vpxord  %%zmm8,  %%zmm4,  %%zmm4"   & ASCII.LF & ASCII.HT &
        "vpxord  %%zmm9,  %%zmm5,  %%zmm5"   & ASCII.LF & ASCII.HT &
        "vpxord  %%zmm10, %%zmm6,  %%zmm6"   & ASCII.LF & ASCII.HT &
        "vpxord  %%zmm11, %%zmm7,  %%zmm7"   & ASCII.LF & ASCII.HT &
        "vprold  $12, %%zmm4,  %%zmm4"       & ASCII.LF & ASCII.HT &
        "vprold  $12, %%zmm5,  %%zmm5"       & ASCII.LF & ASCII.HT &
        "vprold  $12, %%zmm6,  %%zmm6"       & ASCII.LF & ASCII.HT &
        "vprold  $12, %%zmm7,  %%zmm7"       & ASCII.LF & ASCII.HT &
        --  Column step 3: a += b; d ^= a; d <<<= 8
        "vpaddd  %%zmm4,  %%zmm0,  %%zmm0"   & ASCII.LF & ASCII.HT &
        "vpaddd  %%zmm5,  %%zmm1,  %%zmm1"   & ASCII.LF & ASCII.HT &
        "vpaddd  %%zmm6,  %%zmm2,  %%zmm2"   & ASCII.LF & ASCII.HT &
        "vpaddd  %%zmm7,  %%zmm3,  %%zmm3"   & ASCII.LF & ASCII.HT &
        "vpxord  %%zmm0,  %%zmm12, %%zmm12"  & ASCII.LF & ASCII.HT &
        "vpxord  %%zmm1,  %%zmm13, %%zmm13"  & ASCII.LF & ASCII.HT &
        "vpxord  %%zmm2,  %%zmm14, %%zmm14"  & ASCII.LF & ASCII.HT &
        "vpxord  %%zmm3,  %%zmm15, %%zmm15"  & ASCII.LF & ASCII.HT &
        "vprold  $8, %%zmm12, %%zmm12"       & ASCII.LF & ASCII.HT &
        "vprold  $8, %%zmm13, %%zmm13"       & ASCII.LF & ASCII.HT &
        "vprold  $8, %%zmm14, %%zmm14"       & ASCII.LF & ASCII.HT &
        "vprold  $8, %%zmm15, %%zmm15"       & ASCII.LF & ASCII.HT &
        --  Column step 4: c += d; b ^= c; b <<<= 7
        "vpaddd  %%zmm12, %%zmm8,  %%zmm8"   & ASCII.LF & ASCII.HT &
        "vpaddd  %%zmm13, %%zmm9,  %%zmm9"   & ASCII.LF & ASCII.HT &
        "vpaddd  %%zmm14, %%zmm10, %%zmm10"  & ASCII.LF & ASCII.HT &
        "vpaddd  %%zmm15, %%zmm11, %%zmm11"  & ASCII.LF & ASCII.HT &
        "vpxord  %%zmm8,  %%zmm4,  %%zmm4"   & ASCII.LF & ASCII.HT &
        "vpxord  %%zmm9,  %%zmm5,  %%zmm5"   & ASCII.LF & ASCII.HT &
        "vpxord  %%zmm10, %%zmm6,  %%zmm6"   & ASCII.LF & ASCII.HT &
        "vpxord  %%zmm11, %%zmm7,  %%zmm7"   & ASCII.LF & ASCII.HT &
        "vprold  $7, %%zmm4,  %%zmm4"        & ASCII.LF & ASCII.HT &
        "vprold  $7, %%zmm5,  %%zmm5"        & ASCII.LF & ASCII.HT &
        "vprold  $7, %%zmm6,  %%zmm6"        & ASCII.LF & ASCII.HT &
        "vprold  $7, %%zmm7,  %%zmm7"        & ASCII.LF & ASCII.HT &

        --  Diagonal step 1
        "vpaddd  %%zmm5,  %%zmm0,  %%zmm0"   & ASCII.LF & ASCII.HT &
        "vpaddd  %%zmm6,  %%zmm1,  %%zmm1"   & ASCII.LF & ASCII.HT &
        "vpaddd  %%zmm7,  %%zmm2,  %%zmm2"   & ASCII.LF & ASCII.HT &
        "vpaddd  %%zmm4,  %%zmm3,  %%zmm3"   & ASCII.LF & ASCII.HT &
        "vpxord  %%zmm0,  %%zmm15, %%zmm15"  & ASCII.LF & ASCII.HT &
        "vpxord  %%zmm1,  %%zmm12, %%zmm12"  & ASCII.LF & ASCII.HT &
        "vpxord  %%zmm2,  %%zmm13, %%zmm13"  & ASCII.LF & ASCII.HT &
        "vpxord  %%zmm3,  %%zmm14, %%zmm14"  & ASCII.LF & ASCII.HT &
        "vprold  $16, %%zmm15, %%zmm15"      & ASCII.LF & ASCII.HT &
        "vprold  $16, %%zmm12, %%zmm12"      & ASCII.LF & ASCII.HT &
        "vprold  $16, %%zmm13, %%zmm13"      & ASCII.LF & ASCII.HT &
        "vprold  $16, %%zmm14, %%zmm14"      & ASCII.LF & ASCII.HT &
        --  Diagonal step 2
        "vpaddd  %%zmm15, %%zmm10, %%zmm10"  & ASCII.LF & ASCII.HT &
        "vpaddd  %%zmm12, %%zmm11, %%zmm11"  & ASCII.LF & ASCII.HT &
        "vpaddd  %%zmm13, %%zmm8,  %%zmm8"   & ASCII.LF & ASCII.HT &
        "vpaddd  %%zmm14, %%zmm9,  %%zmm9"   & ASCII.LF & ASCII.HT &
        "vpxord  %%zmm10, %%zmm5,  %%zmm5"   & ASCII.LF & ASCII.HT &
        "vpxord  %%zmm11, %%zmm6,  %%zmm6"   & ASCII.LF & ASCII.HT &
        "vpxord  %%zmm8,  %%zmm7,  %%zmm7"   & ASCII.LF & ASCII.HT &
        "vpxord  %%zmm9,  %%zmm4,  %%zmm4"   & ASCII.LF & ASCII.HT &
        "vprold  $12, %%zmm5,  %%zmm5"       & ASCII.LF & ASCII.HT &
        "vprold  $12, %%zmm6,  %%zmm6"       & ASCII.LF & ASCII.HT &
        "vprold  $12, %%zmm7,  %%zmm7"       & ASCII.LF & ASCII.HT &
        "vprold  $12, %%zmm4,  %%zmm4"       & ASCII.LF & ASCII.HT &
        --  Diagonal step 3
        "vpaddd  %%zmm5,  %%zmm0,  %%zmm0"   & ASCII.LF & ASCII.HT &
        "vpaddd  %%zmm6,  %%zmm1,  %%zmm1"   & ASCII.LF & ASCII.HT &
        "vpaddd  %%zmm7,  %%zmm2,  %%zmm2"   & ASCII.LF & ASCII.HT &
        "vpaddd  %%zmm4,  %%zmm3,  %%zmm3"   & ASCII.LF & ASCII.HT &
        "vpxord  %%zmm0,  %%zmm15, %%zmm15"  & ASCII.LF & ASCII.HT &
        "vpxord  %%zmm1,  %%zmm12, %%zmm12"  & ASCII.LF & ASCII.HT &
        "vpxord  %%zmm2,  %%zmm13, %%zmm13"  & ASCII.LF & ASCII.HT &
        "vpxord  %%zmm3,  %%zmm14, %%zmm14"  & ASCII.LF & ASCII.HT &
        "vprold  $8, %%zmm15, %%zmm15"       & ASCII.LF & ASCII.HT &
        "vprold  $8, %%zmm12, %%zmm12"       & ASCII.LF & ASCII.HT &
        "vprold  $8, %%zmm13, %%zmm13"       & ASCII.LF & ASCII.HT &
        "vprold  $8, %%zmm14, %%zmm14"       & ASCII.LF & ASCII.HT &
        --  Diagonal step 4
        "vpaddd  %%zmm15, %%zmm10, %%zmm10"  & ASCII.LF & ASCII.HT &
        "vpaddd  %%zmm12, %%zmm11, %%zmm11"  & ASCII.LF & ASCII.HT &
        "vpaddd  %%zmm13, %%zmm8,  %%zmm8"   & ASCII.LF & ASCII.HT &
        "vpaddd  %%zmm14, %%zmm9,  %%zmm9"   & ASCII.LF & ASCII.HT &
        "vpxord  %%zmm10, %%zmm5,  %%zmm5"   & ASCII.LF & ASCII.HT &
        "vpxord  %%zmm11, %%zmm6,  %%zmm6"   & ASCII.LF & ASCII.HT &
        "vpxord  %%zmm8,  %%zmm7,  %%zmm7"   & ASCII.LF & ASCII.HT &
        "vpxord  %%zmm9,  %%zmm4,  %%zmm4"   & ASCII.LF & ASCII.HT &
        "vprold  $7, %%zmm5,  %%zmm5"        & ASCII.LF & ASCII.HT &
        "vprold  $7, %%zmm6,  %%zmm6"        & ASCII.LF & ASCII.HT &
        "vprold  $7, %%zmm7,  %%zmm7"        & ASCII.LF & ASCII.HT &
        "vprold  $7, %%zmm4,  %%zmm4"        & ASCII.LF & ASCII.HT;

   --  Build the full asm body: 10 round-pairs = 20 rounds total.
   Rounds_Body : constant String :=
      Round_Pair & Round_Pair & Round_Pair & Round_Pair & Round_Pair &
      Round_Pair & Round_Pair & Round_Pair & Round_Pair & Round_Pair;

   ----------------------------------------------------------------------------
   --  16×16 u32 transpose (lane-major zmm0..zmm15 → stream-major
   --  zmm0..zmm15, scratch zmm16..zmm31). Standard 4-stage AVX-512
   --  pattern: 16 vpunpckldq+hdq, 16 vpunpcklqdq+hqdq, 32 vshufi32x4.
   --
   --  Indexing convention: input zmm_w holds state word w broadcast
   --  across 16 streams (zmm_w[s] = state[w][s]). Output zmm_s holds
   --  all 16 state words of stream s (zmm_s[w] = state[w][s]).
   ----------------------------------------------------------------------------
   Transpose_16x16 : constant String :=
        --  Stage 1: vpunpckldq/hdq pair adjacent zmms → zmm16..zmm31.
        "vpunpckldq  %%zmm1,  %%zmm0,  %%zmm16"  & ASCII.LF & ASCII.HT &
        "vpunpckhdq  %%zmm1,  %%zmm0,  %%zmm17"  & ASCII.LF & ASCII.HT &
        "vpunpckldq  %%zmm3,  %%zmm2,  %%zmm18"  & ASCII.LF & ASCII.HT &
        "vpunpckhdq  %%zmm3,  %%zmm2,  %%zmm19"  & ASCII.LF & ASCII.HT &
        "vpunpckldq  %%zmm5,  %%zmm4,  %%zmm20"  & ASCII.LF & ASCII.HT &
        "vpunpckhdq  %%zmm5,  %%zmm4,  %%zmm21"  & ASCII.LF & ASCII.HT &
        "vpunpckldq  %%zmm7,  %%zmm6,  %%zmm22"  & ASCII.LF & ASCII.HT &
        "vpunpckhdq  %%zmm7,  %%zmm6,  %%zmm23"  & ASCII.LF & ASCII.HT &
        "vpunpckldq  %%zmm9,  %%zmm8,  %%zmm24"  & ASCII.LF & ASCII.HT &
        "vpunpckhdq  %%zmm9,  %%zmm8,  %%zmm25"  & ASCII.LF & ASCII.HT &
        "vpunpckldq  %%zmm11, %%zmm10, %%zmm26"  & ASCII.LF & ASCII.HT &
        "vpunpckhdq  %%zmm11, %%zmm10, %%zmm27"  & ASCII.LF & ASCII.HT &
        "vpunpckldq  %%zmm13, %%zmm12, %%zmm28"  & ASCII.LF & ASCII.HT &
        "vpunpckhdq  %%zmm13, %%zmm12, %%zmm29"  & ASCII.LF & ASCII.HT &
        "vpunpckldq  %%zmm15, %%zmm14, %%zmm30"  & ASCII.LF & ASCII.HT &
        "vpunpckhdq  %%zmm15, %%zmm14, %%zmm31"  & ASCII.LF & ASCII.HT &

        --  Stage 2: vpunpcklqdq/hqdq across the T pairs → back to zmm0..zmm15.
        --  U_0  = vpunpcklqdq(T_0,  T_2)  → zmm0
        --  U_1  = vpunpcklqdq(T_1,  T_3)  → zmm1
        --  U_2  = vpunpckhqdq(T_0,  T_2)  → zmm2
        --  U_3  = vpunpckhqdq(T_1,  T_3)  → zmm3
        --  ... and so on for the (4,6),(5,7),(8,10),(9,11),(12,14),(13,15) blocks
        "vpunpcklqdq %%zmm18, %%zmm16, %%zmm0"   & ASCII.LF & ASCII.HT &
        "vpunpcklqdq %%zmm19, %%zmm17, %%zmm1"   & ASCII.LF & ASCII.HT &
        "vpunpckhqdq %%zmm18, %%zmm16, %%zmm2"   & ASCII.LF & ASCII.HT &
        "vpunpckhqdq %%zmm19, %%zmm17, %%zmm3"   & ASCII.LF & ASCII.HT &
        "vpunpcklqdq %%zmm22, %%zmm20, %%zmm4"   & ASCII.LF & ASCII.HT &
        "vpunpcklqdq %%zmm23, %%zmm21, %%zmm5"   & ASCII.LF & ASCII.HT &
        "vpunpckhqdq %%zmm22, %%zmm20, %%zmm6"   & ASCII.LF & ASCII.HT &
        "vpunpckhqdq %%zmm23, %%zmm21, %%zmm7"   & ASCII.LF & ASCII.HT &
        "vpunpcklqdq %%zmm26, %%zmm24, %%zmm8"   & ASCII.LF & ASCII.HT &
        "vpunpcklqdq %%zmm27, %%zmm25, %%zmm9"   & ASCII.LF & ASCII.HT &
        "vpunpckhqdq %%zmm26, %%zmm24, %%zmm10"  & ASCII.LF & ASCII.HT &
        "vpunpckhqdq %%zmm27, %%zmm25, %%zmm11"  & ASCII.LF & ASCII.HT &
        "vpunpcklqdq %%zmm30, %%zmm28, %%zmm12"  & ASCII.LF & ASCII.HT &
        "vpunpcklqdq %%zmm31, %%zmm29, %%zmm13"  & ASCII.LF & ASCII.HT &
        "vpunpckhqdq %%zmm30, %%zmm28, %%zmm14"  & ASCII.LF & ASCII.HT &
        "vpunpckhqdq %%zmm31, %%zmm29, %%zmm15"  & ASCII.LF & ASCII.HT &

        --  Stage 3: vshufi32x4 with imm 0x44 / 0xee. For each Y' in 0..3:
        --    P_{Y'+0}  = vshufi32x4(U_{Y'},   U_{4+Y'},  0x44) → zmm{16+Y'}
        --    P_{Y'+4}  = vshufi32x4(U_{Y'},   U_{4+Y'},  0xee) → zmm{20+Y'}
        --    P_{Y'+8}  = vshufi32x4(U_{8+Y'}, U_{12+Y'}, 0x44) → zmm{24+Y'}
        --    P_{Y'+12} = vshufi32x4(U_{8+Y'}, U_{12+Y'}, 0xee) → zmm{28+Y'}
        "vshufi32x4 $0x44, %%zmm4,  %%zmm0,  %%zmm16" & ASCII.LF & ASCII.HT &
        "vshufi32x4 $0x44, %%zmm5,  %%zmm1,  %%zmm17" & ASCII.LF & ASCII.HT &
        "vshufi32x4 $0x44, %%zmm6,  %%zmm2,  %%zmm18" & ASCII.LF & ASCII.HT &
        "vshufi32x4 $0x44, %%zmm7,  %%zmm3,  %%zmm19" & ASCII.LF & ASCII.HT &
        "vshufi32x4 $0xee, %%zmm4,  %%zmm0,  %%zmm20" & ASCII.LF & ASCII.HT &
        "vshufi32x4 $0xee, %%zmm5,  %%zmm1,  %%zmm21" & ASCII.LF & ASCII.HT &
        "vshufi32x4 $0xee, %%zmm6,  %%zmm2,  %%zmm22" & ASCII.LF & ASCII.HT &
        "vshufi32x4 $0xee, %%zmm7,  %%zmm3,  %%zmm23" & ASCII.LF & ASCII.HT &
        "vshufi32x4 $0x44, %%zmm12, %%zmm8,  %%zmm24" & ASCII.LF & ASCII.HT &
        "vshufi32x4 $0x44, %%zmm13, %%zmm9,  %%zmm25" & ASCII.LF & ASCII.HT &
        "vshufi32x4 $0x44, %%zmm14, %%zmm10, %%zmm26" & ASCII.LF & ASCII.HT &
        "vshufi32x4 $0x44, %%zmm15, %%zmm11, %%zmm27" & ASCII.LF & ASCII.HT &
        "vshufi32x4 $0xee, %%zmm12, %%zmm8,  %%zmm28" & ASCII.LF & ASCII.HT &
        "vshufi32x4 $0xee, %%zmm13, %%zmm9,  %%zmm29" & ASCII.LF & ASCII.HT &
        "vshufi32x4 $0xee, %%zmm14, %%zmm10, %%zmm30" & ASCII.LF & ASCII.HT &
        "vshufi32x4 $0xee, %%zmm15, %%zmm11, %%zmm31" & ASCII.LF & ASCII.HT &

        --  Stage 4: gather P pairs separated by 8 → final zmm0..zmm15.
        --  Y'-mapping: stream's Y bit-1,bit-0 → 0:0, 1:2, 2:1, 3:3
        --    s=0  X=0 Y=0 Y'=0:  vshufi32x4(P0,  P8,  0x88)
        --    s=1  X=0 Y=1 Y'=2:  vshufi32x4(P2,  P10, 0x88)
        --    s=2  X=0 Y=2 Y'=1:  vshufi32x4(P1,  P9,  0x88)
        --    s=3  X=0 Y=3 Y'=3:  vshufi32x4(P3,  P11, 0x88)
        --    s=4..7  X=1: same Y'-mapping but imm=0xdd, sources P_{Y'} and P_{8+Y'}
        --    s=8..11 X=2: imm=0x88, sources P_{4+Y'} and P_{12+Y'}
        --    s=12..15 X=3: imm=0xdd, sources P_{4+Y'} and P_{12+Y'}
        "vshufi32x4 $0x88, %%zmm24, %%zmm16, %%zmm0"  & ASCII.LF & ASCII.HT &
        "vshufi32x4 $0x88, %%zmm26, %%zmm18, %%zmm1"  & ASCII.LF & ASCII.HT &
        "vshufi32x4 $0x88, %%zmm25, %%zmm17, %%zmm2"  & ASCII.LF & ASCII.HT &
        "vshufi32x4 $0x88, %%zmm27, %%zmm19, %%zmm3"  & ASCII.LF & ASCII.HT &
        "vshufi32x4 $0xdd, %%zmm24, %%zmm16, %%zmm4"  & ASCII.LF & ASCII.HT &
        "vshufi32x4 $0xdd, %%zmm26, %%zmm18, %%zmm5"  & ASCII.LF & ASCII.HT &
        "vshufi32x4 $0xdd, %%zmm25, %%zmm17, %%zmm6"  & ASCII.LF & ASCII.HT &
        "vshufi32x4 $0xdd, %%zmm27, %%zmm19, %%zmm7"  & ASCII.LF & ASCII.HT &
        "vshufi32x4 $0x88, %%zmm28, %%zmm20, %%zmm8"  & ASCII.LF & ASCII.HT &
        "vshufi32x4 $0x88, %%zmm30, %%zmm22, %%zmm9"  & ASCII.LF & ASCII.HT &
        "vshufi32x4 $0x88, %%zmm29, %%zmm21, %%zmm10" & ASCII.LF & ASCII.HT &
        "vshufi32x4 $0x88, %%zmm31, %%zmm23, %%zmm11" & ASCII.LF & ASCII.HT &
        "vshufi32x4 $0xdd, %%zmm28, %%zmm20, %%zmm12" & ASCII.LF & ASCII.HT &
        "vshufi32x4 $0xdd, %%zmm30, %%zmm22, %%zmm13" & ASCII.LF & ASCII.HT &
        "vshufi32x4 $0xdd, %%zmm29, %%zmm21, %%zmm14" & ASCII.LF & ASCII.HT &
        "vshufi32x4 $0xdd, %%zmm31, %%zmm23, %%zmm15" & ASCII.LF & ASCII.HT;

   --  XOR each stream's zmm with Buf in place, then store back.
   XOR_Store_Buf : constant String :=
        "vpxorq      (%9), %%zmm0,  %%zmm0"      & ASCII.LF & ASCII.HT &
        "vmovdqu64 %%zmm0,    (%9)"              & ASCII.LF & ASCII.HT &
        "vpxorq    64(%9), %%zmm1,  %%zmm1"      & ASCII.LF & ASCII.HT &
        "vmovdqu64 %%zmm1,  64(%9)"              & ASCII.LF & ASCII.HT &
        "vpxorq   128(%9), %%zmm2,  %%zmm2"      & ASCII.LF & ASCII.HT &
        "vmovdqu64 %%zmm2, 128(%9)"              & ASCII.LF & ASCII.HT &
        "vpxorq   192(%9), %%zmm3,  %%zmm3"      & ASCII.LF & ASCII.HT &
        "vmovdqu64 %%zmm3, 192(%9)"              & ASCII.LF & ASCII.HT &
        "vpxorq   256(%9), %%zmm4,  %%zmm4"      & ASCII.LF & ASCII.HT &
        "vmovdqu64 %%zmm4, 256(%9)"              & ASCII.LF & ASCII.HT &
        "vpxorq   320(%9), %%zmm5,  %%zmm5"      & ASCII.LF & ASCII.HT &
        "vmovdqu64 %%zmm5, 320(%9)"              & ASCII.LF & ASCII.HT &
        "vpxorq   384(%9), %%zmm6,  %%zmm6"      & ASCII.LF & ASCII.HT &
        "vmovdqu64 %%zmm6, 384(%9)"              & ASCII.LF & ASCII.HT &
        "vpxorq   448(%9), %%zmm7,  %%zmm7"      & ASCII.LF & ASCII.HT &
        "vmovdqu64 %%zmm7, 448(%9)"              & ASCII.LF & ASCII.HT &
        "vpxorq   512(%9), %%zmm8,  %%zmm8"      & ASCII.LF & ASCII.HT &
        "vmovdqu64 %%zmm8, 512(%9)"              & ASCII.LF & ASCII.HT &
        "vpxorq   576(%9), %%zmm9,  %%zmm9"      & ASCII.LF & ASCII.HT &
        "vmovdqu64 %%zmm9, 576(%9)"              & ASCII.LF & ASCII.HT &
        "vpxorq   640(%9), %%zmm10, %%zmm10"     & ASCII.LF & ASCII.HT &
        "vmovdqu64 %%zmm10, 640(%9)"             & ASCII.LF & ASCII.HT &
        "vpxorq   704(%9), %%zmm11, %%zmm11"     & ASCII.LF & ASCII.HT &
        "vmovdqu64 %%zmm11, 704(%9)"             & ASCII.LF & ASCII.HT &
        "vpxorq   768(%9), %%zmm12, %%zmm12"     & ASCII.LF & ASCII.HT &
        "vmovdqu64 %%zmm12, 768(%9)"             & ASCII.LF & ASCII.HT &
        "vpxorq   832(%9), %%zmm13, %%zmm13"     & ASCII.LF & ASCII.HT &
        "vmovdqu64 %%zmm13, 832(%9)"             & ASCII.LF & ASCII.HT &
        "vpxorq   896(%9), %%zmm14, %%zmm14"     & ASCII.LF & ASCII.HT &
        "vmovdqu64 %%zmm14, 896(%9)"             & ASCII.LF & ASCII.HT &
        "vpxorq   960(%9), %%zmm15, %%zmm15"     & ASCII.LF & ASCII.HT &
        "vmovdqu64 %%zmm15, 960(%9)"             & ASCII.LF & ASCII.HT;

   procedure Encrypt_1024_InPlace
     (Buf     : in out Byte_Seq;
      K       : in     Bytes_32;
      N       : in     Bytes_12;
      Counter : in     Unsigned_32)
   is
      type U32_256 is array (0 .. 255) of Unsigned_32;  -- 1024 bytes
      Saved : U32_256;
      pragma Warnings (Off, "alignment*");
      for Saved'Alignment use 64;
      pragma Warnings (On, "alignment*");
      Cnt_Reg  : Unsigned_32 := Counter;
      Buf_Addr : constant System.Address := Buf (Buf'First)'Address;
   begin
      Asm
       (--===== State init =====
        "vmovdqa64 (%4), %%zmm0"             & ASCII.LF & ASCII.HT &
        "vmovdqa64 (%5), %%zmm1"             & ASCII.LF & ASCII.HT &
        "vmovdqa64 (%6), %%zmm2"             & ASCII.LF & ASCII.HT &
        "vmovdqa64 (%7), %%zmm3"             & ASCII.LF & ASCII.HT &
        "vpbroadcastd     (%1), %%zmm4"      & ASCII.LF & ASCII.HT &
        "vpbroadcastd    4(%1), %%zmm5"      & ASCII.LF & ASCII.HT &
        "vpbroadcastd    8(%1), %%zmm6"      & ASCII.LF & ASCII.HT &
        "vpbroadcastd   12(%1), %%zmm7"      & ASCII.LF & ASCII.HT &
        "vpbroadcastd   16(%1), %%zmm8"      & ASCII.LF & ASCII.HT &
        "vpbroadcastd   20(%1), %%zmm9"      & ASCII.LF & ASCII.HT &
        "vpbroadcastd   24(%1), %%zmm10"     & ASCII.LF & ASCII.HT &
        "vpbroadcastd   28(%1), %%zmm11"     & ASCII.LF & ASCII.HT &
        "vpbroadcastd  %3, %%zmm12"          & ASCII.LF & ASCII.HT &
        "vpaddd        (%8), %%zmm12, %%zmm12" & ASCII.LF & ASCII.HT &
        "vpbroadcastd     (%2), %%zmm13"     & ASCII.LF & ASCII.HT &
        "vpbroadcastd    4(%2), %%zmm14"     & ASCII.LF & ASCII.HT &
        "vpbroadcastd    8(%2), %%zmm15"     & ASCII.LF & ASCII.HT &

        --  Save originals to scratch.
        "vmovdqa64 %%zmm0,    (%0)"          & ASCII.LF & ASCII.HT &
        "vmovdqa64 %%zmm1,  64(%0)"          & ASCII.LF & ASCII.HT &
        "vmovdqa64 %%zmm2, 128(%0)"          & ASCII.LF & ASCII.HT &
        "vmovdqa64 %%zmm3, 192(%0)"          & ASCII.LF & ASCII.HT &
        "vmovdqa64 %%zmm4, 256(%0)"          & ASCII.LF & ASCII.HT &
        "vmovdqa64 %%zmm5, 320(%0)"          & ASCII.LF & ASCII.HT &
        "vmovdqa64 %%zmm6, 384(%0)"          & ASCII.LF & ASCII.HT &
        "vmovdqa64 %%zmm7, 448(%0)"          & ASCII.LF & ASCII.HT &
        "vmovdqa64 %%zmm8, 512(%0)"          & ASCII.LF & ASCII.HT &
        "vmovdqa64 %%zmm9, 576(%0)"          & ASCII.LF & ASCII.HT &
        "vmovdqa64 %%zmm10, 640(%0)"         & ASCII.LF & ASCII.HT &
        "vmovdqa64 %%zmm11, 704(%0)"         & ASCII.LF & ASCII.HT &
        "vmovdqa64 %%zmm12, 768(%0)"         & ASCII.LF & ASCII.HT &
        "vmovdqa64 %%zmm13, 832(%0)"         & ASCII.LF & ASCII.HT &
        "vmovdqa64 %%zmm14, 896(%0)"         & ASCII.LF & ASCII.HT &
        "vmovdqa64 %%zmm15, 960(%0)"         & ASCII.LF & ASCII.HT &

        --  20 rounds (10 round-pairs).
        Rounds_Body                                              &

        --  Add original state (lane-major sums, ready for transpose).
        "vpaddd    (%0), %%zmm0,  %%zmm0"    & ASCII.LF & ASCII.HT &
        "vpaddd  64(%0), %%zmm1,  %%zmm1"    & ASCII.LF & ASCII.HT &
        "vpaddd 128(%0), %%zmm2,  %%zmm2"    & ASCII.LF & ASCII.HT &
        "vpaddd 192(%0), %%zmm3,  %%zmm3"    & ASCII.LF & ASCII.HT &
        "vpaddd 256(%0), %%zmm4,  %%zmm4"    & ASCII.LF & ASCII.HT &
        "vpaddd 320(%0), %%zmm5,  %%zmm5"    & ASCII.LF & ASCII.HT &
        "vpaddd 384(%0), %%zmm6,  %%zmm6"    & ASCII.LF & ASCII.HT &
        "vpaddd 448(%0), %%zmm7,  %%zmm7"    & ASCII.LF & ASCII.HT &
        "vpaddd 512(%0), %%zmm8,  %%zmm8"    & ASCII.LF & ASCII.HT &
        "vpaddd 576(%0), %%zmm9,  %%zmm9"    & ASCII.LF & ASCII.HT &
        "vpaddd 640(%0), %%zmm10, %%zmm10"   & ASCII.LF & ASCII.HT &
        "vpaddd 704(%0), %%zmm11, %%zmm11"   & ASCII.LF & ASCII.HT &
        "vpaddd 768(%0), %%zmm12, %%zmm12"   & ASCII.LF & ASCII.HT &
        "vpaddd 832(%0), %%zmm13, %%zmm13"   & ASCII.LF & ASCII.HT &
        "vpaddd 896(%0), %%zmm14, %%zmm14"   & ASCII.LF & ASCII.HT &
        "vpaddd 960(%0), %%zmm15, %%zmm15"   & ASCII.LF & ASCII.HT &

        --  4-stage 16×16 u32 transpose: lane-major → stream-major
        --  in zmm0..zmm15 (uses zmm16..zmm31 as scratch).
        Transpose_16x16                                          &

        --  XOR each stream's zmm with Buf in place + store back.
        XOR_Store_Buf                                            &
        "vzeroupper",
        Inputs => (System.Address'Asm_Input ("r", Saved'Address),       --  %0
                   System.Address'Asm_Input ("r", K'Address),           --  %1
                   System.Address'Asm_Input ("r", N'Address),           --  %2
                   Unsigned_32'Asm_Input ("r", Cnt_Reg),                --  %3
                   System.Address'Asm_Input ("r", Sigma0_BC'Address),   --  %4
                   System.Address'Asm_Input ("r", Sigma1_BC'Address),   --  %5
                   System.Address'Asm_Input ("r", Sigma2_BC'Address),   --  %6
                   System.Address'Asm_Input ("r", Sigma3_BC'Address),   --  %7
                   System.Address'Asm_Input ("r", Counter_Offsets'Address), --  %8
                   System.Address'Asm_Input ("r", Buf_Addr)),           --  %9
        Clobber => "xmm0,xmm1,xmm2,xmm3,xmm4,xmm5,xmm6,xmm7," &
                   "xmm8,xmm9,xmm10,xmm11,xmm12,xmm13,xmm14,xmm15," &
                   "xmm16,xmm17,xmm18,xmm19,xmm20,xmm21,xmm22,xmm23," &
                   "xmm24,xmm25,xmm26,xmm27,xmm28,xmm29,xmm30,xmm31," &
                   "memory",
        Volatile => True);
   end Encrypt_1024_InPlace;

begin
   Has_AVX512_ChaCha20 := Detect_AVX512F;
end SPARKTLSCrypto.ChaCha20_AVX512;
