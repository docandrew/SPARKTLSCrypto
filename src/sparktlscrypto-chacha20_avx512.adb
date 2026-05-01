--  AVX-512 ChaCha20 16-block batch (RFC 8439). Body — see spec.
--
--  Algorithm: Initialize 16 ChaCha20 states in zmm0..zmm15
--  (lane-major: each zmm = same state word across 16 streams).
--  Run 20 rounds = 10 × (column-round + diagonal-round). Add original
--  state. Save lane-major to a 1024-byte scratch. Ada then does the
--  transpose + XOR with Buf.
--
--  This first version keeps the transpose in Ada (correctness over
--  speed — the asm-side vpunpck/vshufi transpose is a TODO). The
--  rounds (the bulk of the work) ARE in asm, so we still get most
--  of the SIMD speedup.

with System.Machine_Code; use System.Machine_Code;
with Interfaces;          use Interfaces;
with SPARKNaCl;           use SPARKNaCl;

package body SPARKTLSCrypto.ChaCha20_AVX512 with
   SPARK_Mode => Off
is

   --================================================================
   --  CPUID detection: AVX-512F (CPUID.7.0.EBX[16]).
   --================================================================
   function Detect_AVX512F return Boolean is
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
   end Detect_AVX512F;

   --================================================================
   --  Constants — 64-byte aligned for vmovdqa64.
   --================================================================
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

   --================================================================
   --  Round-pair string fragment (column round + diagonal round).
   --  Used 10 times in the asm body to make 20 rounds total.
   --================================================================
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
      Cnt_Reg : Unsigned_32 := Counter;
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

        --  Add original state.
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

        --  Save final lane-major state to scratch (Saved). Ada
        --  transposes + XORs below.
        "vmovdqu64 %%zmm0,    (%0)"          & ASCII.LF & ASCII.HT &
        "vmovdqu64 %%zmm1,  64(%0)"          & ASCII.LF & ASCII.HT &
        "vmovdqu64 %%zmm2, 128(%0)"          & ASCII.LF & ASCII.HT &
        "vmovdqu64 %%zmm3, 192(%0)"          & ASCII.LF & ASCII.HT &
        "vmovdqu64 %%zmm4, 256(%0)"          & ASCII.LF & ASCII.HT &
        "vmovdqu64 %%zmm5, 320(%0)"          & ASCII.LF & ASCII.HT &
        "vmovdqu64 %%zmm6, 384(%0)"          & ASCII.LF & ASCII.HT &
        "vmovdqu64 %%zmm7, 448(%0)"          & ASCII.LF & ASCII.HT &
        "vmovdqu64 %%zmm8, 512(%0)"          & ASCII.LF & ASCII.HT &
        "vmovdqu64 %%zmm9, 576(%0)"          & ASCII.LF & ASCII.HT &
        "vmovdqu64 %%zmm10, 640(%0)"         & ASCII.LF & ASCII.HT &
        "vmovdqu64 %%zmm11, 704(%0)"         & ASCII.LF & ASCII.HT &
        "vmovdqu64 %%zmm12, 768(%0)"         & ASCII.LF & ASCII.HT &
        "vmovdqu64 %%zmm13, 832(%0)"         & ASCII.LF & ASCII.HT &
        "vmovdqu64 %%zmm14, 896(%0)"         & ASCII.LF & ASCII.HT &
        "vmovdqu64 %%zmm15, 960(%0)"         & ASCII.LF & ASCII.HT &
        "vzeroupper",
        Inputs => (System.Address'Asm_Input ("r", Saved'Address),       --  %0
                   System.Address'Asm_Input ("r", K'Address),           --  %1
                   System.Address'Asm_Input ("r", N'Address),           --  %2
                   Unsigned_32'Asm_Input ("r", Cnt_Reg),                --  %3
                   System.Address'Asm_Input ("r", Sigma0_BC'Address),   --  %4
                   System.Address'Asm_Input ("r", Sigma1_BC'Address),   --  %5
                   System.Address'Asm_Input ("r", Sigma2_BC'Address),   --  %6
                   System.Address'Asm_Input ("r", Sigma3_BC'Address),   --  %7
                   System.Address'Asm_Input ("r", Counter_Offsets'Address)),  --  %8
        Clobber => "xmm0,xmm1,xmm2,xmm3,xmm4,xmm5,xmm6,xmm7," &
                   "xmm8,xmm9,xmm10,xmm11,xmm12,xmm13,xmm14,xmm15,memory",
        Volatile => True);

      --  Transpose lane-major (Saved) -> stream-major + XOR with Buf.
      --  Saved has the layout: Saved[word][stream] (16 streams × 16 words),
      --  i.e. Saved (W * 16 + S) is state word W of stream S.
      declare
         Buf_First : constant N32 := Buf'First;
      begin
         for Stream in 0 .. 15 loop
            for Word in 0 .. 15 loop
               declare
                  W : constant Unsigned_32 := Saved (Word * 16 + Stream);
                  Off : constant N32 :=
                     Buf_First + N32 (Stream) * 64 + N32 (Word) * 4;
               begin
                  Buf (Off)     := Buf (Off)     xor Byte (W and 16#FF#);
                  Buf (Off + 1) := Buf (Off + 1) xor
                                     Byte (Shift_Right (W,  8) and 16#FF#);
                  Buf (Off + 2) := Buf (Off + 2) xor
                                     Byte (Shift_Right (W, 16) and 16#FF#);
                  Buf (Off + 3) := Buf (Off + 3) xor
                                     Byte (Shift_Right (W, 24) and 16#FF#);
               end;
            end loop;
         end loop;
      end;
   end Encrypt_1024_InPlace;

begin
   Has_AVX512_ChaCha20 := Detect_AVX512F;
end SPARKTLSCrypto.ChaCha20_AVX512;
