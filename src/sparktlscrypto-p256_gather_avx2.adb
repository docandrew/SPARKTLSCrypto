--  AVX2 fixed-base table gather (body). See sparktlscrypto-p256_gather_avx2.ads.
--
--  SPARK_Mode Off: inline assembly. The row is 64 entries of 64 bytes
--  (X then Y, four limbs each, as Fixed_Base.Affine_Mont lays them out).
--  ymm3 counts k + 1 in every lane, ymm2 holds Mag; vpcmpeqq gives the
--  all-ones mask for the wanted entry and zero elsewhere, and the masked
--  entries are or-ed into the accumulators. Every entry is loaded on
--  every call; the loop count is the constant 64. The accumulators and
--  the mask registers, which hold the selected point, are cleared before
--  vzeroupper.

with System;
with System.Machine_Code; use System.Machine_Code;

package body SPARKTLSCrypto.P256_Gather_AVX2 with
   SPARK_Mode => Off
is
   procedure Gather
     (Dst : out Affine_Mont;
      Row : in  Window_Row;
      Mag : in  Unsigned_32)
   is
      Mag64 : constant Unsigned_64 := Unsigned_64 (Mag);
   begin
      Asm (
         "    vpxor  %%ymm0, %%ymm0, %%ymm0" & ASCII.LF &
         "    vpxor  %%ymm1, %%ymm1, %%ymm1" & ASCII.LF &
         "    vmovq  %2, %%xmm2" & ASCII.LF &
         "    vpbroadcastq %%xmm2, %%ymm2" & ASCII.LF &
         "    mov    $1, %%eax" & ASCII.LF &
         "    vmovq  %%rax, %%xmm3" & ASCII.LF &
         "    vpbroadcastq %%xmm3, %%ymm3" & ASCII.LF &
         "    vpbroadcastq %%xmm3, %%ymm4" & ASCII.LF &
         "    mov    $64, %%ecx" & ASCII.LF &
         "    mov    %1, %%rdx" & ASCII.LF &
         "1:" & ASCII.LF &
         "    vpcmpeqq %%ymm2, %%ymm3, %%ymm5" & ASCII.LF &
         "    vpand  (%%rdx), %%ymm5, %%ymm6" & ASCII.LF &
         "    vpand  32(%%rdx), %%ymm5, %%ymm7" & ASCII.LF &
         "    vpor   %%ymm6, %%ymm0, %%ymm0" & ASCII.LF &
         "    vpor   %%ymm7, %%ymm1, %%ymm1" & ASCII.LF &
         "    vpaddq %%ymm4, %%ymm3, %%ymm3" & ASCII.LF &
         "    add    $64, %%rdx" & ASCII.LF &
         "    dec    %%ecx" & ASCII.LF &
         "    jnz    1b" & ASCII.LF &
         "    vmovdqu %%ymm0, (%0)" & ASCII.LF &
         "    vmovdqu %%ymm1, 32(%0)" & ASCII.LF &
         "    vpxor  %%ymm0, %%ymm0, %%ymm0" & ASCII.LF &
         "    vpxor  %%ymm1, %%ymm1, %%ymm1" & ASCII.LF &
         "    vpxor  %%ymm5, %%ymm5, %%ymm5" & ASCII.LF &
         "    vpxor  %%ymm6, %%ymm6, %%ymm6" & ASCII.LF &
         "    vpxor  %%ymm7, %%ymm7, %%ymm7" & ASCII.LF &
         "    vzeroupper" & ASCII.LF,
         Inputs   => (System.Address'Asm_Input ("r", Dst'Address),
                      System.Address'Asm_Input ("r", Row'Address),
                      Unsigned_64'Asm_Input ("r", Mag64)),
         Clobber  => "rax,rcx,rdx,xmm0,xmm1,xmm2,xmm3,xmm4,xmm5,xmm6,xmm7,"
                     & "memory,cc",
         Volatile => True);
   end Gather;

end SPARKTLSCrypto.P256_Gather_AVX2;
