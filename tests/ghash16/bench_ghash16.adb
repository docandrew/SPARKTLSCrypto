with Ada.Text_IO; use Ada.Text_IO;
with Ada.Real_Time; use Ada.Real_Time;
with SPARKNaCl; use SPARKNaCl;
with SPARKTLSCrypto.AES_GCM_AVX512; use SPARKTLSCrypto.AES_GCM_AVX512;
procedure Bench_GHASH16 is
   H : constant Bytes_16 := (others => 42);
   Powers : Pre_H_Powers_16;
   Blocks : constant Byte_Seq (7 .. 262) := (others => 23);
   S : Bytes_16 := (others => 17);
   Count : constant Positive := 1_000_000;
   Start : Time;
begin
   if not Has_AVX512_AES_GCM then
      raise Program_Error with "GHASH16 benchmark requires the AVX-512 tier";
   end if;
   Compute_H_Powers_16 (H, Powers);
   Put_Line ("sample,ns_per_batch");
   for Sample in 0 .. 20 loop
      Start := Clock;
      for I in 1 .. Count loop
         GHASH_16_Blocks (S, Blocks, Powers);
      end loop;
      Put_Line (Sample'Image & "," & Long_Float'Image
        (Long_Float (To_Duration (Clock - Start)) * 1.0E9 / Long_Float (Count)));
   end loop;
   Put_Line ("sink:" & S (0)'Image);
end Bench_GHASH16;
