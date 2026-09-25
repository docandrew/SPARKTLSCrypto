with Ada.Text_IO; use Ada.Text_IO;
with Ada.Real_Time; use Ada.Real_Time;
with Interfaces; use Interfaces;
with SPARKNaCl; use SPARKNaCl;
with SPARKNaCl.AES;
with SPARKTLSCrypto.AES_GCM; use SPARKTLSCrypto.AES_GCM;
procedure Bench_Prepared is
   K128 : constant AES.AES128_Key := AES.Construct (Bytes_16'(others => 42));
   K256 : constant AES.AES256_Key := AES.Construct (Bytes_32'(others => 42));
   Context : Prepared_Key;
   AAD : constant Byte_Seq (0 .. 4) := (16#17#, 3, 3, 64, 17);
   Tag : Bytes_16;
   Sink : Byte := 0;
   procedure Run (Len : N32; Bits, Sample : Natural; Cached : Boolean) is
      Buf : Byte_Seq (0 .. Len - 1) := (others => 42);
      Nonce : Bytes_12 := (others => 0);
      Start : Time;
      Elapsed : Duration;
      Count : constant Positive := (if Len > 1024 then 30_000 else 100_000);
   begin
      Start := Clock;
      for J in 1 .. Count loop
         Nonce (0) := Byte (J mod 256);
         Nonce (1) := Byte ((J / 256) mod 256);
         Nonce (2) := Byte (J / 65536);
         if Cached then Encrypt_Prepared (Buf, Tag, Nonce, Context, AAD);
         elsif Bits = 128 then Encrypt_InPlace (Buf, Tag, Nonce, K128, AAD);
         else Encrypt_InPlace_256 (Buf, Tag, Nonce, K256, AAD);
         end if;
         Sink := Sink xor Tag (0);
      end loop;
      Elapsed := To_Duration (Clock - Start);
      Put_Line (Sample'Image & "," & Bits'Image & "," & Len'Image & "," &
                Cached'Image & "," & Long_Float'Image
                  (Long_Float (Elapsed) * 1.0E9 / Long_Float (Count)));
   end Run;
begin
   Put_Line ("sample,bits,length,prepared,ns_per_record");
   for Bits in 1 .. 2 loop
      if Bits = 1 then Prepare_128 (Context, K128);
      else Prepare_256 (Context, K256); end if;
      for Len of Byte_Seq'(1, 4, 16, 64) loop
         for Sample in 0 .. 20 loop
            Run (N32 (Len) * 256 + 1, Bits * 128, Sample, Sample mod 2 = 0);
            Run (N32 (Len) * 256 + 1, Bits * 128, Sample, Sample mod 2 /= 0);
         end loop;
      end loop;
   end loop;
   Put_Line ("sink:" & Sink'Image);
   Clear (Context);
end Bench_Prepared;
