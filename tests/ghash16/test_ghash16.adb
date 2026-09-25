with Ada.Text_IO; use Ada.Text_IO;
with Interfaces; use Interfaces;
with SPARKNaCl; use SPARKNaCl;
with SPARKTLSCrypto.AES_GCM_AVX512; use SPARKTLSCrypto.AES_GCM_AVX512;
procedure Test_GHASH16 is
   --  Independent bit-serial definition, in NIST byte order.
   function Multiply (X, Y : Bytes_16) return Bytes_16 is
      V : Bytes_16 := X;
      Z : Bytes_16 := (others => 0);
      Carry, Next, Low : Byte;
   begin
      for Bit in 0 .. 127 loop
         if (Y (N32 (Bit / 8)) and
             Byte (Shift_Right (Unsigned_8 (128), Bit mod 8))) /= 0
         then
            for J in Z'Range loop Z (J) := Z (J) xor V (J); end loop;
         end if;
         Low := V (15) and 1;
         Carry := 0;
         for J in V'Range loop
            Next := V (J) and 1;
            V (J) := Byte (Shift_Right (Unsigned_8 (V (J)), 1))
              or Byte (Shift_Left (Unsigned_8 (Carry), 7));
            Carry := Next;
         end loop;
         if Low /= 0 then V (0) := V (0) xor 16#E1#; end if;
      end loop;
      return Z;
   end Multiply;
   function Reference (S, H : Bytes_16; B : Byte_Seq) return Bytes_16 is
      R : Bytes_16 := S;
   begin
      for Block in 0 .. 15 loop
         for J in R'Range loop
            R (J) := R (J) xor B (B'First + N32 (Block * 16) + J);
         end loop;
         R := Multiply (R, H);
      end loop;
      return R;
   end Reference;
   Seed : Unsigned_64 := 16#c001_1234_9876_ffee#;
   Digest : Unsigned_64 := 16#cbf29ce484222325#;
   Count : Natural := 0;
   function Random_Byte return Byte is
   begin
      Seed := Seed xor Shift_Left (Seed, 13);
      Seed := Seed xor Shift_Right (Seed, 7);
      Seed := Seed xor Shift_Left (Seed, 17);
      return Byte (Seed and 255);
   end Random_Byte;
   procedure Check (Got, Expected : Bytes_16) is
   begin
      Count := Count + 1;
      if Got /= Expected then
         raise Program_Error with "GHASH16 mismatch at case" & Count'Image;
      end if;
      for B of Got loop
         Digest := (Digest xor Unsigned_64 (B)) * 16#100000001b3#;
      end loop;
   end Check;
   H, S, Expected : Bytes_16;
   Powers : Pre_H_Powers_16;
   B : Byte_Seq (0 .. 255);
begin
   if not Has_AVX512_AES_GCM then
      Put_Line ("SKIP: AVX-512 AES-GCM unavailable");
      return;
   end if;
   --  Basis pairs test the actual multiply and reduction for every bit
   --  position in both operands (the last block is multiplied by H).
   for I in 0 .. 127 loop
      H := (others => 0);
      H (N32 (I / 8)) := Byte (Shift_Left (Unsigned_8 (1), I mod 8));
      Compute_H_Powers_16 (H, Powers);
      for J in 0 .. 127 loop
         B := (others => 0);
         B (240 + N32 (J / 8)) :=
           Byte (Shift_Left (Unsigned_8 (1), J mod 8));
         S := (others => 0);
         Expected := Multiply (B (240 .. 255), H);
         GHASH_16_Blocks (S, B, Powers);
         Check (S, Expected);
      end loop;
   end loop;
   --  Exercise all powers and the incoming accumulator, chained batches,
   --  every 64-byte alignment, nonzero bounds, and immutable input guards.
   for Trial in 0 .. 1023 loop
      declare
         Storage : Byte_Seq (11 .. 330);
         for Storage'Alignment use 64;
         Offset : constant N32 := 11 + N32 (Trial mod 64);
      begin
         for I in H'Range loop
            H (I) := Random_Byte;
            S (I) := Random_Byte;
         end loop;
         if Trial = 0 then H := (others => 0);
         elsif Trial = 1 then H := (others => 255);
         elsif Trial = 2 then H := (others => 0); H (0) := 128;
         end if;
         Compute_H_Powers_16 (H, Powers);
         declare
            Saved_Powers : constant Pre_H_Powers_16 := Powers;
         begin
            for Batch in 1 .. 4 loop
               for I in Storage'Range loop Storage (I) := Random_Byte; end loop;
               declare
                  Saved : constant Byte_Seq := Storage;
                  Guarded : Byte_Seq (0 .. 47) := (others => 16#A5#);
               begin
                  Guarded (16 .. 31) := S;
                  Expected := Reference (S, H, Storage (Offset .. Offset + 255));
                  GHASH_16_Blocks
                    (Guarded (16 .. 31), Storage (Offset .. Offset + 255), Powers);
                  S := Guarded (16 .. 31);
                  Check (S, Expected);
                  if Storage /= Saved or Powers /= Saved_Powers
                    or Guarded (0 .. 15) /= Byte_Seq'(0 .. 15 => 16#A5#)
                    or Guarded (32 .. 47) /= Byte_Seq'(0 .. 15 => 16#A5#)
                  then
                     raise Program_Error with "GHASH16 input/guard mutation";
                  end if;
               end;
            end loop;
         end;
      end;
   end loop;
   if Digest /= 6_845_349_442_263_933_923 then
      raise Program_Error with "pre-optimization golden digest changed";
   end if;
   Put_Line ("PASS:" & Count'Image & " independent GHASH16 comparisons");
   Put_Line ("digest:" & Digest'Image);
end Test_GHASH16;
