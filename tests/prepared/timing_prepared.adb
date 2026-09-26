with Ada.Text_IO; use Ada.Text_IO;
with Ada.Containers.Generic_Array_Sort;
with Ada.Numerics.Long_Elementary_Functions; use Ada.Numerics.Long_Elementary_Functions;
with Interfaces; use Interfaces;
with SPARKNaCl; use SPARKNaCl;
with SPARKNaCl.AES;
with SPARKTLSCrypto.AES_GCM; use SPARKTLSCrypto.AES_GCM;
procedure Timing_Prepared is
   function Ticks return Unsigned_64
     with Import, Convention => C, External_Name => "prepared_ticks";
   procedure Canary (Secret : Byte)
     with Import, Convention => C, External_Name => "prepared_timing_canary";
   type Samples is array (Positive range <>) of Unsigned_64;
   procedure Sort is new Ada.Containers.Generic_Array_Sort (Positive, Unsigned_64, Samples);
   type Mode is (Cached, Setup, Negative_Control);
   Seed : Unsigned_64 := 16#ecaefabcdef#;
   procedure Test (Bits : Positive; Len : N32; Operation : Mode) is
      Count : constant Positive := 40_000;
      T0, T1 : Samples (1 .. Count);
      N0, N1 : Natural := 0;
      Context : Prepared_Key;
      B : Byte;
      Raw : Bytes_32;
      K128 : AES.AES128_Key;
      K256 : AES.AES256_Key;
      Buf : Byte_Seq (0 .. Len - 1) := (others => 17);
      Tag : Bytes_16;
      Nonce : constant Bytes_12 := (others => 23);
      AAD : constant Byte_Seq (0 .. 4) := (others => 42);
      Start, Cycles : Unsigned_64;
      procedure Subject is
      begin
         case Operation is
            when Cached => Encrypt_Prepared (Buf, Tag, Nonce, Context, AAD);
            when Setup =>
               if Bits = 128 then Prepare_128 (Context, K128);
               else Prepare_256 (Context, K256); end if;
            when Negative_Control => Canary (B);
         end case;
      end Subject;
      function Statistic (Trim : Natural) return Long_Float is
         Last : constant Positive := Count - Trim;
         M0, M1, V0, V1 : Long_Float := 0.0;
      begin
         for I in 1 .. Last loop
            M0 := M0 + Long_Float (T0 (I)); M1 := M1 + Long_Float (T1 (I));
         end loop;
         M0 := M0 / Long_Float (Last); M1 := M1 / Long_Float (Last);
         for I in 1 .. Last loop
            V0 := V0 + (Long_Float (T0 (I)) - M0) ** 2;
            V1 := V1 + (Long_Float (T1 (I)) - M1) ** 2;
         end loop;
         V0 := V0 / Long_Float (Last - 1); V1 := V1 / Long_Float (Last - 1);
         return (M0 - M1) / Sqrt ((V0 + V1) / Long_Float (Last));
      end Statistic;
   begin
      while N0 < Count or N1 < Count loop
         --  Random class order, independent of measured elapsed time.
         Seed := Seed xor Shift_Left (Seed, 13);
         Seed := Seed xor Shift_Right (Seed, 7);
         Seed := Seed xor Shift_Left (Seed, 17);
         B := (if (Seed and 1) = 0 then 0 else 255);
         if (B = 0 and N0 < Count) or (B /= 0 and N1 < Count) then
            Raw := (others => B);
            AES.Construct (K128, Raw (0 .. 15)); AES.Construct (K256, Raw);
            if Bits = 128 then Prepare_128 (Context, K128);
            else Prepare_256 (Context, K256); end if;
            --  All classes use the same context and buffer addresses.
            Subject;
            Start := Ticks;
            Subject;
            Cycles := Ticks - Start;
            if B = 0 then N0 := N0 + 1; T0 (N0) := Cycles;
            else N1 := N1 + 1; T1 (N1) := Cycles; end if;
         end if;
      end loop;
      Sort (T0); Sort (T1);
      declare
         Raw_T : constant Long_Float := Statistic (0);
         Trim_T : constant Long_Float := Statistic (Count / 100);
      begin
         Put_Line (Operation'Image & " bits=" & Bits'Image & " len=" & Len'Image &
                   " raw_t=" & Raw_T'Image & " trimmed_99pct_t=" & Trim_T'Image);
         if Operation = Negative_Control then
            if abs Raw_T < 4.5 or abs Trim_T < 4.5 then
               raise Program_Error with "timing negative control not detected";
            end if;
         elsif abs Raw_T >= 4.5 or abs Trim_T >= 4.5 then
            raise Program_Error with "key-class timing correlation requires investigation";
         end if;
      end;
      Clear (Context); AES.Sanitize (K128); AES.Sanitize (K256);
   end Test;
begin
   Test (128, 257, Negative_Control);
   for Bits in 1 .. 2 loop
      Test (Bits * 128, 257, Setup);
      Test (Bits * 128, 257, Cached);
      Test (Bits * 128, 16385, Cached);
   end loop;
end Timing_Prepared;
