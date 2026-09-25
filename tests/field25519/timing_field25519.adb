with Ada.Text_IO; use Ada.Text_IO;
with Ada.Containers.Generic_Array_Sort;
with Ada.Numerics.Long_Elementary_Functions; use Ada.Numerics.Long_Elementary_Functions;
with Interfaces; use Interfaces;
with SPARKNaCl; use SPARKNaCl;
with SPARKTLSCrypto.X25519;
with SPARKTLSCrypto.Ed25519;
procedure Timing_Field25519 is
   function Ticks return Unsigned_64
     with Import, Convention => C, External_Name => "field25519_ticks";
   procedure Canary (Secret : Byte)
     with Import, Convention => C, External_Name => "field25519_timing_canary";
   type Samples is array (Positive range <>) of Unsigned_64;
   procedure Sort is new Ada.Containers.Generic_Array_Sort (Positive, Unsigned_64, Samples);
   type Mode is (X25519_Mult, Ed25519_Sign, Negative_Control);
   Seed : Unsigned_64 := 16#ecaefabcdef#;
   procedure Test (Operation : Mode) is
      Count : constant Positive := 40_000;
      T0, T1 : Samples (1 .. Count);
      N0, N1 : Natural := 0;
      B : Byte;
      Raw, Q, PK : Bytes_32;
      SK : Bytes_64;
      Signature : Byte_Seq (0 .. 95);
      Basepoint : constant Bytes_32 := (9, others => 0);
      Message : constant Byte_Seq (0 .. 31) := (others => 42);
      type Key_Array is array (0 .. 1) of Bytes_64;
      Keys : Key_Array;
      Start, Cycles : Unsigned_64;
      procedure Subject is
      begin
         case Operation is
            when X25519_Mult => SPARKTLSCrypto.X25519.Scalar_Mult (Q, Raw, Basepoint);
            when Ed25519_Sign => SPARKTLSCrypto.Ed25519.Sign (Signature, Message, SK);
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
      Raw := (others => 0);
      SPARKTLSCrypto.Ed25519.Keypair (Raw, PK, Keys (0));
      Raw := (others => 255);
      SPARKTLSCrypto.Ed25519.Keypair (Raw, PK, Keys (1));
      while N0 < Count or N1 < Count loop
         --  Random class order, independent of measured elapsed time.
         Seed := Seed xor Shift_Left (Seed, 13);
         Seed := Seed xor Shift_Right (Seed, 7);
         Seed := Seed xor Shift_Left (Seed, 17);
         B := (if (Seed and 1) = 0 then 0 else 255);
         if (B = 0 and N0 < Count) or (B /= 0 and N1 < Count) then
            Raw := (others => B);
            SK := Keys (if B = 0 then 0 else 1);
            --  All classes use the same scalar, key and output addresses.
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
         Put_Line (Operation'Image &
                   " raw_t=" & Raw_T'Image & " trimmed_99pct_t=" & Trim_T'Image);
         if Operation = Negative_Control then
            if abs Raw_T < 4.5 or abs Trim_T < 4.5 then
               raise Program_Error with "timing negative control not detected";
            end if;
         elsif abs Raw_T >= 4.5 or abs Trim_T >= 4.5 then
            raise Program_Error with "key-class timing correlation requires investigation";
         end if;
      end;
      SPARKNaCl.Sanitize (Byte_Seq (Raw));
      SPARKNaCl.Sanitize (Byte_Seq (SK));
   end Test;
begin
   Test (Negative_Control);
   Test (X25519_Mult);
   Test (Ed25519_Sign);
end Timing_Field25519;
