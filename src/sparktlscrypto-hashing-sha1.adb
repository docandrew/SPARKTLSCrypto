--  SPARKTLS SHA-1 -- software only, fully SPARK (see the spec for scope)
--
--  FIPS 180-4 6.1. The streaming state machine is the SHA-256 unit's,
--  verbatim; only the block function and the state width differ.

with Interfaces; use Interfaces;

package body SPARKTLSCrypto.Hashing.SHA1 with
   SPARK_Mode => On
is
   type W_Array is array (0 .. 15) of Unsigned_32;

   function Ch (X, Y, Z : Unsigned_32) return Unsigned_32 is
     ((X and Y) xor ((not X) and Z));

   function Parity (X, Y, Z : Unsigned_32) return Unsigned_32 is
     (X xor Y xor Z);

   function Maj (X, Y, Z : Unsigned_32) return Unsigned_32 is
     ((X and Y) xor (X and Z) xor (Y and Z));

   function Load_BE32 (Data : Byte_Seq; Pos : N32) return Unsigned_32 is
     (Shift_Left (Unsigned_32 (Data (Pos)), 24) or
      Shift_Left (Unsigned_32 (Data (Pos + 1)), 16) or
      Shift_Left (Unsigned_32 (Data (Pos + 2)), 8) or
      Unsigned_32 (Data (Pos + 3)))
   with Pre => Data'Last >= 3 and then Pos >= Data'First
               and then Pos <= Data'Last - 3;

   procedure Process_Block
     (S    : in out State_Array;
      Data : Byte_Seq;
      Pos  : N32)
   with Global => null, Always_Terminates,
        Pre => Data'Last >= 63 and then Data'First <= Pos
               and then Pos <= Data'Last - 63
   is
      A : Unsigned_32 := S (0);
      B : Unsigned_32 := S (1);
      C : Unsigned_32 := S (2);
      D : Unsigned_32 := S (3);
      E : Unsigned_32 := S (4);
      T : Unsigned_32;
      F : Unsigned_32;
      K : Unsigned_32;
      W : W_Array;
   begin
      for I in 0 .. 15 loop
         W (I) := Load_BE32 (Data, Pos + N32 (I * 4));
      end loop;

      for I in 0 .. 79 loop
         if I >= 16 then
            --  FIPS 180-4 6.1.2 step 1: W(t) = ROTL1 (W(t-3) xor W(t-8)
            --  xor W(t-14) xor W(t-16)), kept in a 16-word ring.
            W (I mod 16) :=
              Rotate_Left
                (W ((I - 3) mod 16) xor W ((I - 8) mod 16) xor
                 W ((I - 14) mod 16) xor W (I mod 16), 1);
         end if;

         if I < 20 then
            F := Ch (B, C, D);     K := 16#5A827999#;
         elsif I < 40 then
            F := Parity (B, C, D); K := 16#6ED9EBA1#;
         elsif I < 60 then
            F := Maj (B, C, D);    K := 16#8F1BBCDC#;
         else
            F := Parity (B, C, D); K := 16#CA62C1D6#;
         end if;

         T := Rotate_Left (A, 5) + F + E + K + W (I mod 16);
         E := D;
         D := C;
         C := Rotate_Left (B, 30);
         B := A;
         A := T;
      end loop;

      S (0) := S (0) + A;
      S (1) := S (1) + B;
      S (2) := S (2) + C;
      S (3) := S (3) + D;
      S (4) := S (4) + E;
   end Process_Block;

   procedure State_To_Digest (Output : out Digest; S : State_Array) is
   begin
      Output := (others => 0);
      for I in 0 .. 4 loop
         Output (I32 (I * 4))     := Byte (Shift_Right (S (I), 24));
         Output (I32 (I * 4 + 1)) := Byte (Shift_Right (S (I), 16) and 16#FF#);
         Output (I32 (I * 4 + 2)) := Byte (Shift_Right (S (I), 8) and 16#FF#);
         Output (I32 (I * 4 + 3)) := Byte (S (I) and 16#FF#);
      end loop;
   end State_To_Digest;

   ----------------------------------------------------------------------------
   --  Streaming (incremental) interface -- identical to the SHA-256 unit
   ----------------------------------------------------------------------------

   procedure Init (Ctx : out Context) is
   begin
      Ctx.State   := Init_State;
      Ctx.Buffer  := (others => 0);
      Ctx.Buf_Len := 0;
      Ctx.Total   := 0;
   end Init;

   procedure Update (Ctx : in out Context; Data : Byte_Seq) is
      Pos       : I32 := Data'First;
      Remaining : N32;
      Space     : N32;
   begin
      if Data'Length = 0 then
         return;
      end if;
      Remaining := N32 (Data'Length);

      --  Fill partial buffer
      if Ctx.Buf_Len > 0 then
         Space := 64 - Ctx.Buf_Len;
         if Remaining < Space then
            Ctx.Buffer (Ctx.Buf_Len .. Ctx.Buf_Len + Remaining - 1) :=
              Data (Pos .. Pos + Remaining - 1);
            Ctx.Buf_Len := Ctx.Buf_Len + Remaining;
            Ctx.Total := Ctx.Total + Unsigned_64 (Remaining);
            return;
         end if;
         Ctx.Buffer (Ctx.Buf_Len .. 63) :=
           Data (Pos .. Pos + Space - 1);
         Process_Block (Ctx.State, Ctx.Buffer, 0);
         Pos := Pos + Space;
         Remaining := Remaining - Space;
         Ctx.Buf_Len := 0;
      end if;

      --  Process full blocks directly
      while Remaining >= 64 loop
         pragma Loop_Variant (Decreases => Remaining);
         pragma Loop_Invariant
           (Pos >= Data'First and then Remaining >= 0
              and then Pos + Remaining - 1 = Data'Last);
         Process_Block (Ctx.State, Data, Pos);
         Pos := Pos + 64;
         Remaining := Remaining - 64;
      end loop;

      --  Buffer remainder
      if Remaining > 0 then
         Ctx.Buffer (0 .. Remaining - 1) := Data (Pos .. Pos + Remaining - 1);
         Ctx.Buf_Len := Remaining;
      end if;

      Ctx.Total := Ctx.Total + Unsigned_64 (Data'Length);
   end Update;

   procedure Final (Ctx : in out Context; Output : out Digest) is
      Bit_Len : constant Unsigned_64 := Ctx.Total * 8;
      P       : N32;
   begin
      --  Append 0x80
      Ctx.Buffer (Ctx.Buf_Len) := 16#80#;
      P := Ctx.Buf_Len + 1;

      --  Need room for 8-byte length; if not, pad+process extra block
      if P > 56 then
         for I in P .. 63 loop
            Ctx.Buffer (I) := 0;
         end loop;
         Process_Block (Ctx.State, Ctx.Buffer, 0);
         P := 0;
      end if;

      --  Pad zeros up to length field
      for I in P .. 55 loop
         Ctx.Buffer (I) := 0;
      end loop;

      --  Big-endian 64-bit length
      for I in 0 .. 7 loop
         Ctx.Buffer (56 + I32 (I)) :=
           Byte (Shift_Right (Bit_Len, (7 - I) * 8) and 16#FF#);
      end loop;

      Process_Block (Ctx.State, Ctx.Buffer, 0);
      State_To_Digest (Output, Ctx.State);
   end Final;

   ----------------------------------------------------------------------------
   --  One-shot interface (built on streaming)
   ----------------------------------------------------------------------------

   procedure Hash (Output : out Digest; M : in Byte_Seq) is
      Ctx : Context;
   begin
      Init (Ctx);
      Update (Ctx, M);
      Final (Ctx, Output);
   end Hash;

   function Hash (M : in Byte_Seq) return Digest is
      D : Digest;
   begin
      Hash (D, M);
      return D;
   end Hash;

end SPARKTLSCrypto.Hashing.SHA1;
