--  Shared FIPS 180-4 SHA-512-family streaming machinery; see spec.
--  Transplanted verbatim from the (KAT-verified) SHA-384 unit of
--  2026-08-25, with the IV taken from the generic formals and the
--  final truncation driven by Digest_Bytes.

with Interfaces; use Interfaces;

package body SPARKTLSCrypto.Hashing.SHA512_Family_G with
   SPARK_Mode => On
is
   --  FIPS 180-4 4.2.3: SHA-512 round constants.
   K : constant array (0 .. 79) of Unsigned_64 :=
     (16#428A2F98D728AE22#, 16#7137449123EF65CD#,
      16#B5C0FBCFEC4D3B2F#, 16#E9B5DBA58189DBBC#,
      16#3956C25BF348B538#, 16#59F111F1B605D019#,
      16#923F82A4AF194F9B#, 16#AB1C5ED5DA6D8118#,
      16#D807AA98A3030242#, 16#12835B0145706FBE#,
      16#243185BE4EE4B28C#, 16#550C7DC3D5FFB4E2#,
      16#72BE5D74F27B896F#, 16#80DEB1FE3B1696B1#,
      16#9BDC06A725C71235#, 16#C19BF174CF692694#,
      16#E49B69C19EF14AD2#, 16#EFBE4786384F25E3#,
      16#0FC19DC68B8CD5B5#, 16#240CA1CC77AC9C65#,
      16#2DE92C6F592B0275#, 16#4A7484AA6EA6E483#,
      16#5CB0A9DCBD41FBD4#, 16#76F988DA831153B5#,
      16#983E5152EE66DFAB#, 16#A831C66D2DB43210#,
      16#B00327C898FB213F#, 16#BF597FC7BEEF0EE4#,
      16#C6E00BF33DA88FC2#, 16#D5A79147930AA725#,
      16#06CA6351E003826F#, 16#142929670A0E6E70#,
      16#27B70A8546D22FFC#, 16#2E1B21385C26C926#,
      16#4D2C6DFC5AC42AED#, 16#53380D139D95B3DF#,
      16#650A73548BAF63DE#, 16#766A0ABB3C77B2A8#,
      16#81C2C92E47EDAEE6#, 16#92722C851482353B#,
      16#A2BFE8A14CF10364#, 16#A81A664BBC423001#,
      16#C24B8B70D0F89791#, 16#C76C51A30654BE30#,
      16#D192E819D6EF5218#, 16#D69906245565A910#,
      16#F40E35855771202A#, 16#106AA07032BBD1B8#,
      16#19A4C116B8D2D0C8#, 16#1E376C085141AB53#,
      16#2748774CDF8EEB99#, 16#34B0BCB5E19B48A8#,
      16#391C0CB3C5C95A63#, 16#4ED8AA4AE3418ACB#,
      16#5B9CCA4F7763E373#, 16#682E6FF3D6B2B8A3#,
      16#748F82EE5DEFB2FC#, 16#78A5636F43172F60#,
      16#84C87814A1F0AB72#, 16#8CC702081A6439EC#,
      16#90BEFFFA23631E28#, 16#A4506CEBDE82BDE9#,
      16#BEF9A3F7B2C67915#, 16#C67178F2E372532B#,
      16#CA273ECEEA26619C#, 16#D186B8C721C0C207#,
      16#EADA7DD6CDE0EB1E#, 16#F57D4F7FEE6ED178#,
      16#06F067AA72176FBA#, 16#0A637DC5A2C898A6#,
      16#113F9804BEF90DAE#, 16#1B710B35131C471B#,
      16#28DB77F523047D84#, 16#32CAAB7B40C72493#,
      16#3C9EBE0A15C9BEBC#, 16#431D67C49C100D4C#,
      16#4CC5D4BECB3E42B6#, 16#597F299CFC657E2A#,
      16#5FCB6FAB3AD6FAEC#, 16#6C44198C4A475817#);

   function Rotr (X : Unsigned_64; N : Natural) return Unsigned_64 is
     (Rotate_Right (X, N))
   with Inline;

   procedure Process_Block
     (State : in out State_Array;
      Data  : in     Byte_Seq;
      Base  : in     N32)
   with Pre => Data'Last >= 127 and then Data'First <= Base
               and then Base <= Data'Last - 127
   is
      W : array (0 .. 79) of Unsigned_64 := (others => 0);
      A, B, C, D, E, F, G, H : Unsigned_64;
      T1, T2 : Unsigned_64;
   begin
      for T in 0 .. 15 loop
         W (T) := 0;
         for J in 0 .. 7 loop
            W (T) := Shift_Left (W (T), 8) or
              Unsigned_64 (Data (Base + N32 (T) * 8 + N32 (J)));
         end loop;
      end loop;
      for T in 16 .. 79 loop
         declare
            S0 : constant Unsigned_64 :=
              Rotr (W (T - 15), 1) xor Rotr (W (T - 15), 8)
                xor Shift_Right (W (T - 15), 7);
            S1 : constant Unsigned_64 :=
              Rotr (W (T - 2), 19) xor Rotr (W (T - 2), 61)
                xor Shift_Right (W (T - 2), 6);
         begin
            W (T) := W (T - 16) + S0 + W (T - 7) + S1;
         end;
      end loop;

      A := State (0); B := State (1); C := State (2); D := State (3);
      E := State (4); F := State (5); G := State (6); H := State (7);

      for T in 0 .. 79 loop
         declare
            S1 : constant Unsigned_64 :=
              Rotr (E, 14) xor Rotr (E, 18) xor Rotr (E, 41);
            Ch : constant Unsigned_64 := (E and F) xor ((not E) and G);
            S0 : constant Unsigned_64 :=
              Rotr (A, 28) xor Rotr (A, 34) xor Rotr (A, 39);
            Mj : constant Unsigned_64 :=
              (A and B) xor (A and C) xor (B and C);
         begin
            T1 := H + S1 + Ch + K (T) + W (T);
            T2 := S0 + Mj;
            H := G; G := F; F := E; E := D + T1;
            D := C; C := B; B := A; A := T1 + T2;
         end;
      end loop;

      State (0) := State (0) + A; State (1) := State (1) + B;
      State (2) := State (2) + C; State (3) := State (3) + D;
      State (4) := State (4) + E; State (5) := State (5) + F;
      State (6) := State (6) + G; State (7) := State (7) + H;
   end Process_Block;

   procedure Init (Ctx : out Context) is
   begin
      Ctx.State   := (IV0, IV1, IV2, IV3, IV4, IV5, IV6, IV7);
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
      Ctx.Total := Ctx.Total + Unsigned_64 (Remaining);

      if Ctx.Buf_Len > 0 then
         Space := 128 - Ctx.Buf_Len;
         if Remaining < Space then
            Ctx.Buffer (Ctx.Buf_Len .. Ctx.Buf_Len + Remaining - 1) :=
              Data (Pos .. Pos + Remaining - 1);
            Ctx.Buf_Len := Ctx.Buf_Len + Remaining;
            return;
         end if;
         Ctx.Buffer (Ctx.Buf_Len .. 127) :=
           Data (Pos .. Pos + Space - 1);
         Process_Block (Ctx.State, Ctx.Buffer, 0);
         Pos := Pos + Space;
         Remaining := Remaining - Space;
         Ctx.Buf_Len := 0;
      end if;

      while Remaining >= 128 loop
         pragma Loop_Variant (Decreases => Remaining);
         pragma Loop_Invariant
           (Pos >= Data'First and then Remaining >= 0
              and then Pos + Remaining - 1 = Data'Last);
         Process_Block (Ctx.State, Data, Pos);
         Pos := Pos + 128;
         Remaining := Remaining - 128;
      end loop;

      if Remaining > 0 then
         Ctx.Buffer (0 .. Remaining - 1) := Data (Pos .. Pos + Remaining - 1);
         Ctx.Buf_Len := Remaining;
      end if;
   end Update;

   procedure Final (Ctx : in out Context; Output : out Digest) is
      Bit_Len : constant Unsigned_64 := Ctx.Total * 8;
      Pad     : Byte_Seq (0 .. 127) := (others => 0);
      Pad_Len : N32;
   begin
      Output := (others => 0);
      --  FIPS 180-4 5.1.2: append 0x80, zero-fill to 112 mod 128, then
      --  the 128-bit big-endian bit length (high half zero here).
      Pad (0) := 16#80#;
      if Ctx.Buf_Len < 112 then
         Pad_Len := 112 - Ctx.Buf_Len;
      else
         Pad_Len := 240 - Ctx.Buf_Len;
      end if;

      declare
         Tail_Last : constant N32 := Pad_Len + 15;
         Tail      : Byte_Seq (0 .. Tail_Last) := (others => 0);
      begin
         Tail (0 .. Pad_Len - 1) := Pad (0 .. Pad_Len - 1);
         for J in 0 .. 7 loop
            Tail (Pad_Len + 8 + N32 (J)) :=
              Byte (Shift_Right (Bit_Len, 56 - 8 * J) and 16#FF#);
         end loop;
         Update (Ctx, Tail);
      end;

      for I in N32 range 0 .. Digest_Bytes / 8 - 1 loop
         for J in N32 range 0 .. 7 loop
            Output (I * 8 + J) :=
              Byte (Shift_Right (Ctx.State (Integer (I)), 56 - 8 * Integer (J))
                    and 16#FF#);
         end loop;
      end loop;
   end Final;

   procedure Hash (Output : out Digest;
                   M      : in  Byte_Seq)
   is
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

end SPARKTLSCrypto.Hashing.SHA512_Family_G;
