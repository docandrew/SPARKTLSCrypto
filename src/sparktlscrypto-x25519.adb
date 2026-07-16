--  X25519 Curve25519 Diffie-Hellman (RFC 7748)
--
--  Uses SPARKTLSCrypto.Fiat_25519 for GF(2^255-19) field arithmetic.
--  Montgomery ladder and encode/decode from RFC 7748 §5.

with Interfaces;           use Interfaces;
with SPARKTLSCrypto.Fiat_25519;  use SPARKTLSCrypto.Fiat_25519;
with SPARKTLSCrypto.Ed25519;

package body SPARKTLSCrypto.X25519 with
   SPARK_Mode => On
is
   --  Rename Fiat_25519.FE locally so the rest of the code reads cleanly
   subtype FE is Fiat_25519.FE;

   type Small_Order_Table is array (Natural range <>) of Bytes_32;

   Small_Order_Points : constant Small_Order_Table :=
     (0 =>
        (others => 0),
      1 =>
        (0 => 1, others => 0),
      2 =>
        (16#E0#, 16#EB#, 16#7A#, 16#7C#, 16#3B#, 16#41#, 16#B8#, 16#AE#,
         16#16#, 16#56#, 16#E3#, 16#FA#, 16#F1#, 16#9F#, 16#C4#, 16#6A#,
         16#DA#, 16#09#, 16#8D#, 16#EB#, 16#9C#, 16#32#, 16#B1#, 16#FD#,
         16#86#, 16#62#, 16#05#, 16#16#, 16#5F#, 16#49#, 16#B8#, 16#00#),
      3 =>
        (16#5F#, 16#9C#, 16#95#, 16#BC#, 16#A3#, 16#50#, 16#8C#, 16#24#,
         16#B1#, 16#D0#, 16#B1#, 16#55#, 16#9C#, 16#83#, 16#EF#, 16#5B#,
         16#04#, 16#44#, 16#5C#, 16#C4#, 16#58#, 16#1C#, 16#8E#, 16#86#,
         16#D8#, 16#22#, 16#4E#, 16#DD#, 16#D0#, 16#9F#, 16#11#, 16#57#),
      4 =>
        (16#EC#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#,
         16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#,
         16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#,
         16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#7F#),
      5 =>
        (16#ED#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#,
         16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#,
         16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#,
         16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#7F#),
      6 =>
        (16#EE#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#,
         16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#,
         16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#,
         16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#7F#));

   function CT_Nonzero (V : Byte) return Byte is
      W : constant Unsigned_16 := Unsigned_16 (V);
   begin
      return Byte (Shift_Right (W or (0 - W), 15) and 1);
   end CT_Nonzero;

   function CT_Eq_Byte (A, B : Byte) return Byte is
   begin
      return 1 - CT_Nonzero (A xor B);
   end CT_Eq_Byte;

   function Small_Order_Flag (P : Bytes_32) return Byte is
      T : Bytes_32 := P;
      Match : Byte := 0;
   begin
      --  RFC 7748 masks the high bit during decode. Do the same before
      --  matching so the canonical encodings and high-bit aliases are
      --  handled identically, without branching on the point bytes.
      T (31) := T (31) and 16#7F#;
      for Candidate of Small_Order_Points loop
         declare
            Diff : Byte := 0;
         begin
            for I in Index_32 loop
               Diff := Diff or (T (I) xor Candidate (I));
            end loop;
            Match := Match or CT_Eq_Byte (Diff, 0);
         end;
      end loop;
      return Match and 1;
   end Small_Order_Flag;

   ----------------------------------------------------------------------------
   --  Encode/Decode between bytes and field elements
   ----------------------------------------------------------------------------

   subtype Load_Offset is I32 range 0 .. 24;

   function Load_LE64 (S : Bytes_32; Offset : Load_Offset) return Unsigned_64 is
     (Unsigned_64 (S (Offset)) or
      Shift_Left (Unsigned_64 (S (Offset + 1)), 8) or
      Shift_Left (Unsigned_64 (S (Offset + 2)), 16) or
      Shift_Left (Unsigned_64 (S (Offset + 3)), 24) or
      Shift_Left (Unsigned_64 (S (Offset + 4)), 32) or
      Shift_Left (Unsigned_64 (S (Offset + 5)), 40) or
      Shift_Left (Unsigned_64 (S (Offset + 6)), 48) or
      Shift_Left (Unsigned_64 (S (Offset + 7)), 56));

   function Decode (S : Bytes_32) return FE is
      R : FE := (others => 0);
   begin
      R (0) := Load_LE64 (S, 0) and Fiat_25519.Mask51;
      R (1) := Shift_Right (Load_LE64 (S, 6), 3) and Fiat_25519.Mask51;
      R (2) := Shift_Right (Load_LE64 (S, 12), 6) and Fiat_25519.Mask51;
      R (3) := Shift_Right (Load_LE64 (S, 19), 1) and Fiat_25519.Mask51;
      R (4) := Shift_Right (Load_LE64 (S, 24), 12) and Fiat_25519.Mask51;
      return R;
   end Decode;

   procedure Store_LE64 (S : in out Bytes_32; Offset : Load_Offset; V : Unsigned_64)
   is
      function Lo8 (X : Unsigned_64) return Byte is (Byte (X mod 256));
   begin
      S (Offset)     := Lo8 (V);
      S (Offset + 1) := Lo8 (Shift_Right (V, 8));
      S (Offset + 2) := Lo8 (Shift_Right (V, 16));
      S (Offset + 3) := Lo8 (Shift_Right (V, 24));
      S (Offset + 4) := Lo8 (Shift_Right (V, 32));
      S (Offset + 5) := Lo8 (Shift_Right (V, 40));
      S (Offset + 6) := Lo8 (Shift_Right (V, 48));
      S (Offset + 7) := Lo8 (Shift_Right (V, 56));
   end Store_LE64;

   procedure Encode (S : out Bytes_32; F : in FE) is
      T : FE := F;
      Q : Unsigned_64;
      H : Unsigned_64;
   begin
      Fiat_25519.Carry (T);
      Fiat_25519.Carry (T);
      Q := (T (0) + 19) / (2**51);
      Q := (T (1) + Q) / (2**51);
      Q := (T (2) + Q) / (2**51);
      Q := (T (3) + Q) / (2**51);
      Q := (T (4) + Q) / (2**51);
      T (0) := T (0) + 19 * Q;
      Fiat_25519.Carry (T);

      S := (others => 0);
      H := T (0) or Shift_Left (T (1), 51);
      Store_LE64 (S, 0, H);
      H := Shift_Right (T (1), 13) or Shift_Left (T (2), 38);
      Store_LE64 (S, 8, H);
      H := Shift_Right (T (2), 26) or Shift_Left (T (3), 25);
      Store_LE64 (S, 16, H);
      H := Shift_Right (T (3), 39) or Shift_Left (T (4), 12);
      Store_LE64 (S, 24, H);
   end Encode;

   ----------------------------------------------------------------------------
   --  Montgomery ladder (RFC 7748 §5)
   ----------------------------------------------------------------------------

   procedure Scalar_Mult
     (Q : out Bytes_32;
      N : in  Bytes_32;
      P : in  Bytes_32)
   is
      E : Bytes_32 := N;
      X1, X2, Z2, X3, Z3 : FE;
      A, AA, B, BB, CB, DA, T : FE;
      Swap : Unsigned_64 := 0;
      K_T  : Unsigned_64;
      Small_Order : constant Byte := Small_Order_Flag (P);
      Clear_Mask  : constant Byte := not (-Small_Order);
   begin
      E (0)  := E (0) and 248;
      E (31) := (E (31) and 127) or 64;

      X1 := Decode (P);
      X2 := Fiat_25519.FE_One;
      Z2 := Fiat_25519.FE_Zero;
      X3 := X1;
      Z3 := Fiat_25519.FE_One;

      for Pos in reverse 0 .. 254 loop
         pragma Loop_Invariant
           (Is_Reduced (X1) and Is_Reduced (X2) and Is_Reduced (Z2) and
            Is_Reduced (X3) and Is_Reduced (Z3) and Swap <= 1);
         K_T := Shift_Right (Unsigned_64 (E (N32 (Pos / 8))),
                             Pos mod 8) and 1;
         K_T := K_T xor Swap;
         Fiat_25519.CSwap (X2, X3, K_T);
         Fiat_25519.CSwap (Z2, Z3, K_T);
         Swap := Shift_Right (Unsigned_64 (E (N32 (Pos / 8))),
                              Pos mod 8) and 1;

         A  := Fiat_25519.Add (X2, Z2);
         AA := Fiat_25519.Sqr (A);
         B  := Fiat_25519.Sub (X2, Z2);
         BB := Fiat_25519.Sqr (B);
         T  := Fiat_25519.Sub (AA, BB);
         CB := Fiat_25519.Mul (Fiat_25519.Sub (X3, Z3), A);
         DA := Fiat_25519.Mul (Fiat_25519.Add (X3, Z3), B);

         X3 := Fiat_25519.Sqr (Fiat_25519.Add (DA, CB));
         Z3 := Fiat_25519.Mul (Fiat_25519.Sqr (Fiat_25519.Sub (DA, CB)), X1);
         X2 := Fiat_25519.Mul (AA, BB);
         Z2 := Fiat_25519.Scmul (T, 121665);
         Z2 := Fiat_25519.Mul (Fiat_25519.Add (Z2, AA), T);
      end loop;

      Fiat_25519.CSwap (X2, X3, Swap);
      Fiat_25519.CSwap (Z2, Z3, Swap);
      --  CSwap preserves Is_Reduced, which implies Is_Mul_Safe via
      --  Lemma_Reduced_Is_Mul_Safe — both X2 and Z2 are valid Inv/Mul inputs.
      declare
         ZI : constant FE := Fiat_25519.Inv (Z2);
      begin
         T := Fiat_25519.Mul (X2, ZI);
      end;
      Encode (Q, T);

      for I in Index_32 loop
         Q (I) := Q (I) and Clear_Mask;
      end loop;
   end Scalar_Mult;

   procedure Test_FE_Mul
     (A, B   : in  Bytes_32;
      Result : out Bytes_32)
   is
      FA : constant FE := Decode (A);
      FB : constant FE := Decode (B);
   begin
      Encode (Result, Fiat_25519.Mul (FA, FB));
   end Test_FE_Mul;

   procedure Test_Encode_Decode
     (Input  : in  Bytes_32;
      Output : out Bytes_32)
   is
      F : constant FE := Decode (Input);
   begin
      Encode (Output, F);
   end Test_Encode_Decode;

   procedure Scalar_Mult_Base
     (Q : out Bytes_32;
      N : in  Bytes_32)
   is
   begin
      SPARKTLSCrypto.Ed25519.Scalar_Mult_Base_To_Montgomery (Q, N);
   end Scalar_Mult_Base;

end SPARKTLSCrypto.X25519;
