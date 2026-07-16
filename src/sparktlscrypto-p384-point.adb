--  SPARKTLS P-384 Point Arithmetic for ECDHE
--
--  Provides scalar multiplication on the P-384 curve
--  for key exchange.

with Interfaces;           use Interfaces;
with SPARKTLSCrypto.BigNat;      use SPARKTLSCrypto.BigNat;
with SPARKTLSCrypto.P384.Field;  use SPARKTLSCrypto.P384.Field;

package body SPARKTLSCrypto.P384.Point with
   SPARK_Mode => On
is
   P384_B : constant Byte_Seq (0 .. 47) :=
     (16#B3#, 16#31#, 16#2F#, 16#A7#, 16#E2#, 16#3E#, 16#E7#, 16#E4#,
      16#98#, 16#8E#, 16#05#, 16#6B#, 16#E3#, 16#F8#, 16#2D#, 16#19#,
      16#18#, 16#1D#, 16#9C#, 16#6E#, 16#FE#, 16#81#, 16#41#, 16#12#,
      16#03#, 16#14#, 16#08#, 16#8F#, 16#50#, 16#13#, 16#87#, 16#5A#,
      16#C6#, 16#56#, 16#39#, 16#8D#, 16#8A#, 16#2E#, 16#D1#, 16#9D#,
      16#2A#, 16#85#, 16#C8#, 16#ED#, 16#D3#, 16#EC#, 16#2A#, 16#EF#);

   function P384_On_Curve (Q : Jacobian) return Boolean
   with Pre => Q.X.Len = W384 and Q.Y.Len = W384 and Q.Z.Len = W384
               and P.Len = W384;

   function P384_On_Curve (Q : Jacobian) return Boolean is
      B, X2, X3, Y2, T1, T2, T3, T4, T : Big_Nat;
   begin
      Decode (B, P384_B);
      B.Len := W384;
      FE_To_Monty (B);

      FE_Sqr (X2, Q.X);
      FE_Mul (X3, X2, Q.X);
      FE_Sqr (Y2, Q.Y);

      --  secp384r1 has a = -3, so check x^3 - 3x + b - y^2 = 0.
      FE_Sub (T1, X3, Q.X);
      FE_Sub (T2, T1, Q.X);
      FE_Sub (T3, T2, Q.X);
      FE_Add (T4, T3, B);
      FE_Sub (T, T4, Y2);
      return FE_Is_Zero (T);
   end P384_On_Curve;

   procedure P384_Mulgen
     (PK_Out : out Byte_Seq;
      SK     : in  Byte_Seq)
   is
      G      : Jacobian;
      T1     : Big_Nat;
      Coords : Byte_Seq (0 .. 47);
   begin
      PK_Out := (others => 0);
      Make_Generator (G);
      Scalar_Mul (G, SK);
      To_Affine (G);

      PK_Out (0) := 16#04#;
      FE_From_Monty (T1, G.X);
      Encode (Coords, T1);
      PK_Out (1 .. 48) := Coords;
      FE_From_Monty (T1, G.Y);
      Encode (Coords, T1);
      PK_Out (49 .. 96) := Coords;
   end P384_Mulgen;

   procedure P384_ECDHE
     (Secret  :    out Bytes_48;
      OK      :    out Boolean;
      SK      : in     Byte_Seq;
      Peer_PK : in     Byte_Seq)
   is
      Q      : Jacobian;
      T1     : Big_Nat;
      Coords : Byte_Seq (0 .. 47);
   begin
      Secret := (others => 0);
      OK := False;

      if Peer_PK (0) /= 16#04# then
         return;
      end if;

      Make_Point (Q, Peer_PK (1 .. 48), Peer_PK (49 .. 96));
      if not P384_On_Curve (Q) then
         return;
      end if;

      Scalar_Mul (Q, SK);

      if FE_Is_Zero (Q.Z) then
         return;
      end if;

      To_Affine (Q);
      FE_From_Monty (T1, Q.X);
      Encode (Coords, T1);
      Secret := Bytes_48 (Coords);
      OK := True;
   end P384_ECDHE;

end SPARKTLSCrypto.P384.Point;
