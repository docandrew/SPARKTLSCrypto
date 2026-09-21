--  SPARKTLS P-384 Point Arithmetic for ECDHE
--
--  Provides scalar multiplication on the P-384 curve
--  for key exchange.

with Interfaces;           use Interfaces;
with SPARKTLSCrypto.BigNat64;    use SPARKTLSCrypto.BigNat64;
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

   --  All-ones when Q (affine, Z = 1 as from Make_Point) satisfies the
   --  curve equation, all-zeros otherwise; no branch on the data.
   function P384_On_Curve_Mask (Q : Jacobian) return Word
   with Pre => Q.X.Len = W384 and Q.Y.Len = W384 and Q.Z.Len = W384
               and P.Len = W384;

   function P384_On_Curve_Mask (Q : Jacobian) return Word is
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
      return FE_Zero_Mask (T);
   end P384_On_Curve_Mask;

   function P384_Public_Key_Valid_Mask
     (Qx, Qy : Byte_Seq) return SPARKTLSCrypto.BigNat64.Word
   is
      Q : Jacobian;
   begin
      Make_Point (Q, Qx, Qy);
      return Coord_Below_P_Mask (Qx)
             and Coord_Below_P_Mask (Qy)
             and P384_On_Curve_Mask (Q);
   end P384_Public_Key_Valid_Mask;

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

      --  Range + on-curve check on the peer's key (public data; the
      --  early return is fine here, ECDHE's secret is SK).
      if P384_Public_Key_Valid_Mask (Peer_PK (1 .. 48), Peer_PK (49 .. 96)) = 0 then
         return;
      end if;
      Make_Point (Q, Peer_PK (1 .. 48), Peer_PK (49 .. 96));

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


   ---------------------------------------------------------------
   --  Blinded scalar multiplication
   ---------------------------------------------------------------

   --  Group order n, big-endian, for the scalar blind k + r * n.
   N_Bytes : constant Byte_Seq (0 .. 47) :=
     (16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#,
      16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#,
      16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#,
      16#C7#, 16#63#, 16#4D#, 16#81#, 16#F4#, 16#37#, 16#2D#, 16#DF#,
      16#58#, 16#1A#, 16#0D#, 16#B2#, 16#48#, 16#B0#, 16#A7#, 16#7A#,
      16#EC#, 16#EC#, 16#19#, 16#6A#, 16#CC#, 16#C5#, 16#29#, 16#73#);

   --  KB := k + r * n as 56 big-endian bytes (r is the first eight bytes
   --  of Blind); Lam := lambda in Montgomery form, one if the 48 blind
   --  bytes are zero or not below p.
   procedure Blinding_Inputs
     (K     : in  Byte_Seq;
      Blind : in  Byte_Seq;
      KB    : out Byte_Seq;
      Lam   : out Big_Nat)
   with Pre  => K'First = 0 and K'Length = 48
                and Blind'First = 0 and Blind'Length = Blind_Len
                and KB'First = 0 and KB'Length = Blind_Len
                and Field.Initialized,
        Post => Lam.Len = W384
   is
      NB, RB, KN, Res : Big_Nat;
      LB : constant Byte_Seq (0 .. 47) := Blind (8 .. 55);
   begin
      Decode (NB, N_Bytes);
      Decode (KN, K);
      NB.Len := W384;
      KN.Len := W384;
      Zero (RB, W384);
      for I in 0 .. 7 loop
         RB.W (0) := RB.W (0) or
           Shift_Left (Unsigned_64 (Blind (N32 (7 - I))), 8 * I);
      end loop;
      Mul_Add (Res, NB, RB, KN);   --  n * r + k, 12 words
      Encode (KB, Res);            --  low 56 bytes: the value is < 2^448

      --  lambda := one when the blind bytes are zero or not below p,
      --  selected by mask: the blind is treated as secret material, so no
      --  branch may depend on it.
      Decode (Lam, LB);
      Lam.Len := W384;
      declare
         Bad : constant Word := (not Coord_Below_P_Mask (LB)) or FE_Zero_Mask (Lam);
         One : Big_Nat;
      begin
         Zero (One, W384);
         One.W (0) := 1;
         for I in 0 .. W384 - 1 loop
            pragma Loop_Invariant (Lam.Len = W384);
            Lam.W (I) := (One.W (I) and Bad) or (Lam.W (I) and not Bad);
         end loop;
      end;
      FE_To_Monty (Lam);

      --  KN and Res reveal k; RB reveals the blind
      pragma Warnings (GNATprove, Off, "statement has no effect");
      pragma Warnings (GNATprove, Off, "*is set by*");
      Sanitize (KN);
      Sanitize (RB);
      Sanitize (Res);
      pragma Warnings (GNATprove, On, "*is set by*");
      pragma Warnings (GNATprove, On, "statement has no effect");
   end Blinding_Inputs;

   procedure Scalar_Mul_Blinded
     (P_Pt  : in out Field.Jacobian;
      K     : in     Byte_Seq;
      Blind : in     Byte_Seq)
   is
      KB   : Byte_Seq (0 .. Blind_Len - 1);
      Lam, Lam2, Lam3, T : Big_Nat;
   begin
      Blinding_Inputs (K, Blind, KB, Lam);
      --  Randomise the projective representation once; every ladder
      --  value derives from it.
      FE_Sqr (Lam2, Lam);
      FE_Mul (Lam3, Lam2, Lam);
      FE_Mul (T, P_Pt.X, Lam2);
      P_Pt.X := T;
      FE_Mul (T, P_Pt.Y, Lam3);
      P_Pt.Y := T;
      FE_Mul (T, P_Pt.Z, Lam);
      P_Pt.Z := T;
      Scalar_Mul (P_Pt, KB);
      --  The blinded scalar reveals k given r; lambda links the
      --  randomised coordinates to the real ones.
      pragma Warnings (GNATprove, Off, "statement has no effect");
      pragma Warnings (GNATprove, Off, "*is set by*");
      SPARKNaCl.Sanitize (KB);
      Sanitize (Lam);
      Sanitize (Lam2);
      Sanitize (Lam3);
      Sanitize (T);
      pragma Warnings (GNATprove, On, "*is set by*");
      pragma Warnings (GNATprove, On, "statement has no effect");
   end Scalar_Mul_Blinded;

   procedure P384_Mulgen_Blinded
     (PK_Out : out Byte_Seq;
      SK     : in  Byte_Seq;
      Blind  : in  Byte_Seq)
   is
      G      : Jacobian;
      T1     : Big_Nat;
      Coords : Byte_Seq (0 .. 47);
   begin
      PK_Out := (others => 0);
      Make_Generator (G);
      Scalar_Mul_Blinded (G, SK, Blind);
      To_Affine (G);
      PK_Out (0) := 16#04#;
      FE_From_Monty (T1, G.X);
      Encode (Coords, T1);
      PK_Out (1 .. 48) := Coords;
      FE_From_Monty (T1, G.Y);
      Encode (Coords, T1);
      PK_Out (49 .. 96) := Coords;
   end P384_Mulgen_Blinded;

   procedure P384_ECDHE_Blinded
     (Secret  :    out Bytes_48;
      OK      :    out Boolean;
      SK      : in     Byte_Seq;
      Peer_PK : in     Byte_Seq;
      Blind   : in     Byte_Seq)
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
      if P384_Public_Key_Valid_Mask (Peer_PK (1 .. 48), Peer_PK (49 .. 96)) = 0 then
         return;
      end if;
      Make_Point (Q, Peer_PK (1 .. 48), Peer_PK (49 .. 96));
      Scalar_Mul_Blinded (Q, SK, Blind);
      if FE_Is_Zero (Q.Z) then
         return;
      end if;
      To_Affine (Q);
      FE_From_Monty (T1, Q.X);
      Encode (Coords, T1);
      Secret := Bytes_48 (Coords);
      OK := True;
   end P384_ECDHE_Blinded;

end SPARKTLSCrypto.P384.Point;
