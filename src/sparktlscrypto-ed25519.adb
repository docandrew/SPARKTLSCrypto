--  SPARKTLS Ed25519 — EdDSA signatures using Fiat Crypto field arithmetic
--
--  Replaces SPARKNaCl.Sign for ~10x speedup on GF(2^255-19) operations.
--  SHA-512 still comes from SPARKNaCl.

with Interfaces;           use Interfaces;
with SPARKTLSCrypto.Fiat_25519;  use SPARKTLSCrypto.Fiat_25519;
with SPARKTLSCrypto.Ed25519_Base_Table;
with SPARKNaCl;
with SPARKNaCl.Hashing.SHA512;

package body SPARKTLSCrypto.Ed25519 with
   SPARK_Mode => On
is
   pragma Warnings (GNATProve, Off, "pragma * ignored (not yet supported)");

   ----------------------------------------------------------------------------
   --  Extended twisted Edwards point: (X, Y, Z, T) where
   --  x = X/Z, y = Y/Z, x*y = T/Z on -x^2 + y^2 = 1 + d*x^2*y^2
   ----------------------------------------------------------------------------

   type Ext_Point is record
      X, Y, Z, T : Fiat_25519.FE;
   end record;

   --  d = -121665/121666 mod p (twisted Edwards curve constant)
   --  In 5×51-bit limbs:
   GF_D : constant Fiat_25519.FE :=
     (16#34DCA135978A3#, 16#1A8283B156EBD#, 16#5E7A26001C029#,
      16#739C663A03CBB#, 16#52036CEE2B6FF#);

   --  2*d
   GF_D2 : constant Fiat_25519.FE :=
     (16#69B9426B2F159#, 16#35050762ADD7A#, 16#3CF44C0038052#,
      16#6738CC7407977#, 16#2406D9DC56DFF#);

   --  Base point coordinates
   GF_BX : constant Fiat_25519.FE :=
     (16#62D608F25D51A#, 16#412A4B4F6592A#, 16#75B7171A4B31D#,
      16#1FF60527118FE#, 16#216936D3CD6E5#);

   GF_BY : constant Fiat_25519.FE :=
     (16#6666666666658#, 16#4CCCCCCCCCCCC#, 16#1999999999999#,
      16#3333333333333#, 16#6666666666666#);

   --  sqrt(-1) mod p
   GF_I : constant Fiat_25519.FE :=
     (16#61B274A0EA0B0#, 16#0D5A5FC8F189D#, 16#7EF5E9CBD0C60#,
      16#78595A6804C9E#, 16#2B8324804FC1D#);

   ----------------------------------------------------------------------------
   --  Point addition (extended coordinates)
   --  Unified addition formula (works for doubling too)
   ----------------------------------------------------------------------------

   --  Ext_Point coordinates are always Reduced — they're produced as
   --  outputs of Mul (post: Is_Reduced) in Point_Add/Point_Double, or
   --  loaded as constants (FE_One, FE_Zero, basepoint table).
   function Is_Valid (P : Ext_Point) return Boolean is
     (Fiat_25519.Is_Reduced (P.X) and Fiat_25519.Is_Reduced (P.Y) and
      Fiat_25519.Is_Reduced (P.Z) and Fiat_25519.Is_Reduced (P.T))
   with Ghost;

   function Point_Add (P, Q : Ext_Point) return Ext_Point
   with Pre  => Is_Valid (P) and Is_Valid (Q),
        Post => Is_Valid (Point_Add'Result)
   is
      A : constant Fiat_25519.FE := Fiat_25519.Mul
            (Fiat_25519.Sub (P.Y, P.X), Fiat_25519.Sub (Q.Y, Q.X));
      B : constant Fiat_25519.FE := Fiat_25519.Mul
            (Fiat_25519.Add (P.X, P.Y), Fiat_25519.Add (Q.X, Q.Y));
      C : constant Fiat_25519.FE := Fiat_25519.Mul
            (Fiat_25519.Mul (P.T, Q.T), GF_D2);
      D : Fiat_25519.FE := Fiat_25519.Add
            (Fiat_25519.Mul (P.Z, Q.Z), Fiat_25519.Mul (P.Z, Q.Z));
      E : constant Fiat_25519.FE := Fiat_25519.Sub (B, A);
      F, G, H : Fiat_25519.FE;
   begin
      Fiat_25519.Carry (D);
      F := Fiat_25519.Sub (D, C);
      G := Fiat_25519.Add (D, C);
      H := Fiat_25519.Add (B, A);
      return Ext_Point'(X => Fiat_25519.Mul (E, F),
                         Y => Fiat_25519.Mul (H, G),
                         Z => Fiat_25519.Mul (G, F),
                         T => Fiat_25519.Mul (E, H));
   end Point_Add;

   ----------------------------------------------------------------------------
   --  Scalar multiplication: double-and-add, MSB first
   ----------------------------------------------------------------------------

   function Scalarmult (Q : Ext_Point; S : Bytes_32) return Ext_Point
   with Pre  => Is_Valid (Q),
        Post => Is_Valid (Scalarmult'Result)
   is
      LP : Ext_Point := (X => Fiat_25519.FE_Zero,
                          Y => Fiat_25519.FE_One,
                          Z => Fiat_25519.FE_One,
                          T => Fiat_25519.FE_Zero);
      LQ : Ext_Point := Q;
      CB : Byte;
      Swap : Unsigned_64;
   begin
      for I in reverse N32 range 0 .. 31 loop
         pragma Loop_Invariant (Is_Valid (LP) and Is_Valid (LQ));
         CB := S (I);
         for J in reverse Natural range 0 .. 7 loop
            pragma Loop_Invariant (Is_Valid (LP) and Is_Valid (LQ));
            Swap := Unsigned_64 (Shift_Right (CB, J) mod 2);
            Fiat_25519.CSwap (LP.X, LQ.X, Swap);
            Fiat_25519.CSwap (LP.Y, LQ.Y, Swap);
            Fiat_25519.CSwap (LP.Z, LQ.Z, Swap);
            Fiat_25519.CSwap (LP.T, LQ.T, Swap);
            LQ := Point_Add (LQ, LP);
            LP := Point_Add (LP, LP);
            Fiat_25519.CSwap (LP.X, LQ.X, Swap);
            Fiat_25519.CSwap (LP.Y, LQ.Y, Swap);
            Fiat_25519.CSwap (LP.Z, LQ.Z, Swap);
            Fiat_25519.CSwap (LP.T, LQ.T, Swap);
         end loop;
      end loop;
      return LP;
   end Scalarmult;

   ----------------------------------------------------------------------------
   --  Point doubling (dedicated formula, faster than Add(P,P))
   --  From RFC 8032 / ref10: uses only 4 squarings + 4 muls
   ----------------------------------------------------------------------------

   ----------------------------------------------------------------------------
   --  P1xP1/P2 intermediate representations for chained doublings
   --  Convention matches our Point_Add: E = H-(X+Y)², G = XX-YY
   ----------------------------------------------------------------------------

   type Proj_Point is record
      X, Y, Z : Fiat_25519.FE;
   end record;

   type P1xP1_Point is record
      X, Y, Z, T : Fiat_25519.FE;
   end record;

   --  P1xP1 components are mul-safe (typically outputs of Add/Sub).
   function Is_P1xP1_Valid (P : P1xP1_Point) return Boolean is
     (Fiat_25519.Is_Mul_Safe (P.X) and Fiat_25519.Is_Mul_Safe (P.Y) and
      Fiat_25519.Is_Mul_Safe (P.Z) and Fiat_25519.Is_Mul_Safe (P.T))
   with Ghost;

   --  Double: P2 → P1xP1 (4 Sqr, 0 Mul)
   --  P1xP1 components: X=E, Y=H, Z=G, T=F in our naming convention
   function Double_P2 (P : Proj_Point) return P1xP1_Point
   with Pre  => Fiat_25519.Is_Reduced (P.X) and
                Fiat_25519.Is_Reduced (P.Y) and
                Fiat_25519.Is_Reduced (P.Z),
        Post => Is_P1xP1_Valid (Double_P2'Result)
   is
      XX    : constant Fiat_25519.FE := Fiat_25519.Sqr (P.X);
      YY    : constant Fiat_25519.FE := Fiat_25519.Sqr (P.Y);
      ZZ2   : Fiat_25519.FE := Fiat_25519.Add
                (Fiat_25519.Sqr (P.Z), Fiat_25519.Sqr (P.Z));
      H_Tmp : Fiat_25519.FE := Fiat_25519.Add (XX, YY);
      G_Tmp : Fiat_25519.FE := Fiat_25519.Sub (XX, YY);
      XpYsq : constant Fiat_25519.FE :=
        Fiat_25519.Sqr (Fiat_25519.Add (P.X, P.Y));
      E     : Fiat_25519.FE;
      F     : Fiat_25519.FE;
   begin
      --  Carry mul-safe intermediates back to reduced before passing to
      --  Add/Sub (whose Pre requires Is_Reduced).
      Fiat_25519.Carry (ZZ2);
      Fiat_25519.Carry (H_Tmp);
      Fiat_25519.Carry (G_Tmp);
      E := Fiat_25519.Sub (H_Tmp, XpYsq);
      F := Fiat_25519.Add (ZZ2, G_Tmp);
      return P1xP1_Point'(X => E, Y => H_Tmp, Z => G_Tmp, T => F);
   end Double_P2;

   --  P1xP1 → Extended: X=E*F, Y=G*H, Z=F*G, T=E*H (4 Mul)
   function P1xP1_To_Ext (P : P1xP1_Point) return Ext_Point is
     (X => Fiat_25519.Mul (P.X, P.T),   --  E * F
      Y => Fiat_25519.Mul (P.Z, P.Y),   --  G * H
      Z => Fiat_25519.Mul (P.T, P.Z),   --  F * G
      T => Fiat_25519.Mul (P.X, P.Y))   --  E * H
   with Pre  => Is_P1xP1_Valid (P),
        Post => Is_Valid (P1xP1_To_Ext'Result);

   --  P1xP1 → Projective: X=E*F, Y=G*H, Z=F*G (3 Mul, drop T)
   function P1xP1_To_P2 (P : P1xP1_Point) return Proj_Point is
     (X => Fiat_25519.Mul (P.X, P.T),   --  E * F
      Y => Fiat_25519.Mul (P.Z, P.Y),   --  G * H
      Z => Fiat_25519.Mul (P.T, P.Z))   --  F * G
   with Pre  => Is_P1xP1_Valid (P),
        Post => Fiat_25519.Is_Reduced (P1xP1_To_P2'Result.X) and
                Fiat_25519.Is_Reduced (P1xP1_To_P2'Result.Y) and
                Fiat_25519.Is_Reduced (P1xP1_To_P2'Result.Z);

   --  Extended → Projective (drop T)
   function Ext_To_P2 (P : Ext_Point) return Proj_Point is
     (X => P.X, Y => P.Y, Z => P.Z)
   with Pre  => Is_Valid (P),
        Post => Fiat_25519.Is_Reduced (Ext_To_P2'Result.X) and
                Fiat_25519.Is_Reduced (Ext_To_P2'Result.Y) and
                Fiat_25519.Is_Reduced (Ext_To_P2'Result.Z);

   --  Point_Double: uses P1xP1 internally, equivalent to old direct formula
   function Point_Double (P : Ext_Point) return Ext_Point
   with Pre  => Is_Valid (P),
        Post => Is_Valid (Point_Double'Result)
   is
   begin
      return P1xP1_To_Ext (Double_P2 (Ext_To_P2 (P)));
   end Point_Double;

   ----------------------------------------------------------------------------
   --  Position-specific affine points [k * 256**i]B. Each lookup scans all
   --  fifteen entries at the public byte position; the scalar is never used
   --  as a memory index. Z is one for all entries, including the identity.
   ----------------------------------------------------------------------------

   package BT renames SPARKTLSCrypto.Ed25519_Base_Table;

   ----------------------------------------------------------------------------
   --  Sum high nibbles with the position tables, multiply by 16, then add
   --  low nibbles: S = sum_i (16*hi_i + lo_i) * 256**i.
   --  This needs four point doublings in total instead of four per nibble.
   ----------------------------------------------------------------------------

   function Scalarbase (S : Bytes_32) return Ext_Point with
      Post => Is_Valid (Scalarbase'Result)
   is
      Identity : constant Ext_Point :=
        (X => Fiat_25519.FE_Zero, Y => Fiat_25519.FE_One,
         Z => Fiat_25519.FE_One,  T => Fiat_25519.FE_Zero);
      R : Ext_Point := Identity;
      Nibble : Unsigned_64;

      --  Constant-time lookup at a public byte position, or identity
      --  Always touches every table entry to avoid timing leaks.
      function CT_Lookup (Position : BT.Position; Idx : Unsigned_64) return Ext_Point
      with Pre  => Idx <= 15,
           Post => Is_Valid (CT_Lookup'Result)
      is
         P : constant BT.Affine_Point := BT.Lookup (Position, Idx);
      begin
         return (X => (P.X (0), P.X (1), P.X (2), P.X (3), P.X (4)), Y => (P.Y (0), P.Y (1), P.Y (2), P.Y (3), P.Y (4)),
                 Z => Fiat_25519.FE_One, T => (P.T (0), P.T (1), P.T (2), P.T (3), P.T (4)));
      end CT_Lookup;

      --  Constant-time conditional point add: always does the add,
      --  then selects old or new result based on whether nibble is 0.
      procedure CT_Add (Acc : in out Ext_Point; Position : BT.Position; Nibble : Unsigned_64)
      with Pre  => Is_Valid (Acc) and Nibble <= 15,
           Post => Is_Valid (Acc)
      is
         T     : constant Ext_Point := CT_Lookup (Position, Nibble);
         Sum   : constant Ext_Point := Point_Add (Acc, T);
         --  Select: if Nibble = 0, keep Acc; else use Sum
         Nz    : Unsigned_64 := Nibble;
         M     : Unsigned_64;
      begin
         Nz := Nz or Shift_Right (Nz, 32);
         Nz := Nz or Shift_Right (Nz, 16);
         Nz := Nz or Shift_Right (Nz, 8);
         Nz := Nz or Shift_Right (Nz, 4);
         Nz := Nz or Shift_Right (Nz, 2);
         Nz := Nz or Shift_Right (Nz, 1);
         M := -(Nz and 1);  --  all-ones if nonzero, 0 if zero
         for L in 0 .. 4 loop
            pragma Loop_Invariant
              ((for all K in 0 .. L - 1 =>
                  Acc.X (K) <= Fiat_25519.Tight51 and
                  Acc.Y (K) <= Fiat_25519.Tight51 and
                  Acc.Z (K) <= Fiat_25519.Tight51 and
                  Acc.T (K) <= Fiat_25519.Tight51) and
               (for all K in L .. 4 =>
                  Acc.X (K) <= Fiat_25519.Tight51 and
                  Acc.Y (K) <= Fiat_25519.Tight51 and
                  Acc.Z (K) <= Fiat_25519.Tight51 and
                  Acc.T (K) <= Fiat_25519.Tight51));
            Acc.X (L) := Acc.X (L) xor (M and (Acc.X (L) xor Sum.X (L)));
            Acc.Y (L) := Acc.Y (L) xor (M and (Acc.Y (L) xor Sum.Y (L)));
            Acc.Z (L) := Acc.Z (L) xor (M and (Acc.Z (L) xor Sum.Z (L)));
            Acc.T (L) := Acc.T (L) xor (M and (Acc.T (L) xor Sum.T (L)));
         end loop;
      end CT_Add;
   begin
      for I in N32 range 0 .. 31 loop
         pragma Loop_Invariant (Is_Valid (R));
         Nibble := Unsigned_64 (Shift_Right (S (I), 4));
         CT_Add (R, BT.Position (I), Nibble);
      end loop;
      declare
         P2 : Proj_Point := Ext_To_P2 (R);
      begin
         P2 := P1xP1_To_P2 (Double_P2 (P2));
         P2 := P1xP1_To_P2 (Double_P2 (P2));
         P2 := P1xP1_To_P2 (Double_P2 (P2));
         R := P1xP1_To_Ext (Double_P2 (P2));
      end;
      for I in N32 range 0 .. 31 loop
         pragma Loop_Invariant (Is_Valid (R));
         Nibble := Unsigned_64 (S (I) and 16#0F#);
         CT_Add (R, BT.Position (I), Nibble);
      end loop;

      return R;
   end Scalarbase;

   ----------------------------------------------------------------------------
   --  Point encoding/decoding
   ----------------------------------------------------------------------------

   --  Encode a field element to 32 little-endian bytes
   procedure FE_To_Bytes (R : out Bytes_32; F : Fiat_25519.FE) is
      T : Fiat_25519.FE := F;
      Q : Unsigned_64;
      H : Unsigned_64;
      function Lo8 (X : Unsigned_64) return Byte is (Byte (X mod 256));
      procedure Store64 (S : in out Bytes_32; Off : I32; V : Unsigned_64)
      with Pre => Off in 0 .. 24
      is
      begin
         S (Off)     := Lo8 (V);
         S (Off + 1) := Lo8 (Shift_Right (V, 8));
         S (Off + 2) := Lo8 (Shift_Right (V, 16));
         S (Off + 3) := Lo8 (Shift_Right (V, 24));
         S (Off + 4) := Lo8 (Shift_Right (V, 32));
         S (Off + 5) := Lo8 (Shift_Right (V, 40));
         S (Off + 6) := Lo8 (Shift_Right (V, 48));
         S (Off + 7) := Lo8 (Shift_Right (V, 56));
      end Store64;
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
      R := (others => 0);
      H := T (0) or Shift_Left (T (1), 51);
      Store64 (R, 0, H);
      H := Shift_Right (T (1), 13) or Shift_Left (T (2), 38);
      Store64 (R, 8, H);
      H := Shift_Right (T (2), 26) or Shift_Left (T (3), 25);
      Store64 (R, 16, H);
      H := Shift_Right (T (3), 39) or Shift_Left (T (4), 12);
      Store64 (R, 24, H);
   end FE_To_Bytes;

   function Bytes_To_FE (S : Bytes_32) return Fiat_25519.FE
   with Post => Fiat_25519.Is_Reduced (Bytes_To_FE'Result) and
                Fiat_25519.Is_Mul_Safe (Bytes_To_FE'Result)
   is
      function Load64 (S : Bytes_32; Off : I32) return Unsigned_64 is
        (Unsigned_64 (S (Off)) or
         Shift_Left (Unsigned_64 (S (Off + 1)), 8) or
         Shift_Left (Unsigned_64 (S (Off + 2)), 16) or
         Shift_Left (Unsigned_64 (S (Off + 3)), 24) or
         Shift_Left (Unsigned_64 (S (Off + 4)), 32) or
         Shift_Left (Unsigned_64 (S (Off + 5)), 40) or
         Shift_Left (Unsigned_64 (S (Off + 6)), 48) or
         Shift_Left (Unsigned_64 (S (Off + 7)), 56))
      with Pre => Off in 0 .. 24;
   begin
      return Fiat_25519.FE'(
        Load64 (S, 0) and Fiat_25519.Mask51,
        Shift_Right (Load64 (S, 6), 3) and Fiat_25519.Mask51,
        Shift_Right (Load64 (S, 12), 6) and Fiat_25519.Mask51,
        Shift_Right (Load64 (S, 19), 1) and Fiat_25519.Mask51,
        Shift_Right (Load64 (S, 24), 12) and Fiat_25519.Mask51);
   end Bytes_To_FE;

   function Par (A : Fiat_25519.FE) return Byte is
      D : Bytes_32;
   begin
      FE_To_Bytes (D, A);
      return D (0) mod 2;
   end Par;

   function Pack (P : Ext_Point) return Bytes_32 is
      ZI : constant Fiat_25519.FE := Fiat_25519.Inv (P.Z);
      TX : constant Fiat_25519.FE := Fiat_25519.Mul (P.X, ZI);
      TY : constant Fiat_25519.FE := Fiat_25519.Mul (P.Y, ZI);
      R  : Bytes_32;
   begin
      FE_To_Bytes (R, TY);
      R (31) := R (31) xor (Par (TX) * 128);
      return R;
   end Pack;

   procedure Unpackneg (R      :    out Ext_Point;
                         Valid  :    out Boolean;
                         PK     : in     Bytes_32)
   with Post => (if Valid then Is_Valid (R))
   is
      --  Follows SPARKNaCl/TweetNaCl unpackneg exactly:
      --  R1 = y (from bytes), R2 = 1
      --  num = y^2 - 1,  den = 1 + d*y^2
      --  den2 = den^2,  den4 = den2^2
      --  R0 = pow2523(den4 * num * den * den2) * num * den * den2
      --  check = R0^2 * den;  if check != num, R0 *= sqrt(-1)
      --  check again;  if still != num, invalid
      --  if par(R0) == par bit from PK, negate R0

      function Pow2523 (I : Fiat_25519.FE) return Fiat_25519.FE
      with Pre  => Fiat_25519.Is_Mul_Safe (I),
           Post => Fiat_25519.Is_Reduced (Pow2523'Result)
      is
         C : Fiat_25519.FE := I;
      begin
         for A in 0 .. 248 loop
            pragma Loop_Invariant (Fiat_25519.Is_Mul_Safe (C));
            C := Fiat_25519.Mul (Fiat_25519.Sqr (C), I);
         end loop;
         return Fiat_25519.Mul (Fiat_25519.Sqr (Fiat_25519.Sqr (C)), I);
      end Pow2523;

      function FE_Eq (A, B : Fiat_25519.FE) return Boolean is
         BA, BB : Bytes_32;
      begin
         FE_To_Bytes (BA, A);
         FE_To_Bytes (BB, B);
         return Byte_Seq (BA) = Byte_Seq (BB);
      end FE_Eq;

      R1   : constant Fiat_25519.FE := Bytes_To_FE (PK);
      R1_Sq   : constant Fiat_25519.FE := Fiat_25519.Sqr (R1);
      Num     : constant Fiat_25519.FE := Fiat_25519.Sub (R1_Sq, Fiat_25519.FE_One);
      Den     : constant Fiat_25519.FE := Fiat_25519.Add (Fiat_25519.FE_One,
                   Fiat_25519.Mul (R1_Sq, GF_D));
      Den2    : constant Fiat_25519.FE := Fiat_25519.Sqr (Den);
      Den4    : constant Fiat_25519.FE := Fiat_25519.Sqr (Den2);
      Num_Den3 : constant Fiat_25519.FE := Fiat_25519.Mul (
                    Fiat_25519.Mul (Num, Den), Den2);
      R0  : Fiat_25519.FE;
      Chk : Fiat_25519.FE;
   begin
      R0  := Fiat_25519.Mul (Pow2523 (Fiat_25519.Mul (Den4, Num_Den3)), Num_Den3);

      Chk := Fiat_25519.Mul (Fiat_25519.Sqr (R0), Den);
      if not FE_Eq (Chk, Num) then
         R0 := Fiat_25519.Mul (R0, GF_I);
      end if;

      Chk := Fiat_25519.Mul (Fiat_25519.Sqr (R0), Den);
      if not FE_Eq (Chk, Num) then
         R := (X => Fiat_25519.FE_Zero, Y => Fiat_25519.FE_One,
               Z => Fiat_25519.FE_One, T => Fiat_25519.FE_Zero);
         Valid := False;
         return;
      end if;

      if Par (R0) = (PK (31) / 128) then
         R0 := Fiat_25519.Sub (Fiat_25519.FE_Zero, R0);
         Fiat_25519.Carry (R0);
      end if;

      R := (X => R0, Y => R1, Z => Fiat_25519.FE_One,
            T => Fiat_25519.Mul (R0, R1));
      Valid := True;
   end Unpackneg;

   ----------------------------------------------------------------------------
   --  Scalar reduction mod L (curve order)
   --  L = 2^252 + 27742317777372353535851937790883648493
   ----------------------------------------------------------------------------

   --  Arithmetic shift right by 8 / 4. These compute the same floor division
   --  semantics as Shift_Right_Arithmetic without a sign-dependent branch.
   function ASR_8 (X : in I64) return I64
   with Post => (if X >= 0 then ASR_8'Result = X / 256 else
                              ASR_8'Result = ((X + 1) / 256) - 1)
   is
      Sign : constant I64 := (if X < 0 then -1 else 0);
   begin
      return ((X - Sign) / 256) + Sign;
   end ASR_8;

   function ASR_4 (X : in I64) return I64
   with Post => (if X >= 0 then ASR_4'Result = X / 16 else
                              ASR_4'Result = ((X + 1) / 16) - 1)
   is
      Sign : constant I64 := (if X < 0 then -1 else 0);
   begin
      return ((X - Sign) / 16) + Sign;
   end ASR_4;

   --  ----------------------------------------------------------------
   --  ModL — scalar reduction modulo the curve order L
   --
   --  This is a verbatim port of the proven harness from
   --  SPARKNaCl.Sign.ModL (sparknacl-sign.adb), authored by Rod
   --  Chapman / SPARKNaCl contributors. All the structural
   --  decomposition, bounded subtypes, and loop invariants are theirs;
   --  reproduced here so this crate can stay self-contained without
   --  depending on SPARKNaCl.Sign for its proof.
   --
   --  We re-use ASR_8 / ASR_4 (which carry the postconditions
   --  the harness needs) and SPARKNaCl base types (I64, I64_Byte,
   --  Index_64, etc.).
   --  ----------------------------------------------------------------

   --  MBP = "Max Byte Product"
   MBP        : constant := (255 * 255);
   Max_X_Limb : constant := (32 * MBP) + 255;

   --  RFC 7748: Curve25519 order L = 2^252 + 0x14def9dea2f79cd65812631a5cf5d3ed
   Min_Non_Zero_L : constant := 16#12#;
   Max_L          : constant := 16#f9#;
   L31            : constant := 16#10#;
   subtype L_Limb is I64_Byte range 0 .. Max_L;

   type L_Table is array (Index_32) of L_Limb;
   L : constant L_Table := (16#ed#, 16#d3#, 16#f5#, 16#5c#,
                            16#1a#, 16#63#, 16#12#, 16#58#,
                            16#d6#, 16#9c#, 16#f7#, 16#a2#,
                            16#de#, 16#f9#, 16#de#, 16#14#,
                            16#00#, 16#00#, 16#00#, 16#00#,
                            16#00#, 16#00#, 16#00#, 16#00#,
                            16#00#, 16#00#, 16#00#, 16#00#,
                            16#00#, 16#00#, 16#00#, L31);

   --  16 * L precomputed (only first 16 elements are non-zero).
   subtype L16_Limb is I64 range (16 * Min_Non_Zero_L) .. (16 * Max_L);
   type L16_Table  is array (Index_16) of L16_Limb;
   L16 : constant L16_Table := (16#ed0#, 16#d30#, 16#f50#, 16#5c0#,
                                16#1a0#, 16#630#, 16#120#, 16#580#,
                                16#d60#, 16#9c0#, 16#f70#, 16#a20#,
                                16#de0#, 16#f90#, 16#de0#, 16#140#);

   function ModL (X_In : I64_Seq_64) return Bytes_32
   with Pre => (for all K in Index_64 => X_In (K) in 0 .. Max_X_Limb);

   function ModL (X_In : I64_Seq_64) return Bytes_32
   is
      X : constant I64_Seq_64 := X_In;

      Max_Carry : constant := 2**14;
      Min_Carry : constant := -2**25;
      subtype Carry_T is I64 range Min_Carry .. Max_Carry;

      Min_Adjustment : constant := (Min_Carry * 16 * Max_L);
      Max_Adjustment : constant := ((Max_X_Limb + Max_Carry) * 16 * Max_L);
      subtype Adjustment_T is I64
        range Min_Adjustment .. Max_Adjustment;

      subtype XL_Limb is I64
        range -((Max_X_Limb + Max_Carry + Max_Adjustment) * 16 * Max_L) ..
               ((Max_X_Limb + Max_Carry + Max_Adjustment) * 16 * Max_L);

      type XL_Table is array (Index_64) of XL_Limb;
      XL : XL_Table;

      --  "PRL" = "Partially Reduced Limb"
      subtype PRL is I64 range -129 .. 128;

      --  "FRL" = "Fully Reduced Limb"
      subtype FRL is PRL range -128 .. 127;

      R     : Bytes_32;

      Max_L63_Carry : constant := (Max_X_Limb + 128) / 255;

      subtype XL51_T is I64 range 0 .. (Max_X_Limb + Max_L63_Carry);

      procedure Initialize_XL
        with Global => (Input  => X,
                        Output => XL),
             Pre  => (for all K in Index_64 => X (K) in 0 .. Max_X_Limb),
             Post => (for all K in Index_64 => XL (K) >= 0) and
                     (for all K in Index_64 => XL (K) <= Max_X_Limb) and
                     (for all K in Index_64 => XL (K) = XL_Limb (X (K)));

      procedure Eliminate_Limb_63
        with Global => (Proof_In => X,
                        In_Out   => XL),
             Pre  => (for all K in Index_64 =>
                        X (K) in 0 .. Max_X_Limb) and then
                     (for all K in Index_64 => XL (K) >= 0) and then
                     (for all K in Index_64 => XL (K) <= Max_X_Limb) and then
                     (for all K in Index_64 => XL (K) = XL_Limb (X (K))),
             Post => (for all K in Index_64 range 0 .. 30 =>
                       XL (K) = X (K)) and
                     (for all K in Index_64 range 31 .. 50 =>
                       XL (K) in FRL) and
                     (XL (51) in XL51_T) and
                     (for all K in Index_64 range 52 .. 62 =>
                       XL (K) = X (K)) and
                     (XL (63) = 0);

      procedure Eliminate_Limbs_62_To_32
        with Global => (Proof_In => X,
                        In_Out   => XL),
             Pre  => ((for all K in Index_64 range 0 .. 30 =>
                         XL (K) = X (K) and
                         XL (K) in 0 .. Max_X_Limb) and
                      (for all K in Index_64 range 31 .. 50 =>
                         XL (K) in FRL) and
                      (XL (51) in XL51_T) and
                      (for all K in Index_64 range 52 .. 62 =>
                         XL (K) = X (K) and
                         XL (K) in 0 .. Max_X_Limb) and
                      (XL (63) = 0)),
             Post => ((for all K in Index_64 range  0 .. 19 =>
                         XL (K) in FRL) and
                      (for all K in Index_64 range 20 .. 31 =>
                         XL (K) in PRL) and
                      (for all K in Index_64 range 32 .. 63 => XL (K) = 0));

      procedure Finalize
        with Global => (In_Out => XL,
                        Output => R),
             Pre  => ((for all K in Index_64 range  0 .. 19 =>
                         XL (K) in FRL) and
                      (for all K in Index_64 range 20 .. 31 =>
                         XL (K) in PRL) and
                      (for all K in Index_64 range 32 .. 63 => XL (K) = 0));

      procedure Initialize_XL
      is
      begin
         XL := (others => 0);
         for K in Index_64 loop
            pragma Loop_Optimize (No_Unroll);
            XL (K) := XL_Limb (X (K));
            pragma Loop_Invariant
              (for all A in Index_64 range 0 .. K => XL (A) = XL_Limb (X (A)));
         end loop;
      end Initialize_XL;

      procedure Eliminate_Limb_63
      is
         Max_L63_Adjustment : constant := 16 * Max_L * Max_X_Limb;
         subtype L63_Adjustment_T is I64 range 0 .. Max_L63_Adjustment;

         Min_L63_Carry : constant := ((128 - Max_L63_Adjustment) / 255) - 1;
         subtype L63_Carry_T is I64 range Min_L63_Carry .. Max_L63_Carry;

         Carry      : L63_Carry_T;
         Adjustment : L63_Adjustment_T;
         XL63       : constant XL_Limb := XL (63);
      begin
         Carry := 0;

         for J in I32 range 31 .. 46 loop
            pragma Loop_Optimize (No_Unroll);
            declare
               XLJ : XL_Limb renames XL (J);
               L16_Factor : constant L16_Limb := L16 (J - 31);
            begin
               pragma Assert (L16_Factor >= 288);
               pragma Assert (L16_Factor <= 3984);
               pragma Assert (XL63 >= 0);
               pragma Assert (XL63 <= XL_Limb'Last);
               pragma Assert (L16_Factor * XL63 <= 3984 * XL_Limb'Last);
               Adjustment := L16_Factor * XL63;
               XLJ := XLJ + Carry - Adjustment;
               Carry := ASR_8 (XLJ + 128);
               XLJ := XLJ - (Carry * 256);
            end;

            pragma Loop_Invariant (XL63 >= 0);
            pragma Loop_Invariant (XL63 <= XL_Limb'Last);
            pragma Loop_Invariant
              ((for all K in Index_64 range 0 .. 30 =>
                  XL (K) = XL'Loop_Entry (K)) and
               (for all K in Index_64 range 31 .. J =>
                  XL (K) in FRL) and
               (for all K in Index_64 range J + 1 .. 63 =>
                  XL (K) = XL'Loop_Entry (K)));
         end loop;

         pragma Assert
           ((for all K in Index_64 range 0 .. 30 =>
               XL (K) = X (K)) and
            (for all K in Index_64 range 31 .. 46 =>
               XL (K) in FRL) and
            (for all K in Index_64 range 47 .. 63 =>
               XL (K) = X (K)));

         declare
            Min_XL47_Carry : constant :=
              ((Min_L63_Carry + 128 + 1) / 2**8) - 1;
            pragma Assert (Min_XL47_Carry = -127006);
            Min_XL48_Carry : constant :=
              ((Min_XL47_Carry + 128 + 1) / 2**8) - 1;
            pragma Assert (Min_XL48_Carry = -496);
            Min_XL49_Carry : constant :=
              ((Min_XL48_Carry + 128 + 1) / 2**8) - 1;
            pragma Assert (Min_XL49_Carry = -2);
            Min_XL50_Carry : constant := ((Min_XL49_Carry + 128) / 2**8);
            pragma Assert (Min_XL50_Carry = 0);
         begin
            XL (47) := XL (47) + Carry;
            Carry := ASR_8 (XL (47) + 128);
            XL (47) := XL (47) - (Carry * 256);

            pragma Assert (Carry >= Min_XL47_Carry);

            XL (48) := XL (48) + Carry;
            Carry := ASR_8 (XL (48) + 128);
            XL (48) := XL (48) - (Carry * 256);

            pragma Assert (Carry >= Min_XL48_Carry);

            XL (49) := XL (49) + Carry;
            Carry := ASR_8 (XL (49) + 128);
            XL (49) := XL (49) - (Carry * 256);

            pragma Assert (Carry >= Min_XL49_Carry);

            XL (50) := XL (50) + Carry;
            Carry := ASR_8 (XL (50) + 128);
            XL (50) := XL (50) - (Carry * 256);

            pragma Assert (Min_XL50_Carry = 0);
            pragma Assert (Carry >= Min_XL50_Carry);
         end;

         pragma Assert
           ((for all K in Index_64 range  0 .. 30 => XL (K) = X (K)) and
            (for all K in Index_64 range 31 .. 50 => XL (K) in FRL) and
            (for all K in Index_64 range 51 .. 63 => XL (K) = X (K)));

         XL (51) := XL (51) + Carry;
         pragma Assert (XL (51) in XL51_T);
         XL (63) := 0;
      end Eliminate_Limb_63;

      procedure Eliminate_Limbs_62_To_32
      is
         Carry      : Carry_T;
         Adjustment : Adjustment_T;
         XLI        : XL_Limb;
      begin
         for I in reverse I32 range 32 .. 62 loop
            pragma Loop_Optimize (No_Unroll);
            Carry := 0;
            XLI := XL (I);
            for J in I32 range (I - 32) .. (I - 17) loop
               pragma Loop_Optimize (No_Unroll);

               declare
                  XLJ : XL_Limb renames XL (J);
               begin
                  Adjustment := (L16 (J - (I - 32))) * XLI;
                  XLJ := XLJ + Carry - Adjustment;
                  Carry := ASR_8 (XLJ + 128);
                  XLJ := XLJ - (Carry * 256);
               end;

               pragma Loop_Invariant
                 (for all K in Index_64 range 0 .. I - 33 =>
                    XL (K) = XL'Loop_Entry (K));
               pragma Loop_Invariant
                 (for all K in Index_64 range I - 32 .. J =>
                    XL (K) in FRL);
               pragma Loop_Invariant
                 (for all K in Index_64 range J + 1 .. I32'Min (50, I - 1) =>
                    XL (K) = XL'Loop_Entry (K));
               pragma Loop_Invariant
                 (for all K in Index_64 range J + 1 .. I32'Min (50, I - 1) =>
                    XL (K) in PRL);
               pragma Loop_Invariant
                 (for all K in Index_64 range I32'Max (I - 11, 52) .. I - 1 =>
                    XL (K) = XL'Loop_Entry (K));
               pragma Loop_Invariant
                 (for all K in Index_64 range I + 1 .. 63 => XL (K) = 0);
               pragma Loop_Invariant
                 (for all K in Index_64 => XL (K) in PRL'First .. XL51_T'Last);

            end loop;

            pragma Assert
              (for all K in Index_64 range I - 32 .. I - 17 =>
                 XL (K) in FRL);

            pragma Assert (XL (I - 16) in FRL);
            XL (I - 16) := XL (I - 16) + Carry;
            Carry := ASR_8 (XL (I - 16) + 128);
            XL (I - 16) := XL (I - 16) - (Carry * 256);

            pragma Assert
              (for all K in Index_64 range I - 32 .. I - 16 =>
                 XL (K) in FRL);

            pragma Assert (XL (I - 15) in FRL);
            pragma Assert (Carry in -2**17 .. 64);
            XL (I - 15) := XL (I - 15) + Carry;
            Carry := ASR_8 (XL (I - 15) + 128);
            XL (I - 15) := XL (I - 15) - (Carry * 256);

            pragma Assert
              (for all K in Index_64 range I - 32 .. I - 15 =>
                 XL (K) in FRL);

            pragma Assert (XL (I - 14) in FRL);
            pragma Assert (Carry in -512 .. 1);
            XL (I - 14) := XL (I - 14) + Carry;
            Carry := ASR_8 (XL (I - 14) + 128);
            XL (I - 14) := XL (I - 14) - (Carry * 256);

            pragma Assert
              (for all K in Index_64 range I - 32 .. I - 14 =>
                 XL (K) in FRL);

            pragma Assert (XL (I - 13) in FRL);
            pragma Assert (Carry in -2 .. 1);
            XL (I - 13) := XL (I - 13) + Carry;
            Carry := ASR_8 (XL (I - 13) + 128);
            XL (I - 13) := XL (I - 13) - (Carry * 256);

            pragma Assert
              (for all K in Index_64 range I - 32 .. I - 13 =>
                 XL (K) in FRL);

            pragma Assert (XL (I - 12) in FRL);
            pragma Assert (Carry in -1 .. 1);

            XL (I - 12) := XL (I - 12) + Carry;
            pragma Assert (XL (I - 12) in PRL);

            XL (I) := 0;

            pragma Loop_Invariant
              (for all K in Index_64 range 0 .. I - 33 =>
                 XL (K) = XL'Loop_Entry (K));
            pragma Loop_Invariant
              (for all K in Index_64 range I - 32 .. I - 13 =>
                 XL (K) in FRL);
            pragma Loop_Invariant
              (XL (I - 12) in PRL);
            pragma Loop_Invariant
              (for all K in Index_64 range I - 11 .. I32'Min (50, I - 1) =>
                 XL (K) in PRL);
            pragma Loop_Invariant
              (if I >= 52 then
              XL (51) >= XL'Loop_Entry (51) + Min_Carry);
            pragma Loop_Invariant
              (if I >= 52 then
              XL (51) <= XL'Loop_Entry (51) + Max_Carry);
            pragma Loop_Invariant
              (for all K in Index_64 range I32'Max (I - 11, 52) .. I - 1 =>
                 XL (K) = XL'Loop_Entry (K));
            pragma Loop_Invariant
              (for all K in Index_64 range I .. 63 => XL (K) = 0);
            pragma Loop_Invariant
              (for all K in Index_64 => XL (K) in PRL'First .. XL51_T'Last);
         end loop;
      end Eliminate_Limbs_62_To_32;

      procedure Finalize
      is
         Final_Carry_Min : constant := -9;
         Final_Carry_Max : constant := 9;

         subtype Final_Carry_T is I64 range Final_Carry_Min .. Final_Carry_Max;

         subtype Step1_XL_Limb is I64 range
           (Final_Carry_Min * 256) ..
           ((Final_Carry_Max + 1) * 256) - 1;

         subtype Step2_XL_Limb is I64 range
           I64_Byte'First - (Final_Carry_Max * Max_L) ..
           I64_Byte'Last  - (Final_Carry_Min * Max_L);

         Carry : Final_Carry_T;
      begin
         --  Step 1
         Carry := 0;
         for J in Index_32 loop
            pragma Loop_Optimize (No_Unroll);
            pragma Assert (XL (31) in PRL);
            XL (J) := XL (J) + (Carry - ASR_4 (XL (31)) * L (J));

            pragma Assert (XL (J) >= Step1_XL_Limb'First);
            pragma Assert (XL (J) <= Step1_XL_Limb'Last);

            Carry := ASR_8 (XL (J));
            XL (J) := XL (J) mod 256;

            pragma Loop_Invariant
              (for all K in Index_64 range 0 .. J => XL (K) in I64_Byte);
            pragma Loop_Invariant
              (for all K in Index_64 range J + 1 .. 31 =>
                 XL (K) = XL'Loop_Entry (K));
            pragma Loop_Invariant
              (for all K in Index_64 range J + 1 .. 31 =>
                 XL (K) in PRL);
            pragma Loop_Invariant
              (for all K in Index_64 range 32 .. 63 => XL (K) = 0);
         end loop;

         pragma Assert
           (for all K in Index_64 range 0 .. 31 => XL (K) in I64_Byte);
         pragma Assert
           (for all K in Index_64 range 32 .. 63 => XL (K) = 0);

         --  Step 2
         for J in Index_32 loop
            pragma Loop_Optimize (No_Unroll);
            XL (J) := XL (J) - Carry * L (J);
            pragma Loop_Invariant
              (for all K in Index_32 range 0 .. J =>
                 XL (K) in Step2_XL_Limb);
            pragma Loop_Invariant
              (for all K in Index_64 range 32 .. 63 => XL (K) = 0);
         end loop;

         pragma Assert
           (for all K in Index_64 => XL (K) in Step2_XL_Limb);
         pragma Assert
           (for all K in Index_64 range 32 .. 63 => XL (K) = 0);

         --  Step 3
         declare
            MXLC : constant := 10;
            subtype S3CT is I64 range -MXLC .. MXLC;
            S3C : S3CT;
         begin
            for I in Index_32 loop
               pragma Loop_Optimize (No_Unroll);

               pragma Assert (XL (I) >=
                                Step2_XL_Limb'First - MXLC * I64 (I));
               S3C := ASR_8 (XL (I));
               XL (I + 1) := XL (I + 1) + S3C;
               R (I) := Byte (XL (I) mod 256);

               pragma Loop_Invariant (XL (0) = XL'Loop_Entry (0));
               pragma Loop_Invariant (XL (0) in Step2_XL_Limb);
               pragma Loop_Invariant (if I <= 30 then XL (32) = 0);
               pragma Loop_Invariant
                 (for all K in Index_32 range 1 .. 31 =>
                    XL (K) >= Step2_XL_Limb'First - (MXLC * I64 (K)));
               pragma Loop_Invariant
                 (for all K in Index_32 range 1 .. 31 =>
                    XL (K) <= Step2_XL_Limb'Last + (MXLC * I64 (K)));
               pragma Loop_Invariant
                 (for all K in Index_32 range I + 2 .. 31 =>
                    XL (K) in Step2_XL_Limb);
            end loop;
         end;
      end Finalize;

   begin
      Initialize_XL;
      Eliminate_Limb_63;
      Eliminate_Limbs_62_To_32;
      pragma Warnings (GNATProve, Off, "unused assignment");
      pragma Warnings (GNATProve, Off, "XL*not used after the call");
      Finalize;
      return R;
   end ModL;

   --  SHA-512 hash wrapper
   procedure Hash (Output : out Bytes_64; Input : in Byte_Seq) is
   begin
      SPARKNaCl.Hashing.SHA512.Hash (Output, Input);
   end Hash;

   function Hash_Reduce (M : Byte_Seq) return Bytes_32 is
      H : Bytes_64;
      X : I64_Seq_64;
   begin
      Hash (H, M);
      X := (others => 0);
      for I in Index_64 loop
         pragma Loop_Optimize (No_Unroll);
         X (I) := I64 (H (I));
         pragma Loop_Invariant
           (for all K in Index_64 range 0 .. I => X (K) in I64_Byte);
      end loop;
      pragma Assert
        (for all K in Index_64 => X (K) in I64_Byte);
      return ModL (X);
   end Hash_Reduce;

   ----------------------------------------------------------------------------
   --  High-level operations
   ----------------------------------------------------------------------------

   procedure Keypair
     (Seed : in     Bytes_32;
      PK   :    out Bytes_32;
      SK   :    out Bytes_64)
   is
      D : Bytes_64;
   begin
      Hash (D, Byte_Seq (Seed));
      D (0)  := D (0) and 248;
      D (31) := (D (31) and 127) or 64;
      PK := Pack (Scalarbase (D (0 .. 31)));
      SK := Seed & PK;
   end Keypair;

   procedure Sign
     (SM : out Byte_Seq;
      M  : in  Byte_Seq;
      SK : in  Bytes_64)
   is
      D    : Bytes_64;
      H, R : Bytes_32;
      X    : I64_Seq_64;
      P    : Ext_Point;
   begin
      --  Hash the secret key
      Hash (D, Byte_Seq (SK (0 .. 31)));
      D (0)  := D (0) and 248;
      D (31) := (D (31) and 127) or 64;

      --  Initialize SM = [zeros_32 | prefix | M]
      SM := (others => 0);
      SM (64 .. SM'Last) := M;
      SM (32 .. 63) := D (32 .. 63);  --  prefix = second half of hash
      SM (0 .. 31) := (others => 0);

      --  R = Hash_Reduce(prefix || M)
      R := Hash_Reduce (SM (32 .. SM'Last));

      --  Encode R*B
      P := Scalarbase (R);
      SM (0 .. 31) := Pack (P);

      --  Put public key in bytes 32..63
      SM (32 .. 63) := SK (32 .. 63);

      --  H = Hash_Reduce(SM)
      H := Hash_Reduce (SM);

      --  X = R + H*D mod L
      --
      --  Each X(K) accumulates at most 32 byte-byte products plus an
      --  initial byte, so the running bound is K*MBP + 255 across the
      --  inner pass, and at most Max_X_Limb = 32*MBP + 255 at the end.
      X := (others => 0);
      for I in Index_32 loop
         pragma Loop_Optimize (No_Unroll);
         X (I) := I64 (R (I));
         pragma Loop_Invariant
           (for all K in Index_64 range 0 .. I => X (K) in I64_Byte);
         pragma Loop_Invariant
           (for all K in Index_64 range I + 1 .. 63 => X (K) = 0);
      end loop;
      pragma Assert
        ((for all K in Index_64 range  0 .. 31 => X (K) in I64_Byte) and
         (for all K in Index_64 range 32 .. 63 => X (K) = 0));

      for I in Index_32 loop
         pragma Loop_Optimize (No_Unroll);
         for J in Index_32 loop
            pragma Loop_Optimize (No_Unroll);
            X (I + J) := X (I + J) + I64 (H (I)) * I64 (D (J));

            --  Each (outer I, inner J) adds one MBP-bounded product to
            --  X(I+J). Indices in I..I+J have been touched this outer;
            --  others have only seen prior outers' contributions.
            pragma Loop_Invariant
              (for all K in Index_64 range I .. I + J =>
                 X (K) in 0 .. (I64 (I) + 1) * MBP + 255);
            pragma Loop_Invariant
              (for all K in Index_64 =>
                 (if K < I or else K > I + J then
                    X (K) in 0 .. I64 (I) * MBP + 255));
         end loop;
         pragma Loop_Invariant
           (for all K in Index_64 =>
              X (K) in 0 .. (I64 (I) + 1) * MBP + 255);
      end loop;

      pragma Assert
        (for all K in Index_64 => X (K) in 0 .. Max_X_Limb);

      SM (32 .. 63) := ModL (X);

      --  Scrub the signing scalar and prefix (D), the nonce (R) and the
      --  unreduced s = r + h*d (X). H and the point [r]B are public.
      pragma Warnings (GNATprove, Off, "statement has no effect");
      pragma Warnings (GNATprove, Off, "*is set by*");
      SPARKNaCl.Sanitize (Byte_Seq (D));
      SPARKNaCl.Sanitize (Byte_Seq (R));
      pragma Warnings (GNATprove, On, "*is set by*");
      pragma Warnings (GNATprove, On, "statement has no effect");
      pragma Warnings (GNATprove, Off, "statement has no effect");
      pragma Warnings (GNATprove, Off, "unused assignment");
      X := (others => 0);
      pragma Inspection_Point (X);
      pragma Warnings (GNATprove, On, "unused assignment");
      pragma Warnings (GNATprove, On, "statement has no effect");
   end Sign;

   --  RFC 8032 §5.1.7: Ed25519 verification requires the scalar S
   --  encoded in bytes [32..63] of the signature to satisfy 0 ≤ S < L.
   --  Without this bound, an attacker who has one valid signature
   --  (R, S) can produce a different signature (R, S + L) that is
   --  mathematically equivalent and still verifies — breaking
   --  signature non-malleability. Wycheproof tcId=63..66, 85 catch
   --  exactly this.
   --
   --  Implementation: constant-time subtract-with-borrow comparing
   --  S to L (both 256-bit, little-endian). Final borrow = 1 iff S < L.
   function S_Below_L (S : Bytes_32) return Boolean is
      Borrow : Unsigned_32 := 0;
      Diff   : Unsigned_32;
   begin
      for I in N32 range 0 .. 31 loop
         Diff := Unsigned_32 (S (I))
               - Unsigned_32 (L (I))
               - Borrow;
         --  The high byte of Diff (post subtract) is 0xFF iff Diff
         --  underflowed (i.e. S[I] - L[I] - Borrow < 0).
         Borrow := Shift_Right (Diff, 31) and 1;
      end loop;
      return Borrow = 1;
   end S_Below_L;

   procedure Open
     (M       :    out Byte_Seq;
      Valid   :    out Boolean;
      Msg_Len :    out I32;
      SM      : in     Byte_Seq;
      PK      : in     Bytes_32)
   is
      T    : Bytes_32;
      P, Q : Ext_Point;
      S    : Bytes_32;
   begin
      M := (others => 0);
      Msg_Len := -1;
      if SM'Length < 64 then
         Valid := False;
         return;
      end if;

      --  Enforce S < L (RFC 8032 §5.1.7) before any expensive crypto.
      for I in N32 range 0 .. 31 loop
         S (I) := SM (32 + I);
      end loop;
      if not S_Below_L (S) then
         Valid := False;
         return;
      end if;

      Unpackneg (Q, Valid, PK);
      if not Valid then
         M := (others => 0);
         return;
      end if;

      M := SM;
      M (32 .. 63) := PK;
      P := Scalarmult (Q, Hash_Reduce (M));
      Q := Scalarbase (SM (32 .. 63));
      P := Point_Add (P, Q);
      T := Pack (P);

      --  Constant-time comparison
      Valid := Byte_Seq (SM (0 .. 31)) = Byte_Seq (T);
      if not Valid then
         M := (others => 0);
         return;
      end if;

      declare
         LN : constant I32 := I32 (I64 (SM'Length) - 64);
      begin
         M (0 .. LN - 1) := SM (64 .. LN + 63);
         Msg_Len := LN;
      end;
   end Open;

   procedure Scalar_Mult_Base_To_Montgomery
     (U : out Bytes_32;
      N : in  Bytes_32)
   is
      --  Clamp the scalar (same as X25519 / RFC 7748 §5)
      E : Bytes_32 := N;
      P : Ext_Point;
      Num, Den, Mont_U : Fiat_25519.FE;
   begin
      E (0)  := E (0) and 248;
      E (31) := (E (31) and 127) or 64;

      --  Compute [clamped_scalar] * G in Edwards (windowed)
      P := Scalarbase (E);

      --  Convert Edwards y to Montgomery u: u = (1 + y) / (1 - y)
      --  With projective coords: y = Y/Z, so u = (Z + Y) / (Z - Y)
      Num := Fiat_25519.Add (P.Z, P.Y);
      Den := Fiat_25519.Sub (P.Z, P.Y);
      Mont_U := Fiat_25519.Mul (Num, Fiat_25519.Inv (Den));

      --  Encode to 32 little-endian bytes
      FE_To_Bytes (U, Mont_U);

      --  E is the clamped private scalar; the point and its coordinates
      --  are functions of it. (The stack-residue scan found the E copy.)
      pragma Warnings (GNATprove, Off, "statement has no effect");
      pragma Warnings (GNATprove, Off, "*is set by*");
      SPARKNaCl.Sanitize (Byte_Seq (E));
      pragma Warnings (GNATprove, On, "*is set by*");
      pragma Warnings (GNATprove, On, "statement has no effect");
   end Scalar_Mult_Base_To_Montgomery;

   function Test_ASR_8 (X : I64) return I64 is
   begin
      return ASR_8 (X);
   end Test_ASR_8;

   function Test_ASR_4 (X : I64) return I64 is
   begin
      return ASR_4 (X);
   end Test_ASR_4;

end SPARKTLSCrypto.Ed25519;
