--  SPARKTLS P-384 Field Arithmetic (body)
--
--  Montgomery-based arithmetic mod p384 using SPARK-proven BigNat.
--  Shared by P384.ECDSA and P384.Point.

with Interfaces; use Interfaces;
--  no RSA import needed, BigNat is via the spec

package body SPARKTLSCrypto.P384.Field with
   SPARK_Mode => On
is
   --================================================================
   --  Field arithmetic
   --================================================================

   procedure FE_Add (D : out Big_Nat; A, B : Big_Nat) is
      Tmp   : Arith_Result;
      Trial : Arith_Result;
      Final : Arith_Result;
   begin
      Tmp   := CT_Add (A, B, 1);
      Trial := CT_Sub (Tmp.Value, P, 0);
      Final := CT_Sub (Tmp.Value, P,
                        CT_Neq (Tmp.Carry, 0) or CT_Not (Trial.Carry));
      D := Final.Value;
   end FE_Add;

   procedure FE_Sub (D : out Big_Nat; A, B : Big_Nat) is
      R1 : Arith_Result;
      R2 : Arith_Result;
   begin
      R1 := CT_Sub (A, B, 1);
      R2 := CT_Add (R1.Value, P, R1.Carry);
      D := R2.Value;
   end FE_Sub;

   procedure FE_Mul (D : out Big_Nat; A, B : Big_Nat) is
   begin
      Monty_Mul (D, A, B, P, P_M0I);
   end FE_Mul;

   procedure FE_Sqr (D : out Big_Nat; A : Big_Nat) is
   begin
      Monty_Mul (D, A, A, P, P_M0I);
   end FE_Sqr;

   procedure FE_To_Monty (X : in out Big_Nat) is
   begin
      To_Monty (X, P, P_M0I);
   end FE_To_Monty;

   procedure FE_From_Monty (D : out Big_Nat; A : Big_Nat) is
      One : Big_Nat;
   begin
      Zero (One, W384);
      One.W (0) := 1;
      Monty_Mul (D, A, One, P, P_M0I);
   end FE_From_Monty;

   procedure FE_Inv (D : out Big_Nat; A : Big_Nat) is
      PM2    : Byte_Seq (0 .. 47) := P384_P;
      Tmp    : Big_Nat;
      Result : Big_Nat;
   begin
      PM2 (47) := PM2 (47) - 2;
      FE_From_Monty (Tmp, A);
      Modpow (Result, Tmp, PM2, P, P_M0I);
      Tmp := Result;
      FE_To_Monty (Tmp);
      D := Tmp;
   end FE_Inv;

   function FE_Is_Zero (A : Big_Nat) return Boolean is
      R : Word := 0;
   begin
      for I in 0 .. W384 - 1 loop
         R := R or A.W (I);
      end loop;
      return R = 0;
   end FE_Is_Zero;

   --================================================================
   --  Point operations
   --================================================================

   procedure Point_Double (Q : in out Jacobian) is
      Delta_V, Gamma, Beta, Alpha, T1, T2, Tmp : Big_Nat;
   begin
      FE_Sqr (Delta_V, Q.Z);
      FE_Sqr (Gamma, Q.Y);
      FE_Mul (Beta, Q.X, Gamma);
      FE_Sub (T1, Q.X, Delta_V);
      FE_Add (T2, Q.X, Delta_V);
      FE_Mul (Alpha, T1, T2);
      FE_Add (T1, Alpha, Alpha);
      FE_Add (Tmp, T1, Alpha); Alpha := Tmp;
      --  Q.X = Alpha^2 - 8*Beta
      FE_Sqr (Tmp, Alpha);
      Q.X := Tmp;
      FE_Add (T1, Beta, Beta);
      FE_Add (Tmp, T1, T1); T1 := Tmp;
      FE_Add (T2, T1, T1);
      FE_Sub (Tmp, Q.X, T2);
      Q.X := Tmp;
      --  Q.Z = (Y + Z)^2 - Gamma - Delta
      FE_Add (T2, Q.Y, Q.Z);
      FE_Sqr (Tmp, T2);
      Q.Z := Tmp;
      FE_Sub (Tmp, Q.Z, Gamma);
      Q.Z := Tmp;
      FE_Sub (Tmp, Q.Z, Delta_V);
      Q.Z := Tmp;
      --  Q.Y = Alpha*(4*Beta - X) - 8*Gamma^2
      FE_Sub (T2, T1, Q.X);
      FE_Mul (Tmp, Alpha, T2);
      Q.Y := Tmp;
      FE_Sqr (T1, Gamma);
      FE_Add (T2, T1, T1);
      FE_Add (Tmp, T2, T2); T2 := Tmp;
      FE_Add (Tmp, T2, T2); T2 := Tmp;
      FE_Sub (Tmp, Q.Y, T2);
      Q.Y := Tmp;
   end Point_Double;

   --  Constant-time conditional select for one field element.
   --  Returns A if Mask = 0xFF..F, B if Mask = 0x00..0. Branch-free.
   procedure CT_Select_FE
     (Dst : out Big_Nat; Mask : Word; A, B : Big_Nat);

   procedure CT_Select_FE
     (Dst : out Big_Nat; Mask : Word; A, B : Big_Nat) is
   begin
      Dst.Len := A.Len;
      for I in 0 .. A.Len - 1 loop
         Dst.W (I) := (Mask and A.W (I)) or ((not Mask) and B.W (I));
      end loop;
   end CT_Select_FE;

   --  Constant-time "is this field element zero?" returning a mask:
   --    0xFF..F if all words are zero
   --    0x00..0 otherwise
   --  Uses OR-reduction; no branch on the data.
   function FE_Zero_Mask (V : Big_Nat) return Word;

   function FE_Zero_Mask (V : Big_Nat) return Word is
      R : Word := 0;
   begin
      for I in 0 .. V.Len - 1 loop
         R := R or V.W (I);
      end loop;
      return -Word (Boolean'Pos (R = 0));
   end FE_Zero_Mask;

   --  Constant-time Point_Add. Always runs the full Jacobian
   --  addition formula, then uses bit-mask selection to handle the
   --  special cases (P1 = O or P2 = O). The previous version
   --  early-returned on those conditions, which ctgrind correctly
   --  flagged as a secret-dependent branch (the Z coordinates are
   --  derived from the secret scalar via Scalar_Mul's intermediate
   --  state).
   --
   --  NOTE: the H = 0 case (P1 = ±P2, requiring point doubling or
   --  identity) is NOT handled here — for the Montgomery ladder
   --  invariants used by Scalar_Mul (R1 = R0 + P, with R0 ≠ ±R1
   --  always), H = 0 cannot occur. If Point_Add is ever used
   --  outside that specific ladder context this formula will give
   --  wrong results when P1 = ±P2.
   procedure Point_Add (P1 : in out Jacobian; P2 : Jacobian) is
      Z1SQ, Z2SQ, U1, U2, S1, S2, H, I_V, J, R_V, V, T1, Tmp : Big_Nat;
      Reg_X, Reg_Y, Reg_Z : Big_Nat;
      M_P1_O, M_P2_O      : Word;
   begin
      M_P1_O := FE_Zero_Mask (P1.Z);
      M_P2_O := FE_Zero_Mask (P2.Z);

      --  Run the regular addition formula unconditionally. If
      --  either Z is zero, the resulting Reg_* values are garbage
      --  and will be discarded by the CT-select below.
      FE_Sqr (Z1SQ, P1.Z);
      FE_Sqr (Z2SQ, P2.Z);
      FE_Mul (U1, P1.X, Z2SQ);
      FE_Mul (U2, P2.X, Z1SQ);
      FE_Mul (T1, P2.Z, Z2SQ);
      FE_Mul (S1, P1.Y, T1);
      FE_Mul (T1, P1.Z, Z1SQ);
      FE_Mul (S2, P2.Y, T1);

      FE_Sub (H, U2, U1);
      FE_Sub (R_V, S2, S1);

      FE_Add (I_V, H, H);
      FE_Sqr (Tmp, I_V);
      I_V := Tmp;
      FE_Mul (J, H, I_V);
      FE_Mul (V, U1, I_V);
      FE_Add (Tmp, R_V, R_V); R_V := Tmp;
      --  Reg_X = R_V^2 - J - 2*V
      FE_Sqr (Tmp, R_V);
      Reg_X := Tmp;
      FE_Sub (Tmp, Reg_X, J);
      Reg_X := Tmp;
      FE_Sub (Tmp, Reg_X, V);
      Reg_X := Tmp;
      FE_Sub (Tmp, Reg_X, V);
      Reg_X := Tmp;
      --  Reg_Y = R_V*(V - Reg_X) - 2*S1*J
      FE_Sub (T1, V, Reg_X);
      FE_Mul (Tmp, R_V, T1);
      Reg_Y := Tmp;
      FE_Mul (T1, S1, J);
      FE_Add (Tmp, T1, T1); T1 := Tmp;
      FE_Sub (Tmp, Reg_Y, T1);
      Reg_Y := Tmp;
      --  Reg_Z = ((Z1 + Z2)^2 - Z1SQ - Z2SQ) * H
      FE_Add (T1, P1.Z, P2.Z);
      FE_Sqr (Tmp, T1);
      T1 := Tmp;
      FE_Sub (Tmp, T1, Z1SQ); T1 := Tmp;
      FE_Sub (Tmp, T1, Z2SQ); T1 := Tmp;
      FE_Mul (Reg_Z, T1, H);

      --  Three-way CT select. Apply P2-is-infinity first (keep P1
      --  unchanged in that case), then P1-is-infinity (use P2).
      --
      --  Step A: result := (M_P2_O ? P1 : Reg)
      CT_Select_FE (Tmp, M_P2_O, P1.X, Reg_X); P1.X := Tmp;
      CT_Select_FE (Tmp, M_P2_O, P1.Y, Reg_Y); P1.Y := Tmp;
      CT_Select_FE (Tmp, M_P2_O, P1.Z, Reg_Z); P1.Z := Tmp;
      --  Step B: result := (M_P1_O ? P2 : result)
      CT_Select_FE (Tmp, M_P1_O, P2.X, P1.X); P1.X := Tmp;
      CT_Select_FE (Tmp, M_P1_O, P2.Y, P1.Y); P1.Y := Tmp;
      CT_Select_FE (Tmp, M_P1_O, P2.Z, P1.Z); P1.Z := Tmp;
   end Point_Add;

   --  Constant-time conditional swap of two Jacobian points. If
   --  Mask = 0x00..0, P and Q are unchanged; if Mask = 0xFF..F they
   --  are swapped. Branch-free — the swap pattern (XOR-with-mask) is
   --  the standard CT cswap from Montgomery-ladder implementations.
   procedure CSwap_Point
     (P, Q : in out Jacobian; Mask : Word);

   procedure CSwap_Point
     (P, Q : in out Jacobian; Mask : Word)
   is
      T : Word;
   begin
      for I in 0 .. W384 - 1 loop
         T := Mask and (P.X.W (I) xor Q.X.W (I));
         P.X.W (I) := P.X.W (I) xor T;
         Q.X.W (I) := Q.X.W (I) xor T;
         T := Mask and (P.Y.W (I) xor Q.Y.W (I));
         P.Y.W (I) := P.Y.W (I) xor T;
         Q.Y.W (I) := Q.Y.W (I) xor T;
         T := Mask and (P.Z.W (I) xor Q.Z.W (I));
         P.Z.W (I) := P.Z.W (I) xor T;
         Q.Z.W (I) := Q.Z.W (I) xor T;
      end loop;
   end CSwap_Point;

   procedure Scalar_Mul (P_Pt : in out Jacobian; K : Byte_Seq) is
      R0, R1 : Jacobian;
      B    : Word;
      Mask : Word;
   begin
      Zero (R0.X, W384);
      Zero (R0.Y, W384);
      R0.Y.W (0) := 1;
      FE_To_Monty (R0.Y);
      Zero (R0.Z, W384);
      R1 := P_Pt;

      --  Constant-time Montgomery ladder: instead of branching on
      --  the secret bit B, conditionally swap R0/R1 with B as the
      --  mask, then unconditionally do the (Add, Double) pair, then
      --  swap back. Each iteration touches the same instructions in
      --  the same order regardless of B — the previous if/else was
      --  the line ctgrind flagged as a per-bit secret leak.
      for Byte_Idx in K'Range loop
         pragma Loop_Invariant
           (R0.X.Len = W384 and R0.Y.Len = W384 and R0.Z.Len = W384
            and R1.X.Len = W384 and R1.Y.Len = W384 and R1.Z.Len = W384);
         for Bit in reverse 0 .. 7 loop
            pragma Loop_Invariant
              (R0.X.Len = W384 and R0.Y.Len = W384 and R0.Z.Len = W384
               and R1.X.Len = W384 and R1.Y.Len = W384 and R1.Z.Len = W384);
            B    := Shift_Right (Word (K (Byte_Idx)), Bit) and 1;
            Mask := -B;       --  0..0 if B=0, F..F if B=1
            CSwap_Point (R0, R1, Mask);
            Point_Add (R0, R1);
            Point_Double (R1);
            CSwap_Point (R0, R1, Mask);
         end loop;
      end loop;

      P_Pt := R0;
   end Scalar_Mul;

   procedure To_Affine (Pt : in out Jacobian) is
      Z_Inv, Z_Inv2, Z_Inv3, Tmp : Big_Nat;
   begin
      if FE_Is_Zero (Pt.Z) then
         return;
      end if;
      FE_Inv (Z_Inv, Pt.Z);
      FE_Sqr (Z_Inv2, Z_Inv);
      FE_Mul (Z_Inv3, Z_Inv2, Z_Inv);
      FE_Mul (Tmp, Pt.X, Z_Inv2);
      Pt.X := Tmp;
      FE_Mul (Tmp, Pt.Y, Z_Inv3);
      Pt.Y := Tmp;
      Zero (Pt.Z, W384);
      Pt.Z.W (0) := 1;
      FE_To_Monty (Pt.Z);
   end To_Affine;

   procedure Make_Generator (G : out Jacobian) is
   begin
      Decode (G.X, P384_GX);
      G.X.Len := W384;  --  Ensure Len matches field width
      FE_To_Monty (G.X);
      Decode (G.Y, P384_GY);
      G.Y.Len := W384;
      FE_To_Monty (G.Y);
      Zero (G.Z, W384);
      G.Z.W (0) := 1;
      FE_To_Monty (G.Z);
   end Make_Generator;

   procedure Make_Point (Pt : out Jacobian; Qx, Qy : Byte_Seq) is
      X_Buf : Byte_Seq (0 .. 47);
      Y_Buf : Byte_Seq (0 .. 47);
   begin
      X_Buf := Qx;
      Y_Buf := Qy;
      Decode (Pt.X, X_Buf);
      Pt.X.Len := W384;
      FE_To_Monty (Pt.X);
      Decode (Pt.Y, Y_Buf);
      Pt.Y.Len := W384;
      FE_To_Monty (Pt.Y);
      Zero (Pt.Z, W384);
      Pt.Z.W (0) := 1;
      FE_To_Monty (Pt.Z);
   end Make_Point;

begin
   --  Initialize field constants P and P_M0I at package elaboration.
   Decode (P, P384_P);
   P.Len := W384;
   P_M0I := Ninv32 (P.W (0));
end SPARKTLSCrypto.P384.Field;
