--  SPARKTLS ECDSA P-384 Signature Verification
--  Uses shared P384.Field for field/point arithmetic,
--  and SPARK-proven BigNat for group order arithmetic.

with Interfaces;           use Interfaces;
with SPARKTLSCrypto.BigNat;      use SPARKTLSCrypto.BigNat;
with SPARKTLSCrypto.P384.Field;  use SPARKTLSCrypto.P384.Field;

package body SPARKTLSCrypto.P384.ECDSA with
   SPARK_Mode => On
is
   --================================================================
   --  N and N_M0I are declared in the spec (with Initial_Condition)
   --  so the prover knows N.Len = W384 globally after elaboration.
   --================================================================

   --  Group order field operations (using BigNat directly)
   procedure Mul_Mod_N (D : out Big_Nat; A, B : Big_Nat) is
   begin
      Monty_Mul (D, A, B, N, N_M0I);
   end Mul_Mod_N;

   procedure Inv_Mod_N (D : out Big_Nat; A : Big_Nat) is
      NM2    : Byte_Seq (0 .. 47) := P384_N;
      Result : Big_Nat;
   begin
      NM2 (47) := NM2 (47) - 2;
      Modpow (Result, A, NM2, N, N_M0I);
      D := Result;
   end Inv_Mod_N;

   function Is_Zero_384 (A : Big_Nat) return Boolean is
      R : Word := 0;
   begin
      for I in 0 .. W384 - 1 loop
         R := R or A.W (I);
      end loop;
      return R = 0;
   end Is_Zero_384;

   function In_Range (V : Big_Nat) return Boolean
   with Pre => N.Len = W384
   is
      T      : Big_Nat := V;
      Trial  : Arith_Result;
   begin
      if Is_Zero_384 (V) then
         return False;
      end if;
      T.Len := N.Len;
      Trial := CT_Sub (T, N, 0);
      return Trial.Carry = 1;  --  borrow = 1 means V < N
   end In_Range;

   --================================================================
   --  ECDSA Verify
   --================================================================

   function Verify
     (Hash : in Bytes_48;
      Qx   : in Byte_Seq;
      Qy   : in Byte_Seq;
      R    : in Byte_Seq;
      S    : in Byte_Seq) return Boolean
   is
      R_Int, S_Int, H_Int : Big_Nat;
      W, U1, U2 : Big_Nat;
      G_Pt, Q_Pt : Jacobian;
      T1, T2 : Big_Nat;
      RX_Bytes : Byte_Seq (0 .. 47);
      RX_Int : Big_Nat;
      One : Big_Nat;
   begin
      --  Decode r, s and check they're in [1, n-1]
      Decode (R_Int, R);
      Decode (S_Int, S);
      R_Int.Len := N.Len;
      S_Int.Len := N.Len;
      if not In_Range (R_Int) or not In_Range (S_Int) then
         return False;
      end if;

      --  Decode hash
      Decode (H_Int, Byte_Seq (Hash));
      H_Int.Len := N.Len;

      --  w = s^(-1) mod n
      Inv_Mod_N (W, S_Int);

      --  u1 = hash * w mod n
      T1 := H_Int;
      To_Monty (T1, N, N_M0I);
      T2 := W;
      To_Monty (T2, N, N_M0I);
      Mul_Mod_N (U1, T1, T2);
      --  Convert U1 from Montgomery to normal: multiply by 1
      Zero (One, N.Len);
      One.W (0) := 1;
      Mul_Mod_N (T1, U1, One);
      U1 := T1;

      --  u2 = r * w mod n
      T1 := R_Int;
      To_Monty (T1, N, N_M0I);
      T2 := W;
      To_Monty (T2, N, N_M0I);
      Mul_Mod_N (U2, T1, T2);
      Mul_Mod_N (T1, U2, One);
      U2 := T1;

      --  Compute u1*G + u2*Q
      declare
         U1_Bytes, U2_Bytes : Byte_Seq (0 .. 47);
      begin
         Encode (U1_Bytes, U1);
         Encode (U2_Bytes, U2);

         Make_Generator (G_Pt);
         Make_Point (Q_Pt, Qx, Qy);

         Scalar_Mul (G_Pt, U1_Bytes);
         Scalar_Mul (Q_Pt, U2_Bytes);
         Point_Add (G_Pt, Q_Pt);

         To_Affine (G_Pt);
      end;

      --  Get x-coordinate back to normal form
      FE_From_Monty (T1, G_Pt.X);

      --  Encode x, decode, reduce mod n, compare with r
      Encode (RX_Bytes, T1);
      Decode (RX_Int, RX_Bytes);
      RX_Int.Len := N.Len;

      --  Reduce mod n: if RX >= N, subtract N
      declare
         Trial : constant Arith_Result := CT_Sub (RX_Int, N, 1);
      begin
         if Trial.Carry = 0 then
            RX_Int := Trial.Value;
         end if;
      end;

      --  Compare RX with R
      declare
         Diff : Word := 0;
      begin
         for I in 0 .. W384 - 1 loop
            Diff := Diff or (RX_Int.W (I) xor R_Int.W (I));
         end loop;
         return Diff = 0;
      end;
   end Verify;

   --================================================================
   --  ECDSA Sign
   --================================================================

   procedure Sign
     (Hash  : in     Bytes_48;
      D     : in     Byte_Seq;
      K     : in     Byte_Seq;
      R_Out :    out Byte_Seq;
      S_Out :    out Byte_Seq;
      OK    :    out Boolean)
   is
      --  PRECONDITION (caller's responsibility): K is in [1, n-1].
      --  Use SPARKTLSCrypto.RFC6979.Derive_K_P384 to obtain a valid K.
      --  See sparktlscrypto-p256-ecdsa.adb's Sign for the full
      --  rationale — same change applies here. The In_Range branch
      --  that used to live here was a non-constant-time early-return
      --  flagged by ctgrind/dudect.
      K_Int, D_Int, H_Int : Big_Nat;
      R_Int, S_Int        : Big_Nat;
      RD, Sum, K_Inv      : Big_Nat;
      T1, T2              : Big_Nat;
      One                 : Big_Nat;
      G_Pt                : Jacobian;
      RX_Bytes            : Byte_Seq (0 .. 47);
   begin
      R_Out := (others => 0);
      S_Out := (others => 0);
      OK := False;

      Decode (K_Int, K);
      Decode (D_Int, D);
      Decode (H_Int, Byte_Seq (Hash));
      K_Int.Len := N.Len;
      D_Int.Len := N.Len;
      H_Int.Len := N.Len;

      Make_Generator (G_Pt);
      Scalar_Mul (G_Pt, K);
      To_Affine (G_Pt);

      FE_From_Monty (T1, G_Pt.X);
      Encode (RX_Bytes, T1);
      Decode (R_Int, RX_Bytes);
      R_Int.Len := N.Len;

      declare
         Trial : constant Arith_Result := CT_Sub (R_Int, N, 1);
         --  Use Trial.Value when R_Int >= N (Trial.Carry = 0). Done
         --  via CT_Mux to avoid a secret-dependent branch.
         Ctl   : constant Word := CT_Not (Trial.Carry);
      begin
         for I in 0 .. R_Int.Len - 1 loop
            R_Int.W (I) := CT_Mux (Ctl, Trial.Value.W (I), R_Int.W (I));
         end loop;
      end;

      Zero (One, N.Len);
      One.W (0) := 1;

      T1 := R_Int;
      To_Monty (T1, N, N_M0I);
      T2 := D_Int;
      To_Monty (T2, N, N_M0I);
      Mul_Mod_N (RD, T1, T2);
      Mul_Mod_N (T1, RD, One);
      RD := T1;

      declare
         Add_Res : constant Arith_Result := CT_Add (RD, H_Int, 1);
         Sub_Res : Arith_Result;
         Ctl     : Word;
      begin
         Sum := Add_Res.Value;
         Sum.Len := N.Len;
         --  Reduce: use Sub_Res.Value when (carry from add) OR
         --  (Sum >= N, i.e. Sub_Res.Carry = 0). CT_Mux'd, branchless.
         Sub_Res := CT_Sub (Sum, N, 1);
         Ctl := CT_Neq (Add_Res.Carry, 0)
                or CT_Eq (Sub_Res.Carry, 0);
         for I in 0 .. Sum.Len - 1 loop
            Sum.W (I) := CT_Mux (Ctl, Sub_Res.Value.W (I), Sum.W (I));
         end loop;
      end;

      Inv_Mod_N (K_Inv, K_Int);

      T1 := K_Inv;
      To_Monty (T1, N, N_M0I);
      T2 := Sum;
      To_Monty (T2, N, N_M0I);
      Mul_Mod_N (S_Int, T1, T2);
      Mul_Mod_N (T1, S_Int, One);
      S_Int := T1;

      Encode (R_Out, R_Int);
      Encode (S_Out, S_Int);
      OK := True;
   end Sign;

   procedure Public_Key
     (D  : in     Byte_Seq;
      Qx :    out Byte_Seq;
      Qy :    out Byte_Seq)
   is
      G_Pt : Jacobian;
      T1   : Big_Nat;
   begin
      Make_Generator (G_Pt);
      Scalar_Mul (G_Pt, D);
      To_Affine (G_Pt);
      FE_From_Monty (T1, G_Pt.X);
      Encode (Qx, T1);
      FE_From_Monty (T1, G_Pt.Y);
      Encode (Qy, T1);
   end Public_Key;

begin
   --  Initialize group order constants N and N_M0I at package elaboration.
   Decode (N, P384_N);
   N.Len := W384;
   N_M0I := Ninv32 (N.W (0));
end SPARKTLSCrypto.P384.ECDSA;
