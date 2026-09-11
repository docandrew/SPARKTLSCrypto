with Interfaces; use Interfaces;

package body SPARKTLSCrypto.BigNat64 with
   SPARK_Mode => On
is

   ----------------------------------------------------------------------------
   --  Constant-time primitives
   ----------------------------------------------------------------------------

   function CT_Not (X : Word) return Word is
     (X xor 1);

   function CT_Mux (Ctl, X, Y : Word) return Word is
     (Y xor ((-Ctl) and (X xor Y)));

   function CT_Eq (X, Y : Word) return Word is
      Q : constant Word := X xor Y;
   begin
      return CT_Not (Shift_Right (Q or (-Q), Word_Bits - 1));
   end CT_Eq;

   function CT_Neq (X, Y : Word) return Word is
      Q : constant Word := X xor Y;
   begin
      return Shift_Right (Q or (-Q), Word_Bits - 1);
   end CT_Neq;

   ----------------------------------------------------------------------------
   --  Ninv: compute -M^(-1) mod 2^64 by Newton's method (each step
   --  doubles the number of correct low bits: 2, 4, 8, 16, 32, 64)
   ----------------------------------------------------------------------------

   function Ninv (M0 : Word) return Word is
      Y : Word;
   begin
      Y := 2 - M0;
      Y := Y * (2 - Y * M0);
      Y := Y * (2 - Y * M0);
      Y := Y * (2 - Y * M0);
      Y := Y * (2 - Y * M0);
      Y := Y * (2 - Y * M0);
      return CT_Mux (M0 and 1, -Y, 0);
   end Ninv;

   ----------------------------------------------------------------------------
   --  Zero
   ----------------------------------------------------------------------------

   procedure Zero
     (Result : out Big_Nat;
      Len    : in  Word_Count)
   is
   begin
      Result.Len := Len;
      Result.W   := (others => 0);
   end Zero;

   ----------------------------------------------------------------------------
   --  CT_Sub: constant-time conditional subtraction
   --  Returns (A - B, borrow) if Ctl=1, (A, 0) if Ctl=0
   ----------------------------------------------------------------------------

   function CT_Sub
     (A, B : Big_Nat;
      Ctl  : Word) return Arith_Result
   is
      R  : Big_Nat;
      CC : DWord := 0;
   begin
      R.Len := A.Len;
      R.W   := (others => 0);

      for I in 0 .. A.Len - 1 loop
         pragma Loop_Invariant (R.Len = A.Len);
         declare
            Aw  : constant Word := A.W (I);
            Bw  : constant Word := B.W (I);
            Diff : DWord;
         begin
            Diff := DWord (Aw) - DWord (Bw) - CC;
            R.W (I) := CT_Mux (Ctl, Word (Diff and Word_Mask), Aw);
            CC := Shift_Right (Diff, 2 * Word_Bits - 1) and 1;
         end;
      end loop;

      return (Value => R, Carry => Word (CC));
   end CT_Sub;

   ----------------------------------------------------------------------------
   --  CT_Add: constant-time conditional addition
   ----------------------------------------------------------------------------

   function CT_Add
     (A, B : Big_Nat;
      Ctl  : Word) return Arith_Result
   is
      R  : Big_Nat;
      CC : DWord := 0;
   begin
      R.Len := A.Len;
      R.W   := (others => 0);

      for I in 0 .. A.Len - 1 loop
         pragma Loop_Invariant (R.Len = A.Len);
         declare
            Aw : constant Word := A.W (I);
            Bw : constant Word := B.W (I);
            Sum : DWord;
         begin
            Sum := DWord (Aw) + DWord (Bw) + CC;
            R.W (I) := CT_Mux (Ctl, Word (Sum and Word_Mask), Aw);
            CC := Shift_Right (Sum, Word_Bits);
         end;
      end loop;

      return (Value => R, Carry => Word (CC));
   end CT_Add;

   ----------------------------------------------------------------------------
   --  Decode: big-endian bytes -> Big_Nat (little-endian words)
   ----------------------------------------------------------------------------

   procedure Decode
     (Result : out Big_Nat;
      Src    : in  Byte_Seq)
   is
      N : constant Natural := Natural (Src'Length);
   begin
      Result.W := (others => 0);
      --  Byte I from the end lands in word I / 8, shifted by 8 (I mod 8).
      for I in 0 .. N - 1 loop
         pragma Loop_Invariant (I < N);
         declare
            Wi : constant Natural := I / Word_Bytes;
            Sh : constant Natural := (I mod Word_Bytes) * 8;
         begin
            Result.W (Wi) := Result.W (Wi) or
              Shift_Left (Word (Src (Src'Last - N32 (I))), Sh);
         end;
      end loop;
      Result.Len := (N + Word_Bytes - 1) / Word_Bytes;
   end Decode;

   ----------------------------------------------------------------------------
   --  Encode: Big_Nat (little-endian words) -> big-endian bytes
   ----------------------------------------------------------------------------

   procedure Encode
     (Dst : out Byte_Seq;
      A   : in  Big_Nat)
   is
      N : constant Natural := Natural (Dst'Length);
   begin
      Dst := (others => 0);
      --  Big-endian, right-aligned: byte I from the end is bits
      --  8 (I mod 8) .. of word I / 8. Words above A.Len are zero in every
      --  value this package produces, so no length case is special.
      for I in 0 .. N - 1 loop
         pragma Loop_Invariant (I < N);
         declare
            Wi : constant Natural := I / Word_Bytes;
            Sh : constant Natural := (I mod Word_Bytes) * 8;
         begin
            Dst (Dst'Last - N32 (I)) :=
              Byte (Shift_Right (A.W (Wi), Sh) and 16#FF#);
         end;
      end loop;
   end Encode;

   ----------------------------------------------------------------------------
   --  To_Monty: convert A to Montgomery domain
   --  A := A * R mod M, where R = 2^(32*Len)
   --  Uses repeated doubling.
   ----------------------------------------------------------------------------

   procedure To_Monty
     (A   : in out Big_Nat;
      M   : in     Big_Nat;
      M0I : in     Word)
   is
      pragma Unreferenced (M0I);
      Total_Bits : constant Natural := M.Len * Word_Bits;
   begin
      for Bit in 1 .. Total_Bits loop
         pragma Loop_Invariant (A.Len = M.Len);
         declare
            Carry : Word := 0;
            Trial : Arith_Result;
            Final : Arith_Result;
         begin
            --  A := A * 2 (shift left by 1 bit)
            for J in 0 .. A.Len - 1 loop
               pragma Loop_Invariant (A.Len = M.Len);
               declare
                  W         : constant Word := A.W (J);
                  New_Carry : constant Word := Shift_Right (W, Word_Bits - 1);
               begin
                  A.W (J) := Shift_Left (W, 1) or Carry;
                  Carry := New_Carry;
               end;
            end loop;

            --  Trial subtraction: check if A >= M
            Trial := CT_Sub (A, M, 0);
            --  Real subtraction: if carry or no borrow
            Final := CT_Sub (A, M,
               CT_Neq (Carry, 0) or CT_Not (Trial.Carry));
            A := Final.Value;
         end;
      end loop;
   end To_Monty;

   ----------------------------------------------------------------------------
   --  Montgomery multiplication: Result = A * B * R^(-1) mod M
   ----------------------------------------------------------------------------

   procedure Monty_Mul
     (Result : out Big_Nat;
      A, B   : in  Big_Nat;
      M      : in  Big_Nat;
      M0I    : in  Word)
   is
      Len : constant Word_Count := M.Len;
      DH  : DWord := 0;
   begin
      Zero (Result, Len);

      for U in 0 .. Len - 1 loop
         pragma Loop_Invariant (Result.Len = Len);
         declare
            AU : constant Word := A.W (U);
            F  : constant Word :=
               (Result.W (0) + AU * B.W (0)) * M0I;
            R1 : DWord := 0;
            R2 : DWord := 0;
         begin
            for V in 0 .. Len - 1 loop
               pragma Loop_Invariant (Result.Len = Len);
               declare
                  Z : DWord;
                  T : Word;
               begin
                  Z := DWord (Result.W (V)) +
                       DWord (AU) * DWord (B.W (V)) + R1;
                  R1 := Shift_Right (Z, Word_Bits);
                  T := Word (Z and Word_Mask);
                  Z := DWord (T) +
                       DWord (F) * DWord (M.W (V)) + R2;
                  R2 := Shift_Right (Z, Word_Bits);
                  if V > 0 then
                     Result.W (V - 1) := Word (Z and Word_Mask);
                  end if;
               end;
            end loop;

            declare
               ZH : constant DWord := DH + R1 + R2;
            begin
               Result.W (Len - 1) := Word (ZH and Word_Mask);
               DH := Shift_Right (ZH, Word_Bits);
            end;
         end;
      end loop;

      --  Final reduction: if DH or Result >= M, subtract M
      declare
         Trial : constant Arith_Result := CT_Sub (Result, M, 0);
         Final : constant Arith_Result := CT_Sub (Result, M,
            CT_Neq (Word (DH and Word_Mask), 0) or
            CT_Not (Trial.Carry));
      begin
         Result := Final.Value;
      end;
   end Monty_Mul;

   ----------------------------------------------------------------------------
   --  Modular exponentiation: Result = Base^Exp mod M
   --  Right-to-left binary method with Montgomery multiplication.
   ----------------------------------------------------------------------------

   procedure R2_Mod
     (R2  : out Big_Nat;
      M   : in  Big_Nat;
      M0I : in  Word)
   is
      Len   : constant Word_Count := M.Len;
      Z     : Big_Nat;
      T     : Big_Nat;
      Bits  : Natural := Word_Bits * Len;   --  R = 2^Bits; we want 2^(2 Bits) mod M
      Odd   : Natural;               --  Bits = Odd * 2^J
      J     : Natural := 0;
   begin
      --  R mod M = 2^Bits - M  (M has its top bit set, so this is < M
      --  and non-negative): 0 - M with the borrow discarded.
      Zero (Z, Len);
      declare
         Neg : constant Arith_Result := CT_Sub (Z, M, 1);
      begin
         T := Neg.Value;
      end;
      pragma Assert (T.Len = Len);

      --  Factor Bits = Odd * 2^J
      Odd := Bits;
      while Odd mod 2 = 0 and then Odd > 0 loop
         pragma Loop_Invariant (Odd > 0 and Odd <= Bits);
         --  Each halving of an even Odd removes at least one from Odd, so
         --  J stays bounded by the total amount removed so far.
         pragma Loop_Invariant (J <= Bits - Odd);
         pragma Loop_Variant (Decreases => Odd);
         Odd := Odd / 2;
         J := J + 1;
      end loop;

      --  T := 2^(Bits + Odd) mod M by Odd doublings of 2^Bits mod M
      for D in 1 .. Odd loop
         pragma Loop_Invariant (T.Len = Len);
         declare
            Carry : Word := 0;
            Trial : Arith_Result;
            Final : Arith_Result;
         begin
            for K in 0 .. Len - 1 loop
               pragma Loop_Invariant (T.Len = Len);
               declare
                  W         : constant Word := T.W (K);
                  New_Carry : constant Word := Shift_Right (W, Word_Bits - 1);
               begin
                  T.W (K) := Shift_Left (W, 1) or Carry;
                  Carry := New_Carry;
               end;
            end loop;
            Trial := CT_Sub (T, M, 0);
            Final := CT_Sub (T, M, CT_Neq (Carry, 0) or CT_Not (Trial.Carry));
            T := Final.Value;
         end;
      end loop;

      --  Each Montgomery squaring maps 2^(Bits + k) to 2^(Bits + 2k):
      --  J of them turn 2^(Bits + Odd) into 2^(Bits + Odd * 2^J) = R^2.
      for S in 1 .. J loop
         pragma Loop_Invariant (T.Len = Len);
         declare
            Sq : Big_Nat;
         begin
            Monty_Mul (Sq, T, T, M, M0I);
            T := Sq;
         end;
      end loop;
      R2 := T;
   end R2_Mod;

   procedure Modpow_Public
     (Result : out Big_Nat;
      Base   : in  Big_Nat;
      Exp    : in  Word;
      M      : in  Big_Nat;
      M0I    : in  Word;
      R2     : in  Big_Nat)
   is
      Len   : constant Word_Count := M.Len;
      B_M   : Big_Nat;   --  Base in Montgomery form
      Acc   : Big_Nat;   --  accumulator, Montgomery form
      One   : Big_Nat;
      Tmp   : Big_Nat;
      Top   : Natural := Word_Bits - 1;
   begin
      Monty_Mul (B_M, Base, R2, M, M0I);
      --  Find the top set bit of Exp (Exp > 0)
      while Top > 0 and then (Shift_Right (Exp, Top) and 1) = 0 loop
         pragma Loop_Variant (Decreases => Top);
         Top := Top - 1;
      end loop;
      --  Acc := Base_M (the top bit is set)
      Acc := B_M;
      if Top > 0 then
         for Bit in reverse 0 .. Top - 1 loop
            pragma Loop_Invariant (Acc.Len = Len and B_M.Len = Len);
            Monty_Mul (Tmp, Acc, Acc, M, M0I);
            Acc := Tmp;
            if (Shift_Right (Exp, Bit) and 1) /= 0 then
               Monty_Mul (Tmp, Acc, B_M, M, M0I);
               Acc := Tmp;
            end if;
         end loop;
      end if;
      --  Leave the Montgomery domain: Acc * 1 * R^-1
      Zero (One, Len);
      One.W (0) := 1;
      Monty_Mul (Result, Acc, One, M, M0I);
   end Modpow_Public;

   --  Fixed-window (4-bit) constant-time exponentiation from Montgomery
   --  forms of Base (Base_M) and of 1 (One_M); shared by Modpow and
   --  Modpow_Top, which differ only in how those forms are obtained.
   procedure Modpow_Core
     (Result : out Big_Nat;
      Base_M : in  Big_Nat;
      One_M  : in  Big_Nat;
      Exp    : in  Byte_Seq;
      M      : in  Big_Nat;
      M0I    : in  Word)
   with Pre  => Base_M.Len = M.Len and One_M.Len = M.Len and M.Len > 0
                and Exp'First = 0 and Exp'Length > 0
                and Exp'Last < N32'Last / 8,
        Post => Result.Len = M.Len;

   procedure Modpow_Core
     (Result : out Big_Nat;
      Base_M : in  Big_Nat;
      One_M  : in  Big_Nat;
      Exp    : in  Byte_Seq;
      M      : in  Big_Nat;
      M0I    : in  Word)
   is
      Len     : constant Word_Count := M.Len;
      subtype Window is Natural range 0 .. 15;
      type Table is array (Window) of Big_Nat;
      T       : Table;
      Acc     : Big_Nat;
      Tmp     : Big_Nat;
      Sel     : Big_Nat;
      One     : Big_Nat;
      Total_Bits : constant N32 := N32 (Exp'Length) * 8;
   begin
      --  T (w) = Base^w in Montgomery form
      T (0) := One_M;
      T (1) := Base_M;
      for W in 2 .. 15 loop
         pragma Loop_Invariant (for all K in 0 .. W - 1 => T (K).Len = Len);
         Monty_Mul (Tmp, T (W - 1), Base_M, M, M0I);
         T (W) := Tmp;
      end loop;
      pragma Assert (for all K in Window => T (K).Len = Len);

      --  Windows from the most significant. Total_Bits is a multiple of
      --  8, hence of 4; the top windows of a short exponent are simply
      --  zero and cost the same as any other (constant time).
      Acc := One_M;
      declare
         N_Windows : constant N32 := Total_Bits / 4;
      begin
         for WI in 0 .. N_Windows - 1 loop
            pragma Loop_Invariant (Acc.Len = Len);
            declare
               --  Window WI covers bits [Total_Bits - 4 (WI + 1), Total_Bits - 4 WI)
               Bit0     : constant N32 := Total_Bits - 4 * (WI + 1);
               Byte_Idx : constant N32 := Exp'Last - Bit0 / 8;
               Shift    : constant Natural := Natural (Bit0 mod 8);
               W        : constant Window :=
                 Window (Shift_Right (Word (Exp (Byte_Idx)), Shift) and 15);
            begin
               for S in 1 .. 4 loop
                  pragma Loop_Invariant (Acc.Len = Len);
                  Monty_Mul (Tmp, Acc, Acc, M, M0I);
                  Acc := Tmp;
               end loop;
               --  Constant-time table select: Sel := T (W)
               Zero (Sel, Len);
               for K in Window loop
                  pragma Loop_Invariant (Sel.Len = Len);
                  declare
                     --  CT_Eq yields 0/1; negate into an all-ones mask
                     Mask : constant Word := -CT_Eq (Word (K), Word (W));
                  begin
                     for I in 0 .. Len - 1 loop
                        pragma Loop_Invariant (Sel.Len = Len);
                        Sel.W (I) := Sel.W (I) or (Mask and T (K).W (I));
                     end loop;
                  end;
               end loop;
               Monty_Mul (Tmp, Acc, Sel, M, M0I);
               Acc := Tmp;
            end;
         end loop;
      end;

      --  Leave the Montgomery domain
      Zero (One, Len);
      One.W (0) := 1;
      Monty_Mul (Result, Acc, One, M, M0I);
   end Modpow_Core;

   procedure Modpow
     (Result : out Big_Nat;
      Base   : in  Big_Nat;
      Exp    : in  Byte_Seq;
      M      : in  Big_Nat;
      M0I    : in  Word)
   is
      Len     : constant Word_Count := M.Len;
      Base_M  : Big_Nat;   --  Base in Montgomery form
      One_M   : Big_Nat;   --  R mod M (Montgomery one)
   begin
      --  Montgomery forms of 1 and Base. The branch is on M's top bit:
      --  every caller of this entry passes a public modulus (RSA n,
      --  the P-384 field and group orders); the CRT path uses Modpow_Top.
      if Top_Bit_Set (M.W (Len - 1)) then
         declare
            R2  : Big_Nat;
            Z   : Big_Nat;
         begin
            R2_Mod (R2, M, M0I);
            Monty_Mul (Base_M, Base, R2, M, M0I);
            --  R mod M = 2^(64 Len) - M
            Zero (Z, Len);
            One_M := CT_Sub (Z, M, 1).Value;
         end;
      else
         Base_M := Base;
         To_Monty (Base_M, M, M0I);
         Zero (One_M, Len);
         One_M.W (0) := 1;
         To_Monty (One_M, M, M0I);
      end if;
      Modpow_Core (Result, Base_M, One_M, Exp, M, M0I);
   end Modpow;

   procedure Modpow_Top
     (Result : out Big_Nat;
      Base   : in  Big_Nat;
      Exp    : in  Byte_Seq;
      M      : in  Big_Nat;
      M0I    : in  Word)
   is
      Len     : constant Word_Count := M.Len;
      Base_M  : Big_Nat;
      One_M   : Big_Nat;
      R2      : Big_Nat;
      Z       : Big_Nat;
   begin
      R2_Mod (R2, M, M0I);
      Monty_Mul (Base_M, Base, R2, M, M0I);
      Zero (Z, Len);
      One_M := CT_Sub (Z, M, 1).Value;
      Modpow_Core (Result, Base_M, One_M, Exp, M, M0I);
   end Modpow_Top;

   ----------------------------------------------------------------------------
   --  CRT support: plain multiply-add, Montgomery-based reduction, and
   --  modular subtraction.
   ----------------------------------------------------------------------------

   procedure Mul_Add
     (Result  : out Big_Nat;
      A, B, C : in  Big_Nat)
   is
      Len : constant Word_Count := A.Len;
   begin
      Zero (Result, 2 * Len);

      --  Seed the low half with C; the upper half is zero.
      for I in 0 .. Len - 1 loop
         pragma Loop_Invariant (Result.Len = 2 * Len);
         Result.W (I) := C.W (I);
      end loop;

      --  Row I adds A (I) * B * 2^(64 I). Position I + Len is still zero
      --  when the row's final carry lands there (row I - 1 wrote up to
      --  I + Len - 1), so a plain store is exact.
      for I in 0 .. Len - 1 loop
         pragma Loop_Invariant (Result.Len = 2 * Len);
         declare
            AI    : constant Word := A.W (I);
            Carry : DWord := 0;
         begin
            for J in 0 .. Len - 1 loop
               pragma Loop_Invariant (Result.Len = 2 * Len);
               pragma Loop_Invariant (Carry <= Word_Mask);
               declare
                  Z : constant DWord :=
                    DWord (Result.W (I + J)) +
                    DWord (AI) * DWord (B.W (J)) + Carry;
               begin
                  Result.W (I + J) := Word (Z and Word_Mask);
                  Carry := Shift_Right (Z, Word_Bits);
               end;
            end loop;
            Result.W (I + Len) := Word (Carry);
         end;
      end loop;
   end Mul_Add;

   procedure Mod_Reduce
     (Result : out Big_Nat;
      X      : in  Big_Nat;
      M      : in  Big_Nat;
      M0I    : in  Word;
      R2     : in  Big_Nat)
   is
      Len : constant Word_Count := M.Len;
      Lo  : Big_Nat;
      Hi  : Big_Nat;
      R3  : Big_Nat;
      A   : Big_Nat;
      B   : Big_Nat;
      S   : Big_Nat;
      One : Big_Nat;
   begin
      --  X = Hi * R + Lo, both halves as Len-word values. Words of X
      --  above X.Len are zero, so a short X simply has Hi = 0.
      Zero (Lo, Len);
      Zero (Hi, Len);
      for I in 0 .. Len - 1 loop
         pragma Loop_Invariant (Lo.Len = Len and Hi.Len = Len);
         Lo.W (I) := X.W (I);
         Hi.W (I) := X.W (Len + I);
      end loop;

      --  R3 = R^3 mod M
      Monty_Mul (R3, R2, R2, M, M0I);
      --  A = Lo * R mod M ; B = Hi * R^2 mod M
      --  (inputs are < R, constants < M, so both products are < R * M
      --  and the Montgomery outputs are fully reduced)
      Monty_Mul (A, Lo, R2, M, M0I);
      Monty_Mul (B, Hi, R3, M, M0I);

      --  S = A + B mod M: both terms are < M, so at most one subtraction.
      declare
         Sum   : constant Arith_Result := CT_Add (A, B, 1);
         Trial : constant Arith_Result := CT_Sub (Sum.Value, M, 0);
         Final : constant Arith_Result := CT_Sub (Sum.Value, M,
            CT_Neq (Sum.Carry, 0) or CT_Not (Trial.Carry));
      begin
         S := Final.Value;
      end;

      --  S = X * R mod M; leave the Montgomery domain.
      Zero (One, Len);
      One.W (0) := 1;
      Monty_Mul (Result, S, One, M, M0I);
   end Mod_Reduce;

   procedure Sub_Mod
     (Result  : out Big_Nat;
      A, B, M : in  Big_Nat)
   is
      Diff  : constant Arith_Result := CT_Sub (A, B, 1);
      Fixed : constant Arith_Result := CT_Add (Diff.Value, M, Diff.Carry);
   begin
      Result := Fixed.Value;
   end Sub_Mod;

end SPARKTLSCrypto.BigNat64;
