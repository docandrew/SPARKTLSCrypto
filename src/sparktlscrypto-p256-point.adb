--  SPARKTLS P-256 Point Arithmetic (body)
--  Ported from BearSSL's ec_p256_m31.c

with SPARKTLSCrypto.P256.Fixed_Base; use SPARKTLSCrypto.P256.Fixed_Base;
with SPARKTLSCrypto.P256_Gather_AVX2;
with SPARKTLSCrypto.CPU;

package body SPARKTLSCrypto.P256.Point with
   SPARK_Mode => On
is
   --  Curve parameter b in Montgomery representation.
   --  b = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
   --  b_mont = b * R mod p where R = 2^256
   P256_B : constant P256_FE :=
     (16#D89CDF6229C4BDDF#,
      16#ACF005CD78843090#,
      16#E5A220ABF7212ED6#,
      16#DC30061D04874834#);


   procedure CT_Copy_Point
     (Ctl : in     U32;
      Dst : in out P256_Jacobian;
      Src : in     P256_Jacobian)
   is
   begin
      CT_Copy (Ctl, Dst.X, Src.X);
      CT_Copy (Ctl, Dst.Y, Src.Y);
      CT_Copy (Ctl, Dst.Z, Src.Z);
   end CT_Copy_Point;

   ---------------------------------------------------------------
   --  Point doubling
   ---------------------------------------------------------------

   procedure P256_Double (Q : in out P256_Jacobian) is
      --  EFD dbl-2001-b formula optimized for a = -3 (3M + 5S)
      --  Saves 1 Mul vs generic BearSSL formula (4M + 4S) by computing
      --  Z' = (Y+Z)^2 - gamma - delta instead of Z' = 2*Y*Z.
      Dlt, Gamma, Beta, Alpha : P256_FE;
      T1, T2 : P256_FE;
   begin
      --  delta = Z^2
      Dlt := Square_F256 (Q.Z);                           -- 1S

      --  gamma = Y^2
      Gamma := Square_F256 (Q.Y);                           -- 2S

      --  beta = X * gamma
      Beta := Mul_F256 (Q.X, Gamma);                        -- 1M

      --  alpha = 3 * (X - delta) * (X + delta)   [uses a = -3]
      T1 := Sub_F256 (Q.X, Dlt);
      T2 := Add_F256 (Q.X, Dlt);
      Alpha := Mul_F256 (T1, T2);                           -- 2M
      T1 := Add_F256 (Alpha, Alpha);
      Alpha := Add_F256 (Alpha, T1);                -- alpha = 3 * (X^2 - Z^4)

      --  X' = alpha^2 - 8*beta
      T1 := Add_F256 (Beta, Beta);                  -- 2*beta
      T1 := Add_F256 (T1, T1);                      -- 4*beta
      T2 := Add_F256 (T1, T1);                      -- 8*beta
      Q.X := Square_F256 (Alpha);                           -- 3S
      Q.X := Sub_F256 (Q.X, T2);                   -- X' = alpha^2 - 8*beta

      --  Z' = (Y + Z)^2 - gamma - delta   [saves 1 Mul vs 2*Y*Z]
      T1 := Add_F256 (Q.Y, Q.Z);
      Q.Z := Square_F256 (T1);                              -- 4S
      Q.Z := Sub_F256 (Q.Z, Gamma);
      Q.Z := Sub_F256 (Q.Z, Dlt);

      --  Y' = alpha * (4*beta - X') - 8*gamma^2
      T1 := Add_F256 (Beta, Beta);                  -- 2*beta
      T1 := Add_F256 (T1, T1);                      -- 4*beta
      T1 := Sub_F256 (T1, Q.X);                    -- 4*beta - X'
      Q.Y := Mul_F256 (Alpha, T1);                          -- 3M
      T2 := Square_F256 (Gamma);                             -- 5S
      T2 := Add_F256 (T2, T2);                      -- 2*gamma^2
      T2 := Add_F256 (T2, T2);                      -- 4*gamma^2
      T2 := Add_F256 (T2, T2);                      -- 8*gamma^2
      Q.Y := Sub_F256 (Q.Y, T2);
   end P256_Double;

   ---------------------------------------------------------------
   --  Point addition (full Jacobian)
   ---------------------------------------------------------------

   procedure P256_Add
     (P1  : in out P256_Jacobian;
      P2  : in     P256_Jacobian;
      Ret :    out U32)
   is
      T1, T2, T3, T4, T5, T6, T7 : P256_FE;
      R64 : Unsigned_64;
   begin
      --  u1 = x1*z2^2 (in T1), s1 = y1*z2^3 (in T3)
      T3 := Square_F256 (P2.Z);
      T1 := Mul_F256 (P1.X, T3);
      T4 := Mul_F256 (P2.Z, T3);
      T3 := Mul_F256 (P1.Y, T4);

      --  u2 = x2*z1^2 (in T2), s2 = y2*z1^3 (in T4)
      T4 := Square_F256 (P1.Z);
      T2 := Mul_F256 (P2.X, T4);
      T5 := Mul_F256 (P1.Z, T4);
      T4 := Mul_F256 (P2.Y, T5);

      --  h = u2 - u1 (in T2), r = s2 - s1 (in T4)
      T2 := Sub_F256 (T2, T1);
      T4 := Sub_F256 (T4, T3);

      --  Check if r (T4) is nonzero — Montgomery zero is all-zero limbs
      R64 := T4 (0) or T4 (1) or T4 (2) or T4 (3);
      --  Fold 64-bit to 32-bit nonzero flag
      Ret := U32 (R64 and 16#FFFF_FFFF#) or U32 (Shift_Right (R64, 32));
      Ret := Shift_Right ((Ret or (0 - Ret)), 31);

      --  u1*h^2 (in T6), h^3 (in T5)
      T7 := Square_F256 (T2);
      T6 := Mul_F256 (T1, T7);
      T5 := Mul_F256 (T7, T2);

      --  x3 = r^2 - h^3 - 2*u1*h^2
      P1.X := Square_F256 (T4);
      P1.X := Sub_F256 (P1.X, T5);
      P1.X := Sub_F256 (P1.X, T6);
      P1.X := Sub_F256 (P1.X, T6);

      --  y3 = r*(u1*h^2 - x3) - s1*h^3
      T6 := Sub_F256 (T6, P1.X);
      P1.Y := Mul_F256 (T4, T6);
      T1 := Mul_F256 (T5, T3);
      P1.Y := Sub_F256 (P1.Y, T1);

      --  z3 = h*z1*z2
      T1 := Mul_F256 (P1.Z, P2.Z);
      P1.Z := Mul_F256 (T1, T2);
   end P256_Add;

   ---------------------------------------------------------------
   --  Point addition, mixed (P2 is affine: z2 = 1)
   ---------------------------------------------------------------

   procedure P256_Add_Mixed
     (P1  : in out P256_Jacobian;
      P2  : in     P256_Jacobian;
      Ret :    out U32)
   is
      T1, T2, T3, T4, T5, T6, T7 : P256_FE;
      R64 : Unsigned_64;
   begin
      --  u1 = x1 (in T1), s1 = y1 (in T3)
      T1 := P1.X;
      T3 := P1.Y;

      --  u2 = x2*z1^2 (in T2), s2 = y2*z1^3 (in T4)
      T4 := Square_F256 (P1.Z);
      T2 := Mul_F256 (P2.X, T4);
      T5 := Mul_F256 (P1.Z, T4);
      T4 := Mul_F256 (P2.Y, T5);

      --  h = u2 - u1 (in T2), r = s2 - s1 (in T4)
      T2 := Sub_F256 (T2, T1);
      T4 := Sub_F256 (T4, T3);

      --  Check if r (T4) is nonzero — Montgomery zero is all-zero limbs
      R64 := T4 (0) or T4 (1) or T4 (2) or T4 (3);
      --  Fold 64-bit to 32-bit nonzero flag
      Ret := U32 (R64 and 16#FFFF_FFFF#) or U32 (Shift_Right (R64, 32));
      Ret := Shift_Right ((Ret or (0 - Ret)), 31);

      --  u1*h^2 (in T6), h^3 (in T5)
      T7 := Square_F256 (T2);
      T6 := Mul_F256 (T1, T7);
      T5 := Mul_F256 (T7, T2);

      --  x3 = r^2 - h^3 - 2*u1*h^2
      P1.X := Square_F256 (T4);
      P1.X := Sub_F256 (P1.X, T5);
      P1.X := Sub_F256 (P1.X, T6);
      P1.X := Sub_F256 (P1.X, T6);

      --  y3 = r*(u1*h^2 - x3) - s1*h^3
      T6 := Sub_F256 (T6, P1.X);
      P1.Y := Mul_F256 (T4, T6);
      T1 := Mul_F256 (T5, T3);
      P1.Y := Sub_F256 (P1.Y, T1);

      --  z3 = h*z1 (z2 = 1)
      P1.Z := Mul_F256 (P1.Z, T2);
   end P256_Add_Mixed;

   ---------------------------------------------------------------
   --  Convert to affine via modular inversion z^(p-2)
   ---------------------------------------------------------------

   --  Modular inversion in GF(p): D := A^(p-2) mod p
   procedure P256_Inv (D : out P256_FE; A : in P256_FE) is
      T1, T2 : P256_FE;
   begin
      --  Compute a^(2^31-1) via square-and-multiply
      T1 := A;
      for I in 0 .. 29 loop
         T1 := Square_F256 (T1);
         T1 := Mul_F256 (T1, A);
      end loop;

      --  Main exponentiation loop for p-2
      T2 := A;
      for I in 1 .. 255 loop
         T2 := Square_F256 (T2);
         case I is
            when 31 | 190 | 221 | 252 =>
               T2 := Mul_F256 (T2, T1);
            when 63 | 253 | 255 =>
               T2 := Mul_F256 (T2, A);
            when others =>
               null;
         end case;
      end loop;
      D := T2;
   end P256_Inv;

   procedure P256_To_Affine (P : in out P256_Jacobian) is
      ZI, T1 : P256_FE;
   begin
      P256_Inv (ZI, P.Z);

      --  x := x * (1/z)^2, y := y * (1/z)^3
      T1 := Mul_F256 (ZI, ZI);
      P.X := Mul_F256 (T1, P.X);
      T1 := Mul_F256 (T1, ZI);
      P.Y := Mul_F256 (T1, P.Y);

      --  z := z * (1/z) = 1 (or 0 if z was 0)
      P.Z := Mul_F256 (P.Z, ZI);
   end P256_To_Affine;

   ---------------------------------------------------------------
   --  Decode uncompressed point (04 || X[32] || Y[32])
   ---------------------------------------------------------------

   --  Prime p, big-endian.
   P256_P_Bytes : constant Byte_Seq (0 .. 31) :=
     (16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#00#, 16#00#, 16#00#, 16#01#,
      16#00#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#,
      16#00#, 16#00#, 16#00#, 16#00#, 16#FF#, 16#FF#, 16#FF#, 16#FF#,
      16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#);

   --  1 when the 32-byte big-endian value is < p, else 0 (SEC 1
   --  3.2.2.1 range check). Borrow chain from the least significant
   --  byte; the borrow is the sign bit of the modular difference. No
   --  branch on the data.
   function Below_P (Src : Byte_Seq) return U32
   with Pre => Src'Length = 32
   is
      Buf    : constant Byte_Seq (0 .. 31) := Src;
      Borrow : U32 := 0;
      D      : U32;
   begin
      for I in reverse Buf'Range loop
         D := U32 (Buf (I)) - U32 (P256_P_Bytes (I)) - Borrow;
         Borrow := D / 16#8000_0000#;
      end loop;
      return Borrow;
   end Below_P;

   procedure P256_Decode
     (P     :    out P256_Jacobian;
      Src   : in     Byte_Seq;
      Valid :    out U32)
   is
      TX, TY, T1, T2 : P256_FE;
      Bad   : U32;
   begin
      Bad := CT_NEQ (U32 (Src (0)), 16#04#);

      --  Coordinates must be canonical: x, y < p.
      Bad := Bad or (1 - Below_P (Src (1 .. 32))) or (1 - Below_P (Src (33 .. 64)));

      Bytes_To_FE (TX, Src (1 .. 32));
      Bytes_To_FE (TY, Src (33 .. 64));

      --  Check curve equation: y^2 = x^3 - 3x + b
      T1 := Square_F256 (TX);
      T1 := Mul_F256 (TX, T1);
      T2 := Square_F256 (TY);
      T1 := Sub_F256 (T1, TX);
      T1 := Sub_F256 (T1, TX);
      T1 := Sub_F256 (T1, TX);
      T1 := Add_F256 (T1, P256_B);
      T1 := Sub_F256 (T1, T2);

      --  Check if T1 is zero (curve equation satisfied)
      if not FE_Is_Zero (T1) then
         Bad := Bad or 1;
      end if;

      P.X := TX;
      P.Y := TY;
      P.Z := FE_One;
      Valid := CT_EQ (Bad, 0);
   end P256_Decode;

   ---------------------------------------------------------------
   --  Encode point to uncompressed format
   ---------------------------------------------------------------

   procedure P256_Encode
     (Dst : out Byte_Seq;
      P   : in  P256_Jacobian)
   is
   begin
      Dst (0) := 16#04#;
      FE_To_Bytes (Dst (1 .. 32), P.X);
      FE_To_Bytes (Dst (33 .. 64), P.Y);
   end P256_Encode;

   ---------------------------------------------------------------
   --  Scalar multiplication, fixed 4-bit windows.
   --
   --  T (w) = [w]P for w in 1 .. 15 is built once (7 doublings and
   --  7 additions), then every nibble of the scalar costs 4 doublings,
   --  one constant-time table scan and one addition: 64 additions
   --  for a 32-byte scalar against 128 with the previous 2-bit form.
   --  The scan reads all 15 live entries for every nibble, and the
   --  identity is tracked with the QZ / BNZ flags exactly as before,
   --  so the operation sequence does not depend on the scalar.
   ---------------------------------------------------------------

   procedure P256_Mul
     (P    : in out P256_Jacobian;
      X    : in     Byte_Seq;
      Xlen : in     N32)
   is
      subtype Window is Natural range 0 .. 15;
      type Point_Table is array (Window) of P256_Jacobian;

      T           : Point_Table;
      Q, U, Sel   : P256_Jacobian;
      QZ, BNZ     : U32;
      Dummy       : U32;
   begin
      --  T (0) is never a live selection (a zero window leaves Q
      --  alone through the flags below); it holds P so that the scan
      --  starts from well-formed data.
      T (0) := P;
      T (1) := P;
      for W in 2 .. 15 loop
         --  The branch is on the loop counter, not on any secret.
         if W mod 2 = 0 then
            T (W) := T (W / 2);
            P256_Double (T (W));
         else
            T (W) := T (W - 1);
            P256_Add (T (W), P, Dummy);
         end if;
      end loop;

      --  Start with Q = 0 (identity)
      Q := (X => FE_Zero, Y => FE_Zero, Z => FE_Zero);
      QZ := 1;

      for J in 0 .. Xlen - 1 loop
         declare
            Bx : constant U32 := U32 (X (J));
         begin
            --  High nibble first, then low nibble
            for Half in reverse 0 .. 1 loop
               declare
                  W : constant U32 := Shift_Right (Bx, Half * 4) and 15;
               begin
                  P256_Double (Q);
                  P256_Double (Q);
                  P256_Double (Q);
                  P256_Double (Q);

                  --  Constant-time select Sel := T (W)
                  Sel := T (0);
                  for K in 1 .. 15 loop
                     CT_Copy_Point (CT_EQ (U32 (K), W), Sel, T (K));
                  end loop;

                  BNZ := CT_NEQ (W, 0);
                  U := Q;
                  P256_Add (U, Sel, Dummy);
                  CT_Copy_Point (BNZ and QZ, Q, Sel);
                  CT_Copy_Point (BNZ and (not QZ), Q, U);
                  QZ := QZ and (not BNZ);
               end;
            end loop;
         end;
      end loop;
      P := Q;
   end P256_Mul;

   ---------------------------------------------------------------
   --  Generator multiplication: fixed-base table, Booth-recoded
   --  7-bit windows (SPARKTLSCrypto.P256.Fixed_Base).
   --
   --  The scalar is read as 46 overlapping 8-bit groups (bits 7i - 1 to
   --  7i + 6, bit -1 and bits past the top being 0) and each is recoded
   --  to a signed digit d_i in -64 .. 64 with k = sum d_i * 2^(7 i).
   --  Window i then adds |d_i| * 2^(7 i) * G, taken from the table by a
   --  constant-time scan of all 64 entries, with y negated when d_i is
   --  negative. No doublings; one lookup and at most one mixed addition
   --  per window (46 windows cover a scalar blinded to 320 bits). The
   --  identity is tracked with the QZ / BNZ flags as in P256_Mul, so the
   --  sequence of operations is fixed for every scalar.
   --  A window's point equal to, or the negative of, the running sum
   --  would meet the mixed addition's doubling exception and yield a
   --  wrong point. For an unblinded 0 < k < n it cannot happen (the
   --  magnitudes differ by more than n allows); for a blinded k + r n
   --  it can, with probability about 2^-249 per window, and the on-curve
   --  check in the ECDSA signer then fails closed.
   ---------------------------------------------------------------

   --  Entry Mag - 1 of window Win of the fixed-base table, or all zero
   --  for Mag = 0, read without a data-dependent address: every entry is
   --  visited and masked. The AVX2 tier does the same with vector
   --  compares; the two agree on every (Win, Mag), which the smoke tests
   --  check.
   procedure Lookup_Fixed_Portable
     (Sel : out Affine_Mont;
      Win : in  Window_Index;
      Mag : in  U32)
   is
      M : U32;
   begin
      Sel := (X => FE_Zero, Y => FE_Zero);
      for K in Entry_Index loop
         M := 0 - CT_EQ (Mag, U32 (K + 1));
         CT_Copy (M, Sel.X, Fixed_G (Win) (K).X);
         CT_Copy (M, Sel.Y, Fixed_G (Win) (K).Y);
      end loop;
   end Lookup_Fixed_Portable;

   procedure Lookup_Fixed
     (Sel : out Affine_Mont;
      Win : in  Window_Index;
      Mag : in  U32)
   is
   begin
      --  The tier flag is fixed at elaboration: no data-dependent branch.
      if SPARKTLSCrypto.CPU.Has_AVX2 then
         SPARKTLSCrypto.P256_Gather_AVX2.Gather (Sel, Fixed_G (Win), Mag);
      else
         Lookup_Fixed_Portable (Sel, Win, Mag);
      end if;
   end Lookup_Fixed;

   --  Shared body of P256_Mulgen and P256_Mulgen_Blinded: the scalar is
   --  up to 40 bytes (a 256-bit key, or k + r n with a 64-bit r), and Lam
   --  randomises the running point after every window (Lam = 1 leaves
   --  the coordinates alone; the multiplies run either way).
   procedure Mulgen_Core
     (P    : out P256_Jacobian;
      X    : in  Byte_Seq;
      Xlen : in  N32;
      Lam  : in  P256_FE)
   with Pre => X'First = 0 and then X'Length <= 40 and then Xlen <= X'Length
   is
      --  Zero-padded scalar (always 40 bytes, big-endian)
      S : Byte_Seq (0 .. 39) := (others => 0);
      --  The same scalar as little-endian words; W (5) = 0 keeps the
      --  extraction of the top window in bounds.
      W : array (0 .. 5) of Unsigned_64 := (others => 0);

      Q, T, U  : P256_Jacobian;
      Sel      : Affine_Mont;
      Neg_Y    : P256_FE;
      Lam2, Lam3 : P256_FE;
      QZ, BNZ  : U32;
      Sgn, Mag : U32;
      In8, D   : Unsigned_64;
      Dummy    : U32;
   begin
      --  Copy scalar into zero-padded 40-byte buffer (right-aligned)
      if Xlen <= 40 then
         for I in 0 .. Xlen - 1 loop
            S (40 - Xlen + I) := X (I);
         end loop;
      else
         S := X (Xlen - 40 .. Xlen - 1);
      end if;
      for I in 0 .. 4 loop
         for B in 0 .. 7 loop
            W (I) := W (I) or
              Shift_Left (Unsigned_64 (S (N32 (39 - 8 * I - B))), 8 * B);
         end loop;
      end loop;
      Lam2 := Square_F256 (Lam);
      Lam3 := Mul_F256 (Lam2, Lam);

      Q := (X => FE_Zero, Y => FE_Zero, Z => FE_Zero);
      QZ := 1;

      for Win in Window_Index loop
         --  Eight bits starting at bit 7 * Win - 1. The selection below
         --  depends only on the window number, never on the scalar.
         if Win = 0 then
            In8 := Shift_Left (W (0), 1) and 16#FF#;
         else
            declare
               Bit : constant Natural := 7 * Win - 1;
               Qw  : constant Natural := Bit / 64;
               Rb  : constant Natural := Bit mod 64;
            begin
               In8 := Shift_Right (W (Qw), Rb);
               if Rb > 56 then
                  In8 := In8 or Shift_Left (W (Qw + 1), 64 - Rb);
               end if;
               In8 := In8 and 16#FF#;
            end;
         end if;

         --  Booth recoding: sign from the top bit; magnitude 0 .. 64
         Sgn := U32 (Shift_Right (In8, 7));
         D   := (In8 xor (0 - Unsigned_64 (Sgn))) and 16#FF#;
         Mag := U32 (Shift_Right (D, 1) + (D and 1));

         --  Constant-time lookup of |d| * 2^(7 Win) * G: every entry read
         Lookup_Fixed (Sel, Win, Mag);
         T.X := Sel.X;
         T.Y := Sel.Y;
         Neg_Y := Sub_F256 (FE_Zero, T.Y);
         CT_Copy (0 - Sgn, T.Y, Neg_Y);
         T.Z := FE_One;

         BNZ := CT_NEQ (Mag, 0);
         U := Q;
         P256_Add_Mixed (U, T, Dummy);
         CT_Copy_Point (BNZ and QZ, Q, T);
         CT_Copy_Point (BNZ and (not QZ), Q, U);
         QZ := QZ and (not BNZ);
         --  Randomise the running point (the identity stays all zero)
         Q.X := Mul_F256 (Q.X, Lam2);
         Q.Y := Mul_F256 (Q.Y, Lam3);
         Q.Z := Mul_F256 (Q.Z, Lam);
      end loop;

      P := Q;
   end Mulgen_Core;

   procedure P256_Mulgen
     (P    : out P256_Jacobian;
      X    : in  Byte_Seq;
      Xlen : in  N32)
   is
   begin
      Mulgen_Core (P, X, Xlen, FE_One);
   end P256_Mulgen;

   --  k + r * n as 40 big-endian bytes, and lambda as a field element
   --  (1 if the random bytes reduce to 0).
   procedure Blinding_Inputs
     (K     : in  Bytes_32;
      Blind : in  Byte_Seq;
      KB    : out Byte_Seq;
      Lam   : out P256_FE)
   with Pre => Blind'First = 0 and then Blind'Length = 40
               and then KB'First = 0 and then KB'Length = 40
   is
      use SPARKTLSCrypto.BigNat64;
      NB, RB, KN, Res : Big_Nat;
      N_Bytes : constant Byte_Seq (0 .. 31) :=
        (16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#00#, 16#00#, 16#00#, 16#00#,
         16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#,
         16#BC#, 16#E6#, 16#FA#, 16#AD#, 16#A7#, 16#17#, 16#9E#, 16#84#,
         16#F3#, 16#B9#, 16#CA#, 16#C2#, 16#FC#, 16#63#, 16#25#, 16#51#);
   begin
      Decode (NB, N_Bytes);
      Decode (KN, Byte_Seq (K));
      Zero (RB, 4);
      for I in 0 .. 7 loop
         RB.W (0) := RB.W (0) or
           Shift_Left (Unsigned_64 (Blind (N32 (7 - I))), 8 * I);
      end loop;
      if NB.Len = 4 and then KN.Len = 4 then
         Mul_Add (Res, NB, RB, KN);        --  n * r + k, 8 words
         Encode (KB, Res);                 --  low 40 bytes: value < 2^320
      else
         KB := (others => 0);
      end if;
      Bytes_To_FE (Lam, Blind (8 .. 39));
      if FE_Is_Zero (Lam) then
         Lam := FE_One;
      end if;
   end Blinding_Inputs;

   procedure P256_Mulgen_Blinded
     (P     : out P256_Jacobian;
      K     : in  Bytes_32;
      Blind : in  Byte_Seq)
   is
      KB  : Byte_Seq (0 .. 39);
      Lam : P256_FE;
   begin
      Blinding_Inputs (K, Blind, KB, Lam);
      Mulgen_Core (P, KB, 40, Lam);
      --  Scrub the blinded scalar (it reveals k given r)
      pragma Warnings (GNATprove, Off, "statement has no effect");
      pragma Warnings (GNATprove, Off, "unused assignment");
      KB := (others => 0);
      pragma Inspection_Point (KB);
      pragma Warnings (GNATprove, On, "unused assignment");
      pragma Warnings (GNATprove, On, "statement has no effect");
   end P256_Mulgen_Blinded;

   procedure P256_Mul_Blinded
     (P     : in out P256_Jacobian;
      K     : in     Bytes_32;
      Blind : in     Byte_Seq)
   is
      KB   : Byte_Seq (0 .. 39);
      Lam, Lam2 : P256_FE;
   begin
      Blinding_Inputs (K, Blind, KB, Lam);
      --  Randomise the input point's projective representation once;
      --  every table entry and the running sum derive from it.
      Lam2 := Square_F256 (Lam);
      P.X := Mul_F256 (P.X, Lam2);
      P.Y := Mul_F256 (P.Y, Mul_F256 (Lam2, Lam));
      P.Z := Mul_F256 (P.Z, Lam);
      P256_Mul (P, KB, 40);
      pragma Warnings (GNATprove, Off, "statement has no effect");
      pragma Warnings (GNATprove, Off, "unused assignment");
      KB := (others => 0);
      pragma Inspection_Point (KB);
      pragma Warnings (GNATprove, On, "unused assignment");
      pragma Warnings (GNATprove, On, "statement has no effect");
   end P256_Mul_Blinded;

   ---------------------------------------------------------------
   --  Public-input scalar multiplication, for signature verification
   --  only. Everything a verifier handles is public (the signature, the
   --  hash, the key), so these two routines may branch and index on the
   --  scalars, as BoringSSL's verify path does. The point arithmetic they
   --  call is the same branch-free code as everywhere else, so an
   --  invalid or unusual public key still takes one path. Never use
   --  them with a secret scalar: P256_Mul and P256_Mulgen are the
   --  constant-time entries for that.
   ---------------------------------------------------------------

   subtype NAF_Digit is Integer range -15 .. 15;
   type NAF_Array is array (0 .. 257) of NAF_Digit;

   --  Width-5 non-adjacent form of the scalar: odd digits in -15 .. 15
   --  with no two adjacent non-zero digits, so at most one addition per
   --  six doublings on average. Top is the index of the highest
   --  non-zero digit, or -1 for the scalar 0.
   procedure WNAF5
     (X    : in  Byte_Seq;
      Xlen : in  N32;
      D    : out NAF_Array;
      Top  : out Integer)
   with Pre  => X'First = 0 and then X'Length <= 32 and then Xlen <= X'Length,
        Post => Top >= -1 and then Top <= 257
                and then (if Top >= 0 then D (Top) /= 0)
   is
      S : Byte_Seq (0 .. 31) := (others => 0);
      K : array (0 .. 4) of Unsigned_64 := (others => 0);
      V : Integer;
   begin
      if Xlen <= 32 then
         for I in 0 .. Xlen - 1 loop
            S (32 - Xlen + I) := X (I);
         end loop;
      else
         S := X (Xlen - 32 .. Xlen - 1);
      end if;
      for I in 0 .. 3 loop
         for B in 0 .. 7 loop
            K (I) := K (I) or
              Shift_Left (Unsigned_64 (S (N32 (31 - 8 * I - B))), 8 * B);
         end loop;
      end loop;

      D   := (others => 0);
      Top := -1;
      for I in D'Range loop
         pragma Loop_Invariant (Top >= -1 and then Top < I);
         pragma Loop_Invariant (if Top >= 0 then D (Top) /= 0);
         if (K (0) and 1) = 1 then
            --  K odd, so its residue mod 32 is odd: V is never 0
            V := Integer (K (0) and 31);
            if V >= 16 then
               V := V - 32;
            end if;
            D (I) := V;
            Top := I;
            --  K := K - V; K stays non-negative (K is odd and V is K's
            --  residue, possibly minus 32) and below 2^257.
            if V > 0 then
               declare
                  Sub    : constant Unsigned_64 := Unsigned_64 (V);
                  Borrow : Boolean := K (0) < Sub;
               begin
                  K (0) := K (0) - Sub;
                  for J in 1 .. 4 loop
                     exit when not Borrow;
                     Borrow := K (J) = 0;
                     K (J) := K (J) - 1;
                  end loop;
               end;
            else
               declare
                  Add   : constant Unsigned_64 := Unsigned_64 (-V);
                  Carry : Boolean;
               begin
                  Carry := K (0) > Unsigned_64'Last - Add;
                  K (0) := K (0) + Add;
                  for J in 1 .. 4 loop
                     exit when not Carry;
                     Carry := K (J) = Unsigned_64'Last;
                     K (J) := K (J) + 1;
                  end loop;
               end;
            end if;
         end if;
         --  K := K / 2
         for J in 0 .. 3 loop
            K (J) := Shift_Right (K (J), 1) or Shift_Left (K (J + 1), 63);
         end loop;
         K (4) := Shift_Right (K (4), 1);
      end loop;
   end WNAF5;

   --  P := [x] * P for a public scalar: wNAF-5 over a table of the odd
   --  multiples P, 3P, ..., 15P. For 0 < x < n the running sum never
   --  equals plus or minus the table point being added (the partial
   --  value is even or smaller than n permits), so the addition never
   --  meets its doubling exception.
   procedure P256_Mul_Public
     (P    : in out P256_Jacobian;
      X    : in     Byte_Seq;
      Xlen : in     N32)
   with Pre => X'First = 0 and then X'Length <= 32 and then Xlen <= X'Length
   is
      subtype Odd_Index is Natural range 0 .. 7;
      type Odd_Table is array (Odd_Index) of P256_Jacobian;
      T     : Odd_Table;
      P2, Q : P256_Jacobian;
      Sel   : P256_Jacobian;
      D     : NAF_Array;
      Top   : Integer;
      Dummy : U32;
   begin
      WNAF5 (X, Xlen, D, Top);
      if Top < 0 then
         P := (X => FE_Zero, Y => FE_Zero, Z => FE_Zero);
         return;
      end if;

      --  T (J) = (2 J + 1) P
      T (0) := P;
      P2 := P;
      P256_Double (P2);
      for J in 1 .. 7 loop
         T (J) := T (J - 1);
         P256_Add (T (J), P2, Dummy);
      end loop;

      Q := T ((abs D (Top) - 1) / 2);
      if D (Top) < 0 then
         Q.Y := Sub_F256 (FE_Zero, Q.Y);
      end if;
      for I in reverse 0 .. Top - 1 loop
         P256_Double (Q);
         if D (I) /= 0 then
            Sel := T ((abs D (I) - 1) / 2);
            if D (I) < 0 then
               Sel.Y := Sub_F256 (FE_Zero, Sel.Y);
            end if;
            P256_Add (Q, Sel, Dummy);
         end if;
      end loop;
      P := Q;
   end P256_Mul_Public;

   --  P := [x] * G for a public scalar: the fixed-base table indexed
   --  directly by the Booth digit, no scan.
   procedure P256_Mulgen_Public
     (P    : out P256_Jacobian;
      X    : in  Byte_Seq;
      Xlen : in  N32)
   with Pre => X'First = 0 and then X'Length <= 40 and then Xlen <= X'Length
   is
      S : Byte_Seq (0 .. 39) := (others => 0);
      W : array (0 .. 5) of Unsigned_64 := (others => 0);
      Q, T     : P256_Jacobian;
      Started  : Boolean := False;
      Sgn, Mag : U32;
      In8, Dg  : Unsigned_64;
      Dummy    : U32;
   begin
      if Xlen <= 40 then
         for I in 0 .. Xlen - 1 loop
            S (40 - Xlen + I) := X (I);
         end loop;
      else
         S := X (Xlen - 40 .. Xlen - 1);
      end if;
      for I in 0 .. 4 loop
         for B in 0 .. 7 loop
            W (I) := W (I) or
              Shift_Left (Unsigned_64 (S (N32 (39 - 8 * I - B))), 8 * B);
         end loop;
      end loop;

      Q := (X => FE_Zero, Y => FE_Zero, Z => FE_Zero);
      for Win in Window_Index loop
         if Win = 0 then
            In8 := Shift_Left (W (0), 1) and 16#FF#;
         else
            declare
               Bit : constant Natural := 7 * Win - 1;
               Qw  : constant Natural := Bit / 64;
               Rb  : constant Natural := Bit mod 64;
            begin
               In8 := Shift_Right (W (Qw), Rb);
               if Rb > 56 then
                  In8 := In8 or Shift_Left (W (Qw + 1), 64 - Rb);
               end if;
               In8 := In8 and 16#FF#;
            end;
         end if;
         Sgn := U32 (Shift_Right (In8, 7));
         Dg  := (In8 xor (0 - Unsigned_64 (Sgn))) and 16#FF#;
         Mag := U32 (Shift_Right (Dg, 1) + (Dg and 1));

         if Mag /= 0 then
            T.X := Fixed_G (Win) (Entry_Index (Mag - 1)).X;
            T.Y := Fixed_G (Win) (Entry_Index (Mag - 1)).Y;
            T.Z := FE_One;
            if Sgn = 1 then
               T.Y := Sub_F256 (FE_Zero, T.Y);
            end if;
            if Started then
               P256_Add_Mixed (Q, T, Dummy);
            else
               Q := T;
               Started := True;
            end if;
         end if;
      end loop;
      P := Q;
   end P256_Mulgen_Public;

   ---------------------------------------------------------------
   --  Combined multiply-add: A := [x]*A + [y]*G
   ---------------------------------------------------------------

   procedure P256_Muladd
     (A    : in out Byte_Seq;
      X    : in     Byte_Seq;
      Xlen : in     N32;
      Y    : in     Byte_Seq;
      Ylen : in     N32;
      OK   :    out U32)
   is
      PP, QQ : P256_Jacobian;
      R, T   : U32;
      Z      : U32;
      Dummy  : U32;
   begin
      P256_Decode (PP, A, R);
      --  Verification inputs are public: the wNAF and direct-index
      --  paths; the decode above and every point operation stay
      --  branch-free with respect to the key.
      P256_Mul_Public (PP, X, Xlen);
      P256_Mulgen_Public (QQ, Y, Ylen);

      --  Final addition (may fail if PP = QQ)
      P256_Add (PP, QQ, T);

      --  Check if Z coordinate is zero
      if FE_Is_Zero (PP.Z) then
         Z := 1;
      else
         Z := 0;
      end if;

      --  If Z=1 and T=0, then PP=QQ, use doubling instead
      P256_Double (QQ);
      CT_Copy_Point (Z and (not T), PP, QQ);

      P256_To_Affine (PP);
      P256_Encode (A, PP);
      R := R and (not (Z and T));
      OK := R;
   end P256_Muladd;

end SPARKTLSCrypto.P256.Point;
