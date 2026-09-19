--  Differential fuzzer: every accelerated tier against its proven SPARK
--  twin, on random and carry-adversarial operands, for a time budget.
--
--    diff_fuzz [seconds] [seed]
--
--  Operand limbs are drawn from a mix of patterns (random, 0, all ones,
--  single bits, alternating, 2^64 - small, small) so that carry chains
--  are exercised at their boundaries, which is where OpenSSL's Montgomery
--  assembly failed (CVE-2016-7055, CVE-2017-3732, CVE-2017-3736). The
--  Montgomery multiply is also checked, on every iteration, against a
--  third implementation (schoolbook product, then separated REDC) that
--  shares no structure with either CIOS version, and against HACL*'s
--  F*-verified Montgomery multiply; the exponentiation (BigNat64.Modpow)
--  against HACL*'s verified constant-time mod_exp; and the P-256 field
--  multiply and square against fiat-crypto's Coq-verified C (the source
--  our Fiat_P256 was ported from). The C oracles are linked into this
--  test binary only. Any mismatch prints the operands in hex and exits
--  non-zero.

with Ada.Calendar;      use Ada.Calendar;
with Ada.Command_Line;
with Ada.Text_IO;       use Ada.Text_IO;
with Interfaces;        use Interfaces;
with Interfaces.C;

with SPARKNaCl;         use SPARKNaCl;
with SPARKNaCl.AES;

with SPARKTLSCrypto.AES_NI;
with SPARKTLSCrypto.BigNat64;       use SPARKTLSCrypto.BigNat64;
with SPARKTLSCrypto.BigNat64_ADX;
with SPARKTLSCrypto.CPU;
with SPARKTLSCrypto.Fiat_P256;
with SPARKTLSCrypto.GHASH_Dispatch;
with SPARKTLSCrypto.GHASH_NI;
with SPARKTLSCrypto.P256.Fixed_Base;
with SPARKTLSCrypto.P256.Point;

procedure Diff_Fuzz is

   Budget : Duration := 20.0;
   Seed   : Unsigned_64 := 16#D1B5_4A32_D192_ED03#;

   --  xorshift64*
   function Next return Unsigned_64 is
   begin
      Seed := Seed xor Shift_Right (Seed, 12);
      Seed := Seed xor Shift_Left (Seed, 25);
      Seed := Seed xor Shift_Right (Seed, 27);
      return Seed * 16#2545_F491_4F6C_DD1D#;
   end Next;

   --  One limb from the pattern mix. Half the draws are uniform random;
   --  the rest are the values that stress carries.
   function Limb return Unsigned_64 is
      R : constant Unsigned_64 := Next;
   begin
      case R and 15 is
         when 0 .. 7 => return Next;
         when 8      => return 0;
         when 9      => return Unsigned_64'Last;
         when 10     => return Shift_Left (1, Natural (Next and 63));
         when 11     => return Unsigned_64'Last - (Next and 255);
         when 12     => return Next and 255;
         when 13     => return 16#AAAA_AAAA_AAAA_AAAA#;
         when 14     => return 16#5555_5555_5555_5555#;
         when others => return not Shift_Left (1, Natural (Next and 63));
      end case;
   end Limb;

   Failures : Natural := 0;

   procedure Fail (What : String) is
   begin
      Put_Line ("MISMATCH " & What & "  (seed state " & Seed'Image & ")");
      Failures := Failures + 1;
   end Fail;

   function Hex (W : Unsigned_64) return String is
      D : constant String := "0123456789ABCDEF";
      S : String (1 .. 16);
      V : Unsigned_64 := W;
   begin
      for I in reverse S'Range loop
         S (I) := D (Natural (V and 15) + 1);
         V := Shift_Right (V, 4);
      end loop;
      return S;
   end Hex;

   procedure Dump (Name : String; X : Big_Nat) is
   begin
      Put ("  " & Name & " =");
      for I in reverse 0 .. X.Len - 1 loop
         Put (" " & Hex (X.W (I)));
      end loop;
      New_Line;
   end Dump;

   ----------------------------------------------------------------------
   --  Third oracle: schoolbook product then separated REDC
   ----------------------------------------------------------------------
   procedure Oracle_Monty
     (Result : out Big_Nat; A, B, M : Big_Nat; M0I : Word)
   is
      Len : constant Word_Count := M.Len;
      T   : array (0 .. 2 * Max_Words + 1) of Unsigned_64 := (others => 0);
      C   : Unsigned_128;
      Mu  : Unsigned_64;
      Mask64 : constant Unsigned_128 := 16#FFFF_FFFF_FFFF_FFFF#;
   begin
      for I in 0 .. Len - 1 loop
         C := 0;
         for J in 0 .. Len - 1 loop
            C := Unsigned_128 (T (I + J))
                 + Unsigned_128 (A.W (I)) * Unsigned_128 (B.W (J)) + C;
            T (I + J) := Unsigned_64 (C and Mask64);
            C := Shift_Right (C, 64);
         end loop;
         T (I + Len) := Unsigned_64 (C and Mask64);
      end loop;
      for I in 0 .. Len - 1 loop
         Mu := T (I) * M0I;
         C := 0;
         for J in 0 .. Len - 1 loop
            C := Unsigned_128 (T (I + J))
                 + Unsigned_128 (Mu) * Unsigned_128 (M.W (J)) + C;
            T (I + J) := Unsigned_64 (C and Mask64);
            C := Shift_Right (C, 64);
         end loop;
         --  propagate the carry up
         declare
            K : Natural := I + Len;
         begin
            while C /= 0 and then K <= 2 * Len + 1 loop
               C := Unsigned_128 (T (K)) + C;
               T (K) := Unsigned_64 (C and Mask64);
               C := Shift_Right (C, 64);
               K := K + 1;
            end loop;
         end;
      end loop;
      --  result = T (Len .. 2 Len), minus M once if >= M or top word set
      Zero (Result, Len);
      declare
         Borrow : Unsigned_128 := 0;
         Ge     : Boolean;
         D      : array (0 .. Max_Words - 1) of Unsigned_64 := (others => 0);
      begin
         for J in 0 .. Len - 1 loop
            C := Unsigned_128 (T (Len + J)) - Unsigned_128 (M.W (J)) - Borrow;
            D (J) := Unsigned_64 (C and Mask64);
            Borrow := Shift_Right (C, 127) and 1;
         end loop;
         Ge := T (2 * Len) /= 0 or else Borrow = 0;
         for J in 0 .. Len - 1 loop
            Result.W (J) := (if Ge then D (J) else T (Len + J));
         end loop;
      end;
   end Oracle_Monty;

   ----------------------------------------------------------------------
   --  HACL* oracles (tests/fuzz/hacl_oracle.c)
   ----------------------------------------------------------------------
   type Limb_Array is array (Natural range <>) of Unsigned_64
     with Convention => C;

   procedure HACL_Mont_Mul
     (Len : Unsigned_32; N : in out Limb_Array; NInv : Unsigned_64;
      A, B : in out Limb_Array; Res : in out Limb_Array)
     with Import, Convention => C, External_Name => "oracle_hacl_mont_mul";

   procedure HACL_Mont_Sqr
     (Len : Unsigned_32; N : in out Limb_Array; NInv : Unsigned_64;
      A : in out Limb_Array; Res : in out Limb_Array)
     with Import, Convention => C, External_Name => "oracle_hacl_mont_sqr";

   function HACL_Mod_Exp
     (Len : Unsigned_32; N : in out Limb_Array; A : in out Limb_Array;
      B_Bits : Unsigned_32; B : in out Limb_Array; Res : in out Limb_Array)
      return Interfaces.C.int
     with Import, Convention => C, External_Name => "oracle_hacl_mod_exp";

   function HACL_Mod_Inv_Limb (N0 : Unsigned_64) return Unsigned_64
     with Import, Convention => C, External_Name => "oracle_hacl_mod_inv_limb";

   Cnt_HACL, Cnt_ModExp : Natural := 0;

   ----------------------------------------------------------------------
   --  Targets
   ----------------------------------------------------------------------
   Sizes : constant array (0 .. 6) of Word_Count := (4, 8, 16, 24, 32, 48, 64);
   Cnt_Monty, Cnt_Oracle, Cnt_M4, Cnt_P256, Cnt_Gather, Cnt_AES, Cnt_GHASH
     : Natural := 0;

   procedure Random_Big (X : out Big_Nat; Len : Word_Count) is
   begin
      Zero (X, Len);
      for I in 0 .. Len - 1 loop
         X.W (I) := Limb;
      end loop;
   end Random_Big;

   procedure Target_Monty is
      S : constant Word_Count := Sizes (Natural (Next mod 7));
      A, B, M, R1, R2, R3 : Big_Nat;
      M0I : Word;
   begin
      Random_Big (M, S);
      M.W (0) := M.W (0) or 1;
      M.W (S - 1) := M.W (S - 1) or Top_Bit;
      Random_Big (A, S);
      Random_Big (B, S);
      --  Mostly below M (clear the top bit); sometimes anything
      if (Next and 7) /= 0 then
         A.W (S - 1) := A.W (S - 1) and not Top_Bit;
         B.W (S - 1) := B.W (S - 1) and not Top_Bit;
      end if;
      M0I := Ninv (M.W (0));
      Monty_Mul (R1, A, B, M, M0I);
      Monty_Mul_Portable (R2, A, B, M, M0I);
      Cnt_Monty := Cnt_Monty + 1;
      if R1 /= R2 then
         Fail ("Monty_Mul tier vs portable, Len" & S'Image);
         Dump ("A", A); Dump ("B", B); Dump ("M", M);
      end if;
      Oracle_Monty (R3, A, B, M, M0I);
      Cnt_Oracle := Cnt_Oracle + 1;
      if R3 /= R2 then
         Fail ("Monty_Mul portable vs oracle, Len" & S'Image);
         Dump ("A", A); Dump ("B", B); Dump ("M", M);
      end if;
      --  Squaring: tier against portable A * A, and against HACL*
      declare
         Q1, Q2 : Big_Nat;
      begin
         Monty_Sqr (Q1, A, M, M0I);
         Monty_Mul_Portable (Q2, A, A, M, M0I);
         if Q1 /= Q2 then
            Fail ("Monty_Sqr tier vs portable, Len" & S'Image);
            Dump ("A", A); Dump ("M", M); Dump ("tier", Q1); Dump ("ref", Q2);
         end if;
         if A.W (S - 1) < Top_Bit then
            declare
               HN, HA, HR : Limb_Array (0 .. S - 1) := (others => 0);
            begin
               for I in 0 .. S - 1 loop
                  HN (I) := M.W (I); HA (I) := A.W (I);
               end loop;
               HACL_Mont_Sqr (Unsigned_32 (S), HN, M0I, HA, HR);
               for I in 0 .. S - 1 loop
                  if HR (I) /= Q2.W (I) then
                     Fail ("Monty_Sqr portable vs HACL* mont_sqr, Len" & S'Image);
                     Dump ("A", A); Dump ("M", M);
                     exit;
                  end if;
               end loop;
            end;
         end if;
      end;
      --  HACL* requires A, B < M; the top bit of M is set, so clearing
      --  the operands' top bit (done above unless this is an "anything"
      --  round) guarantees it.
      if A.W (S - 1) < Top_Bit and then B.W (S - 1) < Top_Bit then
         declare
            HN, HA, HB, HR : Limb_Array (0 .. S - 1) := (others => 0);
         begin
            for I in 0 .. S - 1 loop
               HN (I) := M.W (I); HA (I) := A.W (I); HB (I) := B.W (I);
            end loop;
            HACL_Mont_Mul (Unsigned_32 (S), HN, M0I, HA, HB, HR);
            Cnt_HACL := Cnt_HACL + 1;
            for I in 0 .. S - 1 loop
               if HR (I) /= R2.W (I) then
                  Fail ("Monty_Mul portable vs HACL* mont_mul, Len" & S'Image);
                  Dump ("A", A); Dump ("B", B); Dump ("M", M);
                  exit;
               end if;
            end loop;
         end;
      end if;
   end Target_Monty;

   procedure Target_Mont_Mul_4 is
      use SPARKTLSCrypto.BigNat64_ADX;
      LA, LB, LM, LR : Limbs_4;
      PA, PB, PM, PR : Big_Nat;
   begin
      if not SPARKTLSCrypto.CPU.Has_BMI2_ADX then
         return;
      end if;
      for I in 0 .. 3 loop
         LM (I) := Limb; LA (I) := Limb; LB (I) := Limb;
      end loop;
      if (Next and 3) = 0 then   --  the P-256 group order as modulus
         LM := (16#F3B9_CAC2_FC63_2551#, 16#BCE6_FAAD_A717_9E84#,
                16#FFFF_FFFF_FFFF_FFFF#, 16#FFFF_FFFF_0000_0000#);
      end if;
      LM (0) := LM (0) or 1;
      LM (3) := LM (3) or Top_Bit;
      LA (3) := LA (3) and not Top_Bit;
      LB (3) := LB (3) and not Top_Bit;
      Zero (PA, 4); Zero (PB, 4); Zero (PM, 4);
      for I in 0 .. 3 loop
         PA.W (I) := LA (I); PB.W (I) := LB (I); PM.W (I) := LM (I);
      end loop;
      Mont_Mul_4 (LR, LA, LB, LM, Ninv (LM (0)));
      Monty_Mul_Portable (PR, PA, PB, PM, Ninv (LM (0)));
      Cnt_M4 := Cnt_M4 + 1;
      for I in 0 .. 3 loop
         if LR (I) /= PR.W (I) then
            Fail ("Mont_Mul_4 vs portable"); Dump ("A", PA); Dump ("B", PB); Dump ("M", PM);
            exit;
         end if;
      end loop;
   end Target_Mont_Mul_4;

   --  A field element below p from the limb mix: reduce once if >= p.
   P256_P : constant SPARKTLSCrypto.Fiat_P256.FE :=
     (16#FFFF_FFFF_FFFF_FFFF#, 16#0000_0000_FFFF_FFFF#,
      0,                       16#FFFF_FFFF_0000_0001#);

   function Random_FE return SPARKTLSCrypto.Fiat_P256.FE is
      X : SPARKTLSCrypto.Fiat_P256.FE;
      Ge : Boolean := True;
   begin
      for I in 0 .. 3 loop
         X (I) := Limb;
      end loop;
      for I in reverse 0 .. 3 loop
         if X (I) /= P256_P (I) then
            Ge := X (I) > P256_P (I);
            exit;
         end if;
      end loop;
      if Ge then
         declare
            Borrow : Unsigned_128 := 0;
            C : Unsigned_128;
         begin
            for I in 0 .. 3 loop
               C := Unsigned_128 (X (I)) - Unsigned_128 (P256_P (I)) - Borrow;
               X (I) := Unsigned_64 (C and 16#FFFF_FFFF_FFFF_FFFF#);
               Borrow := Shift_Right (C, 127) and 1;
            end loop;
         end;
      end if;
      return X;
   end Random_FE;

   procedure Oracle_Fiat_Mul (Out1 : out SPARKTLSCrypto.Fiat_P256.FE;
                              A, B : in  SPARKTLSCrypto.Fiat_P256.FE)
     with Import, Convention => C, External_Name => "oracle_fiat_p256_mul";
   procedure Oracle_Fiat_Square (Out1 : out SPARKTLSCrypto.Fiat_P256.FE;
                                 A    : in  SPARKTLSCrypto.Fiat_P256.FE)
     with Import, Convention => C, External_Name => "oracle_fiat_p256_square";

   Cnt_Fiat_C : Natural := 0;

   procedure Target_P256_Field is
      use SPARKTLSCrypto.Fiat_P256;
      A : constant FE := Random_FE;
      B : constant FE := Random_FE;
      C_Mul, C_Sqr : FE;
   begin
      --  The Coq-verified C against our SPARK port, every iteration,
      --  tier or not.
      Oracle_Fiat_Mul (C_Mul, A, B);
      Oracle_Fiat_Square (C_Sqr, A);
      Cnt_Fiat_C := Cnt_Fiat_C + 1;
      if C_Mul /= Mul_Portable (A, B) then
         Fail ("Fiat_P256.Mul_Portable vs fiat-crypto C");
         Put_Line ("  A = " & Hex (A (3)) & Hex (A (2)) & Hex (A (1)) & Hex (A (0)));
         Put_Line ("  B = " & Hex (B (3)) & Hex (B (2)) & Hex (B (1)) & Hex (B (0)));
      end if;
      if C_Sqr /= Sqr_Portable (A) then
         Fail ("Fiat_P256.Sqr_Portable vs fiat-crypto C");
         Put_Line ("  A = " & Hex (A (3)) & Hex (A (2)) & Hex (A (1)) & Hex (A (0)));
      end if;
      if not SPARKTLSCrypto.CPU.Has_BMI2_ADX then
         return;
      end if;
      Cnt_P256 := Cnt_P256 + 1;
      if Mul (A, B) /= Mul_Portable (A, B) then
         Fail ("Fiat_P256.Mul tier vs portable");
         Put_Line ("  A = " & Hex (A (3)) & Hex (A (2)) & Hex (A (1)) & Hex (A (0)));
         Put_Line ("  B = " & Hex (B (3)) & Hex (B (2)) & Hex (B (1)) & Hex (B (0)));
      end if;
      if Sqr (A) /= Sqr_Portable (A) then
         Fail ("Fiat_P256.Sqr tier vs portable");
         Put_Line ("  A = " & Hex (A (3)) & Hex (A (2)) & Hex (A (1)) & Hex (A (0)));
      end if;
   end Target_P256_Field;

   procedure Target_Gather is
      use SPARKTLSCrypto.P256.Fixed_Base;
      use SPARKTLSCrypto.P256.Point;
      use type SPARKTLSCrypto.Fiat_P256.FE;
      Win : constant Window_Index := Window_Index (Next mod 37);
      Mag : constant U32 :=
        U32 (Next mod 65);
      A, B : Affine_Mont;
   begin
      if not SPARKTLSCrypto.CPU.Has_AVX2 then
         return;
      end if;
      Lookup_Fixed (A, Win, Mag);
      Lookup_Fixed_Portable (B, Win, Mag);
      Cnt_Gather := Cnt_Gather + 1;
      if A.X /= B.X or else A.Y /= B.Y then
         Fail ("fixed-base gather vs portable, window" & Win'Image
               & " magnitude" & Mag'Image);
      end if;
   end Target_Gather;

   procedure Target_AES is
      K16 : Bytes_16; K32 : Bytes_32; Blk : Bytes_16;
      O1, O2 : Bytes_16;
   begin
      if not SPARKTLSCrypto.AES_NI.Has_AESNI then
         return;
      end if;
      for I in K16'Range loop K16 (I) := Byte (Next and 255); end loop;
      for I in K32'Range loop K32 (I) := Byte (Next and 255); end loop;
      for I in Blk'Range loop Blk (I) := Byte (Next and 255); end loop;
      declare
         RK : constant SPARKNaCl.AES.AES128_Round_Keys :=
           SPARKNaCl.AES.Key_Expansion (SPARKNaCl.AES.Construct (K16));
      begin
         SPARKTLSCrypto.AES_NI.Cipher_128 (O1, Blk, RK);
         SPARKNaCl.AES.Cipher (O2, Blk, RK);
         if not Equal (O1, O2) then Fail ("AES-NI 128 vs SPARKNaCl"); end if;
      end;
      declare
         RK : constant SPARKNaCl.AES.AES256_Round_Keys :=
           SPARKNaCl.AES.Key_Expansion (SPARKNaCl.AES.Construct (K32));
      begin
         SPARKTLSCrypto.AES_NI.Cipher_256 (O1, Blk, RK);
         SPARKNaCl.AES.Cipher (O2, Blk, RK);
         if not Equal (O1, O2) then Fail ("AES-NI 256 vs SPARKNaCl"); end if;
      end;
      Cnt_AES := Cnt_AES + 1;
   end Target_AES;

   procedure Target_GHASH is
      X, Y : Bytes_16;
   begin
      if not SPARKTLSCrypto.GHASH_NI.Has_PCLMULQDQ then
         return;
      end if;
      for I in X'Range loop
         X (I) := Byte (Limb and 255);
         Y (I) := Byte (Limb and 255);
      end loop;
      Cnt_GHASH := Cnt_GHASH + 1;
      if not Equal (SPARKTLSCrypto.GHASH_NI.GF128_Mul (X, Y),
                    SPARKTLSCrypto.GHASH_Dispatch.SW_GF128_Mul (X, Y))
      then
         Fail ("GF128_Mul PCLMULQDQ vs software");
      end if;
   end Target_GHASH;

   --  BigNat64.Modpow (the RSA public-modulus exponentiation, fixed 4-bit
   --  windows) against HACL*'s verified constant-time mod_exp, random odd
   --  modulus with its top bit set, random exponent of the full width.
   procedure Target_ModExp is
      Sz : constant array (0 .. 2) of Word_Count := (4, 8, 16);
      S  : constant Word_Count := Sz (Natural (Next mod 3));
      Base, M, R : Big_Nat;
      Exp : Byte_Seq (0 .. N32 (8 * S) - 1);
      HN, HA, HB, HR : Limb_Array (0 .. S - 1) := (others => 0);
      OK : Interfaces.C.int;
   begin
      Random_Big (M, S);
      M.W (0) := M.W (0) or 1;
      M.W (S - 1) := M.W (S - 1) or Top_Bit;
      Random_Big (Base, S);
      Base.W (S - 1) := Base.W (S - 1) and not Top_Bit;
      for I in Exp'Range loop
         Exp (I) := Byte (Limb and 255);
      end loop;
      Modpow (R, Base, Exp, M, Ninv (M.W (0)));
      for I in 0 .. S - 1 loop
         HN (I) := M.W (I); HA (I) := Base.W (I);
         --  exponent bytes are big-endian; HACL wants little-endian limbs
         for Bt in 0 .. 7 loop
            HB (I) := HB (I) or Shift_Left
              (Unsigned_64 (Exp (Exp'Last - N32 (8 * I + Bt))), 8 * Bt);
         end loop;
      end loop;
      OK := HACL_Mod_Exp (Unsigned_32 (S), HN, HA, Unsigned_32 (64 * S), HB, HR);
      Cnt_ModExp := Cnt_ModExp + 1;
      if Integer (OK) /= 1 then
         Fail ("HACL* mod_exp rejected the inputs, Len" & S'Image);
         Dump ("M", M);
         return;
      end if;
      for I in 0 .. S - 1 loop
         if HR (I) /= R.W (I) then
            Fail ("Modpow vs HACL* mod_exp, Len" & S'Image);
            Dump ("Base", Base); Dump ("M", M);
            exit;
         end if;
      end loop;
   end Target_ModExp;

   Start : constant Time := Clock;
   Round : Natural := 0;
begin
   --  Montgomery constant convention must agree before anything else
   declare
      N0 : constant Unsigned_64 := Limb or 1;
   begin
      if HACL_Mod_Inv_Limb (N0) /= Ninv (N0) then
         Fail ("HACL* mod_inv_limb convention differs from Ninv");
      end if;
   end;
   if Ada.Command_Line.Argument_Count >= 1 then
      Budget := Duration'Value (Ada.Command_Line.Argument (1));
   end if;
   if Ada.Command_Line.Argument_Count >= 2 then
      Seed := Unsigned_64'Value (Ada.Command_Line.Argument (2));
   end if;
   Put_Line ("=== differential fuzz: tiers vs proven SPARK, budget"
             & Budget'Image & " s ===");
   Put_Line ("  bmi2/adx:" & SPARKTLSCrypto.CPU.Has_BMI2_ADX'Image
             & "  avx2:" & SPARKTLSCrypto.CPU.Has_AVX2'Image
             & "  aes-ni:" & SPARKTLSCrypto.AES_NI.Has_AESNI'Image
             & "  pclmulqdq:" & SPARKTLSCrypto.GHASH_NI.Has_PCLMULQDQ'Image);

   while Clock - Start < Budget and then Failures = 0 loop
      --  A modular exponentiation is ~1300 multiplies; one every 128
      --  rounds keeps the cheap targets at full rate (still thousands of
      --  verified exponentiations per minute).
      if Round mod 128 = 127 then
         Target_ModExp;
      end if;
      case Round mod 6 is
         when 0 => Target_Monty;
         when 1 => Target_Mont_Mul_4;
         when 2 => Target_P256_Field;
         when 3 => Target_Gather;
         when 4 => Target_AES;
         when others => Target_GHASH;
      end case;
      Round := Round + 1;
   end loop;

   Put_Line ("  monty_mul" & Cnt_Monty'Image & " (oracle" & Cnt_Oracle'Image
             & ", hacl" & Cnt_HACL'Image & ")  modexp vs hacl" & Cnt_ModExp'Image
             & "  mont_mul_4" & Cnt_M4'Image & "  p256 mul/sqr" & Cnt_P256'Image
             & " fiat-c" & Cnt_Fiat_C'Image
             & "  gather" & Cnt_Gather'Image & "  aes" & Cnt_AES'Image
             & "  ghash" & Cnt_GHASH'Image);
   if Failures = 0 then
      Put_Line ("=== differential fuzz: PASS (" & Round'Image & " iterations) ===");
   else
      Put_Line ("=== differential fuzz: FAIL," & Failures'Image & " mismatches ===");
      Ada.Command_Line.Set_Exit_Status (Ada.Command_Line.Failure);
   end if;
end Diff_Fuzz;
