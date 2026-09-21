with Ada.Command_Line;
with Ada.Text_IO; use Ada.Text_IO;
with Interfaces; use Interfaces;

with SPARKNaCl; use SPARKNaCl;
with SPARKNaCl.AES;
with SPARKNaCl.Core;
with SPARKNaCl.Hashing.SHA384;

with SPARKTLSCrypto.AES_GCM;
with SPARKTLSCrypto.BigNat64;
with SPARKTLSCrypto.BigNat64_ADX;
with SPARKTLSCrypto.P256.ECDSA;
with SPARKTLSCrypto.P256.Fixed_Base;
with SPARKTLSCrypto.P256.Point;
with SPARKTLSCrypto.CPU;
with SPARKTLSCrypto.Fiat_P256;
with SPARKTLSCrypto.ChaCha20_Poly1305;
with SPARKTLSCrypto.Ed25519;
with SPARKTLSCrypto.Hashing.SHA256;
with SPARKTLSCrypto.HKDF;
with SPARKTLSCrypto.MAC;
with SPARKTLSCrypto.Base64;
with SPARKTLSCrypto.RFC6979;
with SPARKTLSCrypto.RSA;
with SPARKTLSCrypto.X25519;

procedure Smoke_Tests is
   Failures : Natural := 0;

   procedure Check (Name : String; OK : Boolean) is
   begin
      if OK then
         Put_Line ("PASS " & Name);
      else
         Put_Line ("FAIL " & Name);
         Failures := Failures + 1;
      end if;
   end Check;

   --  The BMI2/ADX Montgomery tier must produce exactly the words of the
   --  proven SPARK code. Random operands at every word count the tier
   --  accepts, plus the P-256 field entry. When the tier is inactive (no
   --  BMI2/ADX, or a SPARKTLSCRYPTO_ASM=disabled build) both sides are the
   --  same code and the check is vacuous; the INFO line says which.
   procedure Test_ADX_Tiers is
      use SPARKTLSCrypto.BigNat64;
      Seed : Unsigned_64 := 16#9E37_79B9_7F4A_7C15#;

      function Next return Unsigned_64 is
      begin
         Seed := Seed xor Shift_Left (Seed, 13);
         Seed := Seed xor Shift_Right (Seed, 7);
         Seed := Seed xor Shift_Left (Seed, 17);
         return Seed;
      end Next;

      procedure Random_Nat (X : out Big_Nat; Len : Word_Count) is
      begin
         Zero (X, Len);
         for I in 0 .. Len - 1 loop
            X.W (I) := Next;
         end loop;
      end Random_Nat;

      Sizes    : constant array (1 .. 5) of Word_Count := (4, 8, 16, 32, 64);
      A, B, M  : Big_Nat;
      R1, R2   : Big_Nat;
      M0I      : Word;
      All_Same : Boolean := True;
   begin
      if SPARKTLSCrypto.CPU.Has_BMI2_ADX then
         Put_Line ("INFO bmi2/adx montgomery tier active");
      else
         Put_Line ("INFO bmi2/adx montgomery tier inactive"
                   & " (cpu lacks it or SPARKTLSCRYPTO_ASM=disabled build)");
      end if;
      if SPARKTLSCrypto.Hashing.SHA256.Has_HW_Accel then
         Put_Line ("INFO sha-ni tier active");
      else
         Put_Line ("INFO sha-ni tier inactive"
                   & " (cpu lacks it or SPARKTLSCRYPTO_ASM=disabled build)");
      end if;
      --  Regression for the SHA-NI tier once ignoring the build-time
      --  portable switch: a Portable_Only build must never report hardware
      --  acceleration, whatever CPUID says.
      Check ("portable build never enables sha-ni",
             not (SPARKTLSCrypto.CPU.Portable_Only
                  and SPARKTLSCrypto.Hashing.SHA256.Has_HW_Accel));
      for S of Sizes loop
         for Trial in 1 .. 200 loop
            Random_Nat (M, S);
            M.W (0)     := M.W (0) or 1;
            M.W (S - 1) := M.W (S - 1) or Top_Bit;
            Random_Nat (A, S);
            Random_Nat (B, S);
            A.W (S - 1) := A.W (S - 1) and not Top_Bit;
            B.W (S - 1) := B.W (S - 1) and not Top_Bit;
            M0I := Ninv (M.W (0));
            Monty_Mul (R1, A, B, M, M0I);
            Monty_Mul_Portable (R2, A, B, M, M0I);
            All_Same := All_Same and then R1 = R2;
         end loop;
      end loop;
      Check ("monty_mul tier matches portable (4/8/16/32/64 words x 200)",
             All_Same);

      --  Carry-adversarial operands. OpenSSL's Montgomery assembly had
      --  three carry-propagation CVEs (2016-7055, 2017-3732, 2017-3736)
      --  that random operands do not reach: limbs of all ones, single
      --  bits, values one below the modulus, moduli of the form 2^k - c.
      --  Every pair below is run against the SPARK multiply.
      declare
         type Pattern is (Ones, Zero, Top, One, Alt, Near_M, Rand);
         Pats : constant array (0 .. 6) of Pattern :=
           (Ones, Zero, Top, One, Alt, Near_M, Rand);
         Same : Boolean := True;

         procedure Fill (X : out Big_Nat; Len : Word_Count; P : Pattern;
                         Modulus : Big_Nat) is
         begin
            Zero (X, Len);
            for I in 0 .. Len - 1 loop
               X.W (I) :=
                 (case P is
                    when Ones   => Word'Last,
                    when Zero   => 0,
                    when Top    => (if I = Len - 1 then Top_Bit else 0),
                    when One    => (if I = 0 then 1 else 0),
                    when Alt    => (if I mod 2 = 0 then 16#AAAA_AAAA_AAAA_AAAA#
                                    else 16#5555_5555_5555_5555#),
                    when Near_M => Modulus.W (I),
                    when Rand   => Next);
            end loop;
            if P = Near_M then
               X.W (0) := X.W (0) - 1;   --  M - 1 (M is odd, no borrow)
            end if;
            --  keep A, B below M: clear the top bit (M has it set)
            X.W (Len - 1) := X.W (Len - 1) and not Top_Bit;
         end Fill;
      begin
         for S of Sizes loop
            for MP in 0 .. 2 loop
               Zero (M, S);
               case MP is
                  when 0 =>   --  2^(64 S) - 1: every limb all ones
                     for I in 0 .. S - 1 loop M.W (I) := Word'Last; end loop;
                  when 1 =>   --  2^(64 S - 1) + 1: sparse
                     M.W (S - 1) := Top_Bit; M.W (0) := M.W (0) or 1;
                  when others =>   --  random odd, top bit set
                     Random_Nat (M, S);
                     M.W (0) := M.W (0) or 1;
                     M.W (S - 1) := M.W (S - 1) or Top_Bit;
               end case;
               M0I := Ninv (M.W (0));
               for PA of Pats loop
                  for PB of Pats loop
                     Fill (A, S, PA, M);
                     Fill (B, S, PB, M);
                     Monty_Mul (R1, A, B, M, M0I);
                     Monty_Mul_Portable (R2, A, B, M, M0I);
                     Same := Same and then R1 = R2;
                  end loop;
               end loop;
            end loop;
         end loop;
         Check ("monty_mul tier matches portable on carry-adversarial operands",
                Same);
         --  Squaring: the dedicated tier routine against A * A portable,
         --  same moduli and operand patterns.
         Same := True;
         for S of Sizes loop
            for MP in 0 .. 2 loop
               Zero (M, S);
               case MP is
                  when 0 => for I in 0 .. S - 1 loop M.W (I) := Word'Last; end loop;
                  when 1 => M.W (S - 1) := Top_Bit; M.W (0) := M.W (0) or 1;
                  when others =>
                     Random_Nat (M, S);
                     M.W (0) := M.W (0) or 1;
                     M.W (S - 1) := M.W (S - 1) or Top_Bit;
               end case;
               M0I := Ninv (M.W (0));
               for PA of Pats loop
                  Fill (A, S, PA, M);
                  Monty_Sqr (R1, A, M, M0I);
                  Monty_Mul_Portable (R2, A, A, M, M0I);
                  Same := Same and then R1 = R2;
               end loop;
               for Trial in 1 .. 100 loop
                  Random_Nat (A, S);
                  A.W (S - 1) := A.W (S - 1) and not Top_Bit;
                  Monty_Sqr (R1, A, M, M0I);
                  Monty_Mul_Portable (R2, A, A, M, M0I);
                  Same := Same and then R1 = R2;
               end loop;
            end loop;
         end loop;
         Check ("monty_sqr tier matches portable (adversarial + random)", Same);
      end;

      declare
         use SPARKTLSCrypto.Fiat_P256;
         X, Y : FE;
         Same : Boolean := True;
      begin
         for Trial in 1 .. 1000 loop
            --  top limb below 2^32 keeps the value below p
            X := (Next, Next, Next, Next and 16#FFFF_FFFF#);
            Y := (Next, Next, Next, Next and 16#FFFF_FFFF#);
            Same := Same and then Mul (X, Y) = Mul_Portable (X, Y)
                         and then Sqr (X) = Sqr_Portable (X);
         end loop;
         Check ("fiat p256 mul/sqr tier matches portable (1000)", Same);
      end;

      --  General four-limb Montgomery core against the SPARK Monty_Mul at
      --  four words, random odd moduli with the top bit set.
      declare
         use SPARKTLSCrypto.BigNat64_ADX;
         LA, LB, LM, LR : Limbs_4;
         PA, PB, PM, PR : Big_Nat;
         Same : Boolean := True;
      begin
         if SPARKTLSCrypto.CPU.Has_BMI2_ADX then
            for Trial in 1 .. 1000 loop
               for I in 0 .. 3 loop
                  LM (I) := Next;
                  LA (I) := Next;
                  LB (I) := Next;
               end loop;
               LM (0) := LM (0) or 1;
               LM (3) := LM (3) or Top_Bit;
               LA (3) := LA (3) and not Top_Bit;
               LB (3) := LB (3) and not Top_Bit;
               Zero (PA, 4);
               Zero (PB, 4);
               Zero (PM, 4);
               for I in 0 .. 3 loop
                  PA.W (I) := LA (I);
                  PB.W (I) := LB (I);
                  PM.W (I) := LM (I);
               end loop;
               Mont_Mul_4 (LR, LA, LB, LM, Ninv (LM (0)));
               Monty_Mul_Portable (PR, PA, PB, PM, Ninv (LM (0)));
               for I in 0 .. 3 loop
                  Same := Same and then LR (I) = PR.W (I);
               end loop;
            end loop;
         end if;
         Check ("mont_mul_4 tier matches portable at 4 words (1000)", Same);
      end;

      --  Inversion mod n through the public hooks: a * a^-1 = 1 mod n.
      declare
         use SPARKTLSCrypto.P256.ECDSA;
         A, Inv, Prod : ECDSA_Sig_Half;
         Good : Boolean := True;
      begin
         for Trial in 1 .. 200 loop
            for I in A'Range loop
               A (I) := Byte (Next and 255);
            end loop;
            A (A'First) := 0;   --  below n
            A (A'Last)  := A (A'Last) or 1;   --  non-zero
            Test_Inv_Mod_N (A, Inv);
            Test_Mul_Mod_N (A, Inv, Prod);
            for I in Prod'Range loop
               Good := Good and then
                 Prod (I) = (if I = Prod'Last then 1 else 0);
            end loop;
         end loop;
         Check ("p256 inv_mod_n: a * inv(a) = 1 mod n (200)", Good);
      end;

      --  Fixed-base gather tier against the SPARK scan, every window and
      --  every magnitude including 0.
      declare
         use SPARKTLSCrypto.P256.Fixed_Base;
         use SPARKTLSCrypto.P256.Point;
         use type SPARKTLSCrypto.Fiat_P256.FE;
         A, B : Affine_Mont;
         Same : Boolean := True;
      begin
         if SPARKTLSCrypto.CPU.Has_AVX2 then
            Put_Line ("INFO avx2 fixed-base gather tier active");
         else
            Put_Line ("INFO avx2 fixed-base gather tier inactive");
         end if;
         for Win in Window_Index loop
            for Mag in 0 .. 64 loop
               Lookup_Fixed (A, Win, U32 (Mag));
               Lookup_Fixed_Portable (B, Win, U32 (Mag));
               Same := Same and then A.X = B.X and then A.Y = B.Y;
            end loop;
         end loop;
         Check ("p256 fixed-base gather matches portable (37 x 65)", Same);
      end;

      --  The fixed-base table rebuilt from itself with the proven point
      --  arithmetic: each row's first entry is the previous row's first
      --  entry doubled seven times, and each further entry is the
      --  previous one plus the row's base. Every one of the 2368 points
      --  is checked, so a wrong or corrupted entry cannot hide.
      declare
         use SPARKTLSCrypto.P256.Fixed_Base;
         use SPARKTLSCrypto.P256.Point;
         use type SPARKTLSCrypto.Fiat_P256.FE;
         Base, Acc, Tmp : P256_Jacobian;
         Flag  : U32;
         Good  : Boolean := True;
         function Matches (P : P256_Jacobian; E : Affine_Mont) return Boolean is
            Q : P256_Jacobian := P;
         begin
            P256_To_Affine (Q);
            return Q.X = E.X and then Q.Y = E.Y;
         end Matches;
      begin
         Base := (X => Fixed_G (0) (0).X, Y => Fixed_G (0) (0).Y,
                  Z => SPARKTLSCrypto.P256.FE_One);
         for Win in Window_Index loop
            if Win > 0 then
               for D in 1 .. 7 loop
                  P256_Double (Base);
               end loop;
               Good := Good and then Matches (Base, Fixed_G (Win) (0));
               Base := (X => Fixed_G (Win) (0).X, Y => Fixed_G (Win) (0).Y,
                        Z => SPARKTLSCrypto.P256.FE_One);
            end if;
            Acc := Base;
            for K in 1 .. 63 loop
               if K = 1 then
                  --  2 * base: the mixed add excludes the doubling case
                  P256_Double (Acc);
               else
                  Tmp := (X => Fixed_G (Win) (0).X, Y => Fixed_G (Win) (0).Y,
                          Z => SPARKTLSCrypto.P256.FE_One);
                  P256_Add_Mixed (Acc, Tmp, Flag);
               end if;
               Good := Good and then Matches (Acc, Fixed_G (Win) (K));
            end loop;
         end loop;
         Check ("p256 fixed-base table self-consistent (2944 points)", Good);
      end;

      --  SR-62: blinding must not change results. Random blinds against
      --  the unblinded entries: fixed-base and variable-point multiplies
      --  (compared in affine form) and full ECDSA signatures.
      declare
         use SPARKTLSCrypto.P256.Point;
         use type SPARKTLSCrypto.Fiat_P256.FE;
         K      : Bytes_32;
         Blind  : Byte_Seq (0 .. 39);
         P1, P2, Q : P256_Jacobian;
         Same : Boolean := True;
         Hash : Bytes_32;
         D    : SPARKTLSCrypto.P256.ECDSA.ECDSA_Sig_Half;
         R1, S1, R2, S2 : SPARKTLSCrypto.P256.ECDSA.ECDSA_Sig_Half;
         OK1, OK2 : Boolean;
         Zero40 : constant Byte_Seq (0 .. 39) := (others => 0);
      begin
         for Trial in 1 .. 50 loop
            for I in K'Range loop K (I) := Byte (Next and 255); end loop;
            K (0) := K (0) and 16#7F#;   --  below n
            K (31) := K (31) or 1;
            for I in Blind'Range loop Blind (I) := Byte (Next and 255); end loop;
            P256_Mulgen (P1, Byte_Seq (K), 32);
            P256_Mulgen_Blinded (P2, K, Blind);
            P256_To_Affine (P1); P256_To_Affine (P2);
            Same := Same and then P1.X = P2.X and then P1.Y = P2.Y;
            --  variable point: Q = [k]G in Jacobian form from above
            Q := P1;
            P256_Mul (P1, Byte_Seq (K), 32);
            P256_Mul_Blinded (Q, K, Blind);
            P256_To_Affine (P1); P256_To_Affine (Q);
            Same := Same and then P1.X = Q.X and then P1.Y = Q.Y;
            for I in Hash'Range loop Hash (I) := Byte (Next and 255); end loop;
            for I in D'Range loop D (I) := Byte (Next and 255); end loop;
            D (0) := D (0) and 16#7F#;
            SPARKTLSCrypto.P256.ECDSA.Sign
              (Hash, D, SPARKTLSCrypto.P256.ECDSA.ECDSA_Sig_Half (K), Zero40, R1, S1, OK1);
            SPARKTLSCrypto.P256.ECDSA.Sign
              (Hash, D, SPARKTLSCrypto.P256.ECDSA.ECDSA_Sig_Half (K), Blind, R2, S2, OK2);
            Same := Same and then OK1 and then OK2
                    and then Equal (Byte_Seq (R1), Byte_Seq (R2))
                    and then Equal (Byte_Seq (S1), Byte_Seq (S2));
         end loop;
         Check ("p256 blinded mulgen/mul/sign equal unblinded (50)", Same);
      end;
   end Test_ADX_Tiers;

   procedure Test_SHA256 is
      D : SPARKTLSCrypto.Hashing.SHA256.Digest;
      Ctx : SPARKTLSCrypto.Hashing.SHA256.Context;
      Expected : constant Bytes_32 :=
        (16#BA#, 16#78#, 16#16#, 16#BF#, 16#8F#, 16#01#, 16#CF#, 16#EA#,
         16#41#, 16#41#, 16#40#, 16#DE#, 16#5D#, 16#AE#, 16#22#, 16#23#,
         16#B0#, 16#03#, 16#61#, 16#A3#, 16#96#, 16#17#, 16#7A#, 16#9C#,
         16#B4#, 16#10#, 16#FF#, 16#61#, 16#F2#, 16#00#, 16#15#, 16#AD#);
   begin
      D := SPARKTLSCrypto.Hashing.SHA256.Hash (To_Byte_Seq ("abc"));
      Check ("sha256 one-shot", Equal (D, Expected));

      SPARKTLSCrypto.Hashing.SHA256.Init (Ctx);
      SPARKTLSCrypto.Hashing.SHA256.Update (Ctx, To_Byte_Seq ("a"));
      SPARKTLSCrypto.Hashing.SHA256.Update (Ctx, To_Byte_Seq ("bc"));
      SPARKTLSCrypto.Hashing.SHA256.Final (Ctx, D);
      Check ("sha256 streaming", Equal (D, Expected));
   end Test_SHA256;

   procedure Test_HMAC_HKDF is
      D : SPARKTLSCrypto.Hashing.SHA256.Digest;
      PRK : SPARKTLSCrypto.Hashing.SHA256.Digest;
      OKM : SPARKTLSCrypto.HKDF.OKM_Seq (0 .. 41);
      HMAC_Key : constant Byte_Seq (0 .. 19) := (others => 16#0B#);
      HMAC_Expected : constant Bytes_32 :=
        (16#B0#, 16#34#, 16#4C#, 16#61#, 16#D8#, 16#DB#, 16#38#, 16#53#,
         16#5C#, 16#A8#, 16#AF#, 16#CE#, 16#AF#, 16#0B#, 16#F1#, 16#2B#,
         16#88#, 16#1D#, 16#C2#, 16#00#, 16#C9#, 16#83#, 16#3D#, 16#A7#,
         16#26#, 16#E9#, 16#37#, 16#6C#, 16#2E#, 16#32#, 16#CF#, 16#F7#);
      IKM : constant Byte_Seq (0 .. 21) := (others => 16#0B#);
      Salt : constant Byte_Seq (0 .. 12) :=
        (16#00#, 16#01#, 16#02#, 16#03#, 16#04#, 16#05#, 16#06#,
         16#07#, 16#08#, 16#09#, 16#0A#, 16#0B#, 16#0C#);
      Info : constant Byte_Seq (0 .. 9) :=
        (16#F0#, 16#F1#, 16#F2#, 16#F3#, 16#F4#,
         16#F5#, 16#F6#, 16#F7#, 16#F8#, 16#F9#);
      PRK_Expected : constant Bytes_32 :=
        (16#07#, 16#77#, 16#09#, 16#36#, 16#2C#, 16#2E#, 16#32#, 16#DF#,
         16#0D#, 16#DC#, 16#3F#, 16#0D#, 16#C4#, 16#7B#, 16#BA#, 16#63#,
         16#90#, 16#B6#, 16#C7#, 16#3B#, 16#B5#, 16#0F#, 16#9C#, 16#31#,
         16#22#, 16#EC#, 16#84#, 16#4A#, 16#D7#, 16#C2#, 16#B3#, 16#E5#);
      OKM_Expected : constant SPARKTLSCrypto.HKDF.OKM_Seq (0 .. 41) :=
        (16#3C#, 16#B2#, 16#5F#, 16#25#, 16#FA#, 16#AC#, 16#D5#, 16#7A#,
         16#90#, 16#43#, 16#4F#, 16#64#, 16#D0#, 16#36#, 16#2F#, 16#2A#,
         16#2D#, 16#2D#, 16#0A#, 16#90#, 16#CF#, 16#1A#, 16#5A#, 16#4C#,
         16#5D#, 16#B0#, 16#2D#, 16#56#, 16#EC#, 16#C4#, 16#C5#, 16#BF#,
         16#34#, 16#00#, 16#72#, 16#08#, 16#D5#, 16#B8#, 16#87#, 16#18#,
         16#58#, 16#65#);
   begin
      SPARKTLSCrypto.MAC.HMAC_SHA_256 (D, To_Byte_Seq ("Hi There"), HMAC_Key);
      Check ("hmac-sha256 rfc4231 case 1", Equal (D, HMAC_Expected));

      SPARKTLSCrypto.HKDF.Extract (PRK, IKM, Salt);
      SPARKTLSCrypto.HKDF.Expand (OKM, PRK, Info);
      Check ("hkdf extract rfc5869 case 1", Equal (PRK, PRK_Expected));
      Check ("hkdf expand rfc5869 case 1", Equal (Byte_Seq (OKM), Byte_Seq (OKM_Expected)));
   end Test_HMAC_HKDF;

   procedure Test_X25519 is
      Scalar : constant Bytes_32 :=
        (16#77#, 16#07#, 16#6D#, 16#0A#, 16#73#, 16#18#, 16#A5#, 16#7D#,
         16#3C#, 16#16#, 16#C1#, 16#72#, 16#51#, 16#B2#, 16#66#, 16#45#,
         16#DF#, 16#4C#, 16#2F#, 16#87#, 16#EB#, 16#C0#, 16#99#, 16#2A#,
         16#B1#, 16#77#, 16#FB#, 16#A5#, 16#1D#, 16#B9#, 16#2C#, 16#2A#);
      Base : constant Bytes_32 := (0 => 16#09#, others => 0);
      Expected : constant Bytes_32 :=
        (16#85#, 16#20#, 16#F0#, 16#09#, 16#89#, 16#30#, 16#A7#, 16#54#,
         16#74#, 16#8B#, 16#7D#, 16#DC#, 16#B4#, 16#3E#, 16#F7#, 16#5A#,
         16#0D#, 16#BF#, 16#3A#, 16#0D#, 16#26#, 16#38#, 16#1A#, 16#F4#,
         16#EB#, 16#A4#, 16#A9#, 16#8E#, 16#AA#, 16#9B#, 16#4E#, 16#6A#);
      type Small_Order_Table is array (Natural range <>) of Bytes_32;
      Low_Order_Points : constant Small_Order_Table :=
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
      Zero : constant Bytes_32 := (others => 0);
      Q : Bytes_32;
   begin
      SPARKTLSCrypto.X25519.Scalar_Mult (Q, Scalar, Base);
      Check ("x25519 rfc7748 vector", Equal (Q, Expected));

      for I in Low_Order_Points'Range loop
         declare
            High_Bit_Alias : Bytes_32 := Low_Order_Points (I);
         begin
            SPARKTLSCrypto.X25519.Scalar_Mult
              (Q, Scalar, Low_Order_Points (I));
            Check ("x25519 low-order point" & Natural'Image (I),
                   Equal (Q, Zero));

            High_Bit_Alias (31) := High_Bit_Alias (31) or 16#80#;
            SPARKTLSCrypto.X25519.Scalar_Mult (Q, Scalar, High_Bit_Alias);
            Check ("x25519 low-order high-bit alias" & Natural'Image (I),
                   Equal (Q, Zero));
         end;
      end loop;

      --  The fixed-base keygen (Ed25519 table + Edwards-to-Montgomery map)
      --  is on the handshake hot path; it must agree with the ladder for
      --  every scalar, clamping included. 64 xorshift scalars.
      declare
         Basepoint : constant Bytes_32 := (9, others => 0);
         X   : Unsigned_64 := 16#9E37_79B9_7F4A_7C15#;
         SK, Q_Ladder, Q_Fixed : Bytes_32;
         OK  : Boolean := True;
      begin
         for Trial in 1 .. 64 loop
            for I in SK'Range loop
               X := X xor Shift_Left (X, 13); X := X xor Shift_Right (X, 7); X := X xor Shift_Left (X, 17);
               SK (I) := Byte (X and 255);
            end loop;
            SPARKTLSCrypto.X25519.Scalar_Mult (Q_Ladder, SK, Basepoint);
            SPARKTLSCrypto.X25519.Scalar_Mult_Base (Q_Fixed, SK);
            OK := OK and then Equal (Q_Ladder, Q_Fixed);
         end loop;
         Check ("x25519 fixed-base keygen = ladder (64 scalars)", OK);
      end;
   end Test_X25519;

   procedure Test_RFC6979 is
      D256 : constant Bytes_32 :=
        (16#C9#, 16#AF#, 16#A9#, 16#D8#, 16#45#, 16#BA#, 16#75#, 16#16#,
         16#6B#, 16#5C#, 16#21#, 16#57#, 16#67#, 16#B1#, 16#D6#, 16#93#,
         16#4E#, 16#50#, 16#C3#, 16#DB#, 16#36#, 16#E8#, 16#9B#, 16#12#,
         16#7B#, 16#8A#, 16#62#, 16#2B#, 16#12#, 16#0F#, 16#67#, 16#21#);
      H256 : constant Bytes_32 :=
        SPARKTLSCrypto.Hashing.SHA256.Hash (To_Byte_Seq ("sample"));
      Expected_K256 : constant Bytes_32 :=
        (16#A6#, 16#E3#, 16#C5#, 16#7D#, 16#D0#, 16#1A#, 16#BE#, 16#90#,
         16#08#, 16#65#, 16#38#, 16#39#, 16#83#, 16#55#, 16#DD#, 16#4C#,
         16#3B#, 16#17#, 16#AA#, 16#87#, 16#33#, 16#82#, 16#B0#, 16#F2#,
         16#4D#, 16#61#, 16#29#, 16#49#, 16#3D#, 16#8A#, 16#AD#, 16#60#);
      K256 : Bytes_32;
      OK256 : Boolean;
      D384 : constant Bytes_48 :=
        (16#6B#, 16#9D#, 16#3D#, 16#AD#, 16#2E#, 16#1B#, 16#8C#, 16#1C#,
         16#05#, 16#B1#, 16#98#, 16#75#, 16#B6#, 16#65#, 16#9F#, 16#4D#,
         16#E2#, 16#3C#, 16#3B#, 16#66#, 16#7B#, 16#F2#, 16#97#, 16#BA#,
         16#9A#, 16#A4#, 16#77#, 16#40#, 16#78#, 16#71#, 16#37#, 16#D8#,
         16#96#, 16#D5#, 16#72#, 16#4E#, 16#4C#, 16#70#, 16#A8#, 16#25#,
         16#F8#, 16#72#, 16#C9#, 16#EA#, 16#60#, 16#D2#, 16#ED#, 16#F5#);
      H384 : constant Bytes_48 :=
        SPARKNaCl.Hashing.SHA384.Hash (To_Byte_Seq ("sample"));
      Expected_K384 : constant Bytes_48 :=
        (16#94#, 16#ED#, 16#91#, 16#0D#, 16#1A#, 16#09#, 16#9D#, 16#AD#,
         16#32#, 16#54#, 16#E9#, 16#24#, 16#2A#, 16#E8#, 16#5A#, 16#BD#,
         16#E4#, 16#BA#, 16#15#, 16#16#, 16#8E#, 16#AF#, 16#0C#, 16#A8#,
         16#7A#, 16#55#, 16#5F#, 16#D5#, 16#6D#, 16#10#, 16#FB#, 16#CA#,
         16#29#, 16#07#, 16#E3#, 16#E8#, 16#3B#, 16#A9#, 16#53#, 16#68#,
         16#62#, 16#3B#, 16#8C#, 16#46#, 16#86#, 16#91#, 16#5C#, 16#F9#);
      K384 : Bytes_48;
      OK384 : Boolean;
   begin
      SPARKTLSCrypto.RFC6979.Derive_K_P256 (D256, H256, K256, OK256);
      Check ("rfc6979 p-256 sha256 sample",
             OK256 and then Equal (K256, Expected_K256));

      SPARKTLSCrypto.RFC6979.Derive_K_P384 (D384, H384, K384, OK384);
      Check ("rfc6979 p-384 sha384 sample",
             OK384 and then Equal (K384, Expected_K384));
   end Test_RFC6979;

   --  The buffer-based Base64 decode (the entry library code uses; no
   --  secondary stack) must agree with the String-returning one on the
   --  RFC 4648 section 10 vectors, including both padding shapes.
   --  The buffer-based Base64 procedures (the only entry points; no
   --  secondary stack) against the RFC 4648 section 10 vectors, both
   --  padding shapes included, and encode/decode round trips.
   procedure Test_Base64 is
      use SPARKTLSCrypto.Base64;
      procedure One (Name : String; Encoded : String; Plain : String) is
         B64     : constant Base64_String := Base64_String (Encoded);
         Buf     : Byte_Seq (0 .. 15);
         Len     : Natural;
         Bytes   : Byte_Seq (0 .. N32 (Plain'Length) - 1);
         Enc     : String (1 .. 16);
         Enc_Len : Natural;
         OK      : Boolean;
      begin
         Decode (B64, Buf, Len);
         OK := Len = Plain'Length and then Decoded_Length (B64) = Plain'Length;
         if OK then
            for I in 0 .. Len - 1 loop
               OK := OK and then Character'Pos (Plain (Plain'First + I)) = Natural (Buf (N32 (I)));
            end loop;
            for I in Len .. 15 loop
               OK := OK and then Buf (N32 (I)) = 0;
            end loop;
         end if;
         Check ("base64 decode " & Name, OK);

         for I in Bytes'Range loop
            Bytes (I) := Byte (Character'Pos (Plain (Plain'First + Natural (I))));
         end loop;
         Encode (Bytes, Enc, Enc_Len);
         Check ("base64 encode " & Name,
                Enc_Len = Encoded'Length
                and then Enc (1 .. Enc_Len) = Encoded
                and then Validate (Enc (1 .. Enc_Len)));
      end One;
   begin
      One ("empty",  "",         "");
      One ("f",      "Zg==",     "f");
      One ("fo",     "Zm8=",     "fo");
      One ("foo",    "Zm9v",     "foo");
      One ("foob",   "Zm9vYg==", "foob");
      One ("fooba",  "Zm9vYmE=", "fooba");
      One ("foobar", "Zm9vYmFy", "foobar");
   end Test_Base64;

   procedure Test_Ed25519_ASR is
      use SPARKTLSCrypto.Ed25519;
   begin
      Check ("ed25519 asr8 zero", Test_ASR_8 (0) = 0);
      Check ("ed25519 asr8 positive exact", Test_ASR_8 (256) = 1);
      Check ("ed25519 asr8 positive floor", Test_ASR_8 (255) = 0);
      Check ("ed25519 asr8 negative one", Test_ASR_8 (-1) = -1);
      Check ("ed25519 asr8 negative exact", Test_ASR_8 (-256) = -1);
      Check ("ed25519 asr8 negative floor", Test_ASR_8 (-257) = -2);

      Check ("ed25519 asr4 zero", Test_ASR_4 (0) = 0);
      Check ("ed25519 asr4 positive exact", Test_ASR_4 (16) = 1);
      Check ("ed25519 asr4 positive floor", Test_ASR_4 (15) = 0);
      Check ("ed25519 asr4 negative one", Test_ASR_4 (-1) = -1);
      Check ("ed25519 asr4 negative exact", Test_ASR_4 (-16) = -1);
      Check ("ed25519 asr4 negative floor", Test_ASR_4 (-17) = -2);
   end Test_Ed25519_ASR;

   procedure Test_AES_GCM_Roundtrip is
      K_Raw : constant Bytes_16 := (others => 0);
      K : SPARKNaCl.AES.AES128_Key;
      N : constant Bytes_12 := (others => 0);
      AAD : constant Byte_Seq (0 .. 0) := (0 => 16#A5#);
      M : constant Byte_Seq (0 .. 15) :=
        (16#00#, 16#11#, 16#22#, 16#33#, 16#44#, 16#55#, 16#66#, 16#77#,
         16#88#, 16#99#, 16#AA#, 16#BB#, 16#CC#, 16#DD#, 16#EE#, 16#FF#);
      C : Byte_Seq (0 .. 15);
      M2 : Byte_Seq (0 .. 15);
      Tag : Bytes_16;
      Bad_Tag : Bytes_16;
      Status : Boolean;
   begin
      SPARKNaCl.AES.Construct (K, K_Raw);
      SPARKTLSCrypto.AES_GCM.Encrypt (C, Tag, M, N, K, AAD);
      SPARKTLSCrypto.AES_GCM.Decrypt (M2, Status, Tag, C, N, K, AAD);
      Check ("aes-128-gcm roundtrip", Status and then Equal (M2, M));

      Bad_Tag := Tag;
      Bad_Tag (0) := Bad_Tag (0) xor 1;
      SPARKTLSCrypto.AES_GCM.Decrypt (M2, Status, Bad_Tag, C, N, K, AAD);
      Check ("aes-128-gcm tag rejection", (not Status) and then Equal (M2, Byte_Seq'(0 .. 15 => 0)));
   end Test_AES_GCM_Roundtrip;

   procedure Test_ChaCha20_Poly1305_Smoke is
      K_Raw : constant Bytes_32 := (others => 0);
      K : SPARKNaCl.Core.ChaCha20_Key;
      N : constant SPARKNaCl.Core.ChaCha20_IETF_Nonce := (others => 0);
      AAD : constant Byte_Seq (0 .. 0) := (0 => 16#5A#);
      M : constant Byte_Seq (0 .. 31) := (others => 16#C3#);
      C : Byte_Seq (0 .. 31);
      Tag : Bytes_16;
      Zero_Tag : constant Bytes_16 := (others => 0);
   begin
      SPARKNaCl.Core.Construct (K, K_Raw);
      SPARKTLSCrypto.ChaCha20_Poly1305.Encrypt (C, Tag, M, N, K, AAD);
      Check ("chacha20-poly1305 nonzero tag", not Equal (Tag, Zero_Tag));
   end Test_ChaCha20_Poly1305_Smoke;

   --  RSA verification KATs. A 2049-bit modulus makes emLen = k - 1, so the
   --  PSS encoding is right-aligned in the k-octet buffer (RFC 8017 9.1);
   --  Wycheproof has no such modulus. Signatures produced with
   --  cryptography 41 / OpenSSL over the message "sparktls odd-modulus KAT".
   --  Also: e = 1 and even e must be rejected (RFC 8017 3.1).
   procedure Test_RSA_Verify is
      N : constant Byte_Seq (0 .. 256) :=
        (16#01#, 16#3C#, 16#4D#, 16#87#, 16#23#, 16#94#, 16#57#, 16#FD#,
         16#D3#, 16#4A#, 16#2E#, 16#3F#, 16#1B#, 16#86#, 16#94#, 16#B6#,
         16#4B#, 16#6F#, 16#BC#, 16#C8#, 16#55#, 16#96#, 16#A1#, 16#FE#,
         16#9C#, 16#5C#, 16#C8#, 16#9A#, 16#D7#, 16#FE#, 16#D8#, 16#D1#,
         16#7B#, 16#21#, 16#47#, 16#3D#, 16#0B#, 16#5E#, 16#32#, 16#2E#,
         16#28#, 16#DD#, 16#37#, 16#20#, 16#E6#, 16#49#, 16#B4#, 16#D4#,
         16#3B#, 16#AD#, 16#1D#, 16#C9#, 16#87#, 16#40#, 16#4F#, 16#AC#,
         16#6A#, 16#B1#, 16#3A#, 16#3D#, 16#C4#, 16#78#, 16#05#, 16#CA#,
         16#7A#, 16#93#, 16#55#, 16#D2#, 16#25#, 16#A6#, 16#B8#, 16#70#,
         16#2B#, 16#40#, 16#49#, 16#81#, 16#2C#, 16#E8#, 16#67#, 16#2D#,
         16#75#, 16#B6#, 16#4A#, 16#4E#, 16#EB#, 16#3A#, 16#F7#, 16#CB#,
         16#FB#, 16#E7#, 16#24#, 16#83#, 16#31#, 16#C0#, 16#B5#, 16#90#,
         16#C4#, 16#7F#, 16#76#, 16#78#, 16#E4#, 16#BD#, 16#C8#, 16#A7#,
         16#5E#, 16#8D#, 16#17#, 16#D1#, 16#C9#, 16#39#, 16#D2#, 16#70#,
         16#A8#, 16#A7#, 16#81#, 16#FC#, 16#17#, 16#D8#, 16#F6#, 16#FE#,
         16#DB#, 16#72#, 16#40#, 16#A1#, 16#D1#, 16#F3#, 16#80#, 16#E9#,
         16#D6#, 16#FB#, 16#D2#, 16#7D#, 16#79#, 16#B5#, 16#81#, 16#26#,
         16#F5#, 16#50#, 16#84#, 16#74#, 16#DA#, 16#56#, 16#29#, 16#5D#,
         16#37#, 16#70#, 16#1F#, 16#71#, 16#CE#, 16#53#, 16#8E#, 16#A8#,
         16#51#, 16#06#, 16#4B#, 16#A6#, 16#C4#, 16#5B#, 16#2B#, 16#00#,
         16#D5#, 16#13#, 16#85#, 16#41#, 16#94#, 16#23#, 16#56#, 16#B9#,
         16#29#, 16#ED#, 16#68#, 16#99#, 16#02#, 16#0C#, 16#E6#, 16#BC#,
         16#9D#, 16#4B#, 16#5C#, 16#06#, 16#EB#, 16#C4#, 16#DC#, 16#60#,
         16#7D#, 16#59#, 16#D2#, 16#4F#, 16#1E#, 16#BF#, 16#8E#, 16#99#,
         16#72#, 16#42#, 16#38#, 16#16#, 16#B4#, 16#DC#, 16#70#, 16#EC#,
         16#D8#, 16#14#, 16#88#, 16#27#, 16#8B#, 16#DE#, 16#7F#, 16#9F#,
         16#4C#, 16#34#, 16#4A#, 16#31#, 16#62#, 16#E9#, 16#65#, 16#37#,
         16#01#, 16#4E#, 16#C2#, 16#D8#, 16#90#, 16#ED#, 16#40#, 16#CC#,
         16#E5#, 16#98#, 16#41#, 16#BA#, 16#3A#, 16#4D#, 16#5D#, 16#38#,
         16#FA#, 16#EA#, 16#BC#, 16#CF#, 16#29#, 16#2F#, 16#07#, 16#C4#,
         16#56#, 16#79#, 16#F9#, 16#01#, 16#38#, 16#41#, 16#E4#, 16#F0#,
         16#A3#, 16#7F#, 16#6E#, 16#83#, 16#29#, 16#32#, 16#2E#, 16#57#,
         16#D3#);
      Sig_PSS : constant Byte_Seq (0 .. 256) :=
        (16#00#, 16#44#, 16#2B#, 16#A7#, 16#58#, 16#E9#, 16#F2#, 16#07#,
         16#CE#, 16#D5#, 16#B1#, 16#47#, 16#2F#, 16#83#, 16#7D#, 16#06#,
         16#07#, 16#9C#, 16#4F#, 16#EB#, 16#30#, 16#65#, 16#DA#, 16#FC#,
         16#44#, 16#AE#, 16#71#, 16#4A#, 16#51#, 16#F9#, 16#02#, 16#55#,
         16#FB#, 16#2B#, 16#A7#, 16#00#, 16#77#, 16#43#, 16#BD#, 16#F9#,
         16#93#, 16#18#, 16#A4#, 16#4E#, 16#80#, 16#3F#, 16#A9#, 16#86#,
         16#96#, 16#DF#, 16#1C#, 16#5F#, 16#C7#, 16#97#, 16#4F#, 16#41#,
         16#C1#, 16#30#, 16#3D#, 16#0D#, 16#D1#, 16#91#, 16#6B#, 16#CF#,
         16#C4#, 16#AE#, 16#6F#, 16#4C#, 16#D5#, 16#80#, 16#E1#, 16#44#,
         16#74#, 16#85#, 16#33#, 16#A5#, 16#EF#, 16#88#, 16#2A#, 16#1B#,
         16#58#, 16#1D#, 16#23#, 16#61#, 16#3D#, 16#FD#, 16#6E#, 16#12#,
         16#AF#, 16#20#, 16#EE#, 16#8A#, 16#43#, 16#92#, 16#44#, 16#F7#,
         16#57#, 16#70#, 16#62#, 16#01#, 16#78#, 16#65#, 16#DB#, 16#AE#,
         16#41#, 16#AF#, 16#A1#, 16#9B#, 16#26#, 16#9F#, 16#77#, 16#EF#,
         16#65#, 16#B6#, 16#DF#, 16#89#, 16#BC#, 16#24#, 16#B9#, 16#9A#,
         16#86#, 16#76#, 16#0A#, 16#44#, 16#7C#, 16#55#, 16#72#, 16#17#,
         16#13#, 16#D0#, 16#E5#, 16#D0#, 16#81#, 16#65#, 16#7C#, 16#98#,
         16#39#, 16#21#, 16#A2#, 16#FC#, 16#E8#, 16#2B#, 16#0B#, 16#55#,
         16#01#, 16#7E#, 16#49#, 16#6E#, 16#14#, 16#08#, 16#C2#, 16#E2#,
         16#EB#, 16#75#, 16#69#, 16#1F#, 16#03#, 16#F1#, 16#61#, 16#59#,
         16#BF#, 16#C4#, 16#56#, 16#F1#, 16#04#, 16#7A#, 16#54#, 16#1F#,
         16#4F#, 16#6B#, 16#32#, 16#63#, 16#43#, 16#E9#, 16#D5#, 16#ED#,
         16#9E#, 16#F0#, 16#1B#, 16#DB#, 16#47#, 16#17#, 16#D3#, 16#33#,
         16#75#, 16#2A#, 16#03#, 16#C6#, 16#AD#, 16#D4#, 16#75#, 16#E1#,
         16#1D#, 16#58#, 16#71#, 16#F9#, 16#34#, 16#7D#, 16#2C#, 16#A3#,
         16#D3#, 16#F3#, 16#BB#, 16#01#, 16#9C#, 16#D3#, 16#B7#, 16#55#,
         16#9A#, 16#CB#, 16#EE#, 16#E5#, 16#58#, 16#31#, 16#97#, 16#4A#,
         16#34#, 16#04#, 16#3C#, 16#E7#, 16#DF#, 16#1B#, 16#41#, 16#67#,
         16#82#, 16#F2#, 16#F7#, 16#48#, 16#1C#, 16#07#, 16#DF#, 16#13#,
         16#D0#, 16#C0#, 16#7C#, 16#6A#, 16#A2#, 16#1C#, 16#29#, 16#00#,
         16#5D#, 16#9E#, 16#2E#, 16#86#, 16#98#, 16#0B#, 16#75#, 16#BA#,
         16#AF#, 16#D8#, 16#01#, 16#5C#, 16#C0#, 16#CF#, 16#91#, 16#36#,
         16#BD#);
      Sig_PKCS1 : constant Byte_Seq (0 .. 256) :=
        (16#00#, 16#76#, 16#C9#, 16#07#, 16#38#, 16#09#, 16#C6#, 16#44#,
         16#9D#, 16#DD#, 16#AE#, 16#03#, 16#5A#, 16#D2#, 16#CE#, 16#32#,
         16#A5#, 16#43#, 16#D3#, 16#D4#, 16#4F#, 16#32#, 16#AD#, 16#BF#,
         16#6D#, 16#4A#, 16#78#, 16#C8#, 16#EE#, 16#60#, 16#E8#, 16#45#,
         16#14#, 16#B7#, 16#8C#, 16#56#, 16#36#, 16#A8#, 16#11#, 16#8E#,
         16#BE#, 16#E5#, 16#6E#, 16#6C#, 16#9F#, 16#47#, 16#4F#, 16#DB#,
         16#CD#, 16#32#, 16#D4#, 16#CA#, 16#8B#, 16#72#, 16#DE#, 16#44#,
         16#3A#, 16#97#, 16#AC#, 16#26#, 16#A4#, 16#30#, 16#63#, 16#E6#,
         16#26#, 16#2B#, 16#15#, 16#71#, 16#72#, 16#83#, 16#BD#, 16#E2#,
         16#B6#, 16#73#, 16#33#, 16#86#, 16#F0#, 16#FE#, 16#24#, 16#80#,
         16#AC#, 16#D3#, 16#90#, 16#C5#, 16#EF#, 16#BE#, 16#0E#, 16#3B#,
         16#C9#, 16#86#, 16#02#, 16#0A#, 16#0D#, 16#6F#, 16#58#, 16#07#,
         16#B3#, 16#93#, 16#06#, 16#2F#, 16#C2#, 16#E4#, 16#C8#, 16#B0#,
         16#70#, 16#02#, 16#A7#, 16#F1#, 16#9A#, 16#08#, 16#77#, 16#4E#,
         16#CD#, 16#A1#, 16#39#, 16#7A#, 16#11#, 16#6E#, 16#07#, 16#2F#,
         16#9A#, 16#FE#, 16#91#, 16#FB#, 16#B5#, 16#B3#, 16#4E#, 16#9D#,
         16#88#, 16#40#, 16#CC#, 16#31#, 16#3F#, 16#E9#, 16#97#, 16#08#,
         16#E6#, 16#23#, 16#98#, 16#CA#, 16#8B#, 16#F1#, 16#2C#, 16#CA#,
         16#8A#, 16#65#, 16#FB#, 16#A8#, 16#15#, 16#E1#, 16#FF#, 16#B1#,
         16#33#, 16#80#, 16#E7#, 16#E8#, 16#83#, 16#58#, 16#CE#, 16#2E#,
         16#25#, 16#8A#, 16#87#, 16#53#, 16#D1#, 16#8F#, 16#71#, 16#5D#,
         16#1D#, 16#42#, 16#90#, 16#8C#, 16#85#, 16#5D#, 16#51#, 16#64#,
         16#00#, 16#16#, 16#F2#, 16#35#, 16#AB#, 16#73#, 16#5B#, 16#6B#,
         16#DB#, 16#7F#, 16#41#, 16#99#, 16#93#, 16#E2#, 16#1F#, 16#AD#,
         16#9E#, 16#7C#, 16#B0#, 16#4B#, 16#1F#, 16#2F#, 16#A9#, 16#16#,
         16#88#, 16#5D#, 16#0E#, 16#AD#, 16#E2#, 16#C1#, 16#D2#, 16#FC#,
         16#19#, 16#C3#, 16#E7#, 16#54#, 16#DC#, 16#1A#, 16#BB#, 16#B6#,
         16#E6#, 16#56#, 16#52#, 16#72#, 16#12#, 16#7E#, 16#B0#, 16#2A#,
         16#79#, 16#2C#, 16#15#, 16#8A#, 16#07#, 16#6A#, 16#0A#, 16#39#,
         16#32#, 16#31#, 16#27#, 16#63#, 16#8F#, 16#B5#, 16#B8#, 16#C1#,
         16#94#, 16#4D#, 16#21#, 16#65#, 16#F3#, 16#5A#, 16#FB#, 16#13#,
         16#8B#, 16#EA#, 16#91#, 16#FE#, 16#35#, 16#35#, 16#83#, 16#92#,
         16#1A#);
      Hash : constant Bytes_32 :=
        (16#86#, 16#1E#, 16#DC#, 16#E8#, 16#0C#, 16#9B#, 16#13#, 16#70#, 16#EF#, 16#F4#, 16#7A#, 16#7C#, 16#67#, 16#DB#, 16#1E#, 16#B8#,
         16#01#, 16#60#, 16#AB#, 16#DC#, 16#6A#, 16#A9#, 16#5B#, 16#F5#, 16#34#, 16#15#, 16#0F#, 16#10#, 16#E2#, 16#29#, 16#78#, 16#90#);
      Bad_Sig : Byte_Seq (0 .. 256) := Sig_PSS;
   begin
      Check ("rsa-2049 pss-sha256 verifies",
             SPARKTLSCrypto.RSA.Verify_PSS_SHA256
               (Hash => Hash, Modulus => N, Mod_Len => 257, Exponent => 65537,
                Signature => Sig_PSS, Sig_Len => 257));
      Check ("rsa-2049 pkcs1-sha256 verifies",
             SPARKTLSCrypto.RSA.Verify_PKCS1_v1_5_SHA256
               (Hash => Hash, Modulus => N, Mod_Len => 257, Exponent => 65537,
                Signature => Sig_PKCS1, Sig_Len => 257));
      Bad_Sig (256) := Bad_Sig (256) xor 16#01#;
      Check ("rsa-2049 pss last octet is checked",
             not SPARKTLSCrypto.RSA.Verify_PSS_SHA256
               (Hash => Hash, Modulus => N, Mod_Len => 257, Exponent => 65537,
                Signature => Bad_Sig, Sig_Len => 257));
      Check ("rsa e = 1 rejected",
             not SPARKTLSCrypto.RSA.Verify_PKCS1_v1_5_SHA256
               (Hash => Hash, Modulus => N, Mod_Len => 257, Exponent => 1,
                Signature => Sig_PKCS1, Sig_Len => 257));
      Check ("rsa even e rejected",
             not SPARKTLSCrypto.RSA.Verify_PSS_SHA256
               (Hash => Hash, Modulus => N, Mod_Len => 257, Exponent => 65536,
                Signature => Sig_PSS, Sig_Len => 257));
      Check ("rsa e = 0 rejected",
             not SPARKTLSCrypto.RSA.Verify_PSS_SHA256
               (Hash => Hash, Modulus => N, Mod_Len => 257, Exponent => 0,
                Signature => Sig_PSS, Sig_Len => 257));
   end Test_RSA_Verify;
begin
   Test_ADX_Tiers;
   Test_SHA256;
   Test_HMAC_HKDF;
   Test_X25519;
   Test_RFC6979;
   Test_Base64;
   Test_Ed25519_ASR;
   Test_AES_GCM_Roundtrip;
   Test_ChaCha20_Poly1305_Smoke;
   Test_RSA_Verify;

   if Failures /= 0 then
      Ada.Command_Line.Set_Exit_Status (Ada.Command_Line.Failure);
   end if;
end Smoke_Tests;
