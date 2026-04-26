--  SPARKTLS Fiat Curve25519 — GF(2^255-19) field arithmetic
--
--  Faithful SPARK Ada port of fiat-crypto's curve25519_64.c
--  (MIT PLV, Coq-proven, unsaturated Solinas, 5×51-bit limbs)
--
--  Shared by X25519 (ECDHE) and Ed25519 (signatures).

with Interfaces; use Interfaces;

package SPARKTLSCrypto.Fiat_25519 with
   SPARK_Mode => On
is
   type FE is array (0 .. 4) of Unsigned_64;

   Mask51 : constant Unsigned_64 := 16#7_FFFF_FFFF_FFFF#;

   --  Tight bound: 2^51, matching fiat-crypto's proven output bound for
   --  carry_mul / carry_square / carry / carry_scmul. Limbs masked with
   --  Mask51 are ≤ Mask51 = 2^51 - 1, but the unmasked carry-absorbing
   --  limb (limb 2 in Mul/Sqr) can equal 2^51 exactly (small carry +
   --  masked term). Coq proof in fiat-crypto verifies all five output
   --  limbs are in [0, 2^51].
   Tight51 : constant Unsigned_64 := 16#8_0000_0000_0000#;

   FE_Zero : constant FE := (others => 0);
   FE_One  : constant FE := (1, 0, 0, 0, 0);

   --  Is_Reduced: each limb ≤ Tight51 = 2^51 (output of Mul/Sqr/Carry)
   function Is_Reduced (F : FE) return Boolean is
     (for all I in 0 .. 4 => F (I) <= Tight51)
   with Ghost;

   --  Is_Mul_Safe: each limb ≤ 4*2^51 (safe input for Mul/Sqr —
   --  guarantees 128-bit intermediates don't overflow U128,
   --  and carry chain fits in U64. Verified: 77*L^2 < 2^128
   --  and 114*L^2/2^51 < 2^64 when L = 4*2^51.)
   function Is_Mul_Safe (F : FE) return Boolean is
     (for all I in 0 .. 4 => F (I) <= 16#20_0000_0000_0000#)
   with Ghost;

   --  Ghost lemma: Is_Reduced implies Is_Mul_Safe (Mask51 < 3*2^51)
   procedure Lemma_Reduced_Is_Mul_Safe (F : FE)
   with Ghost,
        Pre  => Is_Reduced (F),
        Post => Is_Mul_Safe (F);

   --  carry_mul/carry_square: mul-safe in → reduced out
   function Mul (A, B : FE) return FE
   with Inline,
        Pre  => Is_Mul_Safe (A) and Is_Mul_Safe (B),
        Post => Is_Reduced (Mul'Result);

   function Sqr (A : FE) return FE
   with Inline,
        Pre  => Is_Mul_Safe (A),
        Post => Is_Reduced (Sqr'Result);

   --  add/sub: expression functions so prover can see through them.
   --  Tight (reduced) inputs → loose (mul-safe) output: each limb of the
   --  result is at most ~2^52 << 2^53 = Mul_Safe upper bound.
   function Add (A, B : FE) return FE is
     (A (0) + B (0), A (1) + B (1), A (2) + B (2),
      A (3) + B (3), A (4) + B (4))
   with Inline,
        Pre  => Is_Reduced (A) and Is_Reduced (B),
        Post => Is_Mul_Safe (Add'Result);
   function Sub (A, B : FE) return FE is
     ((16#FFFF_FFFF_FFFDA# + A (0)) - B (0),
      (16#FFFF_FFFF_FFFFE# + A (1)) - B (1),
      (16#FFFF_FFFF_FFFFE# + A (2)) - B (2),
      (16#FFFF_FFFF_FFFFE# + A (3)) - B (3),
      (16#FFFF_FFFF_FFFFE# + A (4)) - B (4))
   with Inline,
        Pre  => Is_Reduced (A) and Is_Reduced (B),
        Post => Is_Mul_Safe (Sub'Result);

   --  carry: any → reduced
   procedure Carry (F : in out FE)
   with Inline, Post => Is_Reduced (F);

   --  carry_scmul: mul-safe in → reduced out
   function Scmul (A : FE; S : Unsigned_64) return FE
   with Inline,
        Pre  => Is_Mul_Safe (A) and S <= 131071,
        Post => Is_Reduced (Scmul'Result);

   --  constant-time conditional swap (preserves reduced)
   procedure CSwap (A, B : in out FE; Swap : Unsigned_64)
   with Inline,
        Pre  => Swap <= 1 and Is_Reduced (A) and Is_Reduced (B),
        Post => Is_Reduced (A) and Is_Reduced (B);

   --  field inversion: reduced in → reduced out
   function Inv (Z : FE) return FE
   with Pre  => Is_Mul_Safe (Z),
        Post => Is_Mul_Safe (Inv'Result);

end SPARKTLSCrypto.Fiat_25519;
