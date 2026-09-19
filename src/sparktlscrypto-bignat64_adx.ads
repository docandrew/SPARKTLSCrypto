--  Montgomery multiplication on x86_64 with BMI2 mulx and ADX adcx/adox.
--
--  An accelerated tier for SPARKTLSCrypto.BigNat64.Monty_Mul and for the
--  P-256 field multiply of SPARKTLSCrypto.Fiat_P256. It is selected only
--  when SPARKTLSCrypto.CPU.Has_BMI2_ADX is True (CPUID, in a build that
--  has the tiers enabled); the proven SPARK code is the
--  fallback and the reference. Same algorithm as the SPARK Monty_Mul:
--  word-by-word CIOS with one final constant-time conditional subtraction,
--  so the two produce identical words for every input, which the smoke
--  tests check on random operands.
--
--  The inner loops are inline assembly. mulx leaves the flags alone and
--  adcx/adox carry through CF and OF independently, so the a*B and m*M
--  rows each run as two interleaved carry chains with no flag traffic;
--  loop control uses lea and jrcxz, which do not touch flags either.
--  Constant time: no branch or memory address depends on the operands,
--  only on the word count.
--
--  The body is SPARK_Mode Off. The contracts here are the ones the SPARK
--  callers rely on; they match BigNat64.Monty_Mul. Always_Terminates is
--  stated, not proved: the assembly has fixed-count loops only.

with SPARKTLSCrypto.BigNat64; use SPARKTLSCrypto.BigNat64;
with SPARKTLSCrypto.Fiat_P256;

package SPARKTLSCrypto.BigNat64_ADX with
   SPARK_Mode => On
is
   --  Result = (A * B * R^-1) mod M, R = 2^(64 * M.Len), M0I = -M^-1 mod 2^64.
   --  The word count must be a multiple of four (the rows are unrolled by
   --  four); the dispatcher in BigNat64 keeps other sizes on the SPARK path.
   procedure Monty_Mul
     (Result : out Big_Nat;
      A, B   : in  Big_Nat;
      M      : in  Big_Nat;
      M0I    : in  Word)
   with Pre  => A.Len = M.Len and B.Len = M.Len
                and M.Len > 0 and M.Len mod 4 = 0,
        Post => Result.Len = M.Len,
        Always_Terminates;

   --  Result = (A * A * R^-1) mod M, same conditions as Monty_Mul.
   procedure Monty_Sqr
     (Result : out Big_Nat;
      A      : in  Big_Nat;
      M      : in  Big_Nat;
      M0I    : in  Word)
   with Pre  => A.Len = M.Len and M.Len > 0 and M.Len mod 4 = 0,
        Post => Result.Len = M.Len,
        Always_Terminates;

   --  Four-limb Montgomery multiply modulo the P-256 prime, R = 2^256,
   --  for inputs below p; the result is below p. Operates on the
   --  Fiat-Crypto element type, same limbs and Montgomery domain.
   procedure Mont_Mul_P256
     (R    : out SPARKTLSCrypto.Fiat_P256.FE;
      A, B : in  SPARKTLSCrypto.Fiat_P256.FE)
   with Inline, Always_Terminates;

   --  Four-limb Montgomery multiply for any odd 256-bit modulus M with its
   --  top bit set, R = 2^256, M0I = -M^-1 mod 2^64, inputs below M, result
   --  below M. Same words as BigNat64.Monty_Mul at four words; the P-256
   --  scalar field (mod n) uses it for the signature inversion.
   procedure Mont_Mul_4
     (R    : out Limbs_4;
      A, B : in  Limbs_4;
      M    : in  Limbs_4;
      M0I  : in  Word)
   with Always_Terminates;

end SPARKTLSCrypto.BigNat64_ADX;
