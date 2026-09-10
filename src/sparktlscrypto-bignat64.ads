with Interfaces; use Interfaces;
with SPARKNaCl;  use SPARKNaCl;

--  64-bit-limb multi-precision arithmetic for RSA.
--
--  A sibling of SPARKTLSCrypto.BigNat (32-bit limbs), which P-384 keeps
--  using unchanged. RSA moduli are 2048-8192 bits, and on a 64-bit
--  target one 64x64->128 multiply replaces four 32x32->64 ones, so the
--  Montgomery inner loop runs a quarter of the iterations. Products are
--  taken in Unsigned_128 exactly as the Fiat field code does.
--
--  Every operation on secret data is constant time: no data-dependent
--  branches or indices (CT_Sub / CT_Add select through masks, the
--  exponentiation is fixed-window with a masked table read).
--
--  Design choices for SPARK provability, as in BigNat:
--    - Fixed-size word array, word count in a separate record field
--    - Functions return results (no aliasing)
--    - All loops bounded by the Len field
--
package SPARKTLSCrypto.BigNat64 with
   SPARK_Mode => On
is
   Max_Words : constant := 128;  --  Up to 8192-bit values
   Max_Bits  : constant := Max_Words * 64;

   subtype Word is Unsigned_64;
   subtype DWord is Unsigned_128;

   Word_Bits : constant := 64;
   Word_Bytes : constant := 8;
   Top_Bit   : constant Word  := 16#8000_0000_0000_0000#;
   Word_Mask : constant DWord := DWord (Word'Last);

   subtype Word_Count is Natural range 0 .. Max_Words;
   type Word_Array is array (Natural range 0 .. Max_Words - 1) of Word;

   --  A big natural number: Len active words in little-endian order.
   --  Words beyond Len are always zero.
   type Big_Nat is record
      Len : Word_Count := 0;
      W   : Word_Array := (others => 0);
   end record;

   --  Result of addition/subtraction with carry/borrow
   type Arith_Result is record
      Value : Big_Nat;
      Carry : Word;  --  0 or 1
   end record;

   --  Predicate: all words beyond Len are zero
   function Well_Formed (A : Big_Nat) return Boolean is
      (for all I in A.Len .. Max_Words - 1 => A.W (I) = 0);

   --  Create a Big_Nat from a byte sequence (big-endian)
   procedure Decode
     (Result : out Big_Nat;
      Src    : in  Byte_Seq)
   with Pre  => Src'First = 0 and Src'Length <= Max_Words * Word_Bytes
               and Src'Last < N32'Last,
        Always_Terminates;

   --  Encode a Big_Nat to a byte sequence (big-endian)
   procedure Encode
     (Dst    : out Byte_Seq;
      A      : in  Big_Nat)
   with Pre => Dst'First = 0 and Dst'Length <= Max_Words * Word_Bytes,
        Always_Terminates;

   --  Set to zero with a given word count
   procedure Zero
     (Result : out Big_Nat;
      Len    : in  Word_Count)
   with Post => Result.Len = Len and Well_Formed (Result);

   --  Constant-time conditional subtraction: if Ctl=1, Result = A - B;
   --  if Ctl=0, Result = A (unchanged). Returns borrow bit.
   function CT_Sub
     (A, B : Big_Nat;
      Ctl  : Word) return Arith_Result
   with Pre  => A.Len = B.Len and A.Len > 0,
        Post => CT_Sub'Result.Value.Len = A.Len;

   --  Constant-time conditional addition: if Ctl=1, Result = A + B;
   --  if Ctl=0, Result = A (unchanged). Returns carry bit.
   function CT_Add
     (A, B : Big_Nat;
      Ctl  : Word) return Arith_Result
   with Pre  => A.Len = B.Len and A.Len > 0,
        Post => CT_Add'Result.Value.Len = A.Len;

   --  Constant-time comparison helpers
   function CT_Eq  (X, Y : Word) return Word;
   function CT_Neq (X, Y : Word) return Word;
   function CT_Not (X : Word) return Word;
   function CT_Mux (Ctl, X, Y : Word) return Word;

   --  Montgomery multiplication: Result = (A * B * R^-1) mod M
   --  M0I is -M^(-1) mod 2^64.
   procedure Monty_Mul
     (Result : out Big_Nat;
      A, B   : in  Big_Nat;
      M      : in  Big_Nat;
      M0I    : in  Word)
   with Pre => A.Len = M.Len and B.Len = M.Len
               and M.Len > 0,
        Post => Result.Len = M.Len;

   --  Convert to Montgomery domain: A * R mod M (bit-by-bit doubling;
   --  O(64 * Len^2). Kept as the general fallback -- see R2_Mod below).
   procedure To_Monty
     (A   : in out Big_Nat;
      M   : in     Big_Nat;
      M0I : in     Word)
   with Pre  => A.Len = M.Len and M.Len > 0,
        Post => A.Len = M.Len;

   --  R^2 mod M, where R = 2^(64 * M.Len). With it, A * R mod M is one
   --  Monty_Mul (A, R2). Requires the top bit of M's top word to be set
   --  (every RSA modulus of 1024/2048/3072/4096 bits): R mod M is then
   --  2^(64 Len) - M by a single subtraction, and R^2 follows from a
   --  few doublings and Montgomery squarings instead of 64 * Len
   --  doublings. Constant-time in the value of M (only Len matters).
   procedure R2_Mod
     (R2  : out Big_Nat;
      M   : in  Big_Nat;
      M0I : in  Word)
   with Pre  => M.Len > 0
                and then (M.W (M.Len - 1) and Top_Bit) /= 0,
        Post => R2.Len = M.Len;

   --  Result = Base^Exp mod M for a PUBLIC exponent (RSA e): plain
   --  left-to-right square-and-multiply, NOT constant-time in Exp.
   --  Never use it with a private exponent.
   procedure Modpow_Public
     (Result : out Big_Nat;
      Base   : in  Big_Nat;
      Exp    : in  Word;
      M      : in  Big_Nat;
      M0I    : in  Word;
      R2     : in  Big_Nat)
   with Pre  => Base.Len = M.Len and M.Len > 0 and R2.Len = M.Len
                and Exp > 0,
        Post => Result.Len = M.Len;

   --  Modular exponentiation: Result = Base^Exp mod M (via Montgomery).
   --  Constant-time in Exp and Base: fixed 4-bit windows, every window
   --  does four squarings and one multiplication by a table entry chosen
   --  with masks (window 0 multiplies by the Montgomery one), so the
   --  operation sequence and memory access pattern do not depend on
   --  the exponent bits.
   procedure Modpow
     (Result : out Big_Nat;
      Base   : in  Big_Nat;
      Exp    : in  Byte_Seq;
      M      : in  Big_Nat;
      M0I    : in  Word)
   with Pre  => Base.Len = M.Len and M.Len > 0
               and Exp'First = 0 and Exp'Length > 0
               and Exp'Last < N32'Last / 8,
        Post => Result.Len = M.Len;

   --  Compute -M^(-1) mod 2^64 from M.W(0)
   --  Result := A * B + C  (schoolbook, constant time). The product of
   --  two Len-word values plus a Len-word addend always fits 2 * Len
   --  words, so Result.Len = 2 * A.Len.
   procedure Mul_Add
     (Result  : out Big_Nat;
      A, B, C : in  Big_Nat)
   with Pre  => A.Len > 0 and B.Len = A.Len and C.Len = A.Len
                and 2 * A.Len <= Max_Words,
        Post => Result.Len = 2 * A.Len;

   --  Result := X mod M for X of at most 2 * M.Len words, using the
   --  Montgomery constant R2 = R^2 mod M (from R2_Mod) instead of a
   --  bitwise division: with X = Hi * R + Lo,
   --    X * R mod M = Monty (Lo, R^2) + Monty (Hi, R^3)
   --  and one more Montgomery product by 1 strips the factor R.
   --  Four multiplications, all constant time.
   procedure Mod_Reduce
     (Result : out Big_Nat;
      X      : in  Big_Nat;
      M      : in  Big_Nat;
      M0I    : in  Word;
      R2     : in  Big_Nat)
   with Pre  => M.Len > 0 and 2 * M.Len <= Max_Words
                and R2.Len = M.Len and X.Len <= 2 * M.Len,
        Post => Result.Len = M.Len;

   --  Result := A - B mod M for A, B < M (constant time: the borrow
   --  selects whether M is added back).
   procedure Sub_Mod
     (Result  : out Big_Nat;
      A, B, M : in  Big_Nat)
   with Pre  => M.Len > 0 and A.Len = M.Len and B.Len = M.Len,
        Post => Result.Len = M.Len;

   function Ninv (M0 : Word) return Word;

end SPARKTLSCrypto.BigNat64;
