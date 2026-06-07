--  PCLMULQDQ-accelerated GF(2^128) multiplication for GHASH (body).
--  See sparktlscrypto-ghash_ni.ads.
--
--  Algorithm cribbed from BoringSSL's `gcm_gmult_clmul` macro
--  (which itself follows Shay Gueron's "Intel Carry-Less
--  Multiplication Instruction" paper, Algorithm 5).
--
--  Bit/byte ordering note: NIST GHASH (SP 800-38D §6.2) numbers
--  polynomial coefficients so that bit 0 of byte 0 holds u^0 (the
--  identity coefficient).  The PCLMULQDQ instruction expects bit 0
--  of the low qword to be the low-degree coefficient and operates
--  on standard polynomial bit ordering.  We bridge the two by:
--    1. PSHUFB-byte-reversing the 16 bytes on load (mem byte 0
--       becomes xmm byte 15 and vice versa);
--    2. After multiplication, shifting the 256-bit raw product
--       left by 1 bit to undo the bit-reversal-induced extra
--       factor of x;
--    3. Reducing modulo P(x) = x^128 + x^7 + x^2 + x + 1 with
--       the standard "Algorithm 4" two-step shift-XOR reduction;
--    4. PSHUFB-byte-reversing back on store.
--
--  Step (2) carries via 32-bit lane shifts (psrld / pslld) plus
--  inter-lane shuffling — using 64-bit lane shifts loses the carry
--  across the 64-bit boundary inside the low qword.

with System.Machine_Code; use System.Machine_Code;
with Interfaces;          use Interfaces;
with SPARKNaCl;           use SPARKNaCl;

package body SPARKTLSCrypto.GHASH_NI with
   SPARK_Mode => Off
is

   ----------------------------------------------------------------------------
   --  CPUID detection (run once at elaboration)
   ----------------------------------------------------------------------------

   function Detect_PCLMULQDQ return Boolean is
      EAX, EBX, ECX, EDX : Unsigned_32;
   begin
      Asm ("cpuid",
           Outputs  => (Unsigned_32'Asm_Output ("=a", EAX),
                        Unsigned_32'Asm_Output ("=b", EBX),
                        Unsigned_32'Asm_Output ("=c", ECX),
                        Unsigned_32'Asm_Output ("=d", EDX)),
           Inputs   => Unsigned_32'Asm_Input ("a", 1),
           Volatile => True);
      pragma Unreferenced (EAX, EBX, EDX);
      --  CPUID.01h: ECX bit 1 = PCLMULQDQ
      return (ECX and 16#0000_0002#) /= 0;
   end Detect_PCLMULQDQ;

   ----------------------------------------------------------------------------
   --  Constants
   ----------------------------------------------------------------------------

   --  PSHUFB byte-reverse mask: result[i] = source[15 - i].
   Bswap_Mask : constant array (0 .. 15) of Unsigned_8 :=
     (15, 14, 13, 12, 11, 10, 9, 8,
      7,  6,  5,  4,  3,  2,  1, 0);
   for Bswap_Mask'Alignment use 16;

   ----------------------------------------------------------------------------
   --  GF(2^128) multiplication
   ----------------------------------------------------------------------------

   function GF128_Mul (X : Bytes_16; Y : Bytes_16) return Bytes_16 is
      Result : Bytes_16 := (others => 0);
   begin
      Asm
       (--  Load operands and byte-reverse to PCLMULQDQ orientation.
        "movdqu  (%0), %%xmm0"             & ASCII.LF & ASCII.HT &  -- xmm0 = X
        "movdqu  (%1), %%xmm1"             & ASCII.LF & ASCII.HT &  -- xmm1 = Y (H)
        "movdqa  (%2), %%xmm15"            & ASCII.LF & ASCII.HT &  -- BSWAP mask
        "pshufb  %%xmm15, %%xmm0"          & ASCII.LF & ASCII.HT &
        "pshufb  %%xmm15, %%xmm1"          & ASCII.LF & ASCII.HT &

        --  --- Schoolbook 128x128 carry-less multiply: 4 PCLMULQDQ
        --      tmp1 = X_lo * H_lo
        --      tmp4 = X_hi * H_hi
        --      tmp2 = X_hi * H_lo
        --      tmp3 = X_lo * H_hi
        "movdqa  %%xmm0, %%xmm2"           & ASCII.LF & ASCII.HT &
        "pclmulqdq $0x00, %%xmm1, %%xmm2"  & ASCII.LF & ASCII.HT &  -- xmm2 = tmp1
        "movdqa  %%xmm0, %%xmm3"           & ASCII.LF & ASCII.HT &
        "pclmulqdq $0x11, %%xmm1, %%xmm3"  & ASCII.LF & ASCII.HT &  -- xmm3 = tmp4
        "movdqa  %%xmm0, %%xmm4"           & ASCII.LF & ASCII.HT &
        "pclmulqdq $0x10, %%xmm1, %%xmm4"  & ASCII.LF & ASCII.HT &  -- xmm4 = X_lo*H_hi
        "movdqa  %%xmm0, %%xmm5"           & ASCII.LF & ASCII.HT &
        "pclmulqdq $0x01, %%xmm1, %%xmm5"  & ASCII.LF & ASCII.HT &  -- xmm5 = X_hi*H_lo
        "pxor    %%xmm5, %%xmm4"           & ASCII.LF & ASCII.HT &  -- xmm4 = sum

        --  Combine cross terms: low 128 (xmm2) gets low half of xmm4,
        --  high 128 (xmm3) gets high half of xmm4.
        "movdqa  %%xmm4, %%xmm5"           & ASCII.LF & ASCII.HT &
        "pslldq  $8, %%xmm5"               & ASCII.LF & ASCII.HT &
        "psrldq  $8, %%xmm4"               & ASCII.LF & ASCII.HT &
        "pxor    %%xmm5, %%xmm2"           & ASCII.LF & ASCII.HT &  -- xmm2 = lo 128
        "pxor    %%xmm4, %%xmm3"           & ASCII.LF & ASCII.HT &  -- xmm3 = hi 128

        --  --- Bit-shift correction: shift the 256-bit value
        --      xmm3:xmm2 left by 1 bit (BoringSSL pattern, using
        --      32-bit lane shifts so the carry propagates correctly
        --      across the 64-bit boundaries inside each xmm).
        "movdqa  %%xmm2, %%xmm5"           & ASCII.LF & ASCII.HT &
        "movdqa  %%xmm3, %%xmm6"           & ASCII.LF & ASCII.HT &
        "psrld   $31, %%xmm5"              & ASCII.LF & ASCII.HT &  -- xmm5 = top bits of each 32-bit lane of xmm2
        "psrld   $31, %%xmm6"              & ASCII.LF & ASCII.HT &  -- xmm6 = top bits of xmm3
        "pslld   $1, %%xmm2"               & ASCII.LF & ASCII.HT &
        "pslld   $1, %%xmm3"               & ASCII.LF & ASCII.HT &

        --  Carry the top bits one lane to the left, then OR.
        "movdqa  %%xmm5, %%xmm7"           & ASCII.LF & ASCII.HT &
        "psrldq  $12, %%xmm7"              & ASCII.LF & ASCII.HT &  -- top lane of xmm5 -> low lane (carries into xmm3)
        "pslldq  $4, %%xmm5"               & ASCII.LF & ASCII.HT &  -- shift xmm5 lanes left by 4 bytes (one 32-bit lane)
        "pslldq  $4, %%xmm6"               & ASCII.LF & ASCII.HT &
        "por     %%xmm5, %%xmm2"           & ASCII.LF & ASCII.HT &
        "por     %%xmm6, %%xmm3"           & ASCII.LF & ASCII.HT &
        "por     %%xmm7, %%xmm3"           & ASCII.LF & ASCII.HT &

        --  --- Reduction: mod P(x) = x^128 + x^7 + x^2 + x + 1
        --
        --  First fold: produce three shifted copies of the low 128
        --  to inject the contributions of x^126, x^125, x^120 from
        --  the wraparound.
        "movdqa  %%xmm2, %%xmm5"           & ASCII.LF & ASCII.HT &
        "movdqa  %%xmm2, %%xmm6"           & ASCII.LF & ASCII.HT &
        "movdqa  %%xmm2, %%xmm7"           & ASCII.LF & ASCII.HT &
        "pslld   $31, %%xmm5"              & ASCII.LF & ASCII.HT &
        "pslld   $30, %%xmm6"              & ASCII.LF & ASCII.HT &
        "pslld   $25, %%xmm7"              & ASCII.LF & ASCII.HT &
        "pxor    %%xmm6, %%xmm5"           & ASCII.LF & ASCII.HT &
        "pxor    %%xmm7, %%xmm5"           & ASCII.LF & ASCII.HT &
        --  Move xmm5's top lane out (carries up into xmm3); shift
        --  the rest into the low lanes of xmm2.
        "movdqa  %%xmm5, %%xmm6"           & ASCII.LF & ASCII.HT &
        "psrldq  $4, %%xmm6"               & ASCII.LF & ASCII.HT &
        "pslldq  $12, %%xmm5"              & ASCII.LF & ASCII.HT &
        "pxor    %%xmm5, %%xmm2"           & ASCII.LF & ASCII.HT &

        --  Second fold: produce three right-shifted copies of the
        --  (now-updated) low 128 to finish the modular reduction.
        --  Result = xmm3 ^ xmm2 ^ (xmm2 >> 1) ^ (xmm2 >> 2) ^ (xmm2 >> 7)
        "movdqa  %%xmm2, %%xmm7"           & ASCII.LF & ASCII.HT &
        "movdqa  %%xmm2, %%xmm4"           & ASCII.LF & ASCII.HT &
        "movdqa  %%xmm2, %%xmm5"           & ASCII.LF & ASCII.HT &
        "psrld   $1, %%xmm7"               & ASCII.LF & ASCII.HT &
        "psrld   $2, %%xmm4"               & ASCII.LF & ASCII.HT &
        "psrld   $7, %%xmm5"               & ASCII.LF & ASCII.HT &
        "pxor    %%xmm4, %%xmm3"           & ASCII.LF & ASCII.HT &
        "pxor    %%xmm5, %%xmm3"           & ASCII.LF & ASCII.HT &
        "pxor    %%xmm7, %%xmm3"           & ASCII.LF & ASCII.HT &
        "pxor    %%xmm6, %%xmm3"           & ASCII.LF & ASCII.HT &
        "pxor    %%xmm2, %%xmm3"           & ASCII.LF & ASCII.HT &

        --  Convert back from internal (byte-reversed) to NIST byte order.
        "pshufb  %%xmm15, %%xmm3"          & ASCII.LF & ASCII.HT &
        "movdqu  %%xmm3, (%3)",

        Inputs  => (System.Address'Asm_Input ("r", X'Address),
                    System.Address'Asm_Input ("r", Y'Address),
                    System.Address'Asm_Input ("r", Bswap_Mask'Address),
                    System.Address'Asm_Input ("r", Result'Address)),
        Clobber => "xmm0,xmm1,xmm2,xmm3,xmm4,xmm5,xmm6,xmm7,xmm15,memory",
        Volatile => True);
      return Result;
   end GF128_Mul;

   ----------------------------------------------------------------------------
   --  Pre-compute H, H^2, H^3, H^4 (byte-reversed for PCLMULQDQ)
   ----------------------------------------------------------------------------

   procedure Compute_H_Powers
     (H        : in     Bytes_16;
      H_Powers :    out Pre_H_Powers)
   is
      H1 : constant Bytes_16 := H;
      H2 : constant Bytes_16 := GF128_Mul (H1, H1);
      H3 : constant Bytes_16 := GF128_Mul (H1, H2);
      H4 : constant Bytes_16 := GF128_Mul (H1, H3);

      procedure Store_Reversed (Src : in Bytes_16; Off : in Natural) is
      begin
         for I in 0 .. 15 loop
            H_Powers (N32 (Off + I)) := Src (N32 (15 - I));
         end loop;
      end Store_Reversed;
   begin
      --  Layout: H^4 @ 0, H^3 @ 16, H^2 @ 32, H @ 48.
      --  Store each byte-reversed so PCLMULQDQ can consume directly.
      Store_Reversed (H4, 0);
      Store_Reversed (H3, 16);
      Store_Reversed (H2, 32);
      Store_Reversed (H1, 48);
   end Compute_H_Powers;

   ----------------------------------------------------------------------------
   --  4-block aggregated GHASH multiply
   ----------------------------------------------------------------------------

   procedure GHASH_4_Blocks
     (S        : in out Bytes_16;
      Blocks   : in     Byte_Seq;
      H_Powers : in     Pre_H_Powers)
   is
   begin
      Asm
       (--  xmm15 = byte-swap mask (NIST byte order <-> internal).
        "movdqa  (%2), %%xmm15"             & ASCII.LF & ASCII.HT &

        --  Load and byte-reverse the running tag S.
        "movdqu  (%0), %%xmm0"              & ASCII.LF & ASCII.HT &
        "pshufb  %%xmm15, %%xmm0"           & ASCII.LF & ASCII.HT &

        ----------------------------------------------------------------------------
        --  Block 0: (S ^ B0) * H^4
        ----------------------------------------------------------------------------
        "movdqu    (%1), %%xmm1"            & ASCII.LF & ASCII.HT &
        "pshufb  %%xmm15, %%xmm1"           & ASCII.LF & ASCII.HT &
        "pxor    %%xmm0, %%xmm1"            & ASCII.LF & ASCII.HT &
        "movdqu    (%3), %%xmm0"            & ASCII.LF & ASCII.HT &  -- H^4
        --  Schoolbook multiply, accumulating into (xmm2=lo, xmm3=hi, xmm4=mid).
        "movdqa  %%xmm1, %%xmm2"            & ASCII.LF & ASCII.HT &
        "pclmulqdq $0x00, %%xmm0, %%xmm2"   & ASCII.LF & ASCII.HT &
        "movdqa  %%xmm1, %%xmm3"            & ASCII.LF & ASCII.HT &
        "pclmulqdq $0x11, %%xmm0, %%xmm3"   & ASCII.LF & ASCII.HT &
        "movdqa  %%xmm1, %%xmm4"            & ASCII.LF & ASCII.HT &
        "pclmulqdq $0x10, %%xmm0, %%xmm4"   & ASCII.LF & ASCII.HT &
        "pclmulqdq $0x01, %%xmm0, %%xmm1"   & ASCII.LF & ASCII.HT &
        "pxor    %%xmm1, %%xmm4"            & ASCII.LF & ASCII.HT &

        ----------------------------------------------------------------------------
        --  Block 1: B1 * H^3 — accumulate into the same (lo, hi, mid).
        ----------------------------------------------------------------------------
        "movdqu  16(%1), %%xmm5"            & ASCII.LF & ASCII.HT &
        "pshufb  %%xmm15, %%xmm5"           & ASCII.LF & ASCII.HT &
        "movdqu  16(%3), %%xmm0"            & ASCII.LF & ASCII.HT &  -- H^3
        "movdqa  %%xmm5, %%xmm6"            & ASCII.LF & ASCII.HT &
        "pclmulqdq $0x00, %%xmm0, %%xmm6"   & ASCII.LF & ASCII.HT &
        "pxor    %%xmm6, %%xmm2"            & ASCII.LF & ASCII.HT &
        "movdqa  %%xmm5, %%xmm6"            & ASCII.LF & ASCII.HT &
        "pclmulqdq $0x11, %%xmm0, %%xmm6"   & ASCII.LF & ASCII.HT &
        "pxor    %%xmm6, %%xmm3"            & ASCII.LF & ASCII.HT &
        "movdqa  %%xmm5, %%xmm6"            & ASCII.LF & ASCII.HT &
        "pclmulqdq $0x10, %%xmm0, %%xmm6"   & ASCII.LF & ASCII.HT &
        "pxor    %%xmm6, %%xmm4"            & ASCII.LF & ASCII.HT &
        "pclmulqdq $0x01, %%xmm0, %%xmm5"   & ASCII.LF & ASCII.HT &
        "pxor    %%xmm5, %%xmm4"            & ASCII.LF & ASCII.HT &

        ----------------------------------------------------------------------------
        --  Block 2: B2 * H^2
        ----------------------------------------------------------------------------
        "movdqu  32(%1), %%xmm5"            & ASCII.LF & ASCII.HT &
        "pshufb  %%xmm15, %%xmm5"           & ASCII.LF & ASCII.HT &
        "movdqu  32(%3), %%xmm0"            & ASCII.LF & ASCII.HT &  -- H^2
        "movdqa  %%xmm5, %%xmm6"            & ASCII.LF & ASCII.HT &
        "pclmulqdq $0x00, %%xmm0, %%xmm6"   & ASCII.LF & ASCII.HT &
        "pxor    %%xmm6, %%xmm2"            & ASCII.LF & ASCII.HT &
        "movdqa  %%xmm5, %%xmm6"            & ASCII.LF & ASCII.HT &
        "pclmulqdq $0x11, %%xmm0, %%xmm6"   & ASCII.LF & ASCII.HT &
        "pxor    %%xmm6, %%xmm3"            & ASCII.LF & ASCII.HT &
        "movdqa  %%xmm5, %%xmm6"            & ASCII.LF & ASCII.HT &
        "pclmulqdq $0x10, %%xmm0, %%xmm6"   & ASCII.LF & ASCII.HT &
        "pxor    %%xmm6, %%xmm4"            & ASCII.LF & ASCII.HT &
        "pclmulqdq $0x01, %%xmm0, %%xmm5"   & ASCII.LF & ASCII.HT &
        "pxor    %%xmm5, %%xmm4"            & ASCII.LF & ASCII.HT &

        ----------------------------------------------------------------------------
        --  Block 3: B3 * H
        ----------------------------------------------------------------------------
        "movdqu  48(%1), %%xmm5"            & ASCII.LF & ASCII.HT &
        "pshufb  %%xmm15, %%xmm5"           & ASCII.LF & ASCII.HT &
        "movdqu  48(%3), %%xmm0"            & ASCII.LF & ASCII.HT &  -- H
        "movdqa  %%xmm5, %%xmm6"            & ASCII.LF & ASCII.HT &
        "pclmulqdq $0x00, %%xmm0, %%xmm6"   & ASCII.LF & ASCII.HT &
        "pxor    %%xmm6, %%xmm2"            & ASCII.LF & ASCII.HT &
        "movdqa  %%xmm5, %%xmm6"            & ASCII.LF & ASCII.HT &
        "pclmulqdq $0x11, %%xmm0, %%xmm6"   & ASCII.LF & ASCII.HT &
        "pxor    %%xmm6, %%xmm3"            & ASCII.LF & ASCII.HT &
        "movdqa  %%xmm5, %%xmm6"            & ASCII.LF & ASCII.HT &
        "pclmulqdq $0x10, %%xmm0, %%xmm6"   & ASCII.LF & ASCII.HT &
        "pxor    %%xmm6, %%xmm4"            & ASCII.LF & ASCII.HT &
        "pclmulqdq $0x01, %%xmm0, %%xmm5"   & ASCII.LF & ASCII.HT &
        "pxor    %%xmm5, %%xmm4"            & ASCII.LF & ASCII.HT &

        ----------------------------------------------------------------------------
        --  Combine cross terms (mid -> lo & hi).
        ----------------------------------------------------------------------------
        "movdqa  %%xmm4, %%xmm5"            & ASCII.LF & ASCII.HT &
        "pslldq  $8, %%xmm5"                & ASCII.LF & ASCII.HT &
        "psrldq  $8, %%xmm4"                & ASCII.LF & ASCII.HT &
        "pxor    %%xmm5, %%xmm2"            & ASCII.LF & ASCII.HT &
        "pxor    %%xmm4, %%xmm3"            & ASCII.LF & ASCII.HT &

        ----------------------------------------------------------------------------
        --  Bit-shift correction: (xmm3:xmm2) <<= 1 (32-bit-lane carry).
        --  Same pattern as the single-block GF128_Mul; correction is
        --  linear over XOR so doing it once on the sum is correct.
        ----------------------------------------------------------------------------
        "movdqa  %%xmm2, %%xmm5"            & ASCII.LF & ASCII.HT &
        "movdqa  %%xmm3, %%xmm6"            & ASCII.LF & ASCII.HT &
        "psrld   $31, %%xmm5"               & ASCII.LF & ASCII.HT &
        "psrld   $31, %%xmm6"               & ASCII.LF & ASCII.HT &
        "pslld   $1, %%xmm2"                & ASCII.LF & ASCII.HT &
        "pslld   $1, %%xmm3"                & ASCII.LF & ASCII.HT &
        "movdqa  %%xmm5, %%xmm7"            & ASCII.LF & ASCII.HT &
        "psrldq  $12, %%xmm7"               & ASCII.LF & ASCII.HT &
        "pslldq  $4, %%xmm5"                & ASCII.LF & ASCII.HT &
        "pslldq  $4, %%xmm6"                & ASCII.LF & ASCII.HT &
        "por     %%xmm5, %%xmm2"            & ASCII.LF & ASCII.HT &
        "por     %%xmm6, %%xmm3"            & ASCII.LF & ASCII.HT &
        "por     %%xmm7, %%xmm3"            & ASCII.LF & ASCII.HT &

        ----------------------------------------------------------------------------
        --  Reduction mod P(x) = x^128 + x^7 + x^2 + x + 1
        --  (same first-fold + second-fold as GF128_Mul).
        ----------------------------------------------------------------------------
        "movdqa  %%xmm2, %%xmm5"            & ASCII.LF & ASCII.HT &
        "movdqa  %%xmm2, %%xmm6"            & ASCII.LF & ASCII.HT &
        "movdqa  %%xmm2, %%xmm7"            & ASCII.LF & ASCII.HT &
        "pslld   $31, %%xmm5"               & ASCII.LF & ASCII.HT &
        "pslld   $30, %%xmm6"               & ASCII.LF & ASCII.HT &
        "pslld   $25, %%xmm7"               & ASCII.LF & ASCII.HT &
        "pxor    %%xmm6, %%xmm5"            & ASCII.LF & ASCII.HT &
        "pxor    %%xmm7, %%xmm5"            & ASCII.LF & ASCII.HT &
        "movdqa  %%xmm5, %%xmm6"            & ASCII.LF & ASCII.HT &
        "psrldq  $4, %%xmm6"                & ASCII.LF & ASCII.HT &
        "pslldq  $12, %%xmm5"               & ASCII.LF & ASCII.HT &
        "pxor    %%xmm5, %%xmm2"            & ASCII.LF & ASCII.HT &

        "movdqa  %%xmm2, %%xmm7"            & ASCII.LF & ASCII.HT &
        "movdqa  %%xmm2, %%xmm4"            & ASCII.LF & ASCII.HT &
        "movdqa  %%xmm2, %%xmm5"            & ASCII.LF & ASCII.HT &
        "psrld   $1, %%xmm7"                & ASCII.LF & ASCII.HT &
        "psrld   $2, %%xmm4"                & ASCII.LF & ASCII.HT &
        "psrld   $7, %%xmm5"                & ASCII.LF & ASCII.HT &
        "pxor    %%xmm4, %%xmm3"            & ASCII.LF & ASCII.HT &
        "pxor    %%xmm5, %%xmm3"            & ASCII.LF & ASCII.HT &
        "pxor    %%xmm7, %%xmm3"            & ASCII.LF & ASCII.HT &
        "pxor    %%xmm6, %%xmm3"            & ASCII.LF & ASCII.HT &
        "pxor    %%xmm2, %%xmm3"            & ASCII.LF & ASCII.HT &

        --  Convert back to NIST byte order and store.
        "pshufb  %%xmm15, %%xmm3"           & ASCII.LF & ASCII.HT &
        "movdqu  %%xmm3, (%0)",

        Inputs  => (System.Address'Asm_Input ("r", S'Address),
                    System.Address'Asm_Input ("r", Blocks'Address),
                    System.Address'Asm_Input ("r", Bswap_Mask'Address),
                    System.Address'Asm_Input ("r", H_Powers'Address)),
        Clobber => "xmm0,xmm1,xmm2,xmm3,xmm4,xmm5,xmm6,xmm7,xmm15,memory",
        Volatile => True);
   end GHASH_4_Blocks;

begin
   Has_PCLMULQDQ := Detect_PCLMULQDQ;
end SPARKTLSCrypto.GHASH_NI;
