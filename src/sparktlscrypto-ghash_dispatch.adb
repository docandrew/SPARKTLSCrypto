--  GHASH GF(2^128) multiplication dispatcher body.
--
--  Routes to SPARKTLSCrypto.GHASH_NI (CPUID-gated PCLMULQDQ,
--  SPARK_Mode Off) when available, otherwise the bit-by-bit
--  reference inlined here (lifted verbatim from AES_GCM.GF128_Mul
--  so the dispatcher is self-contained).

with Interfaces;             use Interfaces;
with SPARKTLSCrypto.GHASH_NI;

package body SPARKTLSCrypto.GHASH_Dispatch with
   SPARK_Mode => On
is

   --================================================================
   --  Bit-by-bit reference: NIST SP 800-38D §6.3, "Algorithm 1".
   --  Loop runs 128 iterations per call; ~1000 cycles per block on
   --  x86_64.  PCLMULQDQ is ~50x faster but not always available;
   --  this stays as the fallback.
   --================================================================

   function SW_GF128_Mul (X : Bytes_16; Y : Bytes_16) return Bytes_16
   is
      Z : Bytes_16 := (others => 0);
      V : Bytes_16 := X;
      LSB : Byte;

      procedure Shift_Right_1 (W : in out Bytes_16) is
         Carry : Byte := 0;
         Next_Carry : Byte;
      begin
         for I in 0 .. 15 loop
            Next_Carry := W (N32 (I)) and 1;
            W (N32 (I)) := Byte (Shift_Right (Unsigned_8 (W (N32 (I))), 1))
                            or Byte (Shift_Left (Unsigned_8 (Carry), 7));
            Carry := Next_Carry;
         end loop;
      end Shift_Right_1;
   begin
      for I in 0 .. 127 loop
         if (Y (N32 (I / 8)) and
             Byte (Shift_Right (Unsigned_8 (16#80#), I mod 8))) /= 0
         then
            for J in 0 .. 15 loop
               Z (N32 (J)) := Z (N32 (J)) xor V (N32 (J));
            end loop;
         end if;

         LSB := V (15) and 1;
         Shift_Right_1 (V);

         if LSB /= 0 then
            V (0) := V (0) xor 16#E1#;
         end if;
      end loop;
      return Z;
   end SW_GF128_Mul;

   --================================================================
   --  Dispatcher
   --================================================================

   function GF128_Mul (X : Bytes_16; Y : Bytes_16) return Bytes_16 is
   begin
      if SPARKTLSCrypto.GHASH_NI.Has_PCLMULQDQ then
         return SPARKTLSCrypto.GHASH_NI.GF128_Mul (X, Y);
      else
         return SW_GF128_Mul (X, Y);
      end if;
   end GF128_Mul;

end SPARKTLSCrypto.GHASH_Dispatch;
