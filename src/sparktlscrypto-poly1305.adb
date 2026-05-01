--  Fast scalar Poly1305 (RFC 8439). Body — see spec.
--
--  Implementation: radix 2^26 (5 limbs of 26 bits each in U64).
--  Per-block work:
--    a)  Block += message limbs (with implicit msb=1)
--    b)  a *= r   (5×5 = 25 schoolbook mults, lazy carry on each row)
--    c)  Reduce mod 2^130 - 5 (single-pass carry chain)
--
--  Reference layout (Bernstein/poly1305-donna):
--    h, r each split into h[0..4], r[0..4]; r is clamped per RFC §2.5.2.
--    Pre-multiply s[i] = r[i] * 5 to fold the 2^130 ≡ 5 (mod p) wraparound.
--    Each h[i] * r[j] product fits in 52 bits; sum of 5 fits in 56 bits;
--    plus carry-in stays < 2^64.

with Interfaces; use Interfaces;

package body SPARKTLSCrypto.Poly1305 with
   SPARK_Mode => On
is

   subtype U64 is Unsigned_64;
   subtype U32 is Unsigned_32;

   --  Read a little-endian 4-byte u32 from M (P..P+3).
   function Le32 (M : in Byte_Seq; P : in N32) return U32
     with Pre => P >= M'First and then P + 3 <= M'Last;

   function Le32 (M : in Byte_Seq; P : in N32) return U32 is
   begin
      return Unsigned_32 (M (P))
           or Shift_Left (Unsigned_32 (M (P + 1)),  8)
           or Shift_Left (Unsigned_32 (M (P + 2)), 16)
           or Shift_Left (Unsigned_32 (M (P + 3)), 24);
   end Le32;

   procedure Onetimeauth
     (Output :    out Bytes_16;
      M      : in     Byte_Seq;
      K      : in     SPARKNaCl.MAC.Poly_1305_Key)
   is
      --  Accumulator h, key r in 5 × 26-bit limbs.
      h0, h1, h2, h3, h4 : U64 := 0;
      r0, r1, r2, r3, r4 : U64;
      --  Pre-multiplied 5*r[1..4] for the wraparound fold.
      s1, s2, s3, s4     : U64;

      d0, d1, d2, d3, d4 : U64;
      c : U64;

      Pos       : N32 := M'First;
      Len       : constant N32 := N32 (M'Length);
      End_Last  : constant N32 := M'Last;
      Block     : Bytes_16;
      Remaining : N32;

      Key_Bytes : constant Bytes_32 := SPARKNaCl.MAC.Serialize (K);

      --  Mask for one 26-bit limb.
      M26 : constant U64 := 16#03FF_FFFF#;

      --  Process one 16-byte block (already loaded into Block, with the
      --  high "1" bit folded in by caller via Hi_Bit).
      procedure Process_Block (Hi_Bit : in U64);

      procedure Process_Block (Hi_Bit : in U64) is
         t0, t1, t2, t3 : U32;
      begin
         t0 := Le32 (Byte_Seq (Block),  0);
         t1 := Le32 (Byte_Seq (Block),  4);
         t2 := Le32 (Byte_Seq (Block),  8);
         t3 := Le32 (Byte_Seq (Block), 12);

         --  h += message-as-5-limbs (radix 2^26, with high bit = Hi_Bit).
         h0 := h0 + (U64 (t0)                                          and M26);
         h1 := h1 + ((Shift_Right (U64 (t0), 26) or
                      Shift_Left  (U64 (t1),  6))                       and M26);
         h2 := h2 + ((Shift_Right (U64 (t1), 20) or
                      Shift_Left  (U64 (t2), 12))                       and M26);
         h3 := h3 + ((Shift_Right (U64 (t2), 14) or
                      Shift_Left  (U64 (t3), 18))                       and M26);
         h4 := h4 + Shift_Right (U64 (t3),  8) + Shift_Left (Hi_Bit, 24);

         --  d[i] = sum of h[j] * (r[i-j] or 5*r[5+i-j]) for j=0..4.
         d0 := h0*r0 + h1*s4 + h2*s3 + h3*s2 + h4*s1;
         d1 := h0*r1 + h1*r0 + h2*s4 + h3*s3 + h4*s2;
         d2 := h0*r2 + h1*r1 + h2*r0 + h3*s4 + h4*s3;
         d3 := h0*r3 + h1*r2 + h2*r1 + h3*r0 + h4*s4;
         d4 := h0*r4 + h1*r3 + h2*r2 + h3*r1 + h4*r0;

         --  Carry-propagate. Each d[i] is < 2^57; carry chain keeps it.
         c  := Shift_Right (d0, 26); h0 := d0 and M26;
         d1 := d1 + c;
         c  := Shift_Right (d1, 26); h1 := d1 and M26;
         d2 := d2 + c;
         c  := Shift_Right (d2, 26); h2 := d2 and M26;
         d3 := d3 + c;
         c  := Shift_Right (d3, 26); h3 := d3 and M26;
         d4 := d4 + c;
         c  := Shift_Right (d4, 26); h4 := d4 and M26;
         --  Fold the 2^130 overflow back into h0 (× 5).
         h0 := h0 + c * 5;
         c  := Shift_Right (h0, 26); h0 := h0 and M26;
         h1 := h1 + c;
      end Process_Block;

   begin
      --  Extract clamped r from K[0..15] (RFC 8439 §2.5.2).
      --  Clamp = clear top 4 bits of bytes 3,7,11,15 (mask 0x0F)
      --          clear bottom 2 bits of bytes 4,8,12  (mask 0xFC)
      --  Split into 5 × 26-bit limbs, encoding the clamps in the limb masks:
      --    r0 = bytes[0..3]   & 0x03FFFFFF
      --    r1 = (bytes[3..6] >> 2) & 0x03FFFF03
      --    r2 = (bytes[6..9] >> 4) & 0x03FFC0FF
      --    r3 = (bytes[9..12] >> 6) & 0x03F03FFF
      --    r4 = (bytes[12..15] >> 8) & 0x000FFFFF
      r0 := U64 (Le32 (Byte_Seq (Key_Bytes),  0))                  and 16#03FF_FFFF#;
      r1 := Shift_Right (U64 (Le32 (Byte_Seq (Key_Bytes),  3)), 2) and 16#03FF_FF03#;
      r2 := Shift_Right (U64 (Le32 (Byte_Seq (Key_Bytes),  6)), 4) and 16#03FF_C0FF#;
      r3 := Shift_Right (U64 (Le32 (Byte_Seq (Key_Bytes),  9)), 6) and 16#03F0_3FFF#;
      r4 := Shift_Right (U64 (Le32 (Byte_Seq (Key_Bytes), 12)), 8) and 16#000F_FFFF#;

      s1 := r1 * 5;
      s2 := r2 * 5;
      s3 := r3 * 5;
      s4 := r4 * 5;

      --  Process whole 16-byte blocks.
      while Pos + 15 <= End_Last loop
         pragma Loop_Invariant (Pos + 15 <= End_Last);
         for I in 0 .. 15 loop
            Block (N32 (I)) := M (Pos + N32 (I));
         end loop;
         Process_Block (1);
         Pos := Pos + 16;
      end loop;

      --  Final partial block (if any): zero-pad and append a "1" byte
      --  at the next position. This emulates "high bit at byte L".
      if Pos <= End_Last then
         Remaining := End_Last - Pos + 1;
         Block := (others => 0);
         for I in 0 .. Remaining - 1 loop
            pragma Loop_Invariant
              (I < Remaining and Pos + I <= End_Last);
            Block (I) := M (Pos + I);
         end loop;
         Block (Remaining) := 1;  -- explicit "1" terminator
         Process_Block (0);       -- Hi_Bit = 0; the explicit byte does it
      end if;

      --  Final reduction: subtract p = 2^130 - 5 if h >= p, conditionally.
      --  Equivalent: try (h + 5) mod 2^130; if no overflow, use h, else h+5.
      c  := Shift_Right (h1, 26); h1 := h1 and M26;
      h2 := h2 + c;
      c  := Shift_Right (h2, 26); h2 := h2 and M26;
      h3 := h3 + c;
      c  := Shift_Right (h3, 26); h3 := h3 and M26;
      h4 := h4 + c;
      c  := Shift_Right (h4, 26); h4 := h4 and M26;
      h0 := h0 + c * 5;
      c  := Shift_Right (h0, 26); h0 := h0 and M26;
      h1 := h1 + c;

      --  Compute g = h + (-p) = h - (2^130 - 5) = h + 5 - 2^130.
      declare
         g0, g1, g2, g3, g4 : U64;
         mask : U64;
      begin
         g0 := h0 + 5;
         c  := Shift_Right (g0, 26); g0 := g0 and M26;
         g1 := h1 + c;
         c  := Shift_Right (g1, 26); g1 := g1 and M26;
         g2 := h2 + c;
         c  := Shift_Right (g2, 26); g2 := g2 and M26;
         g3 := h3 + c;
         c  := Shift_Right (g3, 26); g3 := g3 and M26;
         g4 := h4 + c - Shift_Left (U64 (1), 26);

         --  Select h when h < p (g4 underflowed), else g (h was >= p).
         --  Constant-time: build a bytewise all-ones mask from the
         --  underflow bit. mask = 0xFF..FF if h < p, 0 otherwise.
         mask := 0 - Shift_Right (g4, 63);
         h0 := (h0 and mask) or (g0 and not mask);
         h1 := (h1 and mask) or (g1 and not mask);
         h2 := (h2 and mask) or (g2 and not mask);
         h3 := (h3 and mask) or (g3 and not mask);
         h4 := (h4 and mask) or (g4 and not mask);
      end;

      --  Pack 5 limbs back to 4 × 32-bit words (little-endian).
      declare
         f0, f1, f2, f3 : U64;
         u : U64;
      begin
         --  Truncate each composed word to 32 bits — without this the
         --  high bits (already counted in f[i+1]) corrupt the carry
         --  chain when s is added below.
         f0 := (h0 or Shift_Left (h1, 26))           and 16#FFFF_FFFF#;
         f1 := (Shift_Right (h1,  6) or Shift_Left (h2, 20)) and 16#FFFF_FFFF#;
         f2 := (Shift_Right (h2, 12) or Shift_Left (h3, 14)) and 16#FFFF_FFFF#;
         f3 := (Shift_Right (h3, 18) or Shift_Left (h4,  8)) and 16#FFFF_FFFF#;

         --  Add s = K[16..31] (the second half of the Poly1305 key).
         u := f0 + U64 (Le32 (Byte_Seq (Key_Bytes), 16));
         f0 := u and 16#FFFF_FFFF#;
         u := f1 + U64 (Le32 (Byte_Seq (Key_Bytes), 20)) + Shift_Right (u, 32);
         f1 := u and 16#FFFF_FFFF#;
         u := f2 + U64 (Le32 (Byte_Seq (Key_Bytes), 24)) + Shift_Right (u, 32);
         f2 := u and 16#FFFF_FFFF#;
         u := f3 + U64 (Le32 (Byte_Seq (Key_Bytes), 28)) + Shift_Right (u, 32);
         f3 := u and 16#FFFF_FFFF#;

         --  Serialize as 16-byte little-endian tag.
         for I in 0 .. 3 loop
            Output (N32 (I))      := Byte (Shift_Right (f0, 8 * I) and 16#FF#);
            Output (N32 (4 + I))  := Byte (Shift_Right (f1, 8 * I) and 16#FF#);
            Output (N32 (8 + I))  := Byte (Shift_Right (f2, 8 * I) and 16#FF#);
            Output (N32 (12 + I)) := Byte (Shift_Right (f3, 8 * I) and 16#FF#);
         end loop;
      end;
   end Onetimeauth;

end SPARKTLSCrypto.Poly1305;
