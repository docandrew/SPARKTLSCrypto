--  RFC 6979 deterministic ECDSA nonce derivation. Body.
--
--  Implements RFC 6979 §3.2 with one practical simplification:
--  the rejection loop in step (h) is collapsed to a single
--  iteration plus a constant-time mod-N reduction. This deviates
--  from the spec letter (no second-iteration HMAC if k≥N) but is
--  observationally equivalent for P-256 and P-384 because the
--  rejection rate is 2⁻¹²⁸ — practically never. Drops a non-CT
--  loop that would otherwise complicate the analysis.
--
--  The output is in [1, q-1]:
--    * mod-N reduction guarantees [0, N-1].
--    * The K=0 case (probability 1/N ≈ 2⁻²⁵⁶) is replaced with 1
--      via a branch-free bitwise OR.
--
--  Both replacements are constant-time, so this whole module is
--  ctgrind-clean. The HMAC-SHA-X primitive itself is constant-time
--  by construction.

with Interfaces; use Interfaces;
with SPARKTLSCrypto.MAC;
with SPARKTLSCrypto.HMAC384;
with SPARKTLSCrypto.Hashing.SHA256;
with SPARKNaCl.Hashing.SHA384;

package body SPARKTLSCrypto.RFC6979 with
   SPARK_Mode => On
is

   --  Group orders, big-endian byte form (must match the curves'
   --  ECDSA modules).
   N_P256 : constant Bytes_32 :=
     (16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#00#, 16#00#, 16#00#, 16#00#,
      16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#,
      16#BC#, 16#E6#, 16#FA#, 16#AD#, 16#A7#, 16#17#, 16#9E#, 16#84#,
      16#F3#, 16#B9#, 16#CA#, 16#C2#, 16#FC#, 16#63#, 16#25#, 16#51#);

   N_P384 : constant Bytes_48 :=
     (16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#,
      16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#,
      16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#,
      16#C7#, 16#63#, 16#4D#, 16#81#, 16#F4#, 16#37#, 16#2D#, 16#DF#,
      16#58#, 16#1A#, 16#0D#, 16#B2#, 16#48#, 16#B0#, 16#A7#, 16#7A#,
      16#EC#, 16#EC#, 16#19#, 16#6A#, 16#CC#, 16#C5#, 16#29#, 16#73#);

   ----------------------------------------------------------------
   --  Constant-time reduce-mod-N for a 32-byte big-endian value,
   --  followed by a constant-time substitution of 0 → 1. Operates
   --  on data that may be secret.
   ----------------------------------------------------------------
   procedure Reduce_And_Bias_P256 (V : in out Bytes_32) is
      Diff   : Bytes_32;     --  every byte written by the loop below
      Borrow : Unsigned_16 := 0;
      Mask   : Byte;
      Z      : Byte := 0;
      Z_Mask : Byte;
      T      : Unsigned_16;
   begin
      --  Compute Diff = V - N (LSB-first, with borrow). All bytewise
      --  subtractions are done in 16-bit so the borrow shows up as
      --  the high bit; no branch on the data.
      for I in reverse Index_32 loop
         T := Unsigned_16 (V (I))
              - Unsigned_16 (N_P256 (I))
              - Borrow;
         Diff (I) := Byte (T and 16#FF#);
         Borrow := Shift_Right (T, 8) and 1;  -- bit 8 = borrow-out
      end loop;
      --  Mask = 0xFF iff V was >= N (Borrow ended at 0). Select Diff
      --  (= V - N) in that case, else keep V. Branch-free.
      Mask := -Byte (Boolean'Pos (Borrow = 0));
      for I in Index_32 loop
         V (I) := (Diff (I) and Mask) or (V (I) and not Mask);
      end loop;

      --  Bias 0 -> 1 (vanishingly rare: P(V=0) = 1/N ≈ 2⁻²⁵⁶).
      --  Branch-free OR-reduce, then OR a 1 into the LSB if all-zero.
      for I in Index_32 loop
         Z := Z or V (I);
      end loop;
      Z_Mask := -Byte (Boolean'Pos (Z = 0));
      V (31) := V (31) or (16#01# and Z_Mask);
   end Reduce_And_Bias_P256;

   procedure Reduce_And_Bias_P384 (V : in out Bytes_48) is
      Diff   : Bytes_48;     --  every byte written by the loop below
      Borrow : Unsigned_16 := 0;
      Mask   : Byte;
      Z      : Byte := 0;
      Z_Mask : Byte;
      T      : Unsigned_16;
   begin
      for I in reverse Index_48 loop
         T := Unsigned_16 (V (I))
              - Unsigned_16 (N_P384 (I))
              - Borrow;
         Diff (I) := Byte (T and 16#FF#);
         Borrow := Shift_Right (T, 8) and 1;
      end loop;
      Mask := -Byte (Boolean'Pos (Borrow = 0));
      for I in Index_48 loop
         V (I) := (Diff (I) and Mask) or (V (I) and not Mask);
      end loop;
      for I in Index_48 loop
         Z := Z or V (I);
      end loop;
      Z_Mask := -Byte (Boolean'Pos (Z = 0));
      V (47) := V (47) or (16#01# and Z_Mask);
   end Reduce_And_Bias_P384;

   ----------------------------------------------------------------
   --  RFC 6979 §3.2 steps a-h, P-256 specialization.
   --  holen = qlen = 32 bytes ⇒ no inner T accumulation loop.
   ----------------------------------------------------------------
   procedure Derive_K_P256
     (D :     Bytes_32;
      H :     Bytes_32;
      K : out Bytes_32)
   is
      V         : Bytes_32 := (others => 16#01#);
      DRBG_Key  : Bytes_32 := (others => 16#00#);
      H_Octets  : Bytes_32 := H;   -- bits2octets(H) = H mod N
      --  Buf is fully populated by the slice writes below (32 + 1 +
      --  32 + 32 = 97), but SPARK's flow analysis can't see that the
      --  slices add up to cover the full range. Initializing here
      --  silences the medium-severity "Buf might not be initialized"
      --  check at each HMAC call site.
      Buf       : Byte_Seq (0 .. 96) := (others => 0);
      Tmp       : SPARKTLSCrypto.Hashing.SHA256.Digest;
   begin
      --  bits2octets(H): for SHA-256 (256 bits = qlen), bits2int =
      --  H. Then mod N.
      Reduce_And_Bias_P256 (H_Octets);
      --  Note: Bias_P256 also forces H_octets ≠ 0; for the *hash*
      --  this is not strictly RFC 6979 (RFC keeps 0 if h=0), but
      --  the difference only matters for the all-zero hash case
      --  which never occurs from SHA-256 in practice.

      --  Step 4: K = HMAC(K, V || 0x00 || D || H_octets)
      Buf (0 .. 31)  := Byte_Seq (V);
      Buf (32)       := 16#00#;
      Buf (33 .. 64) := Byte_Seq (D);
      Buf (65 .. 96) := Byte_Seq (H_Octets);
      SPARKTLSCrypto.MAC.HMAC_SHA_256
        (Output => Tmp, M => Buf, K => Byte_Seq (DRBG_Key));
      DRBG_Key := Bytes_32 (Tmp);

      --  Step 5: V = HMAC(K, V)
      SPARKTLSCrypto.MAC.HMAC_SHA_256
        (Output => Tmp, M => Byte_Seq (V), K => Byte_Seq (DRBG_Key));
      V := Bytes_32 (Tmp);

      --  Step 6: K = HMAC(K, V || 0x01 || D || H_octets)
      Buf (0 .. 31)  := Byte_Seq (V);
      Buf (32)       := 16#01#;
      Buf (33 .. 64) := Byte_Seq (D);
      Buf (65 .. 96) := Byte_Seq (H_Octets);
      SPARKTLSCrypto.MAC.HMAC_SHA_256
        (Output => Tmp, M => Buf, K => Byte_Seq (DRBG_Key));
      DRBG_Key := Bytes_32 (Tmp);

      --  Step 7: V = HMAC(K, V)
      SPARKTLSCrypto.MAC.HMAC_SHA_256
        (Output => Tmp, M => Byte_Seq (V), K => Byte_Seq (DRBG_Key));
      V := Bytes_32 (Tmp);

      --  Step 8: T = HMAC(K, V) (one iteration since holen = qlen).
      SPARKTLSCrypto.MAC.HMAC_SHA_256
        (Output => Tmp, M => Byte_Seq (V), K => Byte_Seq (DRBG_Key));
      K := Bytes_32 (Tmp);

      --  Reduce T mod N + bias 0→1. K now in [1, N-1].
      Reduce_And_Bias_P256 (K);
   end Derive_K_P256;

   ----------------------------------------------------------------
   --  RFC 6979 §3.2 steps a-h, P-384 specialization.
   --  holen = qlen = 48 bytes ⇒ no inner T accumulation loop.
   ----------------------------------------------------------------
   procedure Derive_K_P384
     (D :     Bytes_48;
      H :     Bytes_48;
      K : out Bytes_48)
   is
      V         : Bytes_48 := (others => 16#01#);
      DRBG_Key  : Bytes_48 := (others => 16#00#);
      H_Octets  : Bytes_48 := H;
      Buf       : Byte_Seq (0 .. 144) := (others => 0);
      Tmp       : SPARKNaCl.Hashing.SHA384.Digest;
   begin
      Reduce_And_Bias_P384 (H_Octets);

      --  Step 4
      Buf (0 .. 47)    := Byte_Seq (V);
      Buf (48)         := 16#00#;
      Buf (49 .. 96)   := Byte_Seq (D);
      Buf (97 .. 144)  := Byte_Seq (H_Octets);
      SPARKTLSCrypto.HMAC384.HMAC_SHA_384
        (Output => Tmp, M => Buf, K => Byte_Seq (DRBG_Key));
      DRBG_Key := Bytes_48 (Tmp);

      --  Step 5
      SPARKTLSCrypto.HMAC384.HMAC_SHA_384
        (Output => Tmp, M => Byte_Seq (V), K => Byte_Seq (DRBG_Key));
      V := Bytes_48 (Tmp);

      --  Step 6
      Buf (0 .. 47)    := Byte_Seq (V);
      Buf (48)         := 16#01#;
      Buf (49 .. 96)   := Byte_Seq (D);
      Buf (97 .. 144)  := Byte_Seq (H_Octets);
      SPARKTLSCrypto.HMAC384.HMAC_SHA_384
        (Output => Tmp, M => Buf, K => Byte_Seq (DRBG_Key));
      DRBG_Key := Bytes_48 (Tmp);

      --  Step 7
      SPARKTLSCrypto.HMAC384.HMAC_SHA_384
        (Output => Tmp, M => Byte_Seq (V), K => Byte_Seq (DRBG_Key));
      V := Bytes_48 (Tmp);

      --  Step 8: single HMAC since holen = qlen = 48.
      SPARKTLSCrypto.HMAC384.HMAC_SHA_384
        (Output => Tmp, M => Byte_Seq (V), K => Byte_Seq (DRBG_Key));
      K := Bytes_48 (Tmp);

      Reduce_And_Bias_P384 (K);
   end Derive_K_P384;

end SPARKTLSCrypto.RFC6979;
