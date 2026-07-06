--  RFC 6979 deterministic ECDSA nonce derivation. Body.
--
--  Implements RFC 6979 §3.2 for P-256/SHA-256 and P-384/SHA-384.
--  bits2octets(h1) uses the specified conditional subtraction, while
--  the generated nonce candidate is compared against q and retried
--  instead of reduced modulo q. Reducing the candidate would bias k.

with Interfaces; use Interfaces;
with SPARKTLSCrypto.MAC;
with SPARKTLSCrypto.HMAC384;
with SPARKTLSCrypto.Hashing.SHA256;
with SPARKNaCl.Hashing.SHA384;

package body SPARKTLSCrypto.RFC6979 with
   SPARK_Mode => On
is
   Max_Candidates : constant := 8;


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
   --  Constant-time reduce-mod-N for a big-endian value. Operates
   --  on data that may be secret.
   ----------------------------------------------------------------
   procedure Reduce_P256 (V : in out Bytes_32) is
      Diff   : Bytes_32;     --  every byte written by the loop below
      Borrow : Unsigned_16 := 0;
      Mask   : Byte;
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
   end Reduce_P256;

   function CT_Nonzero (V : Byte) return Byte is
      W : constant Unsigned_16 := Unsigned_16 (V);
   begin
      return Byte (Shift_Right (W or (0 - W), 15) and 1);
   end CT_Nonzero;

   function Valid_K_P256 (V : Bytes_32) return Byte is
      Z      : Byte := 0;
      Borrow : Unsigned_16 := 0;
      T      : Unsigned_16;
   begin
      for I in Index_32 loop
         Z := Z or V (I);
      end loop;

      for I in reverse Index_32 loop
         T := Unsigned_16 (V (I))
              - Unsigned_16 (N_P256 (I))
              - Borrow;
         Borrow := Shift_Right (T, 8) and 1;
      end loop;

      return CT_Nonzero (Z) and Byte (Borrow);
   end Valid_K_P256;

   procedure Reduce_P384 (V : in out Bytes_48) is
      Diff   : Bytes_48;     --  every byte written by the loop below
      Borrow : Unsigned_16 := 0;
      Mask   : Byte;
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
   end Reduce_P384;

   function Valid_K_P384 (V : Bytes_48) return Byte is
      Z      : Byte := 0;
      Borrow : Unsigned_16 := 0;
      T      : Unsigned_16;
   begin
      for I in Index_48 loop
         Z := Z or V (I);
      end loop;

      for I in reverse Index_48 loop
         T := Unsigned_16 (V (I))
              - Unsigned_16 (N_P384 (I))
              - Borrow;
         Borrow := Shift_Right (T, 8) and 1;
      end loop;

      return CT_Nonzero (Z) and Byte (Borrow);
   end Valid_K_P384;

   ----------------------------------------------------------------
   --  RFC 6979 §3.2 steps a-h, P-256 specialization.
   --  holen = qlen = 32 bytes ⇒ no inner T accumulation loop.
   ----------------------------------------------------------------
   procedure Derive_K_P256
     (D :     Bytes_32;
      H :     Bytes_32;
      K : out Bytes_32;
      OK : out Boolean)
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
      Retry_Buf : Byte_Seq (0 .. 32) := (others => 0);
      Tmp       : SPARKTLSCrypto.Hashing.SHA256.Digest;
      Candidate : Bytes_32;
      Have      : Byte := 0;
      Valid     : Byte;
      Take      : Byte;
      Mask      : Byte;
   begin
      K := (others => 0);

      --  bits2octets(H): for SHA-256 (256 bits = qlen), bits2int =
      --  H. Then mod N.
      Reduce_P256 (H_Octets);

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
      --  RFC 6979 normally retries until 1 <= k < q. That retry
      --  decision depends on secret-derived K, so run a fixed number
      --  of candidate draws and branchlessly keep the first valid one.
      for Attempt in 1 .. Max_Candidates loop
         SPARKTLSCrypto.MAC.HMAC_SHA_256
           (Output => Tmp, M => Byte_Seq (V), K => Byte_Seq (DRBG_Key));
         V := Bytes_32 (Tmp);
         Candidate := Bytes_32 (Tmp);

         Valid  := Valid_K_P256 (Candidate);
         Take   := Valid and (Have xor 1);
         Mask   := -Take;
         for I in Index_32 loop
            K (I) := (Candidate (I) and Mask) or (K (I) and not Mask);
         end loop;
         Have := Have or Valid;

         Retry_Buf (0 .. 31) := Byte_Seq (V);
         Retry_Buf (32)      := 16#00#;
         SPARKTLSCrypto.MAC.HMAC_SHA_256
           (Output => Tmp, M => Retry_Buf, K => Byte_Seq (DRBG_Key));
         DRBG_Key := Bytes_32 (Tmp);

         SPARKTLSCrypto.MAC.HMAC_SHA_256
           (Output => Tmp, M => Byte_Seq (V), K => Byte_Seq (DRBG_Key));
         V := Bytes_32 (Tmp);

         pragma Unreferenced (Attempt);
      end loop;

      OK := Have = 1;
   end Derive_K_P256;

   ----------------------------------------------------------------
   --  RFC 6979 §3.2 steps a-h, P-384 specialization.
   --  holen = qlen = 48 bytes ⇒ no inner T accumulation loop.
   ----------------------------------------------------------------
   procedure Derive_K_P384
     (D :     Bytes_48;
      H :     Bytes_48;
      K : out Bytes_48;
      OK : out Boolean)
   is
      V         : Bytes_48 := (others => 16#01#);
      DRBG_Key  : Bytes_48 := (others => 16#00#);
      H_Octets  : Bytes_48 := H;
      Buf       : Byte_Seq (0 .. 144) := (others => 0);
      Retry_Buf : Byte_Seq (0 .. 48) := (others => 0);
      Tmp       : SPARKNaCl.Hashing.SHA384.Digest;
      Candidate : Bytes_48;
      Have      : Byte := 0;
      Valid     : Byte;
      Take      : Byte;
      Mask      : Byte;
   begin
      K := (others => 0);

      Reduce_P384 (H_Octets);

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

      --  Step 8: single HMAC per candidate since holen = qlen = 48.
      --  Use fixed candidate draws and branchless first-valid
      --  selection for the same reason as P-256 above.
      for Attempt in 1 .. Max_Candidates loop
         SPARKTLSCrypto.HMAC384.HMAC_SHA_384
           (Output => Tmp, M => Byte_Seq (V), K => Byte_Seq (DRBG_Key));
         V := Bytes_48 (Tmp);
         Candidate := Bytes_48 (Tmp);

         Valid  := Valid_K_P384 (Candidate);
         Take   := Valid and (Have xor 1);
         Mask   := -Take;
         for I in Index_48 loop
            K (I) := (Candidate (I) and Mask) or (K (I) and not Mask);
         end loop;
         Have := Have or Valid;

         Retry_Buf (0 .. 47) := Byte_Seq (V);
         Retry_Buf (48)      := 16#00#;
         SPARKTLSCrypto.HMAC384.HMAC_SHA_384
           (Output => Tmp, M => Retry_Buf, K => Byte_Seq (DRBG_Key));
         DRBG_Key := Bytes_48 (Tmp);

         SPARKTLSCrypto.HMAC384.HMAC_SHA_384
           (Output => Tmp, M => Byte_Seq (V), K => Byte_Seq (DRBG_Key));
         V := Bytes_48 (Tmp);

         pragma Unreferenced (Attempt);
      end loop;

      OK := Have = 1;
   end Derive_K_P384;

end SPARKTLSCrypto.RFC6979;
