with Interfaces; use Interfaces;
with SPARKTLSCrypto.AES_Dispatch;
with SPARKTLSCrypto.AES_NI;
with SPARKTLSCrypto.AES_GCM_AVX512;
with SPARKTLSCrypto.GHASH_Dispatch;
with SPARKTLSCrypto.GHASH_NI;

package body SPARKTLSCrypto.AES_GCM with
   SPARK_Mode => On
is

   package HW_AES renames SPARKTLSCrypto.AES_Dispatch;

   ----------------------------------------------------------------------------
   --  GF(2^128) multiplication for GHASH (NIST SP 800-38D)
   --  Bit-by-bit method: 128 iterations.
   ----------------------------------------------------------------------------

   --  Inline-renamed: the dispatcher picks PCLMULQDQ when available,
   --  else the bit-by-bit reference. Same semantics as the prior local
   --  GF128_Mul implementation; ~50x faster on x86_64 with PCLMULQDQ.
   function GF128_Mul (X : Bytes_16; Y : Bytes_16) return Bytes_16
      renames SPARKTLSCrypto.GHASH_Dispatch.GF128_Mul;

   ----------------------------------------------------------------------------
   --  GHASH
   ----------------------------------------------------------------------------
   procedure XOR_Block (Dst : in out Bytes_16;
                        Src : in     Bytes_16) is
   begin
      for I in 0 .. 15 loop
         Dst (N32 (I)) := Dst (N32 (I)) xor Src (N32 (I));
      end loop;
   end XOR_Block;

   procedure GHASH
     (Tag   :    out Bytes_16;
      H     : in     Bytes_16;
      AAD   : in     Byte_Seq;
      C     : in     Byte_Seq)
   with Pre => AAD'First = 0 and AAD'Last < N32'Last and
               C'First = 0 and C'Last < N32'Last
   is
      Y     : Bytes_16 := (others => 0);
      Block : Bytes_16;
      Pos   : N32;
      Remaining : N32;
      AAD_Len : constant N32 := N32 (AAD'Length);
      C_Len   : constant N32 := N32 (C'Length);
   begin
      --  Process AAD in 16-byte blocks
      Pos := 0;
      while AAD_Len >= 16 and then Pos <= AAD_Len - 16 loop
         pragma Loop_Invariant (Pos <= AAD_Len - 16 and Pos mod 16 = 0);
         Block := Bytes_16 (AAD (Pos .. Pos + 15));
         XOR_Block (Y, Block);
         Y := GF128_Mul (Y, H);
         Pos := Pos + 16;
      end loop;

      --  Process final partial AAD block (zero-padded)
      Remaining := AAD_Len - Pos;
      if Remaining > 0 then
         Block := (others => 0);
         for I in N32 range 0 .. Remaining - 1 loop
            pragma Loop_Invariant (I < Remaining and Pos + I <= AAD'Last);
            Block (I) := AAD (Pos + I);
         end loop;
         XOR_Block (Y, Block);
         Y := GF128_Mul (Y, H);
      end if;

      --  Process ciphertext in 16-byte blocks
      Pos := 0;
      while C_Len >= 16 and then Pos <= C_Len - 16 loop
         pragma Loop_Invariant (Pos <= C_Len - 16 and Pos mod 16 = 0);
         Block := Bytes_16 (C (Pos .. Pos + 15));
         XOR_Block (Y, Block);
         Y := GF128_Mul (Y, H);
         Pos := Pos + 16;
      end loop;

      --  Process final partial ciphertext block (zero-padded)
      Remaining := C_Len - Pos;
      if Remaining > 0 then
         Block := (others => 0);
         for I in N32 range 0 .. Remaining - 1 loop
            pragma Loop_Invariant (I < Remaining and Pos + I <= C'Last);
            Block (I) := C (Pos + I);
         end loop;
         XOR_Block (Y, Block);
         Y := GF128_Mul (Y, H);
      end if;

      --  Final block: len(A) || len(C) in bits, as 64-bit big-endian
      Block := (others => 0);
      declare
         A_Bits : constant Unsigned_64 := Unsigned_64 (AAD_Len) * 8;
         C_Bits : constant Unsigned_64 := Unsigned_64 (C_Len) * 8;
      begin
         for I in 0 .. 7 loop
            Block (N32 (I)) :=
               Byte (Shift_Right (A_Bits, (7 - I) * 8) and 16#FF#);
            Block (N32 (8 + I)) :=
               Byte (Shift_Right (C_Bits, (7 - I) * 8) and 16#FF#);
         end loop;
      end;
      XOR_Block (Y, Block);
      Y := GF128_Mul (Y, H);

      Tag := Y;
   end GHASH;

   --  Increment the 32-bit counter in bytes 12..15 of a counter block
   procedure Increment_Counter (CB : in out Bytes_16) is
      Val : Unsigned_32;
   begin
      Val := Unsigned_32 (CB (12)) * 2**24 +
             Unsigned_32 (CB (13)) * 2**16 +
             Unsigned_32 (CB (14)) * 2**8 +
             Unsigned_32 (CB (15));
      Val := Val + 1;
      CB (12) := Byte (Shift_Right (Val, 24) and 16#FF#);
      CB (13) := Byte (Shift_Right (Val, 16) and 16#FF#);
      CB (14) := Byte (Shift_Right (Val, 8) and 16#FF#);
      CB (15) := Byte (Val and 16#FF#);
   end Increment_Counter;

   ----------------------------------------------------------------------------
   --  AES-CTR
   ----------------------------------------------------------------------------
   procedure AES_CTR_128
     (Output  :    out Byte_Seq;
      Input   : in     Byte_Seq;
      K       : in     AES.AES128_Round_Keys;
      ICB     : in     Bytes_16)
   with Pre => Output'First = 0 and Input'First = 0 and
               Output'Last = Input'Last and
               Input'Last < N32'Last
   is
      CB        : Bytes_16 := ICB;
      Keystream : Bytes_16;
      Pos       : N32 := 0;
      Remaining : N32;
      In_Len    : constant N32 := N32 (Input'Length);
   begin
      Output := (others => 0);

      while In_Len >= 16 and then Pos <= In_Len - 16 loop
         pragma Loop_Invariant (Pos <= In_Len - 16 and Pos mod 16 = 0);
         HW_AES.Cipher (Keystream, CB, K);
         for I in 0 .. 15 loop
            Output (Pos + N32 (I)) :=
               Input (Pos + N32 (I)) xor Keystream (N32 (I));
         end loop;
         Increment_Counter (CB);
         Pos := Pos + 16;
      end loop;

      Remaining := In_Len - Pos;
      if Remaining > 0 then
         HW_AES.Cipher (Keystream, CB, K);
         for I in N32 range 0 .. Remaining - 1 loop
            pragma Loop_Invariant (I < Remaining and Pos + I <= Input'Last);
            Output (Pos + I) := Input (Pos + I) xor Keystream (I);
         end loop;
      end if;
   end AES_CTR_128;

   procedure AES_CTR_256
     (Output  :    out Byte_Seq;
      Input   : in     Byte_Seq;
      K       : in     AES.AES256_Round_Keys;
      ICB     : in     Bytes_16)
   with Pre => Output'First = 0 and Input'First = 0 and
               Output'Last = Input'Last and
               Input'Last < N32'Last
   is
      CB        : Bytes_16 := ICB;
      Keystream : Bytes_16;
      Pos       : N32 := 0;
      Remaining : N32;
      In_Len    : constant N32 := N32 (Input'Length);
   begin
      Output := (others => 0);

      while In_Len >= 16 and then Pos <= In_Len - 16 loop
         pragma Loop_Invariant (Pos <= In_Len - 16 and Pos mod 16 = 0);
         HW_AES.Cipher (Keystream, CB, K);
         for I in 0 .. 15 loop
            Output (Pos + N32 (I)) :=
               Input (Pos + N32 (I)) xor Keystream (N32 (I));
         end loop;
         Increment_Counter (CB);
         Pos := Pos + 16;
      end loop;

      Remaining := In_Len - Pos;
      if Remaining > 0 then
         HW_AES.Cipher (Keystream, CB, K);
         for I in N32 range 0 .. Remaining - 1 loop
            pragma Loop_Invariant (I < Remaining and Pos + I <= Input'Last);
            Output (Pos + I) := Input (Pos + I) xor Keystream (I);
         end loop;
      end if;
   end AES_CTR_256;

   ----------------------------------------------------------------------------
   --  In-place AES-CTR: XOR Buf with the keystream in place. Works
   --  on any-First slice (so callers can pass `Output.Data (Pos ..
   --  Pos + Len - 1)` directly and skip the intermediate Ciphertext
   --  allocation / copy that the Output-version requires).
   --
   --  Both InPlace variants pre-byteswap the round keys ONCE up-front
   --  (one PSHUFB per round-key word, ~22 PSHUFBs total for AES-128
   --  / 30 for AES-256) and then use the Cipher_*_PreSw fast path in
   --  the loop, which avoids the per-block PSHUFB.  At 16 KB / 1024
   --  blocks, that's ~11K PSHUFBs saved for AES-128.
   ----------------------------------------------------------------------------
   procedure AES_CTR_128_InPlace
     (Buf : in out Byte_Seq;
      K   : in     AES.AES128_Round_Keys;
      ICB : in     Bytes_16)
   with Pre => Buf'Length > 0 and Buf'Last < N32'Last
   is
      use SPARKTLSCrypto.AES_NI;
      CB        : Bytes_16 := ICB;
      Keystream : Bytes_16;
      Pos       : N32 := 0;
      Remaining : N32;
      Buf_Len   : constant N32 := N32 (Buf'Length);
      Base      : constant N32 := Buf'First;
      Pre_RK    : Pre_Swapped_RKs_128         with Relaxed_Initialization;
      Have_HW   : constant Boolean := SPARKTLSCrypto.AES_NI.Has_AESNI;
      Ctr_Buf   : SPARKTLSCrypto.AES_NI.Bytes_64 := (others => 0);
   begin
      if Have_HW then
         Pre_Swap_RKs_128 (K, Pre_RK);

         --  4-way pipelined fast path: interleaved AESENC chains hit
         --  ~1 cycle/AESENC instead of stalling on the 4-cycle latency.
         --  XOR fused into the asm — no Ada-level 64-byte XOR loop.
         while Buf_Len >= 64 and then Pos <= Buf_Len - 64 loop
            pragma Loop_Invariant (Pos <= Buf_Len - 64 and Pos mod 16 = 0);
            for B in 0 .. 3 loop
               for I in 0 .. 15 loop
                  Ctr_Buf (N32 (B * 16 + I)) := CB (N32 (I));
               end loop;
               Increment_Counter (CB);
            end loop;
            Cipher_4x_128_PreSw_XOR
              (Buf (Base + Pos .. Base + Pos + 63), Ctr_Buf, Pre_RK);
            Pos := Pos + 64;
         end loop;
      end if;

      while Buf_Len >= 16 and then Pos <= Buf_Len - 16 loop
         pragma Loop_Invariant (Pos <= Buf_Len - 16 and Pos mod 16 = 0);
         if Have_HW then
            Cipher_128_PreSw (Keystream, CB, Pre_RK);
         else
            HW_AES.Cipher (Keystream, CB, K);
         end if;
         for I in 0 .. 15 loop
            Buf (Base + Pos + N32 (I)) :=
               Buf (Base + Pos + N32 (I)) xor Keystream (N32 (I));
         end loop;
         Increment_Counter (CB);
         Pos := Pos + 16;
      end loop;

      Remaining := Buf_Len - Pos;
      if Remaining > 0 then
         if Have_HW then
            Cipher_128_PreSw (Keystream, CB, Pre_RK);
         else
            HW_AES.Cipher (Keystream, CB, K);
         end if;
         for I in N32 range 0 .. Remaining - 1 loop
            pragma Loop_Invariant (I < Remaining and Base + Pos + I <= Buf'Last);
            Buf (Base + Pos + I) :=
               Buf (Base + Pos + I) xor Keystream (I);
         end loop;
      end if;
   end AES_CTR_128_InPlace;

   procedure AES_CTR_256_InPlace
     (Buf : in out Byte_Seq;
      K   : in     AES.AES256_Round_Keys;
      ICB : in     Bytes_16)
   with Pre => Buf'Length > 0 and Buf'Last < N32'Last
   is
      use SPARKTLSCrypto.AES_NI;
      CB        : Bytes_16 := ICB;
      Keystream : Bytes_16;
      Pos       : N32 := 0;
      Remaining : N32;
      Buf_Len   : constant N32 := N32 (Buf'Length);
      Base      : constant N32 := Buf'First;
      Pre_RK    : Pre_Swapped_RKs_256         with Relaxed_Initialization;
      Have_HW   : constant Boolean := SPARKTLSCrypto.AES_NI.Has_AESNI;
      Ctr_Buf   : SPARKTLSCrypto.AES_NI.Bytes_64 := (others => 0);
   begin
      if Have_HW then
         Pre_Swap_RKs_256 (K, Pre_RK);

         while Buf_Len >= 64 and then Pos <= Buf_Len - 64 loop
            pragma Loop_Invariant (Pos <= Buf_Len - 64 and Pos mod 16 = 0);
            for B in 0 .. 3 loop
               for I in 0 .. 15 loop
                  Ctr_Buf (N32 (B * 16 + I)) := CB (N32 (I));
               end loop;
               Increment_Counter (CB);
            end loop;
            Cipher_4x_256_PreSw_XOR
              (Buf (Base + Pos .. Base + Pos + 63), Ctr_Buf, Pre_RK);
            Pos := Pos + 64;
         end loop;
      end if;

      while Buf_Len >= 16 and then Pos <= Buf_Len - 16 loop
         pragma Loop_Invariant (Pos <= Buf_Len - 16 and Pos mod 16 = 0);
         if Have_HW then
            Cipher_256_PreSw (Keystream, CB, Pre_RK);
         else
            HW_AES.Cipher (Keystream, CB, K);
         end if;
         for I in 0 .. 15 loop
            Buf (Base + Pos + N32 (I)) :=
               Buf (Base + Pos + N32 (I)) xor Keystream (N32 (I));
         end loop;
         Increment_Counter (CB);
         Pos := Pos + 16;
      end loop;

      Remaining := Buf_Len - Pos;
      if Remaining > 0 then
         if Have_HW then
            Cipher_256_PreSw (Keystream, CB, Pre_RK);
         else
            HW_AES.Cipher (Keystream, CB, K);
         end if;
         for I in N32 range 0 .. Remaining - 1 loop
            pragma Loop_Invariant (I < Remaining and Base + Pos + I <= Buf'Last);
            Buf (Base + Pos + I) :=
               Buf (Base + Pos + I) xor Keystream (I);
         end loop;
      end if;
   end AES_CTR_256_InPlace;

   --  Slice-friendly GHASH that processes a single contiguous run of
   --  ciphertext (no separate AAD) and folds it into an in/out
   --  accumulator.  Used by the in-place encrypt path below.
   procedure GHASH_Bytes
     (S   : in out Bytes_16;
      H   : in     Bytes_16;
      Buf : in     Byte_Seq)
   with Pre => Buf'Length > 0 and Buf'Last < N32'Last
   is
      --  Block is fully filled by the 16-iteration for-loop OR
      --  zero-init explicitly in the partial-block tail. Relaxed
      --  initialization keeps SPARK happy without a redundant fill.
      Block     : Bytes_16 with Relaxed_Initialization;
      Pos       : N32 := 0;
      Remaining : N32;
      Buf_Len   : constant N32 := N32 (Buf'Length);
      Base      : constant N32 := Buf'First;

      procedure XOR_Block_Local (Dst : in out Bytes_16;
                                 Src : in     Bytes_16) is
      begin
         for I in 0 .. 15 loop
            Dst (N32 (I)) := Dst (N32 (I)) xor Src (N32 (I));
         end loop;
      end XOR_Block_Local;
   begin
      --  Aggregated 4-block fast path: one reduction per 4 blocks
      --  using pre-computed H, H^2, H^3, H^4. Costs 3 single-block
      --  GF128_Muls upfront (Compute_H_Powers); break-even around
      --  4 blocks, big win on TLS records (≥ 64 blocks).
      if SPARKTLSCrypto.GHASH_NI.Has_PCLMULQDQ and then Buf_Len >= 64 then
         declare
            HP : SPARKTLSCrypto.GHASH_NI.Pre_H_Powers;
         begin
            SPARKTLSCrypto.GHASH_NI.Compute_H_Powers (H, HP);
            while Buf_Len >= 64 and then Pos <= Buf_Len - 64 loop
               pragma Loop_Invariant
                 (Pos <= Buf_Len - 64 and Pos mod 16 = 0);
               SPARKTLSCrypto.GHASH_NI.GHASH_4_Blocks
                 (S, Buf (Base + Pos .. Base + Pos + 63), HP);
               Pos := Pos + 64;
            end loop;
         end;
      end if;

      while Buf_Len >= 16 and then Pos <= Buf_Len - 16 loop
         pragma Loop_Invariant (Pos <= Buf_Len - 16 and Pos mod 16 = 0);
         for I in 0 .. 15 loop
            Block (N32 (I)) := Buf (Base + Pos + N32 (I));
         end loop;
         XOR_Block_Local (S, Block);
         S := GF128_Mul (S, H);
         Pos := Pos + 16;
      end loop;

      Remaining := Buf_Len - Pos;
      if Remaining > 0 then
         Block := (others => 0);
         for I in N32 range 0 .. Remaining - 1 loop
            pragma Loop_Invariant
              (I < Remaining
               and Base + Pos + I <= Buf'Last
               and Block'Initialized);
            Block (I) := Buf (Base + Pos + I);
         end loop;
         XOR_Block_Local (S, Block);
         S := GF128_Mul (S, H);
      end if;
   end GHASH_Bytes;

   procedure GHASH_Empty_Ciphertext
     (Tag :    out Bytes_16;
      H   : in     Bytes_16;
      AAD : in     Byte_Seq)
   with Pre => AAD'First = 0 and AAD'Length > 0 and AAD'Last < N32'Last
   is
      Y       : Bytes_16 := (others => 0);
      Block   : Bytes_16;
      AAD_Len : constant N32 := N32 (AAD'Length);
      A_Bits  : constant Unsigned_64 := Unsigned_64 (AAD_Len) * 8;
   begin
      GHASH_Bytes (Y, H, AAD);

      Block := (others => 0);
      for I in 0 .. 7 loop
         Block (N32 (I)) :=
            Byte (Shift_Right (A_Bits, (7 - I) * 8) and 16#FF#);
      end loop;

      XOR_Block (Y, Block);
      Y := GF128_Mul (Y, H);

      Tag := Y;
   end GHASH_Empty_Ciphertext;

   ----------------------------------------------------------------------------
   --  GCM Encrypt / Decrypt (AES-128)
   ----------------------------------------------------------------------------
   procedure Encrypt
     (C       :    out Byte_Seq;
      Tag     :    out Bytes_16;
      M       : in     Byte_Seq;
      N       : in     Bytes_12;
      K       : in     AES.AES128_Key;
      AAD     : in     Byte_Seq)
   is
      RK  : constant AES.AES128_Round_Keys := AES.Key_Expansion (K);
      H   : Bytes_16;
      J0  : Bytes_16;
      S   : Bytes_16;
      EJ0 : Bytes_16;
   begin
      HW_AES.Cipher (H, Bytes_16'(others => 0), RK);

      J0 := (others => 0);
      J0 (0 .. 11) := N;
      J0 (15) := 16#01#;

      HW_AES.Cipher (EJ0, J0, RK);

      Increment_Counter (J0);
      AES_CTR_128 (C, M, RK, J0);

      GHASH (S, H, AAD, C);

      Tag := S;
      XOR_Block (Tag, EJ0);
   end Encrypt;

   procedure Encrypt_InPlace
     (Buf : in out Byte_Seq;
      Tag :    out Bytes_16;
      N   : in     Bytes_12;
      K   : in     AES.AES128_Key;
      AAD : in     Byte_Seq)
   is
      RK  : constant AES.AES128_Round_Keys := AES.Key_Expansion (K);
      H   : Bytes_16;
      J0  : Bytes_16;
      S   : Bytes_16 := (others => 0);
      EJ0 : Bytes_16;
      Buf_Bits : constant Unsigned_64 := Unsigned_64 (Buf'Length) * 8;
      AAD_Bits : constant Unsigned_64 := Unsigned_64 (AAD'Length) * 8;
      Lengths  : Bytes_16 := (others => 0);
   begin
      --  GHASH key + initial counter, same as Encrypt above.
      HW_AES.Cipher (H, Bytes_16'(others => 0), RK);
      J0 := (others => 0);
      J0 (0 .. 11) := N;
      J0 (15) := 16#01#;
      HW_AES.Cipher (EJ0, J0, RK);

      --  Encrypt Buf in place: counter starts at J_0 + 1.
      Increment_Counter (J0);

      --  GHASH AAD first (before bulk so the fused stripe path can
      --  continue accumulating S). Skip the call on empty AAD —
      --  GHASH_Bytes requires Buf'Length > 0 to avoid SPARK's
      --  degenerate-empty-range edge case on Buf'First.
      if AAD'Length > 0 then
         GHASH_Bytes (S, H, AAD);
      end if;

      --  Fully fused AES + GHASH bulk path: one asm call per 4-block
      --  stripe, ciphertext stays in xmm registers between encrypt
      --  and authenticate. Falls back to separate passes if the CPU
      --  lacks AES-NI or PCLMULQDQ, or the buffer is too short.
      declare
         use SPARKTLSCrypto.AES_NI;
         Buf_Len : constant N32 := N32 (Buf'Length);
         Base    : constant N32 := Buf'First;
         Have_HW : constant Boolean :=
            SPARKTLSCrypto.AES_NI.Has_AESNI
            and then SPARKTLSCrypto.GHASH_NI.Has_PCLMULQDQ;
      begin
         if Have_HW
            and then SPARKTLSCrypto.AES_GCM_AVX512.Has_AVX512_AES_GCM
            and then Buf_Len >= 256
         then
            --  AVX-512 / VAES + VPCLMULQDQ-zmm tier:
            --    16-block VAES encrypt (4 zmm chains)
            --  + 16-block VPCLMULQDQ-zmm aggregated GHASH
            --  per 256-byte stripe.
            declare
               Pre_RK   : Pre_Swapped_RKs_128;
               HP_16    : SPARKTLSCrypto.AES_GCM_AVX512.Pre_H_Powers_16;
               CB       : Bytes_16 := J0;
               Ctr_256  : SPARKTLSCrypto.AES_GCM_AVX512.Bytes_256;
               Pos      : N32 := 0;
            begin
               Pre_Swap_RKs_128 (RK, Pre_RK);
               SPARKTLSCrypto.AES_GCM_AVX512.Compute_H_Powers_16 (H, HP_16);

               while Buf_Len >= 256 and then Pos <= Buf_Len - 256 loop
                  pragma Loop_Invariant
                    (Pos <= Buf_Len - 256 and Pos mod 16 = 0);
                  SPARKTLSCrypto.AES_GCM_AVX512.Build_Ctr_Block_16
                    (CB, Ctr_256);
                  SPARKTLSCrypto.AES_GCM_AVX512.Cipher_16x_128_VAES_XOR
                    (Buf (Base + Pos .. Base + Pos + 255),
                     Ctr_256, Pre_RK);
                  SPARKTLSCrypto.AES_GCM_AVX512.GHASH_16_Blocks
                    (S, Buf (Base + Pos .. Base + Pos + 255), HP_16);
                  Pos := Pos + 256;
               end loop;

               --  Tail: < 256 bytes. CB holds the next free counter.
               --  Drop down to the 4-block fused-stripe path for the
               --  remaining 0-3 stripes + per-block tail.
               if Pos < Buf_Len then
                  AES_CTR_128_InPlace
                    (Buf (Base + Pos .. Buf'Last), RK, CB);
                  GHASH_Bytes
                    (S, H, Buf (Base + Pos .. Buf'Last));
               end if;
            end;
         elsif Have_HW and then Buf_Len >= 128 then
            --  2-stripe pipelined fast path: encrypt stripe k while
            --  GHASHing stripe k-1's ciphertext in the same asm so AES
            --  (port 0) and PCLMULQDQ (port 5) overlap. First stripe is
            --  encrypt-only; last stripe is GHASH-only.
            declare
               Pre_RK  : Pre_Swapped_RKs_128;
               HP      : SPARKTLSCrypto.GHASH_NI.Pre_H_Powers;
               CB      : Bytes_16 := J0;
               Ctr_Buf : SPARKTLSCrypto.AES_NI.Bytes_64;
               Pos     : N32 := 0;
            begin
               Pre_Swap_RKs_128 (RK, Pre_RK);
               SPARKTLSCrypto.GHASH_NI.Compute_H_Powers (H, HP);

               --  Stripe 0: encrypt only (no previous stripe to GHASH).
               Build_Ctr_Block_4 (CB, Ctr_Buf);
               Cipher_4x_128_PreSw_XOR
                 (Buf (Base + Pos .. Base + Pos + 63), Ctr_Buf, Pre_RK);
               Pos := Pos + 64;

               --  Stripes 1..N-1: pipelined encrypt + GHASH-of-prev.
               while Buf_Len >= 64 and then Pos <= Buf_Len - 64 loop
                  pragma Loop_Invariant
                    (Pos <= Buf_Len - 64 and Pos mod 16 = 0
                     and Pos >= 64);
                  Build_Ctr_Block_4 (CB, Ctr_Buf);
                  --  Pass a 128-byte window: bytes 0..63 are the
                  --  previous-stripe ciphertext (GHASH), bytes 64..127
                  --  are the new plaintext encrypted in place.
                  Encrypt_GHASH_Pipelined_4_128
                    (Buf      => Buf (Base + Pos - 64 .. Base + Pos + 63),
                     S        => S,
                     Counter  => Ctr_Buf,
                     Pre_RK   => Pre_RK,
                     H_Powers => HP);
                  Pos := Pos + 64;
               end loop;

               --  Tail GHASH: the last full stripe was encrypted but
               --  not yet GHASHed by the pipelined loop.
               SPARKTLSCrypto.GHASH_NI.GHASH_4_Blocks
                 (S, Buf (Base + Pos - 64 .. Base + Pos - 1), HP);

               --  < 64 bytes left: per-block CTR encrypt + GHASH.
               if Pos < Buf_Len then
                  AES_CTR_128_InPlace
                    (Buf (Base + Pos .. Buf'Last), RK, CB);
                  GHASH_Bytes
                    (S, H, Buf (Base + Pos .. Buf'Last));
               end if;
            end;
         elsif Have_HW and then Buf_Len >= 64 then
            --  1 stripe only: use the non-pipelined fused path.
            declare
               Pre_RK  : Pre_Swapped_RKs_128;
               HP      : SPARKTLSCrypto.GHASH_NI.Pre_H_Powers;
               CB      : Bytes_16 := J0;
               Ctr_Buf : SPARKTLSCrypto.AES_NI.Bytes_64;
               Pos     : N32 := 0;
            begin
               Pre_Swap_RKs_128 (RK, Pre_RK);
               SPARKTLSCrypto.GHASH_NI.Compute_H_Powers (H, HP);
               while Buf_Len >= 64 and then Pos <= Buf_Len - 64 loop
                  pragma Loop_Invariant
                    (Pos <= Buf_Len - 64 and Pos mod 16 = 0);
                  Build_Ctr_Block_4 (CB, Ctr_Buf);
                  Encrypt_GCM_Stripe_4_128
                    (Buf (Base + Pos .. Base + Pos + 63),
                     S, Ctr_Buf, Pre_RK, HP);
                  Pos := Pos + 64;
               end loop;
               if Pos < Buf_Len then
                  AES_CTR_128_InPlace
                    (Buf (Base + Pos .. Buf'Last), RK, CB);
                  GHASH_Bytes
                    (S, H, Buf (Base + Pos .. Buf'Last));
               end if;
            end;
         else
            --  Non-fused fallback: encrypt then GHASH separately.
            --  Guard empty Buf — the helpers require Buf'Length > 0,
            --  but a zero-length plaintext is a valid GCM input
            --  (degenerates to GMAC-of-AAD).
            if Buf_Len > 0 then
               AES_CTR_128_InPlace (Buf, RK, J0);
               GHASH_Bytes (S, H, Buf);
            end if;
         end if;
      end;

      for I in 0 .. 7 loop
         Lengths (N32 (I)) :=
            Byte (Shift_Right (AAD_Bits, (7 - I) * 8) and 16#FF#);
         Lengths (N32 (8 + I)) :=
            Byte (Shift_Right (Buf_Bits, (7 - I) * 8) and 16#FF#);
      end loop;
      XOR_Block (S, Lengths);
      S := GF128_Mul (S, H);

      Tag := S;
      XOR_Block (Tag, EJ0);
   end Encrypt_InPlace;

   procedure Decrypt
     (M       :    out Byte_Seq;
      Status  :    out Boolean;
      Tag     : in     Bytes_16;
      C       : in     Byte_Seq;
      N       : in     Bytes_12;
      K       : in     AES.AES128_Key;
      AAD     : in     Byte_Seq)
   is
      RK  : constant AES.AES128_Round_Keys := AES.Key_Expansion (K);
      H   : Bytes_16;
      J0  : Bytes_16;
      S   : Bytes_16;
      EJ0 : Bytes_16;
      Computed_Tag : Bytes_16;
   begin
      M := (others => 0);
      Status := False;

      HW_AES.Cipher (H, Bytes_16'(others => 0), RK);

      J0 := (others => 0);
      J0 (0 .. 11) := N;
      J0 (15) := 16#01#;

      HW_AES.Cipher (EJ0, J0, RK);

      GHASH (S, H, AAD, C);

      Computed_Tag := S;
      XOR_Block (Computed_Tag, EJ0);

      --  Branch-free tag check + decrypt. Always run the CTR
      --  decryption; mask M to zero if the tag mismatches. This
      --  removes the "skip decrypt on bad tag" branch that ctgrind
      --  flagged — the timing leak it produced was strictly equal
      --  to the public Status bit, but branch-free is the audit-
      --  friendly version (defense-in-depth against future
      --  refactors that might stop exposing Status, and against the
      --  Lucky-13 class of bug that exists because "this branch is
      --  fine" arguments are fragile).
      Increment_Counter (J0);
      AES_CTR_128 (M, C, RK, J0);
      declare
         OK_Mask : constant Byte :=
           (if Equal (Byte_Seq (Computed_Tag), Byte_Seq (Tag))
              then 16#FF# else 16#00#);
      begin
         for I in M'Range loop
            M (I) := M (I) and OK_Mask;
         end loop;
         Status := OK_Mask = 16#FF#;
      end;
   end Decrypt;

   procedure Verify_Empty_Ciphertext
     (Status  :    out Boolean;
      Tag     : in     Bytes_16;
      N       : in     Bytes_12;
      K       : in     AES.AES128_Key;
      AAD     : in     Byte_Seq)
   is
      RK  : constant AES.AES128_Round_Keys := AES.Key_Expansion (K);
      H   : Bytes_16;
      J0  : Bytes_16;
      S   : Bytes_16;
      EJ0 : Bytes_16;
      Computed_Tag : Bytes_16;
   begin
      HW_AES.Cipher (H, Bytes_16'(others => 0), RK);

      J0 := (others => 0);
      J0 (0 .. 11) := N;
      J0 (15) := 16#01#;

      HW_AES.Cipher (EJ0, J0, RK);

      GHASH_Empty_Ciphertext (S, H, AAD);
      Computed_Tag := S;
      XOR_Block (Computed_Tag, EJ0);

      Status := Equal (Byte_Seq (Computed_Tag), Byte_Seq (Tag));
   end Verify_Empty_Ciphertext;

   ----------------------------------------------------------------------------
   --  GCM Encrypt / Decrypt (AES-256)
   ----------------------------------------------------------------------------

   procedure Encrypt_256
     (C       :    out Byte_Seq;
      Tag     :    out Bytes_16;
      M       : in     Byte_Seq;
      N       : in     Bytes_12;
      K       : in     AES.AES256_Key;
      AAD     : in     Byte_Seq)
   is
      RK  : constant AES.AES256_Round_Keys := AES.Key_Expansion (K);
      H   : Bytes_16;
      J0  : Bytes_16;
      S   : Bytes_16;
      EJ0 : Bytes_16;
   begin
      HW_AES.Cipher (H, Bytes_16'(others => 0), RK);

      J0 := (others => 0);
      J0 (0 .. 11) := N;
      J0 (15) := 16#01#;

      HW_AES.Cipher (EJ0, J0, RK);

      Increment_Counter (J0);
      AES_CTR_256 (C, M, RK, J0);

      GHASH (S, H, AAD, C);

      Tag := S;
      XOR_Block (Tag, EJ0);
   end Encrypt_256;

   procedure Encrypt_InPlace_256
     (Buf : in out Byte_Seq;
      Tag :    out Bytes_16;
      N   : in     Bytes_12;
      K   : in     AES.AES256_Key;
      AAD : in     Byte_Seq)
   is
      RK  : constant AES.AES256_Round_Keys := AES.Key_Expansion (K);
      H   : Bytes_16;
      J0  : Bytes_16;
      S   : Bytes_16 := (others => 0);
      EJ0 : Bytes_16;
      Buf_Bits : constant Unsigned_64 := Unsigned_64 (Buf'Length) * 8;
      AAD_Bits : constant Unsigned_64 := Unsigned_64 (AAD'Length) * 8;
      Lengths  : Bytes_16 := (others => 0);
   begin
      HW_AES.Cipher (H, Bytes_16'(others => 0), RK);
      J0 := (others => 0);
      J0 (0 .. 11) := N;
      J0 (15) := 16#01#;
      HW_AES.Cipher (EJ0, J0, RK);

      Increment_Counter (J0);
      if AAD'Length > 0 then
         GHASH_Bytes (S, H, AAD);
      end if;

      declare
         use SPARKTLSCrypto.AES_NI;
         Buf_Len : constant N32 := N32 (Buf'Length);
         Base    : constant N32 := Buf'First;
         Have_HW : constant Boolean :=
            SPARKTLSCrypto.AES_NI.Has_AESNI
            and then SPARKTLSCrypto.GHASH_NI.Has_PCLMULQDQ;
      begin
         if Have_HW
            and then SPARKTLSCrypto.AES_GCM_AVX512.Has_AVX512_AES_GCM
            and then Buf_Len >= 256
         then
            --  AVX-512 VAES + VPCLMULQDQ-zmm tier (AES-256 variant).
            declare
               Pre_RK  : Pre_Swapped_RKs_256;
               HP_16   : SPARKTLSCrypto.AES_GCM_AVX512.Pre_H_Powers_16;
               CB      : Bytes_16 := J0;
               Ctr_256 : SPARKTLSCrypto.AES_GCM_AVX512.Bytes_256;
               Pos     : N32 := 0;
            begin
               Pre_Swap_RKs_256 (RK, Pre_RK);
               SPARKTLSCrypto.AES_GCM_AVX512.Compute_H_Powers_16 (H, HP_16);

               while Buf_Len >= 256 and then Pos <= Buf_Len - 256 loop
                  pragma Loop_Invariant
                    (Pos <= Buf_Len - 256 and Pos mod 16 = 0);
                  SPARKTLSCrypto.AES_GCM_AVX512.Build_Ctr_Block_16
                    (CB, Ctr_256);
                  SPARKTLSCrypto.AES_GCM_AVX512.Cipher_16x_256_VAES_XOR
                    (Buf (Base + Pos .. Base + Pos + 255),
                     Ctr_256, Pre_RK);
                  SPARKTLSCrypto.AES_GCM_AVX512.GHASH_16_Blocks
                    (S, Buf (Base + Pos .. Base + Pos + 255), HP_16);
                  Pos := Pos + 256;
               end loop;

               if Pos < Buf_Len then
                  AES_CTR_256_InPlace
                    (Buf (Base + Pos .. Buf'Last), RK, CB);
                  GHASH_Bytes
                    (S, H, Buf (Base + Pos .. Buf'Last));
               end if;
            end;
         elsif Have_HW and then Buf_Len >= 128 then
            declare
               Pre_RK  : Pre_Swapped_RKs_256;
               HP      : SPARKTLSCrypto.GHASH_NI.Pre_H_Powers;
               CB      : Bytes_16 := J0;
               Ctr_Buf : SPARKTLSCrypto.AES_NI.Bytes_64;
               Pos     : N32 := 0;
            begin
               Pre_Swap_RKs_256 (RK, Pre_RK);
               SPARKTLSCrypto.GHASH_NI.Compute_H_Powers (H, HP);

               --  Stripe 0: encrypt only.
               Build_Ctr_Block_4 (CB, Ctr_Buf);
               Cipher_4x_256_PreSw_XOR
                 (Buf (Base + Pos .. Base + Pos + 63), Ctr_Buf, Pre_RK);
               Pos := Pos + 64;

               --  Stripes 1..N-1: pipelined.
               while Buf_Len >= 64 and then Pos <= Buf_Len - 64 loop
                  pragma Loop_Invariant
                    (Pos <= Buf_Len - 64 and Pos mod 16 = 0
                     and Pos >= 64);
                  Build_Ctr_Block_4 (CB, Ctr_Buf);
                  Encrypt_GHASH_Pipelined_4_256
                    (Buf      => Buf (Base + Pos - 64 .. Base + Pos + 63),
                     S        => S,
                     Counter  => Ctr_Buf,
                     Pre_RK   => Pre_RK,
                     H_Powers => HP);
                  Pos := Pos + 64;
               end loop;

               --  Tail GHASH for the last stripe.
               SPARKTLSCrypto.GHASH_NI.GHASH_4_Blocks
                 (S, Buf (Base + Pos - 64 .. Base + Pos - 1), HP);

               if Pos < Buf_Len then
                  AES_CTR_256_InPlace
                    (Buf (Base + Pos .. Buf'Last), RK, CB);
                  GHASH_Bytes
                    (S, H, Buf (Base + Pos .. Buf'Last));
               end if;
            end;
         elsif Have_HW and then Buf_Len >= 64 then
            declare
               Pre_RK  : Pre_Swapped_RKs_256;
               HP      : SPARKTLSCrypto.GHASH_NI.Pre_H_Powers;
               CB      : Bytes_16 := J0;
               Ctr_Buf : SPARKTLSCrypto.AES_NI.Bytes_64;
               Pos     : N32 := 0;
            begin
               Pre_Swap_RKs_256 (RK, Pre_RK);
               SPARKTLSCrypto.GHASH_NI.Compute_H_Powers (H, HP);
               while Buf_Len >= 64 and then Pos <= Buf_Len - 64 loop
                  pragma Loop_Invariant
                    (Pos <= Buf_Len - 64 and Pos mod 16 = 0);
                  Build_Ctr_Block_4 (CB, Ctr_Buf);
                  Encrypt_GCM_Stripe_4_256
                    (Buf (Base + Pos .. Base + Pos + 63),
                     S, Ctr_Buf, Pre_RK, HP);
                  Pos := Pos + 64;
               end loop;
               if Pos < Buf_Len then
                  AES_CTR_256_InPlace
                    (Buf (Base + Pos .. Buf'Last), RK, CB);
                  GHASH_Bytes
                    (S, H, Buf (Base + Pos .. Buf'Last));
               end if;
            end;
         else
            if Buf_Len > 0 then
               AES_CTR_256_InPlace (Buf, RK, J0);
               GHASH_Bytes (S, H, Buf);
            end if;
         end if;
      end;

      for I in 0 .. 7 loop
         Lengths (N32 (I)) :=
            Byte (Shift_Right (AAD_Bits, (7 - I) * 8) and 16#FF#);
         Lengths (N32 (8 + I)) :=
            Byte (Shift_Right (Buf_Bits, (7 - I) * 8) and 16#FF#);
      end loop;
      XOR_Block (S, Lengths);
      S := GF128_Mul (S, H);

      Tag := S;
      XOR_Block (Tag, EJ0);
   end Encrypt_InPlace_256;

   procedure Decrypt_256
     (M       :    out Byte_Seq;
      Status  :    out Boolean;
      Tag     : in     Bytes_16;
      C       : in     Byte_Seq;
      N       : in     Bytes_12;
      K       : in     AES.AES256_Key;
      AAD     : in     Byte_Seq)
   is
      RK  : constant AES.AES256_Round_Keys := AES.Key_Expansion (K);
      H   : Bytes_16;
      J0  : Bytes_16;
      S   : Bytes_16;
      EJ0 : Bytes_16;
      Computed_Tag : Bytes_16;
   begin
      M := (others => 0);
      Status := False;

      HW_AES.Cipher (H, Bytes_16'(others => 0), RK);

      J0 := (others => 0);
      J0 (0 .. 11) := N;
      J0 (15) := 16#01#;

      HW_AES.Cipher (EJ0, J0, RK);

      GHASH (S, H, AAD, C);

      Computed_Tag := S;
      XOR_Block (Computed_Tag, EJ0);

      --  Branch-free tag check + decrypt. See Decrypt (AES-128) for
      --  the full rationale.
      Increment_Counter (J0);
      AES_CTR_256 (M, C, RK, J0);
      declare
         OK_Mask : constant Byte :=
           (if Equal (Byte_Seq (Computed_Tag), Byte_Seq (Tag))
              then 16#FF# else 16#00#);
      begin
         for I in M'Range loop
            M (I) := M (I) and OK_Mask;
         end loop;
         Status := OK_Mask = 16#FF#;
      end;
   end Decrypt_256;

   procedure Verify_Empty_Ciphertext_256
     (Status  :    out Boolean;
      Tag     : in     Bytes_16;
      N       : in     Bytes_12;
      K       : in     AES.AES256_Key;
      AAD     : in     Byte_Seq)
   is
      RK  : constant AES.AES256_Round_Keys := AES.Key_Expansion (K);
      H   : Bytes_16;
      J0  : Bytes_16;
      S   : Bytes_16;
      EJ0 : Bytes_16;
      Computed_Tag : Bytes_16;
   begin
      HW_AES.Cipher (H, Bytes_16'(others => 0), RK);

      J0 := (others => 0);
      J0 (0 .. 11) := N;
      J0 (15) := 16#01#;

      HW_AES.Cipher (EJ0, J0, RK);

      GHASH_Empty_Ciphertext (S, H, AAD);
      Computed_Tag := S;
      XOR_Block (Computed_Tag, EJ0);

      Status := Equal (Byte_Seq (Computed_Tag), Byte_Seq (Tag));
   end Verify_Empty_Ciphertext_256;

end SPARKTLSCrypto.AES_GCM;
