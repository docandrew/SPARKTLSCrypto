with Interfaces; use Interfaces;
with SPARKTLSCrypto.AES_Dispatch;
with SPARKTLSCrypto.AES_NI;
with SPARKTLSCrypto.AES_GCM_AVX512;
with SPARKTLSCrypto.AES_GCM_AVX2;
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


   --  H^32 .. H^1, each byte-reversed, descending, 16 bytes apiece: the
   --  table the VAES stripe kernels read (AES_GCM_AVX512.Pre_H_Powers_32;
   --  its last 256 bytes are the sixteen-power Pre_H_Powers_16 table).
   --  The loop runs a fixed 32 times, one multiply each; the last
   --  product is unused.
   procedure Compute_H_Powers_32 (H : in Bytes_16; Powers : out Byte_Seq)
   with Pre => Powers'First = 0 and Powers'Last = 511
   is
      Power : Bytes_16 := H;
   begin
      Powers := (others => 0);
      for K in reverse N32 range 0 .. 31 loop
         for I in N32 range 0 .. 15 loop
            Powers (16 * K + I) := Power (15 - I);
         end loop;
         Power := GF128_Mul (Power, H);
      end loop;
      pragma Warnings (GNATprove, Off, "statement has no effect");
      pragma Warnings (GNATprove, Off, "*is set by*");
      SPARKNaCl.Sanitize (Byte_Seq (Power));
      pragma Warnings (GNATprove, On, "*is set by*");
      pragma Warnings (GNATprove, On, "statement has no effect");
   end Compute_H_Powers_32;

   procedure Clear (Context : out Prepared_Key) is
   begin
      SPARKNaCl.Sanitize (Byte_Seq (Context.Raw_Key));
      SPARKNaCl.Sanitize (Context.Rounds);
      SPARKNaCl.Sanitize (Byte_Seq (Context.H));
      SPARKNaCl.Sanitize (Context.Powers_4);
      SPARKNaCl.Sanitize (Context.Powers_32);
      Context.Ready := False;
      Context.Is_256 := False;
      Context.Hardware := False;
   end Clear;

   procedure Prepare_128
     (Context : out Prepared_Key; K : in AES.AES128_Key)
   is
   begin
      Clear (Context);
      Context.Raw_Key (0 .. 15) := AES.Serialize (K);
      Context.Hardware := AES_NI.Has_AESNI and GHASH_NI.Has_PCLMULQDQ;
      if Context.Hardware then
         declare
            RK : AES.AES128_Round_Keys := AES.Key_Expansion (K);
         begin
            AES_NI.Pre_Swap_RKs_128 (RK, Context.Rounds (0 .. 175));
            AES_NI.Cipher_128_PreSw
              (Context.H, Bytes_16'(others => 0), Context.Rounds (0 .. 175));
            AES.Sanitize (RK);
         end;
         GHASH_NI.Compute_H_Powers (Context.H, Context.Powers_4);
         if AES_GCM_AVX512.Has_AVX512_AES_GCM
           or AES_GCM_AVX2.Has_VAES_AVX2
         then
            Compute_H_Powers_32 (Context.H, Context.Powers_32);
         end if;
      end if;
      Context.Ready := True;
   end Prepare_128;

   procedure Prepare_256
     (Context : out Prepared_Key; K : in AES.AES256_Key)
   is
   begin
      Clear (Context);
      Context.Raw_Key := AES.Serialize (K);
      Context.Is_256 := True;
      Context.Hardware := AES_NI.Has_AESNI and GHASH_NI.Has_PCLMULQDQ;
      if Context.Hardware then
         declare
            RK : AES.AES256_Round_Keys := AES.Key_Expansion (K);
         begin
            AES_NI.Pre_Swap_RKs_256 (RK, Context.Rounds);
            AES_NI.Cipher_256_PreSw
              (Context.H, Bytes_16'(others => 0), Context.Rounds);
            AES.Sanitize (RK);
         end;
         GHASH_NI.Compute_H_Powers (Context.H, Context.Powers_4);
         if AES_GCM_AVX512.Has_AVX512_AES_GCM
           or AES_GCM_AVX2.Has_VAES_AVX2
         then
            Compute_H_Powers_32 (Context.H, Context.Powers_32);
         end if;
      end if;
      Context.Ready := True;
   end Prepare_256;

   procedure Prepared_Cipher
     (Block : out Bytes_16; Input : Bytes_16; Context : Prepared_Key)
   with Pre => Context.Ready and Context.Hardware
   is
   begin
      if Context.Is_256 then
         AES_NI.Cipher_256_PreSw (Block, Input, Context.Rounds);
      else
         AES_NI.Cipher_128_PreSw (Block, Input, Context.Rounds (0 .. 175));
      end if;
   end Prepared_Cipher;

   procedure Prepared_GHASH
     (S : in out Bytes_16; Context : Prepared_Key; Buf : Byte_Seq)
   with Pre => Context.Ready and Context.Hardware and Buf'Last < N32'Last
   is
      Pos : N32 := 0;
      Block : Bytes_16;
      Count : N32;
      Len : constant N32 := N32 (Buf'Length);
   begin
      while Len >= 64 and then Pos <= Len - 64 loop
         pragma Loop_Invariant (Pos <= Len and Pos mod 64 = 0);
         GHASH_NI.GHASH_4_Blocks
           (S, Buf (Buf'First + Pos .. Buf'First + Pos + 63),
            Context.Powers_4);
         Pos := Pos + 64;
      end loop;
      while Pos < Len loop
         pragma Loop_Invariant (Pos <= Len);
         Count := N32'Min (16, Len - Pos);
         Block := (others => 0);
         Block (0 .. Count - 1) :=
           Buf (Buf'First + Pos .. Buf'First + Pos + Count - 1);
         XOR_Block (S, Block);
         S := GF128_Mul (S, Context.H);
         Pos := Pos + Count;
      end loop;
   end Prepared_GHASH;

   procedure Encrypt_Prepared
     (Buf     : in out Byte_Seq;
      Tag     : out Bytes_16;
      N       : in Bytes_12;
      Context : in Prepared_Key;
      AAD     : in Byte_Seq)
   is
      S       : Bytes_16 := (others => 0);
      CB      : Bytes_16 := (others => 0);
      EJ0     : Bytes_16;
      Stream  : Bytes_16;
      Lengths : Bytes_16 := (others => 0);
      Ctr_256 : AES_GCM_AVX512.Bytes_256;
      Ctr_64  : AES_NI.Bytes_64;
      Pos     : N32 := 0;
      Count   : N32;
      Len     : constant N32 := N32 (Buf'Length);
      Base    : constant N32 := Buf'First;
      AAD_Bits : constant Unsigned_64 := Unsigned_64 (AAD'Length) * 8;
      Buf_Bits : constant Unsigned_64 := Unsigned_64 (Buf'Length) * 8;
   begin
      if not Context.Hardware then
         if Context.Is_256 then
            declare
               K : AES.AES256_Key := AES.Construct (Context.Raw_Key);
            begin
               Encrypt_InPlace_256 (Buf, Tag, N, K, AAD);
               AES.Sanitize (K);
            end;
         else
            declare
               K : AES.AES128_Key := AES.Construct (Context.Raw_Key (0 .. 15));
            begin
               Encrypt_InPlace (Buf, Tag, N, K, AAD);
               AES.Sanitize (K);
            end;
         end if;
         return;
      end if;

      CB (0 .. 11) := N;
      CB (15) := 1;
      Prepared_Cipher (EJ0, CB, Context);
      Increment_Counter (CB);
      Prepared_GHASH (S, Context, AAD);

      if AES_GCM_AVX512.Has_AVX512_AES_GCM and then Len >= 256 then
         while Len >= 256 and then Pos <= Len - 256 loop
            pragma Loop_Invariant (Pos <= Len and Pos mod 256 = 0);
            AES_GCM_AVX512.Build_Ctr_Block_16 (CB, Ctr_256);
            if Context.Is_256 then
               AES_GCM_AVX512.Encrypt_GCM_Stripe_16_256
                 (Buf (Base + Pos .. Base + Pos + 255), S, Ctr_256,
                  Context.Rounds, Context.Powers_32 (256 .. 511));
            else
               AES_GCM_AVX512.Encrypt_GCM_Stripe_16_128
                 (Buf (Base + Pos .. Base + Pos + 255), S, Ctr_256,
                  Context.Rounds (0 .. 175), Context.Powers_32 (256 .. 511));
            end if;
            Pos := Pos + 256;
         end loop;
      elsif AES_GCM_AVX2.Has_VAES_AVX2 and then Len >= 256 then
         --  VAES on ymm, sixteen blocks per stripe, pipelined like the
         --  AES-NI path below: encrypt stripe k while authenticating the
         --  ciphertext of stripe k-1, then authenticate the last stripe.
         if Context.Is_256 then
            AES_GCM_AVX2.Encrypt_CTR_16_256
              (Buf (Base .. Base + 255), CB, Context.Rounds);
         else
            AES_GCM_AVX2.Encrypt_CTR_16_128
              (Buf (Base .. Base + 255), CB, Context.Rounds (0 .. 175));
         end if;
         Pos := 256;
         while Len - Pos >= 256 loop
            pragma Loop_Invariant
              (Pos >= 256 and Pos <= Len and Pos mod 256 = 0);
            if Context.Is_256 then
               AES_GCM_AVX2.Encrypt_GHASH_Pipelined_16_256
                 (Buf (Base + Pos - 256 .. Base + Pos + 255), S, CB,
                  Context.Rounds, Context.Powers_32 (256 .. 511));
            else
               AES_GCM_AVX2.Encrypt_GHASH_Pipelined_16_128
                 (Buf (Base + Pos - 256 .. Base + Pos + 255), S, CB,
                  Context.Rounds (0 .. 175), Context.Powers_32 (256 .. 511));
            end if;
            Pos := Pos + 256;
         end loop;
         AES_GCM_AVX2.GHASH_16_Blocks
           (Buf (Base + Pos - 256 .. Base + Pos - 1), S,
            Context.Powers_32 (256 .. 511));
      elsif Len >= 128 then
         --  Keep the existing AES-NI pipeline: encrypt stripe k while
         --  authenticating stripe k-1. Only key preparation is hoisted.
         AES_NI.Build_Ctr_Block_4 (CB, Ctr_64);
         if Context.Is_256 then
            AES_NI.Cipher_4x_256_PreSw_XOR
              (Buf (Base .. Base + 63), Ctr_64, Context.Rounds);
         else
            AES_NI.Cipher_4x_128_PreSw_XOR
              (Buf (Base .. Base + 63), Ctr_64, Context.Rounds (0 .. 175));
         end if;
         Pos := 64;
         while Pos <= Len - 64 loop
            pragma Loop_Invariant (Pos >= 64 and Pos <= Len and Pos mod 64 = 0);
            AES_NI.Build_Ctr_Block_4 (CB, Ctr_64);
            if Context.Is_256 then
               AES_NI.Encrypt_GHASH_Pipelined_4_256
                 (Buf (Base + Pos - 64 .. Base + Pos + 63), S, Ctr_64,
                  Context.Rounds, Context.Powers_4);
            else
               AES_NI.Encrypt_GHASH_Pipelined_4_128
                 (Buf (Base + Pos - 64 .. Base + Pos + 63), S, Ctr_64,
                  Context.Rounds (0 .. 175), Context.Powers_4);
            end if;
            Pos := Pos + 64;
         end loop;
         GHASH_NI.GHASH_4_Blocks
           (S, Buf (Base + Pos - 64 .. Base + Pos - 1), Context.Powers_4);
      end if;

      --  Reuse the existing four-block fused kernels for the remaining
      --  stripes (or the whole record on non-AVX512 hardware).
      while Len >= 64 and then Pos <= Len - 64 loop
         pragma Loop_Invariant (Pos <= Len and Pos mod 64 = 0);
         AES_NI.Build_Ctr_Block_4 (CB, Ctr_64);
         if Context.Is_256 then
            AES_NI.Encrypt_GCM_Stripe_4_256
              (Buf (Base + Pos .. Base + Pos + 63), S, Ctr_64,
               Context.Rounds, Context.Powers_4);
         else
            AES_NI.Encrypt_GCM_Stripe_4_128
              (Buf (Base + Pos .. Base + Pos + 63), S, Ctr_64,
               Context.Rounds (0 .. 175), Context.Powers_4);
         end if;
         Pos := Pos + 64;
      end loop;
      while Pos < Len loop
         pragma Loop_Invariant (Pos <= Len);
         Count := N32'Min (16, Len - Pos);
         Prepared_Cipher (Stream, CB, Context);
         Increment_Counter (CB);
         for I in N32 range 0 .. Count - 1 loop
            Buf (Base + Pos + I) := Buf (Base + Pos + I) xor Stream (I);
         end loop;
         Prepared_GHASH
           (S, Context, Buf (Base + Pos .. Base + Pos + Count - 1));
         Pos := Pos + Count;
      end loop;
      for I in 0 .. 7 loop
         Lengths (N32 (I)) := Byte (Shift_Right (AAD_Bits, (7 - I) * 8) and 255);
         Lengths (N32 (I + 8)) := Byte (Shift_Right (Buf_Bits, (7 - I) * 8) and 255);
      end loop;
      XOR_Block (S, Lengths);
      S := GF128_Mul (S, Context.H);
      Tag := S;
      XOR_Block (Tag, EJ0);
      SPARKNaCl.Sanitize (Byte_Seq (Stream));
   end Encrypt_Prepared;

   ----------------------------------------------------------------------------
   --  Prepared decryption
   ----------------------------------------------------------------------------
   --  Both paths compute the expected tag over the ciphertext and decrypt
   --  Buf in place; Decrypt_Prepared then compares the tags and masks the
   --  whole buffer, the same way on every path and for every outcome.

   --  16#FF# if A = B, else 0, with no branch or early exit: the byte
   --  differences are OR-ed over all 16 positions, and D - 1 borrows into
   --  bit 8 exactly when D = 0.
   function Tag_Mask (A, B : Bytes_16) return Byte
   with Post => (if A = B then Tag_Mask'Result = 16#FF#
                 else Tag_Mask'Result = 0)
   is
      D : Byte := 0;
   begin
      for I in A'Range loop
         D := D or (A (I) xor B (I));
         pragma Loop_Invariant
           ((D = 0) = (for all J in A'First .. I => A (J) = B (J)));
      end loop;
      pragma Assert ((D = 0) = (A = B));
      return Byte (Shift_Right (Unsigned_32 (D) - 1, 8) and 16#FF#);
   end Tag_Mask;

   --  Portable counterpart of AES_NI.Mask_Bytes.
   procedure Mask_Portable (Buf : in out Byte_Seq; Mask : in Byte)
   with Pre  => Mask = 0 or Mask = 16#FF#,
        Post => (if Mask = 0 then (for all I in Buf'Range => Buf (I) = 0))
   is
   begin
      for I in Buf'Range loop
         Buf (I) := Buf (I) and Mask;
         pragma Loop_Invariant
           (if Mask = 0 then (for all J in Buf'First .. I => Buf (J) = 0));
      end loop;
   end Mask_Portable;

   --  GHASH of the length block len(A) || len(C), in bits, closing S.
   procedure GHASH_Lengths
     (S : in out Bytes_16; H : in Bytes_16; AAD_Len, C_Len : in N32)
   is
      A_Bits  : constant Unsigned_64 := Unsigned_64 (AAD_Len) * 8;
      C_Bits  : constant Unsigned_64 := Unsigned_64 (C_Len) * 8;
      Lengths : Bytes_16 := (others => 0);
   begin
      for I in 0 .. 7 loop
         Lengths (N32 (I)) :=
           Byte (Shift_Right (A_Bits, (7 - I) * 8) and 16#FF#);
         Lengths (N32 (8 + I)) :=
           Byte (Shift_Right (C_Bits, (7 - I) * 8) and 16#FF#);
      end loop;
      XOR_Block (S, Lengths);
      S := GF128_Mul (S, H);
   end GHASH_Lengths;

   --  The proven portable path: the one-shot building blocks (software AES
   --  and GHASH when the CPU lacks AES-NI or PCLMULQDQ, or in a
   --  SPARKTLSCRYPTO_ASM=disabled build), GHASH before CTR.
   procedure Portable_Decrypt
     (Buf      : in out Byte_Seq;
      Computed :    out Bytes_16;
      N        : in     Bytes_12;
      Context  : in     Prepared_Key;
      AAD      : in     Byte_Seq)
   with Pre => AAD'First = 0 and Buf'Last < N32'Last and AAD'Last < N32'Last
   is
      J0  : Bytes_16 := (others => 0);
      H   : Bytes_16;
      EJ0 : Bytes_16;
      S   : Bytes_16 := (others => 0);
   begin
      J0 (0 .. 11) := N;
      J0 (15) := 16#01#;
      if Context.Is_256 then
         declare
            K  : AES.AES256_Key := AES.Construct (Context.Raw_Key);
            RK : AES.AES256_Round_Keys := AES.Key_Expansion (K);
         begin
            HW_AES.Cipher (H, Bytes_16'(others => 0), RK);
            HW_AES.Cipher (EJ0, J0, RK);
            if AAD'Length > 0 then
               GHASH_Bytes (S, H, AAD);
            end if;
            if Buf'Length > 0 then
               GHASH_Bytes (S, H, Buf);
               Increment_Counter (J0);
               AES_CTR_256_InPlace (Buf, RK, J0);
            end if;
            pragma Warnings (GNATprove, Off, "statement has no effect");
            pragma Warnings (GNATprove, Off, "*is set by*");
            AES.Sanitize (RK);
            AES.Sanitize (K);
            pragma Warnings (GNATprove, On, "*is set by*");
            pragma Warnings (GNATprove, On, "statement has no effect");
         end;
      else
         declare
            K  : AES.AES128_Key := AES.Construct (Context.Raw_Key (0 .. 15));
            RK : AES.AES128_Round_Keys := AES.Key_Expansion (K);
         begin
            HW_AES.Cipher (H, Bytes_16'(others => 0), RK);
            HW_AES.Cipher (EJ0, J0, RK);
            if AAD'Length > 0 then
               GHASH_Bytes (S, H, AAD);
            end if;
            if Buf'Length > 0 then
               GHASH_Bytes (S, H, Buf);
               Increment_Counter (J0);
               AES_CTR_128_InPlace (Buf, RK, J0);
            end if;
            pragma Warnings (GNATprove, Off, "statement has no effect");
            pragma Warnings (GNATprove, Off, "*is set by*");
            AES.Sanitize (RK);
            AES.Sanitize (K);
            pragma Warnings (GNATprove, On, "*is set by*");
            pragma Warnings (GNATprove, On, "statement has no effect");
         end;
      end if;
      GHASH_Lengths (S, H, N32 (AAD'Length), N32 (Buf'Length));
      Computed := S;
      XOR_Block (Computed, EJ0);
      pragma Warnings (GNATprove, Off, "statement has no effect");
      pragma Warnings (GNATprove, Off, "*is set by*");
      SPARKNaCl.Sanitize (Byte_Seq (H));
      --  S xor EJ0 is the expected tag: wipe both, as Decrypt_Prepared
      --  wipes Computed.
      SPARKNaCl.Sanitize (Byte_Seq (S));
      SPARKNaCl.Sanitize (Byte_Seq (EJ0));
      pragma Warnings (GNATprove, On, "*is set by*");
      pragma Warnings (GNATprove, On, "statement has no effect");
   end Portable_Decrypt;

   --  The accelerated path: stitched stripes of 16 blocks (VAES on zmm or
   --  ymm), then 4 blocks (AES-NI), then single blocks. Every stripe
   --  GHASHes its ciphertext before overwriting it, so the tag covers the
   --  ciphertext as received.
   procedure Hardware_Decrypt
     (Buf      : in out Byte_Seq;
      Computed :    out Bytes_16;
      N        : in     Bytes_12;
      Context  : in     Prepared_Key;
      AAD      : in     Byte_Seq)
   with Pre => Context.Ready and Context.Hardware
               and AAD'First = 0 and Buf'Last < N32'Last
               and AAD'Last < N32'Last
   is
      S      : Bytes_16 := (others => 0);
      CB     : Bytes_16 := (others => 0);
      EJ0    : Bytes_16;
      Stream : Bytes_16;
      Block  : Bytes_16;
      Pos    : N32 := 0;
      Count  : N32;
      Len    : constant N32 := N32 (Buf'Length);
      --  The bounds of an empty Buf need not lie in N32; Base is used only
      --  when Buf is not empty.
      Base   : constant N32 := (if Buf'Length = 0 then 0 else Buf'First);
   begin
      CB (0 .. 11) := N;
      CB (15) := 1;
      Prepared_Cipher (EJ0, CB, Context);
      Increment_Counter (CB);
      Prepared_GHASH (S, Context, AAD);

      if AES_GCM_AVX512.Has_AVX512_AES_GCM then
         while Len - Pos >= 512 loop
            pragma Loop_Invariant (Pos <= Len);
            if Context.Is_256 then
               AES_GCM_AVX512.Decrypt_GCM_Stripe_32_256
                 (Buf (Base + Pos .. Base + Pos + 511), S, CB,
                  Context.Rounds, Context.Powers_32);
            else
               AES_GCM_AVX512.Decrypt_GCM_Stripe_32_128
                 (Buf (Base + Pos .. Base + Pos + 511), S, CB,
                  Context.Rounds (0 .. 175), Context.Powers_32);
            end if;
            Pos := Pos + 512;
         end loop;
         while Len - Pos >= 256 loop
            pragma Loop_Invariant (Pos <= Len);
            if Context.Is_256 then
               AES_GCM_AVX512.Decrypt_GCM_Stripe_16_256
                 (Buf (Base + Pos .. Base + Pos + 255), S, CB,
                  Context.Rounds, Context.Powers_32 (256 .. 511));
            else
               AES_GCM_AVX512.Decrypt_GCM_Stripe_16_128
                 (Buf (Base + Pos .. Base + Pos + 255), S, CB,
                  Context.Rounds (0 .. 175), Context.Powers_32 (256 .. 511));
            end if;
            Pos := Pos + 256;
         end loop;
      elsif AES_GCM_AVX2.Has_VAES_AVX2 then
         while Len - Pos >= 256 loop
            pragma Loop_Invariant (Pos <= Len);
            if Context.Is_256 then
               AES_GCM_AVX2.Decrypt_GCM_Stripe_16_256
                 (Buf (Base + Pos .. Base + Pos + 255), S, CB,
                  Context.Rounds, Context.Powers_32 (256 .. 511));
            else
               AES_GCM_AVX2.Decrypt_GCM_Stripe_16_128
                 (Buf (Base + Pos .. Base + Pos + 255), S, CB,
                  Context.Rounds (0 .. 175), Context.Powers_32 (256 .. 511));
            end if;
            Pos := Pos + 256;
         end loop;
      end if;

      while Len - Pos >= 64 loop
         pragma Loop_Invariant (Pos <= Len);
         if Context.Is_256 then
            AES_NI.Decrypt_GCM_Stripe_4_256
              (Buf (Base + Pos .. Base + Pos + 63), S, CB,
               Context.Rounds, Context.Powers_4);
         else
            AES_NI.Decrypt_GCM_Stripe_4_128
              (Buf (Base + Pos .. Base + Pos + 63), S, CB,
               Context.Rounds (0 .. 175), Context.Powers_4);
         end if;
         Pos := Pos + 64;
      end loop;

      --  At most three full blocks and one partial block remain. Each is
      --  GHASHed (zero-padded) before it is decrypted.
      while Pos < Len loop
         pragma Loop_Invariant (Pos < Len);
         Count := N32'Min (16, Len - Pos);
         Block := (others => 0);
         Block (0 .. Count - 1) :=
           Buf (Base + Pos .. Base + Pos + Count - 1);
         XOR_Block (S, Block);
         S := GF128_Mul (S, Context.H);
         Prepared_Cipher (Stream, CB, Context);
         Increment_Counter (CB);
         for I in N32 range 0 .. Count - 1 loop
            Buf (Base + Pos + I) := Buf (Base + Pos + I) xor Stream (I);
         end loop;
         Pos := Pos + Count;
      end loop;

      GHASH_Lengths (S, Context.H, N32 (AAD'Length), Len);
      Computed := S;
      XOR_Block (Computed, EJ0);
      pragma Warnings (GNATprove, Off, "statement has no effect");
      pragma Warnings (GNATprove, Off, "*is set by*");
      SPARKNaCl.Sanitize (Byte_Seq (Stream));
      SPARKNaCl.Sanitize (Byte_Seq (Block));
      --  S xor EJ0 is the expected tag: wipe both, as Decrypt_Prepared
      --  wipes Computed.
      SPARKNaCl.Sanitize (Byte_Seq (S));
      SPARKNaCl.Sanitize (Byte_Seq (EJ0));
      pragma Warnings (GNATprove, On, "*is set by*");
      pragma Warnings (GNATprove, On, "statement has no effect");
   end Hardware_Decrypt;

   procedure Decrypt_Prepared
     (Buf     : in out Byte_Seq;
      Status  :    out Boolean;
      Tag     : in     Bytes_16;
      N       : in     Bytes_12;
      Context : in     Prepared_Key;
      AAD     : in     Byte_Seq)
   is
      Computed : Bytes_16;
      Mask     : Byte;
   begin
      --  Context.Hardware is fixed at preparation from CPUID: public.
      if Context.Hardware then
         Hardware_Decrypt (Buf, Computed, N, Context, AAD);
      else
         Portable_Decrypt (Buf, Computed, N, Context, AAD);
      end if;

      --  Release the plaintext or zeros: one pass over the whole buffer
      --  either way, no branch on the comparison.
      Mask := Tag_Mask (Computed, Tag);
      if Context.Hardware and AES_GCM_AVX2.Has_VAES_AVX2 then
         AES_GCM_AVX2.Mask_Bytes (Buf, Mask);
      elsif Context.Hardware then
         AES_NI.Mask_Bytes (Buf, Mask);
      else
         Mask_Portable (Buf, Mask);
      end if;
      Status := Mask = 16#FF#;
      pragma Warnings (GNATprove, Off, "statement has no effect");
      pragma Warnings (GNATprove, Off, "*is set by*");
      SPARKNaCl.Sanitize (Byte_Seq (Computed));
      pragma Warnings (GNATprove, On, "*is set by*");
      pragma Warnings (GNATprove, On, "statement has no effect");
   end Decrypt_Prepared;

   procedure Decrypt_InPlace
     (Buf    : in out Byte_Seq;
      Status :    out Boolean;
      Tag    : in     Bytes_16;
      N      : in     Bytes_12;
      K      : in     AES.AES128_Key;
      AAD    : in     Byte_Seq)
   is
      Context : Prepared_Key;
   begin
      Prepare_128 (Context, K);
      Decrypt_Prepared (Buf, Status, Tag, N, Context, AAD);
      pragma Warnings (GNATprove, Off, "statement has no effect");
      pragma Warnings (GNATprove, Off, "*is set by*");
      Clear (Context);
      pragma Warnings (GNATprove, On, "*is set by*");
      pragma Warnings (GNATprove, On, "statement has no effect");
   end Decrypt_InPlace;

   procedure Decrypt_InPlace_256
     (Buf    : in out Byte_Seq;
      Status :    out Boolean;
      Tag    : in     Bytes_16;
      N      : in     Bytes_12;
      K      : in     AES.AES256_Key;
      AAD    : in     Byte_Seq)
   is
      Context : Prepared_Key;
   begin
      Prepare_256 (Context, K);
      Decrypt_Prepared (Buf, Status, Tag, N, Context, AAD);
      pragma Warnings (GNATprove, Off, "statement has no effect");
      pragma Warnings (GNATprove, Off, "*is set by*");
      Clear (Context);
      pragma Warnings (GNATprove, On, "*is set by*");
      pragma Warnings (GNATprove, On, "statement has no effect");
   end Decrypt_InPlace_256;

   ----------------------------------------------------------------------------
   --  Cryptographic algorithm self-test (FIPS 140-3 IG 10.3.A)
   ----------------------------------------------------------------------------
   --  Known answers from the NIST CAVP GCM vectors (gcmtestvectors.zip,
   --  https://csrc.nist.gov/projects/cryptographic-algorithm-validation-
   --  program/cavp-testing-block-cipher-modes), one encryption vector and
   --  one FAIL decryption vector per key size, plus the tag of one longer
   --  record under each encryption vector's key, IV and AAD. The CAVP
   --  records (51 bytes) never reach a stripe kernel; the 851-byte record
   --  passes through every stripe width of every tier (32/16/4 blocks, a
   --  full and a partial tail block) so the test exercises the code that
   --  will run. Its tags were computed with an independent implementation
   --  (pyca/cryptography over OpenSSL) and agree with the portable path.
   --  Every field is one slice of KAT_Data; Self_Test_With can flip any
   --  byte of it, which the tests use to show that each one matters.

   KAT_Last : constant := 905;
   subtype KAT_Index is N32 range 0 .. KAT_Last;
   subtype KAT_Image is Byte_Seq (KAT_Index);

   KAT_Data : constant KAT_Image :=
     (
      --  AES-128 gcmEncryptExtIV128.rsp [IVlen = 96] [PTlen = 408] [AADlen = 720] [Taglen = 128] Count = 0: Key (16 bytes, offset 0)
      16#2C#, 16#1F#, 16#21#, 16#CF#, 16#0F#, 16#6F#, 16#B3#, 16#66#,
      16#19#, 16#43#, 16#15#, 16#5C#, 16#3E#, 16#3D#, 16#84#, 16#92#,
      --  AES-128 gcmEncryptExtIV128.rsp [IVlen = 96] [PTlen = 408] [AADlen = 720] [Taglen = 128] Count = 0: IV (12 bytes, offset 16)
      16#23#, 16#CB#, 16#5F#, 16#F3#, 16#62#, 16#E2#, 16#24#, 16#26#,
      16#98#, 16#4D#, 16#19#, 16#07#,
      --  AES-128 gcmEncryptExtIV128.rsp [IVlen = 96] [PTlen = 408] [AADlen = 720] [Taglen = 128] Count = 0: AAD (90 bytes, offset 28)
      16#5D#, 16#36#, 16#24#, 16#87#, 16#9D#, 16#35#, 16#E4#, 16#68#,
      16#49#, 16#95#, 16#3E#, 16#45#, 16#A3#, 16#2A#, 16#62#, 16#4D#,
      16#6A#, 16#6C#, 16#53#, 16#6E#, 16#D9#, 16#85#, 16#7C#, 16#61#,
      16#3B#, 16#57#, 16#2B#, 16#03#, 16#33#, 16#E7#, 16#01#, 16#55#,
      16#7A#, 16#71#, 16#3E#, 16#3F#, 16#01#, 16#0E#, 16#CD#, 16#F9#,
      16#A6#, 16#BD#, 16#6C#, 16#9E#, 16#3E#, 16#44#, 16#B0#, 16#65#,
      16#20#, 16#86#, 16#45#, 16#AF#, 16#F4#, 16#AA#, 16#BE#, 16#E6#,
      16#11#, 16#B3#, 16#91#, 16#52#, 16#85#, 16#14#, 16#17#, 16#00#,
      16#84#, 16#CC#, 16#F5#, 16#87#, 16#17#, 16#7F#, 16#44#, 16#88#,
      16#F3#, 16#3C#, 16#FB#, 16#5E#, 16#97#, 16#9E#, 16#42#, 16#B6#,
      16#E1#, 16#CF#, 16#C0#, 16#A6#, 16#02#, 16#38#, 16#98#, 16#2A#,
      16#7A#, 16#EC#,
      --  AES-128 gcmEncryptExtIV128.rsp [IVlen = 96] [PTlen = 408] [AADlen = 720] [Taglen = 128] Count = 0: PT (51 bytes, offset 118)
      16#42#, 16#F7#, 16#58#, 16#83#, 16#69#, 16#86#, 16#95#, 16#4D#,
      16#B4#, 16#4B#, 16#F3#, 16#7C#, 16#6E#, 16#F5#, 16#E4#, 16#AC#,
      16#0A#, 16#DA#, 16#F3#, 16#8F#, 16#27#, 16#25#, 16#2A#, 16#1B#,
      16#82#, 16#D0#, 16#2E#, 16#A9#, 16#49#, 16#C8#, 16#A1#, 16#A2#,
      16#DB#, 16#C0#, 16#D6#, 16#8B#, 16#56#, 16#15#, 16#BA#, 16#7C#,
      16#12#, 16#20#, 16#FF#, 16#65#, 16#10#, 16#E2#, 16#59#, 16#F0#,
      16#66#, 16#55#, 16#D8#,
      --  AES-128 gcmEncryptExtIV128.rsp [IVlen = 96] [PTlen = 408] [AADlen = 720] [Taglen = 128] Count = 0: CT (51 bytes, offset 169)
      16#81#, 16#82#, 16#4F#, 16#0E#, 16#0D#, 16#52#, 16#3D#, 16#B3#,
      16#0D#, 16#3D#, 16#A3#, 16#69#, 16#FD#, 16#C0#, 16#D6#, 16#08#,
      16#94#, 16#C7#, 16#A0#, 16#A2#, 16#06#, 16#46#, 16#DD#, 16#01#,
      16#50#, 16#73#, 16#AD#, 16#27#, 16#32#, 16#BD#, 16#98#, 16#9B#,
      16#14#, 16#A2#, 16#22#, 16#B6#, 16#AD#, 16#57#, 16#AF#, 16#43#,
      16#E1#, 16#89#, 16#5D#, 16#F9#, 16#DC#, 16#A2#, 16#A5#, 16#34#,
      16#4A#, 16#62#, 16#CC#,
      --  AES-128 gcmEncryptExtIV128.rsp [IVlen = 96] [PTlen = 408] [AADlen = 720] [Taglen = 128] Count = 0: Tag (16 bytes, offset 220)
      16#57#, 16#A3#, 16#EE#, 16#28#, 16#13#, 16#6E#, 16#94#, 16#C7#,
      16#48#, 16#38#, 16#99#, 16#7A#, 16#E9#, 16#82#, 16#3F#, 16#3A#,
      --  AES-128 gcmDecrypt128.rsp [PTlen = 408] [AADlen = 720] Count = 2 (FAIL): Key (16 bytes, offset 236)
      16#19#, 16#86#, 16#31#, 16#0C#, 16#72#, 16#5A#, 16#C9#, 16#4E#,
      16#CF#, 16#E6#, 16#42#, 16#2E#, 16#75#, 16#FC#, 16#3E#, 16#E7#,
      --  AES-128 gcmDecrypt128.rsp [PTlen = 408] [AADlen = 720] Count = 2 (FAIL): IV (12 bytes, offset 252)
      16#93#, 16#EC#, 16#42#, 16#14#, 16#FA#, 16#8E#, 16#6D#, 16#C4#,
      16#E3#, 16#AF#, 16#C7#, 16#75#,
      --  AES-128 gcmDecrypt128.rsp [PTlen = 408] [AADlen = 720] Count = 2 (FAIL): AAD (90 bytes, offset 264)
      16#E8#, 16#0B#, 16#88#, 16#E6#, 16#2C#, 16#49#, 16#C9#, 16#58#,
      16#B5#, 16#E0#, 16#B8#, 16#B5#, 16#4F#, 16#53#, 16#2D#, 16#9F#,
      16#F6#, 16#AA#, 16#84#, 16#C8#, 16#A4#, 16#01#, 16#32#, 16#E9#,
      16#3E#, 16#55#, 16#B5#, 16#9F#, 16#C2#, 16#4E#, 16#8D#, 16#EC#,
      16#F2#, 16#84#, 16#63#, 16#13#, 16#9F#, 16#15#, 16#5D#, 16#1E#,
      16#8C#, 16#E4#, 16#EE#, 16#76#, 16#AA#, 16#EE#, 16#FC#, 16#D2#,
      16#45#, 16#BA#, 16#A0#, 16#FC#, 16#51#, 16#9F#, 16#83#, 16#A5#,
      16#FB#, 16#9A#, 16#D9#, 16#AA#, 16#40#, 16#C4#, 16#B2#, 16#11#,
      16#26#, 16#01#, 16#3F#, 16#57#, 16#6C#, 16#42#, 16#72#, 16#C2#,
      16#CB#, 16#13#, 16#6C#, 16#8F#, 16#D0#, 16#91#, 16#CC#, 16#45#,
      16#39#, 16#87#, 16#7A#, 16#5D#, 16#1E#, 16#72#, 16#D6#, 16#07#,
      16#F9#, 16#60#,
      --  AES-128 gcmDecrypt128.rsp [PTlen = 408] [AADlen = 720] Count = 2 (FAIL): CT (51 bytes, offset 354)
      16#B1#, 16#78#, 16#EC#, 16#72#, 16#F8#, 16#5A#, 16#31#, 16#1A#,
      16#C4#, 16#16#, 16#8F#, 16#42#, 16#A4#, 16#B2#, 16#C2#, 16#31#,
      16#13#, 16#FB#, 16#EA#, 16#4B#, 16#85#, 16#F4#, 16#B9#, 16#DA#,
      16#BB#, 16#74#, 16#E1#, 16#43#, 16#EB#, 16#1B#, 16#8B#, 16#0A#,
      16#36#, 16#1E#, 16#02#, 16#43#, 16#ED#, 16#FD#, 16#36#, 16#5B#,
      16#90#, 16#D5#, 16#B3#, 16#25#, 16#95#, 16#0D#, 16#F0#, 16#AD#,
      16#A0#, 16#58#, 16#F9#,
      --  AES-128 gcmDecrypt128.rsp [PTlen = 408] [AADlen = 720] Count = 2 (FAIL): Tag (16 bytes, offset 405)
      16#8B#, 16#34#, 16#78#, 16#53#, 16#F1#, 16#1D#, 16#75#, 16#E8#,
      16#1E#, 16#8A#, 16#95#, 16#01#, 16#0B#, 16#E8#, 16#1F#, 16#17#,
      --  AES-128 long record: tag of the 851-byte Long_Plain under the Count 0 key, IV and AAD (16 bytes, offset 421)
      16#5C#, 16#E0#, 16#21#, 16#B0#, 16#CF#, 16#EE#, 16#E6#, 16#FD#,
      16#9D#, 16#16#, 16#1D#, 16#4D#, 16#A3#, 16#07#, 16#9C#, 16#AD#,
      --  AES-256 gcmEncryptExtIV256.rsp [IVlen = 96] [PTlen = 408] [AADlen = 720] [Taglen = 128] Count = 0: Key (32 bytes, offset 437)
      16#14#, 16#85#, 16#79#, 16#A3#, 16#CB#, 16#CA#, 16#86#, 16#D5#,
      16#52#, 16#0D#, 16#66#, 16#C0#, 16#EC#, 16#71#, 16#CA#, 16#5F#,
      16#7E#, 16#41#, 16#BA#, 16#78#, 16#E5#, 16#6D#, 16#C6#, 16#EE#,
      16#BD#, 16#56#, 16#6F#, 16#ED#, 16#54#, 16#7F#, 16#E6#, 16#91#,
      --  AES-256 gcmEncryptExtIV256.rsp [IVlen = 96] [PTlen = 408] [AADlen = 720] [Taglen = 128] Count = 0: IV (12 bytes, offset 469)
      16#B0#, 16#8A#, 16#5E#, 16#A1#, 16#92#, 16#74#, 16#99#, 16#C6#,
      16#EC#, 16#BF#, 16#D4#, 16#E0#,
      --  AES-256 gcmEncryptExtIV256.rsp [IVlen = 96] [PTlen = 408] [AADlen = 720] [Taglen = 128] Count = 0: AAD (90 bytes, offset 481)
      16#E4#, 16#F9#, 16#63#, 16#F0#, 16#15#, 16#FF#, 16#BB#, 16#99#,
      16#EE#, 16#33#, 16#49#, 16#BB#, 16#AF#, 16#7E#, 16#8E#, 16#8E#,
      16#6C#, 16#2A#, 16#71#, 16#C2#, 16#30#, 16#A4#, 16#8F#, 16#9D#,
      16#59#, 16#86#, 16#0A#, 16#29#, 16#09#, 16#1D#, 16#27#, 16#47#,
      16#E0#, 16#1A#, 16#5C#, 16#A5#, 16#72#, 16#34#, 16#7E#, 16#24#,
      16#7D#, 16#25#, 16#F5#, 16#6B#, 16#A7#, 16#AE#, 16#8E#, 16#05#,
      16#CD#, 16#E2#, 16#BE#, 16#3C#, 16#97#, 16#93#, 16#12#, 16#92#,
      16#C0#, 16#23#, 16#70#, 16#20#, 16#8E#, 16#CD#, 16#09#, 16#7E#,
      16#F6#, 16#92#, 16#68#, 16#7F#, 16#EC#, 16#F2#, 16#F4#, 16#19#,
      16#D3#, 16#20#, 16#01#, 16#62#, 16#A6#, 16#48#, 16#0A#, 16#57#,
      16#DA#, 16#D4#, 16#08#, 16#A0#, 16#DF#, 16#EB#, 16#49#, 16#2E#,
      16#2C#, 16#5D#,
      --  AES-256 gcmEncryptExtIV256.rsp [IVlen = 96] [PTlen = 408] [AADlen = 720] [Taglen = 128] Count = 0: PT (51 bytes, offset 571)
      16#9D#, 16#0B#, 16#15#, 16#FD#, 16#F1#, 16#BD#, 16#59#, 16#5F#,
      16#91#, 16#F8#, 16#B3#, 16#AB#, 16#C0#, 16#F7#, 16#DE#, 16#C9#,
      16#27#, 16#DF#, 16#D4#, 16#79#, 16#99#, 16#35#, 16#A1#, 16#79#,
      16#5D#, 16#9C#, 16#E0#, 16#0C#, 16#9B#, 16#87#, 16#94#, 16#34#,
      16#42#, 16#0F#, 16#E4#, 16#2C#, 16#27#, 16#5A#, 16#7C#, 16#D7#,
      16#B3#, 16#9D#, 16#63#, 16#8F#, 16#B8#, 16#1C#, 16#A5#, 16#2B#,
      16#49#, 16#DC#, 16#41#,
      --  AES-256 gcmEncryptExtIV256.rsp [IVlen = 96] [PTlen = 408] [AADlen = 720] [Taglen = 128] Count = 0: CT (51 bytes, offset 622)
      16#20#, 16#97#, 16#E3#, 16#72#, 16#95#, 16#0A#, 16#5E#, 16#93#,
      16#83#, 16#C6#, 16#75#, 16#E8#, 16#9E#, 16#EA#, 16#1C#, 16#31#,
      16#4F#, 16#99#, 16#91#, 16#59#, 16#F5#, 16#61#, 16#13#, 16#44#,
      16#B2#, 16#98#, 16#CD#, 16#A4#, 16#5E#, 16#62#, 16#84#, 16#37#,
      16#16#, 16#F2#, 16#15#, 16#F8#, 16#2E#, 16#E6#, 16#63#, 16#91#,
      16#9C#, 16#64#, 16#00#, 16#2A#, 16#5C#, 16#19#, 16#8D#, 16#78#,
      16#78#, 16#FD#, 16#3F#,
      --  AES-256 gcmEncryptExtIV256.rsp [IVlen = 96] [PTlen = 408] [AADlen = 720] [Taglen = 128] Count = 0: Tag (16 bytes, offset 673)
      16#AD#, 16#BE#, 16#CD#, 16#B0#, 16#D5#, 16#C2#, 16#22#, 16#4D#,
      16#80#, 16#4D#, 16#28#, 16#86#, 16#FF#, 16#9A#, 16#57#, 16#60#,
      --  AES-256 gcmDecrypt256.rsp [PTlen = 408] [AADlen = 720] Count = 0 (FAIL): Key (32 bytes, offset 689)
      16#E3#, 16#6A#, 16#CA#, 16#93#, 16#41#, 16#4B#, 16#13#, 16#F5#,
      16#31#, 16#3E#, 16#76#, 16#A7#, 16#24#, 16#45#, 16#88#, 16#EE#,
      16#11#, 16#65#, 16#51#, 16#D1#, 16#F3#, 16#4C#, 16#32#, 16#85#,
      16#91#, 16#66#, 16#F2#, 16#EB#, 16#0A#, 16#C1#, 16#A9#, 16#B7#,
      --  AES-256 gcmDecrypt256.rsp [PTlen = 408] [AADlen = 720] Count = 0 (FAIL): IV (12 bytes, offset 721)
      16#E9#, 16#E7#, 16#01#, 16#B1#, 16#CC#, 16#EF#, 16#6B#, 16#DD#,
      16#D0#, 16#33#, 16#91#, 16#D8#,
      --  AES-256 gcmDecrypt256.rsp [PTlen = 408] [AADlen = 720] Count = 0 (FAIL): AAD (90 bytes, offset 733)
      16#6A#, 16#08#, 16#FE#, 16#6E#, 16#55#, 16#A0#, 16#8F#, 16#28#,
      16#3C#, 16#EC#, 16#4C#, 16#4B#, 16#37#, 16#67#, 16#6E#, 16#77#,
      16#0F#, 16#40#, 16#2A#, 16#F6#, 16#10#, 16#2F#, 16#54#, 16#8A#,
      16#D4#, 16#73#, 16#EC#, 16#62#, 16#36#, 16#DA#, 16#76#, 16#4F#,
      16#70#, 16#76#, 16#FF#, 16#D4#, 16#1B#, 16#BD#, 16#96#, 16#11#,
      16#B4#, 16#39#, 16#36#, 16#2D#, 16#89#, 16#96#, 16#82#, 16#B7#,
      16#B0#, 16#F8#, 16#39#, 16#FC#, 16#5A#, 16#68#, 16#D9#, 16#DF#,
      16#54#, 16#AF#, 16#D1#, 16#E2#, 16#B3#, 16#C4#, 16#E7#, 16#D0#,
      16#72#, 16#45#, 16#4E#, 16#E2#, 16#71#, 16#11#, 16#D5#, 16#21#,
      16#93#, 16#D2#, 16#8B#, 16#9C#, 16#4F#, 16#92#, 16#5D#, 16#2A#,
      16#8B#, 16#45#, 16#16#, 16#75#, 16#AF#, 16#39#, 16#19#, 16#1A#,
      16#2C#, 16#BA#,
      --  AES-256 gcmDecrypt256.rsp [PTlen = 408] [AADlen = 720] Count = 0 (FAIL): CT (51 bytes, offset 823)
      16#5B#, 16#05#, 16#9A#, 16#C6#, 16#73#, 16#3B#, 16#6D#, 16#E0#,
      16#E8#, 16#CF#, 16#5B#, 16#88#, 16#B7#, 16#30#, 16#1C#, 16#02#,
      16#C9#, 16#93#, 16#42#, 16#6F#, 16#71#, 16#BB#, 16#12#, 16#AB#,
      16#F6#, 16#92#, 16#E9#, 16#DE#, 16#EA#, 16#CF#, 16#AC#, 16#1F#,
      16#F1#, 16#64#, 16#4C#, 16#87#, 16#D4#, 16#DF#, 16#13#, 16#00#,
      16#28#, 16#F5#, 16#15#, 16#F0#, 16#FE#, 16#DA#, 16#63#, 16#63#,
      16#09#, 16#A2#, 16#4D#,
      --  AES-256 gcmDecrypt256.rsp [PTlen = 408] [AADlen = 720] Count = 0 (FAIL): Tag (16 bytes, offset 874)
      16#43#, 16#C7#, 16#C9#, 16#C9#, 16#3C#, 16#C2#, 16#65#, 16#FC#,
      16#8E#, 16#19#, 16#20#, 16#00#, 16#E0#, 16#41#, 16#7B#, 16#5B#,
      --  AES-256 long record: tag of the 851-byte Long_Plain under the Count 0 key, IV and AAD (16 bytes, offset 890)
      16#B2#, 16#91#, 16#C4#, 16#BB#, 16#DB#, 16#A9#, 16#6A#, 16#50#,
      16#F8#, 16#FD#, 16#E0#, 16#E7#, 16#4C#, 16#78#, 16#EC#, 16#9F#);

   --  Bytes of KAT_Data per key size: the encryption vector (key, IV, AAD,
   --  PT, CT, tag), the FAIL vector (key, IV, AAD, CT, tag), the long tag.
   KAT_Text_Len : constant N32 := 51;
   KAT_AAD_Len  : constant N32 := 90;
   KAT_Long_Len : constant N32 := 851;
   KAT_128_Len  : constant N32 := 2 * 16 + 2 * 12 + 2 * KAT_AAD_Len
                                   + 3 * KAT_Text_Len + 3 * 16;
   KAT_256_Len  : constant N32 := KAT_128_Len + 2 * 16;
   pragma Assert (KAT_128_Len + KAT_256_Len = KAT_Last + 1);

   --  The long record's plaintext: a fixed pattern, so only its tag is
   --  stored.
   function Long_Plain (I : N32) return Byte is
     (Byte ((I * 31 + 17) mod 256))
   with Pre => I < KAT_Long_Len;

   --  One key size: encrypt and decrypt the CAVP vector and the long
   --  record through the prepared paths, reject a forged long record and
   --  the CAVP FAIL vector with the buffer zeroed.
   procedure KAT_Key_Size
     (D : KAT_Image; Base : KAT_Index; Wide : Boolean; OK : out Boolean)
   with Pre => Base + (if Wide then KAT_256_Len else KAT_128_Len)
                 <= KAT_Last + 1
   is
      K_Len  : constant N32 := (if Wide then 32 else 16);
      IV     : constant N32 := Base + K_Len;
      AAD    : constant N32 := IV + 12;
      PT     : constant N32 := AAD + KAT_AAD_Len;
      CT     : constant N32 := PT + KAT_Text_Len;
      Tag    : constant N32 := CT + KAT_Text_Len;
      F_Key  : constant N32 := Tag + 16;
      F_IV   : constant N32 := F_Key + K_Len;
      F_AAD  : constant N32 := F_IV + 12;
      F_CT   : constant N32 := F_AAD + KAT_AAD_Len;
      F_Tag  : constant N32 := F_CT + KAT_Text_Len;
      L_Tag  : constant N32 := F_Tag + 16;
      Auth   : constant Byte_Seq (0 .. KAT_AAD_Len - 1) :=
        D (AAD .. AAD + KAT_AAD_Len - 1);
      F_Auth : constant Byte_Seq (0 .. KAT_AAD_Len - 1) :=
        D (F_AAD .. F_AAD + KAT_AAD_Len - 1);
      Nonce   : constant Bytes_12 := Bytes_12 (D (IV .. IV + 11));
      Context : Prepared_Key;
      Text    : Byte_Seq (0 .. KAT_Text_Len - 1);
      Long    : Byte_Seq (0 .. KAT_Long_Len - 1);
      T       : Bytes_16;
      Status  : Boolean;

      procedure Prepare_Key (Key : KAT_Index) with
        Pre  => Key + K_Len - 1 <= KAT_Last,
        Post => Is_Prepared (Context)
      is
      begin
         if Wide then
            declare
               K : AES.AES256_Key :=
                 AES.Construct (Bytes_32 (D (Key .. Key + 31)));
            begin
               Prepare_256 (Context, K);
               pragma Warnings (GNATprove, Off, "statement has no effect");
               pragma Warnings (GNATprove, Off, "*is set by*");
               AES.Sanitize (K);
               pragma Warnings (GNATprove, On, "*is set by*");
               pragma Warnings (GNATprove, On, "statement has no effect");
            end;
         else
            declare
               K : AES.AES128_Key :=
                 AES.Construct (Bytes_16 (D (Key .. Key + 15)));
            begin
               Prepare_128 (Context, K);
               pragma Warnings (GNATprove, Off, "statement has no effect");
               pragma Warnings (GNATprove, Off, "*is set by*");
               AES.Sanitize (K);
               pragma Warnings (GNATprove, On, "*is set by*");
               pragma Warnings (GNATprove, On, "statement has no effect");
            end;
         end if;
      end Prepare_Key;
   begin
      Prepare_Key (Base);

      --  1. CAVP encryption: ciphertext and tag.
      Text := D (PT .. PT + KAT_Text_Len - 1);
      Encrypt_Prepared (Text, T, Nonce, Context, Auth);
      OK := Text = D (CT .. CT + KAT_Text_Len - 1)
        and T = Bytes_16 (D (Tag .. Tag + 15));

      --  2. CAVP decryption of the same vector: status and plaintext.
      Text := D (CT .. CT + KAT_Text_Len - 1);
      Decrypt_Prepared (Text, Status, Bytes_16 (D (Tag .. Tag + 15)), Nonce,
                        Context, Auth);
      OK := OK and Status and Text = D (PT .. PT + KAT_Text_Len - 1);

      --  3. The long record: tag, then decryption back to the pattern.
      for I in Long'Range loop
         Long (I) := Long_Plain (I);
      end loop;
      Encrypt_Prepared (Long, T, Nonce, Context, Auth);
      OK := OK and T = Bytes_16 (D (L_Tag .. L_Tag + 15));
      Decrypt_Prepared (Long, Status, Bytes_16 (D (L_Tag .. L_Tag + 15)),
                        Nonce, Context, Auth);
      OK := OK and Status;
      for I in Long'Range loop
         OK := OK and Long (I) = Long_Plain (I);
      end loop;

      --  4. The long record with one tag bit changed: rejected, zeroed.
      Encrypt_Prepared (Long, T, Nonce, Context, Auth);
      T (15) := T (15) xor 1;
      Decrypt_Prepared (Long, Status, T, Nonce, Context, Auth);
      OK := OK and not Status;
      for I in Long'Range loop
         OK := OK and Long (I) = 0;
      end loop;

      --  5. The CAVP FAIL vector under its own key: rejected, zeroed.
      Prepare_Key (F_Key);
      Text := D (F_CT .. F_CT + KAT_Text_Len - 1);
      Decrypt_Prepared (Text, Status, Bytes_16 (D (F_Tag .. F_Tag + 15)),
                        Bytes_12 (D (F_IV .. F_IV + 11)), Context, F_Auth);
      OK := OK and not Status and Text = Byte_Seq'(Text'Range => 0);

      pragma Warnings (GNATprove, Off, "statement has no effect");
      pragma Warnings (GNATprove, Off, "*is set by*");
      Clear (Context);
      pragma Warnings (GNATprove, On, "*is set by*");
      pragma Warnings (GNATprove, On, "statement has no effect");
   end KAT_Key_Size;

   procedure Self_Test_With (Flip : in N32; OK : out Boolean) is
      D : KAT_Image := KAT_Data;
      OK_128, OK_256 : Boolean;
   begin
      if Flip <= D'Last then
         D (Flip) := D (Flip) xor 1;
      end if;
      KAT_Key_Size (D, 0, Wide => False, OK => OK_128);
      KAT_Key_Size (D, KAT_128_Len, Wide => True, OK => OK_256);
      OK := OK_128 and OK_256;
   end Self_Test_With;

   procedure Self_Test (OK : out Boolean) is
   begin
      Self_Test_With (N32'Last, OK);
   end Self_Test;

end SPARKTLSCrypto.AES_GCM;
