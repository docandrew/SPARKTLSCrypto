--  AES-NI hardware-accelerated AES block cipher for x86_64.
--
--  This module is OUT-OF-SCOPE for SPARK formal verification: it uses
--  inline assembly to issue AESENC / AESENCLAST / AESKEYGENASSIST
--  instructions. Functional equivalence with SPARKNaCl.AES is
--  validated via NIST KAT vectors (see
--  tests/unit/test_aes_ni_kat.adb).
--
--  Has_AESNI is a Constant_After_Elaboration boolean set by a CPUID
--  probe in the body. The dispatch in SPARKTLSCrypto.AES_GCM picks
--  the AES-NI path when this is True and falls back to
--  SPARKNaCl.AES.Cipher (formally proven software AES) otherwise.

with SPARKNaCl;       use SPARKNaCl;
with SPARKNaCl.AES;

package SPARKTLSCrypto.AES_NI with
   SPARK_Mode => On,
   Elaborate_Body
is
   --  True iff the running CPU advertises AES-NI (CPUID.01h:ECX[25]).
   --  Set once during elaboration by a CPUID probe in the body and
   --  never modified afterwards. Constant_After_Elaboration lets SPARK
   --  treat reads of this Boolean from SPARK_Mode=>On callers as
   --  side-effect-free.
   Has_AESNI : Boolean := False with Constant_After_Elaboration;

   --  Hardware AES-128 block encrypt.
   --  Uses 10× AESENC + 1× AESENCLAST.
   procedure Cipher_128
     (Output     :    out Bytes_16;
      Input      : in     Bytes_16;
      Round_Keys : in     SPARKNaCl.AES.AES128_Round_Keys);

   --  Hardware AES-256 block encrypt.
   --  Uses 13× AESENC + 1× AESENCLAST.
   procedure Cipher_256
     (Output     :    out Bytes_16;
      Input      : in     Bytes_16;
      Round_Keys : in     SPARKNaCl.AES.AES256_Round_Keys);

   --================================================================
   --  Pre-byteswapped round-key fast paths
   --================================================================
   --  SPARKNaCl stores AES round keys as U32 packed via Big_Endian_Pack
   --  — the byte order in memory is the reverse of what AES-NI's
   --  AESENC/AESENCLAST consume natively. The Cipher_128 / Cipher_256
   --  procedures compensate with a per-call PSHUFB on EACH round key
   --  (~11 PSHUFBs / call for AES-128, ~15 for AES-256). On a per-byte
   --  basis these dominate the AES-NI cycle budget for short blocks.
   --
   --  When encrypting many blocks under one key (TLS record streams),
   --  pre-byteswap the round keys once into a flat byte buffer and use
   --  Cipher_128_PreSw / Cipher_256_PreSw to skip the PSHUFB per call.

   --  176 bytes = 11 round keys × 16 bytes (AES-128).
   subtype Pre_Swapped_RKs_128 is Byte_Seq (0 .. 175);
   --  240 bytes = 15 round keys × 16 bytes (AES-256).
   subtype Pre_Swapped_RKs_256 is Byte_Seq (0 .. 239);

   procedure Pre_Swap_RKs_128
     (Source : in     SPARKNaCl.AES.AES128_Round_Keys;
      Dest   :    out Pre_Swapped_RKs_128);

   procedure Pre_Swap_RKs_256
     (Source : in     SPARKNaCl.AES.AES256_Round_Keys;
      Dest   :    out Pre_Swapped_RKs_256);

   procedure Cipher_128_PreSw
     (Output     :    out Bytes_16;
      Input      : in     Bytes_16;
      Pre_RK     : in     Pre_Swapped_RKs_128);

   procedure Cipher_256_PreSw
     (Output     :    out Bytes_16;
      Input      : in     Bytes_16;
      Pre_RK     : in     Pre_Swapped_RKs_256);

   --================================================================
   --  4-way pipelined block encrypt
   --================================================================
   --  Encrypts 4 independent 16-byte blocks in parallel. AESENC has
   --  ~4-cycle latency but 1-cycle reciprocal throughput; running 4
   --  independent state chains keeps the AES unit fully fed and cuts
   --  cycles-per-block by ~3-4x for CTR-mode keystream generation.
   --
   --  Input/Output are 64-byte buffers (4 blocks at offsets 0/16/32/48).
   subtype Bytes_64 is Byte_Seq (0 .. 63);

   procedure Cipher_4x_128_PreSw
     (Output : out Bytes_64;
      Input  : in     Bytes_64;
      Pre_RK : in     Pre_Swapped_RKs_128);

   procedure Cipher_4x_256_PreSw
     (Output : out Bytes_64;
      Input  : in     Bytes_64;
      Pre_RK : in     Pre_Swapped_RKs_256);

   --================================================================
   --  Fused 4-block CTR-mode encrypt: keystream + XOR in one asm.
   --================================================================
   --  Computes Buf[0..63] ^= AES_E(Counter[0..63], Pre_RK), then
   --  stores back to Buf in place. Eliminates the round-trip through
   --  a 64-byte keystream buffer and the Ada-level XOR loop.
   --
   --  Buf'Length must be exactly 64 (caller responsibility).

   procedure Cipher_4x_128_PreSw_XOR
     (Buf     : in out Byte_Seq;
      Counter : in     Bytes_64;
      Pre_RK  : in     Pre_Swapped_RKs_128)
   with Pre => Buf'Length = 64;

   procedure Cipher_4x_256_PreSw_XOR
     (Buf     : in out Byte_Seq;
      Counter : in     Bytes_64;
      Pre_RK  : in     Pre_Swapped_RKs_256)
   with Pre => Buf'Length = 64;

   --================================================================
   --  Fully fused AES-GCM stripe (Step 4)
   --================================================================
   --  Encrypts 4 plaintext blocks with CTR, stores ciphertext in
   --  place, AND aggregated-GHASHes the ciphertext into S — all in
   --  one asm block. Saves the cache round-trip between encrypt and
   --  GHASH passes, and gives the OOO engine visibility into both
   --  the AESENC and PCLMULQDQ pipelines so it can interleave them
   --  across different execution ports.
   --
   --  H_Powers must hold (H^4, H^3, H^2, H) byte-reversed at offsets
   --  0, 16, 32, 48 (see SPARKTLSCrypto.GHASH_NI.Compute_H_Powers).
   subtype Pre_H_Powers is Byte_Seq (0 .. 63);

   procedure Encrypt_GCM_Stripe_4_128
     (Buf      : in out Byte_Seq;          -- 64 bytes in/out
      S        : in out Bytes_16;          -- GHASH accumulator
      Counter  : in     Bytes_64;          -- 4 prebuilt CTR blocks
      Pre_RK   : in     Pre_Swapped_RKs_128;
      H_Powers : in     Pre_H_Powers)
   with Pre => Buf'Length = 64;

   procedure Encrypt_GCM_Stripe_4_256
     (Buf      : in out Byte_Seq;
      S        : in out Bytes_16;
      Counter  : in     Bytes_64;
      Pre_RK   : in     Pre_Swapped_RKs_256;
      H_Powers : in     Pre_H_Powers)
   with Pre => Buf'Length = 64;

   --================================================================
   --  2-stripe pipelined AEAD (Step 6)
   --================================================================
   --  Encrypts 4 new plaintext blocks (current stripe) AND aggregated-
   --  GHASHes 4 already-encrypted ciphertext blocks (previous stripe)
   --  in one asm block. AES (port 0) and PCLMULQDQ (port 5) execute
   --  on different units, so the OOO engine overlaps them — roughly
   --  hides the GHASH cost behind the AESENC dependency chain.
   --
   --  Caller's bulk loop pattern (Buf is a 128-byte sliding window):
   --    Cipher_4x_128_PreSw_XOR (Buf[0..63], CB0, Pre_RK)         -- first
   --    for k in 1..N-1 loop                                       -- middle
   --       Encrypt_GHASH_Pipelined_4_128
   --         (Buf       => Buf[(k-1)*64..(k+1)*64-1],   -- 128 bytes
   --          ...);    -- bytes 0..63 = prev ct (GHASH); 64..127 = new pt
   --    end loop
   --    GHASH_NI.GHASH_4_Blocks (S, Buf[(N-1)*64..N*64-1], HP)     -- tail
   --
   --  A single Buf parameter avoids SPARK's anti-aliasing rule
   --  (RM 6.4.2) that would otherwise flag two slices of the same
   --  parent array as potentially overlapping.

   procedure Encrypt_GHASH_Pipelined_4_128
     (Buf       : in out Byte_Seq;          -- 128 bytes: [0..63]=prev ct, [64..127]=new pt
      S         : in out Bytes_16;
      Counter   : in     Bytes_64;
      Pre_RK    : in     Pre_Swapped_RKs_128;
      H_Powers  : in     Pre_H_Powers)
   with Pre => Buf'Length = 128;

   procedure Encrypt_GHASH_Pipelined_4_256
     (Buf       : in out Byte_Seq;
      S         : in out Bytes_16;
      Counter   : in     Bytes_64;
      Pre_RK    : in     Pre_Swapped_RKs_256;
      H_Powers  : in     Pre_H_Powers)
   with Pre => Buf'Length = 128;

   --================================================================
   --  Vectorized 4-block counter generation
   --================================================================
   --  Takes a 16-byte CTR block (NIST GCM format: IV at bytes 0..11,
   --  big-endian counter at bytes 12..15) and emits 4 consecutive CTR
   --  blocks (CB, CB+1, CB+2, CB+3) into Counter, advancing CB by 4.
   --
   --  Replaces the per-stripe Ada loop:
   --    for B in 0 .. 3 loop
   --       for I in 0 .. 15 loop
   --          Ctr_Buf (B*16+I) := CB (I);
   --       end loop;
   --       Increment_Counter (CB);
   --    end loop;
   --  with a tiny PSHUFB+PADDD sequence (~10 cycles vs ~150 in Ada).
   procedure Build_Ctr_Block_4
     (CB      : in out Bytes_16;
      Counter :    out Bytes_64);

end SPARKTLSCrypto.AES_NI;
