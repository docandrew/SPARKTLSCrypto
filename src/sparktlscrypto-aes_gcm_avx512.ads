--  AVX-512 VAES + VPCLMULQDQ AES-GCM accelerator (x86_64).
--
--  Higher-throughput tier above SPARKTLSCrypto.AES_NI / GHASH_NI.
--  When the CPU advertises AVX-512F + VAES + VPCLMULQDQ this module
--  takes over the bulk AES-GCM encrypt path. Falls back to the
--  existing 4-block AES-NI fused-stripe path otherwise.
--
--  Strategy: 4 zmm chains × 4 blocks per zmm = 16 blocks per AES
--  round (vs 4 blocks/round in the AES-NI path), and VPCLMULQDQ on
--  zmm does 4 carry-less multiplies per instruction. Same shape as
--  OpenSSL's "aes_gcm_avx512" path; intent is parity with that.
--
--  SPARK_Mode is Off — inline assembly throughout. Functional
--  equivalence is validated against the formally-proven SPARKNaCl
--  software AES via KAT-style unit tests.

with SPARKNaCl;       use SPARKNaCl;
with SPARKTLSCrypto.AES_NI;

package SPARKTLSCrypto.AES_GCM_AVX512 with
   SPARK_Mode => On,
   Elaborate_Body
is
   --  True iff the running CPU advertises AVX-512F + VAES + VPCLMULQDQ
   --  (CPUID.7.0.EBX[16] & CPUID.7.0.ECX[9] & CPUID.7.0.ECX[10]).
   --  Set once at elaboration; Constant_After_Elaboration lets SPARK
   --  treat reads from SPARK_Mode=>On callers as side-effect-free.
   Has_AVX512_AES_GCM : Boolean := False with Constant_After_Elaboration;

   --================================================================
   --  16-block AES-128 cipher (4 zmm chains)
   --================================================================
   --  Encrypts 16 consecutive 16-byte blocks (256 bytes total) using
   --  4 zmm chains × 4 blocks/zmm. Same Pre_Swapped_RKs_128 layout as
   --  the AES-NI module (key broadcast lane-by-lane).
   subtype Bytes_256 is Byte_Seq (0 .. 255);

   procedure Cipher_16x_128_VAES
     (Output : out Bytes_256;
      Input  : in     Bytes_256;
      Pre_RK : in     SPARKTLSCrypto.AES_NI.Pre_Swapped_RKs_128);

   procedure Cipher_16x_256_VAES
     (Output : out Bytes_256;
      Input  : in     Bytes_256;
      Pre_RK : in     SPARKTLSCrypto.AES_NI.Pre_Swapped_RKs_256);

   --================================================================
   --  16-block counter generation (analogous to Build_Ctr_Block_4)
   --================================================================
   --  Takes a 16-byte CB (NIST GCM format: IV at 0..11, BE counter
   --  at 12..15) and emits 16 consecutive CTR blocks (CB+0..CB+15)
   --  into Counter, advancing CB by 16. ~12 cycles inside zmm asm.
   procedure Build_Ctr_Block_16
     (CB      : in out Bytes_16;
      Counter :    out Bytes_256);

   --================================================================
   --  16-block fused CTR-encrypt + XOR
   --================================================================
   --  Generates 16 keystream blocks (VAES on 4 zmm chains) and XORs
   --  with Buf in place. Buf must be exactly 256 bytes.
   procedure Cipher_16x_128_VAES_XOR
     (Buf     : in out Byte_Seq;        -- 256 bytes in/out
      Counter : in     Bytes_256;       -- 16 prebuilt counter blocks
      Pre_RK  : in     SPARKTLSCrypto.AES_NI.Pre_Swapped_RKs_128);

   procedure Cipher_16x_256_VAES_XOR
     (Buf     : in out Byte_Seq;
      Counter : in     Bytes_256;
      Pre_RK  : in     SPARKTLSCrypto.AES_NI.Pre_Swapped_RKs_256);

   --================================================================
   --  16-block aggregated GHASH on zmm (VPCLMULQDQ)
   --================================================================
   --  256-byte H_Powers buffer holds H^16..H^1 byte-reversed and
   --  laid out for VPCLMULQDQ-on-zmm consumption:
   --     zmm offset   0 : (H^16, H^15, H^14, H^13)
   --     zmm offset  64 : (H^12, H^11, H^10, H^9)
   --     zmm offset 128 : (H^8, H^7, H^6, H^5)
   --     zmm offset 192 : (H^4, H^3, H^2, H^1)
   subtype Pre_H_Powers_16 is Byte_Seq (0 .. 255);

   procedure Compute_H_Powers_16
     (H        : in     Bytes_16;
      H_Powers :    out Pre_H_Powers_16);

   --  S := ((S ^ B0) * H^16) ^ (B1 * H^15) ^ ... ^ (B15 * H)
   --  Performs 16 lane-parallel multiplies (16 vpclmulqdq instructions
   --  on zmm = 64 underlying 64×64 carry-less mults) + 1 reduction.
   procedure GHASH_16_Blocks
     (S        : in out Bytes_16;
      Blocks   : in     Byte_Seq;       --  exactly 256 bytes
      H_Powers : in     Pre_H_Powers_16);

end SPARKTLSCrypto.AES_GCM_AVX512;
