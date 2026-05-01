--  AVX-512 ChaCha20 (RFC 8439) — 16-block parallel keystream + XOR.
--
--  Computes 16 ChaCha20 keystream blocks (1024 bytes total) in
--  parallel using AVX-512 zmm registers. Lane-major layout: each
--  zmm holds the same state word across 16 streams. After 20 rounds
--  we transpose 16×16 to stream-major and XOR into Buf in place.
--
--  Same shape as Cipher_*_VAES_XOR for AES — fully fused encrypt-
--  and-XOR inside one asm block.
--
--  CPUID-gated by AVX-512F (vprold + vpunpck on zmm).

with SPARKNaCl;     use SPARKNaCl;
with Interfaces;    use Interfaces;

package SPARKTLSCrypto.ChaCha20_AVX512 with
   SPARK_Mode => On,
   Elaborate_Body
is
   --  True iff the running CPU advertises AVX-512F.
   Has_AVX512_ChaCha20 : Boolean := False with Constant_After_Elaboration;

   --  Buf must be exactly 1024 bytes. Caller advances the counter by
   --  16 after each call.
   procedure Encrypt_1024_InPlace
     (Buf     : in out Byte_Seq;
      K       : in     Bytes_32;
      N       : in     Bytes_12;
      Counter : in     Unsigned_32);

end SPARKTLSCrypto.ChaCha20_AVX512;
