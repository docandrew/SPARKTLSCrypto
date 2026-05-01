with SPARKNaCl;     use SPARKNaCl;
with SPARKNaCl.AES;

--  AES-GCM Authenticated Encryption with Associated Data
--
--  Implements AES-GCM (Galois/Counter Mode) per NIST SP 800-38D,
--  built on top of SPARKNaCl.AES block cipher.
--  Supports both AES-128 and AES-256 key sizes.
--  Nonce: 12 bytes (96 bits) as required by TLS 1.3.
--  Tag: 16 bytes (128 bits).
package SPARKTLSCrypto.AES_GCM with
   SPARK_Mode => On
is
   --================================================================
   --  AES-128-GCM
   --================================================================

   procedure Encrypt
     (C       :    out Byte_Seq;
      Tag     :    out Bytes_16;
      M       : in     Byte_Seq;
      N       : in     Bytes_12;
      K       : in     AES.AES128_Key;
      AAD     : in     Byte_Seq)
   with Pre => M'First  = 0 and then
               C'First  = 0 and then
               AAD'First = 0 and then
               C'Last   = M'Last and then
               C'Length  = M'Length and then
               M'Last   < N32'Last and then
               AAD'Last < N32'Last;

   --  In-place AEAD: Buf holds the plaintext on entry and the
   --  ciphertext on exit (XOR-with-keystream is in-place safe for
   --  CTR mode).  Buf may have any First; the body indexes through
   --  Buf'First + offset.  Lets callers (sparktls record layer)
   --  encrypt directly into the destination Output buffer slice and
   --  skip the intermediate Ciphertext allocation + 16 KB copy.
   procedure Encrypt_InPlace
     (Buf : in out Byte_Seq;
      Tag :    out Bytes_16;
      N   : in     Bytes_12;
      K   : in     AES.AES128_Key;
      AAD : in     Byte_Seq)
   with Pre => AAD'First = 0
               and Buf'Length > 0
               and Buf'Last < N32'Last
               and AAD'Last < N32'Last;

   procedure Decrypt
     (M       :    out Byte_Seq;
      Status  :    out Boolean;
      Tag     : in     Bytes_16;
      C       : in     Byte_Seq;
      N       : in     Bytes_12;
      K       : in     AES.AES128_Key;
      AAD     : in     Byte_Seq)
   with Pre => M'First  = 0 and then
               C'First  = 0 and then
               AAD'First = 0 and then
               M'Last   = C'Last and then
               M'Length  = C'Length and then
               C'Last   < N32'Last and then
               AAD'Last < N32'Last;

   --================================================================
   --  AES-256-GCM
   --================================================================

   procedure Encrypt_256
     (C       :    out Byte_Seq;
      Tag     :    out Bytes_16;
      M       : in     Byte_Seq;
      N       : in     Bytes_12;
      K       : in     AES.AES256_Key;
      AAD     : in     Byte_Seq)
   with Pre => M'First  = 0 and then
               C'First  = 0 and then
               AAD'First = 0 and then
               C'Last   = M'Last and then
               C'Length  = M'Length and then
               M'Last   < N32'Last and then
               AAD'Last < N32'Last;

   --  In-place AES-256-GCM AEAD; see Encrypt_InPlace above.
   procedure Encrypt_InPlace_256
     (Buf : in out Byte_Seq;
      Tag :    out Bytes_16;
      N   : in     Bytes_12;
      K   : in     AES.AES256_Key;
      AAD : in     Byte_Seq)
   with Pre => AAD'First = 0
               and Buf'Length > 0
               and Buf'Last < N32'Last
               and AAD'Last < N32'Last;

   procedure Decrypt_256
     (M       :    out Byte_Seq;
      Status  :    out Boolean;
      Tag     : in     Bytes_16;
      C       : in     Byte_Seq;
      N       : in     Bytes_12;
      K       : in     AES.AES256_Key;
      AAD     : in     Byte_Seq)
   with Pre => M'First  = 0 and then
               C'First  = 0 and then
               AAD'First = 0 and then
               M'Last   = C'Last and then
               M'Length  = C'Length and then
               C'Last   < N32'Last and then
               AAD'Last < N32'Last;

end SPARKTLSCrypto.AES_GCM;
