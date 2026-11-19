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
   --  Per-key preparation for repeated in-place encryption. The context
   --  owns no nonce or record counter. Call Prepare again when installing
   --  a different key, and Clear before releasing the context.
   --  Hardware round keys and GHASH powers are reused on supported CPUs;
   --  the portable path retains the existing one-shot implementation.
   --  Encrypt_Prepared and Decrypt_Prepared both use the context.
   type Prepared_Key is private;

   Unprepared_Key : constant Prepared_Key;

   function Is_Prepared (Context : Prepared_Key) return Boolean;

   procedure Prepare_128
     (Context : out Prepared_Key; K : in AES.AES128_Key)
   with Post => Is_Prepared (Context);

   procedure Prepare_256
     (Context : out Prepared_Key; K : in AES.AES256_Key)
   with Post => Is_Prepared (Context);

   procedure Clear (Context : out Prepared_Key)
   with Post => not Is_Prepared (Context);

   procedure Encrypt_Prepared
     (Buf     : in out Byte_Seq;
      Tag     : out Bytes_16;
      N       : in Bytes_12;
      Context : in Prepared_Key;
      AAD     : in Byte_Seq)
   with Pre => Is_Prepared (Context)
               and AAD'First = 0
               and Buf'Length > 0
               and Buf'Last < N32'Last
               and AAD'Last < N32'Last;

   --  In-place authenticated decryption with a prepared key. Buf holds
   --  the ciphertext on entry. If Tag authenticates (N, AAD, Buf), Status
   --  is True and Buf holds the plaintext; otherwise Status is False and
   --  every byte of Buf is zero, so no unauthenticated plaintext escapes.
   --
   --  Constant time: the tag comparison covers all 16 bytes without an
   --  early exit, and the plaintext is released or zeroed by masking the
   --  whole buffer, so the work done (instructions, branches and memory
   --  addresses) does not depend on the key, the data or whether the tag
   --  matched; only Status does. An empty Buf authenticates AAD alone.
   procedure Decrypt_Prepared
     (Buf     : in out Byte_Seq;
      Status  :    out Boolean;
      Tag     : in     Bytes_16;
      N       : in     Bytes_12;
      Context : in     Prepared_Key;
      AAD     : in     Byte_Seq)
   with Pre  => Is_Prepared (Context)
                and AAD'First = 0
                and Buf'Last < N32'Last
                and AAD'Last < N32'Last,
        Post => (if not Status then (for all I in Buf'Range => Buf (I) = 0));

   ----------------------------------------------------------------------------
   --  AES-128-GCM
   ----------------------------------------------------------------------------

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

   --  One-shot in-place decryption: Decrypt_Prepared with a context
   --  prepared for K and cleared before returning. Same contract.
   procedure Decrypt_InPlace
     (Buf    : in out Byte_Seq;
      Status :    out Boolean;
      Tag    : in     Bytes_16;
      N      : in     Bytes_12;
      K      : in     AES.AES128_Key;
      AAD    : in     Byte_Seq)
   with Pre  => AAD'First = 0
                and Buf'Last < N32'Last
                and AAD'Last < N32'Last,
        Post => (if not Status then (for all I in Buf'Range => Buf (I) = 0));

   procedure Verify_Empty_Ciphertext
     (Status  :    out Boolean;
      Tag     : in     Bytes_16;
      N       : in     Bytes_12;
      K       : in     AES.AES128_Key;
      AAD     : in     Byte_Seq)
   with Pre => AAD'First = 0 and then
               AAD'Length > 0 and then
               AAD'Last < N32'Last;

   ----------------------------------------------------------------------------
   --  AES-256-GCM
   ----------------------------------------------------------------------------

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

   --  One-shot in-place AES-256-GCM decryption; see Decrypt_InPlace.
   procedure Decrypt_InPlace_256
     (Buf    : in out Byte_Seq;
      Status :    out Boolean;
      Tag    : in     Bytes_16;
      N      : in     Bytes_12;
      K      : in     AES.AES256_Key;
      AAD    : in     Byte_Seq)
   with Pre  => AAD'First = 0
                and Buf'Last < N32'Last
                and AAD'Last < N32'Last,
        Post => (if not Status then (for all I in Buf'Range => Buf (I) = 0));

   procedure Verify_Empty_Ciphertext_256
     (Status  :    out Boolean;
      Tag     : in     Bytes_16;
      N       : in     Bytes_12;
      K       : in     AES.AES256_Key;
      AAD     : in     Byte_Seq)
   with Pre => AAD'First = 0 and then
               AAD'Length > 0 and then
               AAD'Last < N32'Last;

private
   type Prepared_Key is record
      Ready    : Boolean := False;
      Is_256   : Boolean := False;
      Hardware : Boolean := False;
      --  Raw key supports the portable fallback. AES128 uses only 0..15.
      Raw_Key  : Bytes_32 := (others => 0);
      Rounds   : Byte_Seq (0 .. 239) := (others => 0);
      H        : Bytes_16 := (others => 0);
      Powers_4 : Byte_Seq (0 .. 63) := (others => 0);
      --  H^32 .. H^1 byte-reversed (Compute_H_Powers_32, body) on CPUs
      --  with a VAES tier; bytes 256 .. 511 are the sixteen-power table.
      Powers_32 : Byte_Seq (0 .. 511) := (others => 0);
   end record;

   Unprepared_Key : constant Prepared_Key := (others => <>);

   function Is_Prepared (Context : Prepared_Key) return Boolean
   is (Context.Ready);
end SPARKTLSCrypto.AES_GCM;
