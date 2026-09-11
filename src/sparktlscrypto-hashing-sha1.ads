--  SPARKTLS SHA-1 -- identifier hashing ONLY (legacy, sunset 2030-12-31)
--
--  SCOPE RESTRICTION. This unit exists for one purpose: computing and
--  comparing the SHA-1 identifiers that RFC 6960 OCSP still uses on the
--  wire -- CertID.issuerNameHash / issuerKeyHash and the byKey
--  ResponderID KeyHash (RFC 6960 4.1.1, 4.2.1). Those are names for
--  public data (an issuer DN, an issuer SPKI), not integrity or
--  authentication values: the response that carries them is separately
--  signed, and SPARKTLS additionally binds the signer to the issuer
--  (Sparktls.Revocation). SHA-1 MUST NOT be used anywhere else in this
--  stack -- not for signatures, HMAC, KDFs or transcripts. There is
--  deliberately no HMAC-SHA1 and no signature algorithm that consumes it.
--
--  FIPS status (NIST SP 800-131A rev 2 / rev 3 draft): disallowed for
--  digital signature generation; legacy-use for signature verification;
--  deprecated through 2030-12-31 for hash-only / non-signature uses and
--  disallowed thereafter. Every FIPS 140-3 validated TLS module (OpenSSL
--  provider, AWS-LC / s2n, wolfSSL) ships SHA-1 for exactly this OCSP use.
--  Deployments that want to refuse SHA-1 CertIDs today set
--  SPARKTLS.Config.Allow_SHA1_CertID := False; the OCSP verifier then
--  never calls this unit. Plan: delete this unit once responders have
--  moved to SHA-256 CertIDs (RFC 6960 4.3 already permits them).
--
--  Timing: the inputs and outputs are public, so there is no secret to
--  leak; the algorithm's control flow depends only on the message length.
--
--  Correctness: tests/unit/test_sha1_cavp.adb runs the NIST CAVP SHAVS
--  byte-oriented vectors (SHA1ShortMsg, SHA1LongMsg, SHA1Monte).
--
--  API mirrors SPARKTLSCrypto.Hashing.SHA256. Pure software, fully SPARK.

with Interfaces;
with SPARKNaCl; use SPARKNaCl;

package SPARKTLSCrypto.Hashing.SHA1 with
   SPARK_Mode => On
is
   subtype Digest is Byte_Seq (0 .. 19);

   --------------------------------------------------------
   --  One-shot interface
   --------------------------------------------------------

   procedure Hash (Output : out Digest;
                   M      : in  Byte_Seq)
   with Global => null, Always_Terminates,
        Pre => M'Last < N32'Last - 128;

   function Hash (M : in Byte_Seq) return Digest
   with Global => null,
        Pre => M'Last < N32'Last - 128;

   --------------------------------------------------------
   --  Streaming (incremental) interface
   --------------------------------------------------------

   type Context is private;

   procedure Init (Ctx : out Context)
   with Global => null, Always_Terminates;

   procedure Update (Ctx : in out Context; Data : Byte_Seq)
   with Global => null, Always_Terminates,
        Pre => Data'Last < N32'Last - 128;

   procedure Final (Ctx : in out Context; Output : out Digest)
   with Global => null, Always_Terminates;

private
   type State_Array is array (0 .. 4) of Interfaces.Unsigned_32;

   --  FIPS 180-4 5.3.1 initial hash value; also the record default so a
   --  Context is a valid fresh hash from declaration (same reasoning as
   --  the SHA-256 unit).
   Init_State : constant State_Array :=
     (16#67452301#, 16#EFCDAB89#, 16#98BADCFE#, 16#10325476#, 16#C3D2E1F0#);

   type Context is record
      State    : State_Array   := Init_State;
      Buffer   : Byte_Seq (0 .. 63) := (others => 0);
      Buf_Len  : N32 range 0 .. 63 := 0;
      Total    : Interfaces.Unsigned_64 := 0;
   end record;

end SPARKTLSCrypto.Hashing.SHA1;
