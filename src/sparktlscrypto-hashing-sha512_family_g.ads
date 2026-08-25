--  FIPS 180-4 SHA-512 family — generic streaming core (2026-08-25).
--
--  SHA-384 and SHA-512 share the identical 128-byte-block compression
--  function and differ only in initial hash value and output length,
--  so the whole streaming machine lives here once and each digest is
--  a thin instantiation (user call: "combine the 512 and 384").
--  Correctness of each instance is pinned by NIST KATs in
--  tests/unit/test_sha384_streaming_kat.adb (both digests, split-point
--  sweeps, SPARKNaCl cross-checks where a reference exists).

with Interfaces;
with SPARKNaCl; use SPARKNaCl;

generic
   Digest_Bytes : N32;                       --  48 (SHA-384) or 64 (SHA-512)
   IV0, IV1, IV2, IV3 : Interfaces.Unsigned_64;
   IV4, IV5, IV6, IV7 : Interfaces.Unsigned_64;
package SPARKTLSCrypto.Hashing.SHA512_Family_G with
   SPARK_Mode => On
is
   subtype Digest is Byte_Seq (0 .. Digest_Bytes - 1);

   procedure Hash (Output : out Digest;
                   M      : in  Byte_Seq)
   with Global => null, Always_Terminates,
        Pre => M'First >= 0 and then M'Last < N32'Last - 256;

   function Hash (M : in Byte_Seq) return Digest
   with Global => null, Pre => M'First >= 0 and then M'Last < N32'Last - 256;

   type Context is private;

   procedure Init (Ctx : out Context)
   with Global => null, Always_Terminates;

   procedure Update (Ctx : in out Context; Data : Byte_Seq)
   with Global => null, Always_Terminates,
        Pre => Data'First >= 0 and then Data'Last < N32'Last - 256;

   procedure Final (Ctx : in out Context; Output : out Digest)
   with Global => null, Always_Terminates;

private
   type State_Array is array (0 .. 7) of Interfaces.Unsigned_64;

   --  Instance IV doubles as the record default: a Context is a valid
   --  fresh hash from the moment it exists (see SHA256.Context note).
   Init_State : constant State_Array :=
     (IV0, IV1, IV2, IV3, IV4, IV5, IV6, IV7);

   type Context is record
      State   : State_Array   := Init_State;
      Buffer  : Byte_Seq (0 .. 127) := (others => 0);
      Buf_Len : N32 range 0 .. 127 := 0;
      Total   : Interfaces.Unsigned_64 := 0;
   end record;

end SPARKTLSCrypto.Hashing.SHA512_Family_G;
