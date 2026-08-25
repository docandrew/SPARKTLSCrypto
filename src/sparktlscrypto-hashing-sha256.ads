--  SPARKTLS SHA-256 — Hardware-accelerated when available
--
--  Uses SHA-NI instructions (x86) when detected at elaboration.
--  Streaming and one-shot software hashing fall back to a SPARKNaCl-derived
--  block implementation when SHA-NI is unavailable.
--
--  API mirrors SPARKNaCl.Hashing.SHA256 for drop-in replacement.

with Interfaces;
with SPARKNaCl; use SPARKNaCl;

package SPARKTLSCrypto.Hashing.SHA256 with
   SPARK_Mode => On,
   Elaborate_Body
is
   subtype Digest is Bytes_32;

   --------------------------------------------------------
   --  One-shot interface
   --------------------------------------------------------

   procedure Hash (Output : out Digest;
                   M      : in  Byte_Seq)
   with Global => null, Always_Terminates,
        Pre => M'First >= 0 and then M'Last < N32'Last - 128;

   function Hash (M : in Byte_Seq) return Digest
   with Global => null,
        Pre => M'First >= 0 and then M'Last < N32'Last - 128;

   --------------------------------------------------------
   --  Streaming (incremental) interface
   --------------------------------------------------------

   type Context is private;

   procedure Init (Ctx : out Context)
   with Global => null, Always_Terminates;

   procedure Update (Ctx : in out Context; Data : Byte_Seq)
   with Global => null, Always_Terminates,
        Pre => Data'First >= 0 and then Data'Last < N32'Last - 128;

   procedure Final (Ctx : in out Context; Output : out Digest)
   with Global => null, Always_Terminates;

   --------------------------------------------------------
   --  Hardware detection
   --------------------------------------------------------

   function Has_HW_Accel return Boolean
   with Global => null;

private
   type State_Array is array (0 .. 7) of Interfaces.Unsigned_32
   with Alignment => 16;

   --  FIPS 180-4 5.3.3 initial hash value. Also the record default:
   --  a Context object is a valid fresh hash from the moment it is
   --  declared or allocated, so a missed Init cannot yield an
   --  uninitialized state (found the hard way: the streamed transcript
   --  crashed on heap residue, 2026-08-25).
   Init_State : constant State_Array :=
     (16#6A09E667#, 16#BB67AE85#, 16#3C6EF372#, 16#A54FF53A#,
      16#510E527F#, 16#9B05688C#, 16#1F83D9AB#, 16#5BE0CD19#);

   type Context is record
      State    : State_Array   := Init_State;
      Buffer   : Byte_Seq (0 .. 63) := (others => 0);
      Buf_Len  : N32 range 0 .. 63 := 0;
      Total    : Interfaces.Unsigned_64 := 0;
   end record;

end SPARKTLSCrypto.Hashing.SHA256;
