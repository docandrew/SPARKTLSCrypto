--  SPARKTLS P-384 Point Arithmetic for ECDHE
--
--  Provides scalar multiplication on the P-384 curve
--  for key exchange.  Reuses Big_Int infrastructure from RSA.

with SPARKNaCl;                use SPARKNaCl;
with SPARKTLSCrypto.BigNat64;
with SPARKTLSCrypto.P384.Field;

package SPARKTLSCrypto.P384.Point with
   SPARK_Mode => On
is
   --  Generate public key from private scalar:
   --  Computes [SK] * G and encodes as 97-byte uncompressed point (04 || X || Y).
   procedure P384_Mulgen
     (PK_Out : out Byte_Seq;
      SK     : in  Byte_Seq)
   with Pre => PK_Out'First = 0 and PK_Out'Length = 97
               and SK'First = 0 and SK'Length = 48
               and Field.Initialized;

   --  ECDHE shared secret:
   --  Computes x-coordinate of [SK] * Peer_PK.
   --  Peer_PK is 97-byte uncompressed point.
   --  Returns 48-byte x-coordinate in Secret, OK = True on success.
   procedure P384_ECDHE
     (Secret  :    out Bytes_48;
      OK      :    out Boolean;
      SK      : in     Byte_Seq;
      Peer_PK : in     Byte_Seq)
   with Pre => SK'First = 0 and SK'Length = 48
               and Peer_PK'First = 0 and Peer_PK'Length = 97
               and Field.Initialized;

   --  Public-key validation (SEC 1 3.2.2.1): x < p, y < p and
   --  y^2 = x^3 - 3x + b. All-ones when valid, all-zeros otherwise,
   --  computed without branching on the coordinates so ECDSA verify can
   --  fold it into a constant-time verdict. Rejects the encoding of the
   --  point at infinity as a side effect (0, 0 is not on the curve).
   function P384_Public_Key_Valid_Mask
     (Qx, Qy : Byte_Seq) return SPARKTLSCrypto.BigNat64.Word
   with Pre => Qx'Length = 48 and Qy'Length = 48 and Field.Initialized;

   --  Blinded forms for secret scalars: the P-384 counterpart of the
   --  P-256 entries in SPARKTLSCrypto.P256.Point. Blind is Blind_Len
   --  fresh random bytes from the caller's CSPRNG: bytes 0 .. 7 give r,
   --  and the scalar the ladder walks is k + r * n (448 bits, the same
   --  point with different ladder bits every time); bytes 8 .. 55 give
   --  lambda, and the input point's projective representation is
   --  randomised (X lambda^2, Y lambda^3, Z lambda) before the ladder,
   --  so no intermediate coordinate is a function of the key alone. A
   --  lambda that is zero or not below p is replaced by one (unblinded
   --  coordinates, still correct). The results equal those of the
   --  unblinded entries; the smoke tests check it.
   Blind_Len : constant := 56;

   procedure Scalar_Mul_Blinded
     (P_Pt  : in out Field.Jacobian;
      K     : in     Byte_Seq;
      Blind : in     Byte_Seq)
   with Pre  => K'First = 0 and K'Length = 48
                and Blind'First = 0 and Blind'Length = Blind_Len
                and P_Pt.X.Len = Field.W384 and P_Pt.Y.Len = Field.W384
                and P_Pt.Z.Len = Field.W384
                and Field.Initialized,
        Post => P_Pt.X.Len = Field.W384 and P_Pt.Y.Len = Field.W384
                and P_Pt.Z.Len = Field.W384;

   procedure P384_Mulgen_Blinded
     (PK_Out : out Byte_Seq;
      SK     : in  Byte_Seq;
      Blind  : in  Byte_Seq)
   with Pre => PK_Out'First = 0 and PK_Out'Length = 97
               and SK'First = 0 and SK'Length = 48
               and Blind'First = 0 and Blind'Length = Blind_Len
               and Field.Initialized;

   procedure P384_ECDHE_Blinded
     (Secret  :    out Bytes_48;
      OK      :    out Boolean;
      SK      : in     Byte_Seq;
      Peer_PK : in     Byte_Seq;
      Blind   : in     Byte_Seq)
   with Pre => SK'First = 0 and SK'Length = 48
               and Peer_PK'First = 0 and Peer_PK'Length = 97
               and Blind'First = 0 and Blind'Length = Blind_Len
               and Field.Initialized;

end SPARKTLSCrypto.P384.Point;
