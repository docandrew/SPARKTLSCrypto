--  SPARKTLS ECDSA P-256 Signature Verification and Signing
--  Ported from BearSSL (Thomas Pornin, MIT license)

with SPARKNaCl; use SPARKNaCl;

package SPARKTLSCrypto.P256.ECDSA with
   SPARK_Mode => On
is
   subtype ECDSA_Sig_Half is Byte_Seq (0 .. 31);

   function Verify
     (Hash : in Bytes_32;
      Qx   : in ECDSA_Sig_Half;
      Qy   : in ECDSA_Sig_Half;
      R    : in ECDSA_Sig_Half;
      S    : in ECDSA_Sig_Half) return Boolean;

   procedure Sign
     (Hash  : in     Bytes_32;
      D     : in     ECDSA_Sig_Half;
      K     : in     ECDSA_Sig_Half;
      R_Out :    out ECDSA_Sig_Half;
      S_Out :    out ECDSA_Sig_Half;
      OK    :    out Boolean);

   --  Test helpers (byte-level interface for unit testing).
   --  R_Bytes is filled element-by-element via Scalar_To_Bytes; flow
   --  analysis can't see the slice writes compose, so use Relaxed_Init.
   procedure Test_Mul_Mod_N
     (A_Bytes : in  ECDSA_Sig_Half;
      B_Bytes : in  ECDSA_Sig_Half;
      R_Bytes : out ECDSA_Sig_Half)
   with Relaxed_Initialization => R_Bytes, Post => R_Bytes'Initialized;

   procedure Test_Inv_Mod_N
     (A_Bytes : in  ECDSA_Sig_Half;
      R_Bytes : out ECDSA_Sig_Half)
   with Relaxed_Initialization => R_Bytes, Post => R_Bytes'Initialized;

   procedure Test_Add_Mod_N
     (A_Bytes : in  ECDSA_Sig_Half;
      B_Bytes : in  ECDSA_Sig_Half;
      R_Bytes : out ECDSA_Sig_Half)
   with Relaxed_Initialization => R_Bytes, Post => R_Bytes'Initialized;

   procedure Test_Sqr_Mod_N
     (A_Bytes : in  ECDSA_Sig_Half;
      R_Bytes : out ECDSA_Sig_Half)
   with Relaxed_Initialization => R_Bytes, Post => R_Bytes'Initialized;

private
   type Scalar_64 is array (0 .. 3) of Unsigned_64;
   type Scalar_Wide is array (0 .. 7) of Unsigned_64;

   procedure P256_Muladd_32
     (A  : in out Byte_Seq;
      X  : in     ECDSA_Sig_Half;
      Y  : in     ECDSA_Sig_Half;
      OK :    out U32)
   with Pre => A'First = 0 and then A'Length = 65;

   procedure Bytes_To_Scalar
     (D   : out Scalar_64;
      Src : in  ECDSA_Sig_Half);

   procedure Scalar_To_Bytes
     (Dst : out ECDSA_Sig_Half;
      Src : in  Scalar_64)
   with Relaxed_Initialization => Dst, Post => Dst'Initialized;

   procedure Mul_Wide
     (D    : out Scalar_Wide;
      A, B : in  Scalar_64);

   procedure Sqr_Wide
     (D : out Scalar_Wide;
      A : in  Scalar_64);

   procedure Sub_Scalar
     (D      : out Scalar_64;
      A, B   : in  Scalar_64;
      Borrow : out Unsigned_64);

   procedure Barrett_Reduce
     (D : out Scalar_64;
      T : in  Scalar_Wide);

   procedure Mul_Mod_N
     (D    : out Scalar_64;
      A, B : in  Scalar_64);

   procedure Square_Mod_N
     (D : out Scalar_64;
      A : in  Scalar_64);

   procedure Add_Mod_N
     (D    : out Scalar_64;
      A, B : in  Scalar_64);

   procedure Inv_Mod_N
     (D : out Scalar_64;
      A : in  Scalar_64);

   function Is_Zero_Scalar (A : Scalar_64) return Boolean;

   function Less_Than_Order (A : Scalar_64) return Boolean;

   procedure Reduce_Once (A : in out Scalar_64);

end SPARKTLSCrypto.P256.ECDSA;
