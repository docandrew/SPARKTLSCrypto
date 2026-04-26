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

end SPARKTLSCrypto.P256.ECDSA;
