--  SPARKTLS ECDSA P-384 Signature Verification and Signing
--  Uses SPARK-proven BigNat for group order arithmetic.

with SPARKNaCl;                use SPARKNaCl;
with SPARKTLSCrypto.BigNat;     use SPARKTLSCrypto.BigNat;
with SPARKTLSCrypto.P384.Field;

package SPARKTLSCrypto.P384.ECDSA with
   SPARK_Mode        => On,
   Initializes       => (N, N_M0I),
   Initial_Condition => N.Len = 12
is
   pragma Elaborate_Body;
   --  Group order N of P-384 (initialized at elaboration). Exposed so
   --  Initial_Condition can reference it; effectively private (clients
   --  should not touch it).
   N     : Big_Nat with Constant_After_Elaboration;
   N_M0I : Word    with Constant_After_Elaboration;

   --  Ghost predicate; mirrors Initialized in Field. SPARK's
   --  Initial_Condition only fires at program start, not at each
   --  subprogram entry — so callers must include this in their Pre.
   function Initialized return Boolean is (N.Len = 12)
     with Ghost;

   function Verify
     (Hash : in Bytes_48;
      Qx   : in Byte_Seq;
      Qy   : in Byte_Seq;
      R    : in Byte_Seq;
      S    : in Byte_Seq) return Boolean
   with Pre => Qx'First = 0 and Qx'Length = 48
               and Qy'First = 0 and Qy'Length = 48
               and R'First = 0 and R'Length = 48
               and S'First = 0 and S'Length = 48
               and Field.Initialized and Initialized;

   procedure Sign
     (Hash  : in     Bytes_48;
      D     : in     Byte_Seq;
      K     : in     Byte_Seq;
      R_Out :    out Byte_Seq;
      S_Out :    out Byte_Seq;
      OK    :    out Boolean)
   with Pre    => D'First = 0 and D'Length = 48
                  and K'First = 0 and K'Length = 48
                  and R_Out'First = 0 and R_Out'Length = 48
                  and S_Out'First = 0 and S_Out'Length = 48
                  and Field.Initialized and Initialized;

   --  Compute public key Q = d * G. Returns uncompressed point (Qx, Qy).
   procedure Public_Key
     (D  : in     Byte_Seq;
      Qx :    out Byte_Seq;
      Qy :    out Byte_Seq)
   with Pre => D'First = 0 and D'Length = 48
               and Qx'First = 0 and Qx'Length = 48
               and Qy'First = 0 and Qy'Length = 48
               and Field.Initialized and Initialized;

end SPARKTLSCrypto.P384.ECDSA;
