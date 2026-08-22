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
   N : constant Big_Nat :=
     (Len => Field.W384,
      W   => (16#CCC52973#, 16#ECEC196A#, 16#48B0A77A#, 16#581A0DB2#,
              16#F4372DDF#, 16#C7634D81#, 16#FFFFFFFF#, 16#FFFFFFFF#,
              16#FFFFFFFF#, 16#FFFFFFFF#, 16#FFFFFFFF#, 16#FFFFFFFF#,
              others => 0));
   N_M0I : constant Word := 16#E88FDC45#;

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
               and S'First = 0 and S'Length = 48;

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
                  and S_Out'First = 0 and S_Out'Length = 48;

   --  Compute public key Q = d * G. Returns uncompressed point (Qx, Qy).
   procedure Public_Key
     (D  : in     Byte_Seq;
      Qx :    out Byte_Seq;
      Qy :    out Byte_Seq)
   with Pre => D'First = 0 and D'Length = 48
               and Qx'First = 0 and Qx'Length = 48
               and Qy'First = 0 and Qy'Length = 48;

end SPARKTLSCrypto.P384.ECDSA;
