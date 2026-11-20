package SPARKTLSCrypto.AES_GCM.Testing is
   function Erased (Context : Prepared_Key) return Boolean;
   --  Self_Test with byte Flip of its known-answer data altered.
   procedure Self_Test_Altered (Flip : N32; OK : out Boolean);
   KAT_Bytes : constant := 906;
   --  The bytes of the two CAVP FAIL vectors (AES-128, then AES-256) in
   --  the known-answer data. Altering one gives another forgery, which
   --  must still be rejected, so the self-test must still pass.
   function Fail_Vector_Byte (Flip : N32) return Boolean is
     (Flip in 236 .. 420 | 689 .. 889);
end SPARKTLSCrypto.AES_GCM.Testing;
