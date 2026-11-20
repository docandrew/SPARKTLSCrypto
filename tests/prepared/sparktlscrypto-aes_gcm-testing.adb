package body SPARKTLSCrypto.AES_GCM.Testing is
   function Erased (Context : Prepared_Key) return Boolean is
     (not Context.Ready and not Context.Is_256 and not Context.Hardware
      and Context.Raw_Key = Bytes_32'(others => 0)
      and Context.Rounds = Byte_Seq'(0 .. 239 => 0)
      and Context.H = Bytes_16'(others => 0)
      and Context.Powers_4 = Byte_Seq'(0 .. 63 => 0)
      and Context.Powers_32 = Byte_Seq'(0 .. 511 => 0));
   procedure Self_Test_Altered (Flip : N32; OK : out Boolean) is
   begin
      Self_Test_With (Flip, OK);
   end Self_Test_Altered;
end SPARKTLSCrypto.AES_GCM.Testing;
