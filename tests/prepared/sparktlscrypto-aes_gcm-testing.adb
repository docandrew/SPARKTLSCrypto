package body SPARKTLSCrypto.AES_GCM.Testing is
   function Erased (Context : Prepared_Key) return Boolean is
     (not Context.Ready and not Context.Is_256 and not Context.Hardware
      and Context.Raw_Key = Bytes_32'(others => 0)
      and Context.Rounds = Byte_Seq'(0 .. 239 => 0)
      and Context.H = Bytes_16'(others => 0)
      and Context.Powers_4 = Byte_Seq'(0 .. 63 => 0)
      and Context.Powers_16 = Byte_Seq'(0 .. 255 => 0));
end SPARKTLSCrypto.AES_GCM.Testing;
