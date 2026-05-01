--  AES block-cipher dispatcher body.
--
--  Routes to SPARKTLSCrypto.AES_NI (CPUID-gated AES-NI, SPARK_Mode Off)
--  when available, otherwise SPARKNaCl.AES.Cipher (formally proven).

with SPARKTLSCrypto.AES_NI;

package body SPARKTLSCrypto.AES_Dispatch with
   SPARK_Mode => On
is

   procedure Cipher
     (Output     :    out Bytes_16;
      Input      : in     Bytes_16;
      Round_Keys : in     SPARKNaCl.AES.AES128_Round_Keys)
   is
   begin
      if SPARKTLSCrypto.AES_NI.Has_AESNI then
         SPARKTLSCrypto.AES_NI.Cipher_128 (Output, Input, Round_Keys);
      else
         SPARKNaCl.AES.Cipher (Output, Input, Round_Keys);
      end if;
   end Cipher;

   procedure Cipher
     (Output     :    out Bytes_16;
      Input      : in     Bytes_16;
      Round_Keys : in     SPARKNaCl.AES.AES256_Round_Keys)
   is
   begin
      if SPARKTLSCrypto.AES_NI.Has_AESNI then
         SPARKTLSCrypto.AES_NI.Cipher_256 (Output, Input, Round_Keys);
      else
         SPARKNaCl.AES.Cipher (Output, Input, Round_Keys);
      end if;
   end Cipher;

end SPARKTLSCrypto.AES_Dispatch;
