with Ada.Text_IO; use Ada.Text_IO;
with Interfaces; use Interfaces;
with Interfaces.C;
with SPARKNaCl; use SPARKNaCl;
with SPARKNaCl.AES;
with SPARKTLSCrypto.AES_GCM; use SPARKTLSCrypto.AES_GCM;
with SPARKTLSCrypto.AES_NI;
with SPARKTLSCrypto.AES_GCM_AVX512;
with Ctgrind;
procedure Ct_Prepared is
   Key : Bytes_32 := (others => 42);
   Nonce : constant Bytes_12 := (others => 17);
   AAD : constant Byte_Seq (0 .. 4) := (others => 19);
   Buf : Byte_Seq (0 .. 16384) := (others => 37);
   Tag : Bytes_16;
   Context : Prepared_Key;
   K128 : AES.AES128_Key;
   K256 : AES.AES256_Key;
begin
   Put_Line ("AESNI=" & SPARKTLSCrypto.AES_NI.Has_AESNI'Image &
             " AVX512=" & SPARKTLSCrypto.AES_GCM_AVX512.Has_AVX512_AES_GCM'Image);
   Ctgrind.Make_Undefined (Key'Address, Interfaces.C.size_t (Key'Length));
   AES.Construct (K128, Key (0 .. 15)); AES.Construct (K256, Key);
   for Bits in 1 .. 2 loop
      if Bits = 1 then Prepare_128 (Context, K128);
      else Prepare_256 (Context, K256); end if;
      --  Context remains tainted across repeated use, including each tail.
      for Len in 1 .. 257 loop
         Encrypt_Prepared (Buf (0 .. N32 (Len - 1)), Tag, Nonce, Context, AAD);
      end loop;
      Encrypt_Prepared (Buf, Tag, Nonce, Context, AAD);
      Ctgrind.Make_Defined (Buf'Address, Interfaces.C.size_t (Buf'Length));
      Ctgrind.Make_Defined (Tag'Address, Interfaces.C.size_t (Tag'Length));
      Ctgrind.Use_Output (Buf'Address, Interfaces.C.size_t (Buf'Length));
      Ctgrind.Use_Output (Tag'Address, Interfaces.C.size_t (Tag'Length));
      Clear (Context);
   end loop;
   AES.Sanitize (K128); AES.Sanitize (K256);
   Put_Line ("PASS: prepared AES-GCM with secret-key taint");
end Ct_Prepared;
