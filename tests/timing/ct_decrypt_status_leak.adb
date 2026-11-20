--  Negative control for ct_decrypt_prepared: the same secret inputs, but
--  the harness branches on Status before declassifying it, and on one
--  plaintext byte, exactly what a library that skipped the zeroing on
--  success (or released plaintext early) would do. memcheck MUST report
--  the conditional jumps; if it does not, the taint is not reaching the
--  tag comparison and ct_decrypt_prepared proves nothing.

with Ada.Text_IO; use Ada.Text_IO;
with Interfaces; use Interfaces;
with Interfaces.C;
with SPARKNaCl; use SPARKNaCl;
with SPARKNaCl.AES;
with SPARKTLSCrypto.AES_GCM; use SPARKTLSCrypto.AES_GCM;
with Ctgrind;

procedure Ct_Decrypt_Status_Leak is
   Key   : Bytes_32 := (others => 42);
   Nonce : constant Bytes_12 := (others => 17);
   AAD   : constant Byte_Seq (0 .. 12) := (others => 19);
   Buf   : Byte_Seq (0 .. 1023) := (others => 37);
   Tag   : Bytes_16;
   Status : Boolean;
   Context : Prepared_Key;
   K128 : AES.AES128_Key;
   Sink : Natural := 0;
begin
   Ctgrind.Make_Undefined (Key'Address, Interfaces.C.size_t (Key'Length));
   AES.Construct (K128, Key (0 .. 15));
   Prepare_128 (Context, K128);
   Encrypt_Prepared (Buf, Tag, Nonce, Context, AAD);
   Decrypt_Prepared (Buf, Status, Tag, Nonce, Context, AAD);
   if Status then          --  deliberately leaky: Status not declassified
      Sink := Sink + 1;
   end if;
   if Buf (0) > 16#80# then  --  deliberately leaky: secret plaintext
      Sink := Sink + 2;
   end if;
   Ctgrind.Make_Defined (Sink'Address, Interfaces.C.size_t (Sink'Size / 8));
   Ctgrind.Use_Output (Sink'Address, Interfaces.C.size_t (Sink'Size / 8));
   Clear (Context);
   Put_Line ("ct_decrypt_status_leak: done");
end Ct_Decrypt_Status_Leak;
