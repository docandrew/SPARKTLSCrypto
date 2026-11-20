--  Constant-time check for Decrypt_Prepared and Decrypt_InPlace(_256).
--
--  Everything but the lengths is marked secret (undefined to memcheck):
--  the key, nonce, AAD, ciphertext and tag. An authentic record (its tag
--  computed under the secret key, so itself secret) and a forged one are
--  decrypted at every length 0 .. 300, the stripe boundaries and one TLS
--  record, for both key sizes, on every tier Valgrind's CPU exposes
--  (the portable code always). Status is declassified only after each
--  call returns: it is the one result allowed to depend on the tag. Any
--  branch, index or address computed from secret data inside the library
--  is a memcheck error.
--
--  ct_decrypt_status_leak is the negative control for this harness.

with Ada.Text_IO; use Ada.Text_IO;
with Interfaces; use Interfaces;
with Interfaces.C;
with SPARKNaCl; use SPARKNaCl;
with SPARKNaCl.AES;
with SPARKTLSCrypto.AES_GCM; use SPARKTLSCrypto.AES_GCM;
with Ctgrind;
with Gcm_Tiers; use Gcm_Tiers;

procedure Ct_Decrypt_Prepared is
   Key   : Bytes_32 := (others => 42);
   Nonce : Bytes_12 := (others => 17);
   AAD   : Byte_Seq (0 .. 12) := (others => 19);
   Plain : Byte_Seq (0 .. 16_384) := (others => 37);
   Buf   : Byte_Seq (0 .. 16_384);
   Tag, Forged : Bytes_16;
   Status : Boolean;
   Context : Prepared_Key;
   K128 : AES.AES128_Key;
   K256 : AES.AES256_Key;
   Decryptions : Natural := 0;

   procedure Secret (X : in out Byte_Seq) is
   begin
      Ctgrind.Make_Undefined (X'Address, Interfaces.C.size_t (X'Length));
   end Secret;

   procedure Release (Len : N32) is
   begin
      Ctgrind.Make_Defined (Status'Address, Interfaces.C.size_t (1));
      Ctgrind.Make_Defined (Buf'Address, Interfaces.C.size_t (Len));
      Ctgrind.Use_Output (Buf'Address, Interfaces.C.size_t (Len));
      if Status then
         Decryptions := Decryptions + 1;
      end if;
   end Release;

   procedure Run (Bits : Positive; Len : N32) is
      Last : constant I32 := I32 (Len) - 1;
   begin
      --  Authentic record: encrypt under the secret key.
      Buf (0 .. Last) := Plain (0 .. Last);
      if Len > 0 then
         Encrypt_Prepared (Buf (0 .. Last), Tag, Nonce, Context, AAD);
      else
         Tag := (others => 0);
      end if;
      declare
         CT : constant Byte_Seq := Buf (0 .. Last);
      begin
         Decrypt_Prepared (Buf (0 .. Last), Status, Tag, Nonce, Context,
                           AAD);
         Release (Len);
         Buf (0 .. Last) := CT;
         Secret (Buf (0 .. Last));
         Forged := Tag;
         Forged (15) := Forged (15) xor 1;
         Decrypt_Prepared (Buf (0 .. Last), Status, Forged, Nonce, Context,
                           AAD);
         Release (Len);
         Buf (0 .. Last) := CT;
         Secret (Buf (0 .. Last));
         if Bits = 128 then
            Decrypt_InPlace (Buf (0 .. Last), Status, Tag, Nonce, K128, AAD);
         else
            Decrypt_InPlace_256 (Buf (0 .. Last), Status, Tag, Nonce, K256,
                                 AAD);
         end if;
         Release (Len);
      end;
   end Run;

   Lengths : constant array (Positive range <>) of N32 :=
     (319, 320, 511, 512, 513, 1024, 4097, 16_384, 16_385);
begin
   Put_Line ("ct_decrypt_prepared: tiers " & Names);
   Secret (Key);
   Secret (Nonce);
   Secret (AAD);
   Secret (Plain);
   AES.Construct (K128, Key (0 .. 15));
   AES.Construct (K256, Key);
   for T in Tier loop
      if Available (T) then
         Select_Tier (T);
         for Bits in 1 .. 2 loop
            if Bits = 1 then Prepare_128 (Context, K128);
            else Prepare_256 (Context, K256); end if;
            for Len in N32 range 0 .. 300 loop
               Run (Bits * 128, Len);
            end loop;
            for Len of Lengths loop
               Run (Bits * 128, Len);
            end loop;
            Clear (Context);
         end loop;
      end if;
   end loop;
   AES.Sanitize (K128);
   AES.Sanitize (K256);
   Put_Line ("ct_decrypt_prepared: done," & Decryptions'Image &
             " authentic records opened");
end Ct_Decrypt_Prepared;
