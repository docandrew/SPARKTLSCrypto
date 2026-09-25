with Ada.Text_IO; use Ada.Text_IO;
with Interfaces; use Interfaces;
with Interfaces.C;
with System;
with SPARKNaCl; use SPARKNaCl;
with SPARKNaCl.AES;
with SPARKTLSCrypto.AES_NI;
with SPARKTLSCrypto.AES_GCM_AVX512;
with SPARKTLSCrypto.AES_GCM; use SPARKTLSCrypto.AES_GCM;
with SPARKTLSCrypto.AES_GCM.Testing;
procedure Test_Prepared is
   use type Interfaces.C.int;
   function Oracle (Key : System.Address; Bits : Interfaces.C.int;
                    IV, AAD : System.Address; AAD_Len : Interfaces.C.int;
                    Buf : System.Address; Len : Interfaces.C.int;
                    Tag : System.Address) return Interfaces.C.int
     with Import, Convention => C, External_Name => "openssl_gcm";
   Context : Prepared_Key;
   Key : Bytes_32;
   Nonce : Bytes_12;
   Total : Natural := 0;
   Seed : Unsigned_64 := 16#cbfe98344192#;
   function Next_Byte return Byte is
   begin
      Seed := Seed xor Shift_Left (Seed, 13);
      Seed := Seed xor Shift_Right (Seed, 7);
      Seed := Seed xor Shift_Left (Seed, 17);
      return Byte (Seed and 255);
   end Next_Byte;
   procedure Check (OK : Boolean; What : String) is
   begin
      if not OK then raise Program_Error with What; end if;
   end Check;
   procedure Run (Len, AAD_Len, Base : N32; Bits : Interfaces.C.int) is
      --  Use a larger object so an empty AAD has a valid base address.
      AAD : Byte_Seq (0 .. 255);
      Plain, Expected, Original : Byte_Seq (Base .. Base + Len - 1);
      Storage : Byte_Seq (0 .. Len + 62) := (others => 16#A5#)
        with Alignment => 64;
      Actual : Byte_Seq renames Storage (Base .. Base + Len - 1);
      Decoded, Zero_Based_CT : Byte_Seq (0 .. Len - 1);
      Tag, Ref_Tag, Old_Tag, Bad_Tag : Bytes_16;
      Valid : Boolean;
      K128 : AES.AES128_Key := AES.Construct (Key (0 .. 15));
      K256 : AES.AES256_Key := AES.Construct (Key);
   begin
      for I in AAD'Range loop AAD (I) := Next_Byte; end loop;
      for I in Plain'Range loop Plain (I) := Next_Byte; end loop;
      for I in Nonce'Range loop Nonce (I) := Next_Byte; end loop;
      Actual := Plain; Expected := Plain; Original := Plain;
      --  An Ada null slice cannot use modular zero minus one.
      declare
         Auth : Byte_Seq (1 .. AAD_Len);
         Zero_Based_Auth : Byte_Seq (0 .. I32 (AAD_Len) - 1);
      begin
         Auth := AAD (1 .. AAD_Len);
         Zero_Based_Auth := Auth;
         Encrypt_Prepared (Actual, Tag, Nonce, Context, Zero_Based_Auth);
         Check ((for all I in Storage'Range =>
                   (if I < Base or I >= Base + Len then Storage (I) = 16#A5#)),
                "write outside ciphertext window");
         Check (Oracle (Key'Address, Bits, Nonce'Address, AAD (1)'Address,
                        Interfaces.C.int (AAD_Len), Expected'Address,
                        Interfaces.C.int (Len), Ref_Tag'Address) = 1, "OpenSSL error");
         Check (Actual = Expected and Tag = Ref_Tag, "OpenSSL mismatch");
         Zero_Based_CT := Actual;
         if Bits = 128 then
            Encrypt_InPlace (Original, Old_Tag, Nonce, K128, Zero_Based_Auth);
            Decrypt (Decoded, Valid, Tag, Zero_Based_CT, Nonce, K128, Zero_Based_Auth);
         else
            Encrypt_InPlace_256 (Original, Old_Tag, Nonce, K256, Zero_Based_Auth);
            Decrypt_256 (Decoded, Valid, Tag, Zero_Based_CT, Nonce, K256, Zero_Based_Auth);
         end if;
         Check (Actual = Original and Tag = Old_Tag, "one-shot mismatch");
         Check (Valid and Decoded = Plain, "decrypt mismatch len=" & Len'Image & " aad=" & AAD_Len'Image & " base=" & Base'Image & " bits=" & Bits'Image & " valid=" & Valid'Image);
         Bad_Tag := Tag; Bad_Tag (7) := Bad_Tag (7) xor 1;
         if Bits = 128 then
            Decrypt (Decoded, Valid, Bad_Tag, Zero_Based_CT, Nonce, K128, Zero_Based_Auth);
         else
            Decrypt_256 (Decoded, Valid, Bad_Tag, Zero_Based_CT, Nonce, K256, Zero_Based_Auth);
         end if;
         Check (not Valid and Decoded = Byte_Seq'(Decoded'Range => 0), "bad tag accepted");
      end;
      AES.Sanitize (K128); AES.Sanitize (K256);
      Total := Total + 1;
   end Run;
begin
   Put_Line ("AESNI=" & SPARKTLSCrypto.AES_NI.Has_AESNI'Image &
             " AVX512=" & SPARKTLSCrypto.AES_GCM_AVX512.Has_AVX512_AES_GCM'Image);
   Check (not Is_Prepared (Context), "default context is prepared");
   for Epoch in 0 .. 3 loop
      for I in Key'Range loop Key (I) := Next_Byte; end loop;
      for Bits in 1 .. 2 loop
         if Bits = 1 then
            declare K : AES.AES128_Key := AES.Construct (Key (0 .. 15));
            begin Prepare_128 (Context, K); AES.Sanitize (K); end;
         else
            declare K : AES.AES256_Key := AES.Construct (Key);
            begin Prepare_256 (Context, K); AES.Sanitize (K); end;
         end if;
         for Len in N32 range 1 .. 1025 loop
            Run (Len, Len mod 256, N32 (Epoch), Interfaces.C.int (Bits * 128));
         end loop;
         for Offset in N32 range 0 .. 31 loop
            Run (257, 13, Offset, Interfaces.C.int (Bits * 128));
         end loop;
         for Len of Byte_Seq'(1, 15, 16, 17, 63, 64, 65, 127, 128, 129, 255) loop
            Run (16384 + N32 (Len) - 1, 5, 7, Interfaces.C.int (Bits * 128));
         end loop;
      end loop;
      Clear (Context);
      Check (SPARKTLSCrypto.AES_GCM.Testing.Erased (Context), "clear retained key material");
   end loop;
   Put_Line ("PASS: prepared AES-GCM / OpenSSL / one-shot equivalence cases:" & Total'Image);
end Test_Prepared;
