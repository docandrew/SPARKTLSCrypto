--  Known-answer tests for AES-GCM decryption: the NIST CAVP GCM decryption
--  vectors (gcmDecrypt128.rsp, gcmDecrypt256.rsp, including their FAIL
--  cases) and Wycheproof's aes_gcm_test.json (valid and invalid cases),
--  fetched and pinned by fetch.sh.
--
--  The crate's AES-GCM takes a 96-bit nonce and a 128-bit tag, the TLS 1.3
--  parameters, and has no AES-192, so vectors with other IV or tag lengths
--  or 192-bit keys are counted as skipped. Each remaining vector goes
--  through Decrypt_Prepared, Decrypt_InPlace(_256) and the one-shot
--  Decrypt(_256), on every dispatch tier this CPU has (the test overwrites
--  the CPUID tier flags, as tests/prepared/test_decrypt does). A passing
--  vector must give its plaintext; a failing one must give Status False
--  and an all-zero buffer.
with Ada.Text_IO;      use Ada.Text_IO;
with Ada.Command_Line;
with Interfaces;       use Interfaces;
with SPARKNaCl;        use SPARKNaCl;
with SPARKNaCl.AES;
with SPARKTLSCrypto.AES_NI;
with SPARKTLSCrypto.GHASH_NI;
with SPARKTLSCrypto.AES_GCM_AVX2;
with SPARKTLSCrypto.AES_GCM_AVX512;
with SPARKTLSCrypto.AES_GCM; use SPARKTLSCrypto.AES_GCM;

procedure KAT_AES_GCM is
   Passed, Failed, Skipped : Natural := 0;

   type Tier is (Portable, AES_NI_4, VAES_256, VAES_512);
   Have_AESNI  : constant Boolean := SPARKTLSCrypto.AES_NI.Has_AESNI;
   Have_PCLMUL : constant Boolean := SPARKTLSCrypto.GHASH_NI.Has_PCLMULQDQ;
   Have_VAES2  : constant Boolean := SPARKTLSCrypto.AES_GCM_AVX2.Has_VAES_AVX2;
   Have_VAES5  : constant Boolean :=
     SPARKTLSCrypto.AES_GCM_AVX512.Has_AVX512_AES_GCM;
   Available : constant array (Tier) of Boolean :=
     (Portable => True, AES_NI_4 => Have_AESNI and Have_PCLMUL,
      VAES_256 => Have_VAES2, VAES_512 => Have_VAES5);

   procedure Select_Tier (T : Tier) is
   begin
      SPARKTLSCrypto.AES_NI.Has_AESNI := Have_AESNI and T /= Portable;
      SPARKTLSCrypto.GHASH_NI.Has_PCLMULQDQ := Have_PCLMUL and T /= Portable;
      SPARKTLSCrypto.AES_GCM_AVX2.Has_VAES_AVX2 := Have_VAES2 and T = VAES_256;
      SPARKTLSCrypto.AES_GCM_AVX512.Has_AVX512_AES_GCM :=
        Have_VAES5 and T = VAES_512;
   end Select_Tier;

   --  Hex text -> bytes; "" or "-" is an empty sequence (First = 0).
   function Hex (S : String) return Byte_Seq is
      function Nib (C : Character) return Byte is
        (case C is
            when '0' .. '9' => Character'Pos (C) - Character'Pos ('0'),
            when 'a' .. 'f' => Character'Pos (C) - Character'Pos ('a') + 10,
            when 'A' .. 'F' => Character'Pos (C) - Character'Pos ('A') + 10,
            when others     => 0);
      Len : constant Natural := (if S = "-" then 0 else S'Length / 2);
      R : Byte_Seq (0 .. I32 (Len) - 1);
   begin
      for I in R'Range loop
         R (I) := Nib (S (S'First + 2 * Natural (I))) * 16
                  + Nib (S (S'First + 2 * Natural (I) + 1));
      end loop;
      return R;
   end Hex;

   --  One vector through every entry point and tier.
   procedure Check_Vector
     (Name : String; Key, IV, AAD, CT, Tag, PT : Byte_Seq; Valid : Boolean)
   is
      OK : Boolean := True;
      Zero : constant Byte_Seq (CT'Range) := (others => 0);
      Bits : constant Natural := Natural (Key'Length) * 8;
   begin
      if Bits not in 128 | 256 or IV'Length /= 12 or Tag'Length /= 16
        or (Valid and then PT'Length /= CT'Length)
      then
         Skipped := Skipped + 1;
         return;
      end if;
      for T in Tier loop
         if Available (T) then
            Select_Tier (T);
            for Mode in 1 .. 3 loop
               declare
                  Buf : Byte_Seq := CT;
                  Status : Boolean;
                  Context : Prepared_Key;
               begin
                  case Mode is
                     when 1 =>
                        if Bits = 128 then
                           Prepare_128 (Context, AES.Construct (Key));
                        else
                           Prepare_256 (Context, AES.Construct (Key));
                        end if;
                        Decrypt_Prepared (Buf, Status, Bytes_16 (Tag),
                                          Bytes_12 (IV), Context, AAD);
                        Clear (Context);
                     when 2 =>
                        if Bits = 128 then
                           Decrypt_InPlace (Buf, Status, Bytes_16 (Tag),
                              Bytes_12 (IV), AES.Construct (Key), AAD);
                        else
                           Decrypt_InPlace_256 (Buf, Status, Bytes_16 (Tag),
                              Bytes_12 (IV), AES.Construct (Key), AAD);
                        end if;
                     when others =>
                        if Bits = 128 then
                           Decrypt (Buf, Status, Bytes_16 (Tag), CT,
                                    Bytes_12 (IV), AES.Construct (Key), AAD);
                        else
                           Decrypt_256 (Buf, Status, Bytes_16 (Tag), CT,
                                        Bytes_12 (IV), AES.Construct (Key),
                                        AAD);
                        end if;
                  end case;
                  if Valid then
                     OK := OK and Status and Buf = PT;
                  else
                     OK := OK and not Status and Buf = Zero;
                  end if;
                  if not OK then
                     Put_Line ("  FAIL " & Name & " tier " & T'Image &
                               " entry point" & Mode'Image);
                     Failed := Failed + 1;
                     return;
                  end if;
               end;
            end loop;
         end if;
      end loop;
      Passed := Passed + 1;
   end Check_Vector;

   function Value (Line : String) return String is
      P : Natural := Line'First;
      E : Natural := Line'Last;
   begin
      while P <= Line'Last and then Line (P) /= '=' loop
         P := P + 1;
      end loop;
      P := P + 1;
      while P <= Line'Last and then Line (P) = ' ' loop
         P := P + 1;
      end loop;
      while E >= P and then (Line (E) = ' ' or else Character'Pos (Line (E)) = 13) loop
         E := E - 1;
      end loop;
      return (if P > E then "" else Line (P .. E));
   end Value;

   function Starts (Line, Key : String) return Boolean is
     (Line'Length >= Key'Length
      and then Line (Line'First .. Line'First + Key'Length - 1) = Key);

   procedure Run_CAVP (Path : String) is
      F : File_Type;
      type Field is (K, IV, CT, AAD, Tag);
      Text : array (Field) of String (1 .. 4096);
      Last : array (Field) of Natural := (others => 0);
      Count : Natural := 0;
      Before : constant Natural := Passed + Failed + Skipped;

      procedure Set (W : Field; V : String) is
      begin
         Text (W) (1 .. V'Length) := V;
         Last (W) := V'Length;
      end Set;
      function Get (W : Field) return Byte_Seq is
        (Hex (Text (W) (1 .. Last (W))));
   begin
      Open (F, In_File, Path);
      while not End_Of_File (F) loop
         declare
            L : constant String := Get_Line (F);
         begin
            if Starts (L, "Count") then
               Count := Natural'Value (Value (L));
            elsif Starts (L, "Key") then Set (K, Value (L));
            elsif Starts (L, "IV") then Set (IV, Value (L));
            elsif Starts (L, "CT") then Set (CT, Value (L));
            elsif Starts (L, "AAD") then Set (AAD, Value (L));
            elsif Starts (L, "Tag") then Set (Tag, Value (L));
            elsif Starts (L, "PT") then
               Check_Vector (Path & " Count" & Count'Image, Get (K), Get (IV),
                             Get (AAD), Get (CT), Get (Tag),
                             Hex (Value (L)), True);
            elsif Starts (L, "FAIL") then
               Check_Vector (Path & " Count" & Count'Image, Get (K), Get (IV),
                             Get (AAD), Get (CT), Get (Tag),
                             Byte_Seq'(0 .. -1 => 0), False);
            end if;
         end;
      end loop;
      Close (F);
      Put_Line ("  " & Path & ":" &
                Natural'Image (Passed + Failed + Skipped - Before) &
                " vectors");
   end Run_CAVP;

   --  keySize ivSize tagSize tcId result key iv aad msg ct tag
   procedure Run_Wycheproof (Path : String) is
      F : File_Type;
      Before : constant Natural := Passed + Failed + Skipped;
   begin
      Open (F, In_File, Path);
      while not End_Of_File (F) loop
         declare
            L : constant String := Get_Line (F);
            Starts_At : array (1 .. 11) of Positive;
            Ends_At   : array (1 .. 11) of Natural;
            N : Natural := 0;
            P : Positive := L'First;
         begin
            while P <= L'Last and N < 11 loop
               N := N + 1;
               Starts_At (N) := P;
               while P <= L'Last and then L (P) /= ' ' loop
                  P := P + 1;
               end loop;
               Ends_At (N) := P - 1;
               P := P + 1;
            end loop;
            declare
               function W (I : Positive) return String is
                 (L (Starts_At (I) .. Ends_At (I)));
               Result : constant String := W (5);
            begin
               --  "acceptable" does not occur for 96-bit nonces and
               --  128-bit tags; treat it as must-pass if it ever does.
               Check_Vector ("wycheproof tcId " & W (4), Hex (W (6)),
                             Hex (W (7)), Hex (W (8)), Hex (W (10)),
                             Hex (W (11)), Hex (W (9)),
                             Result /= "invalid");
            end;
         end;
      end loop;
      Close (F);
      Put_Line ("  " & Path & ":" &
                Natural'Image (Passed + Failed + Skipped - Before) &
                " vectors");
   end Run_Wycheproof;

   Dir : constant String :=
     (if Ada.Command_Line.Argument_Count >= 1
      then Ada.Command_Line.Argument (1) else "vectors");
begin
   Put_Line ("=== AES-GCM decryption known-answer tests ===");
   Put_Line ("  tiers: portable" &
             (if Available (AES_NI_4) then " aes-ni" else "") &
             (if Available (VAES_256) then " vaes-256" else "") &
             (if Available (VAES_512) then " vaes-512" else ""));
   Run_CAVP (Dir & "/gcm/gcmDecrypt128.rsp");
   Run_CAVP (Dir & "/gcm/gcmDecrypt256.rsp");
   Run_Wycheproof (Dir & "/aes_gcm_test.txt");
   Put_Line ("=== KAT:" & Passed'Image & " passed," & Failed'Image &
             " failed," & Skipped'Image &
             " skipped (IV not 96 bits, tag not 128 bits, or AES-192) ===");
   if Failed > 0 or Passed = 0 then
      Ada.Command_Line.Set_Exit_Status (1);
   end if;
end KAT_AES_GCM;
