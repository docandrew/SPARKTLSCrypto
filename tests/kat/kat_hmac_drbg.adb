--  NIST CAVP known-answer tests for HMAC_DRBG with SHA-256, both
--  no-reseed and reseed (PredictionResistance = False) variants. Each
--  COUNT instantiates, optionally reseeds, generates twice and compares
--  the second output with ReturnedBits, over every combination of
--  personalization string and additional input the vectors cover.
--  Also exercises the built-in self-test and the reseed-required gate.
with Ada.Text_IO;      use Ada.Text_IO;
with Ada.Command_Line;
with Interfaces;       use Interfaces;
with SPARKNaCl;        use SPARKNaCl;
with SPARKTLSCrypto.HMAC_DRBG;

procedure KAT_HMAC_DRBG is
   use SPARKTLSCrypto.HMAC_DRBG;

   Passed, Failed : Natural := 0;

   --  Hex text -> bytes; an empty value is an empty sequence.
   function Hex (S : String) return Byte_Seq is
      function Nib (C : Character) return Byte is
        (case C is
            when '0' .. '9' => Character'Pos (C) - Character'Pos ('0'),
            when 'a' .. 'f' => Character'Pos (C) - Character'Pos ('a') + 10,
            when 'A' .. 'F' => Character'Pos (C) - Character'Pos ('A') + 10,
            when others     => 0);
      R : Byte_Seq (0 .. N32 (S'Length / 2) - 1);
   begin
      for I in R'Range loop
         R (I) := Nib (S (S'First + 2 * Natural (I))) * 16
                  + Nib (S (S'First + 2 * Natural (I) + 1));
      end loop;
      return R;
   end Hex;

   --  "Key = value" -> value, trailing CR stripped.
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
      if P > E then
         return "";
      end if;
      return Line (P .. E);
   end Value;

   function Starts (Line, Key : String) return Boolean is
     (Line'Length >= Key'Length and then Line (Line'First .. Line'First + Key'Length - 1) = Key);

   procedure Run_File (Path : String; Reseeds : Boolean) is
      F        : File_Type;
      In_SHA256 : Boolean := False;
      Have     : Natural := 0;
      --  fields of the current COUNT, as hex strings (bounded)
      E, No, Pe, Er, Ar, A1, A2, Ex : String (1 .. 512);
      LE, LN, LP, LEr, LAr, LA1, LA2, LEx : Natural := 0;
      Add_Seen : Natural := 0;
      Count    : Integer := -1;

      procedure Set (Dst : out String; Len : out Natural; V : String) is
      begin
         Dst := (others => ' ');
         Dst (1 .. V'Length) := V;
         Len := V'Length;
      end Set;

      procedure Check_Vector is
         S      : State;
         Out1   : Byte_Seq (0 .. 127);
         Out2   : Byte_Seq (0 .. 127);
         OK1, OK2 : Boolean;
         Exp    : constant Byte_Seq := Hex (Ex (1 .. LEx));
      begin
         Instantiate (S, Hex (E (1 .. LE)), Hex (No (1 .. LN)), Hex (Pe (1 .. LP)));
         if Reseeds then
            Reseed (S, Hex (Er (1 .. LEr)), Hex (Ar (1 .. LAr)));
         end if;
         Generate (S, Hex (A1 (1 .. LA1)), Out1, OK1);
         Generate (S, Hex (A2 (1 .. LA2)), Out2, OK2);
         if (OK1 and OK2) and then Exp'Length = 128 and then Out2 = Exp then
            Passed := Passed + 1;
         else
            Failed := Failed + 1;
            Put_Line ("  FAIL " & Path & " COUNT" & Count'Image);
         end if;
      end Check_Vector;
   begin
      Open (F, In_File, Path);
      while not End_Of_File (F) loop
         declare
            L : constant String := Get_Line (F);
         begin
            if Starts (L, "[SHA-256]") then
               In_SHA256 := True;
            elsif Starts (L, "[SHA-") then
               In_SHA256 := False;
            elsif In_SHA256 then
               if Starts (L, "COUNT") then
                  Count := Integer'Value (Value (L));
                  Add_Seen := 0;
               elsif Starts (L, "EntropyInputReseed") then
                  Set (Er, LEr, Value (L));
               elsif Starts (L, "EntropyInput") then
                  Set (E, LE, Value (L));
               elsif Starts (L, "Nonce") then
                  Set (No, LN, Value (L));
               elsif Starts (L, "PersonalizationString") then
                  Set (Pe, LP, Value (L));
               elsif Starts (L, "AdditionalInputReseed") then
                  Set (Ar, LAr, Value (L));
               elsif Starts (L, "AdditionalInput") then
                  Add_Seen := Add_Seen + 1;
                  if Add_Seen = 1 then
                     Set (A1, LA1, Value (L));
                  else
                     Set (A2, LA2, Value (L));
                  end if;
               elsif Starts (L, "ReturnedBits") then
                  Set (Ex, LEx, Value (L));
                  Have := Have + 1;
                  Check_Vector;
               end if;
            end if;
         end;
      end loop;
      Close (F);
      Put_Line ("  " & Path & ":" & Have'Image & " SHA-256 vectors");
   end Run_File;

   Dir : constant String :=
     (if Ada.Command_Line.Argument_Count >= 1 then Ada.Command_Line.Argument (1) else "vectors");
begin
   Put_Line ("=== HMAC_DRBG (SHA-256) known-answer tests ===");

   if Self_Test then
      Passed := Passed + 1;
      Put_Line ("  PASS built-in self-test");
   else
      Failed := Failed + 1;
      Put_Line ("  FAIL built-in self-test");
   end if;

   --  The reseed gate: with an interval of 2, the third request refuses.
   declare
      S   : State;
      Buf : Byte_Seq (0 .. 15);
      E   : constant Byte_Seq (0 .. 31) := (others => 16#42#);
      Nn  : constant Byte_Seq (0 .. 15) := (others => 16#17#);
      Emp : constant Byte_Seq (0 .. -1) := (others => 0);
      OK  : Boolean;
      Gate_OK : Boolean := True;
   begin
      Instantiate (S, E, Nn, Emp, Reseed_Interval => 2);
      Generate (S, Emp, Buf, OK); Gate_OK := Gate_OK and OK;
      Generate (S, Emp, Buf, OK); Gate_OK := Gate_OK and OK;
      Generate (S, Emp, Buf, OK); Gate_OK := Gate_OK and not OK and Reseed_Required (S);
      Gate_OK := Gate_OK and (for all I in Buf'Range => Buf (I) = 0);
      Reseed (S, E, Emp);
      Generate (S, Emp, Buf, OK); Gate_OK := Gate_OK and OK and Reseed_Counter (S) = 2;
      if Gate_OK then
         Passed := Passed + 1; Put_Line ("  PASS reseed gate (interval 2)");
      else
         Failed := Failed + 1; Put_Line ("  FAIL reseed gate");
      end if;
   end;

   Run_File (Dir & "/no_reseed/HMAC_DRBG.rsp", Reseeds => False);
   Run_File (Dir & "/pr_false/HMAC_DRBG.rsp", Reseeds => True);

   Put_Line ("=== KAT:" & Passed'Image & " passed," & Failed'Image & " failed ===");
   if Failed > 0 then
      Ada.Command_Line.Set_Exit_Status (1);
   end if;
end KAT_HMAC_DRBG;
