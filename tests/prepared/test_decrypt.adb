--  AES-GCM decryption: Decrypt_Prepared, Decrypt_InPlace(_256) and the
--  one-shot Decrypt(_256), against OpenSSL EVP and against each other, on
--  every dispatch tier the CPU has; Encrypt_Prepared against OpenSSL on
--  every tier too.
--
--  Tiers. The accelerated tiers are chosen from CPUID flags set at
--  elaboration. This test (and only this test) overwrites those flags to
--  run the same inputs through each tier the CPU actually supports in one
--  process: the proven portable code, AES-NI + PCLMULQDQ (4-block
--  stripes), VAES/VPCLMULQDQ on ymm (16-block stripes) and on zmm. Every
--  tier must give the same bytes and status. A SPARKTLSCRYPTO_ASM=disabled
--  build has the portable tier only.
--
--  Cases, for AES-128 and AES-256:
--    * every ciphertext length 0 .. 300, with AAD lengths cycling 0 .. 300;
--      every AAD length 0 .. 300 with fixed ciphertext lengths;
--    * lengths around the 16-, 64-, 256- and 512-byte stripe boundaries and
--      the TLS record size, up to 64 KiB;
--    * 64 buffer alignments with guard bytes on both sides;
--    * every single-bit flip of the tag, ciphertext and AAD of several
--      records, equal flips at two tag positions, a wrong nonce and a
--      wrong key: each must fail with the whole buffer zeroed;
--    * the plaintext from OpenSSL's encryption and OpenSSL's decryption of
--      the same record; prepared, one-shot in-place and one-shot copying
--      decryption agree.
with Ada.Text_IO; use Ada.Text_IO;
with Interfaces; use Interfaces;
with Interfaces.C;
with System;
with SPARKNaCl; use SPARKNaCl;
with SPARKNaCl.AES;
with SPARKTLSCrypto.AES_NI;
with SPARKTLSCrypto.GHASH_NI;
with SPARKTLSCrypto.AES_GCM_AVX2;
with SPARKTLSCrypto.AES_GCM_AVX512;
with SPARKTLSCrypto.AES_GCM; use SPARKTLSCrypto.AES_GCM;

procedure Test_Decrypt is
   use type Interfaces.C.int;

   function Seal (Key : System.Address; Bits : Interfaces.C.int;
                  IV, AAD : System.Address; AAD_Len : Interfaces.C.int;
                  Buf : System.Address; Len : Interfaces.C.int;
                  Tag : System.Address) return Interfaces.C.int
     with Import, Convention => C, External_Name => "openssl_gcm";
   function Open (Key : System.Address; Bits : Interfaces.C.int;
                  IV, AAD : System.Address; AAD_Len : Interfaces.C.int;
                  Input, Output : System.Address; Len : Interfaces.C.int;
                  Tag : System.Address) return Interfaces.C.int
     with Import, Convention => C, External_Name => "openssl_gcm_open";

   ----------------------------------------------------------------------------
   --  Tiers
   ----------------------------------------------------------------------------

   type Tier is (Portable, AES_NI_4, VAES_256, VAES_512);

   Have_AESNI  : constant Boolean := SPARKTLSCrypto.AES_NI.Has_AESNI;
   Have_PCLMUL : constant Boolean := SPARKTLSCrypto.GHASH_NI.Has_PCLMULQDQ;
   Have_VAES2  : constant Boolean :=
     SPARKTLSCrypto.AES_GCM_AVX2.Has_VAES_AVX2;
   Have_VAES5  : constant Boolean :=
     SPARKTLSCrypto.AES_GCM_AVX512.Has_AVX512_AES_GCM;

   Available : constant array (Tier) of Boolean :=
     (Portable => True,
      AES_NI_4 => Have_AESNI and Have_PCLMUL,
      VAES_256 => Have_VAES2,
      VAES_512 => Have_VAES5);

   procedure Select_Tier (T : Tier) is
   begin
      SPARKTLSCrypto.AES_NI.Has_AESNI := Have_AESNI and T /= Portable;
      SPARKTLSCrypto.GHASH_NI.Has_PCLMULQDQ := Have_PCLMUL and T /= Portable;
      SPARKTLSCrypto.AES_GCM_AVX2.Has_VAES_AVX2 :=
        Have_VAES2 and T = VAES_256;
      SPARKTLSCrypto.AES_GCM_AVX512.Has_AVX512_AES_GCM :=
        Have_VAES5 and T = VAES_512;
   end Select_Tier;

   ----------------------------------------------------------------------------
   --  Helpers
   ----------------------------------------------------------------------------

   Seed : Unsigned_64 := 16#9E37_79B9_7F4A_7C15#;
   function Next_Byte return Byte is
   begin
      Seed := Seed xor Shift_Left (Seed, 13);
      Seed := Seed xor Shift_Right (Seed, 7);
      Seed := Seed xor Shift_Left (Seed, 17);
      return Byte (Seed and 255);
   end Next_Byte;

   Records, Forgeries, Decryptions : Natural := 0;

   procedure Check (OK : Boolean; What : String) is
   begin
      if not OK then
         raise Program_Error with What;
      end if;
   end Check;

   Guard : constant Byte := 16#A5#;
   Pad   : constant N32 := 64;   --  guard bytes on each side

   --  Decrypt CT (with Tag) at Offset in a guarded buffer under tier T and
   --  return the status; Out_Buf receives the result.
   procedure Decrypt_At
     (T       : Tier;
      Bits    : Positive;
      Key     : Bytes_32;
      Nonce   : Bytes_12;
      AAD     : Byte_Seq;
      CT      : Byte_Seq;
      Tag     : Bytes_16;
      Offset  : N32;
      Out_Buf : out Byte_Seq;
      Status  : out Boolean;
      Mode    : Natural := 0)  --  0 prepared, 1 one-shot in place
   is
      Len : constant N32 := N32 (CT'Length);
      Storage : Byte_Seq (0 .. 2 * Pad + 64 + Len) := (others => Guard)
        with Alignment => 64;
      First : constant N32 := Pad + Offset;
      Context : Prepared_Key;
   begin
      Select_Tier (T);
      Storage (First .. First + Len - 1) := CT;
      if Mode = 0 then
         if Bits = 128 then
            declare K : AES.AES128_Key := AES.Construct (Key (0 .. 15));
            begin Prepare_128 (Context, K); AES.Sanitize (K); end;
         else
            declare K : AES.AES256_Key := AES.Construct (Key);
            begin Prepare_256 (Context, K); AES.Sanitize (K); end;
         end if;
         Decrypt_Prepared (Storage (First .. First + Len - 1), Status, Tag,
                           Nonce, Context, AAD);
         Clear (Context);
      elsif Bits = 128 then
         declare K : AES.AES128_Key := AES.Construct (Key (0 .. 15));
         begin
            Decrypt_InPlace (Storage (First .. First + Len - 1), Status, Tag,
                             Nonce, K, AAD);
            AES.Sanitize (K);
         end;
      else
         declare K : AES.AES256_Key := AES.Construct (Key);
         begin
            Decrypt_InPlace_256 (Storage (First .. First + Len - 1), Status,
                                 Tag, Nonce, K, AAD);
            AES.Sanitize (K);
         end;
      end if;
      for I in Storage'Range loop
         if I < First or I >= First + Len then
            Check (Storage (I) = Guard, "write outside the buffer, tier " &
                   T'Image & " len" & Len'Image & " offset" & Offset'Image);
         end if;
      end loop;
      Out_Buf := Storage (First .. First + Len - 1);
      Decryptions := Decryptions + 1;
   end Decrypt_At;

   --  Every available tier and both entry points: authentic record.
   procedure Expect_Plain
     (Bits : Positive; Key : Bytes_32; Nonce : Bytes_12; AAD : Byte_Seq;
      CT : Byte_Seq; Tag : Bytes_16; Plain : Byte_Seq; Offset : N32;
      What : String)
   is
      Result : Byte_Seq (0 .. N32 (CT'Length) - 1);
      Status : Boolean;
   begin
      for T in Tier loop
         if Available (T) then
            for Mode in 0 .. 1 loop
               Decrypt_At (T, Bits, Key, Nonce, AAD, CT, Tag, Offset,
                           Result, Status, Mode);
               Check (Status and Result = Plain,
                      "authentic record rejected or misdecrypted: " & What &
                      " tier " & T'Image & " mode" & Mode'Image);
            end loop;
         end if;
      end loop;
   end Expect_Plain;

   --  Every available tier: forged record fails with all bytes zero.
   procedure Expect_Forgery
     (Bits : Positive; Key : Bytes_32; Nonce : Bytes_12; AAD : Byte_Seq;
      CT : Byte_Seq; Tag : Bytes_16; What : String;
      Both_Modes : Boolean := False)
   is
      Result : Byte_Seq (0 .. N32 (CT'Length) - 1);
      Status : Boolean;
      Zero   : constant Byte_Seq (Result'Range) := (others => 0);
   begin
      for T in Tier loop
         if Available (T) then
            for Mode in 0 .. (if Both_Modes then 1 else 0) loop
               Decrypt_At (T, Bits, Key, Nonce, AAD, CT, Tag,
                           N32 (Next_Byte mod 64), Result, Status, Mode);
               Check (not Status, "forgery accepted: " & What & " tier " &
                      T'Image);
               Check (Result = Zero, "forgery left plaintext: " & What &
                      " tier " & T'Image);
            end loop;
         end if;
      end loop;
      Forgeries := Forgeries + 1;
   end Expect_Forgery;

   --  One record: OpenSSL seals random data; everything else must agree.
   procedure Record_Case
     (Bits : Positive; Len, AAD_Len : N32; Offset : N32 := 0;
      Flips : Boolean := False)
   is
      Key   : Bytes_32;
      Nonce : Bytes_12;
      --  Larger than needed so an empty AAD or record has an address.
      AAD_Store : Byte_Seq (0 .. AAD_Len) := (others => 0);
      AAD   : Byte_Seq (0 .. I32 (AAD_Len) - 1);
      Plain, CT, Opened : Byte_Seq (0 .. I32 (Len) - 1);
      CT_Store : Byte_Seq (0 .. Len) := (others => 0);
      Opened_Store : Byte_Seq (0 .. Len) := (others => 0);
      Tag   : Bytes_16;
      C_Bits : constant Interfaces.C.int := Interfaces.C.int (Bits);
   begin
      for I in Key'Range loop Key (I) := Next_Byte; end loop;
      for I in Nonce'Range loop Nonce (I) := Next_Byte; end loop;
      for I in AAD'Range loop AAD (I) := Next_Byte; end loop;
      for I in Plain'Range loop Plain (I) := Next_Byte; end loop;
      if AAD_Len > 0 then AAD_Store (AAD'Range) := AAD; end if;
      if Len > 0 then CT_Store (CT'Range) := Plain; end if;

      Check (Seal (Key'Address, C_Bits, Nonce'Address, AAD_Store'Address,
                   Interfaces.C.int (AAD_Len), CT_Store'Address,
                   Interfaces.C.int (Len), Tag'Address) = 1, "OpenSSL seal");
      CT := CT_Store (CT'Range);
      Check (Open (Key'Address, C_Bits, Nonce'Address, AAD_Store'Address,
                   Interfaces.C.int (AAD_Len), CT_Store'Address,
                   Opened_Store'Address, Interfaces.C.int (Len),
                   Tag'Address) = 1, "OpenSSL open");
      Opened := Opened_Store (Opened'Range);
      Check (Opened = Plain, "OpenSSL round trip");

      Expect_Plain (Bits, Key, Nonce, AAD, CT, Tag, Plain, Offset,
                    "len" & Len'Image & " aad" & AAD_Len'Image);

      --  Prepared encryption on every tier gives OpenSSL's record.
      if Len > 0 then
         for T in Tier loop
            if Available (T) then
               declare
                  Context : Prepared_Key;
                  Buf     : Byte_Seq := Plain;
                  Our_Tag : Bytes_16;
               begin
                  Select_Tier (T);
                  if Bits = 128 then
                     Prepare_128 (Context, AES.Construct (Key (0 .. 15)));
                  else
                     Prepare_256 (Context, AES.Construct (Key));
                  end if;
                  Encrypt_Prepared (Buf, Our_Tag, Nonce, Context, AAD);
                  Check (Buf = CT and Our_Tag = Tag,
                         "Encrypt_Prepared disagrees with OpenSSL, tier " &
                         T'Image & " len" & Len'Image);
                  Clear (Context);
               end;
            end if;
         end loop;
      end if;

      --  The existing copying one-shot API (the independent reference).
      declare
         M : Byte_Seq (CT'Range);
         Valid : Boolean;
      begin
         for T in Tier loop
            if Available (T) then
               Select_Tier (T);
            end if;
         end loop;
         if Bits = 128 then
            Decrypt (M, Valid, Tag, CT, Nonce,
                     AES.Construct (Key (0 .. 15)), AAD);
         else
            Decrypt_256 (M, Valid, Tag, CT, Nonce, AES.Construct (Key), AAD);
         end if;
         Check (Valid and M = Plain, "one-shot Decrypt disagrees");
      end;

      --  A tag from the right key but a different nonce or key.
      declare
         Other_Nonce : Bytes_12 := Nonce;
         Other_Key   : Bytes_32 := Key;
      begin
         Other_Nonce (11) := Other_Nonce (11) xor 1;
         Expect_Forgery (Bits, Key, Other_Nonce, AAD, CT, Tag, "nonce");
         Other_Key (0) := Other_Key (0) xor 16#80#;
         Expect_Forgery (Bits, Other_Key, Nonce, AAD, CT, Tag, "key", True);
      end;

      if Flips then
         --  Every single-bit change of tag, ciphertext and AAD.
         for Bit in 0 .. 127 loop
            declare
               Bad : Bytes_16 := Tag;
            begin
               Bad (N32 (Bit / 8)) :=
                 Bad (N32 (Bit / 8)) xor Shift_Left (1, Bit mod 8);
               Expect_Forgery (Bits, Key, Nonce, AAD, CT, Bad,
                               "tag bit" & Bit'Image, Bit mod 17 = 0);
            end;
         end loop;
         --  Equal changes at two tag positions: an XOR-accumulated
         --  comparison must not let them cancel.
         for Pos in N32 range 1 .. 15 loop
            declare
               Bad : Bytes_16 := Tag;
               Flip : constant Byte := Shift_Left (1, Natural (Pos) mod 8);
            begin
               Bad (0) := Bad (0) xor Flip;
               Bad (Pos) := Bad (Pos) xor Flip;
               Expect_Forgery (Bits, Key, Nonce, AAD, CT, Bad,
                               "tag pair" & Pos'Image);
            end;
         end loop;
         for Bit in 0 .. Natural (Len) * 8 - 1 loop
            declare
               Bad : Byte_Seq := CT;
            begin
               Bad (N32 (Bit / 8)) :=
                 Bad (N32 (Bit / 8)) xor Shift_Left (1, Bit mod 8);
               Expect_Forgery (Bits, Key, Nonce, AAD, Bad, Tag,
                               "ciphertext bit" & Bit'Image, Bit mod 97 = 0);
            end;
         end loop;
         for Bit in 0 .. Natural (AAD_Len) * 8 - 1 loop
            declare
               Bad : Byte_Seq := AAD;
            begin
               Bad (N32 (Bit / 8)) :=
                 Bad (N32 (Bit / 8)) xor Shift_Left (1, Bit mod 8);
               Expect_Forgery (Bits, Key, Nonce, Bad, CT, Tag,
                               "AAD bit" & Bit'Image);
            end;
         end loop;
      end if;
      Records := Records + 1;
   end Record_Case;

   Boundaries : constant array (Positive range <>) of N32 :=
     (319, 320, 321, 383, 384, 385, 447, 448, 449, 511, 512, 513,
      767, 768, 769, 1023, 1024, 1025, 1279, 1280, 1281, 4095, 4096, 4097,
      16_383, 16_384, 16_385, 16_399, 16_400, 16_401, 65_535, 65_536);
   Flip_Lengths : constant array (Positive range <>) of N32 :=
     (0, 1, 15, 16, 17, 63, 64, 65, 255, 256, 257);
begin
   Put_Line ("tiers: portable" &
             (if Available (AES_NI_4) then " aes-ni" else "") &
             (if Available (VAES_256) then " vaes-256" else "") &
             (if Available (VAES_512) then " vaes-512" else ""));
   for B in 1 .. 2 loop
      declare
         Bits : constant Positive := B * 128;
      begin
         for Len in N32 range 0 .. 300 loop
            Record_Case (Bits, Len, (Len * 7) mod 301);
         end loop;
         for AAD_Len in N32 range 0 .. 300 loop
            Record_Case (Bits, 1 + (AAD_Len mod 4) * 85, AAD_Len);
         end loop;
         for Len of Boundaries loop
            Record_Case (Bits, Len, 13);
         end loop;
         for Offset in N32 range 0 .. 63 loop
            Record_Case (Bits, 257 + Offset * 5, 5, Offset);
         end loop;
         for Len of Flip_Lengths loop
            Record_Case (Bits, Len, 20, Flips => True);
         end loop;
         Record_Case (Bits, 300, 3, Flips => True);
         Record_Case (Bits, 527, 0, Flips => True);
      end;
   end loop;
   Select_Tier (Tier'First);
   Put_Line ("PASS: AES-GCM decrypt records" & Records'Image &
             ", forgeries" & Forgeries'Image & ", decryptions" &
             Decryptions'Image);
end Test_Decrypt;
