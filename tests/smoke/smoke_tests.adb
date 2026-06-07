with Ada.Command_Line;
with Ada.Text_IO; use Ada.Text_IO;
with Interfaces; use Interfaces;

with SPARKNaCl; use SPARKNaCl;
with SPARKNaCl.AES;
with SPARKNaCl.Core;
with SPARKNaCl.Hashing.SHA384;

with SPARKTLSCrypto.AES_GCM;
with SPARKTLSCrypto.ChaCha20_Poly1305;
with SPARKTLSCrypto.Hashing.SHA256;
with SPARKTLSCrypto.HKDF;
with SPARKTLSCrypto.MAC;
with SPARKTLSCrypto.RFC6979;
with SPARKTLSCrypto.X25519;

procedure Smoke_Tests is
   Failures : Natural := 0;

   procedure Check (Name : String; OK : Boolean) is
   begin
      if OK then
         Put_Line ("PASS " & Name);
      else
         Put_Line ("FAIL " & Name);
         Failures := Failures + 1;
      end if;
   end Check;

   procedure Test_SHA256 is
      D : SPARKTLSCrypto.Hashing.SHA256.Digest;
      Ctx : SPARKTLSCrypto.Hashing.SHA256.Context;
      Expected : constant Bytes_32 :=
        (16#BA#, 16#78#, 16#16#, 16#BF#, 16#8F#, 16#01#, 16#CF#, 16#EA#,
         16#41#, 16#41#, 16#40#, 16#DE#, 16#5D#, 16#AE#, 16#22#, 16#23#,
         16#B0#, 16#03#, 16#61#, 16#A3#, 16#96#, 16#17#, 16#7A#, 16#9C#,
         16#B4#, 16#10#, 16#FF#, 16#61#, 16#F2#, 16#00#, 16#15#, 16#AD#);
   begin
      D := SPARKTLSCrypto.Hashing.SHA256.Hash (To_Byte_Seq ("abc"));
      Check ("sha256 one-shot", Equal (D, Expected));

      SPARKTLSCrypto.Hashing.SHA256.Init (Ctx);
      SPARKTLSCrypto.Hashing.SHA256.Update (Ctx, To_Byte_Seq ("a"));
      SPARKTLSCrypto.Hashing.SHA256.Update (Ctx, To_Byte_Seq ("bc"));
      SPARKTLSCrypto.Hashing.SHA256.Final (Ctx, D);
      Check ("sha256 streaming", Equal (D, Expected));
   end Test_SHA256;

   procedure Test_HMAC_HKDF is
      D : SPARKTLSCrypto.Hashing.SHA256.Digest;
      PRK : SPARKTLSCrypto.Hashing.SHA256.Digest;
      OKM : SPARKTLSCrypto.HKDF.OKM_Seq (0 .. 41);
      HMAC_Key : constant Byte_Seq (0 .. 19) := (others => 16#0B#);
      HMAC_Expected : constant Bytes_32 :=
        (16#B0#, 16#34#, 16#4C#, 16#61#, 16#D8#, 16#DB#, 16#38#, 16#53#,
         16#5C#, 16#A8#, 16#AF#, 16#CE#, 16#AF#, 16#0B#, 16#F1#, 16#2B#,
         16#88#, 16#1D#, 16#C2#, 16#00#, 16#C9#, 16#83#, 16#3D#, 16#A7#,
         16#26#, 16#E9#, 16#37#, 16#6C#, 16#2E#, 16#32#, 16#CF#, 16#F7#);
      IKM : constant Byte_Seq (0 .. 21) := (others => 16#0B#);
      Salt : constant Byte_Seq (0 .. 12) :=
        (16#00#, 16#01#, 16#02#, 16#03#, 16#04#, 16#05#, 16#06#,
         16#07#, 16#08#, 16#09#, 16#0A#, 16#0B#, 16#0C#);
      Info : constant Byte_Seq (0 .. 9) :=
        (16#F0#, 16#F1#, 16#F2#, 16#F3#, 16#F4#,
         16#F5#, 16#F6#, 16#F7#, 16#F8#, 16#F9#);
      PRK_Expected : constant Bytes_32 :=
        (16#07#, 16#77#, 16#09#, 16#36#, 16#2C#, 16#2E#, 16#32#, 16#DF#,
         16#0D#, 16#DC#, 16#3F#, 16#0D#, 16#C4#, 16#7B#, 16#BA#, 16#63#,
         16#90#, 16#B6#, 16#C7#, 16#3B#, 16#B5#, 16#0F#, 16#9C#, 16#31#,
         16#22#, 16#EC#, 16#84#, 16#4A#, 16#D7#, 16#C2#, 16#B3#, 16#E5#);
      OKM_Expected : constant SPARKTLSCrypto.HKDF.OKM_Seq (0 .. 41) :=
        (16#3C#, 16#B2#, 16#5F#, 16#25#, 16#FA#, 16#AC#, 16#D5#, 16#7A#,
         16#90#, 16#43#, 16#4F#, 16#64#, 16#D0#, 16#36#, 16#2F#, 16#2A#,
         16#2D#, 16#2D#, 16#0A#, 16#90#, 16#CF#, 16#1A#, 16#5A#, 16#4C#,
         16#5D#, 16#B0#, 16#2D#, 16#56#, 16#EC#, 16#C4#, 16#C5#, 16#BF#,
         16#34#, 16#00#, 16#72#, 16#08#, 16#D5#, 16#B8#, 16#87#, 16#18#,
         16#58#, 16#65#);
   begin
      SPARKTLSCrypto.MAC.HMAC_SHA_256 (D, To_Byte_Seq ("Hi There"), HMAC_Key);
      Check ("hmac-sha256 rfc4231 case 1", Equal (D, HMAC_Expected));

      SPARKTLSCrypto.HKDF.Extract (PRK, IKM, Salt);
      SPARKTLSCrypto.HKDF.Expand (OKM, PRK, Info);
      Check ("hkdf extract rfc5869 case 1", Equal (PRK, PRK_Expected));
      Check ("hkdf expand rfc5869 case 1", Equal (Byte_Seq (OKM), Byte_Seq (OKM_Expected)));
   end Test_HMAC_HKDF;

   procedure Test_X25519 is
      Scalar : constant Bytes_32 :=
        (16#77#, 16#07#, 16#6D#, 16#0A#, 16#73#, 16#18#, 16#A5#, 16#7D#,
         16#3C#, 16#16#, 16#C1#, 16#72#, 16#51#, 16#B2#, 16#66#, 16#45#,
         16#DF#, 16#4C#, 16#2F#, 16#87#, 16#EB#, 16#C0#, 16#99#, 16#2A#,
         16#B1#, 16#77#, 16#FB#, 16#A5#, 16#1D#, 16#B9#, 16#2C#, 16#2A#);
      Base : constant Bytes_32 := (0 => 16#09#, others => 0);
      Expected : constant Bytes_32 :=
        (16#85#, 16#20#, 16#F0#, 16#09#, 16#89#, 16#30#, 16#A7#, 16#54#,
         16#74#, 16#8B#, 16#7D#, 16#DC#, 16#B4#, 16#3E#, 16#F7#, 16#5A#,
         16#0D#, 16#BF#, 16#3A#, 16#0D#, 16#26#, 16#38#, 16#1A#, 16#F4#,
         16#EB#, 16#A4#, 16#A9#, 16#8E#, 16#AA#, 16#9B#, 16#4E#, 16#6A#);
      Q : Bytes_32;
   begin
      SPARKTLSCrypto.X25519.Scalar_Mult (Q, Scalar, Base);
      Check ("x25519 rfc7748 vector", Equal (Q, Expected));
   end Test_X25519;

   procedure Test_RFC6979 is
      D256 : constant Bytes_32 :=
        (16#C9#, 16#AF#, 16#A9#, 16#D8#, 16#45#, 16#BA#, 16#75#, 16#16#,
         16#6B#, 16#5C#, 16#21#, 16#57#, 16#67#, 16#B1#, 16#D6#, 16#93#,
         16#4E#, 16#50#, 16#C3#, 16#DB#, 16#36#, 16#E8#, 16#9B#, 16#12#,
         16#7B#, 16#8A#, 16#62#, 16#2B#, 16#12#, 16#0F#, 16#67#, 16#21#);
      H256 : constant Bytes_32 :=
        SPARKTLSCrypto.Hashing.SHA256.Hash (To_Byte_Seq ("sample"));
      Expected_K256 : constant Bytes_32 :=
        (16#A6#, 16#E3#, 16#C5#, 16#7D#, 16#D0#, 16#1A#, 16#BE#, 16#90#,
         16#08#, 16#65#, 16#38#, 16#39#, 16#83#, 16#55#, 16#DD#, 16#4C#,
         16#3B#, 16#17#, 16#AA#, 16#87#, 16#33#, 16#82#, 16#B0#, 16#F2#,
         16#4D#, 16#61#, 16#29#, 16#49#, 16#3D#, 16#8A#, 16#AD#, 16#60#);
      K256 : Bytes_32;
      D384 : constant Bytes_48 :=
        (16#6B#, 16#9D#, 16#3D#, 16#AD#, 16#2E#, 16#1B#, 16#8C#, 16#1C#,
         16#05#, 16#B1#, 16#98#, 16#75#, 16#B6#, 16#65#, 16#9F#, 16#4D#,
         16#E2#, 16#3C#, 16#3B#, 16#66#, 16#7B#, 16#F2#, 16#97#, 16#BA#,
         16#9A#, 16#A4#, 16#77#, 16#40#, 16#78#, 16#71#, 16#37#, 16#D8#,
         16#96#, 16#D5#, 16#72#, 16#4E#, 16#4C#, 16#70#, 16#A8#, 16#25#,
         16#F8#, 16#72#, 16#C9#, 16#EA#, 16#60#, 16#D2#, 16#ED#, 16#F5#);
      H384 : constant Bytes_48 :=
        SPARKNaCl.Hashing.SHA384.Hash (To_Byte_Seq ("sample"));
      Expected_K384 : constant Bytes_48 :=
        (16#94#, 16#ED#, 16#91#, 16#0D#, 16#1A#, 16#09#, 16#9D#, 16#AD#,
         16#32#, 16#54#, 16#E9#, 16#24#, 16#2A#, 16#E8#, 16#5A#, 16#BD#,
         16#E4#, 16#BA#, 16#15#, 16#16#, 16#8E#, 16#AF#, 16#0C#, 16#A8#,
         16#7A#, 16#55#, 16#5F#, 16#D5#, 16#6D#, 16#10#, 16#FB#, 16#CA#,
         16#29#, 16#07#, 16#E3#, 16#E8#, 16#3B#, 16#A9#, 16#53#, 16#68#,
         16#62#, 16#3B#, 16#8C#, 16#46#, 16#86#, 16#91#, 16#5C#, 16#F9#);
      K384 : Bytes_48;
   begin
      SPARKTLSCrypto.RFC6979.Derive_K_P256 (D256, H256, K256);
      Check ("rfc6979 p-256 sha256 sample", Equal (K256, Expected_K256));

      SPARKTLSCrypto.RFC6979.Derive_K_P384 (D384, H384, K384);
      Check ("rfc6979 p-384 sha384 sample", Equal (K384, Expected_K384));
   end Test_RFC6979;

   procedure Test_AES_GCM_Roundtrip is
      K_Raw : constant Bytes_16 := (others => 0);
      K : SPARKNaCl.AES.AES128_Key;
      N : constant Bytes_12 := (others => 0);
      AAD : constant Byte_Seq (0 .. 0) := (0 => 16#A5#);
      M : constant Byte_Seq (0 .. 15) :=
        (16#00#, 16#11#, 16#22#, 16#33#, 16#44#, 16#55#, 16#66#, 16#77#,
         16#88#, 16#99#, 16#AA#, 16#BB#, 16#CC#, 16#DD#, 16#EE#, 16#FF#);
      C : Byte_Seq (0 .. 15);
      M2 : Byte_Seq (0 .. 15);
      Tag : Bytes_16;
      Bad_Tag : Bytes_16;
      Status : Boolean;
   begin
      SPARKNaCl.AES.Construct (K, K_Raw);
      SPARKTLSCrypto.AES_GCM.Encrypt (C, Tag, M, N, K, AAD);
      SPARKTLSCrypto.AES_GCM.Decrypt (M2, Status, Tag, C, N, K, AAD);
      Check ("aes-128-gcm roundtrip", Status and then Equal (M2, M));

      Bad_Tag := Tag;
      Bad_Tag (0) := Bad_Tag (0) xor 1;
      SPARKTLSCrypto.AES_GCM.Decrypt (M2, Status, Bad_Tag, C, N, K, AAD);
      Check ("aes-128-gcm tag rejection", (not Status) and then Equal (M2, Byte_Seq'(0 .. 15 => 0)));
   end Test_AES_GCM_Roundtrip;

   procedure Test_ChaCha20_Poly1305_Smoke is
      K_Raw : constant Bytes_32 := (others => 0);
      K : SPARKNaCl.Core.ChaCha20_Key;
      N : constant SPARKNaCl.Core.ChaCha20_IETF_Nonce := (others => 0);
      AAD : constant Byte_Seq (0 .. 0) := (0 => 16#5A#);
      M : constant Byte_Seq (0 .. 31) := (others => 16#C3#);
      C : Byte_Seq (0 .. 31);
      Tag : Bytes_16;
      Zero_Tag : constant Bytes_16 := (others => 0);
   begin
      SPARKNaCl.Core.Construct (K, K_Raw);
      SPARKTLSCrypto.ChaCha20_Poly1305.Encrypt (C, Tag, M, N, K, AAD);
      Check ("chacha20-poly1305 nonzero tag", not Equal (Tag, Zero_Tag));
   end Test_ChaCha20_Poly1305_Smoke;
begin
   Test_SHA256;
   Test_HMAC_HKDF;
   Test_X25519;
   Test_RFC6979;
   Test_AES_GCM_Roundtrip;
   Test_ChaCha20_Poly1305_Smoke;

   if Failures /= 0 then
      Ada.Command_Line.Set_Exit_Status (Ada.Command_Line.Failure);
   end if;
end Smoke_Tests;
