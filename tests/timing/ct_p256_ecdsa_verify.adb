--  Constant-time check for ECDSA-P-256 verification.
--
--  Same intent as ct_p384_ecdsa_verify: the public key is marked
--  undefined so that the point validation (prefix, range, on-curve) and
--  its rollup into the verdict show no data-dependent branch. r, s and
--  the hash stay defined.

with Ada.Command_Line;
with Ada.Text_IO; use Ada.Text_IO;
with Interfaces.C;
with SPARKNaCl; use SPARKNaCl;
with SPARKTLSCrypto.P256.ECDSA;
with Ctgrind;

procedure Ct_P256_ECDSA_Verify is
   Hash : constant Bytes_32 := (others => 16#A5#);

   --  Generator coordinates: a valid public key.
   Qx : SPARKTLSCrypto.P256.ECDSA.ECDSA_Sig_Half :=
     (16#6B#, 16#17#, 16#D1#, 16#F2#, 16#E1#, 16#2C#, 16#42#, 16#47#,
      16#F8#, 16#BC#, 16#E6#, 16#E5#, 16#63#, 16#A4#, 16#40#, 16#F2#,
      16#77#, 16#03#, 16#7D#, 16#81#, 16#2D#, 16#EB#, 16#33#, 16#A0#,
      16#F4#, 16#A1#, 16#39#, 16#45#, 16#D8#, 16#98#, 16#C2#, 16#96#);
   Qy : SPARKTLSCrypto.P256.ECDSA.ECDSA_Sig_Half :=
     (16#4F#, 16#E3#, 16#42#, 16#E2#, 16#FE#, 16#1A#, 16#7F#, 16#9B#,
      16#8E#, 16#E7#, 16#EB#, 16#4A#, 16#7C#, 16#0F#, 16#9E#, 16#16#,
      16#2B#, 16#CE#, 16#33#, 16#57#, 16#6B#, 16#31#, 16#5E#, 16#CE#,
      16#CB#, 16#B6#, 16#40#, 16#68#, 16#37#, 16#BF#, 16#51#, 16#F5#);

   R : constant SPARKTLSCrypto.P256.ECDSA.ECDSA_Sig_Half := (31 => 16#07#, others => 16#11#);
   S : constant SPARKTLSCrypto.P256.ECDSA.ECDSA_Sig_Half := (31 => 16#0D#, others => 16#22#);

   OK : Boolean;
begin
   Ctgrind.Make_Undefined (Qx'Address, Interfaces.C.size_t (Qx'Length));
   Ctgrind.Make_Undefined (Qy'Address, Interfaces.C.size_t (Qy'Length));

   OK := SPARKTLSCrypto.P256.ECDSA.Verify (Hash, Qx, Qy, R, S);

   Ctgrind.Make_Defined (OK'Address, Interfaces.C.size_t (1));
   Ctgrind.Use_Output (OK'Address, Interfaces.C.size_t (1));

   Put_Line ("ct_p256_ecdsa_verify: Verify completed (OK=" & OK'Image & ")");
   Ada.Command_Line.Set_Exit_Status (0);
end Ct_P256_ECDSA_Verify;
