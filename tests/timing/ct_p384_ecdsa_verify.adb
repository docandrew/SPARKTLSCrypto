--  Constant-time check for ECDSA-P-384 verification.
--
--  Verify's inputs are public, so this is not about secrets: it is
--  about the public-key validation (range, on-curve, not-infinity) being
--  folded into the verdict without a data-dependent branch, so that a
--  forged or malformed Q is not distinguishable from a valid one by
--  timing. The public key is marked undefined; r, s and the hash stay
--  defined (their range checks are public early returns by design).

with Ada.Command_Line;
with Ada.Text_IO; use Ada.Text_IO;
with Interfaces.C;
with SPARKNaCl; use SPARKNaCl;
with SPARKTLSCrypto.P384.ECDSA;
with Ctgrind;

procedure Ct_P384_ECDSA_Verify is
   Hash : constant Bytes_48 := (others => 16#A5#);

   --  Generator coordinates: a valid public key.
   Qx : Byte_Seq (0 .. 47) :=
     (16#AA#, 16#87#, 16#CA#, 16#22#, 16#BE#, 16#8B#, 16#05#, 16#37#,
      16#8E#, 16#B1#, 16#C7#, 16#1E#, 16#F3#, 16#20#, 16#AD#, 16#74#,
      16#6E#, 16#1D#, 16#3B#, 16#62#, 16#8B#, 16#A7#, 16#9B#, 16#98#,
      16#59#, 16#F7#, 16#41#, 16#E0#, 16#82#, 16#54#, 16#2A#, 16#38#,
      16#55#, 16#02#, 16#F2#, 16#5D#, 16#BF#, 16#55#, 16#29#, 16#6C#,
      16#3A#, 16#54#, 16#5E#, 16#38#, 16#72#, 16#76#, 16#0A#, 16#B7#);
   Qy : Byte_Seq (0 .. 47) :=
     (16#36#, 16#17#, 16#DE#, 16#4A#, 16#96#, 16#26#, 16#2C#, 16#6F#,
      16#5D#, 16#9E#, 16#98#, 16#BF#, 16#92#, 16#92#, 16#DC#, 16#29#,
      16#F8#, 16#F4#, 16#1D#, 16#BD#, 16#28#, 16#9A#, 16#14#, 16#7C#,
      16#E9#, 16#DA#, 16#31#, 16#13#, 16#B5#, 16#F0#, 16#B8#, 16#C0#,
      16#0A#, 16#60#, 16#B1#, 16#CE#, 16#1D#, 16#7E#, 16#81#, 16#9D#,
      16#7A#, 16#43#, 16#1D#, 16#7C#, 16#90#, 16#EA#, 16#0E#, 16#5F#);

   R : constant Byte_Seq (0 .. 47) := (47 => 16#07#, others => 16#11#);
   S : constant Byte_Seq (0 .. 47) := (47 => 16#0D#, others => 16#22#);

   OK : Boolean;
begin
   Ctgrind.Make_Undefined (Qx'Address, Interfaces.C.size_t (Qx'Length));
   Ctgrind.Make_Undefined (Qy'Address, Interfaces.C.size_t (Qy'Length));

   OK := SPARKTLSCrypto.P384.ECDSA.Verify (Hash, Qx, Qy, R, S);

   Ctgrind.Make_Defined (OK'Address, Interfaces.C.size_t (1));
   Ctgrind.Use_Output (OK'Address, Interfaces.C.size_t (1));

   Put_Line ("ct_p384_ecdsa_verify: Verify completed (OK=" & OK'Image & ")");
   Ada.Command_Line.Set_Exit_Status (0);
end Ct_P384_ECDSA_Verify;
