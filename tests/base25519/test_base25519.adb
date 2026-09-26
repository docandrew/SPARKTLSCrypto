with Ada.Text_IO; use Ada.Text_IO;
with Interfaces; use Interfaces;
with Interfaces.C;
with System;
with SPARKNaCl; use SPARKNaCl;
with SPARKTLSCrypto.Ed25519;
with SPARKTLSCrypto.X25519;
procedure Test_Base25519 is
   function Oracle (Seed, PK, Sig, Msg : System.Address;
                    Len : Interfaces.C.size_t; XP : System.Address)
     return Interfaces.C.int
   with Import, Convention => C, External_Name => "base25519_check";
   use type Interfaces.C.int;
   Seed, PK, XP, Reference : Bytes_32;
   SK : Bytes_64;
   Random : Unsigned_64 := 16#C0FFEE123456789#;
   Lengths : constant array (Natural range 0 .. 8) of N32 :=
     (0, 1, 31, 32, 33, 64, 127, 128, 255);
   Hex : constant String := "0123456789abcdef";
   procedure Emit (B : Byte_Seq) is
   begin
      for V of B loop
         Put (Hex (Natural (V / 16) + 1));
         Put (Hex (Natural (V mod 16) + 1));
      end loop;
   end Emit;
begin
   for Sample in 0 .. 4095 loop
      for I in Seed'Range loop
         Random := Random xor Shift_Left (Random, 13);
         Random := Random xor Shift_Right (Random, 7);
         Random := Random xor Shift_Left (Random, 17);
         Seed (I) := Byte (Random and 255);
      end loop;
      if Sample = 0 then Seed := (others => 0);
      elsif Sample = 1 then Seed := (others => 255);
      elsif Sample < 258 then
         Seed := (others => 0);
         Seed (N32 ((Sample - 2) / 8)) := Shift_Left (Byte (1), (Sample - 2) mod 8);
      end if;
      declare
         Len : constant N32 := Lengths (Sample mod Lengths'Length);
         Msg : Byte_Seq (0 .. Len - 1);
         SM, Recovered : Byte_Seq (0 .. Len + 63);
         Valid : Boolean;
         Recovered_Len : I32;
      begin
         for I in Msg'Range loop Msg (I) := Byte ((I + N32 (Sample)) mod 256); end loop;
         SPARKTLSCrypto.Ed25519.Keypair (Seed, PK, SK);
         SPARKTLSCrypto.Ed25519.Sign (SM, Msg, SK);
         SPARKTLSCrypto.X25519.Scalar_Mult_Base (XP, Seed);
         SPARKTLSCrypto.X25519.Scalar_Mult (Reference, Seed, (9, others => 0));
         if XP /= Reference or else SM (64 .. SM'Last) /= Msg or else
            Oracle (Seed'Address, PK'Address, SM'Address, Msg'Address,
                    Interfaces.C.size_t (Len), XP'Address) /= 1
         then raise Program_Error with "independent oracle mismatch" & Sample'Image; end if;
         SPARKTLSCrypto.Ed25519.Open (Recovered, Valid, Recovered_Len, SM, PK);
         if not Valid or else Recovered_Len /= Len or else Recovered (0 .. Len - 1) /= Msg
         then raise Program_Error with "signature did not verify"; end if;
         Emit (PK); Emit (SM); Emit (XP); New_Line;
      end;
   end loop;
   Put_Line ("PASS: 4096 Ed25519 key/sign/open and X25519 base cases");
end Test_Base25519;
