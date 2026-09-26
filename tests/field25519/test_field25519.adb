with Ada.Text_IO; use Ada.Text_IO;
with Interfaces; use Interfaces;
with Interfaces.C;
with System;
with SPARKTLSCrypto.Fiat_25519; use SPARKTLSCrypto.Fiat_25519;
procedure Test_Field25519 is
   function Oracle
     (Op : Interfaces.C.int; R, A, B : System.Address; S : Unsigned_64)
      return Interfaces.C.int
   with Import, Convention => C, External_Name => "field25519_check";
   use type Interfaces.C.int;
   Limit : constant Unsigned_64 := 2**53;
   Values : constant array (Natural range <>) of Unsigned_64 :=
     (0, 1, Mask51 - 1, Mask51, Tight51, Tight51 + 1,
      2 * Tight51 - 1, 2 * Tight51, Limit - 1, Limit);
   State : Unsigned_64 := 16#3DA0_215B_68A9_317D#;
   Digest : Unsigned_64 := 16#CBF2_9CE4_8422_2325#;
   Total : Natural := 0;
   A, B, R : aliased FE;
   function Next return Unsigned_64 is
   begin
      State := State xor Shift_Left (State, 13);
      State := State xor Shift_Right (State, 7);
      State := State xor Shift_Left (State, 17);
      return State;
   end Next;
   procedure Check (Op : Interfaces.C.int; S : Unsigned_64 := 0) is
   begin
      if Oracle (Op, R'Address, A'Address, B'Address, S) /= 1 then
         raise Program_Error with "field oracle mismatch at case" & Total'Image;
      end if;
      --  Hash exact output limbs, not just their residues modulo p. The
      --  preserved baseline's digest catches representation changes too.
      for Limb of R loop
         Digest := (Digest xor Limb) * 16#100_0000_01B3#;
      end loop;
      Total := Total + 1;
   end Check;
   procedure Exercise is
      Scalar : constant Unsigned_64 := Next mod 131072;
   begin
      R := Mul (A, B); Check (0);
      R := Sqr (A); Check (1);
      R := Scmul (A, Scalar); Check (2, Scalar);
   end Exercise;
begin
   for X of Values loop
      for Y of Values loop
         A := (others => X); B := (others => Y); Exercise;
         for I in A'Range loop
            A := (others => Limit); A (I) := X;
            B := (others => 0); B (I) := Y; Exercise;
         end loop;
      end loop;
   end loop;
   for Case_No in 1 .. 10_000 loop
      for I in A'Range loop
         A (I) := Next mod (Limit + 1);
         B (I) := Next mod (Limit + 1);
      end loop;
      Exercise;
   end loop;
   if Digest /= 847_381_207_782_782_335 then
      raise Program_Error with "exact-limb baseline digest changed";
   end if;
   Put_Line ("PASS: field25519 OpenSSL arithmetic checks:" & Total'Image);
   Put_Line ("Exact-limb digest:" & Digest'Image);
end Test_Field25519;
