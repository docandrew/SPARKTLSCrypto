with Ada.Text_IO; use Ada.Text_IO;
with Ada.Real_Time; use Ada.Real_Time;
with Interfaces; use Interfaces;
with SPARKNaCl; use SPARKNaCl;
with SPARKTLSCrypto.Fiat_25519; use SPARKTLSCrypto.Fiat_25519;
with SPARKTLSCrypto.X25519;
with SPARKTLSCrypto.Ed25519;
procedure Bench_Field25519 is
   A : FE := (2, 3, 5, 7, 11);
   B : constant FE := (13, 17, 19, 23, 29);
   N : Bytes_32 := (others => 42);
   P : constant Bytes_32 := (9, others => 0);
   Q, PK : Bytes_32;
   SK, Sig : Bytes_64;
   Sink : Unsigned_64 := 0 with Volatile;
   procedure Run (Sample, Kind : Natural) is
      Start : Time;
      Count : constant Positive := (if Kind < 2 then 200_000 else 100);
      Names : constant array (0 .. 3) of String (1 .. 7) :=
        ("mul    ", "sqr    ", "x25519 ", "ed_sign");
   begin
      Start := Clock;
      for I in 1 .. Count loop
         case Kind is
            when 0 => A := Mul (A, B);
            when 1 => A := Sqr (A);
            when 2 =>
               N (2) := N (2) + 1;
               SPARKTLSCrypto.X25519.Scalar_Mult (Q, N, P);
            when others =>
               N (2) := N (2) + 1;
               SPARKTLSCrypto.Ed25519.Sign (Sig, Byte_Seq (N), SK);
         end case;
      end loop;
      Put_Line (Sample'Image & "," & Names (Kind) & "," &
        Long_Float'Image (Long_Float (To_Duration (Clock - Start)) * 1.0E9 /
                         Long_Float (Count)));
      if Kind < 2 then Sink := Sink xor A (0);
      elsif Kind = 2 then Sink := Sink xor Unsigned_64 (Q (0));
      else Sink := Sink xor Unsigned_64 (Sig (0)); end if;
   end Run;
begin
   SPARKTLSCrypto.Ed25519.Keypair (N, PK, SK);
   Put_Line ("sample,operation,ns_per_op");
   for Sample in 0 .. 20 loop
      for I in 0 .. 3 loop Run (Sample, (Sample + I) mod 4); end loop;
   end loop;
   if Sink = Unsigned_64'Last then Put_Line ("sink"); end if;
end Bench_Field25519;
