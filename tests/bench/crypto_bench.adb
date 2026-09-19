--  Cycle counts (rdtsc) and ops/s for the public-key primitives a TLS
--  handshake pays for, in the shape openssl speed reports them: X25519
--  scalar multiplication, Ed25519 sign and open, P-256 ECDSA sign and
--  verify, RSA-2048 PSS sign (CRT) and verify. The RSA key is the one the
--  ctgrind harness uses. Optimize build of the library.

with Ada.Text_IO;         use Ada.Text_IO;
with Ada.Real_Time;       use Ada.Real_Time;
with Interfaces;          use Interfaces;
with System.Machine_Code; use System.Machine_Code;
with SPARKNaCl;           use SPARKNaCl;
with SPARKTLSCrypto.RSA;
with SPARKTLSCrypto.BigNat64;
with SPARKTLSCrypto.Fiat_P256;
with SPARKTLSCrypto.X25519;
with SPARKTLSCrypto.Ed25519;
with SPARKTLSCrypto.P256.ECDSA;
with SPARKTLSCrypto.P256.Point;

procedure Crypto_Bench is
   --  Fixed blinding inputs: the bench measures the blinded paths as production runs them
   Blind16 : constant Bytes_16 := (others => 16#42#);
   Blind40 : constant Byte_Seq (0 .. 39) := (others => 16#7E#);

   function Rdtsc return Unsigned_64 is
      Lo, Hi : Unsigned_32;
   begin
      Asm ("rdtsc",
           Outputs => (Unsigned_32'Asm_Output ("=a", Lo), Unsigned_32'Asm_Output ("=d", Hi)),
           Volatile => True);
      return Unsigned_64 (Hi) * 2**32 or Unsigned_64 (Lo);
   end Rdtsc;

   type Samples is array (Positive range <>) of Unsigned_64;

   procedure Report (Name : String; S : in out Samples; Secs : Duration) is
      T : Unsigned_64;
   begin
      for I in S'Range loop
         for J in reverse I + 1 .. S'Last loop
            if S (J) < S (J - 1) then
               T := S (J); S (J) := S (J - 1); S (J - 1) := T;
            end if;
         end loop;
      end loop;
      Put_Line ("  " & Name & ": median" & S (S'First + S'Length / 2)'Image
                & " cycles," & Integer (Duration (S'Length) / Secs)'Image & " ops/s");
   end Report;

--  poisoned: d, p, q, dP, dQ, qInv. The library makes no key-dependent
--  branch on this path except one: after signing it verifies the result
--  under the public key (constant-time compare) and branches on the
--  outcome. That bit is public by construction, but its operands derive
--  from the key, so memcheck reports the branch and the two places the
--  resulting Boolean flows to (Sign_PSS's OK, this program's print).
--  Expected memcheck count: exactly 3. See run.sh.
   K_N : constant Byte_Seq (0 .. 255) :=
     (
      16#AB#, 16#38#, 16#CC#, 16#55#, 16#C2#, 16#D2#, 16#20#, 16#EA#, 16#8B#, 16#AB#, 16#20#, 16#6C#,
      16#E7#, 16#2D#, 16#5E#, 16#AC#, 16#80#, 16#95#, 16#3D#, 16#7E#, 16#C9#, 16#2E#, 16#4C#, 16#19#,
      16#42#, 16#62#, 16#20#, 16#94#, 16#85#, 16#B5#, 16#0D#, 16#AF#, 16#A8#, 16#A5#, 16#20#, 16#3D#,
      16#E0#, 16#20#, 16#A9#, 16#5A#, 16#EB#, 16#45#, 16#6E#, 16#95#, 16#3B#, 16#2F#, 16#A8#, 16#64#,
      16#ED#, 16#4A#, 16#03#, 16#34#, 16#D1#, 16#70#, 16#9F#, 16#8A#, 16#B8#, 16#8B#, 16#54#, 16#84#,
      16#77#, 16#E6#, 16#00#, 16#EF#, 16#9B#, 16#B9#, 16#59#, 16#AA#, 16#86#, 16#95#, 16#DB#, 16#A0#,
      16#74#, 16#B3#, 16#92#, 16#96#, 16#8F#, 16#80#, 16#95#, 16#AC#, 16#D5#, 16#6C#, 16#5C#, 16#C5#,
      16#03#, 16#19#, 16#C2#, 16#46#, 16#54#, 16#9F#, 16#35#, 16#57#, 16#58#, 16#DB#, 16#F1#, 16#26#,
      16#D1#, 16#F2#, 16#2D#, 16#14#, 16#98#, 16#16#, 16#19#, 16#96#, 16#47#, 16#37#, 16#08#, 16#42#,
      16#AE#, 16#16#, 16#E1#, 16#0E#, 16#16#, 16#94#, 16#67#, 16#ED#, 16#ED#, 16#C5#, 16#E1#, 16#20#,
      16#A6#, 16#78#, 16#15#, 16#E8#, 16#1B#, 16#58#, 16#83#, 16#C3#, 16#59#, 16#9C#, 16#C0#, 16#A2#,
      16#26#, 16#9E#, 16#78#, 16#D7#, 16#B9#, 16#60#, 16#6F#, 16#1D#, 16#35#, 16#4D#, 16#26#, 16#74#,
      16#B0#, 16#83#, 16#4D#, 16#5B#, 16#EA#, 16#7B#, 16#1F#, 16#77#, 16#5E#, 16#3A#, 16#CE#, 16#5C#,
      16#2D#, 16#E1#, 16#10#, 16#98#, 16#5D#, 16#57#, 16#C5#, 16#83#, 16#47#, 16#24#, 16#B3#, 16#8C#,
      16#99#, 16#44#, 16#B8#, 16#C0#, 16#1D#, 16#64#, 16#37#, 16#C4#, 16#74#, 16#2C#, 16#3B#, 16#B7#,
      16#E1#, 16#C8#, 16#A8#, 16#4F#, 16#FA#, 16#B7#, 16#EC#, 16#38#, 16#A3#, 16#25#, 16#0B#, 16#04#,
      16#15#, 16#CF#, 16#4D#, 16#A8#, 16#2D#, 16#19#, 16#6C#, 16#C6#, 16#07#, 16#13#, 16#9C#, 16#D5#,
      16#20#, 16#AF#, 16#DC#, 16#11#, 16#2D#, 16#63#, 16#C0#, 16#13#, 16#79#, 16#05#, 16#B6#, 16#72#,
      16#0E#, 16#85#, 16#C4#, 16#BE#, 16#ED#, 16#46#, 16#94#, 16#BF#, 16#82#, 16#1A#, 16#07#, 16#AC#,
      16#58#, 16#8C#, 16#E5#, 16#CF#, 16#0D#, 16#34#, 16#82#, 16#31#, 16#F3#, 16#BA#, 16#4B#, 16#F6#,
      16#21#, 16#DF#, 16#6E#, 16#B1#, 16#13#, 16#3B#, 16#ED#, 16#1B#, 16#7E#, 16#52#, 16#F2#, 16#CD#,
      16#52#, 16#43#, 16#13#, 16#79#);
   K_D : constant Byte_Seq (0 .. 255) :=
     (
      16#34#, 16#C5#, 16#44#, 16#20#, 16#D8#, 16#73#, 16#17#, 16#C7#, 16#01#, 16#F5#, 16#E3#, 16#7F#,
      16#FC#, 16#FD#, 16#FC#, 16#34#, 16#51#, 16#4A#, 16#ED#, 16#D1#, 16#92#, 16#22#, 16#AD#, 16#3C#,
      16#89#, 16#BB#, 16#A1#, 16#8B#, 16#F4#, 16#EB#, 16#98#, 16#C4#, 16#BF#, 16#46#, 16#E9#, 16#39#,
      16#78#, 16#C6#, 16#C8#, 16#3B#, 16#67#, 16#D0#, 16#95#, 16#E4#, 16#F3#, 16#81#, 16#5C#, 16#36#,
      16#82#, 16#F5#, 16#B1#, 16#28#, 16#49#, 16#B6#, 16#9A#, 16#CD#, 16#4F#, 16#D4#, 16#4D#, 16#5F#,
      16#A8#, 16#6E#, 16#60#, 16#72#, 16#78#, 16#BD#, 16#B6#, 16#F7#, 16#7A#, 16#14#, 16#5C#, 16#C4#,
      16#C6#, 16#C3#, 16#03#, 16#96#, 16#58#, 16#B3#, 16#0A#, 16#2E#, 16#62#, 16#F6#, 16#CB#, 16#5E#,
      16#C2#, 16#F6#, 16#60#, 16#EC#, 16#79#, 16#2F#, 16#3A#, 16#6A#, 16#E9#, 16#CD#, 16#9B#, 16#B4#,
      16#D9#, 16#B6#, 16#F8#, 16#92#, 16#E4#, 16#CE#, 16#C6#, 16#E3#, 16#0C#, 16#9E#, 16#D6#, 16#F2#,
      16#6A#, 16#22#, 16#4E#, 16#09#, 16#A0#, 16#06#, 16#EC#, 16#43#, 16#25#, 16#E9#, 16#BB#, 16#59#,
      16#6B#, 16#45#, 16#0E#, 16#87#, 16#63#, 16#4A#, 16#34#, 16#0D#, 16#73#, 16#96#, 16#C6#, 16#1D#,
      16#4F#, 16#FE#, 16#28#, 16#80#, 16#65#, 16#67#, 16#F0#, 16#0C#, 16#42#, 16#76#, 16#9F#, 16#6D#,
      16#F6#, 16#A0#, 16#D0#, 16#12#, 16#97#, 16#5B#, 16#F9#, 16#03#, 16#65#, 16#A7#, 16#0D#, 16#D6#,
      16#CC#, 16#98#, 16#4A#, 16#7B#, 16#EA#, 16#5F#, 16#C4#, 16#F9#, 16#49#, 16#84#, 16#3A#, 16#7F#,
      16#91#, 16#7F#, 16#8F#, 16#68#, 16#B8#, 16#35#, 16#71#, 16#80#, 16#5F#, 16#42#, 16#D9#, 16#A1#,
      16#29#, 16#95#, 16#2F#, 16#9D#, 16#E4#, 16#0C#, 16#AA#, 16#6F#, 16#97#, 16#E7#, 16#99#, 16#BC#,
      16#1F#, 16#03#, 16#E1#, 16#99#, 16#27#, 16#29#, 16#2E#, 16#38#, 16#FB#, 16#48#, 16#2B#, 16#93#,
      16#D5#, 16#22#, 16#0D#, 16#CE#, 16#AA#, 16#2E#, 16#86#, 16#FA#, 16#9E#, 16#96#, 16#C5#, 16#13#,
      16#73#, 16#21#, 16#E0#, 16#43#, 16#FF#, 16#10#, 16#D3#, 16#CE#, 16#F4#, 16#99#, 16#2E#, 16#0B#,
      16#58#, 16#0D#, 16#9E#, 16#32#, 16#20#, 16#2C#, 16#BB#, 16#1C#, 16#C9#, 16#95#, 16#B0#, 16#62#,
      16#B8#, 16#2C#, 16#77#, 16#35#, 16#88#, 16#61#, 16#B9#, 16#DD#, 16#76#, 16#0D#, 16#FD#, 16#AD#,
      16#79#, 16#50#, 16#EB#, 16#0B#);
   K_P : constant Byte_Seq (0 .. 127) :=
     (
      16#D1#, 16#E2#, 16#0B#, 16#73#, 16#F3#, 16#2F#, 16#14#, 16#4E#, 16#13#, 16#4C#, 16#4F#, 16#37#,
      16#11#, 16#43#, 16#29#, 16#AF#, 16#09#, 16#CE#, 16#A3#, 16#2B#, 16#80#, 16#4C#, 16#B8#, 16#5B#,
      16#DA#, 16#3C#, 16#E5#, 16#47#, 16#1E#, 16#2A#, 16#5A#, 16#91#, 16#A0#, 16#EB#, 16#C3#, 16#26#,
      16#34#, 16#1E#, 16#EB#, 16#CE#, 16#E6#, 16#98#, 16#B4#, 16#AC#, 16#19#, 16#AC#, 16#CC#, 16#F1#,
      16#1C#, 16#1A#, 16#00#, 16#A0#, 16#DF#, 16#25#, 16#66#, 16#92#, 16#DA#, 16#5C#, 16#98#, 16#69#,
      16#FA#, 16#0C#, 16#15#, 16#A6#, 16#E1#, 16#29#, 16#7C#, 16#62#, 16#B7#, 16#A3#, 16#8A#, 16#DE#,
      16#B5#, 16#27#, 16#9F#, 16#0A#, 16#23#, 16#C0#, 16#75#, 16#F6#, 16#8E#, 16#BB#, 16#8A#, 16#1C#,
      16#35#, 16#3B#, 16#13#, 16#EA#, 16#8E#, 16#E9#, 16#61#, 16#E5#, 16#C3#, 16#DC#, 16#F3#, 16#FA#,
      16#AF#, 16#3A#, 16#DE#, 16#8E#, 16#58#, 16#85#, 16#9F#, 16#6A#, 16#45#, 16#90#, 16#F5#, 16#D5#,
      16#A6#, 16#96#, 16#7C#, 16#D4#, 16#04#, 16#33#, 16#D3#, 16#BF#, 16#DD#, 16#4B#, 16#0F#, 16#FE#,
      16#64#, 16#9B#, 16#AA#, 16#DD#, 16#23#, 16#58#, 16#7C#, 16#0B#);
   K_Q : constant Byte_Seq (0 .. 127) :=
     (
      16#D0#, 16#D8#, 16#0F#, 16#02#, 16#01#, 16#2D#, 16#09#, 16#77#, 16#6B#, 16#06#, 16#76#, 16#5F#,
      16#63#, 16#71#, 16#77#, 16#A2#, 16#7F#, 16#A0#, 16#AC#, 16#CE#, 16#BC#, 16#4A#, 16#51#, 16#BF#,
      16#2B#, 16#51#, 16#3E#, 16#56#, 16#52#, 16#5C#, 16#22#, 16#41#, 16#4E#, 16#2A#, 16#A8#, 16#17#,
      16#3E#, 16#F1#, 16#E1#, 16#AC#, 16#CD#, 16#A2#, 16#7A#, 16#D1#, 16#BD#, 16#55#, 16#A3#, 16#B2#,
      16#73#, 16#7D#, 16#32#, 16#39#, 16#5F#, 16#AC#, 16#B7#, 16#2E#, 16#F0#, 16#4D#, 16#40#, 16#BA#,
      16#B3#, 16#5F#, 16#B2#, 16#A1#, 16#AE#, 16#65#, 16#69#, 16#7B#, 16#57#, 16#06#, 16#85#, 16#A0#,
      16#80#, 16#B8#, 16#2C#, 16#B6#, 16#7A#, 16#7E#, 16#5E#, 16#FA#, 16#72#, 16#48#, 16#40#, 16#99#,
      16#01#, 16#80#, 16#20#, 16#A0#, 16#E8#, 16#5A#, 16#4D#, 16#D9#, 16#47#, 16#29#, 16#45#, 16#1C#,
      16#99#, 16#A2#, 16#1E#, 16#AC#, 16#5F#, 16#E5#, 16#88#, 16#77#, 16#B2#, 16#9E#, 16#D9#, 16#4E#,
      16#31#, 16#43#, 16#64#, 16#C4#, 16#21#, 16#2A#, 16#83#, 16#79#, 16#D8#, 16#07#, 16#2E#, 16#0C#,
      16#7D#, 16#EE#, 16#77#, 16#C8#, 16#A7#, 16#09#, 16#9D#, 16#0B#);
   K_DP : constant Byte_Seq (0 .. 127) :=
     (
      16#2B#, 16#A4#, 16#D1#, 16#B4#, 16#DE#, 16#D0#, 16#DF#, 16#6C#, 16#0C#, 16#DF#, 16#45#, 16#69#,
      16#B2#, 16#11#, 16#41#, 16#4D#, 16#C0#, 16#C0#, 16#53#, 16#75#, 16#EC#, 16#4C#, 16#07#, 16#DA#,
      16#31#, 16#DB#, 16#8F#, 16#E1#, 16#E6#, 16#07#, 16#F0#, 16#A5#, 16#6F#, 16#CD#, 16#16#, 16#DB#,
      16#8E#, 16#E3#, 16#0F#, 16#2E#, 16#0B#, 16#0D#, 16#9E#, 16#24#, 16#5B#, 16#82#, 16#6F#, 16#6B#,
      16#83#, 16#E8#, 16#74#, 16#50#, 16#FF#, 16#96#, 16#0B#, 16#6A#, 16#66#, 16#35#, 16#F3#, 16#0B#,
      16#B6#, 16#8F#, 16#64#, 16#C1#, 16#3A#, 16#F9#, 16#21#, 16#80#, 16#75#, 16#A7#, 16#70#, 16#6D#,
      16#37#, 16#46#, 16#71#, 16#EF#, 16#ED#, 16#D7#, 16#4B#, 16#B0#, 16#65#, 16#A5#, 16#E1#, 16#E6#,
      16#53#, 16#BB#, 16#61#, 16#3C#, 16#D9#, 16#52#, 16#F6#, 16#A4#, 16#8C#, 16#C2#, 16#19#, 16#89#,
      16#FB#, 16#7E#, 16#46#, 16#61#, 16#5B#, 16#4F#, 16#0E#, 16#03#, 16#4F#, 16#4C#, 16#01#, 16#92#,
      16#D7#, 16#FD#, 16#5B#, 16#1F#, 16#CB#, 16#6F#, 16#EB#, 16#8C#, 16#6E#, 16#3B#, 16#F9#, 16#AB#,
      16#70#, 16#C8#, 16#5E#, 16#13#, 16#76#, 16#12#, 16#24#, 16#59#);
   K_DQ : constant Byte_Seq (0 .. 127) :=
     (
      16#71#, 16#ED#, 16#1B#, 16#2A#, 16#C5#, 16#C7#, 16#72#, 16#BD#, 16#91#, 16#45#, 16#C2#, 16#37#,
      16#41#, 16#01#, 16#39#, 16#F9#, 16#0C#, 16#54#, 16#73#, 16#50#, 16#87#, 16#C8#, 16#A7#, 16#15#,
      16#79#, 16#24#, 16#E5#, 16#B3#, 16#A3#, 16#54#, 16#1D#, 16#5F#, 16#B0#, 16#AB#, 16#76#, 16#6C#,
      16#CF#, 16#EA#, 16#95#, 16#68#, 16#75#, 16#F8#, 16#E7#, 16#B5#, 16#18#, 16#EA#, 16#E9#, 16#D4#,
      16#C4#, 16#49#, 16#8C#, 16#A7#, 16#5D#, 16#B8#, 16#D3#, 16#69#, 16#28#, 16#AF#, 16#8B#, 16#DB#,
      16#0D#, 16#54#, 16#EC#, 16#16#, 16#65#, 16#13#, 16#6F#, 16#5A#, 16#58#, 16#5B#, 16#F7#, 16#73#,
      16#5A#, 16#24#, 16#9E#, 16#47#, 16#A1#, 16#44#, 16#E4#, 16#BD#, 16#0C#, 16#B0#, 16#BB#, 16#84#,
      16#7C#, 16#1C#, 16#10#, 16#30#, 16#96#, 16#F0#, 16#04#, 16#3D#, 16#BE#, 16#23#, 16#16#, 16#4F#,
      16#86#, 16#C3#, 16#B8#, 16#A5#, 16#E1#, 16#DE#, 16#4D#, 16#F6#, 16#B6#, 16#1B#, 16#0F#, 16#82#,
      16#27#, 16#3F#, 16#93#, 16#6D#, 16#A6#, 16#86#, 16#11#, 16#98#, 16#DB#, 16#2E#, 16#F7#, 16#80#,
      16#DB#, 16#05#, 16#C6#, 16#94#, 16#50#, 16#02#, 16#DF#, 16#87#);
   K_QI : constant Byte_Seq (0 .. 127) :=
     (
      16#05#, 16#24#, 16#3E#, 16#F7#, 16#88#, 16#2F#, 16#A9#, 16#AD#, 16#66#, 16#53#, 16#73#, 16#90#,
      16#04#, 16#9F#, 16#1B#, 16#3E#, 16#BE#, 16#BE#, 16#7B#, 16#B5#, 16#98#, 16#EA#, 16#14#, 16#33#,
      16#2E#, 16#F1#, 16#74#, 16#4B#, 16#6E#, 16#74#, 16#D9#, 16#2E#, 16#46#, 16#CF#, 16#C0#, 16#2E#,
      16#C3#, 16#CB#, 16#39#, 16#10#, 16#60#, 16#6E#, 16#FE#, 16#13#, 16#0A#, 16#06#, 16#F3#, 16#E2#,
      16#52#, 16#D4#, 16#D3#, 16#23#, 16#D4#, 16#42#, 16#DF#, 16#A0#, 16#B0#, 16#0F#, 16#5F#, 16#D1#,
      16#86#, 16#A6#, 16#A5#, 16#89#, 16#11#, 16#7C#, 16#14#, 16#41#, 16#E4#, 16#CD#, 16#F2#, 16#C7#,
      16#0F#, 16#0C#, 16#CC#, 16#03#, 16#9D#, 16#BB#, 16#2B#, 16#E0#, 16#8F#, 16#84#, 16#60#, 16#47#,
      16#FB#, 16#63#, 16#60#, 16#28#, 16#0A#, 16#26#, 16#12#, 16#6D#, 16#18#, 16#12#, 16#E4#, 16#19#,
      16#48#, 16#F7#, 16#57#, 16#88#, 16#E3#, 16#AE#, 16#24#, 16#D0#, 16#95#, 16#34#, 16#6C#, 16#FF#,
      16#48#, 16#A3#, 16#E1#, 16#67#, 16#3C#, 16#30#, 16#9C#, 16#BD#, 16#1E#, 16#CE#, 16#01#, 16#ED#,
      16#75#, 16#57#, 16#07#, 16#F8#, 16#FA#, 16#69#, 16#F5#, 16#C8#);
   Hash : constant Bytes_32 := (others => 16#5A#);
   Salt : constant Bytes_32 := (others => 16#A5#);

   Sink : Unsigned_8 := 0 with Volatile;
begin
   Put_Line ("SPARKTLSCrypto public-key primitives");

   --  X25519
   declare
      N   : constant := 3000;
      Sm  : Samples (1 .. N);
      SK  : constant Bytes_32 := (16#77#, others => 16#42#);
      PK  : Bytes_32 := (9, others => 0);
      Q   : Bytes_32;
      T0  : Unsigned_64; W0 : constant Time := Clock;
   begin
      for I in 1 .. N loop
         T0 := Rdtsc;
         SPARKTLSCrypto.X25519.Scalar_Mult (Q, SK, PK);
         Sm (I) := Rdtsc - T0;
         PK := Q;
      end loop;
      Sink := Sink xor Q (0);
      Report ("X25519 Scalar_Mult", Sm, To_Duration (Clock - W0));
   end;

   --  Ed25519
   declare
      N    : constant := 2000;
      Ss, So : Samples (1 .. N);
      Seed : constant Bytes_32 := (others => 16#31#);
      PK   : Bytes_32;
      SK   : Bytes_64;
      M    : constant Byte_Seq (0 .. 63) := (others => 16#A5#);
      SM   : Byte_Seq (0 .. 127);
      MO   : Byte_Seq (0 .. 127);
      Valid : Boolean;
      Len   : I32;
      T0   : Unsigned_64; W0 : Time; Secs_S : Duration;
   begin
      SPARKTLSCrypto.Ed25519.Keypair (Seed, PK, SK);
      W0 := Clock;
      for I in 1 .. N loop
         T0 := Rdtsc;
         SPARKTLSCrypto.Ed25519.Sign (SM, M, SK);
         Ss (I) := Rdtsc - T0;
      end loop;
      Secs_S := To_Duration (Clock - W0);
      W0 := Clock;
      for I in 1 .. N loop
         T0 := Rdtsc;
         SPARKTLSCrypto.Ed25519.Open (MO, Valid, Len, SM, PK);
         So (I) := Rdtsc - T0;
         Sink := Sink xor Boolean'Pos (Valid);
      end loop;
      Report ("Ed25519 Sign (64-byte msg)", Ss, Secs_S);
      Report ("Ed25519 Open", So, To_Duration (Clock - W0));
   end;

   --  P-256 ECDSA
   declare
      use SPARKTLSCrypto.P256.ECDSA;
      N     : constant := 2000;
      Ss, Sv : Samples (1 .. N);
      Hash  : constant Bytes_32 := (others => 16#5A#);
      D     : constant ECDSA_Sig_Half := (16#01#, others => 16#3C#);
      K     : constant ECDSA_Sig_Half := (16#02#, others => 16#7E#);
      R, S  : ECDSA_Sig_Half;
      OK    : Boolean;
      Qx, Qy : ECDSA_Sig_Half;
      T0    : Unsigned_64; W0 : Time; Secs_S : Duration;
   begin
      declare
         Pt  : SPARKTLSCrypto.P256.Point.P256_Jacobian;
         Enc : Byte_Seq (0 .. 64);
      begin
         SPARKTLSCrypto.P256.Point.P256_Mulgen (Pt, Bytes_32 (D), 32);
         SPARKTLSCrypto.P256.Point.P256_To_Affine (Pt);
         SPARKTLSCrypto.P256.Point.P256_Encode (Enc, Pt);
         Qx := ECDSA_Sig_Half (Enc (1 .. 32));
         Qy := ECDSA_Sig_Half (Enc (33 .. 64));
      end;
      W0 := Clock;
      for I in 1 .. N loop
         T0 := Rdtsc;
         Sign (Hash, D, K, Blind40, R, S, OK);
         Ss (I) := Rdtsc - T0;
      end loop;
      Secs_S := To_Duration (Clock - W0);
      W0 := Clock;
      for I in 1 .. N loop
         T0 := Rdtsc;
         OK := Verify (Hash, Qx, Qy, R, S);
         Sv (I) := Rdtsc - T0;
         Sink := Sink xor Boolean'Pos (OK);
      end loop;
      Report ("P-256 ECDSA Sign", Ss, Secs_S);
      Report ("P-256 ECDSA Verify (valid=" & OK'Image & ")", Sv, To_Duration (Clock - W0));
   end;

   --  RSA-2048 PSS
   declare
      N      : constant := 300;
      Ss, Sv : Samples (1 .. N);
      D      : constant Byte_Seq (0 .. 255) := K_D;
      CRT    : SPARKTLSCrypto.RSA.CRT_Params;
      Sig    : Byte_Seq (0 .. 255) := (others => 0);
      Sig_Len : N32;
      OK     : Boolean;
      T0     : Unsigned_64; W0 : Time; Secs_S : Duration;
   begin
      CRT.Valid := True;
      CRT.Prime_Len := 128;
      CRT.P (0 .. 127) := K_P;   CRT.Q (0 .. 127) := K_Q;
      CRT.DP (0 .. 127) := K_DP; CRT.DQ (0 .. 127) := K_DQ;
      CRT.QInv (0 .. 127) := K_QI;
      W0 := Clock;
      for I in 1 .. N loop
         T0 := Rdtsc;
         SPARKTLSCrypto.RSA.Sign_PSS
           (M_Hash => Hash, Hash_Len => 32, Hash_Alg => SPARKTLSCrypto.RSA.PSS_SHA256,
            Modulus => K_N, Mod_Len => 256, Priv_Exp => D, Salt => Salt,
            Signature => Sig, Sig_Len => Sig_Len, OK => OK, Blind => Blind16,
            Pub_Exp => 65537, CRT => CRT);
         Ss (I) := Rdtsc - T0;
      end loop;
      Secs_S := To_Duration (Clock - W0);
      Put_Line ("  (RSA sign OK=" & OK'Image & ", Sig_Len=" & Sig_Len'Image & ")");
      W0 := Clock;
      for I in 1 .. N loop
         T0 := Rdtsc;
         OK := SPARKTLSCrypto.RSA.Verify_PSS_SHA256 (Hash, K_N, 256, 65537, Sig, 256);
         Sv (I) := Rdtsc - T0;
         Sink := Sink xor Boolean'Pos (OK);
      end loop;
      Report ("RSA-2048 PSS Sign (CRT)", Ss, Secs_S);
      Report ("RSA-2048 PSS Verify (valid=" & OK'Image & ")", Sv, To_Duration (Clock - W0));
   end;
   --  BigNat64 building blocks at the 1024-bit (16-word) size the RSA-2048
   --  CRT signer runs: Monty_Mul, R2_Mod and one Modpow_Top with the real
   --  prime p and exponent dP, to attribute the RSA sign cost.
   declare
      use SPARKTLSCrypto.BigNat64;
      N    : constant := 2000;
      Sm   : Samples (1 .. N);
      Sr   : Samples (1 .. 200);
      Se   : Samples (1 .. 50);
      P, XP, R2P, T, Acc : Big_Nat;
      P0I  : Word;
      T0   : Unsigned_64; W0 : Time; Secs : Duration;
   begin
      Decode (P, K_P);
      Decode (XP, K_DQ);       --  any value < p will do as an operand
      P0I := Ninv (P.W (0));
      R2_Mod (R2P, P, P0I);
      Put_Line ("  (bignat: Len =" & P.Len'Image & " words)");
      W0 := Clock;
      for I in 1 .. 200 loop
         T0 := Rdtsc;
         R2_Mod (T, P, P0I);
         Sr (I) := Rdtsc - T0;
      end loop;
      Report ("BigNat64 R2_Mod (16 words)", Sr, To_Duration (Clock - W0));
      Acc := R2P;
      W0 := Clock;
      for I in 1 .. N loop
         T0 := Rdtsc;
         Monty_Mul (T, Acc, XP, P, P0I);
         Sm (I) := Rdtsc - T0;
         Acc := T;
      end loop;
      Sink := Sink xor Unsigned_8 (Acc.W (0) and 255);
      Report ("BigNat64 Monty_Mul (16 words)", Sm, To_Duration (Clock - W0));
      Acc := R2P;
      W0 := Clock;
      for I in 1 .. N loop
         T0 := Rdtsc;
         Monty_Sqr (T, Acc, P, P0I);
         Sm (I) := Rdtsc - T0;
         Acc := T;
      end loop;
      Sink := Sink xor Unsigned_8 (Acc.W (0) and 255);
      Report ("BigNat64 Monty_Sqr (16 words)", Sm, To_Duration (Clock - W0));
      W0 := Clock;
      for I in 1 .. 50 loop
         T0 := Rdtsc;
         Modpow_Top (T, XP, K_DP, P, P0I);
         Se (I) := Rdtsc - T0;
      end loop;
      Sink := Sink xor Unsigned_8 (T.W (0) and 255);
      Report ("BigNat64 Modpow_Top (1024-bit exp, 16 words)", Se, To_Duration (Clock - W0));
   end;
   --  P-256 field multiply (Fiat port), the primitive under every
   --  point operation.
   declare
      use SPARKTLSCrypto.Fiat_P256;
      N  : constant := 20000;
      S  : Samples (1 .. N);
      A  : FE := (16#0123_4567_89AB_CDEF#, 16#FEDC_BA98_7654_3210#,
                  16#0F0F_0F0F_0F0F_0F0F#, 16#1234_5678_9ABC_DEF0#);
      B  : constant FE := (16#7777_7777_7777_7777#, 16#8888_8888_8888_8888#,
                           16#9999_9999_9999_9999#, 16#0AAA_AAAA_AAAA_AAAA#);
      T0 : Unsigned_64; W0 : constant Time := Clock;
   begin
      for I in 1 .. N loop
         T0 := Rdtsc;
         A := Mul (A, B);
         A := Mul (A, B);
         A := Mul (A, B);
         A := Mul (A, B);
         S (I) := (Rdtsc - T0) / 4;
      end loop;
      Sink := Sink xor Unsigned_8 (A (0) and 255);
      Report ("Fiat P-256 Mul (per op, 4 chained)", S, To_Duration (Clock - W0));
   end;
   --  P-256 building blocks: fixed-base scalar mult alone, and the
   --  Jacobian-to-affine conversion (one inversion mod p).
   declare
      use SPARKTLSCrypto.P256.Point;
      N  : constant := 3000;
      S1 : Samples (1 .. N);
      S2 : Samples (1 .. N);
      K  : Bytes_32 := (others => 16#5A#);
      Pt : P256_Jacobian;
      T0 : Unsigned_64; W0 : Time;
   begin
      W0 := Clock;
      for I in 1 .. N loop
         K (31) := Unsigned_8 (I mod 256);
         T0 := Rdtsc;
         P256_Mulgen (Pt, Byte_Seq (K), 32);
         S1 (I) := Rdtsc - T0;
      end loop;
      Sink := Sink xor Unsigned_8 (Pt.X (0) and 255);
      Report ("P-256 Mulgen (fixed-base [k]G)", S1, To_Duration (Clock - W0));
      W0 := Clock;
      for I in 1 .. N loop
         T0 := Rdtsc;
         P256_To_Affine (Pt);
         S2 (I) := Rdtsc - T0;
         Pt.Z := Pt.X;
      end loop;
      Sink := Sink xor Unsigned_8 (Pt.Y (0) and 255);
      Report ("P-256 To_Affine (inversion mod p)", S2, To_Duration (Clock - W0));
   end;
   Put_Line ("  (sink" & Sink'Image & ")");
end Crypto_Bench;
