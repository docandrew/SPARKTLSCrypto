--  Stack-residue scan for the signing and key-agreement primitives.
--
--  Method: a deep frame paints the stack below the harness with a marker;
--  the primitive then runs at the same depth, so its frames overwrite the
--  painted region; after it returns the region is read back and searched
--  for 8-byte fragments of the secrets that went in (private keys,
--  nonces, RSA CRT parameters). Source-level scrubbing zeroes named
--  temporaries; this finds what it cannot reach: register spills, function
--  return temporaries, compiler-made copies.
--
--  Harness hygiene: every secret and every output buffer lives in the
--  main frame, above the region; the case bodies only call the primitive;
--  the scan reads the region without copying anything into it and skips
--  the top Skip bytes, where its own small frame sits. Needles are
--  random so that no window matches by accident. Run natively, not under
--  valgrind (memcheck marks popped stack inaccessible). Exit status 1 if
--  any primitive leaves a fragment, or if the negative control does not
--  find all of its planted windows (then the scanner itself is broken and
--  a zero would mean nothing). ci/residue.sh runs it as a gate.
with Ada.Text_IO;                use Ada.Text_IO;
with Ada.Command_Line;
with System;
with System.Storage_Elements;    use System.Storage_Elements;
with Interfaces;                 use Interfaces;
with SPARKNaCl;                  use SPARKNaCl;
with SPARKNaCl.Hashing.SHA512;
with SPARKTLSCrypto.P256.ECDSA;
with SPARKTLSCrypto.P384.ECDSA;
with SPARKTLSCrypto.RSA;
with SPARKTLSCrypto.RFC6979;
with SPARKTLSCrypto.X25519;
with SPARKTLSCrypto.Ed25519;

procedure Residue_Scan is
   Scan_Bytes : constant := 262_144;   --  256 KB below the harness
   Skip       : constant := 512;       --  the scan's own frame
   Window     : constant := 8;         --  one 64-bit limb: catches lone spills
   Paint_Byte : constant Byte := 16#A5#;
   Total_Hits : Natural := 0;   --  primitives only, the control excluded
   Ctl_Found  : Natural := 0;
   Ctl_Want   : Natural := 0;
   Sink       : Byte := 0;

   type Needle_Ref is access constant Byte_Seq;
   type Needle_Set is array (Positive range <>) of Needle_Ref;
   type Needle_Result is record
      Windows, Found : Natural := 0;
      Lo, Hi         : Natural := 0;   --  offsets below the marker
   end record;
   type Result_Set is array (1 .. 8) of Needle_Result;

   --  Deterministic pseudo-random bytes for the needles
   Seed : Unsigned_64 := 16#9E37_79B9_7F4A_7C15#;
   function Rand (Len : N32) return Byte_Seq is
      R : Byte_Seq (0 .. Len - 1);
   begin
      for I in R'Range loop
         Seed := Seed xor Shift_Left (Seed, 13);
         Seed := Seed xor Shift_Right (Seed, 7);
         Seed := Seed xor Shift_Left (Seed, 17);
         R (I) := Byte (Seed and 255);
      end loop;
      return R;
   end Rand;

   procedure Paint is
      Buf : Byte_Seq (0 .. Scan_Bytes - 1) := (others => Paint_Byte);
      pragma Volatile (Buf);
   begin
      Sink := Sink xor Buf (Scan_Bytes - 1);
   end Paint;

   --  Read the region below Marker and search it in place.
   procedure Scan
     (Marker  : System.Address;
      Needles : Needle_Set;
      Res     : out Result_Set;
      Touched : out Natural)
   is
      Base   : constant System.Address :=
        To_Address (To_Integer (Marker) - Skip - Scan_Bytes);
      Region : Byte_Seq (0 .. Scan_Bytes - 1) with Import, Address => Base;
   begin
      Res := (others => <>);
      Touched := 0;
      for I in Region'Range loop
         if Region (I) /= Paint_Byte then
            Touched := Touched + 1;
         end if;
      end loop;
      for N in Needles'Range loop
         for S in Needles (N).all'First .. Needles (N).all'Last - Window + 1 loop
            Res (N).Windows := Res (N).Windows + 1;
            for I in Region'First .. Region'Last - Window + 1 loop
               if Region (I .. I + Window - 1) = Needles (N).all (S .. S + Window - 1) then
                  declare
                     Off : constant Natural := Natural (Scan_Bytes - 1 - I) + Skip;
                  begin
                     if Res (N).Found = 0 then
                        Res (N).Lo := Off; Res (N).Hi := Off;
                     else
                        Res (N).Lo := Natural'Min (Res (N).Lo, Off);
                        Res (N).Hi := Natural'Max (Res (N).Hi, Off);
                     end if;
                     Res (N).Found := Res (N).Found + 1;
                  end;
                  exit;
               end if;
            end loop;
         end loop;
      end loop;
   end Scan;

   --  Run the case below a spacer frame, so that the scan's own frame
   --  (which follows at the same depth as this one) lands on the spacer
   --  and not on the primitive's frames.
   procedure Deep (Op : access procedure) is
      Spacer : Byte_Seq (0 .. 4095) := (others => 0);
      pragma Volatile (Spacer);
   begin
      Op.all;
      Sink := Sink xor Spacer (0);
   end Deep;

   --  Paint, run the case below the spacer, then scan from here.
   procedure Run (Name : String; Op : access procedure; Needles : Needle_Set; Names : String;
                  Is_Control : Boolean := False) is
      Marker  : Byte := 0;
      pragma Volatile (Marker);
      Res     : Result_Set;
      Touched : Natural;
      Hits    : Natural := 0;
   begin
      Paint;
      Deep (Op);
      Scan (Marker'Address, Needles, Res, Touched);
      for N in Needles'Range loop
         Hits := Hits + Res (N).Found;
      end loop;
      Put_Line (Name & ": stack used" & Touched'Image & " B, residue fragments:" & Hits'Image & "   [" & Names & "]");
      for N in Needles'Range loop
         if Res (N).Found > 0 then
            Put_Line ("    needle" & N'Image & ":" & Res (N).Found'Image & " of" & Res (N).Windows'Image
                      & " windows found," & Res (N).Lo'Image & " .." & Res (N).Hi'Image & " bytes below the harness frame");
         end if;
      end loop;
      if Is_Control then
         Ctl_Found := Hits;
         Ctl_Want  := Res (1).Windows;
      else
         Total_Hits := Total_Hits + Hits;
      end if;
   end Run;

   ---------------------------------------------------------------------
   --  RSA-2048 test key (from the ctgrind harness)
   ---------------------------------------------------------------------


   K_N : constant Byte_Seq (0 .. 255) :=
     (
      16#AF#, 16#E1#, 16#93#, 16#8C#, 16#CD#, 16#80#, 16#C4#, 16#BC#, 16#60#, 16#22#, 16#0B#, 16#9A#,
      16#4B#, 16#91#, 16#47#, 16#81#, 16#4F#, 16#CB#, 16#FB#, 16#C8#, 16#B7#, 16#F1#, 16#37#, 16#C9#,
      16#64#, 16#F0#, 16#0F#, 16#21#, 16#D2#, 16#FE#, 16#45#, 16#F8#, 16#59#, 16#92#, 16#A2#, 16#2F#,
      16#1D#, 16#3D#, 16#A9#, 16#17#, 16#8C#, 16#1B#, 16#51#, 16#60#, 16#AF#, 16#B5#, 16#8D#, 16#61#,
      16#04#, 16#F5#, 16#DD#, 16#07#, 16#55#, 16#69#, 16#0B#, 16#B6#, 16#B4#, 16#BF#, 16#18#, 16#97#,
      16#EA#, 16#38#, 16#94#, 16#6B#, 16#BD#, 16#CD#, 16#22#, 16#7E#, 16#BB#, 16#58#, 16#88#, 16#55#,
      16#8B#, 16#1F#, 16#21#, 16#16#, 16#12#, 16#F1#, 16#8E#, 16#F8#, 16#A7#, 16#0C#, 16#A8#, 16#E8#,
      16#2A#, 16#B9#, 16#81#, 16#63#, 16#25#, 16#6B#, 16#A2#, 16#6A#, 16#D4#, 16#E0#, 16#CC#, 16#35#,
      16#EC#, 16#8C#, 16#A3#, 16#97#, 16#52#, 16#52#, 16#D3#, 16#98#, 16#67#, 16#02#, 16#D7#, 16#E8#,
      16#5F#, 16#12#, 16#99#, 16#F1#, 16#9C#, 16#4E#, 16#6D#, 16#2F#, 16#B3#, 16#AB#, 16#4C#, 16#90#,
      16#C6#, 16#45#, 16#E7#, 16#A3#, 16#3B#, 16#79#, 16#25#, 16#1A#, 16#17#, 16#FF#, 16#A2#, 16#E4#,
      16#63#, 16#96#, 16#01#, 16#14#, 16#3D#, 16#8E#, 16#CA#, 16#63#, 16#55#, 16#7D#, 16#C3#, 16#0C#,
      16#83#, 16#92#, 16#83#, 16#9D#, 16#46#, 16#45#, 16#B1#, 16#B0#, 16#D2#, 16#A9#, 16#0B#, 16#A1#,
      16#17#, 16#A5#, 16#0F#, 16#53#, 16#A4#, 16#15#, 16#BB#, 16#8C#, 16#ED#, 16#D7#, 16#AE#, 16#88#,
      16#4B#, 16#36#, 16#72#, 16#0B#, 16#BE#, 16#B0#, 16#A3#, 16#6A#, 16#69#, 16#06#, 16#1D#, 16#01#,
      16#B0#, 16#E8#, 16#CA#, 16#0B#, 16#DD#, 16#A3#, 16#A6#, 16#40#, 16#A7#, 16#61#, 16#D4#, 16#7E#,
      16#46#, 16#F2#, 16#8E#, 16#D7#, 16#B1#, 16#EF#, 16#BF#, 16#5B#, 16#9A#, 16#4F#, 16#1E#, 16#AF#,
      16#97#, 16#B3#, 16#DA#, 16#E4#, 16#C4#, 16#F8#, 16#D3#, 16#BD#, 16#BE#, 16#08#, 16#83#, 16#42#,
      16#CB#, 16#C8#, 16#8C#, 16#E6#, 16#69#, 16#AC#, 16#41#, 16#00#, 16#97#, 16#4F#, 16#AF#, 16#8E#,
      16#56#, 16#EB#, 16#C3#, 16#A2#, 16#34#, 16#45#, 16#B7#, 16#66#, 16#98#, 16#1D#, 16#92#, 16#9D#,
      16#AA#, 16#22#, 16#F0#, 16#DE#, 16#79#, 16#5F#, 16#0D#, 16#96#, 16#AB#, 16#F1#, 16#5B#, 16#FD#,
      16#56#, 16#16#, 16#AC#, 16#E5#);
   K_D : constant Byte_Seq (0 .. 255) :=
     (
      16#18#, 16#81#, 16#BE#, 16#41#, 16#3F#, 16#8E#, 16#3A#, 16#7B#, 16#84#, 16#0A#, 16#A2#, 16#62#,
      16#BE#, 16#B6#, 16#50#, 16#C8#, 16#16#, 16#22#, 16#16#, 16#64#, 16#86#, 16#AA#, 16#DC#, 16#0A#,
      16#DA#, 16#1F#, 16#70#, 16#00#, 16#56#, 16#C9#, 16#BA#, 16#DE#, 16#AA#, 16#BE#, 16#79#, 16#8E#,
      16#46#, 16#8D#, 16#05#, 16#AF#, 16#64#, 16#04#, 16#97#, 16#6F#, 16#79#, 16#34#, 16#3B#, 16#2D#,
      16#A2#, 16#57#, 16#0E#, 16#D3#, 16#FB#, 16#84#, 16#EE#, 16#4E#, 16#A8#, 16#3B#, 16#3B#, 16#56#,
      16#49#, 16#9A#, 16#D6#, 16#25#, 16#78#, 16#16#, 16#2A#, 16#01#, 16#0E#, 16#22#, 16#3D#, 16#26#,
      16#EC#, 16#42#, 16#6B#, 16#66#, 16#0B#, 16#C0#, 16#30#, 16#5B#, 16#79#, 16#CD#, 16#54#, 16#08#,
      16#BB#, 16#91#, 16#4B#, 16#13#, 16#D1#, 16#4E#, 16#40#, 16#DC#, 16#91#, 16#6A#, 16#7C#, 16#51#,
      16#E4#, 16#32#, 16#C9#, 16#85#, 16#A7#, 16#81#, 16#26#, 16#7E#, 16#25#, 16#16#, 16#5A#, 16#96#,
      16#C4#, 16#8E#, 16#8F#, 16#38#, 16#40#, 16#FF#, 16#15#, 16#8C#, 16#30#, 16#C5#, 16#04#, 16#DF#,
      16#64#, 16#5D#, 16#2F#, 16#B4#, 16#49#, 16#30#, 16#6D#, 16#68#, 16#8C#, 16#CC#, 16#8B#, 16#E7#,
      16#64#, 16#C0#, 16#77#, 16#E9#, 16#21#, 16#B7#, 16#C6#, 16#3F#, 16#69#, 16#4F#, 16#90#, 16#7C#,
      16#71#, 16#39#, 16#DF#, 16#09#, 16#39#, 16#B2#, 16#9D#, 16#F6#, 16#20#, 16#B9#, 16#89#, 16#BE#,
      16#A4#, 16#04#, 16#76#, 16#E3#, 16#01#, 16#AB#, 16#0E#, 16#64#, 16#50#, 16#40#, 16#AA#, 16#63#,
      16#99#, 16#9C#, 16#F8#, 16#9C#, 16#B0#, 16#7F#, 16#8C#, 16#D8#, 16#30#, 16#4F#, 16#7C#, 16#FF#,
      16#48#, 16#EF#, 16#D4#, 16#18#, 16#6E#, 16#4B#, 16#D2#, 16#A9#, 16#98#, 16#B8#, 16#8E#, 16#4E#,
      16#EB#, 16#F5#, 16#F0#, 16#61#, 16#8E#, 16#62#, 16#BD#, 16#7E#, 16#45#, 16#92#, 16#8A#, 16#59#,
      16#27#, 16#FB#, 16#B8#, 16#D1#, 16#26#, 16#F8#, 16#6C#, 16#4D#, 16#C0#, 16#B5#, 16#9D#, 16#F8#,
      16#D4#, 16#72#, 16#3A#, 16#E5#, 16#27#, 16#48#, 16#01#, 16#9C#, 16#2C#, 16#FF#, 16#70#, 16#87#,
      16#39#, 16#E5#, 16#F1#, 16#58#, 16#5C#, 16#65#, 16#78#, 16#F7#, 16#32#, 16#AB#, 16#FE#, 16#E3#,
      16#E8#, 16#FD#, 16#94#, 16#A8#, 16#C4#, 16#80#, 16#F0#, 16#8D#, 16#32#, 16#72#, 16#2B#, 16#9B#,
      16#74#, 16#8C#, 16#30#, 16#A9#);
   K_P : constant Byte_Seq (0 .. 127) :=
     (
      16#E6#, 16#34#, 16#65#, 16#0D#, 16#48#, 16#92#, 16#08#, 16#D6#, 16#81#, 16#42#, 16#7F#, 16#D0#,
      16#E0#, 16#E8#, 16#7A#, 16#4D#, 16#9C#, 16#F0#, 16#5C#, 16#3D#, 16#7E#, 16#23#, 16#27#, 16#F0#,
      16#AB#, 16#10#, 16#AA#, 16#CE#, 16#88#, 16#23#, 16#1F#, 16#B4#, 16#71#, 16#42#, 16#FD#, 16#24#,
      16#5C#, 16#CD#, 16#D5#, 16#5F#, 16#71#, 16#92#, 16#27#, 16#A3#, 16#81#, 16#FC#, 16#5F#, 16#0C#,
      16#B2#, 16#11#, 16#07#, 16#B0#, 16#69#, 16#12#, 16#F9#, 16#89#, 16#5C#, 16#59#, 16#8A#, 16#C4#,
      16#CF#, 16#AC#, 16#C2#, 16#81#, 16#06#, 16#74#, 16#0A#, 16#D3#, 16#97#, 16#63#, 16#88#, 16#63#,
      16#ED#, 16#6B#, 16#2B#, 16#7B#, 16#11#, 16#A3#, 16#DE#, 16#8D#, 16#F0#, 16#6F#, 16#A9#, 16#04#,
      16#46#, 16#5D#, 16#CB#, 16#73#, 16#7B#, 16#65#, 16#67#, 16#62#, 16#12#, 16#F1#, 16#67#, 16#02#,
      16#CB#, 16#32#, 16#DE#, 16#01#, 16#AC#, 16#17#, 16#2F#, 16#29#, 16#90#, 16#31#, 16#2F#, 16#A3#,
      16#88#, 16#E7#, 16#62#, 16#5D#, 16#31#, 16#40#, 16#EE#, 16#71#, 16#03#, 16#04#, 16#CB#, 16#4F#,
      16#27#, 16#C4#, 16#63#, 16#47#, 16#E4#, 16#72#, 16#72#, 16#1D#);
   K_Q : constant Byte_Seq (0 .. 127) :=
     (
      16#C3#, 16#96#, 16#DE#, 16#46#, 16#1A#, 16#1D#, 16#82#, 16#DC#, 16#18#, 16#A8#, 16#AA#, 16#1B#,
      16#61#, 16#0D#, 16#14#, 16#52#, 16#63#, 16#9F#, 16#19#, 16#06#, 16#67#, 16#14#, 16#13#, 16#37#,
      16#3B#, 16#2A#, 16#54#, 16#D5#, 16#3B#, 16#00#, 16#C1#, 16#FD#, 16#80#, 16#E9#, 16#0B#, 16#0E#,
      16#A6#, 16#78#, 16#99#, 16#90#, 16#5A#, 16#12#, 16#1F#, 16#2C#, 16#95#, 16#A6#, 16#46#, 16#84#,
      16#9B#, 16#8A#, 16#C6#, 16#C9#, 16#54#, 16#CF#, 16#D2#, 16#41#, 16#30#, 16#50#, 16#20#, 16#FB#,
      16#0E#, 16#B2#, 16#E7#, 16#60#, 16#CC#, 16#E2#, 16#BA#, 16#55#, 16#07#, 16#D1#, 16#D5#, 16#6C#,
      16#32#, 16#73#, 16#2F#, 16#6C#, 16#7F#, 16#97#, 16#09#, 16#D1#, 16#F0#, 16#D3#, 16#BA#, 16#D4#,
      16#20#, 16#A1#, 16#BC#, 16#29#, 16#E1#, 16#5D#, 16#1D#, 16#DD#, 16#EE#, 16#41#, 16#A9#, 16#D1#,
      16#18#, 16#0F#, 16#84#, 16#02#, 16#77#, 16#EE#, 16#08#, 16#FA#, 16#B2#, 16#BB#, 16#8F#, 16#A4#,
      16#49#, 16#C6#, 16#C2#, 16#24#, 16#CA#, 16#BA#, 16#81#, 16#5B#, 16#24#, 16#FD#, 16#EF#, 16#27#,
      16#90#, 16#87#, 16#44#, 16#89#, 16#90#, 16#F7#, 16#2B#, 16#69#);
   K_DP : constant Byte_Seq (0 .. 127) :=
     (
      16#98#, 16#63#, 16#E6#, 16#E1#, 16#3C#, 16#41#, 16#30#, 16#08#, 16#8F#, 16#D8#, 16#ED#, 16#B3#,
      16#E0#, 16#AF#, 16#05#, 16#07#, 16#8B#, 16#F4#, 16#B1#, 16#9B#, 16#23#, 16#7D#, 16#32#, 16#5B#,
      16#67#, 16#62#, 16#C9#, 16#2F#, 16#9F#, 16#7F#, 16#60#, 16#E5#, 16#9A#, 16#74#, 16#B6#, 16#0E#,
      16#F4#, 16#40#, 16#6E#, 16#17#, 16#98#, 16#9F#, 16#20#, 16#0E#, 16#65#, 16#66#, 16#23#, 16#A5#,
      16#CB#, 16#DA#, 16#EA#, 16#34#, 16#25#, 16#DA#, 16#A1#, 16#C6#, 16#04#, 16#94#, 16#62#, 16#00#,
      16#97#, 16#59#, 16#CE#, 16#08#, 16#8B#, 16#B5#, 16#15#, 16#D5#, 16#AC#, 16#49#, 16#FF#, 16#67#,
      16#E7#, 16#2B#, 16#22#, 16#C5#, 16#7D#, 16#8F#, 16#F5#, 16#2C#, 16#11#, 16#16#, 16#59#, 16#D4#,
      16#B2#, 16#A0#, 16#34#, 16#A6#, 16#65#, 16#F1#, 16#62#, 16#D6#, 16#D1#, 16#A3#, 16#6C#, 16#85#,
      16#B4#, 16#EE#, 16#1F#, 16#79#, 16#0B#, 16#EA#, 16#ED#, 16#15#, 16#9E#, 16#96#, 16#70#, 16#EA#,
      16#D9#, 16#1E#, 16#13#, 16#47#, 16#8D#, 16#EB#, 16#65#, 16#EC#, 16#FA#, 16#0A#, 16#9A#, 16#6B#,
      16#F3#, 16#EF#, 16#55#, 16#A9#, 16#A9#, 16#D8#, 16#F9#, 16#21#);
   K_DQ : constant Byte_Seq (0 .. 127) :=
     (
      16#02#, 16#CB#, 16#1C#, 16#D1#, 16#93#, 16#7D#, 16#E8#, 16#68#, 16#8C#, 16#51#, 16#9C#, 16#5C#,
      16#57#, 16#BE#, 16#80#, 16#13#, 16#CD#, 16#28#, 16#70#, 16#8B#, 16#0E#, 16#DD#, 16#D2#, 16#88#,
      16#6F#, 16#67#, 16#E3#, 16#5E#, 16#48#, 16#41#, 16#72#, 16#83#, 16#D4#, 16#5B#, 16#7F#, 16#B4#,
      16#ED#, 16#DB#, 16#BB#, 16#15#, 16#BC#, 16#B3#, 16#95#, 16#8E#, 16#65#, 16#74#, 16#C2#, 16#7D#,
      16#12#, 16#5B#, 16#A1#, 16#0B#, 16#2F#, 16#12#, 16#E8#, 16#C5#, 16#D5#, 16#92#, 16#CF#, 16#65#,
      16#C6#, 16#87#, 16#F7#, 16#96#, 16#02#, 16#57#, 16#1A#, 16#A2#, 16#2C#, 16#42#, 16#6A#, 16#F1#,
      16#E8#, 16#A6#, 16#8C#, 16#7E#, 16#D8#, 16#33#, 16#A8#, 16#08#, 16#3F#, 16#90#, 16#46#, 16#92#,
      16#D1#, 16#04#, 16#7E#, 16#53#, 16#7A#, 16#CC#, 16#81#, 16#A8#, 16#B1#, 16#C6#, 16#6E#, 16#4E#,
      16#76#, 16#31#, 16#82#, 16#89#, 16#26#, 16#7D#, 16#57#, 16#D3#, 16#7C#, 16#CA#, 16#00#, 16#FB#,
      16#2F#, 16#B2#, 16#8F#, 16#03#, 16#47#, 16#81#, 16#F2#, 16#67#, 16#02#, 16#D8#, 16#3D#, 16#9A#,
      16#2B#, 16#0E#, 16#43#, 16#84#, 16#53#, 16#75#, 16#B4#, 16#41#);
   K_QI : constant Byte_Seq (0 .. 127) :=
     (
      16#BD#, 16#3C#, 16#CD#, 16#FD#, 16#FB#, 16#76#, 16#6C#, 16#91#, 16#AC#, 16#63#, 16#F4#, 16#FD#,
      16#52#, 16#03#, 16#A8#, 16#E2#, 16#43#, 16#19#, 16#E5#, 16#C9#, 16#CC#, 16#BF#, 16#50#, 16#13#,
      16#7E#, 16#9A#, 16#3D#, 16#94#, 16#B9#, 16#5D#, 16#F9#, 16#56#, 16#53#, 16#95#, 16#22#, 16#5B#,
      16#83#, 16#93#, 16#BF#, 16#37#, 16#5E#, 16#15#, 16#01#, 16#F4#, 16#07#, 16#BC#, 16#94#, 16#B6#,
      16#9B#, 16#91#, 16#45#, 16#2D#, 16#EE#, 16#0B#, 16#B1#, 16#30#, 16#79#, 16#D3#, 16#2C#, 16#FB#,
      16#F2#, 16#01#, 16#C9#, 16#D9#, 16#6D#, 16#75#, 16#C5#, 16#0C#, 16#8B#, 16#1A#, 16#0B#, 16#D4#,
      16#D1#, 16#05#, 16#24#, 16#62#, 16#71#, 16#C6#, 16#B0#, 16#68#, 16#36#, 16#A1#, 16#58#, 16#96#,
      16#06#, 16#FB#, 16#5A#, 16#71#, 16#27#, 16#DA#, 16#65#, 16#C0#, 16#29#, 16#32#, 16#24#, 16#7A#,
      16#C9#, 16#23#, 16#15#, 16#3A#, 16#11#, 16#2B#, 16#88#, 16#0D#, 16#B7#, 16#8F#, 16#56#, 16#F8#,
      16#DB#, 16#A5#, 16#72#, 16#5D#, 16#BA#, 16#C2#, 16#28#, 16#04#, 16#DC#, 16#71#, 16#2F#, 16#7D#,
      16#5B#, 16#2D#, 16#21#, 16#79#, 16#81#, 16#02#, 16#78#, 16#47#);
   Hash : constant Bytes_32 := (others => 16#5A#);
   Salt : constant Bytes_32 := (others => 16#A5#);
   D    : Byte_Seq (0 .. 255) := K_D;

   RSA_Blind : constant Bytes_16 := (others => 16#42#);
   RSA_CRT   : SPARKTLSCrypto.RSA.CRT_Params;
   RSA_Sig   : Byte_Seq (0 .. 255) := (others => 0);
   RSA_Len   : N32;
   RSA_OK    : Boolean;
   RSA_P   : aliased constant Byte_Seq := K_P;
   RSA_Q   : aliased constant Byte_Seq := K_Q;
   RSA_DP  : aliased constant Byte_Seq := K_DP;
   RSA_DQ  : aliased constant Byte_Seq := K_DQ;
   RSA_QI  : aliased constant Byte_Seq := K_QI;
   RSA_D   : aliased constant Byte_Seq := D;

   --  ECC secrets: random, top byte masked so the scalars are below n
   function Scalar (Len : N32) return Byte_Seq is
      R : Byte_Seq := Rand (Len);
   begin
      R (0) := R (0) and 16#0F#;
      return R;
   end Scalar;

   P256_D : aliased constant Byte_Seq := Scalar (32);
   P256_K : aliased constant Byte_Seq := Scalar (32);
   P256_Blind : constant Byte_Seq := Rand (40);
   P256_H : constant Bytes_32 := (others => 16#11#);
   P256_R, P256_S : SPARKTLSCrypto.P256.ECDSA.ECDSA_Sig_Half;
   P256_OK : Boolean;
   P384_D : aliased constant Byte_Seq := Scalar (48);
   P384_K : aliased constant Byte_Seq := Scalar (48);
   P384_Blind : constant Byte_Seq := Rand (56);
   P384_H : constant Bytes_48 := (others => 16#22#);
   P384_R, P384_S : Byte_Seq (0 .. 47);
   P384_OK : Boolean;
   K6979  : Bytes_32;
   K6979_OK : Boolean;
   X_SK   : constant Bytes_32 := Bytes_32 (Rand (32));
   X_SK_N : aliased constant Byte_Seq := Byte_Seq (X_SK);
   function Clamp (S : Bytes_32) return Byte_Seq is
      E : Bytes_32 := S;
   begin
      E (0)  := E (0) and 248;
      E (31) := (E (31) and 127) or 64;
      return Byte_Seq (E);
   end Clamp;
   X_Clamped : aliased constant Byte_Seq := Clamp (X_SK);
   X_Base : constant Bytes_32 := (9, others => 0);
   X_Q    : Bytes_32;
   Ed_Seed  : constant Bytes_32 := Bytes_32 (Rand (32));
   Ed_Seed_N : aliased constant Byte_Seq := Byte_Seq (Ed_Seed);
   function Ed_Scalar_Prefix (S : Bytes_32) return Byte_Seq is
      H : Bytes_64;
   begin
      SPARKNaCl.Hashing.SHA512.Hash (H, Byte_Seq (S));
      H (0)  := H (0) and 248;
      H (31) := (H (31) and 127) or 64;
      return Byte_Seq (H);
   end Ed_Scalar_Prefix;
   Ed_Hash  : aliased constant Byte_Seq := Ed_Scalar_Prefix (Ed_Seed);
   Ed_PK    : Bytes_32;
   Ed_SK    : Bytes_64;
   Ed_Msg   : constant Byte_Seq (0 .. 31) := (others => 16#44#);
   Ed_SM    : Byte_Seq (0 .. 95);

   --  Negative control: a routine that copies the secret into a local and
   --  returns without scrubbing. The scanner must see this one.
   Ctl_Secret : aliased constant Byte_Seq := Rand (32);
   procedure Case_Control is
      Local : Byte_Seq (0 .. 31) := Ctl_Secret;
      pragma Volatile (Local);
   begin
      Sink := Sink xor Local (5);
   end Case_Control;

   --  Case bodies: nothing but the call.
   procedure Case_P256 is
   begin
      SPARKTLSCrypto.P256.ECDSA.Sign
        (P256_H, SPARKTLSCrypto.P256.ECDSA.ECDSA_Sig_Half (P256_D),
         SPARKTLSCrypto.P256.ECDSA.ECDSA_Sig_Half (P256_K), P256_Blind, P256_R, P256_S, P256_OK);
   end Case_P256;
   procedure Case_P384 is
   begin
      SPARKTLSCrypto.P384.ECDSA.Sign (P384_H, P384_D, P384_K, P384_Blind, P384_R, P384_S, P384_OK);
   end Case_P384;
   procedure Case_6979 is
   begin
      SPARKTLSCrypto.RFC6979.Derive_K_P256 (Bytes_32 (P256_D), P256_H, K6979, K6979_OK);
   end Case_6979;
   procedure Case_X25519 is
   begin
      SPARKTLSCrypto.X25519.Scalar_Mult (X_Q, X_SK, X_Base);
   end Case_X25519;
   X_QB : Bytes_32;
   procedure Case_X25519_Base is
   begin
      SPARKTLSCrypto.X25519.Scalar_Mult_Base (X_QB, X_SK);
   end Case_X25519_Base;
   procedure Case_Ed25519 is
   begin
      SPARKTLSCrypto.Ed25519.Sign (Ed_SM, Ed_Msg, Ed_SK);
   end Case_Ed25519;
   procedure Case_RSA is
   begin
      SPARKTLSCrypto.RSA.Sign_PSS
        (M_Hash => Byte_Seq (Hash), Hash_Len => 32,
         Hash_Alg => SPARKTLSCrypto.RSA.PSS_SHA256,
         Modulus => K_N, Mod_Len => 256, Priv_Exp => D,
         Salt => Byte_Seq (Salt), Signature => RSA_Sig, Sig_Len => RSA_Len, OK => RSA_OK,
         Blind => RSA_Blind, Pub_Exp => 65537, CRT => RSA_CRT);
   end Case_RSA;
begin
   SPARKTLSCrypto.Ed25519.Keypair (Ed_Seed, Ed_PK, Ed_SK);
   RSA_CRT.Valid := True;
   RSA_CRT.Prime_Len := 128;
   RSA_CRT.P (0 .. 127) := K_P;   RSA_CRT.Q (0 .. 127) := K_Q;
   RSA_CRT.DP (0 .. 127) := K_DP; RSA_CRT.DQ (0 .. 127) := K_DQ;
   RSA_CRT.QInv (0 .. 127) := K_QI;

   Put_Line ("=== stack residue scan:" & Integer'Image (Scan_Bytes / 1024) & " KB region, 8-byte fragments, random needles ===");
   Run ("negative control  ", Case_Control'Access, (1 => Ctl_Secret'Access), "1=leaked copy; MUST be found",
        Is_Control => True);
   Run ("P-256 ECDSA sign  ", Case_P256'Access, (P256_D'Access, P256_K'Access), "1=d 2=k");
   Run ("P-384 ECDSA sign  ", Case_P384'Access, (P384_D'Access, P384_K'Access), "1=d 2=k");
   Run ("RFC 6979 P-256 k  ", Case_6979'Access, (1 => P256_D'Access), "1=d");
   Run ("X25519 scalar mult", Case_X25519'Access, (X_SK_N'Access, X_Clamped'Access), "1=sk 2=clamped sk");
   Run ("X25519 fixed-base ", Case_X25519_Base'Access, (X_SK_N'Access, X_Clamped'Access), "1=sk 2=clamped sk");
   Run ("Ed25519 sign      ", Case_Ed25519'Access, (Ed_Seed_N'Access, Ed_Hash'Access), "1=seed 2=scalar||prefix");
   Run ("RSA-2048 PSS sign ", Case_RSA'Access,
        (RSA_P'Access, RSA_Q'Access, RSA_DP'Access, RSA_DQ'Access, RSA_QI'Access, RSA_D'Access),
        "1=p 2=q 3=dP 4=dQ 5=qInv 6=d");
   Put_Line ("=== residue fragments in the primitives:" & Total_Hits'Image
             & "; control found" & Ctl_Found'Image & " of" & Ctl_Want'Image
             & "  (ok flags:" & P256_OK'Image & P384_OK'Image & K6979_OK'Image & RSA_OK'Image & ", sink" & Sink'Image & ")");
   if Ctl_Found /= Ctl_Want or Ctl_Want = 0 then
      Put_Line ("=== residue scan: FAIL (the control did not light up; the scanner is not seeing the stack)");
      Ada.Command_Line.Set_Exit_Status (1);
   elsif Total_Hits > 0 then
      Put_Line ("=== residue scan: FAIL");
      Ada.Command_Line.Set_Exit_Status (1);
   else
      Put_Line ("=== residue scan: PASS");
      Ada.Command_Line.Set_Exit_Status (0);
   end if;
end Residue_Scan;
