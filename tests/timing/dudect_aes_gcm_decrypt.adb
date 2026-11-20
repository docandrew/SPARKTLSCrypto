--  dudect timing tests for AES-GCM decryption (Decrypt_Prepared), built
--  against the optimize library so the production assembly runs: every
--  tier this CPU has (VAES on zmm or ymm, AES-NI + PCLMULQDQ, portable),
--  selected in turn (see Gcm_Tiers).
--
--  For each tier:
--    A/A      both classes identical: the noise floor of the machine
--             (reported, never a failure);
--    tag      authentic vs forged tag (last byte flipped), 16 KiB record:
--             the tag result must not change the timing;
--    position forged in the first vs the last tag byte, 1 KiB: no early
--             exit in the comparison;
--    key      authentic records under an all-zero vs an all-one key, and
--             under two random keys, 1 KiB.
--
--  Method (as tests/prepared/timing_prepared): the class of each sample is
--  drawn at random; its inputs are selected by masking (both classes' data
--  are read every time) into the same working variables (tag, context,
--  ciphertext) before the timed region, so both classes use the same code
--  and the same addresses and differ only in values; each
--  sample runs once untimed and once timed, and only the Decrypt_Prepared
--  call is timed (lfence; rdtsc). Welch's t over the raw samples and over
--  the fastest 99% must stay below 4.5.
--
--  "dudect_aes_gcm_decrypt keypair R [swap]" instead runs R alternating
--  rounds of the A/A control and the zero/one key pair, with "swap" the
--  all-one key as class 0 (reported, never failed). A difference that
--  follows the key values changes sign under swap; a bias of the
--  harness's class position does not.
--
--  Each tier also runs a canary: the same authentic/forged classes with
--  the realistic mutant of the zeroing (one extra masking pass, by the
--  tier's own masking routine, only when the tag is bad), which the method
--  must detect on the hardware tiers (on the portable tier that pass is
--  below the resolution at this sample count and is only reported).
--
--  Passing is statistical evidence, not proof. ct_decrypt_prepared and
--  ct_mask_bytes (memcheck) check every branch and address the Valgrind
--  CPU can run.

with Ada.Text_IO; use Ada.Text_IO;
with Ada.Command_Line;
with Ada.Containers.Generic_Array_Sort;
with Ada.Numerics.Long_Elementary_Functions;
use Ada.Numerics.Long_Elementary_Functions;
with Interfaces;      use Interfaces;
with System.Machine_Code; use System.Machine_Code;
with SPARKNaCl;       use SPARKNaCl;
with SPARKNaCl.AES;
with SPARKTLSCrypto.AES_GCM; use SPARKTLSCrypto.AES_GCM;
with Gcm_Tiers; use Gcm_Tiers;
with SPARKTLSCrypto.AES_NI;
with SPARKTLSCrypto.GHASH_NI;
with SPARKTLSCrypto.AES_GCM_AVX2;

procedure Dudect_AES_GCM_Decrypt is
   Nonce : constant Bytes_12 := (others => 16#5C#);
   AAD   : constant Byte_Seq (0 .. 12) := (others => 16#17#);
   Big   : constant N32 := 16_384;
   Small : constant N32 := 1_024;

   --  Per-class inputs, and the working copies every sample uses.
   CT_0, CT_1   : Byte_Seq (0 .. Big - 1);
   Tag_0, Tag_1 : Bytes_16;
   Ctx_0, Ctx_1 : Prepared_Key;
   Work_CT      : Byte_Seq (0 .. Big - 1);
   Work_Tag     : Bytes_16;
   Work_Ctx     : Prepared_Key;
   Buf          : Byte_Seq (0 .. Big - 1);
   Status       : Boolean;
   pragma Volatile (Status);
   Failed       : Boolean := False;

   function Ticks return Unsigned_64 is
      Lo, Hi : Unsigned_32;
   begin
      Asm ("lfence" & ASCII.LF & ASCII.HT & "rdtsc" & ASCII.LF & ASCII.HT &
           "lfence",
           Outputs => (Unsigned_32'Asm_Output ("=a", Lo),
                       Unsigned_32'Asm_Output ("=d", Hi)),
           Volatile => True);
      return Shift_Left (Unsigned_64 (Hi), 32) or Unsigned_64 (Lo);
   end Ticks;

   --  Copy class 0's or class 1's inputs into the working variables by
   --  reading both and masking (M = 0 or 16#FF#): the harness's own loads
   --  and stores are the same for both classes, only the values differ.
   Ctx_Bytes : constant N32 := N32 (Ctx_0'Size / 8);
   procedure Select_Class (Len : N32; M : Byte) is
      C0 : Byte_Seq (0 .. Ctx_Bytes - 1) with Import, Address => Ctx_0'Address;
      C1 : Byte_Seq (0 .. Ctx_Bytes - 1) with Import, Address => Ctx_1'Address;
      CW : Byte_Seq (0 .. Ctx_Bytes - 1)
        with Import, Address => Work_Ctx'Address;
   begin
      for I in 0 .. Len - 1 loop
         Work_CT (I) := (CT_0 (I) and not M) or (CT_1 (I) and M);
      end loop;
      for I in Work_Tag'Range loop
         Work_Tag (I) := (Tag_0 (I) and not M) or (Tag_1 (I) and M);
      end loop;
      for I in CW'Range loop
         CW (I) := (C0 (I) and not M) or (C1 (I) and M);
      end loop;
   end Select_Class;

   type Samples is array (Positive range <>) of Unsigned_64;
   procedure Sort is new Ada.Containers.Generic_Array_Sort
     (Positive, Unsigned_64, Samples);

   Seed : Unsigned_64 := 16#2545_F491_4F6C_DD1D#;

   procedure Measure (Name : String; Len : N32; Count : Positive;
                      Canary : Boolean := False;
                      Control : Boolean := False) is
      T0, T1 : Samples (1 .. Count);
      N0, N1 : Natural := 0;
      Start, Stop : Unsigned_64;
      Class : Natural;

      function Statistic (Trim : Natural) return Long_Float is
         Last : constant Positive := Count - Trim;
         M0, M1, V0, V1 : Long_Float := 0.0;
      begin
         for I in 1 .. Last loop
            M0 := M0 + Long_Float (T0 (I));
            M1 := M1 + Long_Float (T1 (I));
         end loop;
         M0 := M0 / Long_Float (Last);
         M1 := M1 / Long_Float (Last);
         for I in 1 .. Last loop
            V0 := V0 + (Long_Float (T0 (I)) - M0) ** 2;
            V1 := V1 + (Long_Float (T1 (I)) - M1) ** 2;
         end loop;
         V0 := V0 / Long_Float (Last - 1);
         V1 := V1 / Long_Float (Last - 1);
         return (M0 - M1) / Sqrt ((V0 + V1) / Long_Float (Last));
      end Statistic;

      procedure Subject is
      begin
         Decrypt_Prepared (Buf (0 .. Len - 1), Status, Work_Tag, Nonce,
                           Work_Ctx, AAD);
         --  The canary is the realistic mutant: an implementation that
         --  masks the buffer only when the tag is bad, i.e. one extra pass
         --  of the same masking routine on failure, with the same code
         --  Decrypt_Prepared chooses for this tier.
         if Canary and then not Status then   --  the deliberate leak
            if SPARKTLSCrypto.AES_GCM_AVX2.Has_VAES_AVX2 then
               SPARKTLSCrypto.AES_GCM_AVX2.Mask_Bytes (Buf (0 .. Len - 1), 0);
            elsif SPARKTLSCrypto.AES_NI.Has_AESNI
              and SPARKTLSCrypto.GHASH_NI.Has_PCLMULQDQ
            then
               SPARKTLSCrypto.AES_NI.Mask_Bytes (Buf (0 .. Len - 1), 0);
            else
               for I in 0 .. Len - 1 loop
                  Buf (I) := Buf (I) and 0;
                  pragma Inspection_Point (Buf);
               end loop;
            end if;
         end if;
      end Subject;
   begin
      for I in 1 .. 200 loop   --  warm up
         Select_Class (Len, 0);
         Buf (0 .. Len - 1) := Work_CT (0 .. Len - 1);
         Subject;
      end loop;
      while N0 < Count or N1 < Count loop
         Seed := Seed xor Shift_Left (Seed, 13);
         Seed := Seed xor Shift_Right (Seed, 7);
         Seed := Seed xor Shift_Left (Seed, 17);
         Class := Natural (Seed and 1);
         if (Class = 0 and N0 < Count) or (Class = 1 and N1 < Count) then
            Select_Class (Len, (if Class = 0 then 0 else 16#FF#));
            --  One untimed run first, so caches and predictors are in
            --  the same state for both classes when the timed run starts.
            Buf (0 .. Len - 1) := Work_CT (0 .. Len - 1);
            Subject;
            Buf (0 .. Len - 1) := Work_CT (0 .. Len - 1);
            Start := Ticks;
            Subject;
            Stop := Ticks;
            if Class = 0 then
               N0 := N0 + 1; T0 (N0) := Stop - Start;
            else
               N1 := N1 + 1; T1 (N1) := Stop - Start;
            end if;
         end if;
      end loop;
      Sort (T0);
      Sort (T1);
      declare
         Raw_T  : constant Long_Float := Statistic (0);
         Trim_T : constant Long_Float := Statistic (Count / 100);
         Leaks  : constant Boolean := abs Raw_T >= 4.5 or abs Trim_T >= 4.5;
      begin
         Put_Line (Name & ": median cycles" & T0 (Count / 2)'Image & " /" &
                   T1 (Count / 2)'Image & "  raw t =" & Raw_T'Image &
                   "  trimmed 99% t =" & Trim_T'Image);
         if Control then
            Put_Line ((if Leaks then "  note: A/A control above threshold:"
                       & " this machine's noise floor"
                       else "  ok: A/A control below threshold"));
         elsif Canary then
            if Leaks then
               Put_Line ("  ok: negative control detected");
            elsif not (SPARKTLSCrypto.AES_NI.Has_AESNI
                       and SPARKTLSCrypto.GHASH_NI.Has_PCLMULQDQ)
            then
               --  Portable tier: one byte-loop pass (about 1,000 cycles)
               --  in a 600,000-cycle software decryption is below this
               --  sample count's resolution. Reported, not failed; the
               --  portable path runs entirely under memcheck instead
               --  (ct_decrypt_prepared with CTGRIND_PORTABLE=1).
               Put_Line ("  note: negative control below resolution on the"
                         & " portable tier (memcheck covers this path)");
            else
               Put_Line ("  *** NEGATIVE CONTROL NOT DETECTED ***");
               Failed := True;
            end if;
         elsif Leaks then
            Put_Line ("  *** TIMING DEPENDS ON SECRET INPUT ***");
            Failed := True;
         else
            Put_Line ("  ok: timing independent of the class");
         end if;
      end;
   end Measure;

   procedure Seal (CT : in out Byte_Seq; Tag : out Bytes_16;
                   Ctx : Prepared_Key) is
   begin
      CT := (others => 16#AA#);
      Encrypt_Prepared (CT, Tag, Nonce, Ctx, AAD);
   end Seal;
   --  "keypair R": R alternating rounds of the A/A control and the
   --  all-zero vs all-one key test, AES-NI and VAES tiers only, to compare
   --  the key classes with the machine's noise floor.
   procedure Key_Pair_Rounds (Rounds : Positive; Swap : Boolean) is
      Key_0 : constant Byte := (if Swap then 16#FF# else 0);
   begin
      for Round in 1 .. Rounds loop
         for T in AES_NI_4 .. VAES_256 loop
            if Available (T) then
               Select_Tier (T);
               Prepare_128 (Ctx_0,
                            AES.Construct (Bytes_16'(others => Key_0)));
               Ctx_1 := Ctx_0;
               Seal (CT_0 (0 .. Small - 1), Tag_0, Ctx_0);
               CT_1 := CT_0;
               Tag_1 := Tag_0;
               Measure (T'Image & " round" & Round'Image & " A/A", Small,
                        100_000, Control => True);
               Prepare_128 (Ctx_1,
                            AES.Construct (Bytes_16'(others => not Key_0)));
               Seal (CT_1 (0 .. Small - 1), Tag_1, Ctx_1);
               Measure (T'Image & " round" & Round'Image &
                        (if Swap then " key ones vs zeros"
                         else " key zeros vs ones"), Small, 100_000,
                        Control => True);
            end if;
         end loop;
      end loop;
   end Key_Pair_Rounds;
begin
   Put_Line ("tiers: " & Names);
   if Ada.Command_Line.Argument_Count >= 2
     and then Ada.Command_Line.Argument (1) = "keypair"
   then
      Key_Pair_Rounds (Positive'Value (Ada.Command_Line.Argument (2)),
                       Swap => Ada.Command_Line.Argument_Count = 3
                       and then Ada.Command_Line.Argument (3) = "swap");
      return;
   end if;
   for T in Tier loop
      if Available (T) then
         Select_Tier (T);
         declare
            Small_Count : constant Positive :=
              (if T = Portable then 20_000 else 100_000);
            Big_Count : constant Positive :=
              (if T = Portable then 4_000 else 40_000);
         begin
            --  A/A control: both classes identical. Any |t| >= 4.5 here
            --  is the noise floor of this machine, not a leak; it is
            --  reported but does not fail the run.
            Prepare_128 (Ctx_0, AES.Construct (Bytes_16'(others => 0)));
            Ctx_1 := Ctx_0;
            Seal (CT_0 (0 .. Small - 1), Tag_0, Ctx_0);
            CT_1 := CT_0;
            Tag_1 := Tag_0;
            Measure (T'Image & " A/A 1KiB identical classes (noise floor)",
                     Small, Small_Count, Control => True);

            --  tag: one key, authentic vs forged, 16 KiB.
            Prepare_128 (Ctx_0, AES.Construct (Bytes_16'(others => 0)));
            Ctx_1 := Ctx_0;
            Seal (CT_0, Tag_0, Ctx_0);
            CT_1 := CT_0;
            Tag_1 := Tag_0;
            Tag_1 (15) := Tag_1 (15) xor 1;
            Measure (T'Image & " 16KiB authentic vs forged tag", Big,
                     Big_Count);

            --  The same classes at 1 KiB with a branch on Status added
            --  after the call: the method must detect it.
            Seal (CT_0 (0 .. Small - 1), Tag_0, Ctx_0);
            CT_1 := CT_0;
            Tag_1 := Tag_0;
            Tag_1 (15) := Tag_1 (15) xor 1;
            Measure (T'Image & " CANARY 1KiB authentic vs forged, mask"
                     & " only when forged", Small, Small_Count,
                     Canary => True);

            --  position: forged in byte 0 vs byte 15, 1 KiB.
            Tag_0 (0) := Tag_0 (0) xor 1;
            Measure (T'Image & " 1KiB tag wrong in byte 0 vs byte 15",
                     Small, Small_Count);

            --  key: all-zero vs all-one key, authentic, 1 KiB.
            Prepare_128 (Ctx_1, AES.Construct (Bytes_16'(others => 16#FF#)));
            Seal (CT_0 (0 .. Small - 1), Tag_0, Ctx_0);
            Seal (CT_1 (0 .. Small - 1), Tag_1, Ctx_1);
            Measure (T'Image & " 1KiB key zeros vs ones", Small,
                     Small_Count);

            --  key: two random keys (similar Hamming weight), 1 KiB.
            --  Separates a dependence on key values from the power and
            --  frequency effect of extreme Hamming weights (Hertzbleed).
            Prepare_128 (Ctx_0, AES.Construct (Bytes_16'
              (16#3C#, 16#A1#, 16#5E#, 16#07#, 16#D2#, 16#94#, 16#6B#, 16#F0#,
               16#18#, 16#C7#, 16#2D#, 16#85#, 16#E9#, 16#4A#, 16#73#, 16#1F#)));
            Prepare_128 (Ctx_1, AES.Construct (Bytes_16'
              (16#9B#, 16#04#, 16#E6#, 16#71#, 16#2F#, 16#D8#, 16#53#, 16#AC#,
               16#C1#, 16#6E#, 16#38#, 16#97#, 16#0D#, 16#F4#, 16#25#, 16#BA#)));
            Seal (CT_0 (0 .. Small - 1), Tag_0, Ctx_0);
            Seal (CT_1 (0 .. Small - 1), Tag_1, Ctx_1);
            Measure (T'Image & " 1KiB key random A vs random B", Small,
                     Small_Count);
         end;
      end if;
   end loop;
   Clear (Ctx_0);
   Clear (Ctx_1);
   Clear (Work_Ctx);
   if Failed then
      Ada.Command_Line.Set_Exit_Status (Ada.Command_Line.Failure);
   end if;
end Dudect_AES_GCM_Decrypt;
