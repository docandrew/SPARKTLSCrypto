with SPARKTLSCrypto.MAC;

package body SPARKTLSCrypto.HMAC_DRBG with
   SPARK_Mode => On
is

   --  HMAC-SHA-256 is SPARKTLSCrypto.MAC's, which runs on SHA-NI where the
   --  CPU has it. The SHA-NI block function is SPARK_Mode => Off, so a
   --  caller inside a protected operation (SPARKTLS.RBG) gets a "potentially
   --  blocking" check it has to justify: the dispatch and both block
   --  functions are straight-line computation, with no I/O, delay, entry
   --  call or task interaction. Three HMACs per 32-byte request.

   --  10.1.2.2 HMAC_DRBG_Update (provided_data = Data):
   --    K = HMAC (K, V || 0x00 || Data); V = HMAC (K, V);
   --    if Data is non-empty: K = HMAC (K, V || 0x01 || Data); V = HMAC (K, V).
   procedure Update (S : in out State; Data : in Byte_Seq)
   with
     Pre  => Data'First = 0 and Data'Length <= Max_Seed_Material,
     Post => S.Counter = S.Counter'Old and S.Interval = S.Interval'Old and S.Live = S.Live'Old
   is
      Msg : Byte_Seq (0 .. 32 + Data'Length) := (others => 0);
      D   : Bytes_32;
   begin
      Msg (0 .. 31) := S.V;
      Msg (32) := 0;
      if Data'Length > 0 then
         Msg (33 .. Msg'Last) := Data;
      end if;
      SPARKTLSCrypto.MAC.HMAC_SHA_256 (D, Msg, S.K);
      S.K := D;
      SPARKTLSCrypto.MAC.HMAC_SHA_256 (D, S.V, S.K);
      S.V := D;
      if Data'Length > 0 then
         Msg (0 .. 31) := S.V;
         Msg (32) := 1;
         SPARKTLSCrypto.MAC.HMAC_SHA_256 (D, Msg, S.K);
         S.K := D;
         SPARKTLSCrypto.MAC.HMAC_SHA_256 (D, S.V, S.K);
         S.V := D;
      end if;
      pragma Warnings (GNATprove, Off, "statement has no effect");
      pragma Warnings (GNATprove, Off, "*is set by*");
      Sanitize (Msg);
      pragma Warnings (GNATprove, On, "*is set by*");
      pragma Warnings (GNATprove, On, "statement has no effect");
   end Update;

   procedure Instantiate
     (S               :    out State;
      Entropy         : in     Byte_Seq;
      Nonce           : in     Byte_Seq;
      Personalization : in     Byte_Seq;
      Reseed_Interval : in     Unsigned_64 := Max_Reseed_Interval)
   is
      Seed : Byte_Seq (0 .. Entropy'Length + Nonce'Length + Personalization'Length - 1) := (others => 0);
   begin
      Seed (0 .. Entropy'Length - 1) := Entropy;
      Seed (Entropy'Length .. Entropy'Length + Nonce'Length - 1) := Nonce;
      if Personalization'Length > 0 then
         Seed (Entropy'Length + Nonce'Length .. Seed'Last) := Personalization;
      end if;
      --  10.1.2.3 steps 2-3: K = 0x00..00, V = 0x01..01
      S := (K => (others => 0), V => (others => 1),
            Counter => 0, Interval => Reseed_Interval, Live => True);
      Update (S, Seed);
      S.Counter := 1;
      pragma Warnings (GNATprove, Off, "statement has no effect");
      pragma Warnings (GNATprove, Off, "*is set by*");
      Sanitize (Seed);
      pragma Warnings (GNATprove, On, "*is set by*");
      pragma Warnings (GNATprove, On, "statement has no effect");
   end Instantiate;

   procedure Reseed
     (S          : in out State;
      Entropy    : in     Byte_Seq;
      Additional : in     Byte_Seq)
   is
      Seed : Byte_Seq (0 .. Entropy'Length + Additional'Length - 1) := (others => 0);
   begin
      Seed (0 .. Entropy'Length - 1) := Entropy;
      if Additional'Length > 0 then
         Seed (Entropy'Length .. Seed'Last) := Additional;
      end if;
      Update (S, Seed);
      S.Counter := 1;
      pragma Warnings (GNATprove, Off, "statement has no effect");
      pragma Warnings (GNATprove, Off, "*is set by*");
      Sanitize (Seed);
      pragma Warnings (GNATprove, On, "*is set by*");
      pragma Warnings (GNATprove, On, "statement has no effect");
   end Reseed;

   procedure Generate
     (S          : in out State;
      Additional : in     Byte_Seq;
      Output     :    out Byte_Seq;
      OK         :    out Boolean)
   is
      D   : Bytes_32;
      Pos : N32 := 0;
   begin
      Output := (others => 0);
      --  Step 1: a reseed is required first.
      if S.Counter > S.Interval then
         OK := False;
         return;
      end if;
      --  Step 2: additional input, if any, goes in first.
      if Additional'Length > 0 then
         Update (S, Additional);
      end if;
      --  Steps 3-4: temp = temp || (V = HMAC (K, V)) until enough.
      while Pos <= Output'Last loop
         pragma Loop_Invariant (Pos <= Output'Last);
         pragma Loop_Invariant (S.Counter = S.Counter'Loop_Entry
                                and S.Interval = S.Interval'Loop_Entry
                                and S.Live = S.Live'Loop_Entry);
         pragma Loop_Variant (Increases => Pos);
         SPARKTLSCrypto.MAC.HMAC_SHA_256 (D, S.V, S.K);
         S.V := D;
         declare
            N : constant N32 := N32'Min (32, Output'Last - Pos + 1);
         begin
            Output (Pos .. Pos + N - 1) := S.V (0 .. N - 1);
            Pos := Pos + N;
         end;
      end loop;
      --  Step 6: update with the additional input (possibly empty).
      Update (S, Additional);
      --  Step 7
      S.Counter := S.Counter + 1;
      OK := True;
   end Generate;

   procedure Sanitize (S : out State) is
   begin
      S := (K => (others => 0), V => (others => 0),
            Counter => 0, Interval => Max_Reseed_Interval, Live => False);
   end Sanitize;

   ----------------------------------------------------------------------------
   --  Known-answer self-test, SP 800-90A 11.3: one vector that exercises
   --  every DRBG function the mechanism implements (instantiate, reseed,
   --  generate; uninstantiate is exempt, 11.3.5). NIST CAVP
   --  drbgtestvectors, pr_false, HMAC_DRBG.rsp, [SHA-256]
   --  [PredictionResistance = False] [EntropyInputLen = 256]
   --  [NonceLen = 128] [PersonalizationStringLen = 0]
   --  [AdditionalInputLen = 0] [ReturnedBitsLen = 1024], COUNT = 0:
   --  instantiate, reseed, generate twice; ReturnedBits is the output of
   --  the second generate.
   ----------------------------------------------------------------------------

   KAT_Entropy : constant Byte_Seq (0 .. 31) :=
     (16#06#, 16#03#, 16#2c#, 16#d5#, 16#ee#, 16#d3#, 16#3f#, 16#39#,
      16#26#, 16#5f#, 16#49#, 16#ec#, 16#b1#, 16#42#, 16#c5#, 16#11#,
      16#da#, 16#9a#, 16#ff#, 16#2a#, 16#f7#, 16#12#, 16#03#, 16#bf#,
      16#fa#, 16#f3#, 16#4a#, 16#9c#, 16#a5#, 16#bd#, 16#9c#, 16#0d#);
   KAT_Nonce : constant Byte_Seq (0 .. 15) :=
     (16#0e#, 16#66#, 16#f7#, 16#1e#, 16#dc#, 16#43#, 16#e4#, 16#2a#,
      16#45#, 16#ad#, 16#3c#, 16#6f#, 16#c6#, 16#cd#, 16#c4#, 16#df#);
   KAT_Reseed : constant Byte_Seq (0 .. 31) :=
     (16#01#, 16#92#, 16#0a#, 16#4e#, 16#66#, 16#9e#, 16#d3#, 16#a8#,
      16#5a#, 16#e8#, 16#a3#, 16#3b#, 16#35#, 16#a7#, 16#4a#, 16#d7#,
      16#fb#, 16#2a#, 16#6b#, 16#b4#, 16#cf#, 16#39#, 16#5c#, 16#e0#,
      16#03#, 16#34#, 16#a9#, 16#c9#, 16#a5#, 16#a5#, 16#d5#, 16#52#);
   KAT_Expected : constant Byte_Seq (0 .. 127) :=
     (16#76#, 16#fc#, 16#79#, 16#fe#, 16#9b#, 16#50#, 16#be#, 16#cc#,
      16#c9#, 16#91#, 16#a1#, 16#1b#, 16#56#, 16#35#, 16#78#, 16#3a#,
      16#83#, 16#53#, 16#6a#, 16#dd#, 16#03#, 16#c1#, 16#57#, 16#fb#,
      16#30#, 16#64#, 16#5e#, 16#61#, 16#1c#, 16#28#, 16#98#, 16#bb#,
      16#2b#, 16#1b#, 16#c2#, 16#15#, 16#00#, 16#02#, 16#09#, 16#20#,
      16#8c#, 16#d5#, 16#06#, 16#cb#, 16#28#, 16#da#, 16#2a#, 16#51#,
      16#bd#, 16#b0#, 16#38#, 16#26#, 16#aa#, 16#f2#, 16#bd#, 16#23#,
      16#35#, 16#d5#, 16#76#, 16#d5#, 16#19#, 16#16#, 16#08#, 16#42#,
      16#e7#, 16#15#, 16#8a#, 16#d0#, 16#94#, 16#9d#, 16#1a#, 16#9e#,
      16#c3#, 16#e6#, 16#6e#, 16#a1#, 16#b1#, 16#a0#, 16#64#, 16#b0#,
      16#05#, 16#de#, 16#91#, 16#4e#, 16#ac#, 16#2e#, 16#9d#, 16#4f#,
      16#2d#, 16#72#, 16#a8#, 16#61#, 16#6a#, 16#80#, 16#22#, 16#54#,
      16#22#, 16#91#, 16#82#, 16#50#, 16#ff#, 16#66#, 16#a4#, 16#1b#,
      16#d2#, 16#f8#, 16#64#, 16#a6#, 16#a3#, 16#8c#, 16#c5#, 16#b6#,
      16#49#, 16#9d#, 16#c4#, 16#3f#, 16#7f#, 16#2b#, 16#d0#, 16#9e#,
      16#1e#, 16#0f#, 16#8f#, 16#58#, 16#85#, 16#93#, 16#51#, 16#24#);
   Empty : constant Byte_Seq (0 .. -1) := (others => 0);

   function Self_Test return Boolean is
      S    : State;
      Out1 : Byte_Seq (0 .. 127);
      Out2 : Byte_Seq (0 .. 127);
      OK1, OK2 : Boolean;
      Match : Boolean;
   begin
      Instantiate (S, KAT_Entropy, KAT_Nonce, Empty);
      Reseed (S, KAT_Reseed, Empty);
      Generate (S, Empty, Out1, OK1);
      Generate (S, Empty, Out2, OK2);
      Match := (OK1 and OK2) and then Out2 = KAT_Expected;
      Sanitize (S);
      pragma Warnings (GNATprove, Off, "statement has no effect");
      pragma Warnings (GNATprove, Off, "*is set by*");
      Sanitize (Out1);
      Sanitize (Out2);
      pragma Warnings (GNATprove, On, "*is set by*");
      pragma Warnings (GNATprove, On, "statement has no effect");
      return Match;
   end Self_Test;

end SPARKTLSCrypto.HMAC_DRBG;
