--  HMAC_DRBG with SHA-256: NIST SP 800-90A Rev. 1 section 10.1.2, the
--  deterministic random bit generator that sits between an entropy
--  source (SP 800-90B, e.g. SPARKEntropy) and every consumer of
--  randomness. This package is the mechanism only: a pure state machine
--  with no notion of where seed material comes from. The policy around
--  it (when to reseed, what to do when the entropy source fails) lives
--  in the caller, see SPARKTLS.RBG.
--
--  Security strength 256 bits. Sizes are bytes throughout.
--
--  The same construction, instantiated with the private key, is what
--  RFC 6979 uses for deterministic ECDSA nonces (SPARKTLSCrypto.RFC6979).
with SPARKNaCl; use SPARKNaCl;

package SPARKTLSCrypto.HMAC_DRBG with
   SPARK_Mode => On
is

   --  Table 2 of SP 800-90A for HMAC_DRBG with SHA-256.
   Min_Entropy_Len    : constant := 32;       --  security_strength = 256 bits
   Min_Nonce_Len      : constant := 16;       --  security_strength / 2
   Max_Seed_Material  : constant := 512;      --  our cap on entropy || nonce || personalization, and on additional input
   Max_Request        : constant := 65536;    --  2**19 bits per Generate
   Max_Reseed_Interval : constant := 2**48;   --  requests between reseeds

   type State is private;

   function Instantiated (S : State) return Boolean;

   --  Requests answered since the last seed (1 right after seeding).
   function Reseed_Counter (S : State) return Unsigned_64
   with Pre => Instantiated (S);

   --  True once the counter exceeds the interval given at Instantiate:
   --  Generate then refuses until Reseed (10.1.2.5 step 1).
   function Reseed_Required (S : State) return Boolean
   with Pre => Instantiated (S);

   --  10.1.2.3 Instantiate: seed_material = Entropy || Nonce ||
   --  Personalization. Reseed_Interval bounds the requests between
   --  reseeds; the caller's policy picks it (SPARKTLS.RBG uses 4096).
   procedure Instantiate
     (S               :    out State;
      Entropy         : in     Byte_Seq;
      Nonce           : in     Byte_Seq;
      Personalization : in     Byte_Seq;
      Reseed_Interval : in     Unsigned_64 := Max_Reseed_Interval)
   with
     Pre  => Entropy'First = 0 and Entropy'Length >= Min_Entropy_Len
             and Nonce'First = 0 and Nonce'Length >= Min_Nonce_Len
             and Personalization'First = 0
             and Entropy'Length + Nonce'Length + Personalization'Length <= Max_Seed_Material
             and Reseed_Interval in 1 .. Max_Reseed_Interval,
     Post => Instantiated (S) and then Reseed_Counter (S) = 1;

   --  10.1.2.4 Reseed: seed_material = Entropy || Additional.
   procedure Reseed
     (S          : in out State;
      Entropy    : in     Byte_Seq;
      Additional : in     Byte_Seq)
   with
     Pre  => Instantiated (S)
             and Entropy'First = 0 and Entropy'Length >= Min_Entropy_Len
             and Additional'First = 0
             and Entropy'Length + Additional'Length <= Max_Seed_Material,
     Post => Instantiated (S) and then Reseed_Counter (S) = 1;

   --  10.1.2.5 Generate. OK is False, and Output all zero, when a reseed
   --  is required first; nothing else fails.
   procedure Generate
     (S          : in out State;
      Additional : in     Byte_Seq;
      Output     :    out Byte_Seq;
      OK         :    out Boolean)
   with
     Pre  => Instantiated (S)
             and Additional'First = 0 and Additional'Length <= Max_Seed_Material
             and Output'First = 0 and Output'Length in 1 .. Max_Request,
     Post => Instantiated (S)
             and then OK = (not Reseed_Required (S'Old))
             and then (if OK then Reseed_Counter (S) = Reseed_Counter (S'Old) + 1
                       else Reseed_Counter (S) = Reseed_Counter (S'Old));

   --  Zero the working state and mark it uninstantiated.
   procedure Sanitize (S : out State)
   with Post => not Instantiated (S);

   --  SP 800-90A 11.3 known-answer self-test on a CAVP vector covering
   --  every implemented function: instantiate, reseed, generate twice,
   --  compare. Run at start-up by SPARKTLS.RBG.
   function Self_Test return Boolean;

private

   type State is record
      K, V            : Bytes_32 := (others => 0);
      Counter         : Unsigned_64 := 0;
      Interval        : Unsigned_64 := Max_Reseed_Interval;
      Live            : Boolean := False;
   end record;

   function Instantiated (S : State) return Boolean is (S.Live);
   function Reseed_Counter (S : State) return Unsigned_64 is (S.Counter);
   function Reseed_Required (S : State) return Boolean is (S.Counter > S.Interval);

end SPARKTLSCrypto.HMAC_DRBG;
