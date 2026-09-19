--  SPARKTLS ECDSA P-256 Signature Verification (body)
--
--  Scalar mod-n arithmetic uses 4×64-bit limbs with Barrett reduction
--  for the few products a signature needs. The inversion mod n, which is
--  hundreds of products, runs in the Montgomery domain (R = 2^256) on a
--  dedicated four-limb multiply: Mont_Mul_N_Portable here in SPARK, or
--  the BMI2/ADX tier's Mont_Mul_4 when the CPU has it.

with SPARKTLSCrypto.P256.Point; use SPARKTLSCrypto.P256.Point;
with SPARKTLSCrypto.BigNat64;
with SPARKTLSCrypto.BigNat64_ADX;
with SPARKTLSCrypto.CPU;

package body SPARKTLSCrypto.P256.ECDSA with
   SPARK_Mode => On
is
   --  ================================================================
   --  64-bit scalar types for mod-n arithmetic
   --  ================================================================

   --  P-256 curve order n (little-endian 64-bit limbs)
   N64 : constant Scalar_64 :=
     (0 => 16#F3B9CAC2FC632551#,
      1 => 16#BCE6FAADA7179E84#,
      2 => 16#FFFFFFFFFFFFFFFF#,
      3 => 16#FFFFFFFF00000000#);

   --  Barrett constant mu = floor(2^512 / n)
   --  257 bits, stored as 5 limbs (top limb = 1)
   type Mu_Array is array (0 .. 4) of Unsigned_64;
   Mu64 : constant Mu_Array :=
     (0 => 16#012FFD85EEDF9BFE#,
      1 => 16#43190552DF1A6C21#,
      2 => 16#FFFFFFFEFFFFFFFF#,
      3 => 16#00000000FFFFFFFF#,
      4 => 16#0000000000000001#);

   procedure P256_Muladd_32
     (A  : in out Byte_Seq;
      X  : in     ECDSA_Sig_Half;
      Y  : in     ECDSA_Sig_Half;
      OK :    out U32)
   is
   begin
      pragma Assert (X'First = 0);
      pragma Assert (X'Length = 32);
      pragma Assert (Y'First = 0);
      pragma Assert (Y'Length = 32);
      P256_Muladd (A, Byte_Seq (X), 32, Byte_Seq (Y), 32, OK);
   end P256_Muladd_32;

   ---------------------------------------------------------------
   --  Convert 32-byte big-endian to 4×64-bit LE scalar
   ---------------------------------------------------------------

   procedure Bytes_To_Scalar
     (D   : out Scalar_64;
      Src : in  ECDSA_Sig_Half)
   is
   begin
      --  Big-endian: Src(0) is MSB, Src(31) is LSB
      --  Little-endian limbs: D(0) = bytes 24..31, D(3) = bytes 0..7
      for L in 0 .. 3 loop
         declare
            Base : constant N32 := N32 (24 - L * 8);
            V : Unsigned_64 := 0;
         begin
            for B in 0 .. 7 loop
               V := V or Shift_Left (Unsigned_64 (Src (Base + N32 (B))),
                                     (7 - B) * 8);
            end loop;
            D (L) := V;
         end;
      end loop;
   end Bytes_To_Scalar;

   ---------------------------------------------------------------
   --  Convert 4×64-bit LE scalar to 32-byte big-endian
   ---------------------------------------------------------------

   procedure Scalar_To_Bytes
     (Dst : out ECDSA_Sig_Half;
      Src : in  Scalar_64)
   is
   begin
      for L in 0 .. 3 loop
         pragma Loop_Invariant
           (if L = 0 then True
            else
              (for all K in N32 range 32 - N32 (L) * 8 .. 31 =>
                 Dst (K)'Initialized));
         declare
            Base : constant N32 := N32 (24 - L * 8);
            V : constant Unsigned_64 := Src (L);
         begin
            for B in 0 .. 7 loop
               Dst (Base + N32 (B)) :=
                 Byte (Shift_Right (V, (7 - B) * 8) and 16#FF#);
            end loop;
         end;
      end loop;
   end Scalar_To_Bytes;

   ---------------------------------------------------------------
   --  4×4 schoolbook multiplication: 256-bit × 256-bit → 512-bit
   --  Uses Unsigned_128 for wide multiply-accumulate
   ---------------------------------------------------------------

   procedure Mul_Wide
     (D    : out Scalar_Wide;
      A, B : in  Scalar_64)
   is
      W : Unsigned_128;
      CC : Unsigned_128;
   begin
      D := (others => 0);

      for I in 0 .. 3 loop
         CC := 0;
         for J in 0 .. 3 loop
            W := Unsigned_128 (A (I)) * Unsigned_128 (B (J))
                 + Unsigned_128 (D (I + J)) + CC;
            D (I + J) := Unsigned_64 (W and 16#FFFF_FFFF_FFFF_FFFF#);
            CC := Shift_Right (W, 64);
         end loop;
         D (I + 4) := Unsigned_64 (CC);
      end loop;
   end Mul_Wide;

   ---------------------------------------------------------------
   --  Squaring: 256-bit → 512-bit (uses Mul_Wide for simplicity)
   ---------------------------------------------------------------

   procedure Sqr_Wide
     (D : out Scalar_Wide;
      A : in  Scalar_64)
   is
   begin
      Mul_Wide (D, A, A);
   end Sqr_Wide;

   ---------------------------------------------------------------
   --  Subtract: D := A - B, returns borrow (0 or 1)
   ---------------------------------------------------------------

   procedure Sub_Scalar
     (D      : out Scalar_64;
      A, B   : in  Scalar_64;
      Borrow : out Unsigned_64)
   is
      W  : Unsigned_128;
      CC : Unsigned_128 := 0;
   begin
      for I in 0 .. 3 loop
         W := Unsigned_128 (A (I)) - Unsigned_128 (B (I)) - CC;
         D (I) := Unsigned_64 (W and 16#FFFF_FFFF_FFFF_FFFF#);
         --  Borrow: if W < 0 (bit 64 set in two's complement)
         CC := Shift_Right (W, 127);  -- sign bit of 128-bit
      end loop;
      Borrow := Unsigned_64 (CC);
   end Sub_Scalar;

   ---------------------------------------------------------------
   --  Barrett reduction: given 512-bit product T, compute T mod n
   --
   --  1. q = floor(T * mu / 2^512)
   --  2. r = T - q * n (low 256 bits + carry)
   --  3. Conditional subtract n (at most twice)
   ---------------------------------------------------------------

   procedure Barrett_Reduce
     (D : out Scalar_64;
      T : in  Scalar_Wide)
   is
      --  T * mu: we need a 8×5 multiply, but only care about
      --  limbs 8+ (bits 512+) for the quotient.
      --  Actually: q = floor(T * mu >> 512).
      --  T is 8 limbs, mu is 5 limbs, product is 13 limbs.
      --  We need limbs 8..12 (5 limbs) of the product.
      --
      --  Optimization: we only need the high part, so we can skip
      --  computing product limbs 0..6 entirely. We need limb 7
      --  for the carry into limb 8+.
      --
      --  For correctness, compute the full product at first.

      --  Product T*mu (13 limbs, but we only store 14 for safety)
      type Wide13 is array (0 .. 13) of Unsigned_64;
      TM : Wide13 := (others => 0);

      Q  : Scalar_64;   --  quotient estimate (limbs 8..11 of T*mu)
      QN : Scalar_Wide;  --  q * n (512 bits)
      R  : Scalar_64;
      R4 : Unsigned_64;  --  5th limb of R (bits 256..319)
      Borrow : Unsigned_64;

      W  : Unsigned_128;
      CC : Unsigned_128;
   begin
      --  Step 1: Compute T * mu (8 × 5 schoolbook)
      for I in 0 .. 7 loop
         CC := 0;
         for J in 0 .. 4 loop
            declare
               K : constant Integer := I + J;
            begin
               if K <= 13 then
                  W := Unsigned_128 (T (I)) * Unsigned_128 (Mu64 (J))
                       + Unsigned_128 (TM (K)) + CC;
                  TM (K) := Unsigned_64 (W and 16#FFFF_FFFF_FFFF_FFFF#);
                  CC := Shift_Right (W, 64);
               else
                  CC := 0;
               end if;
            end;
         end loop;
         TM (I + 5) := TM (I + 5) + Unsigned_64 (CC);
      end loop;

      --  Step 2: Extract quotient q = limbs 8..11 of T*mu
      --  (This is floor(T * mu / 2^512))
      Q := (TM (8), TM (9), TM (10), TM (11));

      --  Step 3: Compute q * n (low 512 bits = 8 limbs)
      --  We only need the low 8 limbs since r < 3n < 2^258
      QN := (others => 0);
      for I in 0 .. 3 loop
         CC := 0;
         for J in 0 .. 3 loop
            declare
               K : constant Integer := I + J;
            begin
               if K <= 7 then
                  W := Unsigned_128 (Q (I)) * Unsigned_128 (N64 (J))
                       + Unsigned_128 (QN (K)) + CC;
                  QN (K) := Unsigned_64 (W and 16#FFFF_FFFF_FFFF_FFFF#);
                  CC := Shift_Right (W, 64);
               end if;
            end;
         end loop;
         QN (I + 4) := QN (I + 4) + Unsigned_64 (CC);
      end loop;

      --  Step 4: r = T - q*n (5 limbs, since R < 3n < 2^258)
      declare
         BW : Unsigned_128;
         BC : Unsigned_128 := 0;
      begin
         for I in 0 .. 3 loop
            BW := Unsigned_128 (T (I)) - Unsigned_128 (QN (I)) - BC;
            R (I) := Unsigned_64 (BW and 16#FFFF_FFFF_FFFF_FFFF#);
            BC := Shift_Right (BW, 127);
         end loop;
         --  5th limb
         BW := Unsigned_128 (T (4)) - Unsigned_128 (QN (4)) - BC;
         R4 := Unsigned_64 (BW and 16#FFFF_FFFF_FFFF_FFFF#);
      end;

      --  Step 5: Conditional subtract n (at most twice).
      --  R_actual = R4 * 2^256 + R, R_actual < 3n < 2^258.
      --  Subtract n up to twice to bring into [0, n). Done branch-
      --  free with mask-select so timing doesn't depend on R/R4
      --  values (which derive from secret K via Mul_Mod_N).
      for Round in 1 .. 2 loop
         Sub_Scalar (D, R, N64, Borrow);
         declare
            R4_NZ   : constant Unsigned_64 :=
              (if R4 > 0 then 1 else 0);
            Take    : constant Unsigned_64 := R4_NZ or (Borrow xor 1);
            Mask    : constant Unsigned_64 := -Take;
         begin
            for I in 0 .. 3 loop
               R (I) := (D (I) and Mask) or (R (I) and not Mask);
            end loop;
            --  Update R4: subtract Borrow*Take. When Take=1: R4 -=
            --  Borrow. When Take=0: R4 unchanged. Both branch-free.
            R4 := R4 - (Borrow and Take);
         end;
      end loop;
      D := R;
   end Barrett_Reduce;

   ---------------------------------------------------------------
   --  Modular multiplication: D := A * B mod n
   ---------------------------------------------------------------

   procedure Mul_Mod_N
     (D    : out Scalar_64;
      A, B : in  Scalar_64)
   is
      T : Scalar_Wide;
   begin
      Mul_Wide (T, A, B);
      Barrett_Reduce (D, T);
   end Mul_Mod_N;

   ---------------------------------------------------------------
   --  Modular squaring: D := A^2 mod n
   ---------------------------------------------------------------

   procedure Square_Mod_N
     (D : out Scalar_64;
      A : in  Scalar_64)
   is
      T : Scalar_Wide;
   begin
      Sqr_Wide (T, A);
      Barrett_Reduce (D, T);
   end Square_Mod_N;

   ---------------------------------------------------------------
   --  Modular addition: D := (A + B) mod n
   ---------------------------------------------------------------

   procedure Add_Mod_N
     (D    : out Scalar_64;
      A, B : in  Scalar_64)
   is
      W  : Unsigned_128;
      CC : Unsigned_128 := 0;
      Sum : Scalar_64;
      Tmp : Scalar_64;
      Borrow : Unsigned_64;
   begin
      --  Sum = A + B
      for I in 0 .. 3 loop
         W := Unsigned_128 (A (I)) + Unsigned_128 (B (I)) + CC;
         Sum (I) := Unsigned_64 (W and 16#FFFF_FFFF_FFFF_FFFF#);
         CC := Shift_Right (W, 64);
      end loop;
      --  Try subtract n.
      --  If CC > 0, the true sum is 2^256 + Sum, which is > n,
      --  so we must subtract.  Sub_Scalar gives the right 256-bit result
      --  even with the implicit high bit (Tmp = 2^256 + Sum - n).
      Sub_Scalar (Tmp, Sum, N64, Borrow);
      --  Branch-free CT reduction: use Tmp (= Sum - N) if CC > 0
      --  (carry from add) OR Borrow = 0 (Sum >= N), else use Sum.
      --  CC is 0 or 1 (carry-out of 2^64 add chain), Borrow is 0 or 1.
      declare
         Use_Tmp : constant Unsigned_64 :=
           Unsigned_64 (CC) or (Borrow xor 1);
         Mask    : constant Unsigned_64 := -Use_Tmp;
      begin
         for I in 0 .. 3 loop
            D (I) := (Tmp (I) and Mask) or (Sum (I) and not Mask);
         end loop;
      end;
   end Add_Mod_N;

   ---------------------------------------------------------------
   --  Modular inversion: D := A^(n-2) mod n (Fermat)
   ---------------------------------------------------------------

   ---------------------------------------------------------------
   --  Montgomery arithmetic modulo n, R = 2^256
   ---------------------------------------------------------------

   --  R mod n: the Montgomery form of 1.
   N_R_Mod_N : constant Scalar_64 :=
     (16#0C46_353D_039C_DAAF#, 16#4319_0552_58E8_617B#,
      16#0000_0000_0000_0000#, 16#0000_0000_FFFF_FFFF#);

   --  R^2 mod n: multiplying by it takes a value into Montgomery form.
   N_R2_Mod_N : constant Scalar_64 :=
     (16#8324_4C95_BE79_EEA2#, 16#4699_799C_49BD_6FA6#,
      16#2845_B239_2B6B_EC59#, 16#66E1_2D94_F3D9_5620#);

   --  -n^-1 mod 2^64
   N0I : constant Unsigned_64 := 16#CCD1_C8AA_EE00_BC4F#;

   Mask64 : constant Unsigned_128 := 16#FFFF_FFFF_FFFF_FFFF#;

   --  Word-by-word CIOS on four limbs with one final conditional
   --  subtraction, the shape of BigNat64.Monty_Mul without its
   --  Max_Words record. All arithmetic is on modular types; every
   --  narrowing masks first, so there is no overflow or range check to
   --  discharge beyond the indices.
   procedure Mont_Mul_N_Portable
     (D    : out Scalar_64;
      A, B : in  Scalar_64)
   is
      T   : array (0 .. 5) of Unsigned_64 := (others => 0);
      C   : Unsigned_128;
      M   : Unsigned_64;
      Borrow, CC : Unsigned_128 := 0;
      Ctl : Unsigned_64;
   begin
      for I in 0 .. 3 loop
         --  T := T + A (I) * B
         C := 0;
         for J in 0 .. 3 loop
            C := Unsigned_128 (T (J))
                 + Unsigned_128 (A (I)) * Unsigned_128 (B (J)) + C;
            T (J) := Unsigned_64 (C and Mask64);
            C := Shift_Right (C, 64);
         end loop;
         C := Unsigned_128 (T (4)) + C;
         T (4) := Unsigned_64 (C and Mask64);
         T (5) := T (5) + Unsigned_64 (Shift_Right (C, 64));
         --  T := (T + m * n) / 2^64 with m chosen so the low word cancels
         M := T (0) * N0I;
         C := Unsigned_128 (T (0)) + Unsigned_128 (M) * Unsigned_128 (N64 (0));
         C := Shift_Right (C, 64);
         for J in 1 .. 3 loop
            C := Unsigned_128 (T (J))
                 + Unsigned_128 (M) * Unsigned_128 (N64 (J)) + C;
            T (J - 1) := Unsigned_64 (C and Mask64);
            C := Shift_Right (C, 64);
         end loop;
         C := Unsigned_128 (T (4)) + C;
         T (3) := Unsigned_64 (C and Mask64);
         T (4) := T (5) + Unsigned_64 (Shift_Right (C, 64));
         T (5) := 0;
      end loop;

      --  Subtract n once if T (4) /= 0 or T >= n: borrow scan, then a
      --  masked subtraction, both over every limb.
      for J in 0 .. 3 loop
         declare
            Diff : constant Unsigned_128 :=
              Unsigned_128 (T (J)) - Unsigned_128 (N64 (J)) - Borrow;
         begin
            Borrow := Shift_Right (Diff, 127) and 1;
         end;
      end loop;
      Ctl := SPARKTLSCrypto.BigNat64.CT_Neq (T (4), 0) or
             SPARKTLSCrypto.BigNat64.CT_Not (Unsigned_64 (Borrow));
      for J in 0 .. 3 loop
         declare
            Diff : constant Unsigned_128 :=
              Unsigned_128 (T (J)) - Unsigned_128 (N64 (J)) - CC;
         begin
            D (J) := SPARKTLSCrypto.BigNat64.CT_Mux
              (Ctl, Unsigned_64 (Diff and Mask64), T (J));
            CC := Shift_Right (Diff, 127) and 1;
         end;
      end loop;
      --  Scrub: to flow analysis these are dead stores, which is the point.
      pragma Warnings (GNATprove, Off, "statement has no effect");
      pragma Warnings (GNATprove, Off, "unused assignment");
      T := (others => 0);
      M := 0;
      pragma Inspection_Point (T);
      pragma Inspection_Point (M);
      pragma Warnings (GNATprove, On, "unused assignment");
      pragma Warnings (GNATprove, On, "statement has no effect");
   end Mont_Mul_N_Portable;

   procedure Mont_Mul_N
     (D    : out Scalar_64;
      A, B : in  Scalar_64)
   is
   begin
      --  The tier flag is fixed at elaboration: no data-dependent branch.
      if SPARKTLSCrypto.CPU.Has_BMI2_ADX then
         SPARKTLSCrypto.BigNat64_ADX.Mont_Mul_4
           (SPARKTLSCrypto.BigNat64.Limbs_4 (D),
            SPARKTLSCrypto.BigNat64.Limbs_4 (A),
            SPARKTLSCrypto.BigNat64.Limbs_4 (B),
            SPARKTLSCrypto.BigNat64.Limbs_4 (N64),
            N0I);
      else
         Mont_Mul_N_Portable (D, A, B);
      end if;
   end Mont_Mul_N;

   ---------------------------------------------------------------
   --  Modular inversion: D := A^(n-2) mod n (Fermat)
   ---------------------------------------------------------------

   procedure Inv_Mod_N
     (D : out Scalar_64;
      A : in  Scalar_64)
   is
      --  n - 2 in big-endian bytes; the exponent is public, so the table
      --  below is indexed by it directly: no scan is needed.
      N_Minus_2 : constant Byte_Seq (0 .. 31) :=
        (16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#00#, 16#00#, 16#00#, 16#00#,
         16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#,
         16#BC#, 16#E6#, 16#FA#, 16#AD#, 16#A7#, 16#17#, 16#9E#, 16#84#,
         16#F3#, 16#B9#, 16#CA#, 16#C2#, 16#FC#, 16#63#, 16#25#, 16#4F#);

      subtype Window is Natural range 0 .. 15;
      type Table is array (Window) of Scalar_64;
      --  Every entry is written below; the aggregate is for flow analysis.
      T   : Table := (others => (others => 0));
      Acc : Scalar_64;
      Tmp : Scalar_64;
      One : constant Scalar_64 := (1, 0, 0, 0);
   begin
      --  A into Montgomery form, then A^w for w in 0 .. 15
      Mont_Mul_N (T (1), A, N_R2_Mod_N);
      T (0) := N_R_Mod_N;
      for W in 2 .. 15 loop
         Mont_Mul_N (Tmp, T (W - 1), T (1));
         T (W) := Tmp;
      end loop;

      --  Windows from the most significant nibble. Four squarings
      --  ping-pong between Acc and Tmp so no copy is needed.
      Acc := N_R_Mod_N;
      for I in N_Minus_2'Range loop
         for Half in reverse 0 .. 1 loop
            declare
               W : constant Window :=
                 Window (Shift_Right (Unsigned_8 (N_Minus_2 (I)), Half * 4)
                         and 15);
            begin
               Mont_Mul_N (Tmp, Acc, Acc);
               Mont_Mul_N (Acc, Tmp, Tmp);
               Mont_Mul_N (Tmp, Acc, Acc);
               Mont_Mul_N (Acc, Tmp, Tmp);
               Mont_Mul_N (Tmp, Acc, T (W));
               Acc := Tmp;
            end;
         end loop;
      end loop;

      --  Leave the Montgomery domain
      Mont_Mul_N (D, Acc, One);

      --  Scrub: to flow analysis these are dead stores, which is the point.
      pragma Warnings (GNATprove, Off, "statement has no effect");
      pragma Warnings (GNATprove, Off, "unused assignment");
      T   := (others => (others => 0));
      Acc := (others => 0);
      Tmp := (others => 0);
      pragma Inspection_Point (T);
      pragma Inspection_Point (Acc);
      pragma Inspection_Point (Tmp);
      pragma Warnings (GNATprove, On, "unused assignment");
      pragma Warnings (GNATprove, On, "statement has no effect");
   end Inv_Mod_N;

   ---------------------------------------------------------------
   --  Check if scalar is zero (constant-time)
   ---------------------------------------------------------------

   function Is_Zero_Scalar (A : Scalar_64) return Boolean is
      Z : Unsigned_64 := 0;
   begin
      for I in 0 .. 3 loop
         Z := Z or A (I);
      end loop;
      return Z = 0;
   end Is_Zero_Scalar;

   ---------------------------------------------------------------
   --  Check if A < n (try subtract, check borrow)
   ---------------------------------------------------------------

   function Less_Than_Order (A : Scalar_64) return Boolean is
      Tmp    : Scalar_64;
      Borrow : Unsigned_64;
   begin
      Sub_Scalar (Tmp, A, N64, Borrow);
      return Borrow = 1;
   end Less_Than_Order;

   ---------------------------------------------------------------
   --  Reduce mod n: if A >= n, subtract n
   ---------------------------------------------------------------

   procedure Reduce_Once
     (A : in out Scalar_64)
   is
      Tmp    : Scalar_64;
      Borrow : Unsigned_64;
      Mask   : Unsigned_64;
   begin
      Sub_Scalar (Tmp, A, N64, Borrow);
      --  If Borrow = 0 (A >= N), use Tmp (= A - N). Otherwise keep A.
      --  Branch-free via mask. The previous `if Borrow = 0 then A :=
      --  Tmp; end if;` is constant-time IF the compiler emits cmov,
      --  but a dudect timing test detected a residual variance —
      --  this explicit mask version eliminates that ambiguity.
      Mask := -(Borrow xor 1);  --  0xFF..F if Borrow=0, else 0
      for I in A'Range loop
         A (I) := (A (I) and not Mask) or (Tmp (I) and Mask);
      end loop;
   end Reduce_Once;

   ---------------------------------------------------------------
   --  ECDSA Sign
   ---------------------------------------------------------------

   procedure Sign
     (Hash  : in     Bytes_32;
      D     : in     ECDSA_Sig_Half;
      K     : in     ECDSA_Sig_Half;
      Blind : in     Byte_Seq;
      R_Out :    out ECDSA_Sig_Half;
      S_Out :    out ECDSA_Sig_Half;
      OK    :    out Boolean)
   is
      --  PRECONDITION (caller's responsibility): K is in [1, n-1].
      --  Use SPARKTLSCrypto.RFC6979.Derive_K_P256 to obtain a valid K.
      --  Sign no longer validates K — that previous validation was a
      --  non-constant-time early-return on data derived from K, which
      --  ctgrind/dudect both flagged. With RFC 6979, K is guaranteed
      --  in range by construction so the check is moot.
      --
      --  R_Out / S_Out are guaranteed in [1, n-1] for any valid K
      --  with overwhelming probability — the once-in-2²⁵⁶ corner
      --  cases (R = 0 or S = 0) would now produce a malformed
      --  signature, but those are statistically impossible.
      K_S, D_S, H_S : Scalar_64;
      R_S, S_S      : Scalar_64;
      RD, Sum, K_Inv : Scalar_64;

      Pt     : P256_Jacobian;
      Chk    : P256_Jacobian;
      Enc    : Byte_Seq (0 .. 64);
      On_Curve : U32;
      RX     : Byte_Seq (0 .. 31);
      RX_Half : ECDSA_Sig_Half;
   begin
      Bytes_To_Scalar (K_S, K);
      Bytes_To_Scalar (D_S, D);
      Bytes_To_Scalar (H_S, ECDSA_Sig_Half (Hash));

      Reduce_Once (H_S);

      --  SR-62: blinded scalar and randomised coordinates
      P256_Mulgen_Blinded (Pt, Bytes_32 (K), Blind);
      P256_To_Affine (Pt);

      --  SR-66: the point must satisfy the curve equation; a corrupted
      --  table entry or a computation fault otherwise becomes a wrong
      --  signature. Encode and re-decode, which performs the check.
      P256_Encode (Enc, Pt);
      P256_Decode (Chk, Enc, On_Curve);
      if On_Curve /= 1 then
         R_Out := (others => 0);
         S_Out := (others => 0);
         OK := False;
         return;
      end if;

      FE_To_Bytes (RX, Pt.X);
      RX_Half := ECDSA_Sig_Half (RX);
      Bytes_To_Scalar (R_S, RX_Half);
      Reduce_Once (R_S);

      --  s = k^(-1) * (hash + r*d) mod n
      Mul_Mod_N (RD, R_S, D_S);
      Add_Mod_N (Sum, H_S, RD);
      Inv_Mod_N (K_Inv, K_S);
      Mul_Mod_N (S_S, K_Inv, Sum);

      Scalar_To_Bytes (R_Out, R_S);
      Scalar_To_Bytes (S_Out, S_S);
      OK := True;
   end Sign;

   ---------------------------------------------------------------
   --  ECDSA Verify
   ---------------------------------------------------------------

   function Verify
     (Hash : in Bytes_32;
      Qx   : in ECDSA_Sig_Half;
      Qy   : in ECDSA_Sig_Half;
      R    : in ECDSA_Sig_Half;
      S    : in ECDSA_Sig_Half) return Boolean
   is
      R_S, S_S    : Scalar_64;
      H_S         : Scalar_64;
      W_S         : Scalar_64;
      U1_S, U2_S  : Scalar_64;

      U1_Bytes, U2_Bytes : ECDSA_Sig_Half;

      PK_Enc : Byte_Seq (0 .. 64) := (others => 0);
      RX     : Byte_Seq (0 .. 31);
      RX_S   : Scalar_64;
      Diff   : Scalar_64;

      OK     : U32;
      Borrow : Unsigned_64;
   begin
      Bytes_To_Scalar (R_S, R);
      Bytes_To_Scalar (S_S, S);

      --  Check r, s in [1, n-1]
      if Is_Zero_Scalar (R_S) or Is_Zero_Scalar (S_S) then
         return False;
      end if;
      if not Less_Than_Order (R_S) then
         return False;
      end if;
      if not Less_Than_Order (S_S) then
         return False;
      end if;

      Bytes_To_Scalar (H_S, ECDSA_Sig_Half (Hash));
      Reduce_Once (H_S);

      --  w = s^(-1) mod n
      Inv_Mod_N (W_S, S_S);

      --  u1 = hash * w mod n
      Mul_Mod_N (U1_S, H_S, W_S);

      --  u2 = r * w mod n
      Mul_Mod_N (U2_S, R_S, W_S);

      --  Convert back to bytes for P256_Muladd
      Scalar_To_Bytes (U1_Bytes, U1_S);
      Scalar_To_Bytes (U2_Bytes, U2_S);

      --  R = u1*G + u2*Q
      PK_Enc (0) := 16#04#;
      PK_Enc (1 .. 32) := Qx;
      PK_Enc (33 .. 64) := Qy;

      P256_Muladd_32 (PK_Enc, U2_Bytes, U1_Bytes, OK);

      --  OK carries the public-key validation (prefix, x, y < p,
      --  on-curve) and the not-infinity condition as a 0/1 flag. It is
      --  folded into the verdict below rather than branched on, so an
      --  invalid Q takes the same path as a valid one.

      --  Check R.x == r (mod n)
      RX := PK_Enc (1 .. 32);
      Bytes_To_Scalar (RX_S, ECDSA_Sig_Half (RX));
      Reduce_Once (RX_S);

      --  Constant-time comparison
      Sub_Scalar (Diff, RX_S, R_S, Borrow);
      return Is_Zero_Scalar (Diff) and Borrow = 0 and OK = 1;
   end Verify;

   procedure Test_Mul_Mod_N
     (A_Bytes : in  ECDSA_Sig_Half;
      B_Bytes : in  ECDSA_Sig_Half;
      R_Bytes : out ECDSA_Sig_Half)
   is
      A_S, B_S, R_S : Scalar_64;
   begin
      Bytes_To_Scalar (A_S, A_Bytes);
      Bytes_To_Scalar (B_S, B_Bytes);
      Mul_Mod_N (R_S, A_S, B_S);
      Scalar_To_Bytes (R_Bytes, R_S);
   end Test_Mul_Mod_N;

   procedure Test_Inv_Mod_N
     (A_Bytes : in  ECDSA_Sig_Half;
      R_Bytes : out ECDSA_Sig_Half)
   is
      A_S, R_S : Scalar_64;
   begin
      Bytes_To_Scalar (A_S, A_Bytes);
      Inv_Mod_N (R_S, A_S);
      Scalar_To_Bytes (R_Bytes, R_S);
   end Test_Inv_Mod_N;

   procedure Test_Add_Mod_N
     (A_Bytes : in  ECDSA_Sig_Half;
      B_Bytes : in  ECDSA_Sig_Half;
      R_Bytes : out ECDSA_Sig_Half)
   is
      A_S, B_S, R_S : Scalar_64;
   begin
      Bytes_To_Scalar (A_S, A_Bytes);
      Bytes_To_Scalar (B_S, B_Bytes);
      Add_Mod_N (R_S, A_S, B_S);
      Scalar_To_Bytes (R_Bytes, R_S);
   end Test_Add_Mod_N;

   procedure Test_Sqr_Mod_N
     (A_Bytes : in  ECDSA_Sig_Half;
      R_Bytes : out ECDSA_Sig_Half)
   is
      A_S, R_S : Scalar_64;
   begin
      Bytes_To_Scalar (A_S, A_Bytes);
      Square_Mod_N (R_S, A_S);
      Scalar_To_Bytes (R_Bytes, R_S);
   end Test_Sqr_Mod_N;

end SPARKTLSCrypto.P256.ECDSA;
