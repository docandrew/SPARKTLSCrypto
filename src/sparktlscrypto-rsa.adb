--  SPARKTLS RSA-PSS-RSAE Signature Verification
--  Uses SPARK-proven BigNat library for modular exponentiation.

with SPARKTLSCrypto.Hashing.SHA256;
with SPARKNaCl.Hashing.SHA384;
with SPARKNaCl.Hashing.SHA512;
with SPARKTLSCrypto.BigNat64;
with Interfaces; use Interfaces;

package body SPARKTLSCrypto.RSA with
   SPARK_Mode => On
is
   ----------------------------------------------------------------------------
   --  Forward declarations
   ----------------------------------------------------------------------------

   procedure RSA_Public
     (X       : in out Byte_Seq;
      X_Len   : in     Natural;
      Modulus : in     Byte_Seq;
      Mod_Len : in     Natural;
      Exp     : in     Unsigned_32;
      OK      :    out Boolean)
   with Always_Terminates,
        Pre => X'First = 0 and X'Last < N32'Last
               and Modulus'First = 0 and Modulus'Last < N32'Last
               and Mod_Len <= Max_RSA_Bytes
               and (Mod_Len = 0 or else N32 (Mod_Len) - 1 <= Modulus'Last)
               and (X_Len = 0 or else N32 (X_Len) - 1 <= X'Last);

   procedure PSS_Verify
     (EM       : in out Byte_Seq;
      EM_Len   : in     Natural;
      M_Hash   : in     Byte_Seq;
      Hash_Len : in     Natural;
      Hash_Alg : in     PSS_Hash;
      N_Bitlen : in     Natural;
      Valid    :    out Boolean)
   with Always_Terminates,
        Pre => N_Bitlen >= 2 and N_Bitlen <= Max_RSA_Bits
               and Hash_Len in 32 | 48 | 64
               and EM'First = 0
               and EM'Last < Max_RSA_Bytes
               and EM_Len > 0 and N32 (EM_Len) - 1 <= EM'Last
               and M_Hash'First = 0
               and N32 (Hash_Len) - 1 <= M_Hash'Last;

   ----------------------------------------------------------------------------
   --  Constant-time primitives
   ----------------------------------------------------------------------------

   --  Constant-time "is X equal to zero?", returning 1 iff X = 0.
   --
   --  Trick: for any X /= 0, exactly one of X or -X has its top bit
   --  set (a non-zero unsigned value or its two's-complement negation
   --  spans the high bit). For X = 0, both are 0. So
   --    (X or -X) bit 31 = 1  iff  X /= 0
   --  Shift_Right by 31 isolates that bit, and xor 1 inverts to
   --  return 1-iff-zero.
   --
   --  Previous implementation used `Shift_Right (X, 1) or (X and 1)`
   --  which always produces a value with bit 31 = 0 (Shift_Right
   --  zero-extends), so `Shift_Right (..., 31)` was always 0 and
   --  the function always returned 1 — silently breaking every
   --  caller. The fix below mirrors the CT_Neq pattern used in
   --  Bit_Length_Word.
   function CT_Eq0 (X : Unsigned_32) return Unsigned_32 is
     (Shift_Right (X or (0 - X), 31) xor 1)
   with Post => CT_Eq0'Result = (if X = 0 then 1 else 0);

   function Bit_Length_Word (X : Unsigned_32) return Unsigned_32 is
      function CT_Neq (A, B : Unsigned_32) return Unsigned_32 is
         (Shift_Right ((A xor B) or (-(A xor B)), 31));
      function CT_GT (A, B : Unsigned_32) return Unsigned_32 is
         (Shift_Right ((B - A) xor ((A xor B) and ((A xor (B - A)))), 31));
      function CT_Mux (Ctl, A, B : Unsigned_32) return Unsigned_32 is
        (B xor ((-Ctl) and (A xor B)));
      V : Unsigned_32 := X;
      K : Unsigned_32;
      C : Unsigned_32;
   begin
      K := CT_Neq (V, 0);
      C := CT_GT (V, 16#FFFF#);
      V := CT_Mux (C, Shift_Right (V, 16), V);
      K := K + Shift_Left (C, 4);
      C := CT_GT (V, 16#FF#);
      V := CT_Mux (C, Shift_Right (V, 8), V);
      K := K + Shift_Left (C, 3);
      C := CT_GT (V, 16#F#);
      V := CT_Mux (C, Shift_Right (V, 4), V);
      K := K + Shift_Left (C, 2);
      C := CT_GT (V, 16#3#);
      V := CT_Mux (C, Shift_Right (V, 2), V);
      K := K + Shift_Left (C, 1);
      K := K + CT_GT (V, 16#1#);
      return K;
   end Bit_Length_Word;

   ----------------------------------------------------------------------------
   --  RSA public key operation using SPARK-proven BigNat
   ----------------------------------------------------------------------------

   procedure RSA_Public
     (X       : in out Byte_Seq;
      X_Len   : in     Natural;
      Modulus : in     Byte_Seq;
      Mod_Len : in     Natural;
      Exp     : in     Unsigned_32;
      OK      :    out Boolean)
   is
      use BigNat64;
      M       : Big_Nat;
      A       : Big_Nat;
      M0I     : Word;
      E       : Byte_Seq (0 .. 3) := (others => 0);
      Reduced : Word := 0;   --  1 iff the signature satisfied 0 <= s < n
   begin
      OK := False;

      if Mod_Len = 0 or else X_Len /= Mod_Len
         or else Mod_Len > Max_RSA_Bytes
      then
         return;
      end if;

      --  Copy to 0-indexed buffers for BigNat (requires First=0)
      declare
         Mod_Buf : Byte_Seq (0 .. N32 (Mod_Len) - 1);
         X_Buf   : Byte_Seq (0 .. N32 (X_Len) - 1);
      begin
         Mod_Buf := Modulus (Modulus'First .. Modulus'First + N32 (Mod_Len) - 1);
         X_Buf   := X (X'First .. X'First + N32 (X_Len) - 1);

         Decode (M, Mod_Buf);

         if M.Len = 0 or else (M.W (0) and 1) = 0 then
            return;
         end if;

         M0I := Ninv (M.W (0));

         Decode (A, X_Buf);

         if A.Len < M.Len then
            A.Len := M.Len;
         elsif A.Len > M.Len then
            return;
         end if;

         --  RFC 8017 5.2.2 step 1 / RSASSA verify: the signature
         --  representative s MUST satisfy 0 <= s < n. A non-reduced s
         --  (s >= n, same word length) exponentiates to the identical
         --  s^e mod n and would otherwise verify, so it must be rejected
         --  (Wycheproof rsa_signature "the signature is not reduced",
         --  flag SignatureMalleability); the 32-bit-limb predecessor
         --  rejected it, the BigNat64 rewrite dropped it.
         --
         --  BRANCHLESS: RSA_Public is also the verify-after-sign step of
         --  the CRT signer (RSA_Private_Fast), where A is the signature
         --  derived from the SECRET key, so this must not branch on the
         --  value. A.Len now equals M.Len; CT_Sub's borrow (Carry) is 1
         --  iff A < M. Record it and fold it into OK at the end, where
         --  the caller already makes its (classified) accept/reject
         --  decision. Modpow still runs, so timing is input-independent.
         Reduced := CT_Sub (A, M, 1).Carry;

         declare
            Result : Big_Nat;
         begin
            if Exp > 0 and then Top_Bit_Set (M.W (M.Len - 1)) then
               --  Public exponent, public base: plain ladder with R^2
               --  from squarings (BigNat64.Modpow_Public / R2_Mod).
               declare
                  R2 : Big_Nat;
               begin
                  R2_Mod (R2, M, M0I);
                  Modpow_Public (Result, A, Word (Exp), M, M0I, R2);
               end;
            else
               E (0) := Byte (Shift_Right (Exp, 24) and 16#FF#);
               E (1) := Byte (Shift_Right (Exp, 16) and 16#FF#);
               E (2) := Byte (Shift_Right (Exp, 8) and 16#FF#);
               E (3) := Byte (Exp and 16#FF#);
               Modpow (Result, A, E, M, M0I);
            end if;
            Encode (X_Buf, Result);
         end;

         X (X'First .. X'First + N32 (X_Len) - 1) := X_Buf;
      end;

      --  Accept only if the signature was reduced (Reduced = 1). A
      --  non-reduced s falls through to OK = False with no data-dependent
      --  branch; the caller (Verify_PKCS1_v1_5 / Verify_PSS) rejects on
      --  not OK, and RSA_Private_Fast folds it into the classified
      --  verify-after-sign decision.
      OK := Reduced = 1;
   end RSA_Public;

   ----------------------------------------------------------------------------
   --  Hash computation
   ----------------------------------------------------------------------------

   procedure Compute_Hash
     (Alg     : in     PSS_Hash;
      Input   : in     Byte_Seq;
      Output  :    out Byte_Seq;
      Out_Len : in     Natural)
   with Always_Terminates,
        Pre => Input'First = 0 and Output'First = 0 and
               Input'Last < N32'Last - 256
               and Output'Last < N32'Last
               and (Out_Len = 0 or else N32 (Out_Len) - 1 <= Output'Last)
               and Out_Len <= 64
               and Input'Last < N32'Last
   is
   begin
      Output := (others => 0);
      case Alg is
         when PSS_SHA256 =>
            declare
               D : SPARKTLSCrypto.Hashing.SHA256.Digest;
               Len : constant Natural := Natural'Min (Out_Len, 32);
            begin
               SPARKTLSCrypto.Hashing.SHA256.Hash (D, Input);
               for I in 0 .. Len - 1 loop
                  Output (N32 (I)) := D (N32 (I));
               end loop;
            end;
         when PSS_SHA384 =>
            declare
               D : SPARKNaCl.Hashing.SHA384.Digest;
               Len : constant Natural := Natural'Min (Out_Len, 48);
            begin
               SPARKNaCl.Hashing.SHA384.Hash (D, Input);
               for I in 0 .. Len - 1 loop
                  Output (N32 (I)) := D (N32 (I));
               end loop;
            end;
         when PSS_SHA512 =>
            declare
               D : SPARKNaCl.Hashing.SHA512.Digest;
               Len : constant Natural := Natural'Min (Out_Len, 64);
            begin
               SPARKNaCl.Hashing.SHA512.Hash (D, Input);
               for I in 0 .. Len - 1 loop
                  Output (N32 (I)) := D (N32 (I));
               end loop;
            end;
      end case;
   end Compute_Hash;

   ----------------------------------------------------------------------------
   --  MGF1
   ----------------------------------------------------------------------------

   procedure MGF1_XOR
     (Alg       : in     PSS_Hash;
      Hash_Len  : in     Natural;
      Data      : in out Byte_Seq;
      Data_Len  : in     Natural;
      Seed      : in     Byte_Seq;
      Seed_Len  : in     Natural)
   with Pre => Hash_Len in 32 | 48 | 64
               and Data'First = 0
               and Data'Last < Max_RSA_Bytes
               and (Data_Len = 0 or else N32 (Data_Len) - 1 <= Data'Last)
               and Data_Len <= Max_RSA_Bytes
               and Seed'First = 0
               and Seed'Last < 1000
               and (Seed_Len = 0 or else N32 (Seed_Len) - 1 <= Seed'Last)
               and Seed_Len <= 500,
        Always_Terminates
   is
      Counter : Unsigned_32 := 0;
      Pos     : Natural := 0;
   begin
      while Pos < Data_Len loop
         pragma Loop_Invariant (Pos <= Data_Len and Pos <= Max_RSA_Bytes);
         pragma Loop_Variant (Increases => Pos);
         declare
            Input_Len : constant N32 := N32 (Seed_Len) + 4;
            Input     : Byte_Seq (0 .. Input_Len - 1) := (others => 0);
            H_Out     : Byte_Seq (0 .. N32 (Hash_Len) - 1);
         begin
            Input (0 .. N32 (Seed_Len) - 1) :=
               Seed (0 .. N32 (Seed_Len) - 1);
            Input (N32 (Seed_Len))     :=
               Byte (Shift_Right (Counter, 24) and 16#FF#);
            Input (N32 (Seed_Len) + 1) :=
               Byte (Shift_Right (Counter, 16) and 16#FF#);
            Input (N32 (Seed_Len) + 2) :=
               Byte (Shift_Right (Counter, 8) and 16#FF#);
            Input (N32 (Seed_Len) + 3) :=
               Byte (Counter and 16#FF#);

            Compute_Hash (Alg, Input, H_Out, Hash_Len);

            for I in 0 .. Hash_Len - 1 loop
               exit when Pos + I >= Data_Len;
               Data (N32 (Pos + I)) :=
                  Data (N32 (Pos + I)) xor H_Out (N32 (I));
            end loop;
         end;

         Pos := Pos + Hash_Len;
         Counter := Counter + 1;
      end loop;
   end MGF1_XOR;

   ----------------------------------------------------------------------------
   --  PSS Verify (RFC 8017 Section 9.1.2)
   ----------------------------------------------------------------------------

   procedure PSS_Verify
     (EM       : in out Byte_Seq;
      EM_Len   : in     Natural;
      M_Hash   : in     Byte_Seq;
      Hash_Len : in     Natural;
      Hash_Alg : in     PSS_Hash;
      N_Bitlen : in     Natural;
      Valid    :    out Boolean)
   is
      Salt_Len  : constant Natural := Hash_Len;
      R         : Unsigned_32 := 0;
      --  N_Bitlen >= 2 from Pre, so EM_Bits >= 1
      EM_Bits   : constant Natural := N_Bitlen - 1;
      --  EM_Bits >= 1 so (1 + 7)/8 = 1 min; no overflow since
      --  N_Bitlen <= 8 * Max_RSA_Bytes which fits in Natural.
      XLen      : constant Natural := (EM_Bits + 7) / 8;
      DB_Len    : Natural;
      Seed_Off  : N32;
      Salt_Off  : N32;
      Pad_Len   : Natural;
   begin
      Valid := False;

      --  Hash_Len in 32|48|64 and Salt_Len = Hash_Len, so
      --  Hash_Len + Salt_Len + 2 in {66, 98, 130} -- no overflow.
      if XLen < Hash_Len + Salt_Len + 2 then
         return;
      end if;

      --  XLen >= Hash_Len + Salt_Len + 2 >= 66, and XLen <= EM_Len
      --  since XLen = ceil((N_Bitlen-1)/8) <= ceil(N_Bitlen/8) <= EM_Len.
      --  Guard that XLen fits within EM bounds.
      if XLen > EM_Len or else N32 (XLen) > EM'Last + 1 then
         return;
      end if;

      pragma Assert (XLen >= 66);
      pragma Assert (N32 (XLen) - 1 <= EM'Last);

      if (EM_Bits mod 8) /= 0 then
         R := R or (Unsigned_32 (EM (0)) and
                    Unsigned_32 (Shift_Left (Unsigned_8 (16#FF#),
                                             Natural (EM_Bits mod 8))));
      end if;

      --  XLen >= 66 so N32(XLen) - 1 >= 65, and <= EM'Last
      R := R or (Unsigned_32 (EM (N32 (XLen) - 1)) xor 16#BC#);

      --  XLen >= Hash_Len + Salt_Len + 2 = 2*Hash_Len + 2
      --  DB_Len = XLen - Hash_Len - 1 >= Hash_Len + 1 >= 33
      DB_Len   := XLen - Hash_Len - 1;
      Seed_Off := N32 (DB_Len);

      pragma Assert (DB_Len >= 33);
      pragma Assert (DB_Len < XLen);
      pragma Assert (N32 (DB_Len) - 1 <= EM'Last);
      pragma Assert (Seed_Off + N32 (Hash_Len) - 1 <= EM'Last);
      pragma Assert (DB_Len <= Max_RSA_Bytes);

      --  Fix aliasing: copy seed to local buffer before MGF1_XOR
      declare
         Seed_Copy : Byte_Seq (0 .. N32 (Hash_Len) - 1);
      begin
         Seed_Copy := EM (Seed_Off .. Seed_Off + N32 (Hash_Len) - 1);
         MGF1_XOR
           (Alg      => Hash_Alg,
            Hash_Len => Hash_Len,
            Data     => EM (0 .. N32 (DB_Len) - 1),
            Data_Len => DB_Len,
            Seed     => Seed_Copy,
            Seed_Len => Hash_Len);
      end;

      if (EM_Bits mod 8) /= 0 then
         EM (0) := EM (0) and
            Byte (Shift_Right (Unsigned_8 (16#FF#),
                               8 - Natural (EM_Bits mod 8)));
      end if;

      --  Pad_Len = DB_Len - Salt_Len - 1 >= 0
      --  DB_Len >= Hash_Len + 1 = Salt_Len + 1, so Pad_Len >= 0.
      Pad_Len := DB_Len - Salt_Len - 1;

      pragma Assert (Pad_Len < DB_Len);
      pragma Assert (N32 (Pad_Len) <= EM'Last);

      for I in 0 .. Pad_Len - 1 loop
         pragma Loop_Invariant (I <= Pad_Len - 1);
         R := R or Unsigned_32 (EM (N32 (I)));
      end loop;
      R := R or (Unsigned_32 (EM (N32 (Pad_Len))) xor 16#01#);

      Salt_Off := N32 (Pad_Len) + 1;

      --  Salt_Off + Salt_Len - 1 = Pad_Len + 1 + Salt_Len - 1
      --    = Pad_Len + Salt_Len = DB_Len - 1 < XLen <= EM'Last + 1
      pragma Assert (Salt_Off + N32 (Salt_Len) - 1 <= EM'Last);

      declare
         M_Buf_Len : constant N32 := 8 + N32 (Hash_Len) + N32 (Salt_Len);
         M_Buf     : Byte_Seq (0 .. M_Buf_Len - 1);
         H_Out     : Byte_Seq (0 .. N32 (Hash_Len) - 1);
      begin
         M_Buf := (others => 0);
         M_Buf (8 .. 8 + N32 (Hash_Len) - 1) :=
            M_Hash (M_Hash'First .. M_Hash'First + N32 (Hash_Len) - 1);
         for I in 0 .. Salt_Len - 1 loop
            pragma Loop_Invariant (I <= Salt_Len - 1);
            M_Buf (8 + N32 (Hash_Len) + N32 (I)) :=
               EM (Salt_Off + N32 (I));
         end loop;

         Compute_Hash (Hash_Alg, M_Buf, H_Out, Hash_Len);

         for I in 0 .. Hash_Len - 1 loop
            pragma Loop_Invariant (I <= Hash_Len - 1);
            R := R or (Unsigned_32 (H_Out (N32 (I))) xor
                       Unsigned_32 (EM (Seed_Off + N32 (I))));
         end loop;
      end;

      Valid := CT_Eq0 (R) = 1;
   end PSS_Verify;

   ----------------------------------------------------------------------------
   --  Top-level Verify_PSS
   ----------------------------------------------------------------------------

   function Verify_PSS
     (M_Hash    : in Byte_Seq;
      Hash_Len  : in N32;
      Hash_Alg  : in PSS_Hash;
      Modulus   : in Byte_Seq;
      Mod_Len   : in N32;
      Exponent  : in Unsigned_32;
      Signature : in Byte_Seq;
      Sig_Len   : in N32) return Boolean
   is
      X  : Byte_Seq (0 .. N32 (Sig_Len) - 1);
      OK : Boolean;
   begin
      X := Signature (Signature'First .. Signature'First + N32 (Sig_Len) - 1);

      RSA_Public
        (X       => X,
         X_Len   => Natural (Sig_Len),
         Modulus => Modulus,
         Mod_Len => Natural (Mod_Len),
         Exp     => Exponent,
         OK      => OK);

      if not OK then
         return False;
      end if;

      declare
         N_Bitlen : Natural := Natural (Mod_Len) * 8;
         Skip     : Natural := 0;
         PSS_OK   : Boolean;
      begin
         while Skip < Natural (Mod_Len) and then
               Modulus (Modulus'First + N32 (Skip)) = 0
         loop
            pragma Loop_Invariant (Skip < Natural (Mod_Len));
            pragma Loop_Variant (Increases => Skip);
            Skip := Skip + 1;
         end loop;
         if Skip < Natural (Mod_Len) then
            N_Bitlen := (Natural (Mod_Len) - Skip - 1) * 8 +
               Natural (Bit_Length_Word (
                  Unsigned_32 (Modulus (Modulus'First + N32 (Skip)))));
         end if;

         if N_Bitlen < 2 then
            return False;
         end if;

         PSS_Verify
           (EM       => X,
            EM_Len   => Natural (Sig_Len),
            M_Hash   => M_Hash,
            Hash_Len => Natural (Hash_Len),
            Hash_Alg => Hash_Alg,
            N_Bitlen => N_Bitlen,
            Valid    => PSS_OK);

         return PSS_OK;
      end;
   end Verify_PSS;

   ----------------------------------------------------------------------------
   --  Convenience wrappers
   ----------------------------------------------------------------------------

   function Verify_PSS_SHA256
     (Hash      : in Bytes_32;
      Modulus   : in Byte_Seq;
      Mod_Len   : in N32;
      Exponent  : in Unsigned_32;
      Signature : in Byte_Seq;
      Sig_Len   : in N32) return Boolean
   is
   begin
      return Verify_PSS
        (M_Hash    => Byte_Seq (Hash),
         Hash_Len  => 32,
         Hash_Alg  => PSS_SHA256,
         Modulus   => Modulus,
         Mod_Len   => Mod_Len,
         Exponent  => Exponent,
         Signature => Signature,
         Sig_Len   => Sig_Len);
   end Verify_PSS_SHA256;

   function Verify_PSS_SHA384
     (Hash      : in Bytes_48;
      Modulus   : in Byte_Seq;
      Mod_Len   : in N32;
      Exponent  : in Unsigned_32;
      Signature : in Byte_Seq;
      Sig_Len   : in N32) return Boolean
   is
   begin
      return Verify_PSS
        (M_Hash    => Byte_Seq (Hash),
         Hash_Len  => 48,
         Hash_Alg  => PSS_SHA384,
         Modulus   => Modulus,
         Mod_Len   => Mod_Len,
         Exponent  => Exponent,
         Signature => Signature,
         Sig_Len   => Sig_Len);
   end Verify_PSS_SHA384;

   function Verify_PSS_SHA512
     (Hash      : in Bytes_64;
      Modulus   : in Byte_Seq;
      Mod_Len   : in N32;
      Exponent  : in Unsigned_32;
      Signature : in Byte_Seq;
      Sig_Len   : in N32) return Boolean
   is
   begin
      return Verify_PSS
        (M_Hash    => Byte_Seq (Hash),
         Hash_Len  => 64,
         Hash_Alg  => PSS_SHA512,
         Modulus   => Modulus,
         Mod_Len   => Mod_Len,
         Exponent  => Exponent,
         Signature => Signature,
         Sig_Len   => Sig_Len);
   end Verify_PSS_SHA512;

   ----------------------------------------------------------------------------
   --  PKCS#1 v1.5 verify (RFC 8017 §9.2, EMSA-PKCS1-v1_5)
   --
   --  Expected encoded message after RSA_Public:
   --    EM = 0x00 || 0x01 || PS || 0x00 || T
   --  where PS is at least 8 bytes of 0xFF (filler) and
   --        T  = DigestInfo (DER, fixed by hash alg) || mHash.
   ----------------------------------------------------------------------------

   --  DigestInfo DER prefixes for SHA-256 / SHA-384 / SHA-512.
   --  Each is 19 bytes; followed by the hash. Reference: RFC 8017 §9.2,
   --  Notes appendix.
   DI_Len : constant := 19;

   DI_SHA256 : constant Byte_Seq (0 .. DI_Len - 1) :=
     (16#30#, 16#31#, 16#30#, 16#0d#, 16#06#, 16#09#, 16#60#, 16#86#,
      16#48#, 16#01#, 16#65#, 16#03#, 16#04#, 16#02#, 16#01#, 16#05#,
      16#00#, 16#04#, 16#20#);

   DI_SHA384 : constant Byte_Seq (0 .. DI_Len - 1) :=
     (16#30#, 16#41#, 16#30#, 16#0d#, 16#06#, 16#09#, 16#60#, 16#86#,
      16#48#, 16#01#, 16#65#, 16#03#, 16#04#, 16#02#, 16#02#, 16#05#,
      16#00#, 16#04#, 16#30#);

   DI_SHA512 : constant Byte_Seq (0 .. DI_Len - 1) :=
     (16#30#, 16#51#, 16#30#, 16#0d#, 16#06#, 16#09#, 16#60#, 16#86#,
      16#48#, 16#01#, 16#65#, 16#03#, 16#04#, 16#02#, 16#03#, 16#05#,
      16#00#, 16#04#, 16#40#);

   function Verify_PKCS1_v1_5
     (M_Hash    : in Byte_Seq;
      Hash_Len  : in N32;
      Modulus   : in Byte_Seq;
      Mod_Len   : in N32;
      Exponent  : in Unsigned_32;
      Signature : in Byte_Seq;
      Sig_Len   : in N32) return Boolean
   is
      X    : Byte_Seq (0 .. N32 (Sig_Len) - 1);
      OK   : Boolean;
      T_Len : constant N32 := DI_Len + Hash_Len;
      Diff  : Byte := 0;
   begin
      X := Signature (Signature'First .. Signature'First + N32 (Sig_Len) - 1);

      RSA_Public
        (X       => X,
         X_Len   => Natural (Sig_Len),
         Modulus => Modulus,
         Mod_Len => Natural (Mod_Len),
         Exp     => Exponent,
         OK      => OK);

      if not OK then
         return False;
      end if;

      --  Need room for: 0x00 || 0x01 || PS(>=8) || 0x00 || T
      --  i.e. EM_Len >= 11 + T_Len.
      if Mod_Len < 11 + T_Len then
         return False;
      end if;

      --  Constant-time accumulate-on-mismatch over the full encoded
      --  message. Bail-out is replaced by mask-OR so timing is fixed.
      --  EM[0] must be 0x00.
      Diff := Diff or X (0);
      --  EM[1] must be 0x01.
      Diff := Diff or (X (1) xor 16#01#);

      --  PS region: bytes at indices 2 .. Mod_Len - T_Len - 2 must all
      --  be 0xFF. (At least 8 bytes by the length check above.)
      for I in N32 range 2 .. Mod_Len - T_Len - 2 loop
         pragma Loop_Invariant
           (I <= Mod_Len - T_Len - 2 and I >= 2 and Mod_Len <= X'Last + 1);
         Diff := Diff or (X (I) xor 16#FF#);
      end loop;

      --  Separator byte at index Mod_Len - T_Len - 1 must be 0x00.
      Diff := Diff or X (Mod_Len - T_Len - 1);

      --  DigestInfo prefix at indices Mod_Len - T_Len .. Mod_Len - T_Len
      --  + DI_Len - 1, selected by Hash_Len.
      declare
         DI_Start : constant N32 := Mod_Len - T_Len;
      begin
         case Hash_Len is
            when 32 =>
               for I in N32 range 0 .. DI_Len - 1 loop
                  pragma Loop_Invariant
                    (DI_Start + I <= X'Last and Mod_Len <= X'Last + 1);
                  Diff := Diff or (X (DI_Start + I) xor DI_SHA256 (I));
               end loop;
            when 48 =>
               for I in N32 range 0 .. DI_Len - 1 loop
                  pragma Loop_Invariant
                    (DI_Start + I <= X'Last and Mod_Len <= X'Last + 1);
                  Diff := Diff or (X (DI_Start + I) xor DI_SHA384 (I));
               end loop;
            when 64 =>
               for I in N32 range 0 .. DI_Len - 1 loop
                  pragma Loop_Invariant
                    (DI_Start + I <= X'Last and Mod_Len <= X'Last + 1);
                  Diff := Diff or (X (DI_Start + I) xor DI_SHA512 (I));
               end loop;
            when others =>
               return False;
         end case;
      end;

      --  mHash at the tail.
      declare
         Hash_Start : constant N32 := Mod_Len - Hash_Len;
      begin
         for I in N32 range 0 .. Hash_Len - 1 loop
            pragma Loop_Invariant
              (Hash_Start + I <= X'Last and Mod_Len <= X'Last + 1);
            Diff := Diff or (X (Hash_Start + I) xor M_Hash (I));
         end loop;
      end;

      return Diff = 0;
   end Verify_PKCS1_v1_5;

   --  Convenience wrappers

   function Verify_PKCS1_v1_5_SHA256
     (Hash      : in Bytes_32;
      Modulus   : in Byte_Seq;
      Mod_Len   : in N32;
      Exponent  : in Unsigned_32;
      Signature : in Byte_Seq;
      Sig_Len   : in N32) return Boolean
   is
   begin
      return Verify_PKCS1_v1_5
        (M_Hash    => Byte_Seq (Hash),
         Hash_Len  => 32,
         Modulus   => Modulus,
         Mod_Len   => Mod_Len,
         Exponent  => Exponent,
         Signature => Signature,
         Sig_Len   => Sig_Len);
   end Verify_PKCS1_v1_5_SHA256;

   function Verify_PKCS1_v1_5_SHA384
     (Hash      : in Bytes_48;
      Modulus   : in Byte_Seq;
      Mod_Len   : in N32;
      Exponent  : in Unsigned_32;
      Signature : in Byte_Seq;
      Sig_Len   : in N32) return Boolean
   is
   begin
      return Verify_PKCS1_v1_5
        (M_Hash    => Byte_Seq (Hash),
         Hash_Len  => 48,
         Modulus   => Modulus,
         Mod_Len   => Mod_Len,
         Exponent  => Exponent,
         Signature => Signature,
         Sig_Len   => Sig_Len);
   end Verify_PKCS1_v1_5_SHA384;

   function Verify_PKCS1_v1_5_SHA512
     (Hash      : in Bytes_64;
      Modulus   : in Byte_Seq;
      Mod_Len   : in N32;
      Exponent  : in Unsigned_32;
      Signature : in Byte_Seq;
      Sig_Len   : in N32) return Boolean
   is
   begin
      return Verify_PKCS1_v1_5
        (M_Hash    => Byte_Seq (Hash),
         Hash_Len  => 64,
         Modulus   => Modulus,
         Mod_Len   => Mod_Len,
         Exponent  => Exponent,
         Signature => Signature,
         Sig_Len   => Sig_Len);
   end Verify_PKCS1_v1_5_SHA512;

   ----------------------------------------------------------------------------
   --  RSA private key operation: X = X^D mod N
   ----------------------------------------------------------------------------

   procedure RSA_Private
     (X       : in out Byte_Seq;
      X_Len   : in     Natural;
      Modulus : in     Byte_Seq;
      Mod_Len : in     Natural;
      Exp     : in     Byte_Seq;
      Exp_Len : in     Natural;
      OK      :    out Boolean)
   with Pre => X'First = 0 and X'Last < N32'Last
               and Modulus'First = 0 and Modulus'Last < N32'Last
               and Exp'First = 0 and Exp'Last < N32'Last
               and Mod_Len <= Max_RSA_Bytes
               and Exp_Len <= Max_RSA_Bytes
               and (Mod_Len = 0 or else N32 (Mod_Len) - 1 <= Modulus'Last)
               and (X_Len = 0 or else N32 (X_Len) - 1 <= X'Last)
               and (Exp_Len = 0 or else N32 (Exp_Len) - 1 <= Exp'Last)
   is
      use BigNat64;
      M     : Big_Nat;
      A     : Big_Nat;
      M0I   : Word;
   begin
      OK := False;

      if Mod_Len = 0 or else X_Len /= Mod_Len
         or else Exp_Len = 0
         or else Mod_Len > Max_RSA_Bytes
      then
         return;
      end if;

      declare
         Mod_Buf : Byte_Seq (0 .. N32 (Mod_Len) - 1);
         X_Buf   : Byte_Seq (0 .. N32 (X_Len) - 1);
         E_Buf   : Byte_Seq (0 .. N32 (Exp_Len) - 1);
      begin
         Mod_Buf := Modulus (0 .. N32 (Mod_Len) - 1);
         X_Buf   := X (0 .. N32 (X_Len) - 1);
         E_Buf   := Exp (0 .. N32 (Exp_Len) - 1);

         Decode (M, Mod_Buf);

         if M.Len = 0 or else (M.W (0) and 1) = 0 then
            return;
         end if;

         M0I := Ninv (M.W (0));

         Decode (A, X_Buf);

         if A.Len < M.Len then
            A.Len := M.Len;
         elsif A.Len > M.Len then
            return;
         end if;

         declare
            Result : Big_Nat;
         begin
            Modpow (Result, A, E_Buf, M, M0I);
            Encode (X_Buf, Result);
         end;

         X (0 .. N32 (X_Len) - 1) := X_Buf;
      end;

      OK := True;
   end RSA_Private;

   ----------------------------------------------------------------------------
   --  PSS Encode (RFC 8017 Section 9.1.1)
   ----------------------------------------------------------------------------

   procedure PSS_Encode
     (EM       :    out Byte_Seq;
      EM_Len   : in     Natural;
      M_Hash   : in     Byte_Seq;
      Hash_Len : in     Natural;
      Hash_Alg : in     PSS_Hash;
      Salt     : in     Byte_Seq;
      N_Bitlen : in     Natural;
      OK       :    out Boolean)
   with Pre => N_Bitlen >= 2 and N_Bitlen <= Max_RSA_Bits
               and Hash_Len in 32 | 48 | 64
               and EM'First = 0
               and EM'Last < Max_RSA_Bytes
               and EM_Len > 0 and N32 (EM_Len) - 1 <= EM'Last
               and M_Hash'First = 0
               and N32 (Hash_Len) - 1 <= M_Hash'Last
               and Salt'First = 0
               and N32 (Hash_Len) - 1 <= Salt'Last
   is
      Salt_Len  : constant Natural := Hash_Len;
      EM_Bits   : constant Natural := N_Bitlen - 1;
      XLen      : constant Natural := (EM_Bits + 7) / 8;
      DB_Len    : Natural;
      Pad_Len   : Natural;
   begin
      EM := (others => 0);
      OK := False;

      if XLen < Hash_Len + Salt_Len + 2 then
         return;
      end if;

      if XLen > EM_Len or else N32 (XLen) > EM'Last + 1 then
         return;
      end if;

      DB_Len  := XLen - Hash_Len - 1;
      Pad_Len := DB_Len - Salt_Len - 1;

      --  Compute H = Hash(0x00^8 || M_Hash || Salt)
      declare
         M_Buf_Len : constant N32 := 8 + N32 (Hash_Len) + N32 (Salt_Len);
         M_Buf     : Byte_Seq (0 .. M_Buf_Len - 1) := (others => 0);
         H         : Byte_Seq (0 .. N32 (Hash_Len) - 1);
      begin
         --  M_Buf(0..7) = 0x00 (already zeroed)
         M_Buf (8 .. 8 + N32 (Hash_Len) - 1) :=
            M_Hash (0 .. N32 (Hash_Len) - 1);
         for I in 0 .. Salt_Len - 1 loop
            M_Buf (8 + N32 (Hash_Len) + N32 (I)) := Salt (N32 (I));
         end loop;

         Compute_Hash (Hash_Alg, M_Buf, H, Hash_Len);

         --  Build DB = 0x00^Pad_Len || 0x01 || Salt
         --  (EM is already zeroed, so padding is in place)
         EM (N32 (Pad_Len)) := 16#01#;
         for I in 0 .. Salt_Len - 1 loop
            EM (N32 (Pad_Len) + 1 + N32 (I)) := Salt (N32 (I));
         end loop;

         --  maskedDB = DB XOR MGF1(H)
         declare
            H_Copy : Byte_Seq (0 .. N32 (Hash_Len) - 1) := H;
         begin
            MGF1_XOR
              (Alg      => Hash_Alg,
               Hash_Len => Hash_Len,
               Data     => EM (0 .. N32 (DB_Len) - 1),
               Data_Len => DB_Len,
               Seed     => H_Copy,
               Seed_Len => Hash_Len);
         end;

         --  Clear top bits per emBits
         if (EM_Bits mod 8) /= 0 then
            EM (0) := EM (0) and
               Byte (Shift_Right (Unsigned_8 (16#FF#),
                                   8 - Natural (EM_Bits mod 8)));
         end if;

         --  EM = maskedDB || H || 0xBC
         EM (N32 (DB_Len) .. N32 (DB_Len) + N32 (Hash_Len) - 1) := H;
         EM (N32 (XLen) - 1) := 16#BC#;
      end;

      OK := True;
   end PSS_Encode;

   ----------------------------------------------------------------------------
   --  Sign_PSS
   ----------------------------------------------------------------------------

   ----------------------------------------------------------------------------
   --  CRT private-key operation (RFC 8017 §5.1.2 (b)):
   --    m1 = x^dP mod p,  m2 = x^dQ mod q,
   --    h  = qInv * (m1 - m2) mod p,  m = m2 + h * q.
   --  Two exponentiations on half-size moduli. Every step is constant
   --  time in the secret values; the exponents are the windowed CT
   --  Modpow, the reductions are Montgomery products.
   ----------------------------------------------------------------------------

   procedure RSA_Private_CRT
     (X       : in out Byte_Seq;
      X_Len   : in     Natural;
      Modulus : in     Byte_Seq;
      Mod_Len : in     Natural;
      CRT     : in     CRT_Params;
      OK      :    out Boolean)
   with Pre => X'First = 0 and X'Last < N32'Last
               and Modulus'First = 0 and Modulus'Last < N32'Last
               and Mod_Len > 0 and Mod_Len <= Max_RSA_Bytes
               and X_Len = Mod_Len
               and N32 (Mod_Len) - 1 <= Modulus'Last
               and N32 (X_Len) - 1 <= X'Last
               and CRT.Prime_Len > 0
               and 2 * Natural (CRT.Prime_Len) = Mod_Len
   is
      use BigNat64;
      PL  : constant N32 := CRT.Prime_Len;
      M   : Big_Nat;   --  n
      P   : Big_Nat;
      Q   : Big_Nat;
      QI  : Big_Nat;   --  qInv
      XN  : Big_Nat;   --  x (< n)
      XP  : Big_Nat;   --  x mod p
      XQ  : Big_Nat;   --  x mod q
      MP  : Big_Nat;   --  m1
      MQ  : Big_Nat;   --  m2
      MQP : Big_Nat;   --  m2 mod p
      T   : Big_Nat;   --  m1 - m2 mod p
      QIM : Big_Nat;   --  qInv in Montgomery form (mod p)
      H   : Big_Nat;
      R2P : Big_Nat;
      R2Q : Big_Nat;
      Res : Big_Nat;
      P0I : Word;
      Q0I : Word;
   begin
      OK := False;

      --  No key-shape checks here on purpose. Parity and top-bit tests
      --  on p and q would be branches on key material (and GCC compiles
      --  a top-bit test into a sign test that taint tracking sees as
      --  depending on the whole limb). A malformed key -- even prime,
      --  short prime, unbalanced sizes -- simply yields a wrong CRT
      --  result, which the verify-after-sign check below catches, and
      --  the plain exponent is used instead. Nothing on this path can
      --  fault for such a key: R2_Mod / Ninv / Modpow_Top are proved free
      --  of runtime errors for any modulus.

      Decode (M,  Modulus (0 .. N32 (Mod_Len) - 1));
      Decode (P,  CRT.P (0 .. PL - 1));
      Decode (Q,  CRT.Q (0 .. PL - 1));
      Decode (QI, CRT.QInv (0 .. PL - 1));
      Decode (XN, X (0 .. N32 (X_Len) - 1));

      --  Size checks only (all on public lengths): balanced primes and a
      --  modulus of exactly twice their size.
      if P.Len = 0
        or else Q.Len /= P.Len
        or else QI.Len /= P.Len
        or else 2 * P.Len /= M.Len
        or else XN.Len /= M.Len
      then
         return;
      end if;

      P0I := Ninv (P.W (0));
      Q0I := Ninv (Q.W (0));
      R2_Mod (R2P, P, P0I);
      R2_Mod (R2Q, Q, Q0I);

      --  x mod p, x mod q
      Mod_Reduce (XP, XN, P, P0I, R2P);
      Mod_Reduce (XQ, XN, Q, Q0I, R2Q);

      --  m1 = (x mod p)^dP mod p ; m2 = (x mod q)^dQ mod q
      Modpow_Top (MP, XP, CRT.DP (0 .. PL - 1), P, P0I);
      Modpow_Top (MQ, XQ, CRT.DQ (0 .. PL - 1), Q, Q0I);

      --  h = qInv * (m1 - m2) mod p. m2 < q may exceed p, so reduce it
      --  first; then a single borrow-corrected subtraction suffices.
      Mod_Reduce (MQP, MQ, P, P0I, R2P);
      Sub_Mod (T, MP, MQP, P);
      Monty_Mul (QIM, QI, R2P, P, P0I);   --  qInv * R mod p
      Monty_Mul (H, T, QIM, P, P0I);      --  (t * qInv * R) / R = t * qInv

      --  m = m2 + h * q  (< p * q = n, so it fits Mod_Len bytes)
      Mul_Add (Res, H, Q, MQ);
      Encode (X (0 .. N32 (X_Len) - 1), Res);
      OK := True;
   end RSA_Private_CRT;

   --  X := X^d mod n. Uses the CRT path when Pub_Exp and CRT allow it
   --  and the result verifies under e; otherwise (no CRT, odd shapes,
   --  or a verification mismatch) restores X and runs the plain path.
   --  The verify-after-sign compares public values only.
   procedure RSA_Private_Fast
     (X       : in out Byte_Seq;
      X_Len   : in     Natural;
      Modulus : in     Byte_Seq;
      Mod_Len : in     Natural;
      Exp     : in     Byte_Seq;
      Exp_Len : in     Natural;
      Pub_Exp : in     Unsigned_32;
      CRT     : in     CRT_Params;
      OK      :    out Boolean)
   with Pre => X'First = 0 and X'Last < N32'Last
               and Modulus'First = 0 and Modulus'Last < N32'Last
               and Exp'First = 0 and Exp'Last < N32'Last
               and Mod_Len <= Max_RSA_Bytes
               and Exp_Len <= Max_RSA_Bytes
               and (Mod_Len = 0 or else N32 (Mod_Len) - 1 <= Modulus'Last)
               and (X_Len = 0 or else N32 (X_Len) - 1 <= X'Last)
               and (Exp_Len = 0 or else N32 (Exp_Len) - 1 <= Exp'Last)
   is
   begin
      if CRT.Valid
        and then Pub_Exp > 0
        and then Mod_Len > 0
        and then X_Len = Mod_Len
        and then CRT.Prime_Len > 0
        and then 2 * Natural (CRT.Prime_Len) = Mod_Len
      then
         declare
            Saved  : constant Byte_Seq (0 .. N32 (X_Len) - 1) :=
              X (0 .. N32 (X_Len) - 1);
            CRT_OK : Boolean;
         begin
            RSA_Private_CRT (X, X_Len, Modulus, Mod_Len, CRT, CRT_OK);
            if CRT_OK then
               declare
                  Y      : Byte_Seq (0 .. N32 (X_Len) - 1) :=
                    X (0 .. N32 (X_Len) - 1);
                  Pub_OK : Boolean;
               begin
                  RSA_Public (Y, X_Len, Modulus, Mod_Len, Pub_Exp, Pub_OK);
                  --  Constant-time equality: both operands are public
                  --  (the signature and the padded message), but the
                  --  compare runs on the signing path, so no early exit.
                  declare
                     Diff : Byte_Seq (0 .. 0) := (0 => 0);
                  begin
                     for I in Y'Range loop
                        Diff (0) := Diff (0) or (Y (I) xor Saved (I));
                     end loop;
                     --  This is the one decision on this path that a taint
                     --  tracker reports: the bit "did the CRT result
                     --  verify" is public by construction (success => the
                     --  signature goes out; failure => the caller observes
                     --  the plain path), but its operands derive from the
                     --  key. Left as it is, and classified in the ctgrind
                     --  lane, rather than hidden from the tool.
                     if Pub_OK and then Diff (0) = 0 then
                        OK := True;
                        return;
                     end if;
                  end;
               end;
            end if;
            X (0 .. N32 (X_Len) - 1) := Saved;
         end;
      end if;
      RSA_Private (X, X_Len, Modulus, Mod_Len, Exp, Exp_Len, OK);
   end RSA_Private_Fast;

   procedure Sign_PSS
     (M_Hash    : in     Byte_Seq;
      Hash_Len  : in     N32;
      Hash_Alg  : in     PSS_Hash;
      Modulus   : in     Byte_Seq;
      Mod_Len   : in     N32;
      Priv_Exp  : in     Byte_Seq;
      Salt      : in     Byte_Seq;
      Signature :    out Byte_Seq;
      Sig_Len   :    out N32;
      OK        :    out Boolean;
      Pub_Exp   : in     Unsigned_32 := 0;
      CRT       : in     CRT_Params  := No_CRT)
   is
      EM : Byte_Seq (0 .. N32 (Mod_Len) - 1);
   begin
      Signature := (others => 0);
      Sig_Len := 0;
      OK := False;

      --  Compute N_Bitlen from modulus
      declare
         N_Bitlen : Natural := Natural (Mod_Len) * 8;
         Skip     : Natural := 0;
         Enc_OK   : Boolean;
      begin
         while Skip < Natural (Mod_Len) and then
               Modulus (N32 (Skip)) = 0
         loop
            pragma Loop_Invariant (Skip < Natural (Mod_Len));
            pragma Loop_Variant (Increases => Skip);
            Skip := Skip + 1;
         end loop;
         if Skip < Natural (Mod_Len) then
            N_Bitlen := (Natural (Mod_Len) - Skip - 1) * 8 +
               Natural (Bit_Length_Word (
                  Unsigned_32 (Modulus (N32 (Skip)))));
         end if;

         if N_Bitlen < 2 then
            return;
         end if;

         --  PSS encode
         PSS_Encode
           (EM       => EM,
            EM_Len   => Natural (Mod_Len),
            M_Hash   => M_Hash,
            Hash_Len => Natural (Hash_Len),
            Hash_Alg => Hash_Alg,
            Salt     => Salt,
            N_Bitlen => N_Bitlen,
            OK       => Enc_OK);

         if not Enc_OK then
            return;
         end if;
      end;

      --  RSA private key operation: EM^d mod n
      declare
         Priv_OK : Boolean;
      begin
         RSA_Private_Fast
           (X       => EM,
            X_Len   => Natural (Mod_Len),
            Modulus => Modulus,
            Mod_Len => Natural (Mod_Len),
            Exp     => Priv_Exp,
            Exp_Len => Natural (Mod_Len),
            Pub_Exp => Pub_Exp,
            CRT     => CRT,
            OK      => Priv_OK);

         if not Priv_OK then
            return;
         end if;
      end;

      Signature (0 .. N32 (Mod_Len) - 1) := EM;
      Sig_Len := Mod_Len;
      OK := True;
   end Sign_PSS;

   ----------------------------------------------------------------------------
   --  Sign_PKCS1_v1_5 (RFC 8017 §8.2.1 + §9.2 EMSA-PKCS1-v1_5)
   --
   --  EM = 0x00 || 0x01 || PS || 0x00 || T
   --    where PS is at least 8 bytes of 0xFF and
   --          T  = DigestInfo (DI_SHA{256,384,512}) || mHash.
   ----------------------------------------------------------------------------
   procedure Sign_PKCS1_v1_5
     (M_Hash    : in     Byte_Seq;
      Hash_Len  : in     N32;
      Modulus   : in     Byte_Seq;
      Mod_Len   : in     N32;
      Priv_Exp  : in     Byte_Seq;
      Signature :    out Byte_Seq;
      Sig_Len   :    out N32;
      OK        :    out Boolean;
      Pub_Exp   : in     Unsigned_32 := 0;
      CRT       : in     CRT_Params  := No_CRT)
   is
      EM    : Byte_Seq (0 .. N32 (Mod_Len) - 1);
      T_Len : constant N32 := DI_Len + Hash_Len;
   begin
      Signature := (others => 0);
      Sig_Len := 0;
      OK := False;

      --  Need room for: 0x00 || 0x01 || PS(>=8) || 0x00 || T
      if Mod_Len < 11 + T_Len then
         return;
      end if;

      EM := (others => 16#FF#);
      EM (0) := 16#00#;
      EM (1) := 16#01#;
      --  Separator before T
      EM (Mod_Len - T_Len - 1) := 16#00#;
      --  DigestInfo
      case Hash_Len is
         when 32 =>
            EM (Mod_Len - T_Len .. Mod_Len - T_Len + DI_Len - 1) :=
               DI_SHA256;
         when 48 =>
            EM (Mod_Len - T_Len .. Mod_Len - T_Len + DI_Len - 1) :=
               DI_SHA384;
         when 64 =>
            EM (Mod_Len - T_Len .. Mod_Len - T_Len + DI_Len - 1) :=
               DI_SHA512;
         when others =>
            return;
      end case;
      --  mHash
      EM (Mod_Len - Hash_Len .. Mod_Len - 1) :=
         M_Hash (M_Hash'First .. M_Hash'First + Hash_Len - 1);

      declare
         Priv_OK : Boolean;
      begin
         RSA_Private_Fast
           (X       => EM,
            X_Len   => Natural (Mod_Len),
            Modulus => Modulus,
            Mod_Len => Natural (Mod_Len),
            Exp     => Priv_Exp,
            Exp_Len => Natural (Mod_Len),
            Pub_Exp => Pub_Exp,
            CRT     => CRT,
            OK      => Priv_OK);

         if not Priv_OK then
            return;
         end if;
      end;

      Signature (0 .. N32 (Mod_Len) - 1) := EM;
      Sig_Len := Mod_Len;
      OK := True;
   end Sign_PKCS1_v1_5;

end SPARKTLSCrypto.RSA;
