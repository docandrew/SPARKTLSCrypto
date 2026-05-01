--  ChaCha20-Poly1305 AEAD body. See spec.

with SPARKNaCl.Stream;
with SPARKNaCl.MAC;
with SPARKNaCl.Core;
with SPARKTLSCrypto.Poly1305;
with SPARKTLSCrypto.Poly1305_AVX512;
with SPARKTLSCrypto.ChaCha20_AVX512;

package body SPARKTLSCrypto.ChaCha20_Poly1305 with
   SPARK_Mode => On
is

   --  Replicates the private Gen_Auth_Msg in SPARKNaCl.Secretbox:
   --  builds (AAD || pad16 || C || pad16 || AAD_len_le64 || C_len_le64)
   --  per RFC 8439 §2.8.1.
   function Gen_Auth_Msg (C   : in Byte_Seq;
                          AAD : in Byte_Seq) return Byte_Seq
     with Pre => AAD'First = 0
                 and then C'First = 0
                 and then AAD'Last < N32'Last
                 and then C'Last   < N32'Last
                 --  Total = AAD + AAD_pad + C + C_pad + 16 ≤ AAD+C+46.
                 --  Result'Last = Total - 1, and downstream
                 --  Poly1305.Onetimeauth requires M'Last ≤ N32'Last-16.
                 --  Bound at +62 (= 46+16) so Total-1 ≤ N32'Last-16.
                 and then I64 (C'Length) + I64 (AAD'Length) + 62
                            <= I64 (N32'Last),
          Post => Gen_Auth_Msg'Result'First = 0
                  and then Gen_Auth_Msg'Result'Length > 0
                  and then Gen_Auth_Msg'Result'Last <= N32'Last - 16;

   function Gen_Auth_Msg (C   : in Byte_Seq;
                          AAD : in Byte_Seq) return Byte_Seq
   is
      function LE64 (U : in U64) return Bytes_8 is
         X : Bytes_8;
         T : U64 := U;
      begin
         for I in X'Range loop
            X (I) := Byte (T mod 256);
            T := T / 256;
         end loop;
         return X;
      end LE64;

      --  Length of a 16-byte-aligning pad (0..15 bytes). The Post
      --  exposes the upper bound so SPARK can carry it into Total.
      function Pad_Len (L : in N32) return N32
        with Post => Pad_Len'Result < 16;

      function Pad_Len (L : in N32) return N32 is
         R : constant N32 := L mod 16;
      begin
         if R = 0 then return 0; else return 16 - R; end if;
      end Pad_Len;

      AAD_Pad : constant N32 := Pad_Len (AAD'Length);
      C_Pad   : constant N32 := Pad_Len (C'Length);
      --  Compute via I64 to bypass SPARK's N32 overflow check; the
      --  Pre on this function bounds the sum to fit N32.
      Total   : constant N32 :=
         N32 (I64 (AAD'Length) + I64 (AAD_Pad)
              + I64 (C'Length) + I64 (C_Pad) + 16);
      Result : Byte_Seq (0 .. Total - 1) := (others => 0);
      Pos    : N32 := 0;
      Lengths : Bytes_16 := (others => 0);
   begin
      --  AAD
      if AAD'Length > 0 then
         Result (Pos .. Pos + AAD'Length - 1) := AAD;
      end if;
      Pos := Pos + AAD'Length + AAD_Pad;  -- skip the zero padding

      --  Ciphertext
      if C'Length > 0 then
         Result (Pos .. Pos + C'Length - 1) := C;
      end if;
      Pos := Pos + C'Length + C_Pad;

      --  Lengths block: AAD_len_le64 || C_len_le64
      Lengths (0 .. 7)  := LE64 (U64 (AAD'Length));
      Lengths (8 .. 15) := LE64 (U64 (C'Length));
      Result (Pos .. Pos + 15) := Lengths;

      return Result;
   end Gen_Auth_Msg;

   procedure Encrypt
     (C   :    out Byte_Seq;
      Tag :    out Bytes_16;
      M   : in     Byte_Seq;
      N   : in     Core.ChaCha20_IETF_Nonce;
      K   : in     Core.ChaCha20_Key;
      AAD : in     Byte_Seq)
   is
      OTK_Bytes : Bytes_32;
      OTK       : SPARKNaCl.MAC.Poly_1305_Key;
   begin
      --  Step 1: Generate the Poly1305 one-time key from ChaCha20 with
      --  counter 0 (RFC 8439 §2.6).
      SPARKNaCl.Stream.ChaCha20_IETF (OTK_Bytes, N, K, 0);
      SPARKNaCl.MAC.Construct (OTK, OTK_Bytes);

      --  Step 2: Encrypt with ChaCha20 starting at counter 1.
      --  AVX-512 fast path processes the body in 1024-byte stripes
      --  (16 parallel ChaCha20 streams via zmm). Falls back to scalar
      --  for any sub-1024 tail and on CPUs without AVX-512F.
      if SPARKTLSCrypto.ChaCha20_AVX512.Has_AVX512_ChaCha20
         and then M'Length >= 1024
      then
         declare
            --  Copy plaintext into C; AVX-512 path encrypts in place.
            Pos       : N32 := 0;
            Counter   : Unsigned_32 := 1;
            Total     : constant N32 := N32 (M'Length);
            Bulk_Last : constant N32 := (Total / 1024) * 1024;
            Key_Bytes : constant Bytes_32 := SPARKNaCl.Core.Serialize (K);
            Nonce_Bytes : constant Bytes_12 := Bytes_12 (N);
         begin
            --  Stage the message into C, then encrypt in place.
            C := M;
            while Pos < Bulk_Last loop
               --  Loop invariant: Pos is always a 1024-byte multiple
               --  in [0, Bulk_Last) and Bulk_Last <= C'Length, so the
               --  slice C (Pos .. Pos + 1023) is always in range.
               pragma Loop_Invariant
                 (Pos >= 0
                  and Pos < Bulk_Last
                  and Pos mod 1024 = 0
                  and Bulk_Last <= Total
                  and Pos + 1023 <= C'Last);
               SPARKTLSCrypto.ChaCha20_AVX512.Encrypt_1024_InPlace
                 (Buf     => C (Pos .. Pos + 1023),
                  K       => Key_Bytes,
                  N       => Nonce_Bytes,
                  Counter => Counter);
               Pos := Pos + 1024;
               Counter := Counter + 16;
            end loop;
            --  Tail (< 1024 bytes): scalar path for the remainder.
            --  Hoist Tail_Len into a constant — SPARK requires subtype
            --  constraints to come from constants, not variable inputs
            --  (RM E0007).
            if Pos < Total then
               declare
                  Tail_Len    : constant N32 := Total - Pos;
                  Tail_Plain  : Byte_Seq (0 .. Tail_Len - 1) :=
                                   M (Pos .. Total - 1);
                  Tail_Cipher : Byte_Seq (0 .. Tail_Len - 1);
               begin
                  SPARKNaCl.Stream.ChaCha20_IETF_Xor
                    (C => Tail_Cipher, M => Tail_Plain,
                     N => N, K => K, Counter => Counter);
                  C (Pos .. Total - 1) := Tail_Cipher;
               end;
            end if;
         end;
      else
         SPARKNaCl.Stream.ChaCha20_IETF_Xor
           (C => C, M => M, N => N, K => K, Counter => 1);
      end if;

      --  Step 3: Poly1305 tag over (AAD || pad || C || pad || lengths).
      --  Dispatch tier: AVX-512 IFMA path (when available, currently
      --  forwards to fast scalar pending SIMD body) → fast scalar
      --  (radix-2²⁶ limbs).
      declare
         Auth_Msg : constant Byte_Seq := Gen_Auth_Msg (C, AAD);
      begin
         if SPARKTLSCrypto.Poly1305_AVX512.Has_AVX512_Poly1305 then
            SPARKTLSCrypto.Poly1305_AVX512.Onetimeauth
              (Tag, Auth_Msg, OTK);
         else
            SPARKTLSCrypto.Poly1305.Onetimeauth (Tag, Auth_Msg, OTK);
         end if;
      end;
   end Encrypt;

end SPARKTLSCrypto.ChaCha20_Poly1305;
