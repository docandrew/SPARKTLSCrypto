--  ChaCha20-Poly1305 AEAD body. See spec.

with SPARKNaCl.Stream;
with SPARKNaCl.MAC;
with SPARKNaCl.Core;
with SPARKTLSCrypto.Poly1305;
with SPARKTLSCrypto.Poly1305_AVX512;
with SPARKTLSCrypto.Poly1305_AVX512_IFMA;
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

   procedure Encrypt_InPlace
     (Buf : in out Byte_Seq;
      Tag :    out Bytes_16;
      N   : in     Core.ChaCha20_IETF_Nonce;
      K   : in     Core.ChaCha20_Key;
      AAD : in     Byte_Seq)
   is
      OTK_Bytes : Bytes_32;
      OTK       : SPARKNaCl.MAC.Poly_1305_Key;
   begin
      --  RFC 8439 2.6: the one-time Poly1305 key is the first 32 bytes of the
      --  ChaCha20 keystream at counter 0.
      SPARKNaCl.Stream.ChaCha20_IETF (OTK_Bytes, N, K, 0);
      SPARKNaCl.MAC.Construct (OTK, OTK_Bytes);

      --  Keystream XOR, in place. AVX-512 path: whole 1 KB blocks through the
      --  vector core, the tail through the scalar stream via a small
      --  temporary. Scalar path: the stream routine needs distinct source and
      --  destination, so it reads a copy (that path is the slow one anyway).
      if SPARKTLSCrypto.ChaCha20_AVX512.Has_AVX512_ChaCha20
         and then Buf'Length >= 1024
      then
         declare
            Pos         : N32 := 0;
            Counter     : Unsigned_32 := 1;
            Total       : constant N32 := N32 (Buf'Length);
            Bulk_Last   : constant N32 := (Total / 1024) * 1024;
            Key_Bytes   : constant Bytes_32 := SPARKNaCl.Core.Serialize (K);
            Nonce_Bytes : constant Bytes_12 := Bytes_12 (N);
         begin
            while Pos < Bulk_Last loop
               pragma Loop_Invariant
                 (Pos >= 0
                  and Pos < Bulk_Last
                  and Pos mod 1024 = 0
                  and Bulk_Last <= Total
                  and Pos + 1023 <= Buf'Last);
               SPARKTLSCrypto.ChaCha20_AVX512.Encrypt_1024_InPlace
                 (Buf     => Buf (Pos .. Pos + 1023),
                  K       => Key_Bytes,
                  N       => Nonce_Bytes,
                  Counter => Counter);
               Pos := Pos + 1024;
               Counter := Counter + 16;
            end loop;

            if Pos < Total then
               declare
                  Tail_Len    : constant N32 := Total - Pos;
                  Tail_Plain  : constant Byte_Seq (0 .. Tail_Len - 1) :=
                                   Buf (Pos .. Total - 1);
                  Tail_Cipher : Byte_Seq (0 .. Tail_Len - 1);
               begin
                  SPARKNaCl.Stream.ChaCha20_IETF_Xor
                    (C => Tail_Cipher, M => Tail_Plain,
                     N => N, K => K, Counter => Counter);
                  Buf (Pos .. Total - 1) := Tail_Cipher;
               end;
            end if;
         end;
      else
         declare
            Plain : constant Byte_Seq := Buf;
         begin
            SPARKNaCl.Stream.ChaCha20_IETF_Xor
              (C => Buf, M => Plain, N => N, K => K, Counter => 1);
         end;
      end if;

      --  RFC 8439 2.8: Poly1305 over pad16(AAD) || pad16(C) || len(AAD) || len(C).
      declare
         Auth_Msg : constant Byte_Seq := Gen_Auth_Msg (Buf, AAD);
      begin
         if SPARKTLSCrypto.Poly1305_AVX512_IFMA.Has_AVX512_IFMA_Poly1305 then
            SPARKTLSCrypto.Poly1305_AVX512_IFMA.Onetimeauth
              (Tag, Auth_Msg, OTK);
         elsif SPARKTLSCrypto.Poly1305_AVX512.Has_AVX512_Poly1305 then
            SPARKTLSCrypto.Poly1305_AVX512.Onetimeauth
              (Tag, Auth_Msg, OTK);
         else
            SPARKTLSCrypto.Poly1305.Onetimeauth (Tag, Auth_Msg, OTK);
         end if;
      end;
   end Encrypt_InPlace;

   procedure Encrypt
     (C   :    out Byte_Seq;
      Tag :    out Bytes_16;
      M   : in     Byte_Seq;
      N   : in     Core.ChaCha20_IETF_Nonce;
      K   : in     Core.ChaCha20_Key;
      AAD : in     Byte_Seq)
   is
   begin
      C := M;
      Encrypt_InPlace (Buf => C, Tag => Tag, N => N, K => K, AAD => AAD);
   end Encrypt;

end SPARKTLSCrypto.ChaCha20_Poly1305;
