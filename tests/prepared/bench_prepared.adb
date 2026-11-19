with Ada.Text_IO; use Ada.Text_IO;
with Ada.Real_Time; use Ada.Real_Time;
with Ada.Command_Line;
with Interfaces; use Interfaces;
with Interfaces.C;
with System;
with SPARKNaCl; use SPARKNaCl;
with SPARKNaCl.AES;
with SPARKTLSCrypto.AES_NI;
with SPARKTLSCrypto.GHASH_NI;
with SPARKTLSCrypto.AES_GCM_AVX512;
with SPARKTLSCrypto.AES_GCM; use SPARKTLSCrypto.AES_GCM;

--  Two sections, both printed as CSV (sample zero is warmup):
--
--  prepared  one-shot vs cached encryption (the original benchmark);
--  aead      SPARKTLSCrypto encrypt and decrypt against OpenSSL EVP with a
--            cached key schedule, AES-128/256-GCM at 64 B, 1 KiB and 16 KiB
--            (one TLS record), followed by a median / IQR / range summary
--            per implementation.
--
--  With no argument both sections run; "prepared" or "aead" runs one.
procedure Bench_Prepared is
   K128 : constant AES.AES128_Key := AES.Construct (Bytes_16'(others => 42));
   K256 : constant AES.AES256_Key := AES.Construct (Bytes_32'(others => 42));
   Raw_Key : constant Bytes_32 := (others => 42);
   Context : Prepared_Key;
   AAD : constant Byte_Seq (0 .. 4) := (16#17#, 3, 3, 64, 17);
   Tag : Bytes_16;
   Sink : Byte := 0;

   ----------------------------------------------------------------------------
   --  Section 1: one-shot vs prepared encryption
   ----------------------------------------------------------------------------

   procedure Run (Len : N32; Bits, Sample : Natural; Cached : Boolean) is
      Buf : Byte_Seq (0 .. Len - 1) := (others => 42);
      Nonce : Bytes_12 := (others => 0);
      Start : Time;
      Elapsed : Duration;
      Count : constant Positive := (if Len > 1024 then 30_000 else 100_000);
   begin
      Start := Clock;
      for J in 1 .. Count loop
         Nonce (0) := Byte (J mod 256);
         Nonce (1) := Byte ((J / 256) mod 256);
         Nonce (2) := Byte (J / 65536);
         if Cached then Encrypt_Prepared (Buf, Tag, Nonce, Context, AAD);
         elsif Bits = 128 then Encrypt_InPlace (Buf, Tag, Nonce, K128, AAD);
         else Encrypt_InPlace_256 (Buf, Tag, Nonce, K256, AAD);
         end if;
         Sink := Sink xor Tag (0);
      end loop;
      Elapsed := To_Duration (Clock - Start);
      Put_Line (Sample'Image & "," & Bits'Image & "," & Len'Image & "," &
                Cached'Image & "," & Long_Float'Image
                  (Long_Float (Elapsed) * 1.0E9 / Long_Float (Count)));
   end Run;

   procedure Prepared_Section is
   begin
      Put_Line ("sample,bits,length,prepared,ns_per_record");
      for Bits in 1 .. 2 loop
         if Bits = 1 then Prepare_128 (Context, K128);
         else Prepare_256 (Context, K256); end if;
         for Len of Byte_Seq'(1, 4, 16, 64) loop
            for Sample in 0 .. 20 loop
               Run (N32 (Len) * 256 + 1, Bits * 128, Sample, Sample mod 2 = 0);
               Run (N32 (Len) * 256 + 1, Bits * 128, Sample, Sample mod 2 /= 0);
            end loop;
         end loop;
      end loop;
   end Prepared_Section;

   ----------------------------------------------------------------------------
   --  Section 2: encrypt and decrypt against OpenSSL EVP
   ----------------------------------------------------------------------------

   use type Interfaces.C.int;
   use type System.Address;

   function OSSL_New (Key : System.Address; Bits, Decrypt : Interfaces.C.int)
     return System.Address
     with Import, Convention => C, External_Name => "openssl_gcm_bench_new";
   procedure OSSL_Free (Ctx : System.Address)
     with Import, Convention => C, External_Name => "openssl_gcm_bench_free";
   function OSSL_Seal (Ctx, IV, AAD : System.Address;
                       AAD_Len : Interfaces.C.int;
                       Buf : System.Address; Len : Interfaces.C.int;
                       Tag : System.Address) return Interfaces.C.int
     with Import, Convention => C, External_Name => "openssl_gcm_bench_seal";
   function OSSL_Open (Ctx, IV, AAD : System.Address;
                       AAD_Len : Interfaces.C.int;
                       Input, Output : System.Address; Len : Interfaces.C.int;
                       Tag : System.Address) return Interfaces.C.int
     with Import, Convention => C, External_Name => "openssl_gcm_bench_open";

   --  Each row is one implementation. Decrypt rows always decrypt an
   --  authentic record, so they time the success path that TLS takes on
   --  every legitimate record.
   type Impl is
     (STC_Encrypt_Prepared,  --  in place, prepared context
      STC_Decrypt,           --  one-shot Decrypt / Decrypt_256, C -> M
      OSSL_Encrypt,          --  EVP, in place, key set once
      OSSL_Decrypt);         --  EVP, C -> M, key set once

   Impl_Name : constant array (Impl) of access constant String :=
     (STC_Encrypt_Prepared => new String'("stc.encrypt_prepared"),
      STC_Decrypt          => new String'("stc.decrypt"),
      OSSL_Encrypt         => new String'("openssl.encrypt"),
      OSSL_Decrypt         => new String'("openssl.decrypt"));

   Impl_Count : constant := Impl'Pos (Impl'Last) + 1;

   Lengths : constant array (1 .. 3) of N32 := (64, 1024, 16_384);
   Retained : constant := 20;
   type Sample_Array is array (1 .. Retained) of Long_Float;
   type Result_Table is array (Impl, Lengths'Range) of Sample_Array;

   --  Iterations per sample: about 16 MiB of payload, at least 20_000
   --  records, so every sample runs for milliseconds.
   function Count_For (Len : N32) return Positive is
     (Positive'Max (20_000, Positive (16 * 1024 * 1024 / Len)));

   procedure Fail (What : String) is
   begin
      raise Program_Error with What;
   end Fail;

   procedure Summarise (Bits : Natural; Results : Result_Table) is
      procedure Sort (S : in out Sample_Array) is
         T : Long_Float;
      begin
         for I in S'First + 1 .. S'Last loop
            for J in reverse S'First + 1 .. I loop
               exit when S (J - 1) <= S (J);
               T := S (J); S (J) := S (J - 1); S (J - 1) := T;
            end loop;
         end loop;
      end Sort;

      function Img (X : Long_Float) return String is
         R : constant Long_Long_Integer := Long_Long_Integer (X);
         S : constant String := R'Image;
      begin
         return S (S'First + 1 .. S'Last);
      end Img;
   begin
      for L in Lengths'Range loop
         for I in Impl loop
            declare
               S : Sample_Array := Results (I, L);
               Median, P25, P75 : Long_Float;
               Len : constant Long_Float := Long_Float (Lengths (L));
            begin
               Sort (S);
               Median := (S (10) + S (11)) / 2.0;
               P25 := (S (5) + S (6)) / 2.0;
               P75 := (S (15) + S (16)) / 2.0;
               Put_Line ("summary," & Img (Long_Float (Bits)) & "," &
                         Img (Len) & "," & Impl_Name (I).all & "," &
                         Img (Median) & "," & Img (P25) & "," & Img (P75) &
                         "," & Img (S (S'First)) & "," & Img (S (S'Last)) &
                         "," & Img (Len * 1000.0 / Median) & "," &
                         Img (Len * 1000.0 / P75) & "," &
                         Img (Len * 1000.0 / P25));
            end;
         end loop;
      end loop;
   end Summarise;

   procedure AEAD_Section is
      Results : Result_Table;
   begin
      Put_Line ("AESNI=" & SPARKTLSCrypto.AES_NI.Has_AESNI'Image &
                " PCLMULQDQ=" & SPARKTLSCrypto.GHASH_NI.Has_PCLMULQDQ'Image &
                " AVX512=" &
                SPARKTLSCrypto.AES_GCM_AVX512.Has_AVX512_AES_GCM'Image);
      Put_Line ("sample,bits,length,impl,ns_per_record");
      for Bits in 1 .. 2 loop
         declare
            Bit_Count : constant Interfaces.C.int :=
              Interfaces.C.int (Bits * 128);
            Enc_Ctx : constant System.Address :=
              OSSL_New (Raw_Key'Address, Bit_Count, 0);
            Dec_Ctx : constant System.Address :=
              OSSL_New (Raw_Key'Address, Bit_Count, 1);
         begin
            if Enc_Ctx = System.Null_Address
              or Dec_Ctx = System.Null_Address
            then
               Fail ("OpenSSL context");
            end if;
            if Bits = 1 then Prepare_128 (Context, K128);
            else Prepare_256 (Context, K256); end if;

            for L in Lengths'Range loop
               declare
                  Len   : constant N32 := Lengths (L);
                  Count : constant Positive := Count_For (Len);
                  Plain : constant Byte_Seq (0 .. Len - 1) := (others => 42);
                  Fixed_Nonce : constant Bytes_12 := (others => 7);
                  CT    : Byte_Seq (0 .. Len - 1) := Plain
                    with Alignment => 64;
                  CT_Tag : Bytes_16;
                  Buf   : Byte_Seq (0 .. Len - 1) := Plain
                    with Alignment => 64;
                  Nonce : Bytes_12 := (others => 0);
                  Valid : Boolean;
                  Start : Time;
                  Ns    : Long_Float;
               begin
                  --  The decrypt rows reuse one authentic record.
                  Encrypt_Prepared (CT, CT_Tag, Fixed_Nonce, Context, AAD);

                  for Sample in 0 .. Retained loop
                     for K in 0 .. Impl_Count - 1 loop
                        declare
                           --  Rotate the order so no row always runs
                           --  first (or after the same neighbour).
                           I : constant Impl :=
                             Impl'Val ((Sample + K) mod Impl_Count);
                        begin
                           Start := Clock;
                           case I is
                           when STC_Encrypt_Prepared =>
                              for J in 1 .. Count loop
                                 Nonce (0) := Byte (J mod 256);
                                 Nonce (1) := Byte ((J / 256) mod 256);
                                 Encrypt_Prepared
                                   (Buf, Tag, Nonce, Context, AAD);
                                 Sink := Sink xor Tag (0);
                              end loop;
                           when STC_Decrypt =>
                              for J in 1 .. Count loop
                                 if Bits = 1 then
                                    Decrypt (Buf, Valid, CT_Tag, CT,
                                             Fixed_Nonce, K128, AAD);
                                 else
                                    Decrypt_256 (Buf, Valid, CT_Tag, CT,
                                                 Fixed_Nonce, K256, AAD);
                                 end if;
                                 if not Valid then Fail ("stc decrypt"); end if;
                                 Sink := Sink xor Buf (0);
                              end loop;
                           when OSSL_Encrypt =>
                              for J in 1 .. Count loop
                                 Nonce (0) := Byte (J mod 256);
                                 Nonce (1) := Byte ((J / 256) mod 256);
                                 if OSSL_Seal (Enc_Ctx, Nonce'Address,
                                               AAD'Address, AAD'Length,
                                               Buf'Address,
                                               Interfaces.C.int (Len),
                                               Tag'Address) /= 1
                                 then
                                    Fail ("openssl seal");
                                 end if;
                                 Sink := Sink xor Tag (0);
                              end loop;
                           when OSSL_Decrypt =>
                              for J in 1 .. Count loop
                                 if OSSL_Open (Dec_Ctx, Fixed_Nonce'Address,
                                               AAD'Address, AAD'Length,
                                               CT'Address, Buf'Address,
                                               Interfaces.C.int (Len),
                                               CT_Tag'Address) /= 1
                                 then
                                    Fail ("openssl open");
                                 end if;
                                 Sink := Sink xor Buf (0);
                              end loop;
                           end case;
                           Ns := Long_Float (To_Duration (Clock - Start))
                             * 1.0E9 / Long_Float (Count);
                           Put_Line (Sample'Image & "," &
                                     Natural'Image (Bits * 128) & "," &
                                     Len'Image & "," & Impl_Name (I).all &
                                     "," & Long_Float'Image (Ns));
                           if Sample > 0 then
                              Results (I, L) (Sample) := Ns;
                           end if;
                        end;
                     end loop;
                  end loop;
               end;
            end loop;
            OSSL_Free (Enc_Ctx);
            OSSL_Free (Dec_Ctx);
         end;
         Put_Line ("summary,bits,length,impl,median_ns,p25_ns,p75_ns,min_ns,"
                   & "max_ns,median_MBps,p75_MBps,p25_MBps");
         Summarise (Bits * 128, Results);
      end loop;
   end AEAD_Section;

   Which : constant String :=
     (if Ada.Command_Line.Argument_Count > 0
      then Ada.Command_Line.Argument (1) else "all");
begin
   if Which = "all" or Which = "prepared" then
      Prepared_Section;
   end if;
   if Which = "all" or Which = "aead" then
      AEAD_Section;
   end if;
   Put_Line ("sink:" & Sink'Image);
   Clear (Context);
end Bench_Prepared;
