--  The stitched AES-GCM stripe kernels (tools/generate_gcm_kernels.py)
--  against a block-at-a-time reference built from independent parts:
--  SPARKNaCl's software AES for the keystream, an Ada inc32 for the counter
--  blocks, and one GF(2^128) multiply per block (no aggregation) for GHASH.
--
--  For each kernel available on this CPU: both key sizes, every 64-byte
--  alignment, random and degenerate (zero, all-one) hash keys, random
--  accumulators, and counter blocks whose 32-bit counter wraps inside the
--  stripe. Guard bytes around the buffer and the accumulator, and the
--  round keys, powers and (for GHASH-only kernels) the data must be left
--  untouched; each case is rerun with the buffer and the powers against
--  PROT_NONE guard pages (both ends), so reads outside them fault too. Kernels the CPU lacks are reported as skipped.
with Ada.Text_IO; use Ada.Text_IO;
with Interfaces; use Interfaces;
with SPARKNaCl; use SPARKNaCl;
with SPARKNaCl.AES;
with SPARKTLSCrypto.AES_NI; use SPARKTLSCrypto.AES_NI;
with SPARKTLSCrypto.GHASH_NI;
with SPARKTLSCrypto.GHASH_Dispatch;
with SPARKTLSCrypto.AES_GCM_AVX2;
with SPARKTLSCrypto.AES_GCM_AVX512;
with System;
with System.Storage_Elements;
with Guarded_Memory;

procedure Test_Stripes is
   package AVX2 renames SPARKTLSCrypto.AES_GCM_AVX2;
   package AVX512 renames SPARKTLSCrypto.AES_GCM_AVX512;

   type Kernel is
     (NI_Decrypt_4,            --  AES_NI.Decrypt_GCM_Stripe_4_*
      Y_Decrypt_16,            --  AES_GCM_AVX2.Decrypt_GCM_Stripe_16_*
      Y_CTR_16,                --  AES_GCM_AVX2.Encrypt_CTR_16_*
      Y_Pipelined_16,          --  AES_GCM_AVX2.Encrypt_GHASH_Pipelined_16_*
      Y_GHASH_16,              --  AES_GCM_AVX2.GHASH_16_Blocks
      Z_Decrypt_16,            --  AES_GCM_AVX512.Decrypt_GCM_Stripe_16_*
      Z_Decrypt_32);           --  AES_GCM_AVX512.Decrypt_GCM_Stripe_32_*

   function Present (K : Kernel) return Boolean is
     (case K is
         when NI_Decrypt_4 =>
            Has_AESNI and SPARKTLSCrypto.GHASH_NI.Has_PCLMULQDQ,
         when Y_Decrypt_16 .. Y_GHASH_16 => AVX2.Has_VAES_AVX2,
         when Z_Decrypt_16 .. Z_Decrypt_32 => AVX512.Has_AVX512_AES_GCM);

   --  Bytes encrypted (AES) and hashed (GHASH) by one call, and where.
   function AES_Len (K : Kernel) return N32 is
     (case K is
         when NI_Decrypt_4 => 64,
         when Y_GHASH_16 => 0,
         when Z_Decrypt_32 => 512,
         when others => 256);
   function GHASH_Len (K : Kernel) return N32 is
     (case K is
         when NI_Decrypt_4 => 64,
         when Y_CTR_16 => 0,
         when Z_Decrypt_32 => 512,
         when others => 256);
   function AES_Offset (K : Kernel) return N32 is
     (if K = Y_Pipelined_16 then 256 else 0);
   function Window (K : Kernel) return N32 is
     (N32'Max (AES_Offset (K) + AES_Len (K), GHASH_Len (K)));

   Seed : Unsigned_64 := 16#5DEE_CE66_D1CE_4E5B#;
   function Next_Byte return Byte is
   begin
      Seed := Seed xor Shift_Left (Seed, 13);
      Seed := Seed xor Shift_Right (Seed, 7);
      Seed := Seed xor Shift_Left (Seed, 17);
      return Byte (Seed and 255);
   end Next_Byte;

   Count : Natural := 0;
   Guard : constant Byte := 16#5A#;

   use type System.Storage_Elements.Storage_Offset;
   Buf_Region : constant Guarded_Memory.Region := Guarded_Memory.Allocate (512);
   Pow_Region : constant Guarded_Memory.Region := Guarded_Memory.Allocate (512);

   procedure Check (OK : Boolean; What : String) is
   begin
      if not OK then
         raise Program_Error with What;
      end if;
   end Check;

   procedure Inc32 (CB : in out Bytes_16) is
      V : Unsigned_32 :=
        Shift_Left (Unsigned_32 (CB (12)), 24) or
        Shift_Left (Unsigned_32 (CB (13)), 16) or
        Shift_Left (Unsigned_32 (CB (14)), 8) or Unsigned_32 (CB (15));
   begin
      V := V + 1;
      CB (12) := Byte (Shift_Right (V, 24) and 255);
      CB (13) := Byte (Shift_Right (V, 16) and 255);
      CB (14) := Byte (Shift_Right (V, 8) and 255);
      CB (15) := Byte (V and 255);
   end Inc32;

   procedure Run (K : Kernel; Bits : Positive; Trial : Natural) is
      Key    : Bytes_32;
      H, S0  : Bytes_16;
      CB0    : Bytes_16;
      W      : constant N32 := Window (K);
      Offset : constant N32 := N32 (Trial mod 64);
      Storage, Expected : Byte_Seq (0 .. 64 + 512 + 64 + 63)
        with Alignment => 64;
      First  : constant N32 := 64 + Offset;
      S_Store : Byte_Seq (0 .. 47) := (others => Guard);
      CB_Store : Byte_Seq (0 .. 47) := (others => Guard);
      Powers : Byte_Seq (0 .. 511);
      RK : Pre_Swapped_RKs_256 := (others => 0);
      S_Ref, CB_Ref : Bytes_16;
   begin
      for I in Key'Range loop Key (I) := Next_Byte; end loop;
      for I in H'Range loop H (I) := Next_Byte; S0 (I) := Next_Byte; end loop;
      for I in CB0'Range loop CB0 (I) := Next_Byte; end loop;
      case Trial mod 8 is
         when 0 => H := (others => 0);
         when 1 => H := (others => 255);
         when 2 => CB0 (12 .. 15) := (255, 255, 255, 16#F9#);  --  wraps
         when 3 => CB0 (12 .. 15) := (255, 255, 255, 255);
         when 4 => S0 := (others => 0);
         when others => null;
      end case;
      for I in Storage'Range loop Storage (I) := Next_Byte; end loop;
      Storage (0 .. First - 1) := (others => Guard);
      Storage (First + W .. Storage'Last) := (others => Guard);
      Expected := Storage;

      --  Reference: GHASH block by block over the GHASH window as it is
      --  on entry, then the keystream XORed into the AES window.
      S_Ref := S0;
      for B in 0 .. GHASH_Len (K) / 16 - 1 loop
         for I in N32 range 0 .. 15 loop
            S_Ref (I) := S_Ref (I) xor Storage (First + 16 * B + I);
         end loop;
         S_Ref := SPARKTLSCrypto.GHASH_Dispatch.GF128_Mul (S_Ref, H);
      end loop;
      CB_Ref := CB0;
      declare
         Stream : Bytes_16;
         RK128 : constant AES.AES128_Round_Keys :=
           AES.Key_Expansion (AES.Construct (Key (0 .. 15)));
         RK256 : constant AES.AES256_Round_Keys :=
           AES.Key_Expansion (AES.Construct (Key));
      begin
         for B in 0 .. AES_Len (K) / 16 - 1 loop
            if Bits = 128 then
               AES.Cipher (Stream, CB_Ref, RK128);
            else
               AES.Cipher (Stream, CB_Ref, RK256);
            end if;
            Inc32 (CB_Ref);
            for I in N32 range 0 .. 15 loop
               declare
                  P : constant N32 := First + AES_Offset (K) + 16 * B + I;
               begin
                  Expected (P) := Expected (P) xor Stream (I);
               end;
            end loop;
         end loop;
      end;

      --  The kernel under test.
      --  H^32 .. H^1, byte-reversed, descending.
      declare
         Power : Bytes_16 := H;
      begin
         for K in reverse N32 range 0 .. 31 loop
            for I in N32 range 0 .. 15 loop
               Powers (16 * K + I) := Power (15 - I);
            end loop;
            Power := SPARKTLSCrypto.GHASH_Dispatch.GF128_Mul (Power, H);
         end loop;
      end;
      if Bits = 128 then
         Pre_Swap_RKs_128
           (AES.Key_Expansion (AES.Construct (Key (0 .. 15))), RK (0 .. 175));
      else
         Pre_Swap_RKs_256 (AES.Key_Expansion (AES.Construct (Key)), RK);
      end if;
      S_Store (16 .. 31) := S0;
      CB_Store (16 .. 31) := CB0;
      declare
         Saved_Powers : constant Byte_Seq := Powers;
         Saved_RK : constant Pre_Swapped_RKs_256 := RK;
         Input : constant Byte_Seq := Storage (First .. First + W - 1);

         --  The kernel K on Buf, reading the powers from Pw (H^32 .. H^1).
         procedure Call (Buf : in out Byte_Seq; Pw : Byte_Seq) is
            P16 : Byte_Seq renames Pw (Pw'First + 256 .. Pw'First + 511);
            P4  : Byte_Seq renames Pw (Pw'First + 448 .. Pw'First + 511);
            Powers : Byte_Seq renames Pw;
         begin
            case K is
               when NI_Decrypt_4 =>
                  if Bits = 128 then
                     Decrypt_GCM_Stripe_4_128 (Buf, S_Store (16 .. 31),
                        CB_Store (16 .. 31), RK (0 .. 175), P4);
                  else
                     Decrypt_GCM_Stripe_4_256 (Buf, S_Store (16 .. 31),
                        CB_Store (16 .. 31), RK, P4);
                  end if;
               when Y_Decrypt_16 =>
                  if Bits = 128 then
                     AVX2.Decrypt_GCM_Stripe_16_128 (Buf, S_Store (16 .. 31),
                        CB_Store (16 .. 31), RK (0 .. 175), P16);
                  else
                     AVX2.Decrypt_GCM_Stripe_16_256 (Buf, S_Store (16 .. 31),
                        CB_Store (16 .. 31), RK, P16);
                  end if;
               when Y_CTR_16 =>
                  if Bits = 128 then
                     AVX2.Encrypt_CTR_16_128 (Buf, CB_Store (16 .. 31),
                                              RK (0 .. 175));
                  else
                     AVX2.Encrypt_CTR_16_256 (Buf, CB_Store (16 .. 31), RK);
                  end if;
               when Y_Pipelined_16 =>
                  if Bits = 128 then
                     AVX2.Encrypt_GHASH_Pipelined_16_128 (Buf,
                        S_Store (16 .. 31), CB_Store (16 .. 31), RK (0 .. 175),
                        P16);
                  else
                     AVX2.Encrypt_GHASH_Pipelined_16_256 (Buf,
                        S_Store (16 .. 31), CB_Store (16 .. 31), RK, P16);
                  end if;
               when Y_GHASH_16 =>
                  AVX2.GHASH_16_Blocks (Buf, S_Store (16 .. 31), P16);
               when Z_Decrypt_16 =>
                  if Bits = 128 then
                     AVX512.Decrypt_GCM_Stripe_16_128 (Buf, S_Store (16 .. 31),
                        CB_Store (16 .. 31), RK (0 .. 175), P16);
                  else
                     AVX512.Decrypt_GCM_Stripe_16_256 (Buf, S_Store (16 .. 31),
                        CB_Store (16 .. 31), RK, P16);
                  end if;
               when Z_Decrypt_32 =>
                  if Bits = 128 then
                     AVX512.Decrypt_GCM_Stripe_32_128 (Buf, S_Store (16 .. 31),
                        CB_Store (16 .. 31), RK (0 .. 175), Powers);
                  else
                     AVX512.Decrypt_GCM_Stripe_32_256 (Buf, S_Store (16 .. 31),
                        CB_Store (16 .. 31), RK, Powers);
                  end if;
            end case;
         end Call;
      begin
         Call (Storage (First .. First + W - 1), Powers);
         Check (Powers = Saved_Powers and RK = Saved_RK,
                K'Image & ": powers or round keys modified");

         --  Again with the buffer and the powers against PROT_NONE guard
         --  pages (ending at one, then starting right after one): a read
         --  or write outside either faults. Same results, same state.
         declare
            Main_Buf : constant Byte_Seq := Storage (First .. First + W - 1);
            Main_S   : constant Byte_Seq := S_Store (16 .. 31);
            Main_CB  : constant Byte_Seq := CB_Store (16 .. 31);
         begin
            for At_End in Boolean loop
               declare
                  use type System.Storage_Elements.Storage_Offset;
                  B_Addr : constant System.Address :=
                    (if At_End then Guarded_Memory.At_End
                       (Buf_Region, System.Storage_Elements.Storage_Offset (W))
                     else Guarded_Memory.At_Start (Buf_Region));
                  P_Addr : constant System.Address :=
                    (if At_End then Guarded_Memory.At_End (Pow_Region, 512)
                     else Guarded_Memory.At_Start (Pow_Region));
                  G_Buf : Byte_Seq (0 .. W - 1)
                    with Import, Address => B_Addr;
                  G_Pow : Byte_Seq (0 .. 511)
                    with Import, Address => P_Addr;
               begin
                  G_Pow := Powers;
                  G_Buf := Input;
                  S_Store (16 .. 31) := S0;
                  CB_Store (16 .. 31) := CB0;
                  Call (G_Buf, G_Pow);
                  Check (G_Buf = Main_Buf and S_Store (16 .. 31) = Main_S
                         and CB_Store (16 .. 31) = Main_CB,
                         K'Image & Bits'Image & ": guarded-page run differs");
               end;
            end loop;
         end;
      end;
      Check (Storage = Expected, K'Image & Bits'Image &
             ": buffer differs from reference, trial" & Trial'Image);
      if GHASH_Len (K) > 0 then
         Check (S_Store (16 .. 31) = S_Ref, K'Image & Bits'Image &
                ": GHASH state differs, trial" & Trial'Image);
      else
         Check (S_Store (16 .. 31) = S0, K'Image & ": S modified");
      end if;
      if AES_Len (K) > 0 then
         Check (CB_Store (16 .. 31) = CB_Ref, K'Image & Bits'Image &
                ": counter block differs, trial" & Trial'Image);
      else
         Check (CB_Store (16 .. 31) = CB0, K'Image & ": CB modified");
      end if;
      Check ((for all I in 0 .. 15 =>
                S_Store (N32 (I)) = Guard and S_Store (N32 (I) + 32) = Guard
                and CB_Store (N32 (I)) = Guard
                and CB_Store (N32 (I) + 32) = Guard),
             K'Image & ": write outside S or CB");
      Count := Count + 1;
   end Run;
begin
   for K in Kernel loop
      if Present (K) then
         for B in 1 .. 2 loop
            for Trial in 0 .. 1023 loop
               Run (K, B * 128, Trial);
            end loop;
         end loop;
         Put_Line ("  " & K'Image & ": 2048 cases");
      else
         Put_Line ("  " & K'Image & ": SKIP (CPU lacks the tier)");
      end if;
   end loop;
   Put_Line ("PASS: stitched stripe kernels vs block reference:" &
             Count'Image);
end Test_Stripes;
