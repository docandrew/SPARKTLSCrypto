--  Constant-time check for the two branch-free masking loops,
--  AES_NI.Mask_Bytes (SSE2) and AES_GCM_AVX2.Mask_Bytes (AVX2), called
--  directly: ct_decrypt_prepared reaches the SSE2 one through the AES-NI
--  tier, but Valgrind exposes no VAES, so the AVX2 one is otherwise never
--  run under memcheck. Valgrind does execute AVX2, which is all the AVX2
--  loop uses. The mask (0 or 16#FF#, the tag comparison's result) and the
--  buffer are secret; only the length is public. Every length 0 .. 300
--  and one TLS record, both mask values.

with Ada.Text_IO; use Ada.Text_IO;
with Interfaces; use Interfaces;
with Interfaces.C;
with SPARKNaCl; use SPARKNaCl;
with SPARKTLSCrypto.AES_NI;
with SPARKTLSCrypto.AES_GCM_AVX2;
with Ctgrind;

procedure Ct_Mask_Bytes is
   Buf  : Byte_Seq (0 .. 16_384) := (others => 16#5A#);
   Mask : Byte;
begin
   for M in 0 .. 1 loop
      for Wide in Boolean loop
         for Len in 0 .. 301 loop
            declare
               L : constant N32 := (if Len = 301 then 16_385 else N32 (Len));
               Last : constant I32 := I32 (L) - 1;
            begin
               Mask := (if M = 0 then 0 else 16#FF#);
               Buf := (others => 16#5A#);
               Ctgrind.Make_Undefined (Mask'Address, Interfaces.C.size_t (1));
               Ctgrind.Make_Undefined
                 (Buf'Address, Interfaces.C.size_t (Buf'Length));
               if Wide then
                  SPARKTLSCrypto.AES_GCM_AVX2.Mask_Bytes (Buf (0 .. Last), Mask);
               else
                  SPARKTLSCrypto.AES_NI.Mask_Bytes (Buf (0 .. Last), Mask);
               end if;
               Ctgrind.Make_Defined
                 (Buf'Address, Interfaces.C.size_t (Buf'Length));
               Ctgrind.Use_Output (Buf'Address, Interfaces.C.size_t (L));
            end;
         end loop;
      end loop;
   end loop;
   Put_Line ("ct_mask_bytes: SSE2 and AVX2 masking, every length 0 .. 300"
             & " and 16 KiB, both masks");
end Ct_Mask_Bytes;
