with Ada.Text_IO; use Ada.Text_IO;
with Interfaces; use Interfaces;
with SPARKNaCl; use SPARKNaCl;
with SPARKNaCl.AES;
with SPARKTLSCrypto.AES_NI; use SPARKTLSCrypto.AES_NI;
with SPARKTLSCrypto.AES_GCM_AVX512; use SPARKTLSCrypto.AES_GCM_AVX512;
procedure Test_Fused is
 Seed : Unsigned_64 := 16#18E9_A3BA_5719_1234#;
 Digest : Unsigned_64 := 16#CBF2_9CE4_8422_2325#;
 Count : Natural := 0;
 function Next_Byte return Byte is
 begin
  Seed := Seed xor Shift_Left(Seed,13);
  Seed := Seed xor Shift_Right(Seed,7);
  Seed := Seed xor Shift_Left(Seed,17);
  return Byte(Seed and 255);
 end Next_Byte;
 procedure Check (Bits : Positive; Trial : Natural) is
  Key : Bytes_32;
  Counter : Bytes_256;
  H, Expected_S : Bytes_16;
  Powers : Pre_H_Powers_16;
  RK : Pre_Swapped_RKs_256;
  Storage, Expected : Byte_Seq (11..330) with Alignment => 64;
  Offset : constant N32 := 11 + N32(Trial mod 64);
  Guarded_S : Byte_Seq (7..54) := (others => 16#A5#);
 begin
  for I in Key'Range loop Key(I):=Next_Byte; end loop;
  for I in Counter'Range loop Counter(I):=Next_Byte; end loop;
  for I in H'Range loop H(I):=Next_Byte; Expected_S(I):=Next_Byte; end loop;
  for I in Storage'Range loop Storage(I):=Next_Byte; end loop;
  if Trial=0 then H:=(others=>0); Counter:=(others=>0);
  elsif Trial=1 then H:=(others=>255); Counter:=(others=>255);
  end if;
  Expected:=Storage; Guarded_S(23..38):=Expected_S;
  Compute_H_Powers_16(H,Powers);
  RK := (others=>0);
  if Bits=128 then
   Pre_Swap_RKs_128(AES.Key_Expansion(AES.Construct(Key(0..15))),RK(0..175));
   Cipher_16x_128_VAES_XOR(Expected(Offset..Offset+255),Counter,RK(0..175));
  else
   Pre_Swap_RKs_256(AES.Key_Expansion(AES.Construct(Key)),RK);
   Cipher_16x_256_VAES_XOR(Expected(Offset..Offset+255),Counter,RK);
  end if;
  GHASH_16_Blocks(Expected_S,Expected(Offset..Offset+255),Powers);
  declare
   Saved_Counter : constant Bytes_256 := Counter;
   Saved_Powers : constant Pre_H_Powers_16 := Powers;
   Saved_RK : constant Pre_Swapped_RKs_256 := RK;
  begin
   if Bits=128 then
    Encrypt_GCM_Stripe_16_128(Storage(Offset..Offset+255),Guarded_S(23..38),
      Counter,RK(0..175),Powers);
   else
    Encrypt_GCM_Stripe_16_256(Storage(Offset..Offset+255),Guarded_S(23..38),
      Counter,RK,Powers);
   end if;
   if Storage/=Expected or Guarded_S(23..38)/=Expected_S or
     Guarded_S(7..22)/=Byte_Seq'(0..15=>16#A5#) or
     Guarded_S(39..54)/=Byte_Seq'(0..15=>16#A5#) or
     Counter/=Saved_Counter or Powers/=Saved_Powers or RK/=Saved_RK
   then raise Program_Error with "fused stripe mismatch or guard mutation";
   end if;
  end;
  for B of Storage loop Digest:=(Digest xor Unsigned_64(B))*16#100_0000_01B3#; end loop;
  for B of Expected_S loop Digest:=(Digest xor Unsigned_64(B))*16#100_0000_01B3#; end loop;
  Count:=Count+1;
 end Check;
begin
 if not Has_AVX512_AES_GCM then
  Put_Line("SKIP: AVX-512 AES-GCM unavailable");return;
 end if;
 for Bits in 1..2 loop
  for Trial in 0..4095 loop Check(Bits*128,Trial); end loop;
 end loop;
 if Digest /= 8_091_673_054_100_983_235 then
  raise Program_Error with "fused stripe reference digest changed";
 end if;
 Put_Line("PASS: fused/unfused stripe, state and guard comparisons:" & Count'Image);
 Put_Line("Digest:" & Digest'Image);
end Test_Fused;
