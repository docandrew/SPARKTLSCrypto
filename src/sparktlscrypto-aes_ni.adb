--  AES-NI hardware-accelerated AES block cipher (x86_64).
--  See sparktlscrypto-aes_ni.ads.
--
--  CPUID dispatch + inline assembly. SPARK_Mode is Off for the entire
--  body. Functional equivalence is verified via NIST KAT vectors.

with System.Machine_Code; use System.Machine_Code;
with Interfaces;          use Interfaces;
with SPARKNaCl;           use SPARKNaCl;
with SPARKNaCl.AES;

package body SPARKTLSCrypto.AES_NI with
   SPARK_Mode => Off
is

   ----------------------------------------------------------------------------
   --  CPUID detection (run once at elaboration)
   ----------------------------------------------------------------------------

   function Detect_AES_NI return Boolean is
      EAX, EBX, ECX, EDX : Unsigned_32;
   begin
      Asm ("cpuid",
           Outputs  => (Unsigned_32'Asm_Output ("=a", EAX),
                        Unsigned_32'Asm_Output ("=b", EBX),
                        Unsigned_32'Asm_Output ("=c", ECX),
                        Unsigned_32'Asm_Output ("=d", EDX)),
           Inputs   => Unsigned_32'Asm_Input ("a", 1),
           Volatile => True);
      pragma Unreferenced (EAX, EBX, EDX);
      --  CPUID.01h: ECX bit 25 = AES-NI
      return (ECX and 16#0200_0000#) /= 0;
   end Detect_AES_NI;

   ----------------------------------------------------------------------------
   --  Round-key conversion: SPARKNaCl uses big-endian U32 packing
   --  internally; AES-NI wants raw bytes in their natural order.
   --  PSHUFB with this mask reverses each 4-byte word.
   ----------------------------------------------------------------------------

   --  Mask for PSHUFB to byte-swap each 32-bit word in a 128-bit
   --  register. Bytes are reversed within each 4-byte group:
   --    [3,2,1,0, 7,6,5,4, 11,10,9,8, 15,14,13,12]
   --  16-byte aligned for movdqa.
   Bswap_Mask : constant array (0 .. 15) of Unsigned_8 :=
     (3, 2, 1, 0,
      7, 6, 5, 4,
      11, 10, 9, 8,
      15, 14, 13, 12);
   for Bswap_Mask'Alignment use 16;

   --  Full 16-byte reverse mask used by GHASH (NIST <-> PCLMULQDQ).
   --  Used in the fused encrypt+GHASH primitive below.
   Ghash_Bswap_Mask : constant array (0 .. 15) of Unsigned_8 :=
     (15, 14, 13, 12, 11, 10, 9, 8,
       7,  6,  5,  4,  3,  2, 1, 0);
   for Ghash_Bswap_Mask'Alignment use 16;

   ----------------------------------------------------------------------------
   --  Counter-block byte-shuffle support
   ----------------------------------------------------------------------------
   --  PSHUFB mask that reverses ONLY bytes 12..15 of the xmm register
   --  (the NIST GCM counter portion). Bytes 0..11 (IV) stay put. After
   --  applying it, the BE 32-bit counter at bytes 12..15 is laid out
   --  LE within those bytes, so PADDD on lane 3 increments correctly.
   --  Applying the same mask a second time reverts to BE.
   Reverse_Ctr_Mask : constant array (0 .. 15) of Unsigned_8 :=
     (0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 15, 14, 13, 12);
   for Reverse_Ctr_Mask'Alignment use 16;

   --  Per-lane increments: lane 3 = +1/+2/+3/+4 in LE u32 = byte 12 = N.
   --  PADDD adds these to the (LE-after-PSHUFB) counter in lane 3.
   Ctr_Inc_1 : constant array (0 .. 15) of Unsigned_8 :=
     (0,0,0,0, 0,0,0,0, 0,0,0,0, 1,0,0,0);
   for Ctr_Inc_1'Alignment use 16;
   Ctr_Inc_2 : constant array (0 .. 15) of Unsigned_8 :=
     (0,0,0,0, 0,0,0,0, 0,0,0,0, 2,0,0,0);
   for Ctr_Inc_2'Alignment use 16;
   Ctr_Inc_3 : constant array (0 .. 15) of Unsigned_8 :=
     (0,0,0,0, 0,0,0,0, 0,0,0,0, 3,0,0,0);
   for Ctr_Inc_3'Alignment use 16;
   Ctr_Inc_4 : constant array (0 .. 15) of Unsigned_8 :=
     (0,0,0,0, 0,0,0,0, 0,0,0,0, 4,0,0,0);
   for Ctr_Inc_4'Alignment use 16;

   ----------------------------------------------------------------------------
   --  AES-128 block encrypt
   ----------------------------------------------------------------------------
   --  Round keys come in SPARKNaCl format (11 × 16 bytes, each word
   --  big-endian-packed into a U32). We byte-swap each word as we
   --  load via PSHUFB so we never touch the original storage.

   procedure Cipher_128
     (Output     :    out Bytes_16;
      Input      : in     Bytes_16;
      Round_Keys : in     SPARKNaCl.AES.AES128_Round_Keys)
   is
   begin
      Asm
       (--  xmm0 = input block. Bytes_16 is a raw byte array — already
        --  in AES-NI native order, no swap needed.
        "movdqu  (%0), %%xmm0"           & ASCII.LF & ASCII.HT &
        --  xmm7 = byte-swap mask. Round keys are stored as
        --  SPARKNaCl U32_Seq with Big_Endian_Pack, so each 4-byte
        --  word is reversed in memory; PSHUFB restores AES-NI order.
        "movdqa  (%1), %%xmm7"           & ASCII.LF & ASCII.HT &

        --  Round 0: AddRoundKey
        "movdqu    (%2), %%xmm1"         & ASCII.LF & ASCII.HT &
        "pshufb  %%xmm7, %%xmm1"         & ASCII.LF & ASCII.HT &
        "pxor    %%xmm1, %%xmm0"         & ASCII.LF & ASCII.HT &

        --  Rounds 1..9: AESENC
        "movdqu  16(%2), %%xmm1"         & ASCII.LF & ASCII.HT &
        "pshufb  %%xmm7, %%xmm1"         & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm1, %%xmm0"         & ASCII.LF & ASCII.HT &

        "movdqu  32(%2), %%xmm1"         & ASCII.LF & ASCII.HT &
        "pshufb  %%xmm7, %%xmm1"         & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm1, %%xmm0"         & ASCII.LF & ASCII.HT &

        "movdqu  48(%2), %%xmm1"         & ASCII.LF & ASCII.HT &
        "pshufb  %%xmm7, %%xmm1"         & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm1, %%xmm0"         & ASCII.LF & ASCII.HT &

        "movdqu  64(%2), %%xmm1"         & ASCII.LF & ASCII.HT &
        "pshufb  %%xmm7, %%xmm1"         & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm1, %%xmm0"         & ASCII.LF & ASCII.HT &

        "movdqu  80(%2), %%xmm1"         & ASCII.LF & ASCII.HT &
        "pshufb  %%xmm7, %%xmm1"         & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm1, %%xmm0"         & ASCII.LF & ASCII.HT &

        "movdqu  96(%2), %%xmm1"         & ASCII.LF & ASCII.HT &
        "pshufb  %%xmm7, %%xmm1"         & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm1, %%xmm0"         & ASCII.LF & ASCII.HT &

        "movdqu  112(%2), %%xmm1"        & ASCII.LF & ASCII.HT &
        "pshufb  %%xmm7, %%xmm1"         & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm1, %%xmm0"         & ASCII.LF & ASCII.HT &

        "movdqu  128(%2), %%xmm1"        & ASCII.LF & ASCII.HT &
        "pshufb  %%xmm7, %%xmm1"         & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm1, %%xmm0"         & ASCII.LF & ASCII.HT &

        "movdqu  144(%2), %%xmm1"        & ASCII.LF & ASCII.HT &
        "pshufb  %%xmm7, %%xmm1"         & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm1, %%xmm0"         & ASCII.LF & ASCII.HT &

        --  Round 10: AESENCLAST
        "movdqu  160(%2), %%xmm1"        & ASCII.LF & ASCII.HT &
        "pshufb  %%xmm7, %%xmm1"         & ASCII.LF & ASCII.HT &
        "aesenclast %%xmm1, %%xmm0"      & ASCII.LF & ASCII.HT &

        --  Output is also Bytes_16 (raw bytes); store directly.
        "movdqu  %%xmm0, (%3)",

        Inputs  => (System.Address'Asm_Input ("r", Input'Address),
                    System.Address'Asm_Input ("r", Bswap_Mask'Address),
                    System.Address'Asm_Input ("r", Round_Keys'Address),
                    System.Address'Asm_Input ("r", Output'Address)),
        Clobber => "xmm0,xmm1,xmm7,memory",
        Volatile => True);
   end Cipher_128;

   ----------------------------------------------------------------------------
   --  AES-256 block encrypt — 14 rounds = 15 round keys (240 bytes)
   ----------------------------------------------------------------------------

   procedure Cipher_256
     (Output     :    out Bytes_16;
      Input      : in     Bytes_16;
      Round_Keys : in     SPARKNaCl.AES.AES256_Round_Keys)
   is
   begin
      Asm
       ("movdqu  (%0), %%xmm0"           & ASCII.LF & ASCII.HT &
        "movdqa  (%1), %%xmm7"           & ASCII.LF & ASCII.HT &

        --  Round 0
        "movdqu    (%2), %%xmm1"         & ASCII.LF & ASCII.HT &
        "pshufb  %%xmm7, %%xmm1"         & ASCII.LF & ASCII.HT &
        "pxor    %%xmm1, %%xmm0"         & ASCII.LF & ASCII.HT &

        --  Rounds 1..13: AESENC
        "movdqu  16(%2), %%xmm1"         & ASCII.LF & ASCII.HT &
        "pshufb  %%xmm7, %%xmm1"         & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm1, %%xmm0"         & ASCII.LF & ASCII.HT &

        "movdqu  32(%2), %%xmm1"         & ASCII.LF & ASCII.HT &
        "pshufb  %%xmm7, %%xmm1"         & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm1, %%xmm0"         & ASCII.LF & ASCII.HT &

        "movdqu  48(%2), %%xmm1"         & ASCII.LF & ASCII.HT &
        "pshufb  %%xmm7, %%xmm1"         & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm1, %%xmm0"         & ASCII.LF & ASCII.HT &

        "movdqu  64(%2), %%xmm1"         & ASCII.LF & ASCII.HT &
        "pshufb  %%xmm7, %%xmm1"         & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm1, %%xmm0"         & ASCII.LF & ASCII.HT &

        "movdqu  80(%2), %%xmm1"         & ASCII.LF & ASCII.HT &
        "pshufb  %%xmm7, %%xmm1"         & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm1, %%xmm0"         & ASCII.LF & ASCII.HT &

        "movdqu  96(%2), %%xmm1"         & ASCII.LF & ASCII.HT &
        "pshufb  %%xmm7, %%xmm1"         & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm1, %%xmm0"         & ASCII.LF & ASCII.HT &

        "movdqu  112(%2), %%xmm1"        & ASCII.LF & ASCII.HT &
        "pshufb  %%xmm7, %%xmm1"         & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm1, %%xmm0"         & ASCII.LF & ASCII.HT &

        "movdqu  128(%2), %%xmm1"        & ASCII.LF & ASCII.HT &
        "pshufb  %%xmm7, %%xmm1"         & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm1, %%xmm0"         & ASCII.LF & ASCII.HT &

        "movdqu  144(%2), %%xmm1"        & ASCII.LF & ASCII.HT &
        "pshufb  %%xmm7, %%xmm1"         & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm1, %%xmm0"         & ASCII.LF & ASCII.HT &

        "movdqu  160(%2), %%xmm1"        & ASCII.LF & ASCII.HT &
        "pshufb  %%xmm7, %%xmm1"         & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm1, %%xmm0"         & ASCII.LF & ASCII.HT &

        "movdqu  176(%2), %%xmm1"        & ASCII.LF & ASCII.HT &
        "pshufb  %%xmm7, %%xmm1"         & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm1, %%xmm0"         & ASCII.LF & ASCII.HT &

        "movdqu  192(%2), %%xmm1"        & ASCII.LF & ASCII.HT &
        "pshufb  %%xmm7, %%xmm1"         & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm1, %%xmm0"         & ASCII.LF & ASCII.HT &

        "movdqu  208(%2), %%xmm1"        & ASCII.LF & ASCII.HT &
        "pshufb  %%xmm7, %%xmm1"         & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm1, %%xmm0"         & ASCII.LF & ASCII.HT &

        --  Round 14: AESENCLAST
        "movdqu  224(%2), %%xmm1"        & ASCII.LF & ASCII.HT &
        "pshufb  %%xmm7, %%xmm1"         & ASCII.LF & ASCII.HT &
        "aesenclast %%xmm1, %%xmm0"      & ASCII.LF & ASCII.HT &

        "movdqu  %%xmm0, (%3)",

        Inputs  => (System.Address'Asm_Input ("r", Input'Address),
                    System.Address'Asm_Input ("r", Bswap_Mask'Address),
                    System.Address'Asm_Input ("r", Round_Keys'Address),
                    System.Address'Asm_Input ("r", Output'Address)),
        Clobber => "xmm0,xmm1,xmm7,memory",
        Volatile => True);
   end Cipher_256;

   ----------------------------------------------------------------------------
   --  Pre-swap round keys: byte-reverse each 4-byte word so AES-NI
   --  AESENC/AESENCLAST can consume them with raw movdqu loads.
   --  Run once per session (or once per encrypt) instead of once per
   --  block — saves ~11 PSHUFBs per AES-128 block, ~15 per AES-256
   --  block.
   ----------------------------------------------------------------------------

   procedure Pre_Swap_RKs_128
     (Source : in     SPARKNaCl.AES.AES128_Round_Keys;
      Dest   :    out Pre_Swapped_RKs_128)
   is
   begin
      Asm
       ("movdqa  (%2), %%xmm7"            & ASCII.LF & ASCII.HT &
        --  11 round keys × 16 bytes; reverse each 4-byte word.
        "movdqu    (%0), %%xmm0; pshufb %%xmm7, %%xmm0; movdqu %%xmm0,    (%1)" & ASCII.LF & ASCII.HT &
        "movdqu  16(%0), %%xmm0; pshufb %%xmm7, %%xmm0; movdqu %%xmm0,  16(%1)" & ASCII.LF & ASCII.HT &
        "movdqu  32(%0), %%xmm0; pshufb %%xmm7, %%xmm0; movdqu %%xmm0,  32(%1)" & ASCII.LF & ASCII.HT &
        "movdqu  48(%0), %%xmm0; pshufb %%xmm7, %%xmm0; movdqu %%xmm0,  48(%1)" & ASCII.LF & ASCII.HT &
        "movdqu  64(%0), %%xmm0; pshufb %%xmm7, %%xmm0; movdqu %%xmm0,  64(%1)" & ASCII.LF & ASCII.HT &
        "movdqu  80(%0), %%xmm0; pshufb %%xmm7, %%xmm0; movdqu %%xmm0,  80(%1)" & ASCII.LF & ASCII.HT &
        "movdqu  96(%0), %%xmm0; pshufb %%xmm7, %%xmm0; movdqu %%xmm0,  96(%1)" & ASCII.LF & ASCII.HT &
        "movdqu 112(%0), %%xmm0; pshufb %%xmm7, %%xmm0; movdqu %%xmm0, 112(%1)" & ASCII.LF & ASCII.HT &
        "movdqu 128(%0), %%xmm0; pshufb %%xmm7, %%xmm0; movdqu %%xmm0, 128(%1)" & ASCII.LF & ASCII.HT &
        "movdqu 144(%0), %%xmm0; pshufb %%xmm7, %%xmm0; movdqu %%xmm0, 144(%1)" & ASCII.LF & ASCII.HT &
        "movdqu 160(%0), %%xmm0; pshufb %%xmm7, %%xmm0; movdqu %%xmm0, 160(%1)",
        Inputs  => (System.Address'Asm_Input ("r", Source'Address),
                    System.Address'Asm_Input ("r", Dest'Address),
                    System.Address'Asm_Input ("r", Bswap_Mask'Address)),
        Clobber => "xmm0,xmm7,memory",
        Volatile => True);
   end Pre_Swap_RKs_128;

   procedure Pre_Swap_RKs_256
     (Source : in     SPARKNaCl.AES.AES256_Round_Keys;
      Dest   :    out Pre_Swapped_RKs_256)
   is
   begin
      Asm
       ("movdqa  (%2), %%xmm7"            & ASCII.LF & ASCII.HT &
        --  15 round keys × 16 bytes.
        "movdqu    (%0), %%xmm0; pshufb %%xmm7, %%xmm0; movdqu %%xmm0,    (%1)" & ASCII.LF & ASCII.HT &
        "movdqu  16(%0), %%xmm0; pshufb %%xmm7, %%xmm0; movdqu %%xmm0,  16(%1)" & ASCII.LF & ASCII.HT &
        "movdqu  32(%0), %%xmm0; pshufb %%xmm7, %%xmm0; movdqu %%xmm0,  32(%1)" & ASCII.LF & ASCII.HT &
        "movdqu  48(%0), %%xmm0; pshufb %%xmm7, %%xmm0; movdqu %%xmm0,  48(%1)" & ASCII.LF & ASCII.HT &
        "movdqu  64(%0), %%xmm0; pshufb %%xmm7, %%xmm0; movdqu %%xmm0,  64(%1)" & ASCII.LF & ASCII.HT &
        "movdqu  80(%0), %%xmm0; pshufb %%xmm7, %%xmm0; movdqu %%xmm0,  80(%1)" & ASCII.LF & ASCII.HT &
        "movdqu  96(%0), %%xmm0; pshufb %%xmm7, %%xmm0; movdqu %%xmm0,  96(%1)" & ASCII.LF & ASCII.HT &
        "movdqu 112(%0), %%xmm0; pshufb %%xmm7, %%xmm0; movdqu %%xmm0, 112(%1)" & ASCII.LF & ASCII.HT &
        "movdqu 128(%0), %%xmm0; pshufb %%xmm7, %%xmm0; movdqu %%xmm0, 128(%1)" & ASCII.LF & ASCII.HT &
        "movdqu 144(%0), %%xmm0; pshufb %%xmm7, %%xmm0; movdqu %%xmm0, 144(%1)" & ASCII.LF & ASCII.HT &
        "movdqu 160(%0), %%xmm0; pshufb %%xmm7, %%xmm0; movdqu %%xmm0, 160(%1)" & ASCII.LF & ASCII.HT &
        "movdqu 176(%0), %%xmm0; pshufb %%xmm7, %%xmm0; movdqu %%xmm0, 176(%1)" & ASCII.LF & ASCII.HT &
        "movdqu 192(%0), %%xmm0; pshufb %%xmm7, %%xmm0; movdqu %%xmm0, 192(%1)" & ASCII.LF & ASCII.HT &
        "movdqu 208(%0), %%xmm0; pshufb %%xmm7, %%xmm0; movdqu %%xmm0, 208(%1)" & ASCII.LF & ASCII.HT &
        "movdqu 224(%0), %%xmm0; pshufb %%xmm7, %%xmm0; movdqu %%xmm0, 224(%1)",
        Inputs  => (System.Address'Asm_Input ("r", Source'Address),
                    System.Address'Asm_Input ("r", Dest'Address),
                    System.Address'Asm_Input ("r", Bswap_Mask'Address)),
        Clobber => "xmm0,xmm7,memory",
        Volatile => True);
   end Pre_Swap_RKs_256;

   ----------------------------------------------------------------------------
   --  AES block encrypt with pre-swapped round keys.  No per-call
   --  PSHUFB; just movdqu + AESENC sequences.
   ----------------------------------------------------------------------------

   procedure Cipher_128_PreSw
     (Output     :    out Bytes_16;
      Input      : in     Bytes_16;
      Pre_RK     : in     Pre_Swapped_RKs_128)
   is
   begin
      Asm
       ("movdqu    (%0), %%xmm0"          & ASCII.LF & ASCII.HT &
        "movdqu    (%1), %%xmm1; pxor    %%xmm1, %%xmm0" & ASCII.LF & ASCII.HT &
        "movdqu  16(%1), %%xmm1; aesenc  %%xmm1, %%xmm0" & ASCII.LF & ASCII.HT &
        "movdqu  32(%1), %%xmm1; aesenc  %%xmm1, %%xmm0" & ASCII.LF & ASCII.HT &
        "movdqu  48(%1), %%xmm1; aesenc  %%xmm1, %%xmm0" & ASCII.LF & ASCII.HT &
        "movdqu  64(%1), %%xmm1; aesenc  %%xmm1, %%xmm0" & ASCII.LF & ASCII.HT &
        "movdqu  80(%1), %%xmm1; aesenc  %%xmm1, %%xmm0" & ASCII.LF & ASCII.HT &
        "movdqu  96(%1), %%xmm1; aesenc  %%xmm1, %%xmm0" & ASCII.LF & ASCII.HT &
        "movdqu 112(%1), %%xmm1; aesenc  %%xmm1, %%xmm0" & ASCII.LF & ASCII.HT &
        "movdqu 128(%1), %%xmm1; aesenc  %%xmm1, %%xmm0" & ASCII.LF & ASCII.HT &
        "movdqu 144(%1), %%xmm1; aesenc  %%xmm1, %%xmm0" & ASCII.LF & ASCII.HT &
        "movdqu 160(%1), %%xmm1; aesenclast %%xmm1, %%xmm0" & ASCII.LF & ASCII.HT &
        "movdqu  %%xmm0, (%2)",
        Inputs  => (System.Address'Asm_Input ("r", Input'Address),
                    System.Address'Asm_Input ("r", Pre_RK'Address),
                    System.Address'Asm_Input ("r", Output'Address)),
        Clobber => "xmm0,xmm1,memory",
        Volatile => True);
   end Cipher_128_PreSw;

   procedure Cipher_256_PreSw
     (Output     :    out Bytes_16;
      Input      : in     Bytes_16;
      Pre_RK     : in     Pre_Swapped_RKs_256)
   is
   begin
      Asm
       ("movdqu    (%0), %%xmm0"          & ASCII.LF & ASCII.HT &
        "movdqu    (%1), %%xmm1; pxor    %%xmm1, %%xmm0" & ASCII.LF & ASCII.HT &
        "movdqu  16(%1), %%xmm1; aesenc  %%xmm1, %%xmm0" & ASCII.LF & ASCII.HT &
        "movdqu  32(%1), %%xmm1; aesenc  %%xmm1, %%xmm0" & ASCII.LF & ASCII.HT &
        "movdqu  48(%1), %%xmm1; aesenc  %%xmm1, %%xmm0" & ASCII.LF & ASCII.HT &
        "movdqu  64(%1), %%xmm1; aesenc  %%xmm1, %%xmm0" & ASCII.LF & ASCII.HT &
        "movdqu  80(%1), %%xmm1; aesenc  %%xmm1, %%xmm0" & ASCII.LF & ASCII.HT &
        "movdqu  96(%1), %%xmm1; aesenc  %%xmm1, %%xmm0" & ASCII.LF & ASCII.HT &
        "movdqu 112(%1), %%xmm1; aesenc  %%xmm1, %%xmm0" & ASCII.LF & ASCII.HT &
        "movdqu 128(%1), %%xmm1; aesenc  %%xmm1, %%xmm0" & ASCII.LF & ASCII.HT &
        "movdqu 144(%1), %%xmm1; aesenc  %%xmm1, %%xmm0" & ASCII.LF & ASCII.HT &
        "movdqu 160(%1), %%xmm1; aesenc  %%xmm1, %%xmm0" & ASCII.LF & ASCII.HT &
        "movdqu 176(%1), %%xmm1; aesenc  %%xmm1, %%xmm0" & ASCII.LF & ASCII.HT &
        "movdqu 192(%1), %%xmm1; aesenc  %%xmm1, %%xmm0" & ASCII.LF & ASCII.HT &
        "movdqu 208(%1), %%xmm1; aesenc  %%xmm1, %%xmm0" & ASCII.LF & ASCII.HT &
        "movdqu 224(%1), %%xmm1; aesenclast %%xmm1, %%xmm0" & ASCII.LF & ASCII.HT &
        "movdqu  %%xmm0, (%2)",
        Inputs  => (System.Address'Asm_Input ("r", Input'Address),
                    System.Address'Asm_Input ("r", Pre_RK'Address),
                    System.Address'Asm_Input ("r", Output'Address)),
        Clobber => "xmm0,xmm1,memory",
        Volatile => True);
   end Cipher_256_PreSw;

   ----------------------------------------------------------------------------
   --  4-way pipelined block encrypt (pre-swapped round keys).
   --  Same xmm4 broadcast trick as Cipher_*_PreSw, but with 4 state
   --  chains (xmm0..xmm3) running in parallel so the AESENC unit is
   --  saturated at 1 instr/cycle instead of stalling on dependency.
   ----------------------------------------------------------------------------

   procedure Cipher_4x_128_PreSw
     (Output : out Bytes_64;
      Input  : in     Bytes_64;
      Pre_RK : in     Pre_Swapped_RKs_128)
   is
   begin
      Asm
       (--  Load 4 input blocks into xmm0..xmm3.
        "movdqu    (%0), %%xmm0"          & ASCII.LF & ASCII.HT &
        "movdqu  16(%0), %%xmm1"          & ASCII.LF & ASCII.HT &
        "movdqu  32(%0), %%xmm2"          & ASCII.LF & ASCII.HT &
        "movdqu  48(%0), %%xmm3"          & ASCII.LF & ASCII.HT &
        --  Round 0: AddRoundKey (broadcast RK[0] from xmm4).
        "movdqu    (%1), %%xmm4"          & ASCII.LF & ASCII.HT &
        "pxor    %%xmm4, %%xmm0"          & ASCII.LF & ASCII.HT &
        "pxor    %%xmm4, %%xmm1"          & ASCII.LF & ASCII.HT &
        "pxor    %%xmm4, %%xmm2"          & ASCII.LF & ASCII.HT &
        "pxor    %%xmm4, %%xmm3"          & ASCII.LF & ASCII.HT &
        --  Rounds 1..9: AESENC against the shared round key in xmm4.
        "movdqu  16(%1), %%xmm4"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm0"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm1"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm2"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm3"          & ASCII.LF & ASCII.HT &
        "movdqu  32(%1), %%xmm4"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm0"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm1"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm2"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm3"          & ASCII.LF & ASCII.HT &
        "movdqu  48(%1), %%xmm4"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm0"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm1"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm2"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm3"          & ASCII.LF & ASCII.HT &
        "movdqu  64(%1), %%xmm4"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm0"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm1"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm2"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm3"          & ASCII.LF & ASCII.HT &
        "movdqu  80(%1), %%xmm4"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm0"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm1"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm2"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm3"          & ASCII.LF & ASCII.HT &
        "movdqu  96(%1), %%xmm4"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm0"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm1"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm2"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm3"          & ASCII.LF & ASCII.HT &
        "movdqu 112(%1), %%xmm4"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm0"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm1"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm2"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm3"          & ASCII.LF & ASCII.HT &
        "movdqu 128(%1), %%xmm4"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm0"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm1"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm2"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm3"          & ASCII.LF & ASCII.HT &
        "movdqu 144(%1), %%xmm4"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm0"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm1"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm2"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm3"          & ASCII.LF & ASCII.HT &
        --  Round 10: AESENCLAST.
        "movdqu 160(%1), %%xmm4"          & ASCII.LF & ASCII.HT &
        "aesenclast %%xmm4, %%xmm0"       & ASCII.LF & ASCII.HT &
        "aesenclast %%xmm4, %%xmm1"       & ASCII.LF & ASCII.HT &
        "aesenclast %%xmm4, %%xmm2"       & ASCII.LF & ASCII.HT &
        "aesenclast %%xmm4, %%xmm3"       & ASCII.LF & ASCII.HT &
        --  Store 4 output blocks.
        "movdqu  %%xmm0,    (%2)"         & ASCII.LF & ASCII.HT &
        "movdqu  %%xmm1,  16(%2)"         & ASCII.LF & ASCII.HT &
        "movdqu  %%xmm2,  32(%2)"         & ASCII.LF & ASCII.HT &
        "movdqu  %%xmm3,  48(%2)",
        Inputs  => (System.Address'Asm_Input ("r", Input'Address),
                    System.Address'Asm_Input ("r", Pre_RK'Address),
                    System.Address'Asm_Input ("r", Output'Address)),
        Clobber => "xmm0,xmm1,xmm2,xmm3,xmm4,memory",
        Volatile => True);
   end Cipher_4x_128_PreSw;

   procedure Cipher_4x_256_PreSw
     (Output : out Bytes_64;
      Input  : in     Bytes_64;
      Pre_RK : in     Pre_Swapped_RKs_256)
   is
   begin
      Asm
       ("movdqu    (%0), %%xmm0"          & ASCII.LF & ASCII.HT &
        "movdqu  16(%0), %%xmm1"          & ASCII.LF & ASCII.HT &
        "movdqu  32(%0), %%xmm2"          & ASCII.LF & ASCII.HT &
        "movdqu  48(%0), %%xmm3"          & ASCII.LF & ASCII.HT &
        "movdqu    (%1), %%xmm4"          & ASCII.LF & ASCII.HT &
        "pxor    %%xmm4, %%xmm0"          & ASCII.LF & ASCII.HT &
        "pxor    %%xmm4, %%xmm1"          & ASCII.LF & ASCII.HT &
        "pxor    %%xmm4, %%xmm2"          & ASCII.LF & ASCII.HT &
        "pxor    %%xmm4, %%xmm3"          & ASCII.LF & ASCII.HT &
        "movdqu  16(%1), %%xmm4"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm0"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm1"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm2"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm3"          & ASCII.LF & ASCII.HT &
        "movdqu  32(%1), %%xmm4"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm0"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm1"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm2"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm3"          & ASCII.LF & ASCII.HT &
        "movdqu  48(%1), %%xmm4"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm0"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm1"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm2"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm3"          & ASCII.LF & ASCII.HT &
        "movdqu  64(%1), %%xmm4"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm0"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm1"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm2"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm3"          & ASCII.LF & ASCII.HT &
        "movdqu  80(%1), %%xmm4"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm0"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm1"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm2"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm3"          & ASCII.LF & ASCII.HT &
        "movdqu  96(%1), %%xmm4"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm0"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm1"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm2"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm3"          & ASCII.LF & ASCII.HT &
        "movdqu 112(%1), %%xmm4"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm0"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm1"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm2"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm3"          & ASCII.LF & ASCII.HT &
        "movdqu 128(%1), %%xmm4"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm0"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm1"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm2"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm3"          & ASCII.LF & ASCII.HT &
        "movdqu 144(%1), %%xmm4"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm0"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm1"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm2"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm3"          & ASCII.LF & ASCII.HT &
        "movdqu 160(%1), %%xmm4"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm0"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm1"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm2"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm3"          & ASCII.LF & ASCII.HT &
        "movdqu 176(%1), %%xmm4"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm0"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm1"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm2"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm3"          & ASCII.LF & ASCII.HT &
        "movdqu 192(%1), %%xmm4"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm0"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm1"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm2"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm3"          & ASCII.LF & ASCII.HT &
        "movdqu 208(%1), %%xmm4"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm0"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm1"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm2"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm3"          & ASCII.LF & ASCII.HT &
        "movdqu 224(%1), %%xmm4"          & ASCII.LF & ASCII.HT &
        "aesenclast %%xmm4, %%xmm0"       & ASCII.LF & ASCII.HT &
        "aesenclast %%xmm4, %%xmm1"       & ASCII.LF & ASCII.HT &
        "aesenclast %%xmm4, %%xmm2"       & ASCII.LF & ASCII.HT &
        "aesenclast %%xmm4, %%xmm3"       & ASCII.LF & ASCII.HT &
        "movdqu  %%xmm0,    (%2)"         & ASCII.LF & ASCII.HT &
        "movdqu  %%xmm1,  16(%2)"         & ASCII.LF & ASCII.HT &
        "movdqu  %%xmm2,  32(%2)"         & ASCII.LF & ASCII.HT &
        "movdqu  %%xmm3,  48(%2)",
        Inputs  => (System.Address'Asm_Input ("r", Input'Address),
                    System.Address'Asm_Input ("r", Pre_RK'Address),
                    System.Address'Asm_Input ("r", Output'Address)),
        Clobber => "xmm0,xmm1,xmm2,xmm3,xmm4,memory",
        Volatile => True);
   end Cipher_4x_256_PreSw;

   ----------------------------------------------------------------------------
   --  Fused 4-block CTR encrypt: keystream + XOR in one asm.
   --  Saves the keystream temp buffer + Ada XOR loop; OOO can also
   --  start the buffer loads while the AES rounds are still running.
   ----------------------------------------------------------------------------

   procedure Cipher_4x_128_PreSw_XOR
     (Buf     : in out Byte_Seq;
      Counter : in     Bytes_64;
      Pre_RK  : in     Pre_Swapped_RKs_128)
   is
   begin
      Asm
       (--  Load 4 counter blocks into xmm0..xmm3.
        "movdqu    (%0), %%xmm0"          & ASCII.LF & ASCII.HT &
        "movdqu  16(%0), %%xmm1"          & ASCII.LF & ASCII.HT &
        "movdqu  32(%0), %%xmm2"          & ASCII.LF & ASCII.HT &
        "movdqu  48(%0), %%xmm3"          & ASCII.LF & ASCII.HT &
        "movdqu    (%1), %%xmm4"          & ASCII.LF & ASCII.HT &
        "pxor    %%xmm4, %%xmm0"          & ASCII.LF & ASCII.HT &
        "pxor    %%xmm4, %%xmm1"          & ASCII.LF & ASCII.HT &
        "pxor    %%xmm4, %%xmm2"          & ASCII.LF & ASCII.HT &
        "pxor    %%xmm4, %%xmm3"          & ASCII.LF & ASCII.HT &
        "movdqu  16(%1), %%xmm4"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm0"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm1"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm2"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm3"          & ASCII.LF & ASCII.HT &
        "movdqu  32(%1), %%xmm4"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm0"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm1"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm2"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm3"          & ASCII.LF & ASCII.HT &
        "movdqu  48(%1), %%xmm4"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm0"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm1"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm2"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm3"          & ASCII.LF & ASCII.HT &
        "movdqu  64(%1), %%xmm4"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm0"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm1"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm2"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm3"          & ASCII.LF & ASCII.HT &
        "movdqu  80(%1), %%xmm4"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm0"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm1"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm2"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm3"          & ASCII.LF & ASCII.HT &
        "movdqu  96(%1), %%xmm4"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm0"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm1"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm2"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm3"          & ASCII.LF & ASCII.HT &
        "movdqu 112(%1), %%xmm4"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm0"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm1"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm2"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm3"          & ASCII.LF & ASCII.HT &
        "movdqu 128(%1), %%xmm4"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm0"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm1"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm2"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm3"          & ASCII.LF & ASCII.HT &
        "movdqu 144(%1), %%xmm4"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm0"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm1"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm2"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm3"          & ASCII.LF & ASCII.HT &
        "movdqu 160(%1), %%xmm4"          & ASCII.LF & ASCII.HT &
        "aesenclast %%xmm4, %%xmm0"       & ASCII.LF & ASCII.HT &
        "aesenclast %%xmm4, %%xmm1"       & ASCII.LF & ASCII.HT &
        "aesenclast %%xmm4, %%xmm2"       & ASCII.LF & ASCII.HT &
        "aesenclast %%xmm4, %%xmm3"       & ASCII.LF & ASCII.HT &
        --  Fused XOR with Buf in place (no separate keystream buffer).
        "movdqu    (%2), %%xmm4"          & ASCII.LF & ASCII.HT &
        "pxor    %%xmm4, %%xmm0"          & ASCII.LF & ASCII.HT &
        "movdqu  16(%2), %%xmm4"          & ASCII.LF & ASCII.HT &
        "pxor    %%xmm4, %%xmm1"          & ASCII.LF & ASCII.HT &
        "movdqu  32(%2), %%xmm4"          & ASCII.LF & ASCII.HT &
        "pxor    %%xmm4, %%xmm2"          & ASCII.LF & ASCII.HT &
        "movdqu  48(%2), %%xmm4"          & ASCII.LF & ASCII.HT &
        "pxor    %%xmm4, %%xmm3"          & ASCII.LF & ASCII.HT &
        "movdqu  %%xmm0,    (%2)"         & ASCII.LF & ASCII.HT &
        "movdqu  %%xmm1,  16(%2)"         & ASCII.LF & ASCII.HT &
        "movdqu  %%xmm2,  32(%2)"         & ASCII.LF & ASCII.HT &
        "movdqu  %%xmm3,  48(%2)",
        Inputs  => (System.Address'Asm_Input ("r", Counter'Address),
                    System.Address'Asm_Input ("r", Pre_RK'Address),
                    System.Address'Asm_Input ("r", Buf'Address)),
        Clobber => "xmm0,xmm1,xmm2,xmm3,xmm4,memory",
        Volatile => True);
   end Cipher_4x_128_PreSw_XOR;

   procedure Cipher_4x_256_PreSw_XOR
     (Buf     : in out Byte_Seq;
      Counter : in     Bytes_64;
      Pre_RK  : in     Pre_Swapped_RKs_256)
   is
   begin
      Asm
       ("movdqu    (%0), %%xmm0"          & ASCII.LF & ASCII.HT &
        "movdqu  16(%0), %%xmm1"          & ASCII.LF & ASCII.HT &
        "movdqu  32(%0), %%xmm2"          & ASCII.LF & ASCII.HT &
        "movdqu  48(%0), %%xmm3"          & ASCII.LF & ASCII.HT &
        "movdqu    (%1), %%xmm4"          & ASCII.LF & ASCII.HT &
        "pxor    %%xmm4, %%xmm0"          & ASCII.LF & ASCII.HT &
        "pxor    %%xmm4, %%xmm1"          & ASCII.LF & ASCII.HT &
        "pxor    %%xmm4, %%xmm2"          & ASCII.LF & ASCII.HT &
        "pxor    %%xmm4, %%xmm3"          & ASCII.LF & ASCII.HT &
        "movdqu  16(%1), %%xmm4"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm0"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm1"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm2"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm3"          & ASCII.LF & ASCII.HT &
        "movdqu  32(%1), %%xmm4"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm0"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm1"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm2"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm3"          & ASCII.LF & ASCII.HT &
        "movdqu  48(%1), %%xmm4"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm0"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm1"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm2"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm3"          & ASCII.LF & ASCII.HT &
        "movdqu  64(%1), %%xmm4"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm0"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm1"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm2"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm3"          & ASCII.LF & ASCII.HT &
        "movdqu  80(%1), %%xmm4"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm0"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm1"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm2"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm3"          & ASCII.LF & ASCII.HT &
        "movdqu  96(%1), %%xmm4"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm0"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm1"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm2"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm3"          & ASCII.LF & ASCII.HT &
        "movdqu 112(%1), %%xmm4"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm0"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm1"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm2"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm3"          & ASCII.LF & ASCII.HT &
        "movdqu 128(%1), %%xmm4"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm0"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm1"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm2"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm3"          & ASCII.LF & ASCII.HT &
        "movdqu 144(%1), %%xmm4"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm0"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm1"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm2"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm3"          & ASCII.LF & ASCII.HT &
        "movdqu 160(%1), %%xmm4"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm0"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm1"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm2"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm3"          & ASCII.LF & ASCII.HT &
        "movdqu 176(%1), %%xmm4"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm0"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm1"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm2"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm3"          & ASCII.LF & ASCII.HT &
        "movdqu 192(%1), %%xmm4"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm0"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm1"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm2"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm3"          & ASCII.LF & ASCII.HT &
        "movdqu 208(%1), %%xmm4"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm0"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm1"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm2"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm3"          & ASCII.LF & ASCII.HT &
        "movdqu 224(%1), %%xmm4"          & ASCII.LF & ASCII.HT &
        "aesenclast %%xmm4, %%xmm0"       & ASCII.LF & ASCII.HT &
        "aesenclast %%xmm4, %%xmm1"       & ASCII.LF & ASCII.HT &
        "aesenclast %%xmm4, %%xmm2"       & ASCII.LF & ASCII.HT &
        "aesenclast %%xmm4, %%xmm3"       & ASCII.LF & ASCII.HT &
        "movdqu    (%2), %%xmm4"          & ASCII.LF & ASCII.HT &
        "pxor    %%xmm4, %%xmm0"          & ASCII.LF & ASCII.HT &
        "movdqu  16(%2), %%xmm4"          & ASCII.LF & ASCII.HT &
        "pxor    %%xmm4, %%xmm1"          & ASCII.LF & ASCII.HT &
        "movdqu  32(%2), %%xmm4"          & ASCII.LF & ASCII.HT &
        "pxor    %%xmm4, %%xmm2"          & ASCII.LF & ASCII.HT &
        "movdqu  48(%2), %%xmm4"          & ASCII.LF & ASCII.HT &
        "pxor    %%xmm4, %%xmm3"          & ASCII.LF & ASCII.HT &
        "movdqu  %%xmm0,    (%2)"         & ASCII.LF & ASCII.HT &
        "movdqu  %%xmm1,  16(%2)"         & ASCII.LF & ASCII.HT &
        "movdqu  %%xmm2,  32(%2)"         & ASCII.LF & ASCII.HT &
        "movdqu  %%xmm3,  48(%2)",
        Inputs  => (System.Address'Asm_Input ("r", Counter'Address),
                    System.Address'Asm_Input ("r", Pre_RK'Address),
                    System.Address'Asm_Input ("r", Buf'Address)),
        Clobber => "xmm0,xmm1,xmm2,xmm3,xmm4,memory",
        Volatile => True);
   end Cipher_4x_256_PreSw_XOR;

   ----------------------------------------------------------------------------
   --  Fully fused AES-GCM stripe (Step 4)
   ----------------------------------------------------------------------------
   --  AES + XOR + aggregated 4-block GHASH for one 64-byte stripe in
   --  a single asm block. The OOO engine sees both the AES and the
   --  GHASH dependency chains in the same call and can dispatch them
   --  to different execution units (AES vs CLMUL ports).
   ----------------------------------------------------------------------------

   procedure Encrypt_GCM_Stripe_4_128
     (Buf      : in out Byte_Seq;
      S        : in out Bytes_16;
      Counter  : in     Bytes_64;
      Pre_RK   : in     Pre_Swapped_RKs_128;
      H_Powers : in     Pre_H_Powers)
   is
   begin
      Asm
       (--===== Phase A: AES encrypt 4 counter blocks =====
        "movdqu    (%0), %%xmm0"          & ASCII.LF & ASCII.HT &
        "movdqu  16(%0), %%xmm1"          & ASCII.LF & ASCII.HT &
        "movdqu  32(%0), %%xmm2"          & ASCII.LF & ASCII.HT &
        "movdqu  48(%0), %%xmm3"          & ASCII.LF & ASCII.HT &
        "movdqu    (%1), %%xmm4"          & ASCII.LF & ASCII.HT &
        "pxor    %%xmm4, %%xmm0"          & ASCII.LF & ASCII.HT &
        "pxor    %%xmm4, %%xmm1"          & ASCII.LF & ASCII.HT &
        "pxor    %%xmm4, %%xmm2"          & ASCII.LF & ASCII.HT &
        "pxor    %%xmm4, %%xmm3"          & ASCII.LF & ASCII.HT &
        "movdqu  16(%1), %%xmm4"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm0"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm1"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm2"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm3"          & ASCII.LF & ASCII.HT &
        "movdqu  32(%1), %%xmm4"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm0"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm1"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm2"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm3"          & ASCII.LF & ASCII.HT &
        "movdqu  48(%1), %%xmm4"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm0"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm1"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm2"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm3"          & ASCII.LF & ASCII.HT &
        "movdqu  64(%1), %%xmm4"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm0"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm1"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm2"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm3"          & ASCII.LF & ASCII.HT &
        "movdqu  80(%1), %%xmm4"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm0"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm1"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm2"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm3"          & ASCII.LF & ASCII.HT &
        "movdqu  96(%1), %%xmm4"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm0"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm1"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm2"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm3"          & ASCII.LF & ASCII.HT &
        "movdqu 112(%1), %%xmm4"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm0"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm1"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm2"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm3"          & ASCII.LF & ASCII.HT &
        "movdqu 128(%1), %%xmm4"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm0"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm1"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm2"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm3"          & ASCII.LF & ASCII.HT &
        "movdqu 144(%1), %%xmm4"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm0"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm1"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm2"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm3"          & ASCII.LF & ASCII.HT &
        "movdqu 160(%1), %%xmm4"          & ASCII.LF & ASCII.HT &
        "aesenclast %%xmm4, %%xmm0"       & ASCII.LF & ASCII.HT &
        "aesenclast %%xmm4, %%xmm1"       & ASCII.LF & ASCII.HT &
        "aesenclast %%xmm4, %%xmm2"       & ASCII.LF & ASCII.HT &
        "aesenclast %%xmm4, %%xmm3"       & ASCII.LF & ASCII.HT &

        --===== Phase B: XOR with plaintext + store ciphertext =====
        "movdqu    (%2), %%xmm4"          & ASCII.LF & ASCII.HT &
        "pxor    %%xmm4, %%xmm0"          & ASCII.LF & ASCII.HT &
        "movdqu  16(%2), %%xmm4"          & ASCII.LF & ASCII.HT &
        "pxor    %%xmm4, %%xmm1"          & ASCII.LF & ASCII.HT &
        "movdqu  32(%2), %%xmm4"          & ASCII.LF & ASCII.HT &
        "pxor    %%xmm4, %%xmm2"          & ASCII.LF & ASCII.HT &
        "movdqu  48(%2), %%xmm4"          & ASCII.LF & ASCII.HT &
        "pxor    %%xmm4, %%xmm3"          & ASCII.LF & ASCII.HT &
        "movdqu  %%xmm0,    (%2)"         & ASCII.LF & ASCII.HT &
        "movdqu  %%xmm1,  16(%2)"         & ASCII.LF & ASCII.HT &
        "movdqu  %%xmm2,  32(%2)"         & ASCII.LF & ASCII.HT &
        "movdqu  %%xmm3,  48(%2)"         & ASCII.LF & ASCII.HT &

        --===== Phase C: GHASH ciphertext into S =====
        "movdqa  (%5), %%xmm15"           & ASCII.LF & ASCII.HT &
        "pshufb  %%xmm15, %%xmm0"         & ASCII.LF & ASCII.HT &
        "pshufb  %%xmm15, %%xmm1"         & ASCII.LF & ASCII.HT &
        "pshufb  %%xmm15, %%xmm2"         & ASCII.LF & ASCII.HT &
        "pshufb  %%xmm15, %%xmm3"         & ASCII.LF & ASCII.HT &
        "movdqu  (%3), %%xmm4"            & ASCII.LF & ASCII.HT &
        "pshufb  %%xmm15, %%xmm4"         & ASCII.LF & ASCII.HT &
        "pxor    %%xmm4, %%xmm0"          & ASCII.LF & ASCII.HT &

        --  Block 0 * H^4 -> initialize (xmm5=lo, xmm6=hi, xmm7=mid)
        "movdqu    (%4), %%xmm4"          & ASCII.LF & ASCII.HT &
        "movdqa  %%xmm0, %%xmm5"          & ASCII.LF & ASCII.HT &
        "pclmulqdq $0x00, %%xmm4, %%xmm5" & ASCII.LF & ASCII.HT &
        "movdqa  %%xmm0, %%xmm6"          & ASCII.LF & ASCII.HT &
        "pclmulqdq $0x11, %%xmm4, %%xmm6" & ASCII.LF & ASCII.HT &
        "movdqa  %%xmm0, %%xmm7"          & ASCII.LF & ASCII.HT &
        "pclmulqdq $0x10, %%xmm4, %%xmm7" & ASCII.LF & ASCII.HT &
        "pclmulqdq $0x01, %%xmm4, %%xmm0" & ASCII.LF & ASCII.HT &
        "pxor    %%xmm0, %%xmm7"          & ASCII.LF & ASCII.HT &

        --  Block 1 * H^3
        "movdqu  16(%4), %%xmm4"          & ASCII.LF & ASCII.HT &
        "movdqa  %%xmm1, %%xmm0"          & ASCII.LF & ASCII.HT &
        "pclmulqdq $0x00, %%xmm4, %%xmm0" & ASCII.LF & ASCII.HT &
        "pxor    %%xmm0, %%xmm5"          & ASCII.LF & ASCII.HT &
        "movdqa  %%xmm1, %%xmm0"          & ASCII.LF & ASCII.HT &
        "pclmulqdq $0x11, %%xmm4, %%xmm0" & ASCII.LF & ASCII.HT &
        "pxor    %%xmm0, %%xmm6"          & ASCII.LF & ASCII.HT &
        "movdqa  %%xmm1, %%xmm0"          & ASCII.LF & ASCII.HT &
        "pclmulqdq $0x10, %%xmm4, %%xmm0" & ASCII.LF & ASCII.HT &
        "pxor    %%xmm0, %%xmm7"          & ASCII.LF & ASCII.HT &
        "pclmulqdq $0x01, %%xmm4, %%xmm1" & ASCII.LF & ASCII.HT &
        "pxor    %%xmm1, %%xmm7"          & ASCII.LF & ASCII.HT &

        --  Block 2 * H^2
        "movdqu  32(%4), %%xmm4"          & ASCII.LF & ASCII.HT &
        "movdqa  %%xmm2, %%xmm0"          & ASCII.LF & ASCII.HT &
        "pclmulqdq $0x00, %%xmm4, %%xmm0" & ASCII.LF & ASCII.HT &
        "pxor    %%xmm0, %%xmm5"          & ASCII.LF & ASCII.HT &
        "movdqa  %%xmm2, %%xmm0"          & ASCII.LF & ASCII.HT &
        "pclmulqdq $0x11, %%xmm4, %%xmm0" & ASCII.LF & ASCII.HT &
        "pxor    %%xmm0, %%xmm6"          & ASCII.LF & ASCII.HT &
        "movdqa  %%xmm2, %%xmm0"          & ASCII.LF & ASCII.HT &
        "pclmulqdq $0x10, %%xmm4, %%xmm0" & ASCII.LF & ASCII.HT &
        "pxor    %%xmm0, %%xmm7"          & ASCII.LF & ASCII.HT &
        "pclmulqdq $0x01, %%xmm4, %%xmm2" & ASCII.LF & ASCII.HT &
        "pxor    %%xmm2, %%xmm7"          & ASCII.LF & ASCII.HT &

        --  Block 3 * H
        "movdqu  48(%4), %%xmm4"          & ASCII.LF & ASCII.HT &
        "movdqa  %%xmm3, %%xmm0"          & ASCII.LF & ASCII.HT &
        "pclmulqdq $0x00, %%xmm4, %%xmm0" & ASCII.LF & ASCII.HT &
        "pxor    %%xmm0, %%xmm5"          & ASCII.LF & ASCII.HT &
        "movdqa  %%xmm3, %%xmm0"          & ASCII.LF & ASCII.HT &
        "pclmulqdq $0x11, %%xmm4, %%xmm0" & ASCII.LF & ASCII.HT &
        "pxor    %%xmm0, %%xmm6"          & ASCII.LF & ASCII.HT &
        "movdqa  %%xmm3, %%xmm0"          & ASCII.LF & ASCII.HT &
        "pclmulqdq $0x10, %%xmm4, %%xmm0" & ASCII.LF & ASCII.HT &
        "pxor    %%xmm0, %%xmm7"          & ASCII.LF & ASCII.HT &
        "pclmulqdq $0x01, %%xmm4, %%xmm3" & ASCII.LF & ASCII.HT &
        "pxor    %%xmm3, %%xmm7"          & ASCII.LF & ASCII.HT &

        --  Combine cross terms (mid -> lo & hi).
        "movdqa  %%xmm7, %%xmm0"          & ASCII.LF & ASCII.HT &
        "pslldq  $8, %%xmm0"              & ASCII.LF & ASCII.HT &
        "psrldq  $8, %%xmm7"              & ASCII.LF & ASCII.HT &
        "pxor    %%xmm0, %%xmm5"          & ASCII.LF & ASCII.HT &
        "pxor    %%xmm7, %%xmm6"          & ASCII.LF & ASCII.HT &

        --  Bit-shift correction (<<1 on xmm6:xmm5 with 32-bit lane carry).
        "movdqa  %%xmm5, %%xmm0"          & ASCII.LF & ASCII.HT &
        "movdqa  %%xmm6, %%xmm1"          & ASCII.LF & ASCII.HT &
        "psrld   $31, %%xmm0"             & ASCII.LF & ASCII.HT &
        "psrld   $31, %%xmm1"             & ASCII.LF & ASCII.HT &
        "pslld   $1, %%xmm5"              & ASCII.LF & ASCII.HT &
        "pslld   $1, %%xmm6"              & ASCII.LF & ASCII.HT &
        "movdqa  %%xmm0, %%xmm2"          & ASCII.LF & ASCII.HT &
        "psrldq  $12, %%xmm2"             & ASCII.LF & ASCII.HT &
        "pslldq  $4, %%xmm0"              & ASCII.LF & ASCII.HT &
        "pslldq  $4, %%xmm1"              & ASCII.LF & ASCII.HT &
        "por     %%xmm0, %%xmm5"          & ASCII.LF & ASCII.HT &
        "por     %%xmm1, %%xmm6"          & ASCII.LF & ASCII.HT &
        "por     %%xmm2, %%xmm6"          & ASCII.LF & ASCII.HT &

        --  Reduction mod P(x): first fold.
        "movdqa  %%xmm5, %%xmm0"          & ASCII.LF & ASCII.HT &
        "movdqa  %%xmm5, %%xmm1"          & ASCII.LF & ASCII.HT &
        "movdqa  %%xmm5, %%xmm2"          & ASCII.LF & ASCII.HT &
        "pslld   $31, %%xmm0"             & ASCII.LF & ASCII.HT &
        "pslld   $30, %%xmm1"             & ASCII.LF & ASCII.HT &
        "pslld   $25, %%xmm2"             & ASCII.LF & ASCII.HT &
        "pxor    %%xmm1, %%xmm0"          & ASCII.LF & ASCII.HT &
        "pxor    %%xmm2, %%xmm0"          & ASCII.LF & ASCII.HT &
        "movdqa  %%xmm0, %%xmm1"          & ASCII.LF & ASCII.HT &
        "psrldq  $4, %%xmm1"              & ASCII.LF & ASCII.HT &
        "pslldq  $12, %%xmm0"             & ASCII.LF & ASCII.HT &
        "pxor    %%xmm0, %%xmm5"          & ASCII.LF & ASCII.HT &

        --  Reduction: second fold (final tag in xmm6).
        "movdqa  %%xmm5, %%xmm2"          & ASCII.LF & ASCII.HT &
        "movdqa  %%xmm5, %%xmm3"          & ASCII.LF & ASCII.HT &
        "movdqa  %%xmm5, %%xmm0"          & ASCII.LF & ASCII.HT &
        "psrld   $1, %%xmm2"              & ASCII.LF & ASCII.HT &
        "psrld   $2, %%xmm3"              & ASCII.LF & ASCII.HT &
        "psrld   $7, %%xmm0"              & ASCII.LF & ASCII.HT &
        "pxor    %%xmm3, %%xmm6"          & ASCII.LF & ASCII.HT &
        "pxor    %%xmm0, %%xmm6"          & ASCII.LF & ASCII.HT &
        "pxor    %%xmm2, %%xmm6"          & ASCII.LF & ASCII.HT &
        "pxor    %%xmm1, %%xmm6"          & ASCII.LF & ASCII.HT &
        "pxor    %%xmm5, %%xmm6"          & ASCII.LF & ASCII.HT &

        --  Convert tag back to NIST byte order and store to S.
        "pshufb  %%xmm15, %%xmm6"         & ASCII.LF & ASCII.HT &
        "movdqu  %%xmm6, (%3)",

        Inputs => (System.Address'Asm_Input ("r", Counter'Address),
                   System.Address'Asm_Input ("r", Pre_RK'Address),
                   System.Address'Asm_Input ("r", Buf'Address),
                   System.Address'Asm_Input ("r", S'Address),
                   System.Address'Asm_Input ("r", H_Powers'Address),
                   System.Address'Asm_Input ("r", Ghash_Bswap_Mask'Address)),
        Clobber => "xmm0,xmm1,xmm2,xmm3,xmm4,xmm5,xmm6,xmm7,xmm15,memory",
        Volatile => True);
   end Encrypt_GCM_Stripe_4_128;

   ----------------------------------------------------------------------------
   --  Same fused stripe for AES-256 (13-round AESENC).
   ----------------------------------------------------------------------------

   procedure Encrypt_GCM_Stripe_4_256
     (Buf      : in out Byte_Seq;
      S        : in out Bytes_16;
      Counter  : in     Bytes_64;
      Pre_RK   : in     Pre_Swapped_RKs_256;
      H_Powers : in     Pre_H_Powers)
   is
   begin
      Asm
       ("movdqu    (%0), %%xmm0"          & ASCII.LF & ASCII.HT &
        "movdqu  16(%0), %%xmm1"          & ASCII.LF & ASCII.HT &
        "movdqu  32(%0), %%xmm2"          & ASCII.LF & ASCII.HT &
        "movdqu  48(%0), %%xmm3"          & ASCII.LF & ASCII.HT &
        "movdqu    (%1), %%xmm4"          & ASCII.LF & ASCII.HT &
        "pxor    %%xmm4, %%xmm0"          & ASCII.LF & ASCII.HT &
        "pxor    %%xmm4, %%xmm1"          & ASCII.LF & ASCII.HT &
        "pxor    %%xmm4, %%xmm2"          & ASCII.LF & ASCII.HT &
        "pxor    %%xmm4, %%xmm3"          & ASCII.LF & ASCII.HT &
        "movdqu  16(%1), %%xmm4"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm0"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm1"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm2"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm3"          & ASCII.LF & ASCII.HT &
        "movdqu  32(%1), %%xmm4"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm0"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm1"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm2"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm3"          & ASCII.LF & ASCII.HT &
        "movdqu  48(%1), %%xmm4"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm0"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm1"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm2"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm3"          & ASCII.LF & ASCII.HT &
        "movdqu  64(%1), %%xmm4"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm0"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm1"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm2"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm3"          & ASCII.LF & ASCII.HT &
        "movdqu  80(%1), %%xmm4"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm0"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm1"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm2"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm3"          & ASCII.LF & ASCII.HT &
        "movdqu  96(%1), %%xmm4"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm0"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm1"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm2"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm3"          & ASCII.LF & ASCII.HT &
        "movdqu 112(%1), %%xmm4"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm0"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm1"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm2"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm3"          & ASCII.LF & ASCII.HT &
        "movdqu 128(%1), %%xmm4"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm0"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm1"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm2"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm3"          & ASCII.LF & ASCII.HT &
        "movdqu 144(%1), %%xmm4"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm0"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm1"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm2"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm3"          & ASCII.LF & ASCII.HT &
        "movdqu 160(%1), %%xmm4"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm0"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm1"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm2"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm3"          & ASCII.LF & ASCII.HT &
        "movdqu 176(%1), %%xmm4"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm0"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm1"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm2"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm3"          & ASCII.LF & ASCII.HT &
        "movdqu 192(%1), %%xmm4"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm0"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm1"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm2"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm3"          & ASCII.LF & ASCII.HT &
        "movdqu 208(%1), %%xmm4"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm0"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm1"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm2"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm3"          & ASCII.LF & ASCII.HT &
        "movdqu 224(%1), %%xmm4"          & ASCII.LF & ASCII.HT &
        "aesenclast %%xmm4, %%xmm0"       & ASCII.LF & ASCII.HT &
        "aesenclast %%xmm4, %%xmm1"       & ASCII.LF & ASCII.HT &
        "aesenclast %%xmm4, %%xmm2"       & ASCII.LF & ASCII.HT &
        "aesenclast %%xmm4, %%xmm3"       & ASCII.LF & ASCII.HT &
        "movdqu    (%2), %%xmm4"          & ASCII.LF & ASCII.HT &
        "pxor    %%xmm4, %%xmm0"          & ASCII.LF & ASCII.HT &
        "movdqu  16(%2), %%xmm4"          & ASCII.LF & ASCII.HT &
        "pxor    %%xmm4, %%xmm1"          & ASCII.LF & ASCII.HT &
        "movdqu  32(%2), %%xmm4"          & ASCII.LF & ASCII.HT &
        "pxor    %%xmm4, %%xmm2"          & ASCII.LF & ASCII.HT &
        "movdqu  48(%2), %%xmm4"          & ASCII.LF & ASCII.HT &
        "pxor    %%xmm4, %%xmm3"          & ASCII.LF & ASCII.HT &
        "movdqu  %%xmm0,    (%2)"         & ASCII.LF & ASCII.HT &
        "movdqu  %%xmm1,  16(%2)"         & ASCII.LF & ASCII.HT &
        "movdqu  %%xmm2,  32(%2)"         & ASCII.LF & ASCII.HT &
        "movdqu  %%xmm3,  48(%2)"         & ASCII.LF & ASCII.HT &

        "movdqa  (%5), %%xmm15"           & ASCII.LF & ASCII.HT &
        "pshufb  %%xmm15, %%xmm0"         & ASCII.LF & ASCII.HT &
        "pshufb  %%xmm15, %%xmm1"         & ASCII.LF & ASCII.HT &
        "pshufb  %%xmm15, %%xmm2"         & ASCII.LF & ASCII.HT &
        "pshufb  %%xmm15, %%xmm3"         & ASCII.LF & ASCII.HT &
        "movdqu  (%3), %%xmm4"            & ASCII.LF & ASCII.HT &
        "pshufb  %%xmm15, %%xmm4"         & ASCII.LF & ASCII.HT &
        "pxor    %%xmm4, %%xmm0"          & ASCII.LF & ASCII.HT &

        "movdqu    (%4), %%xmm4"          & ASCII.LF & ASCII.HT &
        "movdqa  %%xmm0, %%xmm5"          & ASCII.LF & ASCII.HT &
        "pclmulqdq $0x00, %%xmm4, %%xmm5" & ASCII.LF & ASCII.HT &
        "movdqa  %%xmm0, %%xmm6"          & ASCII.LF & ASCII.HT &
        "pclmulqdq $0x11, %%xmm4, %%xmm6" & ASCII.LF & ASCII.HT &
        "movdqa  %%xmm0, %%xmm7"          & ASCII.LF & ASCII.HT &
        "pclmulqdq $0x10, %%xmm4, %%xmm7" & ASCII.LF & ASCII.HT &
        "pclmulqdq $0x01, %%xmm4, %%xmm0" & ASCII.LF & ASCII.HT &
        "pxor    %%xmm0, %%xmm7"          & ASCII.LF & ASCII.HT &

        "movdqu  16(%4), %%xmm4"          & ASCII.LF & ASCII.HT &
        "movdqa  %%xmm1, %%xmm0"          & ASCII.LF & ASCII.HT &
        "pclmulqdq $0x00, %%xmm4, %%xmm0" & ASCII.LF & ASCII.HT &
        "pxor    %%xmm0, %%xmm5"          & ASCII.LF & ASCII.HT &
        "movdqa  %%xmm1, %%xmm0"          & ASCII.LF & ASCII.HT &
        "pclmulqdq $0x11, %%xmm4, %%xmm0" & ASCII.LF & ASCII.HT &
        "pxor    %%xmm0, %%xmm6"          & ASCII.LF & ASCII.HT &
        "movdqa  %%xmm1, %%xmm0"          & ASCII.LF & ASCII.HT &
        "pclmulqdq $0x10, %%xmm4, %%xmm0" & ASCII.LF & ASCII.HT &
        "pxor    %%xmm0, %%xmm7"          & ASCII.LF & ASCII.HT &
        "pclmulqdq $0x01, %%xmm4, %%xmm1" & ASCII.LF & ASCII.HT &
        "pxor    %%xmm1, %%xmm7"          & ASCII.LF & ASCII.HT &

        "movdqu  32(%4), %%xmm4"          & ASCII.LF & ASCII.HT &
        "movdqa  %%xmm2, %%xmm0"          & ASCII.LF & ASCII.HT &
        "pclmulqdq $0x00, %%xmm4, %%xmm0" & ASCII.LF & ASCII.HT &
        "pxor    %%xmm0, %%xmm5"          & ASCII.LF & ASCII.HT &
        "movdqa  %%xmm2, %%xmm0"          & ASCII.LF & ASCII.HT &
        "pclmulqdq $0x11, %%xmm4, %%xmm0" & ASCII.LF & ASCII.HT &
        "pxor    %%xmm0, %%xmm6"          & ASCII.LF & ASCII.HT &
        "movdqa  %%xmm2, %%xmm0"          & ASCII.LF & ASCII.HT &
        "pclmulqdq $0x10, %%xmm4, %%xmm0" & ASCII.LF & ASCII.HT &
        "pxor    %%xmm0, %%xmm7"          & ASCII.LF & ASCII.HT &
        "pclmulqdq $0x01, %%xmm4, %%xmm2" & ASCII.LF & ASCII.HT &
        "pxor    %%xmm2, %%xmm7"          & ASCII.LF & ASCII.HT &

        "movdqu  48(%4), %%xmm4"          & ASCII.LF & ASCII.HT &
        "movdqa  %%xmm3, %%xmm0"          & ASCII.LF & ASCII.HT &
        "pclmulqdq $0x00, %%xmm4, %%xmm0" & ASCII.LF & ASCII.HT &
        "pxor    %%xmm0, %%xmm5"          & ASCII.LF & ASCII.HT &
        "movdqa  %%xmm3, %%xmm0"          & ASCII.LF & ASCII.HT &
        "pclmulqdq $0x11, %%xmm4, %%xmm0" & ASCII.LF & ASCII.HT &
        "pxor    %%xmm0, %%xmm6"          & ASCII.LF & ASCII.HT &
        "movdqa  %%xmm3, %%xmm0"          & ASCII.LF & ASCII.HT &
        "pclmulqdq $0x10, %%xmm4, %%xmm0" & ASCII.LF & ASCII.HT &
        "pxor    %%xmm0, %%xmm7"          & ASCII.LF & ASCII.HT &
        "pclmulqdq $0x01, %%xmm4, %%xmm3" & ASCII.LF & ASCII.HT &
        "pxor    %%xmm3, %%xmm7"          & ASCII.LF & ASCII.HT &

        "movdqa  %%xmm7, %%xmm0"          & ASCII.LF & ASCII.HT &
        "pslldq  $8, %%xmm0"              & ASCII.LF & ASCII.HT &
        "psrldq  $8, %%xmm7"              & ASCII.LF & ASCII.HT &
        "pxor    %%xmm0, %%xmm5"          & ASCII.LF & ASCII.HT &
        "pxor    %%xmm7, %%xmm6"          & ASCII.LF & ASCII.HT &

        "movdqa  %%xmm5, %%xmm0"          & ASCII.LF & ASCII.HT &
        "movdqa  %%xmm6, %%xmm1"          & ASCII.LF & ASCII.HT &
        "psrld   $31, %%xmm0"             & ASCII.LF & ASCII.HT &
        "psrld   $31, %%xmm1"             & ASCII.LF & ASCII.HT &
        "pslld   $1, %%xmm5"              & ASCII.LF & ASCII.HT &
        "pslld   $1, %%xmm6"              & ASCII.LF & ASCII.HT &
        "movdqa  %%xmm0, %%xmm2"          & ASCII.LF & ASCII.HT &
        "psrldq  $12, %%xmm2"             & ASCII.LF & ASCII.HT &
        "pslldq  $4, %%xmm0"              & ASCII.LF & ASCII.HT &
        "pslldq  $4, %%xmm1"              & ASCII.LF & ASCII.HT &
        "por     %%xmm0, %%xmm5"          & ASCII.LF & ASCII.HT &
        "por     %%xmm1, %%xmm6"          & ASCII.LF & ASCII.HT &
        "por     %%xmm2, %%xmm6"          & ASCII.LF & ASCII.HT &

        "movdqa  %%xmm5, %%xmm0"          & ASCII.LF & ASCII.HT &
        "movdqa  %%xmm5, %%xmm1"          & ASCII.LF & ASCII.HT &
        "movdqa  %%xmm5, %%xmm2"          & ASCII.LF & ASCII.HT &
        "pslld   $31, %%xmm0"             & ASCII.LF & ASCII.HT &
        "pslld   $30, %%xmm1"             & ASCII.LF & ASCII.HT &
        "pslld   $25, %%xmm2"             & ASCII.LF & ASCII.HT &
        "pxor    %%xmm1, %%xmm0"          & ASCII.LF & ASCII.HT &
        "pxor    %%xmm2, %%xmm0"          & ASCII.LF & ASCII.HT &
        "movdqa  %%xmm0, %%xmm1"          & ASCII.LF & ASCII.HT &
        "psrldq  $4, %%xmm1"              & ASCII.LF & ASCII.HT &
        "pslldq  $12, %%xmm0"             & ASCII.LF & ASCII.HT &
        "pxor    %%xmm0, %%xmm5"          & ASCII.LF & ASCII.HT &

        "movdqa  %%xmm5, %%xmm2"          & ASCII.LF & ASCII.HT &
        "movdqa  %%xmm5, %%xmm3"          & ASCII.LF & ASCII.HT &
        "movdqa  %%xmm5, %%xmm0"          & ASCII.LF & ASCII.HT &
        "psrld   $1, %%xmm2"              & ASCII.LF & ASCII.HT &
        "psrld   $2, %%xmm3"              & ASCII.LF & ASCII.HT &
        "psrld   $7, %%xmm0"              & ASCII.LF & ASCII.HT &
        "pxor    %%xmm3, %%xmm6"          & ASCII.LF & ASCII.HT &
        "pxor    %%xmm0, %%xmm6"          & ASCII.LF & ASCII.HT &
        "pxor    %%xmm2, %%xmm6"          & ASCII.LF & ASCII.HT &
        "pxor    %%xmm1, %%xmm6"          & ASCII.LF & ASCII.HT &
        "pxor    %%xmm5, %%xmm6"          & ASCII.LF & ASCII.HT &

        "pshufb  %%xmm15, %%xmm6"         & ASCII.LF & ASCII.HT &
        "movdqu  %%xmm6, (%3)",

        Inputs => (System.Address'Asm_Input ("r", Counter'Address),
                   System.Address'Asm_Input ("r", Pre_RK'Address),
                   System.Address'Asm_Input ("r", Buf'Address),
                   System.Address'Asm_Input ("r", S'Address),
                   System.Address'Asm_Input ("r", H_Powers'Address),
                   System.Address'Asm_Input ("r", Ghash_Bswap_Mask'Address)),
        Clobber => "xmm0,xmm1,xmm2,xmm3,xmm4,xmm5,xmm6,xmm7,xmm15,memory",
        Volatile => True);
   end Encrypt_GCM_Stripe_4_256;

   ----------------------------------------------------------------------------
   --  2-stripe pipelined AEAD (Step 6)
   ----------------------------------------------------------------------------
   --  AES rounds on the new stripe live in xmm0..xmm3. GHASH operates
   --  on the previous stripe (xmm5..xmm8 hold the byte-reversed
   --  ciphertext), accumulating into xmm9 (lo) / xmm10 (hi) / xmm11
   --  (mid). Round-key loads use xmm4; H_Power loads + GHASH temps
   --  use xmm12. The two phases share no register dependencies until
   --  the very end, so OOO dispatches AES to port 0 and PCLMULQDQ to
   --  port 5 in parallel, hiding GHASH behind the AES dep chain.
   ----------------------------------------------------------------------------

   procedure Encrypt_GHASH_Pipelined_4_128
     (Buf       : in out Byte_Seq;
      S         : in out Bytes_16;
      Counter   : in     Bytes_64;
      Pre_RK    : in     Pre_Swapped_RKs_128;
      H_Powers  : in     Pre_H_Powers)
   is
   begin
      Asm
       (--===== Setup: load previous ciphertext, byte-reverse, XOR S in =====
        "movdqa  (%6), %%xmm15"           & ASCII.LF & ASCII.HT &
        "movdqu    (%1), %%xmm5"          & ASCII.LF & ASCII.HT &
        "movdqu  16(%1), %%xmm6"          & ASCII.LF & ASCII.HT &
        "movdqu  32(%1), %%xmm7"          & ASCII.LF & ASCII.HT &
        "movdqu  48(%1), %%xmm8"          & ASCII.LF & ASCII.HT &
        "pshufb  %%xmm15, %%xmm5"         & ASCII.LF & ASCII.HT &
        "pshufb  %%xmm15, %%xmm6"         & ASCII.LF & ASCII.HT &
        "pshufb  %%xmm15, %%xmm7"         & ASCII.LF & ASCII.HT &
        "pshufb  %%xmm15, %%xmm8"         & ASCII.LF & ASCII.HT &
        "movdqu  (%2), %%xmm12"           & ASCII.LF & ASCII.HT &
        "pshufb  %%xmm15, %%xmm12"        & ASCII.LF & ASCII.HT &
        "pxor    %%xmm12, %%xmm5"         & ASCII.LF & ASCII.HT &

        --===== Setup: load 4 counter blocks for new stripe =====
        "movdqu    (%0), %%xmm0"          & ASCII.LF & ASCII.HT &
        "movdqu  16(%0), %%xmm1"          & ASCII.LF & ASCII.HT &
        "movdqu  32(%0), %%xmm2"          & ASCII.LF & ASCII.HT &
        "movdqu  48(%0), %%xmm3"          & ASCII.LF & ASCII.HT &

        --===== AES round 0 (AddRoundKey on xmm0..3) interleaved
        --      with GHASH block 5 × H^4 (xmm9=lo, xmm10=hi, xmm11=mid) =====
        "movdqu    (%3), %%xmm4"          & ASCII.LF & ASCII.HT &
        "pxor    %%xmm4, %%xmm0"          & ASCII.LF & ASCII.HT &
        "pxor    %%xmm4, %%xmm1"          & ASCII.LF & ASCII.HT &
        "pxor    %%xmm4, %%xmm2"          & ASCII.LF & ASCII.HT &
        "pxor    %%xmm4, %%xmm3"          & ASCII.LF & ASCII.HT &
        "movdqu    (%4), %%xmm12"         & ASCII.LF & ASCII.HT &  -- H^4
        "movdqa  %%xmm5, %%xmm9"          & ASCII.LF & ASCII.HT &
        "pclmulqdq $0x00, %%xmm12, %%xmm9"  & ASCII.LF & ASCII.HT &
        "movdqa  %%xmm5, %%xmm10"         & ASCII.LF & ASCII.HT &
        "pclmulqdq $0x11, %%xmm12, %%xmm10" & ASCII.LF & ASCII.HT &
        "movdqa  %%xmm5, %%xmm11"         & ASCII.LF & ASCII.HT &
        "pclmulqdq $0x10, %%xmm12, %%xmm11" & ASCII.LF & ASCII.HT &
        "pclmulqdq $0x01, %%xmm12, %%xmm5"  & ASCII.LF & ASCII.HT &
        "pxor    %%xmm5, %%xmm11"         & ASCII.LF & ASCII.HT &

        --===== AES round 1 + start GHASH block 6 × H^3 =====
        "movdqu  16(%3), %%xmm4"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm0"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm1"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm2"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm3"          & ASCII.LF & ASCII.HT &
        "movdqu  16(%4), %%xmm12"         & ASCII.LF & ASCII.HT &  -- H^3
        "movdqa  %%xmm6, %%xmm5"          & ASCII.LF & ASCII.HT &
        "pclmulqdq $0x00, %%xmm12, %%xmm5"  & ASCII.LF & ASCII.HT &
        "pxor    %%xmm5, %%xmm9"          & ASCII.LF & ASCII.HT &
        "movdqa  %%xmm6, %%xmm5"          & ASCII.LF & ASCII.HT &
        "pclmulqdq $0x11, %%xmm12, %%xmm5"  & ASCII.LF & ASCII.HT &
        "pxor    %%xmm5, %%xmm10"         & ASCII.LF & ASCII.HT &
        "movdqa  %%xmm6, %%xmm5"          & ASCII.LF & ASCII.HT &
        "pclmulqdq $0x10, %%xmm12, %%xmm5"  & ASCII.LF & ASCII.HT &
        "pxor    %%xmm5, %%xmm11"         & ASCII.LF & ASCII.HT &
        "pclmulqdq $0x01, %%xmm12, %%xmm6"  & ASCII.LF & ASCII.HT &
        "pxor    %%xmm6, %%xmm11"         & ASCII.LF & ASCII.HT &

        --===== AES round 2 + GHASH block 7 × H^2 =====
        "movdqu  32(%3), %%xmm4"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm0"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm1"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm2"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm3"          & ASCII.LF & ASCII.HT &
        "movdqu  32(%4), %%xmm12"         & ASCII.LF & ASCII.HT &  -- H^2
        "movdqa  %%xmm7, %%xmm5"          & ASCII.LF & ASCII.HT &
        "pclmulqdq $0x00, %%xmm12, %%xmm5"  & ASCII.LF & ASCII.HT &
        "pxor    %%xmm5, %%xmm9"          & ASCII.LF & ASCII.HT &
        "movdqa  %%xmm7, %%xmm5"          & ASCII.LF & ASCII.HT &
        "pclmulqdq $0x11, %%xmm12, %%xmm5"  & ASCII.LF & ASCII.HT &
        "pxor    %%xmm5, %%xmm10"         & ASCII.LF & ASCII.HT &
        "movdqa  %%xmm7, %%xmm5"          & ASCII.LF & ASCII.HT &
        "pclmulqdq $0x10, %%xmm12, %%xmm5"  & ASCII.LF & ASCII.HT &
        "pxor    %%xmm5, %%xmm11"         & ASCII.LF & ASCII.HT &
        "pclmulqdq $0x01, %%xmm12, %%xmm7"  & ASCII.LF & ASCII.HT &
        "pxor    %%xmm7, %%xmm11"         & ASCII.LF & ASCII.HT &

        --===== AES round 3 + GHASH block 8 × H =====
        "movdqu  48(%3), %%xmm4"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm0"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm1"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm2"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm3"          & ASCII.LF & ASCII.HT &
        "movdqu  48(%4), %%xmm12"         & ASCII.LF & ASCII.HT &  -- H
        "movdqa  %%xmm8, %%xmm5"          & ASCII.LF & ASCII.HT &
        "pclmulqdq $0x00, %%xmm12, %%xmm5"  & ASCII.LF & ASCII.HT &
        "pxor    %%xmm5, %%xmm9"          & ASCII.LF & ASCII.HT &
        "movdqa  %%xmm8, %%xmm5"          & ASCII.LF & ASCII.HT &
        "pclmulqdq $0x11, %%xmm12, %%xmm5"  & ASCII.LF & ASCII.HT &
        "pxor    %%xmm5, %%xmm10"         & ASCII.LF & ASCII.HT &
        "movdqa  %%xmm8, %%xmm5"          & ASCII.LF & ASCII.HT &
        "pclmulqdq $0x10, %%xmm12, %%xmm5"  & ASCII.LF & ASCII.HT &
        "pxor    %%xmm5, %%xmm11"         & ASCII.LF & ASCII.HT &
        "pclmulqdq $0x01, %%xmm12, %%xmm8"  & ASCII.LF & ASCII.HT &
        "pxor    %%xmm8, %%xmm11"         & ASCII.LF & ASCII.HT &

        --===== AES round 4 + GHASH cross-term combine =====
        "movdqu  64(%3), %%xmm4"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm0"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm1"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm2"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm3"          & ASCII.LF & ASCII.HT &
        --  Combine cross terms (mid -> lo & hi).
        "movdqa  %%xmm11, %%xmm5"         & ASCII.LF & ASCII.HT &
        "pslldq  $8, %%xmm5"              & ASCII.LF & ASCII.HT &
        "psrldq  $8, %%xmm11"             & ASCII.LF & ASCII.HT &
        "pxor    %%xmm5, %%xmm9"          & ASCII.LF & ASCII.HT &
        "pxor    %%xmm11, %%xmm10"        & ASCII.LF & ASCII.HT &

        --===== AES round 5 + bit-shift correction (<<1 on xmm10:xmm9) =====
        "movdqu  80(%3), %%xmm4"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm0"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm1"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm2"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm3"          & ASCII.LF & ASCII.HT &
        "movdqa  %%xmm9, %%xmm5"          & ASCII.LF & ASCII.HT &
        "movdqa  %%xmm10, %%xmm6"         & ASCII.LF & ASCII.HT &
        "psrld   $31, %%xmm5"             & ASCII.LF & ASCII.HT &
        "psrld   $31, %%xmm6"             & ASCII.LF & ASCII.HT &
        "pslld   $1, %%xmm9"              & ASCII.LF & ASCII.HT &
        "pslld   $1, %%xmm10"             & ASCII.LF & ASCII.HT &
        "movdqa  %%xmm5, %%xmm7"          & ASCII.LF & ASCII.HT &
        "psrldq  $12, %%xmm7"             & ASCII.LF & ASCII.HT &
        "pslldq  $4, %%xmm5"              & ASCII.LF & ASCII.HT &
        "pslldq  $4, %%xmm6"              & ASCII.LF & ASCII.HT &
        "por     %%xmm5, %%xmm9"          & ASCII.LF & ASCII.HT &
        "por     %%xmm6, %%xmm10"         & ASCII.LF & ASCII.HT &
        "por     %%xmm7, %%xmm10"         & ASCII.LF & ASCII.HT &

        --===== AES round 6 + reduction first fold =====
        "movdqu  96(%3), %%xmm4"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm0"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm1"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm2"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm3"          & ASCII.LF & ASCII.HT &
        "movdqa  %%xmm9, %%xmm5"          & ASCII.LF & ASCII.HT &
        "movdqa  %%xmm9, %%xmm6"          & ASCII.LF & ASCII.HT &
        "movdqa  %%xmm9, %%xmm7"          & ASCII.LF & ASCII.HT &
        "pslld   $31, %%xmm5"             & ASCII.LF & ASCII.HT &
        "pslld   $30, %%xmm6"             & ASCII.LF & ASCII.HT &
        "pslld   $25, %%xmm7"             & ASCII.LF & ASCII.HT &
        "pxor    %%xmm6, %%xmm5"          & ASCII.LF & ASCII.HT &
        "pxor    %%xmm7, %%xmm5"          & ASCII.LF & ASCII.HT &
        "movdqa  %%xmm5, %%xmm8"          & ASCII.LF & ASCII.HT &
        "psrldq  $4, %%xmm8"              & ASCII.LF & ASCII.HT &
        "pslldq  $12, %%xmm5"             & ASCII.LF & ASCII.HT &
        "pxor    %%xmm5, %%xmm9"          & ASCII.LF & ASCII.HT &

        --===== AES round 7 + reduction second fold (final tag in xmm10) =====
        "movdqu 112(%3), %%xmm4"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm0"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm1"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm2"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm3"          & ASCII.LF & ASCII.HT &
        "movdqa  %%xmm9, %%xmm5"          & ASCII.LF & ASCII.HT &
        "movdqa  %%xmm9, %%xmm6"          & ASCII.LF & ASCII.HT &
        "movdqa  %%xmm9, %%xmm7"          & ASCII.LF & ASCII.HT &
        "psrld   $1, %%xmm5"              & ASCII.LF & ASCII.HT &
        "psrld   $2, %%xmm6"              & ASCII.LF & ASCII.HT &
        "psrld   $7, %%xmm7"              & ASCII.LF & ASCII.HT &
        "pxor    %%xmm6, %%xmm10"         & ASCII.LF & ASCII.HT &
        "pxor    %%xmm7, %%xmm10"         & ASCII.LF & ASCII.HT &
        "pxor    %%xmm5, %%xmm10"         & ASCII.LF & ASCII.HT &
        "pxor    %%xmm8, %%xmm10"         & ASCII.LF & ASCII.HT &
        "pxor    %%xmm9, %%xmm10"         & ASCII.LF & ASCII.HT &

        --===== AES rounds 8..9 + store updated S =====
        "movdqu 128(%3), %%xmm4"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm0"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm1"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm2"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm3"          & ASCII.LF & ASCII.HT &
        "pshufb  %%xmm15, %%xmm10"        & ASCII.LF & ASCII.HT &
        "movdqu  %%xmm10, (%2)"           & ASCII.LF & ASCII.HT &

        "movdqu 144(%3), %%xmm4"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm0"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm1"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm2"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm3"          & ASCII.LF & ASCII.HT &

        --===== AES round 10 (aesenclast) =====
        "movdqu 160(%3), %%xmm4"          & ASCII.LF & ASCII.HT &
        "aesenclast %%xmm4, %%xmm0"       & ASCII.LF & ASCII.HT &
        "aesenclast %%xmm4, %%xmm1"       & ASCII.LF & ASCII.HT &
        "aesenclast %%xmm4, %%xmm2"       & ASCII.LF & ASCII.HT &
        "aesenclast %%xmm4, %%xmm3"       & ASCII.LF & ASCII.HT &

        --===== XOR with new plaintext, store ciphertext =====
        "movdqu    (%5), %%xmm4"          & ASCII.LF & ASCII.HT &
        "pxor    %%xmm4, %%xmm0"          & ASCII.LF & ASCII.HT &
        "movdqu  16(%5), %%xmm4"          & ASCII.LF & ASCII.HT &
        "pxor    %%xmm4, %%xmm1"          & ASCII.LF & ASCII.HT &
        "movdqu  32(%5), %%xmm4"          & ASCII.LF & ASCII.HT &
        "pxor    %%xmm4, %%xmm2"          & ASCII.LF & ASCII.HT &
        "movdqu  48(%5), %%xmm4"          & ASCII.LF & ASCII.HT &
        "pxor    %%xmm4, %%xmm3"          & ASCII.LF & ASCII.HT &
        "movdqu  %%xmm0,    (%5)"         & ASCII.LF & ASCII.HT &
        "movdqu  %%xmm1,  16(%5)"         & ASCII.LF & ASCII.HT &
        "movdqu  %%xmm2,  32(%5)"         & ASCII.LF & ASCII.HT &
        "movdqu  %%xmm3,  48(%5)",

        Inputs => (System.Address'Asm_Input ("r", Counter'Address),
                   --  GHASH region = first 64 bytes of Buf.
                   System.Address'Asm_Input ("r", Buf (Buf'First)'Address),
                   System.Address'Asm_Input ("r", S'Address),
                   System.Address'Asm_Input ("r", Pre_RK'Address),
                   System.Address'Asm_Input ("r", H_Powers'Address),
                   --  New region = bytes 64..127 of Buf.
                   System.Address'Asm_Input ("r", Buf (Buf'First + 64)'Address),
                   System.Address'Asm_Input ("r", Ghash_Bswap_Mask'Address)),
        Clobber => "xmm0,xmm1,xmm2,xmm3,xmm4,xmm5,xmm6,xmm7,xmm8," &
                   "xmm9,xmm10,xmm11,xmm12,xmm15,memory",
        Volatile => True);
   end Encrypt_GHASH_Pipelined_4_128;

   ----------------------------------------------------------------------------
   --  AES-256 variant (14 rounds): same structure, more AES rounds
   --  to interleave with the same GHASH. Easier to hide GHASH.
   ----------------------------------------------------------------------------

   procedure Encrypt_GHASH_Pipelined_4_256
     (Buf       : in out Byte_Seq;
      S         : in out Bytes_16;
      Counter   : in     Bytes_64;
      Pre_RK    : in     Pre_Swapped_RKs_256;
      H_Powers  : in     Pre_H_Powers)
   is
   begin
      Asm
       ("movdqa  (%6), %%xmm15"           & ASCII.LF & ASCII.HT &
        "movdqu    (%1), %%xmm5"          & ASCII.LF & ASCII.HT &
        "movdqu  16(%1), %%xmm6"          & ASCII.LF & ASCII.HT &
        "movdqu  32(%1), %%xmm7"          & ASCII.LF & ASCII.HT &
        "movdqu  48(%1), %%xmm8"          & ASCII.LF & ASCII.HT &
        "pshufb  %%xmm15, %%xmm5"         & ASCII.LF & ASCII.HT &
        "pshufb  %%xmm15, %%xmm6"         & ASCII.LF & ASCII.HT &
        "pshufb  %%xmm15, %%xmm7"         & ASCII.LF & ASCII.HT &
        "pshufb  %%xmm15, %%xmm8"         & ASCII.LF & ASCII.HT &
        "movdqu  (%2), %%xmm12"           & ASCII.LF & ASCII.HT &
        "pshufb  %%xmm15, %%xmm12"        & ASCII.LF & ASCII.HT &
        "pxor    %%xmm12, %%xmm5"         & ASCII.LF & ASCII.HT &

        "movdqu    (%0), %%xmm0"          & ASCII.LF & ASCII.HT &
        "movdqu  16(%0), %%xmm1"          & ASCII.LF & ASCII.HT &
        "movdqu  32(%0), %%xmm2"          & ASCII.LF & ASCII.HT &
        "movdqu  48(%0), %%xmm3"          & ASCII.LF & ASCII.HT &

        --  AES round 0 + GHASH block 5 × H^4
        "movdqu    (%3), %%xmm4"          & ASCII.LF & ASCII.HT &
        "pxor    %%xmm4, %%xmm0"          & ASCII.LF & ASCII.HT &
        "pxor    %%xmm4, %%xmm1"          & ASCII.LF & ASCII.HT &
        "pxor    %%xmm4, %%xmm2"          & ASCII.LF & ASCII.HT &
        "pxor    %%xmm4, %%xmm3"          & ASCII.LF & ASCII.HT &
        "movdqu    (%4), %%xmm12"         & ASCII.LF & ASCII.HT &
        "movdqa  %%xmm5, %%xmm9"          & ASCII.LF & ASCII.HT &
        "pclmulqdq $0x00, %%xmm12, %%xmm9"  & ASCII.LF & ASCII.HT &
        "movdqa  %%xmm5, %%xmm10"         & ASCII.LF & ASCII.HT &
        "pclmulqdq $0x11, %%xmm12, %%xmm10" & ASCII.LF & ASCII.HT &
        "movdqa  %%xmm5, %%xmm11"         & ASCII.LF & ASCII.HT &
        "pclmulqdq $0x10, %%xmm12, %%xmm11" & ASCII.LF & ASCII.HT &
        "pclmulqdq $0x01, %%xmm12, %%xmm5"  & ASCII.LF & ASCII.HT &
        "pxor    %%xmm5, %%xmm11"         & ASCII.LF & ASCII.HT &

        --  AES round 1 + GHASH block 6 × H^3
        "movdqu  16(%3), %%xmm4"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm0"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm1"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm2"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm3"          & ASCII.LF & ASCII.HT &
        "movdqu  16(%4), %%xmm12"         & ASCII.LF & ASCII.HT &
        "movdqa  %%xmm6, %%xmm5"          & ASCII.LF & ASCII.HT &
        "pclmulqdq $0x00, %%xmm12, %%xmm5"  & ASCII.LF & ASCII.HT &
        "pxor    %%xmm5, %%xmm9"          & ASCII.LF & ASCII.HT &
        "movdqa  %%xmm6, %%xmm5"          & ASCII.LF & ASCII.HT &
        "pclmulqdq $0x11, %%xmm12, %%xmm5"  & ASCII.LF & ASCII.HT &
        "pxor    %%xmm5, %%xmm10"         & ASCII.LF & ASCII.HT &
        "movdqa  %%xmm6, %%xmm5"          & ASCII.LF & ASCII.HT &
        "pclmulqdq $0x10, %%xmm12, %%xmm5"  & ASCII.LF & ASCII.HT &
        "pxor    %%xmm5, %%xmm11"         & ASCII.LF & ASCII.HT &
        "pclmulqdq $0x01, %%xmm12, %%xmm6"  & ASCII.LF & ASCII.HT &
        "pxor    %%xmm6, %%xmm11"         & ASCII.LF & ASCII.HT &

        --  AES round 2 + GHASH block 7 × H^2
        "movdqu  32(%3), %%xmm4"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm0"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm1"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm2"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm3"          & ASCII.LF & ASCII.HT &
        "movdqu  32(%4), %%xmm12"         & ASCII.LF & ASCII.HT &
        "movdqa  %%xmm7, %%xmm5"          & ASCII.LF & ASCII.HT &
        "pclmulqdq $0x00, %%xmm12, %%xmm5"  & ASCII.LF & ASCII.HT &
        "pxor    %%xmm5, %%xmm9"          & ASCII.LF & ASCII.HT &
        "movdqa  %%xmm7, %%xmm5"          & ASCII.LF & ASCII.HT &
        "pclmulqdq $0x11, %%xmm12, %%xmm5"  & ASCII.LF & ASCII.HT &
        "pxor    %%xmm5, %%xmm10"         & ASCII.LF & ASCII.HT &
        "movdqa  %%xmm7, %%xmm5"          & ASCII.LF & ASCII.HT &
        "pclmulqdq $0x10, %%xmm12, %%xmm5"  & ASCII.LF & ASCII.HT &
        "pxor    %%xmm5, %%xmm11"         & ASCII.LF & ASCII.HT &
        "pclmulqdq $0x01, %%xmm12, %%xmm7"  & ASCII.LF & ASCII.HT &
        "pxor    %%xmm7, %%xmm11"         & ASCII.LF & ASCII.HT &

        --  AES round 3 + GHASH block 8 × H
        "movdqu  48(%3), %%xmm4"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm0"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm1"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm2"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm3"          & ASCII.LF & ASCII.HT &
        "movdqu  48(%4), %%xmm12"         & ASCII.LF & ASCII.HT &
        "movdqa  %%xmm8, %%xmm5"          & ASCII.LF & ASCII.HT &
        "pclmulqdq $0x00, %%xmm12, %%xmm5"  & ASCII.LF & ASCII.HT &
        "pxor    %%xmm5, %%xmm9"          & ASCII.LF & ASCII.HT &
        "movdqa  %%xmm8, %%xmm5"          & ASCII.LF & ASCII.HT &
        "pclmulqdq $0x11, %%xmm12, %%xmm5"  & ASCII.LF & ASCII.HT &
        "pxor    %%xmm5, %%xmm10"         & ASCII.LF & ASCII.HT &
        "movdqa  %%xmm8, %%xmm5"          & ASCII.LF & ASCII.HT &
        "pclmulqdq $0x10, %%xmm12, %%xmm5"  & ASCII.LF & ASCII.HT &
        "pxor    %%xmm5, %%xmm11"         & ASCII.LF & ASCII.HT &
        "pclmulqdq $0x01, %%xmm12, %%xmm8"  & ASCII.LF & ASCII.HT &
        "pxor    %%xmm8, %%xmm11"         & ASCII.LF & ASCII.HT &

        --  AES round 4 + cross-term combine
        "movdqu  64(%3), %%xmm4"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm0"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm1"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm2"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm3"          & ASCII.LF & ASCII.HT &
        "movdqa  %%xmm11, %%xmm5"         & ASCII.LF & ASCII.HT &
        "pslldq  $8, %%xmm5"              & ASCII.LF & ASCII.HT &
        "psrldq  $8, %%xmm11"             & ASCII.LF & ASCII.HT &
        "pxor    %%xmm5, %%xmm9"          & ASCII.LF & ASCII.HT &
        "pxor    %%xmm11, %%xmm10"        & ASCII.LF & ASCII.HT &

        --  AES round 5 + bit-shift correction
        "movdqu  80(%3), %%xmm4"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm0"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm1"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm2"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm3"          & ASCII.LF & ASCII.HT &
        "movdqa  %%xmm9, %%xmm5"          & ASCII.LF & ASCII.HT &
        "movdqa  %%xmm10, %%xmm6"         & ASCII.LF & ASCII.HT &
        "psrld   $31, %%xmm5"             & ASCII.LF & ASCII.HT &
        "psrld   $31, %%xmm6"             & ASCII.LF & ASCII.HT &
        "pslld   $1, %%xmm9"              & ASCII.LF & ASCII.HT &
        "pslld   $1, %%xmm10"             & ASCII.LF & ASCII.HT &
        "movdqa  %%xmm5, %%xmm7"          & ASCII.LF & ASCII.HT &
        "psrldq  $12, %%xmm7"             & ASCII.LF & ASCII.HT &
        "pslldq  $4, %%xmm5"              & ASCII.LF & ASCII.HT &
        "pslldq  $4, %%xmm6"              & ASCII.LF & ASCII.HT &
        "por     %%xmm5, %%xmm9"          & ASCII.LF & ASCII.HT &
        "por     %%xmm6, %%xmm10"         & ASCII.LF & ASCII.HT &
        "por     %%xmm7, %%xmm10"         & ASCII.LF & ASCII.HT &

        --  AES round 6 + reduction first fold
        "movdqu  96(%3), %%xmm4"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm0"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm1"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm2"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm3"          & ASCII.LF & ASCII.HT &
        "movdqa  %%xmm9, %%xmm5"          & ASCII.LF & ASCII.HT &
        "movdqa  %%xmm9, %%xmm6"          & ASCII.LF & ASCII.HT &
        "movdqa  %%xmm9, %%xmm7"          & ASCII.LF & ASCII.HT &
        "pslld   $31, %%xmm5"             & ASCII.LF & ASCII.HT &
        "pslld   $30, %%xmm6"             & ASCII.LF & ASCII.HT &
        "pslld   $25, %%xmm7"             & ASCII.LF & ASCII.HT &
        "pxor    %%xmm6, %%xmm5"          & ASCII.LF & ASCII.HT &
        "pxor    %%xmm7, %%xmm5"          & ASCII.LF & ASCII.HT &
        "movdqa  %%xmm5, %%xmm8"          & ASCII.LF & ASCII.HT &
        "psrldq  $4, %%xmm8"              & ASCII.LF & ASCII.HT &
        "pslldq  $12, %%xmm5"             & ASCII.LF & ASCII.HT &
        "pxor    %%xmm5, %%xmm9"          & ASCII.LF & ASCII.HT &

        --  AES round 7 + reduction second fold (final tag in xmm10)
        "movdqu 112(%3), %%xmm4"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm0"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm1"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm2"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm3"          & ASCII.LF & ASCII.HT &
        "movdqa  %%xmm9, %%xmm5"          & ASCII.LF & ASCII.HT &
        "movdqa  %%xmm9, %%xmm6"          & ASCII.LF & ASCII.HT &
        "movdqa  %%xmm9, %%xmm7"          & ASCII.LF & ASCII.HT &
        "psrld   $1, %%xmm5"              & ASCII.LF & ASCII.HT &
        "psrld   $2, %%xmm6"              & ASCII.LF & ASCII.HT &
        "psrld   $7, %%xmm7"              & ASCII.LF & ASCII.HT &
        "pxor    %%xmm6, %%xmm10"         & ASCII.LF & ASCII.HT &
        "pxor    %%xmm7, %%xmm10"         & ASCII.LF & ASCII.HT &
        "pxor    %%xmm5, %%xmm10"         & ASCII.LF & ASCII.HT &
        "pxor    %%xmm8, %%xmm10"         & ASCII.LF & ASCII.HT &
        "pxor    %%xmm9, %%xmm10"         & ASCII.LF & ASCII.HT &

        --  AES rounds 8..13 (the rest)
        "movdqu 128(%3), %%xmm4"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm0"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm1"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm2"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm3"          & ASCII.LF & ASCII.HT &
        "pshufb  %%xmm15, %%xmm10"        & ASCII.LF & ASCII.HT &
        "movdqu  %%xmm10, (%2)"           & ASCII.LF & ASCII.HT &

        "movdqu 144(%3), %%xmm4"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm0"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm1"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm2"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm3"          & ASCII.LF & ASCII.HT &
        "movdqu 160(%3), %%xmm4"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm0"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm1"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm2"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm3"          & ASCII.LF & ASCII.HT &
        "movdqu 176(%3), %%xmm4"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm0"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm1"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm2"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm3"          & ASCII.LF & ASCII.HT &
        "movdqu 192(%3), %%xmm4"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm0"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm1"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm2"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm3"          & ASCII.LF & ASCII.HT &
        "movdqu 208(%3), %%xmm4"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm0"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm1"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm2"          & ASCII.LF & ASCII.HT &
        "aesenc  %%xmm4, %%xmm3"          & ASCII.LF & ASCII.HT &
        "movdqu 224(%3), %%xmm4"          & ASCII.LF & ASCII.HT &
        "aesenclast %%xmm4, %%xmm0"       & ASCII.LF & ASCII.HT &
        "aesenclast %%xmm4, %%xmm1"       & ASCII.LF & ASCII.HT &
        "aesenclast %%xmm4, %%xmm2"       & ASCII.LF & ASCII.HT &
        "aesenclast %%xmm4, %%xmm3"       & ASCII.LF & ASCII.HT &

        "movdqu    (%5), %%xmm4"          & ASCII.LF & ASCII.HT &
        "pxor    %%xmm4, %%xmm0"          & ASCII.LF & ASCII.HT &
        "movdqu  16(%5), %%xmm4"          & ASCII.LF & ASCII.HT &
        "pxor    %%xmm4, %%xmm1"          & ASCII.LF & ASCII.HT &
        "movdqu  32(%5), %%xmm4"          & ASCII.LF & ASCII.HT &
        "pxor    %%xmm4, %%xmm2"          & ASCII.LF & ASCII.HT &
        "movdqu  48(%5), %%xmm4"          & ASCII.LF & ASCII.HT &
        "pxor    %%xmm4, %%xmm3"          & ASCII.LF & ASCII.HT &
        "movdqu  %%xmm0,    (%5)"         & ASCII.LF & ASCII.HT &
        "movdqu  %%xmm1,  16(%5)"         & ASCII.LF & ASCII.HT &
        "movdqu  %%xmm2,  32(%5)"         & ASCII.LF & ASCII.HT &
        "movdqu  %%xmm3,  48(%5)",

        Inputs => (System.Address'Asm_Input ("r", Counter'Address),
                   System.Address'Asm_Input ("r", Buf (Buf'First)'Address),
                   System.Address'Asm_Input ("r", S'Address),
                   System.Address'Asm_Input ("r", Pre_RK'Address),
                   System.Address'Asm_Input ("r", H_Powers'Address),
                   System.Address'Asm_Input ("r", Buf (Buf'First + 64)'Address),
                   System.Address'Asm_Input ("r", Ghash_Bswap_Mask'Address)),
        Clobber => "xmm0,xmm1,xmm2,xmm3,xmm4,xmm5,xmm6,xmm7,xmm8," &
                   "xmm9,xmm10,xmm11,xmm12,xmm15,memory",
        Volatile => True);
   end Encrypt_GHASH_Pipelined_4_256;

   ----------------------------------------------------------------------------
   --  Vectorized 4-block counter generation
   ----------------------------------------------------------------------------

   procedure Build_Ctr_Block_4
     (CB      : in out Bytes_16;
      Counter :    out Bytes_64)
   is
   begin
      Asm
       (--  xmm14 = "reverse counter" mask (identity for IV bytes,
        --   swap of bytes 12..15 — turns BE counter into LE for PADDD).
        "movdqa  (%2), %%xmm14"           & ASCII.LF & ASCII.HT &
        --  Load CB and pre-swap counter portion.
        "movdqu  (%0), %%xmm0"            & ASCII.LF & ASCII.HT &
        "pshufb  %%xmm14, %%xmm0"         & ASCII.LF & ASCII.HT &
        --  4 copies, each with a different LE-counter increment.
        "movdqa  %%xmm0, %%xmm1"          & ASCII.LF & ASCII.HT &
        "movdqa  %%xmm0, %%xmm2"          & ASCII.LF & ASCII.HT &
        "movdqa  %%xmm0, %%xmm3"          & ASCII.LF & ASCII.HT &
        "paddd   (%3), %%xmm1"            & ASCII.LF & ASCII.HT &  -- +1
        "paddd   (%4), %%xmm2"            & ASCII.LF & ASCII.HT &  -- +2
        "paddd   (%5), %%xmm3"            & ASCII.LF & ASCII.HT &  -- +3
        "paddd   (%6), %%xmm0"            & ASCII.LF & ASCII.HT &  -- +4 -> CB+4
        --  Reverse counter portion back to BE for AES consumption.
        --  (xmm0 now holds the new CB to write back.)
        "movdqa  %%xmm0, %%xmm13"         & ASCII.LF & ASCII.HT &  -- save CB+4
        "movdqu  (%0), %%xmm0"            & ASCII.LF & ASCII.HT &  -- reload CB+0 (BE)
        --  xmm0 = CB+0 in original BE form (no swap needed)
        "pshufb  %%xmm14, %%xmm1"         & ASCII.LF & ASCII.HT &
        "pshufb  %%xmm14, %%xmm2"         & ASCII.LF & ASCII.HT &
        "pshufb  %%xmm14, %%xmm3"         & ASCII.LF & ASCII.HT &
        "pshufb  %%xmm14, %%xmm13"        & ASCII.LF & ASCII.HT &  -- CB+4 back to BE
        --  Store the 4 counter blocks and updated CB.
        "movdqu  %%xmm0,    (%1)"         & ASCII.LF & ASCII.HT &
        "movdqu  %%xmm1,  16(%1)"         & ASCII.LF & ASCII.HT &
        "movdqu  %%xmm2,  32(%1)"         & ASCII.LF & ASCII.HT &
        "movdqu  %%xmm3,  48(%1)"         & ASCII.LF & ASCII.HT &
        "movdqu  %%xmm13,  (%0)",
        Inputs => (System.Address'Asm_Input ("r", CB'Address),
                   System.Address'Asm_Input ("r", Counter'Address),
                   System.Address'Asm_Input ("r", Reverse_Ctr_Mask'Address),
                   System.Address'Asm_Input ("r", Ctr_Inc_1'Address),
                   System.Address'Asm_Input ("r", Ctr_Inc_2'Address),
                   System.Address'Asm_Input ("r", Ctr_Inc_3'Address),
                   System.Address'Asm_Input ("r", Ctr_Inc_4'Address)),
        Clobber => "xmm0,xmm1,xmm2,xmm3,xmm13,xmm14,memory",
        Volatile => True);
   end Build_Ctr_Block_4;

begin
   Has_AESNI := Detect_AES_NI;
end SPARKTLSCrypto.AES_NI;
