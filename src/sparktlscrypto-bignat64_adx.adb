--  BMI2/ADX Montgomery multiplication (body). See sparktlscrypto-bignat64_adx.ads.
--
--  SPARK_Mode Off: inline assembly. Equivalence to the SPARK Monty_Mul is
--  checked by the smoke tests on random operands and by every RSA and
--  P-256 test vector the crate runs, since the dispatchers route through
--  here whenever the CPU has BMI2 and ADX.

with System;
with System.Machine_Code;    use System.Machine_Code;
with System.Storage_Elements;

package body SPARKTLSCrypto.BigNat64_ADX with
   SPARK_Mode => Off
is
   function Addr (X : System.Address) return Unsigned_64 is
     (Unsigned_64 (System.Storage_Elements.To_Integer (X)));

   ---------------------------------------------------------------------------
   --  Generic word count (multiple of four)
   ---------------------------------------------------------------------------

   --  Parameter block read by the assembly core:
   --    0: address of T, the accumulator (Len + 2 words, zero on entry,
   --       with one spare word BEFORE it that the shifted row writes)
   --    1: address of A's words   2: address of B's words
   --    3: address of M's words   4: word count times 8
   --    5: M0I                    6: address of the result words
   type Params is array (0 .. 6) of Unsigned_64;

   --  CIOS, one a_u row then one m*M row per word of A. Each row is the
   --  two-chain form: for word v, lo(v) joins T[v] through adcx (CF
   --  chain) and hi(v-1) joins the same word through adox (OF chain);
   --  the word is stored and never read again in that row, so no load
   --  waits on a store. The m*M row stores to T[v-1], which is the CIOS
   --  shift; its first store lands in the spare word before T and is
   --  zero by construction of m. Register use:
   --    r8  T        r9  A        r10 B        r11 M
   --    r12 Len*8    r13 M0I      r14 row byte offset into A
   --    r15 byte index within a row   rcx block counter (jrcxz)
   --    rdx multiplier   rax low half   rsi/rbx alternate high halves
   --  lea, mov, mulx, jrcxz and jmp leave CF and OF alone, which is what
   --  lets the two chains run across the whole row. After the last row
   --  T[0 .. Len - 1] holds the unreduced result and T[Len] its top bit;
   --  the core then subtracts M into the result words with an sbb chain
   --  (loop control by lea/jrcxz, which leave CF alone) and, from the
   --  final borrow and the top bit, forms an all-ones or all-zero mask
   --  that selects the unreduced value or the difference word by word:
   --  no branch on the data. "sbb $0" on the top word folds the top bit
   --  in; "sbb %rbx,%rbx" turns the resulting borrow into the mask, all
   --  ones meaning T < M, keep T.
   --  Both cores clear every general register they used before returning,
   --  so no operand or partial product outlives the call in a register.
   procedure Core (P : Params) with No_Inline;

   procedure Core (P : Params) is
   begin
      Asm (
         ".macro MROW src, sh" & ASCII.LF &
         "    mov  %%r12, %%rcx" & ASCII.LF &
         "    shr  $5, %%rcx" & ASCII.LF &
         "    xor  %%r15d, %%r15d" & ASCII.LF &
         "    mov  $0, %%ebx" & ASCII.LF &
         "1:" & ASCII.LF &
         "    mulx (\src,%%r15), %%rax, %%rsi" & ASCII.LF &
         "    adcx (%%r8,%%r15), %%rax" & ASCII.LF &
         "    adox %%rbx, %%rax" & ASCII.LF &
         "    mov  %%rax, \sh(%%r8,%%r15)" & ASCII.LF &
         "    mulx 8(\src,%%r15), %%rax, %%rbx" & ASCII.LF &
         "    adcx 8(%%r8,%%r15), %%rax" & ASCII.LF &
         "    adox %%rsi, %%rax" & ASCII.LF &
         "    mov  %%rax, 8+\sh(%%r8,%%r15)" & ASCII.LF &
         "    mulx 16(\src,%%r15), %%rax, %%rsi" & ASCII.LF &
         "    adcx 16(%%r8,%%r15), %%rax" & ASCII.LF &
         "    adox %%rbx, %%rax" & ASCII.LF &
         "    mov  %%rax, 16+\sh(%%r8,%%r15)" & ASCII.LF &
         "    mulx 24(\src,%%r15), %%rax, %%rbx" & ASCII.LF &
         "    adcx 24(%%r8,%%r15), %%rax" & ASCII.LF &
         "    adox %%rsi, %%rax" & ASCII.LF &
         "    mov  %%rax, 24+\sh(%%r8,%%r15)" & ASCII.LF &
         "    lea  32(%%r15), %%r15" & ASCII.LF &
         "    lea  -1(%%rcx), %%rcx" & ASCII.LF &
         "    jrcxz 2f" & ASCII.LF &
         "    jmp  1b" & ASCII.LF &
         "2:" & ASCII.LF &
         "    mov  $0, %%esi" & ASCII.LF &
         "    mov  (%%r8,%%r15), %%rax" & ASCII.LF &
         "    adcx %%rbx, %%rax" & ASCII.LF &
         "    adox %%rsi, %%rax" & ASCII.LF &
         "    mov  %%rax, \sh(%%r8,%%r15)" & ASCII.LF &
         "    mov  8(%%r8,%%r15), %%rax" & ASCII.LF &
         "    adcx %%rsi, %%rax" & ASCII.LF &
         "    adox %%rsi, %%rax" & ASCII.LF &
         "    mov  %%rax, 8+\sh(%%r8,%%r15)" & ASCII.LF &
         ".endm" & ASCII.LF &
         "    mov  0(%0), %%r8" & ASCII.LF &
         "    mov  8(%0), %%r9" & ASCII.LF &
         "    mov  16(%0), %%r10" & ASCII.LF &
         "    mov  24(%0), %%r11" & ASCII.LF &
         "    mov  32(%0), %%r12" & ASCII.LF &
         "    mov  40(%0), %%r13" & ASCII.LF &
         "    xor  %%r14d, %%r14d" & ASCII.LF &
         "3:" & ASCII.LF &
         "    mov  (%%r9,%%r14), %%rdx" & ASCII.LF &
         "    MROW %%r10, 0" & ASCII.LF &
         "    mov  (%%r8), %%rdx" & ASCII.LF &
         "    imul %%r13, %%rdx" & ASCII.LF &
         "    MROW %%r11, -8" & ASCII.LF &
         "    movq $0, 8(%%r8,%%r12)" & ASCII.LF &
         "    add  $8, %%r14" & ASCII.LF &
         "    cmp  %%r14, %%r12" & ASCII.LF &
         "    jne  3b" & ASCII.LF &
         ".purgem MROW" & ASCII.LF &
         "    mov  48(%0), %%r9" & ASCII.LF &
         "    mov  %%r12, %%rcx" & ASCII.LF &
         "    shr  $3, %%rcx" & ASCII.LF &
         "    xor  %%r15d, %%r15d" & ASCII.LF &
         "    xor  %%ebx, %%ebx" & ASCII.LF &
         "4:" & ASCII.LF &
         "    mov  (%%r8,%%r15), %%rax" & ASCII.LF &
         "    sbb  (%%r11,%%r15), %%rax" & ASCII.LF &
         "    mov  %%rax, (%%r9,%%r15)" & ASCII.LF &
         "    lea  8(%%r15), %%r15" & ASCII.LF &
         "    lea  -1(%%rcx), %%rcx" & ASCII.LF &
         "    jrcxz 6f" & ASCII.LF &
         "    jmp  4b" & ASCII.LF &
         "6:" & ASCII.LF &
         "    mov  (%%r8,%%r12), %%rax" & ASCII.LF &
         "    sbb  $0, %%rax" & ASCII.LF &
         "    sbb  %%rbx, %%rbx" & ASCII.LF &
         "    xor  %%r15d, %%r15d" & ASCII.LF &
         "5:" & ASCII.LF &
         "    mov  (%%r9,%%r15), %%rax" & ASCII.LF &
         "    mov  (%%r8,%%r15), %%rdx" & ASCII.LF &
         "    xor  %%rax, %%rdx" & ASCII.LF &
         "    and  %%rbx, %%rdx" & ASCII.LF &
         "    xor  %%rdx, %%rax" & ASCII.LF &
         "    mov  %%rax, (%%r9,%%r15)" & ASCII.LF &
         "    lea  8(%%r15), %%r15" & ASCII.LF &
         "    cmp  %%r15, %%r12" & ASCII.LF &
         "    jne  5b" & ASCII.LF &
         "    xor  %%eax, %%eax" & ASCII.LF &
         "    xor  %%ebx, %%ebx" & ASCII.LF &
         "    xor  %%ecx, %%ecx" & ASCII.LF &
         "    xor  %%edx, %%edx" & ASCII.LF &
         "    xor  %%esi, %%esi" & ASCII.LF &
         "    xor  %%r8d, %%r8d" & ASCII.LF &
         "    xor  %%r9d, %%r9d" & ASCII.LF &
         "    xor  %%r10d, %%r10d" & ASCII.LF &
         "    xor  %%r11d, %%r11d" & ASCII.LF &
         "    xor  %%r12d, %%r12d" & ASCII.LF &
         "    xor  %%r13d, %%r13d" & ASCII.LF &
         "    xor  %%r14d, %%r14d" & ASCII.LF &
         "    xor  %%r15d, %%r15d" & ASCII.LF,

         Inputs   => System.Address'Asm_Input ("r", P'Address),
         Clobber  => "rax,rbx,rcx,rdx,rsi,r8,r9,r10,r11,r12,r13,r14,r15,"
                     & "memory,cc",
         Volatile => True);
   end Core;

   procedure Monty_Mul
     (Result : out Big_Nat;
      A, B   : in  Big_Nat;
      M      : in  Big_Nat;
      M0I    : in  Word)
   is
      Len     : constant Word_Count := M.Len;
      --  Scratch (0) is the spare word; T is Scratch (1 .. Len + 2).
      Scratch : array (0 .. Max_Words + 3) of Word;
      P       : Params;
   begin
      Scratch (0 .. Len + 2) := (others => 0);
      Result.Len := Len;
      Result.W   := (others => 0);
      P := (Addr (Scratch (1)'Address), Addr (A.W'Address),
            Addr (B.W'Address), Addr (M.W'Address),
            Unsigned_64 (Len) * 8, M0I, Addr (Result.W'Address));
      Core (P);
      --  Scratch held the unreduced product of possibly secret operands;
      --  the parameter block holds M0I, which is -M^-1 mod 2^64 and so a
      --  function of a secret modulus on the CRT path.
      Scratch (0 .. Len + 2) := (others => 0);
      P := (others => 0);
      pragma Inspection_Point (Scratch);
      pragma Inspection_Point (P);
   end Monty_Mul;

   ---------------------------------------------------------------------------
   --  Squaring, generic word count (multiple of four)
   ---------------------------------------------------------------------------

   --  Parameter block: 0: T (2 Len + 2 words, zero on entry), 1: A's
   --  words, 2: M, 3: Len * 8, 4: M0I, 5: result words.
   type Sqr_Params is array (0 .. 5) of Unsigned_64;

   --  Separated Montgomery squaring. Phase 1 adds the off-diagonal
   --  products a_u * a_v (v > u) once: row u, multiplier a_u, runs over
   --  a_(u+1) .. a_(Len-1) and starts at word 2u + 1, so its two fold
   --  words are Len + u and Len + u + 1 and move up by exactly one word
   --  per row. That is what lets a row's carry out of its top fold word
   --  be kept in a register and added into the next row's second fold
   --  word instead of being chased through memory. Rows have exact
   --  lengths (blocks of four, then a scalar tail of 0 .. 3 words). Phase
   --  2 doubles the accumulator with one adc chain; phase 3 adds a_u^2
   --  into words 2u, 2u + 1 along one adcx chain; phase 4 is the Len
   --  reduction rows of the multiply core, each based one word higher,
   --  whose fold words Len + i, Len + i + 1 again move up by one per row,
   --  so the same pending-carry register handles them. The result lands
   --  in T (Len .. 2 Len - 1) with its top bit in T (2 Len); the
   --  constant-time final subtraction is the one from Core. 16 words:
   --  120 + 16 + 256 = 392 mulx against 512 for the multiply.
   procedure Sqr_Core (P : Sqr_Params) with No_Inline;

   procedure Sqr_Core (P : Sqr_Params) is
   begin
      Asm (
         ".macro SROW src, len, pend" & ASCII.LF &
         "    mov  \len, %%rcx" & ASCII.LF &
         "    shr  $5, %%rcx" & ASCII.LF &
         "    and  $24, \len" & ASCII.LF &
         "    shr  $3, \len" & ASCII.LF &
         "    xor  %%r15d, %%r15d" & ASCII.LF &
         "    mov  $0, %%ebx" & ASCII.LF &
         "1:" & ASCII.LF &
         "    jrcxz 2f" & ASCII.LF &
         "    mulx (\src,%%r15), %%rax, %%rsi" & ASCII.LF &
         "    adcx (%%r8,%%r15), %%rax" & ASCII.LF &
         "    adox %%rbx, %%rax" & ASCII.LF &
         "    mov  %%rax, (%%r8,%%r15)" & ASCII.LF &
         "    mulx 8(\src,%%r15), %%rax, %%rbx" & ASCII.LF &
         "    adcx 8(%%r8,%%r15), %%rax" & ASCII.LF &
         "    adox %%rsi, %%rax" & ASCII.LF &
         "    mov  %%rax, 8(%%r8,%%r15)" & ASCII.LF &
         "    mulx 16(\src,%%r15), %%rax, %%rsi" & ASCII.LF &
         "    adcx 16(%%r8,%%r15), %%rax" & ASCII.LF &
         "    adox %%rbx, %%rax" & ASCII.LF &
         "    mov  %%rax, 16(%%r8,%%r15)" & ASCII.LF &
         "    mulx 24(\src,%%r15), %%rax, %%rbx" & ASCII.LF &
         "    adcx 24(%%r8,%%r15), %%rax" & ASCII.LF &
         "    adox %%rsi, %%rax" & ASCII.LF &
         "    mov  %%rax, 24(%%r8,%%r15)" & ASCII.LF &
         "    lea  32(%%r15), %%r15" & ASCII.LF &
         "    lea  -1(%%rcx), %%rcx" & ASCII.LF &
         "    jmp  1b" & ASCII.LF &
         "2:" & ASCII.LF &
         "    mov  \len, %%rcx" & ASCII.LF &
         "3:" & ASCII.LF &
         "    jrcxz 4f" & ASCII.LF &
         "    mulx (\src,%%r15), %%rax, %%rsi" & ASCII.LF &
         "    adcx (%%r8,%%r15), %%rax" & ASCII.LF &
         "    adox %%rbx, %%rax" & ASCII.LF &
         "    mov  %%rax, (%%r8,%%r15)" & ASCII.LF &
         "    mov  %%rsi, %%rbx" & ASCII.LF &
         "    lea  8(%%r15), %%r15" & ASCII.LF &
         "    lea  -1(%%rcx), %%rcx" & ASCII.LF &
         "    jmp  3b" & ASCII.LF &
         "4:" & ASCII.LF &
         "    mov  $0, %%esi" & ASCII.LF &
         "    mov  (%%r8,%%r15), %%rax" & ASCII.LF &
         "    adcx %%rbx, %%rax" & ASCII.LF &
         "    adox %%rsi, %%rax" & ASCII.LF &
         "    mov  %%rax, (%%r8,%%r15)" & ASCII.LF &
         "    mov  8(%%r8,%%r15), %%rax" & ASCII.LF &
         "    adox %%rsi, %%rax" & ASCII.LF &
         "    adcx \pend, %%rax" & ASCII.LF &
         "    mov  %%rax, 8(%%r8,%%r15)" & ASCII.LF &
         "    mov  $0, \pend" & ASCII.LF &
         "    adcx %%rsi, \pend" & ASCII.LF &
         "    adox %%rsi, \pend" & ASCII.LF &
         ".endm" & ASCII.LF &
         "    mov  0(%0), %%r8" & ASCII.LF &
         "    mov  8(%0), %%r9" & ASCII.LF &
         "    mov  24(%0), %%r12" & ASCII.LF &
         "    xor  %%r11d, %%r11d" & ASCII.LF &
         "    mov  $8, %%r14" & ASCII.LF &
         "5:" & ASCII.LF &
         "    mov  %%r12, %%r13" & ASCII.LF &
         "    sub  %%r14, %%r13" & ASCII.LF &
         "    jbe  7f" & ASCII.LF &
         "    mov  0(%0), %%r8" & ASCII.LF &
         "    lea  -8(%%r8,%%r14,2), %%r8" & ASCII.LF &
         "    mov  8(%0), %%r10" & ASCII.LF &
         "    add  %%r14, %%r10" & ASCII.LF &
         "    mov  -8(%%r10), %%rdx" & ASCII.LF &
         "    SROW %%r10, %%r13, %%r11" & ASCII.LF &
         "    add  $8, %%r14" & ASCII.LF &
         "    jmp  5b" & ASCII.LF &
         "7:" & ASCII.LF &
         "    mov  0(%0), %%r8" & ASCII.LF &
         "    add  %%r11, (%%r8,%%r12,2)" & ASCII.LF &
         "    adcq $0, 8(%%r8,%%r12,2)" & ASCII.LF &
         "    mov  %%r12, %%rcx" & ASCII.LF &
         "    shr  $3, %%rcx" & ASCII.LF &
         "    lea  2(%%rcx,%%rcx), %%rcx" & ASCII.LF &
         "    xor  %%r15d, %%r15d" & ASCII.LF &
         "8:" & ASCII.LF &
         "    mov  (%%r8,%%r15), %%rax" & ASCII.LF &
         "    adc  %%rax, %%rax" & ASCII.LF &
         "    mov  %%rax, (%%r8,%%r15)" & ASCII.LF &
         "    lea  8(%%r15), %%r15" & ASCII.LF &
         "    lea  -1(%%rcx), %%rcx" & ASCII.LF &
         "    jrcxz 9f" & ASCII.LF &
         "    jmp  8b" & ASCII.LF &
         "9:" & ASCII.LF &
         "    mov  %%r12, %%rcx" & ASCII.LF &
         "    shr  $3, %%rcx" & ASCII.LF &
         "    xor  %%r14d, %%r14d" & ASCII.LF &
         "10:" & ASCII.LF &
         "    mov  (%%r9,%%r14), %%rdx" & ASCII.LF &
         "    mulx %%rdx, %%rax, %%rbx" & ASCII.LF &
         "    adcx (%%r8,%%r14,2), %%rax" & ASCII.LF &
         "    mov  %%rax, (%%r8,%%r14,2)" & ASCII.LF &
         "    adcx 8(%%r8,%%r14,2), %%rbx" & ASCII.LF &
         "    mov  %%rbx, 8(%%r8,%%r14,2)" & ASCII.LF &
         "    lea  8(%%r14), %%r14" & ASCII.LF &
         "    lea  -1(%%rcx), %%rcx" & ASCII.LF &
         "    jrcxz 11f" & ASCII.LF &
         "    jmp  10b" & ASCII.LF &
         "11:" & ASCII.LF &
         "    mov  (%%r8,%%r12,2), %%rax" & ASCII.LF &
         "    adcx %%rcx, %%rax" & ASCII.LF &
         "    mov  %%rax, (%%r8,%%r12,2)" & ASCII.LF &
         "    mov  8(%%r8,%%r12,2), %%rax" & ASCII.LF &
         "    adcx %%rcx, %%rax" & ASCII.LF &
         "    mov  %%rax, 8(%%r8,%%r12,2)" & ASCII.LF &
         "    mov  16(%0), %%r11" & ASCII.LF &
         "    mov  32(%0), %%r13" & ASCII.LF &
         "    xor  %%r9d, %%r9d" & ASCII.LF &
         "    xor  %%r14d, %%r14d" & ASCII.LF &
         "12:" & ASCII.LF &
         "    mov  (%%r8), %%rdx" & ASCII.LF &
         "    imul %%r13, %%rdx" & ASCII.LF &
         "    mov  %%r12, %%r10" & ASCII.LF &
         "    SROW %%r11, %%r10, %%r9" & ASCII.LF &
         "    lea  8(%%r8), %%r8" & ASCII.LF &
         "    add  $8, %%r14" & ASCII.LF &
         "    cmp  %%r14, %%r12" & ASCII.LF &
         "    jne  12b" & ASCII.LF &
         ".purgem SROW" & ASCII.LF &
         "    add  %%r9, 8(%%r8,%%r12)" & ASCII.LF &
         "    mov  40(%0), %%r9" & ASCII.LF &
         "    mov  %%r12, %%rcx" & ASCII.LF &
         "    shr  $3, %%rcx" & ASCII.LF &
         "    xor  %%r15d, %%r15d" & ASCII.LF &
         "    xor  %%ebx, %%ebx" & ASCII.LF &
         "13:" & ASCII.LF &
         "    mov  (%%r8,%%r15), %%rax" & ASCII.LF &
         "    sbb  (%%r11,%%r15), %%rax" & ASCII.LF &
         "    mov  %%rax, (%%r9,%%r15)" & ASCII.LF &
         "    lea  8(%%r15), %%r15" & ASCII.LF &
         "    lea  -1(%%rcx), %%rcx" & ASCII.LF &
         "    jrcxz 14f" & ASCII.LF &
         "    jmp  13b" & ASCII.LF &
         "14:" & ASCII.LF &
         "    mov  (%%r8,%%r12), %%rax" & ASCII.LF &
         "    sbb  $0, %%rax" & ASCII.LF &
         "    sbb  %%rbx, %%rbx" & ASCII.LF &
         "    xor  %%r15d, %%r15d" & ASCII.LF &
         "15:" & ASCII.LF &
         "    mov  (%%r9,%%r15), %%rax" & ASCII.LF &
         "    mov  (%%r8,%%r15), %%rdx" & ASCII.LF &
         "    xor  %%rax, %%rdx" & ASCII.LF &
         "    and  %%rbx, %%rdx" & ASCII.LF &
         "    xor  %%rdx, %%rax" & ASCII.LF &
         "    mov  %%rax, (%%r9,%%r15)" & ASCII.LF &
         "    lea  8(%%r15), %%r15" & ASCII.LF &
         "    cmp  %%r15, %%r12" & ASCII.LF &
         "    jne  15b" & ASCII.LF &
         "    xor  %%eax, %%eax" & ASCII.LF &
         "    xor  %%ebx, %%ebx" & ASCII.LF &
         "    xor  %%ecx, %%ecx" & ASCII.LF &
         "    xor  %%edx, %%edx" & ASCII.LF &
         "    xor  %%esi, %%esi" & ASCII.LF &
         "    xor  %%r8d, %%r8d" & ASCII.LF &
         "    xor  %%r9d, %%r9d" & ASCII.LF &
         "    xor  %%r10d, %%r10d" & ASCII.LF &
         "    xor  %%r11d, %%r11d" & ASCII.LF &
         "    xor  %%r12d, %%r12d" & ASCII.LF &
         "    xor  %%r13d, %%r13d" & ASCII.LF &
         "    xor  %%r14d, %%r14d" & ASCII.LF &
         "    xor  %%r15d, %%r15d" & ASCII.LF,
         Inputs   => System.Address'Asm_Input ("r", P'Address),
         Clobber  => "rax,rbx,rcx,rdx,rsi,r8,r9,r10,r11,r12,r13,r14,r15,"
                     & "memory,cc",
         Volatile => True);
   end Sqr_Core;

   procedure Monty_Sqr
     (Result : out Big_Nat;
      A      : in  Big_Nat;
      M      : in  Big_Nat;
      M0I    : in  Word)
   is
      Len : constant Word_Count := M.Len;
      T   : array (0 .. 2 * Max_Words + 1) of Word;
      P   : Sqr_Params;
   begin
      T (0 .. 2 * Len + 1) := (others => 0);
      Result.Len := Len;
      Result.W   := (others => 0);
      P := (Addr (T'Address), Addr (A.W'Address), Addr (M.W'Address),
            Unsigned_64 (Len) * 8, M0I, Addr (Result.W'Address));
      Sqr_Core (P);
      T (0 .. 2 * Len + 1) := (others => 0);
      P := (others => 0);
      pragma Inspection_Point (T);
      pragma Inspection_Point (P);
   end Monty_Sqr;

   ---------------------------------------------------------------------------
   --  P-256, four limbs, fully unrolled, accumulator in registers
   ---------------------------------------------------------------------------

   subtype FE is SPARKTLSCrypto.Fiat_P256.FE;

   --  p = 2^256 - 2^224 + 2^192 + 2^96 - 1; its low limb is 2^64 - 1, so
   --  -p^-1 mod 2^64 = 1 and the Montgomery factor of each row is the
   --  accumulator's low word itself. The limbs are immediates in the code
   --  (the third is 0, so that product is skipped and only the carries
   --  propagate), so the routine takes just the three addresses and can
   --  be inlined into the point arithmetic: no parameter block, no call.
   --
   --  Four CIOS rows on the six registers r8 .. r13, whose roles rotate
   --  one place per row: the row's t0 becomes zero in its reduction step
   --  and serves as the next row's empty top word, so the CIOS shift is
   --  a renaming. Each row is the same two-chain form as the generic
   --  core. The final conditional subtraction is a sub/sbb chain into
   --  copies with cmovc selecting the original when it borrows: no
   --  branch on the data. Every scratch register is cleared on exit.
   procedure Mont_Mul_P256 (R : out FE; A, B : in FE) is
   begin
      Asm (
         "    xor  %%r8d, %%r8d" & ASCII.LF &
         "    xor  %%r9d, %%r9d" & ASCII.LF &
         "    xor  %%r10d, %%r10d" & ASCII.LF &
         "    xor  %%r11d, %%r11d" & ASCII.LF &
         "    xor  %%r12d, %%r12d" & ASCII.LF &
         "    xor  %%r13d, %%r13d" & ASCII.LF &
         "    mov  0(%0), %%rdx" & ASCII.LF &
         "    xor  %%ecx, %%ecx" & ASCII.LF &
         "    mulx 0(%1), %%rax, %%rbx" & ASCII.LF &
         "    adcx %%rax, %%r8" & ASCII.LF &
         "    mulx 8(%1), %%rax, %%rsi" & ASCII.LF &
         "    adox %%rbx, %%r9" & ASCII.LF &
         "    adcx %%rax, %%r9" & ASCII.LF &
         "    mulx 16(%1), %%rax, %%rbx" & ASCII.LF &
         "    adox %%rsi, %%r10" & ASCII.LF &
         "    adcx %%rax, %%r10" & ASCII.LF &
         "    mulx 24(%1), %%rax, %%rsi" & ASCII.LF &
         "    adox %%rbx, %%r11" & ASCII.LF &
         "    adcx %%rax, %%r11" & ASCII.LF &
         "    adox %%rsi, %%r12" & ASCII.LF &
         "    adcx %%rcx, %%r12" & ASCII.LF &
         "    adox %%rcx, %%r13" & ASCII.LF &
         "    adcx %%rcx, %%r13" & ASCII.LF &
         "    mov  %%r8, %%rdx" & ASCII.LF &
         "    xor  %%ecx, %%ecx" & ASCII.LF &
         "    mov  $-1, %%rbx" & ASCII.LF &
         "    mulx %%rbx, %%rax, %%rbx" & ASCII.LF &
         "    adcx %%rax, %%r8" & ASCII.LF &
         "    mov  $0xFFFFFFFF, %%esi" & ASCII.LF &
         "    mulx %%rsi, %%rax, %%rsi" & ASCII.LF &
         "    adox %%rbx, %%r9" & ASCII.LF &
         "    adcx %%rax, %%r9" & ASCII.LF &
         "    adox %%rsi, %%r10" & ASCII.LF &
         "    adcx %%rcx, %%r10" & ASCII.LF &
         "    movabs $0xFFFFFFFF00000001, %%rbx" & ASCII.LF &
         "    mulx %%rbx, %%rax, %%rbx" & ASCII.LF &
         "    adox %%rcx, %%r11" & ASCII.LF &
         "    adcx %%rax, %%r11" & ASCII.LF &
         "    adox %%rbx, %%r12" & ASCII.LF &
         "    adcx %%rcx, %%r12" & ASCII.LF &
         "    adox %%rcx, %%r13" & ASCII.LF &
         "    adcx %%rcx, %%r13" & ASCII.LF &
         "    mov  8(%0), %%rdx" & ASCII.LF &
         "    xor  %%ecx, %%ecx" & ASCII.LF &
         "    mulx 0(%1), %%rax, %%rbx" & ASCII.LF &
         "    adcx %%rax, %%r9" & ASCII.LF &
         "    mulx 8(%1), %%rax, %%rsi" & ASCII.LF &
         "    adox %%rbx, %%r10" & ASCII.LF &
         "    adcx %%rax, %%r10" & ASCII.LF &
         "    mulx 16(%1), %%rax, %%rbx" & ASCII.LF &
         "    adox %%rsi, %%r11" & ASCII.LF &
         "    adcx %%rax, %%r11" & ASCII.LF &
         "    mulx 24(%1), %%rax, %%rsi" & ASCII.LF &
         "    adox %%rbx, %%r12" & ASCII.LF &
         "    adcx %%rax, %%r12" & ASCII.LF &
         "    adox %%rsi, %%r13" & ASCII.LF &
         "    adcx %%rcx, %%r13" & ASCII.LF &
         "    adox %%rcx, %%r8" & ASCII.LF &
         "    adcx %%rcx, %%r8" & ASCII.LF &
         "    mov  %%r9, %%rdx" & ASCII.LF &
         "    xor  %%ecx, %%ecx" & ASCII.LF &
         "    mov  $-1, %%rbx" & ASCII.LF &
         "    mulx %%rbx, %%rax, %%rbx" & ASCII.LF &
         "    adcx %%rax, %%r9" & ASCII.LF &
         "    mov  $0xFFFFFFFF, %%esi" & ASCII.LF &
         "    mulx %%rsi, %%rax, %%rsi" & ASCII.LF &
         "    adox %%rbx, %%r10" & ASCII.LF &
         "    adcx %%rax, %%r10" & ASCII.LF &
         "    adox %%rsi, %%r11" & ASCII.LF &
         "    adcx %%rcx, %%r11" & ASCII.LF &
         "    movabs $0xFFFFFFFF00000001, %%rbx" & ASCII.LF &
         "    mulx %%rbx, %%rax, %%rbx" & ASCII.LF &
         "    adox %%rcx, %%r12" & ASCII.LF &
         "    adcx %%rax, %%r12" & ASCII.LF &
         "    adox %%rbx, %%r13" & ASCII.LF &
         "    adcx %%rcx, %%r13" & ASCII.LF &
         "    adox %%rcx, %%r8" & ASCII.LF &
         "    adcx %%rcx, %%r8" & ASCII.LF &
         "    mov  16(%0), %%rdx" & ASCII.LF &
         "    xor  %%ecx, %%ecx" & ASCII.LF &
         "    mulx 0(%1), %%rax, %%rbx" & ASCII.LF &
         "    adcx %%rax, %%r10" & ASCII.LF &
         "    mulx 8(%1), %%rax, %%rsi" & ASCII.LF &
         "    adox %%rbx, %%r11" & ASCII.LF &
         "    adcx %%rax, %%r11" & ASCII.LF &
         "    mulx 16(%1), %%rax, %%rbx" & ASCII.LF &
         "    adox %%rsi, %%r12" & ASCII.LF &
         "    adcx %%rax, %%r12" & ASCII.LF &
         "    mulx 24(%1), %%rax, %%rsi" & ASCII.LF &
         "    adox %%rbx, %%r13" & ASCII.LF &
         "    adcx %%rax, %%r13" & ASCII.LF &
         "    adox %%rsi, %%r8" & ASCII.LF &
         "    adcx %%rcx, %%r8" & ASCII.LF &
         "    adox %%rcx, %%r9" & ASCII.LF &
         "    adcx %%rcx, %%r9" & ASCII.LF &
         "    mov  %%r10, %%rdx" & ASCII.LF &
         "    xor  %%ecx, %%ecx" & ASCII.LF &
         "    mov  $-1, %%rbx" & ASCII.LF &
         "    mulx %%rbx, %%rax, %%rbx" & ASCII.LF &
         "    adcx %%rax, %%r10" & ASCII.LF &
         "    mov  $0xFFFFFFFF, %%esi" & ASCII.LF &
         "    mulx %%rsi, %%rax, %%rsi" & ASCII.LF &
         "    adox %%rbx, %%r11" & ASCII.LF &
         "    adcx %%rax, %%r11" & ASCII.LF &
         "    adox %%rsi, %%r12" & ASCII.LF &
         "    adcx %%rcx, %%r12" & ASCII.LF &
         "    movabs $0xFFFFFFFF00000001, %%rbx" & ASCII.LF &
         "    mulx %%rbx, %%rax, %%rbx" & ASCII.LF &
         "    adox %%rcx, %%r13" & ASCII.LF &
         "    adcx %%rax, %%r13" & ASCII.LF &
         "    adox %%rbx, %%r8" & ASCII.LF &
         "    adcx %%rcx, %%r8" & ASCII.LF &
         "    adox %%rcx, %%r9" & ASCII.LF &
         "    adcx %%rcx, %%r9" & ASCII.LF &
         "    mov  24(%0), %%rdx" & ASCII.LF &
         "    xor  %%ecx, %%ecx" & ASCII.LF &
         "    mulx 0(%1), %%rax, %%rbx" & ASCII.LF &
         "    adcx %%rax, %%r11" & ASCII.LF &
         "    mulx 8(%1), %%rax, %%rsi" & ASCII.LF &
         "    adox %%rbx, %%r12" & ASCII.LF &
         "    adcx %%rax, %%r12" & ASCII.LF &
         "    mulx 16(%1), %%rax, %%rbx" & ASCII.LF &
         "    adox %%rsi, %%r13" & ASCII.LF &
         "    adcx %%rax, %%r13" & ASCII.LF &
         "    mulx 24(%1), %%rax, %%rsi" & ASCII.LF &
         "    adox %%rbx, %%r8" & ASCII.LF &
         "    adcx %%rax, %%r8" & ASCII.LF &
         "    adox %%rsi, %%r9" & ASCII.LF &
         "    adcx %%rcx, %%r9" & ASCII.LF &
         "    adox %%rcx, %%r10" & ASCII.LF &
         "    adcx %%rcx, %%r10" & ASCII.LF &
         "    mov  %%r11, %%rdx" & ASCII.LF &
         "    xor  %%ecx, %%ecx" & ASCII.LF &
         "    mov  $-1, %%rbx" & ASCII.LF &
         "    mulx %%rbx, %%rax, %%rbx" & ASCII.LF &
         "    adcx %%rax, %%r11" & ASCII.LF &
         "    mov  $0xFFFFFFFF, %%esi" & ASCII.LF &
         "    mulx %%rsi, %%rax, %%rsi" & ASCII.LF &
         "    adox %%rbx, %%r12" & ASCII.LF &
         "    adcx %%rax, %%r12" & ASCII.LF &
         "    adox %%rsi, %%r13" & ASCII.LF &
         "    adcx %%rcx, %%r13" & ASCII.LF &
         "    movabs $0xFFFFFFFF00000001, %%rbx" & ASCII.LF &
         "    mulx %%rbx, %%rax, %%rbx" & ASCII.LF &
         "    adox %%rcx, %%r8" & ASCII.LF &
         "    adcx %%rax, %%r8" & ASCII.LF &
         "    adox %%rbx, %%r9" & ASCII.LF &
         "    adcx %%rcx, %%r9" & ASCII.LF &
         "    adox %%rcx, %%r10" & ASCII.LF &
         "    adcx %%rcx, %%r10" & ASCII.LF &
         "    mov  %%r12, %%rax" & ASCII.LF &
         "    mov  %%r13, %%rbx" & ASCII.LF &
         "    mov  %%r8, %%rcx" & ASCII.LF &
         "    mov  %%r9, %%rsi" & ASCII.LF &
         "    sub  $-1, %%rax" & ASCII.LF &
         "    mov  $0xFFFFFFFF, %%edx" & ASCII.LF &
         "    sbb  %%rdx, %%rbx" & ASCII.LF &
         "    sbb  $0, %%rcx" & ASCII.LF &
         "    movabs $0xFFFFFFFF00000001, %%rdx" & ASCII.LF &
         "    sbb  %%rdx, %%rsi" & ASCII.LF &
         "    sbb  $0, %%r10" & ASCII.LF &
         "    cmovc %%r12, %%rax" & ASCII.LF &
         "    cmovc %%r13, %%rbx" & ASCII.LF &
         "    cmovc %%r8, %%rcx" & ASCII.LF &
         "    cmovc %%r9, %%rsi" & ASCII.LF &
         "    mov  %%rax, 0(%2)" & ASCII.LF &
         "    mov  %%rbx, 8(%2)" & ASCII.LF &
         "    mov  %%rcx, 16(%2)" & ASCII.LF &
         "    mov  %%rsi, 24(%2)" & ASCII.LF &
         "    xor  %%eax, %%eax" & ASCII.LF &
         "    xor  %%ebx, %%ebx" & ASCII.LF &
         "    xor  %%ecx, %%ecx" & ASCII.LF &
         "    xor  %%edx, %%edx" & ASCII.LF &
         "    xor  %%esi, %%esi" & ASCII.LF &
         "    xor  %%r8d, %%r8d" & ASCII.LF &
         "    xor  %%r9d, %%r9d" & ASCII.LF &
         "    xor  %%r10d, %%r10d" & ASCII.LF &
         "    xor  %%r11d, %%r11d" & ASCII.LF &
         "    xor  %%r12d, %%r12d" & ASCII.LF &
         "    xor  %%r13d, %%r13d" & ASCII.LF,
         Inputs   => (System.Address'Asm_Input ("r", A'Address),
                      System.Address'Asm_Input ("r", B'Address),
                      System.Address'Asm_Input ("r", R'Address)),
         Clobber  => "rax,rbx,rcx,rdx,rsi,r8,r9,r10,r11,r12,r13,memory,cc",
         Volatile => True);
   end Mont_Mul_P256;

   ---------------------------------------------------------------------------
   --  Any 256-bit odd modulus, four limbs, fully unrolled
   ---------------------------------------------------------------------------

   --  Parameter block: 0: A  1: B  2: R  3 .. 6: M limbs  7: M0I.
   --  The P-256 core above with the two specialisations undone: the
   --  Montgomery factor is t0 * M0I (one imul) and all four limbs of M
   --  are multiplied.
   type Gen4_Params is array (0 .. 7) of Unsigned_64;

   procedure Gen4_Core (P : Gen4_Params) with No_Inline;

   procedure Gen4_Core (P : Gen4_Params) is
   begin
      Asm (
         "    mov  0(%0), %%r8" & ASCII.LF &
         "    mov  8(%0), %%r9" & ASCII.LF &
         "    xor  %%r10d, %%r10d" & ASCII.LF &
         "    xor  %%r11d, %%r11d" & ASCII.LF &
         "    xor  %%r12d, %%r12d" & ASCII.LF &
         "    xor  %%r13d, %%r13d" & ASCII.LF &
         "    xor  %%r14d, %%r14d" & ASCII.LF &
         "    xor  %%r15d, %%r15d" & ASCII.LF &
         "    mov  0(%%r8), %%rdx" & ASCII.LF &
         "    xor  %%ecx, %%ecx" & ASCII.LF &
         "    mulx 0(%%r9), %%rax, %%rbx" & ASCII.LF &
         "    adcx %%rax, %%r10" & ASCII.LF &
         "    mulx 8(%%r9), %%rax, %%rsi" & ASCII.LF &
         "    adox %%rbx, %%r11" & ASCII.LF &
         "    adcx %%rax, %%r11" & ASCII.LF &
         "    mulx 16(%%r9), %%rax, %%rbx" & ASCII.LF &
         "    adox %%rsi, %%r12" & ASCII.LF &
         "    adcx %%rax, %%r12" & ASCII.LF &
         "    mulx 24(%%r9), %%rax, %%rsi" & ASCII.LF &
         "    adox %%rbx, %%r13" & ASCII.LF &
         "    adcx %%rax, %%r13" & ASCII.LF &
         "    adox %%rsi, %%r14" & ASCII.LF &
         "    adcx %%rcx, %%r14" & ASCII.LF &
         "    adox %%rcx, %%r15" & ASCII.LF &
         "    adcx %%rcx, %%r15" & ASCII.LF &
         "    mov  %%r10, %%rdx" & ASCII.LF &
         "    imul 56(%0), %%rdx" & ASCII.LF &
         "    xor  %%ecx, %%ecx" & ASCII.LF &
         "    mulx 24(%0), %%rax, %%rbx" & ASCII.LF &
         "    adcx %%rax, %%r10" & ASCII.LF &
         "    mulx 32(%0), %%rax, %%rsi" & ASCII.LF &
         "    adox %%rbx, %%r11" & ASCII.LF &
         "    adcx %%rax, %%r11" & ASCII.LF &
         "    mulx 40(%0), %%rax, %%rbx" & ASCII.LF &
         "    adox %%rsi, %%r12" & ASCII.LF &
         "    adcx %%rax, %%r12" & ASCII.LF &
         "    mulx 48(%0), %%rax, %%rsi" & ASCII.LF &
         "    adox %%rbx, %%r13" & ASCII.LF &
         "    adcx %%rax, %%r13" & ASCII.LF &
         "    adox %%rsi, %%r14" & ASCII.LF &
         "    adcx %%rcx, %%r14" & ASCII.LF &
         "    adox %%rcx, %%r15" & ASCII.LF &
         "    adcx %%rcx, %%r15" & ASCII.LF &
         "    mov  8(%%r8), %%rdx" & ASCII.LF &
         "    xor  %%ecx, %%ecx" & ASCII.LF &
         "    mulx 0(%%r9), %%rax, %%rbx" & ASCII.LF &
         "    adcx %%rax, %%r11" & ASCII.LF &
         "    mulx 8(%%r9), %%rax, %%rsi" & ASCII.LF &
         "    adox %%rbx, %%r12" & ASCII.LF &
         "    adcx %%rax, %%r12" & ASCII.LF &
         "    mulx 16(%%r9), %%rax, %%rbx" & ASCII.LF &
         "    adox %%rsi, %%r13" & ASCII.LF &
         "    adcx %%rax, %%r13" & ASCII.LF &
         "    mulx 24(%%r9), %%rax, %%rsi" & ASCII.LF &
         "    adox %%rbx, %%r14" & ASCII.LF &
         "    adcx %%rax, %%r14" & ASCII.LF &
         "    adox %%rsi, %%r15" & ASCII.LF &
         "    adcx %%rcx, %%r15" & ASCII.LF &
         "    adox %%rcx, %%r10" & ASCII.LF &
         "    adcx %%rcx, %%r10" & ASCII.LF &
         "    mov  %%r11, %%rdx" & ASCII.LF &
         "    imul 56(%0), %%rdx" & ASCII.LF &
         "    xor  %%ecx, %%ecx" & ASCII.LF &
         "    mulx 24(%0), %%rax, %%rbx" & ASCII.LF &
         "    adcx %%rax, %%r11" & ASCII.LF &
         "    mulx 32(%0), %%rax, %%rsi" & ASCII.LF &
         "    adox %%rbx, %%r12" & ASCII.LF &
         "    adcx %%rax, %%r12" & ASCII.LF &
         "    mulx 40(%0), %%rax, %%rbx" & ASCII.LF &
         "    adox %%rsi, %%r13" & ASCII.LF &
         "    adcx %%rax, %%r13" & ASCII.LF &
         "    mulx 48(%0), %%rax, %%rsi" & ASCII.LF &
         "    adox %%rbx, %%r14" & ASCII.LF &
         "    adcx %%rax, %%r14" & ASCII.LF &
         "    adox %%rsi, %%r15" & ASCII.LF &
         "    adcx %%rcx, %%r15" & ASCII.LF &
         "    adox %%rcx, %%r10" & ASCII.LF &
         "    adcx %%rcx, %%r10" & ASCII.LF &
         "    mov  16(%%r8), %%rdx" & ASCII.LF &
         "    xor  %%ecx, %%ecx" & ASCII.LF &
         "    mulx 0(%%r9), %%rax, %%rbx" & ASCII.LF &
         "    adcx %%rax, %%r12" & ASCII.LF &
         "    mulx 8(%%r9), %%rax, %%rsi" & ASCII.LF &
         "    adox %%rbx, %%r13" & ASCII.LF &
         "    adcx %%rax, %%r13" & ASCII.LF &
         "    mulx 16(%%r9), %%rax, %%rbx" & ASCII.LF &
         "    adox %%rsi, %%r14" & ASCII.LF &
         "    adcx %%rax, %%r14" & ASCII.LF &
         "    mulx 24(%%r9), %%rax, %%rsi" & ASCII.LF &
         "    adox %%rbx, %%r15" & ASCII.LF &
         "    adcx %%rax, %%r15" & ASCII.LF &
         "    adox %%rsi, %%r10" & ASCII.LF &
         "    adcx %%rcx, %%r10" & ASCII.LF &
         "    adox %%rcx, %%r11" & ASCII.LF &
         "    adcx %%rcx, %%r11" & ASCII.LF &
         "    mov  %%r12, %%rdx" & ASCII.LF &
         "    imul 56(%0), %%rdx" & ASCII.LF &
         "    xor  %%ecx, %%ecx" & ASCII.LF &
         "    mulx 24(%0), %%rax, %%rbx" & ASCII.LF &
         "    adcx %%rax, %%r12" & ASCII.LF &
         "    mulx 32(%0), %%rax, %%rsi" & ASCII.LF &
         "    adox %%rbx, %%r13" & ASCII.LF &
         "    adcx %%rax, %%r13" & ASCII.LF &
         "    mulx 40(%0), %%rax, %%rbx" & ASCII.LF &
         "    adox %%rsi, %%r14" & ASCII.LF &
         "    adcx %%rax, %%r14" & ASCII.LF &
         "    mulx 48(%0), %%rax, %%rsi" & ASCII.LF &
         "    adox %%rbx, %%r15" & ASCII.LF &
         "    adcx %%rax, %%r15" & ASCII.LF &
         "    adox %%rsi, %%r10" & ASCII.LF &
         "    adcx %%rcx, %%r10" & ASCII.LF &
         "    adox %%rcx, %%r11" & ASCII.LF &
         "    adcx %%rcx, %%r11" & ASCII.LF &
         "    mov  24(%%r8), %%rdx" & ASCII.LF &
         "    xor  %%ecx, %%ecx" & ASCII.LF &
         "    mulx 0(%%r9), %%rax, %%rbx" & ASCII.LF &
         "    adcx %%rax, %%r13" & ASCII.LF &
         "    mulx 8(%%r9), %%rax, %%rsi" & ASCII.LF &
         "    adox %%rbx, %%r14" & ASCII.LF &
         "    adcx %%rax, %%r14" & ASCII.LF &
         "    mulx 16(%%r9), %%rax, %%rbx" & ASCII.LF &
         "    adox %%rsi, %%r15" & ASCII.LF &
         "    adcx %%rax, %%r15" & ASCII.LF &
         "    mulx 24(%%r9), %%rax, %%rsi" & ASCII.LF &
         "    adox %%rbx, %%r10" & ASCII.LF &
         "    adcx %%rax, %%r10" & ASCII.LF &
         "    adox %%rsi, %%r11" & ASCII.LF &
         "    adcx %%rcx, %%r11" & ASCII.LF &
         "    adox %%rcx, %%r12" & ASCII.LF &
         "    adcx %%rcx, %%r12" & ASCII.LF &
         "    mov  %%r13, %%rdx" & ASCII.LF &
         "    imul 56(%0), %%rdx" & ASCII.LF &
         "    xor  %%ecx, %%ecx" & ASCII.LF &
         "    mulx 24(%0), %%rax, %%rbx" & ASCII.LF &
         "    adcx %%rax, %%r13" & ASCII.LF &
         "    mulx 32(%0), %%rax, %%rsi" & ASCII.LF &
         "    adox %%rbx, %%r14" & ASCII.LF &
         "    adcx %%rax, %%r14" & ASCII.LF &
         "    mulx 40(%0), %%rax, %%rbx" & ASCII.LF &
         "    adox %%rsi, %%r15" & ASCII.LF &
         "    adcx %%rax, %%r15" & ASCII.LF &
         "    mulx 48(%0), %%rax, %%rsi" & ASCII.LF &
         "    adox %%rbx, %%r10" & ASCII.LF &
         "    adcx %%rax, %%r10" & ASCII.LF &
         "    adox %%rsi, %%r11" & ASCII.LF &
         "    adcx %%rcx, %%r11" & ASCII.LF &
         "    adox %%rcx, %%r12" & ASCII.LF &
         "    adcx %%rcx, %%r12" & ASCII.LF &
         "    mov  %%r14, %%rax" & ASCII.LF &
         "    mov  %%r15, %%rbx" & ASCII.LF &
         "    mov  %%r10, %%rcx" & ASCII.LF &
         "    mov  %%r11, %%rsi" & ASCII.LF &
         "    sub  24(%0), %%rax" & ASCII.LF &
         "    sbb  32(%0), %%rbx" & ASCII.LF &
         "    sbb  40(%0), %%rcx" & ASCII.LF &
         "    sbb  48(%0), %%rsi" & ASCII.LF &
         "    sbb  $0, %%r12" & ASCII.LF &
         "    cmovc %%r14, %%rax" & ASCII.LF &
         "    cmovc %%r15, %%rbx" & ASCII.LF &
         "    cmovc %%r10, %%rcx" & ASCII.LF &
         "    cmovc %%r11, %%rsi" & ASCII.LF &
         "    mov  16(%0), %%rdx" & ASCII.LF &
         "    mov  %%rax, 0(%%rdx)" & ASCII.LF &
         "    mov  %%rbx, 8(%%rdx)" & ASCII.LF &
         "    mov  %%rcx, 16(%%rdx)" & ASCII.LF &
         "    mov  %%rsi, 24(%%rdx)" & ASCII.LF &
         "    xor  %%eax, %%eax" & ASCII.LF &
         "    xor  %%ebx, %%ebx" & ASCII.LF &
         "    xor  %%ecx, %%ecx" & ASCII.LF &
         "    xor  %%edx, %%edx" & ASCII.LF &
         "    xor  %%esi, %%esi" & ASCII.LF &
         "    xor  %%r8d, %%r8d" & ASCII.LF &
         "    xor  %%r9d, %%r9d" & ASCII.LF &
         "    xor  %%r10d, %%r10d" & ASCII.LF &
         "    xor  %%r11d, %%r11d" & ASCII.LF &
         "    xor  %%r12d, %%r12d" & ASCII.LF &
         "    xor  %%r13d, %%r13d" & ASCII.LF &
         "    xor  %%r14d, %%r14d" & ASCII.LF &
         "    xor  %%r15d, %%r15d" & ASCII.LF,
         Inputs   => System.Address'Asm_Input ("r", P'Address),
         Clobber  => "rax,rbx,rcx,rdx,rsi,r8,r9,r10,r11,r12,r13,r14,r15,"
                     & "memory,cc",
         Volatile => True);
   end Gen4_Core;

   procedure Mont_Mul_4
     (R    : out Limbs_4;
      A, B : in  Limbs_4;
      M    : in  Limbs_4;
      M0I  : in  Word)
   is
      P : Gen4_Params :=
        (Addr (A'Address), Addr (B'Address), Addr (R'Address),
         M (0), M (1), M (2), M (3), M0I);
   begin
      Gen4_Core (P);
      P := (others => 0);
      pragma Inspection_Point (P);
   end Mont_Mul_4;

end SPARKTLSCrypto.BigNat64_ADX;
