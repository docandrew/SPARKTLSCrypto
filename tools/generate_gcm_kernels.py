#!/usr/bin/env python3
"""Generate the stitched AES-GCM stripe kernels (inline assembly in Ada).

Each kernel generates its own counter blocks from CB, runs AES-CTR on one
stripe of Buf, and folds a stripe of ciphertext into the GHASH state S
with one aggregated reduction, interleaving the GHASH multiplies between
the AES rounds so the AES and carry-less-multiply units work at once.

For decryption the GHASH input is the stripe being decrypted: the
ciphertext is read for GHASH during the rounds and overwritten with
plaintext only after the last round. For the pipelined encryption the
GHASH input is the previous stripe, already encrypted, as in the AES-NI
Encrypt_GHASH_Pipelined_4_* kernels.

The algebra is the crate's existing one, so every tier produces the same
bits: byte-reflected blocks and powers of H (layout of GHASH_NI.Pre_H_Powers
and AES_GCM_AVX512.Pre_H_Powers_16), four-product schoolbook multiplies
summed before one reduction (Gueron and Kounavis's aggregated reduction),
a one-bit left shift for the reflected representation, and the two-fold
Montgomery reduction by 0xC2...01 of AES_GCM_AVX512.GHASH_16_Blocks.
Stitching AES-CTR with GHASH follows the published design of Gueron and
Krasnov ("The fragility of AES-GCM authentication algorithm", and the
"stitched" AES-GCM code they contributed to OpenSSL); this generator is an
independent implementation of the idea, not a copy of that code.

Three register widths share one schedule:
  xmm  legacy SSE encodings (AES-NI + PCLMULQDQ + SSSE3), 1 block/register
  ymm  VEX encodings (VAES + VPCLMULQDQ on 256 bits),     2 blocks/register
  zmm  EVEX encodings (AVX-512F/BW + VAES + VPCLMULQDQ),  4 blocks/register

The generated text sits between "--  BEGIN GENERATED <name>" and
"--  END GENERATED <name>" markers in the unit bodies. Usage:

  tools/generate_gcm_kernels.py --check   # fail if a region differs
  tools/generate_gcm_kernels.py --write   # rewrite the regions
"""
import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

#  Asm operand numbers, fixed for every kernel.
OP_CB, OP_RK, OP_BUF, OP_S, OP_HP, OP_BSWAP, OP_REVCTR, OP_STEPS, OP_POLY = (
    range(9))


class ISA:
    def __init__(self, name, width):
        self.name = name          # 'xmm', 'ymm' or 'zmm'
        self.w = width            # blocks per register
        self.vb = 16 * width      # bytes per register

    def r(self, i):
        return f"%%{self.name}{i}"

    @staticmethod
    def x(i):
        return f"%%xmm{i}"

    @property
    def sse(self):
        return self.name == "xmm"

    @property
    def evex(self):
        return self.name == "zmm"

    # ---- moves -------------------------------------------------------
    def loadu(self, mem, d):
        op = "movdqu" if self.sse else ("vmovdqu64" if self.evex else "vmovdqu")
        return [f"{op} {mem}, {self.r(d)}"]

    def loada(self, mem, d):
        op = "movdqa" if self.sse else ("vmovdqa64" if self.evex else "vmovdqa")
        return [f"{op} {mem}, {self.r(d)}"]

    def storeu(self, s, mem):
        op = "movdqu" if self.sse else ("vmovdqu64" if self.evex else "vmovdqu")
        return [f"{op} {self.r(s)}, {mem}"]

    def bcast(self, mem, d):
        """One 16-byte value into every 128-bit lane."""
        if self.sse:
            return [f"movdqu {mem}, {self.r(d)}"]
        if self.evex:
            return [f"vbroadcasti32x4 {mem}, {self.r(d)}"]
        return [f"vbroadcasti128 {mem}, {self.r(d)}"]

    # ---- arithmetic: d := a op b --------------------------------------
    def xor(self, a, b, d):
        if self.sse:
            if d == b:
                return [f"pxor {self.r(a)}, {self.r(d)}"]
            if d == a:
                return [f"pxor {self.r(b)}, {self.r(d)}"]
            return [f"movdqa {self.r(b)}, {self.r(d)}",
                    f"pxor {self.r(a)}, {self.r(d)}"]
        op = "vpxorq" if self.evex else "vpxor"
        return [f"{op} {self.r(a)}, {self.r(b)}, {self.r(d)}"]

    def xor_mem(self, mem, s):
        """s := s xor 16*W bytes at mem (unaligned); SSE needs a temp."""
        assert not self.sse
        op = "vpxorq" if self.evex else "vpxor"
        return [f"{op} {mem}, {self.r(s)}, {self.r(s)}"]

    def shuf(self, m, s, d):
        if self.sse:
            pre = [] if d == s else [f"movdqa {self.r(s)}, {self.r(d)}"]
            return pre + [f"pshufb {self.r(m)}, {self.r(d)}"]
        return [f"vpshufb {self.r(m)}, {self.r(s)}, {self.r(d)}"]

    def clmul(self, imm, h, c, d):
        """d := clmul(c, h) with imm selecting c (bit 0) and h (bit 4)."""
        if self.sse:
            pre = [] if d == c else [f"movdqa {self.r(c)}, {self.r(d)}"]
            return pre + [f"pclmulqdq ${imm}, {self.r(h)}, {self.r(d)}"]
        return [f"vpclmulqdq ${imm}, {self.r(h)}, {self.r(c)}, {self.r(d)}"]

    def addd(self, mem, s, d):
        if self.sse:
            pre = [] if d == s else [f"movdqa {self.r(s)}, {self.r(d)}"]
            return pre + [f"paddd {mem}, {self.r(d)}"]
        return [f"vpaddd {mem}, {self.r(s)}, {self.r(d)}"]

    def aesenc(self, k, s, last=False):
        op = "aesenclast" if last else "aesenc"
        if self.sse:
            return [f"{op} {self.r(k)}, {self.r(s)}"]
        return [f"v{op} {self.r(k)}, {self.r(s)}, {self.r(s)}"]

    def bytes_shift(self, left, n, s, d):
        op = "slldq" if left else "srldq"
        if self.sse:
            pre = [] if d == s else [f"movdqa {self.r(s)}, {self.r(d)}"]
            return pre + [f"p{op} ${n}, {self.r(d)}"]
        return [f"vp{op} ${n}, {self.r(s)}, {self.r(d)}"]


XMM, YMM, ZMM = ISA("xmm", 1), ISA("ymm", 2), ISA("zmm", 4)


def x(i):
    return f"%%xmm{i}"


def reduce128(isa, lo, hi, a, b, c2, p):
    """Shift (hi:lo) left by one, reduce, store S. Operates on xmm only."""
    if isa.sse:
        return [
            f"movdqa {x(lo)}, {x(a)}", f"psrld $31, {x(a)}",
            f"movdqa {x(hi)}, {x(b)}", f"psrld $31, {x(b)}",
            f"pslld $1, {x(lo)}", f"pslld $1, {x(hi)}",
            f"movdqa {x(a)}, {x(c2)}", f"psrldq $12, {x(c2)}",
            f"pslldq $4, {x(a)}", f"pslldq $4, {x(b)}",
            f"por {x(a)}, {x(lo)}", f"por {x(b)}, {x(hi)}",
            f"por {x(c2)}, {x(hi)}",
            f"movdqa ({op(OP_POLY)}), {x(p)}",
            f"movdqa {x(lo)}, {x(a)}", f"pclmulqdq $0x10, {x(p)}, {x(a)}",
            f"pshufd $0x4e, {x(lo)}, {x(lo)}", f"pxor {x(a)}, {x(lo)}",
            f"movdqa {x(lo)}, {x(a)}", f"pclmulqdq $0x10, {x(p)}, {x(a)}",
            f"pshufd $0x4e, {x(lo)}, {x(lo)}", f"pxor {x(a)}, {x(lo)}",
            f"pxor {x(lo)}, {x(hi)}",
        ]
    return [
        f"vpsrld $31, {x(lo)}, {x(a)}", f"vpsrld $31, {x(hi)}, {x(b)}",
        f"vpslld $1, {x(lo)}, {x(lo)}", f"vpslld $1, {x(hi)}, {x(hi)}",
        f"vpsrldq $12, {x(a)}, {x(c2)}",
        f"vpslldq $4, {x(a)}, {x(a)}", f"vpslldq $4, {x(b)}, {x(b)}",
        f"vpor {x(a)}, {x(lo)}, {x(lo)}", f"vpor {x(b)}, {x(hi)}, {x(hi)}",
        f"vpor {x(c2)}, {x(hi)}, {x(hi)}",
        f"vmovdqa ({op(OP_POLY)}), {x(p)}",
        f"vpclmulqdq $0x10, {x(p)}, {x(lo)}, {x(a)}",
        f"vpshufd $0x4e, {x(lo)}, {x(lo)}", f"vpxor {x(a)}, {x(lo)}, {x(lo)}",
        f"vpclmulqdq $0x10, {x(p)}, {x(lo)}, {x(a)}",
        f"vpshufd $0x4e, {x(lo)}, {x(lo)}", f"vpxor {x(a)}, {x(lo)}, {x(lo)}",
        f"vpxor {x(lo)}, {x(hi)}, {x(hi)}",
    ]


def op(n):
    return f"%{n}"


def mem(n, disp=0):
    return f"{disp}({op(n)})" if disp else f"({op(n)})"


def kernel(isa, regs, rounds, aes, ghash, x_disp, power_count):
    """Instruction list for one stripe of `regs` registers.

    aes:   run AES-CTR on Buf[x_disp ..] from CB, advancing CB.
    ghash: fold Buf[0 ..] into S using the last regs*W powers of a
           power_count-entry table (H^power_count .. H^1, descending).
    """
    blocks = regs * isa.w
    if regs <= 4:
        state = list(range(regs))
        k, lo, hi, mid, c, h, t, m = 4, 5, 6, 7, 8, 9, 10, 15
        base, q, adv = 11, 12, 13
    else:
        assert regs == 8
        state = list(range(8))
        k, lo, hi, mid, c, h, t, m = 8, 9, 10, 11, 12, 13, 14, 15
        base, q, adv = 9, 10, 11       # free until GHASH starts
    code = []

    # ---- counter blocks ---------------------------------------------------
    if aes:
        code += isa.bcast(mem(OP_CB), base)
        code += isa.loada(mem(OP_REVCTR), q)
        code += isa.shuf(q, base, base)
        for i, s in enumerate(state):
            code += isa.addd(mem(OP_STEPS, 16 * i * isa.w), base, s)
            code += isa.shuf(q, s, s)
        # CB := CB + blocks (low 128-bit lane only).
        if isa.sse:
            code += [f"movdqa {x(base)}, {x(adv)}",
                     f"paddd {mem(OP_STEPS, 16 * blocks)}, {x(adv)}",
                     f"pshufb {x(q)}, {x(adv)}",
                     f"movdqu {x(adv)}, {mem(OP_CB)}"]
        else:
            code += [f"vpaddd {mem(OP_STEPS, 16 * blocks)}, {x(base)}, {x(adv)}",
                     f"vpshufb {x(q)}, {x(adv)}, {x(adv)}",
                     f"vmovdqu {x(adv)}, {mem(OP_CB)}"]
        # Round 0 whitening.
        code += isa.bcast(mem(OP_RK), k)
        for s in state:
            code += isa.xor(k, s, s)

    # ---- GHASH work, to be spread across the rounds ----------------------
    gh = []
    if ghash:
        gh += isa.loada(mem(OP_BSWAP), m)
        for j in range(regs):
            gh += isa.loadu(mem(OP_BUF, j * isa.vb), c)
            gh += isa.shuf(m, c, c)
            if j == 0:
                # S enters lane 0 of the first chunk (multiplied by the
                # highest power). The 128-bit load zeroes the upper lanes.
                if isa.sse:
                    gh += [f"movdqu {mem(OP_S)}, {x(t)}",
                           f"pshufb {x(m)}, {x(t)}",
                           f"pxor {x(t)}, {x(c)}"]
                else:
                    gh += [f"vmovdqu {mem(OP_S)}, {x(t)}",
                           f"vpshufb {x(m)}, {x(t)}, {x(t)}"]
                    gh += isa.xor(t, c, c)
            hoff = 16 * (power_count - blocks + j * isa.w)
            gh += isa.loadu(mem(OP_HP, hoff), h)
            if j == 0:
                gh += isa.clmul("0x00", h, c, lo)
                gh += isa.clmul("0x11", h, c, hi)
                gh += isa.clmul("0x10", h, c, mid)
                gh += isa.clmul("0x01", h, c, c)
                gh += isa.xor(c, mid, mid)
            else:
                gh += isa.clmul("0x00", h, c, t)
                gh += isa.xor(t, lo, lo)
                gh += isa.clmul("0x11", h, c, t)
                gh += isa.xor(t, hi, hi)
                gh += isa.clmul("0x10", h, c, t)
                gh += isa.xor(t, mid, mid)
                gh += isa.clmul("0x01", h, c, c)
                gh += isa.xor(c, mid, mid)

    # ---- AES rounds with GHASH interleaved -------------------------------
    if aes:
        slots = rounds - 1
        per = -(-len(gh) // slots) if gh else 0
        for rnd in range(1, rounds + 1):
            code += isa.bcast(mem(OP_RK, 16 * rnd), k)
            for s in state:
                code += isa.aesenc(k, s, last=(rnd == rounds))
            if rnd < rounds and gh:
                code += gh[:per]
                gh = gh[per:]
        assert not gh
        # XOR the keystream into Buf (after every GHASH load of Buf).
        for i, s in enumerate(state):
            where = mem(OP_BUF, x_disp + i * isa.vb)
            if isa.sse:
                code += [f"movdqu {where}, {x(t)}", f"pxor {x(t)}, {x(s)}"]
            else:
                code += isa.xor_mem(where, s)
            code += isa.storeu(s, where)
    else:
        code += gh

    # ---- reduction ----------------------------------------------------------
    if ghash:
        code += isa.bytes_shift(True, 8, mid, t)
        code += isa.bytes_shift(False, 8, mid, mid)
        code += isa.xor(t, lo, lo)
        code += isa.xor(mid, hi, hi)
        if isa.evex:
            code += [f"vextracti64x4 $1, %%zmm{lo}, %%ymm{t}",
                     f"vpxor %%ymm{t}, %%ymm{lo}, %%ymm{lo}",
                     f"vextracti64x4 $1, %%zmm{hi}, %%ymm{t}",
                     f"vpxor %%ymm{t}, %%ymm{hi}, %%ymm{hi}"]
        if not isa.sse:
            code += [f"vextracti128 $1, %%ymm{lo}, {x(t)}",
                     f"vpxor {x(t)}, {x(lo)}, {x(lo)}",
                     f"vextracti128 $1, %%ymm{hi}, {x(t)}",
                     f"vpxor {x(t)}, {x(hi)}, {x(hi)}"]
        code += reduce128(isa, lo, hi, 0, 1, 2, 3)
        if isa.sse:
            code += [f"pshufb {x(m)}, {x(hi)}", f"movdqu {x(hi)}, {mem(OP_S)}"]
        else:
            code += [f"vpshufb {x(m)}, {x(hi)}, {x(hi)}",
                     f"vmovdqu {x(hi)}, {mem(OP_S)}"]
    if not isa.sse:
        code += ["vzeroupper"]
    #  Constant time by construction: straight-line code, no control flow
    #  at all (so nothing can depend on the data, and Valgrind need not
    #  run the VAES kernels to show it).
    for line in code:
        mnemonic = line.split()[0]
        assert not (mnemonic.startswith(("j", "loop", "cmov", "set"))
                    or mnemonic in ("call", "ret", "jmp")), (
            "branch or data-dependent select in a kernel: " + line)
    return code


#  Ada parameter profile and Asm inputs for each kernel shape.
def ada_procedure(name, isa, regs, rounds, aes, ghash, x_disp, power_count,
                  rk_type, hp_type, comment):
    code = kernel(isa, regs, rounds, aes, ghash, x_disp, power_count)
    used = sorted({int(n) for line in code
                   for n in re.findall(r"%%[xyz]mm(\d+)", line)})
    clobber = ",".join(f"xmm{i}" for i in used) + ",memory"
    params = ["Buf      : in out Byte_Seq" if aes else
              "Buf      : in     Byte_Seq"]
    if ghash:
        params.append("S        : in out Bytes_16")
    if aes:
        params.append("CB       : in out Bytes_16")
        params.append(f"Pre_RK   : in     {rk_type}")
    if ghash:
        params.append(f"H_Powers : in     {hp_type}")
    addr = {OP_CB: "CB'Address" if aes else "Buf'Address",
            OP_RK: "Pre_RK'Address" if aes else "Buf'Address",
            OP_BUF: "Buf'Address",
            OP_S: "S'Address" if ghash else "Buf'Address",
            OP_HP: "H_Powers'Address" if ghash else "Buf'Address",
            OP_BSWAP: "Gen_Bswap_Mask'Address",
            OP_REVCTR: "Gen_Reverse_Ctr_Mask'Address",
            OP_STEPS: "Gen_Ctr_Steps'Address",
            OP_POLY: "Gen_Reduction_Poly'Address"}
    lines = [f"   --  {line}" if line else "   --" for line in comment]
    lines.append(f"   procedure {name}")
    lines.append("     (" + ";\n      ".join(params) + ")")
    lines.append("   is")
    lines.append("   begin")
    lines.append("      Asm")
    body = [f'        "{c}"' for c in code]
    for i in range(len(body) - 1):
        body[i] += " & ASCII.LF & ASCII.HT &"
    body[-1] += ","
    body[0] = "       (" + body[0].lstrip()
    lines += body
    inputs = [f'System.Address\'Asm_Input ("r", {addr[n]})'
              for n in range(9)]
    lines.append("        Inputs => (" +
                 ",\n                   ".join(inputs) + "),")
    lines.append(f'        Clobber => "{clobber}",')
    lines.append("        Volatile => True);")
    lines.append(f"   end {name};")
    return "\n".join(lines) + "\n"


def constants(isa, steps):
    """Package-level constants used by the generated kernels of a unit."""
    lanes = 4 if isa.evex else (2 if isa.name == "ymm" else 1)
    bswap = ",\n      ".join(["15,14,13,12, 11,10,9,8, 7,6,5,4, 3,2,1,0"] * lanes)
    rev = ",\n      ".join(["0,1,2,3, 4,5,6,7, 8,9,10,11, 15,14,13,12"] * lanes)
    step_rows = ",\n      ".join(
        f"0,0,0,0, 0,0,0,0, 0,0,0,0, {k},0,0,0" for k in range(steps + 1))
    n = 16 * lanes
    return f"""   --  Constants of the generated kernels. Gen_Bswap_Mask reverses each
   --  16-byte lane (NIST GHASH <-> PCLMULQDQ order); Gen_Reverse_Ctr_Mask
   --  reverses only the big-endian counter word of each lane so PADDD can
   --  add to it; entry k of Gen_Ctr_Steps adds k to that word (inc32 mod
   --  2**32, as Increment_Counter); Gen_Reduction_Poly is the upper half
   --  of the reflected reduction polynomial, 0xC2 << 56.
   Gen_Bswap_Mask : constant array (0 .. {n - 1}) of Unsigned_8 :=
     ({bswap});
   for Gen_Bswap_Mask'Alignment use {max(16, n)};
   Gen_Reverse_Ctr_Mask : constant array (0 .. {n - 1}) of Unsigned_8 :=
     ({rev});
   for Gen_Reverse_Ctr_Mask'Alignment use {max(16, n)};
   Gen_Ctr_Steps : constant array (0 .. {16 * (steps + 1) - 1}) of Unsigned_8 :=
     ({step_rows});
   for Gen_Ctr_Steps'Alignment use 64;
   Gen_Reduction_Poly : constant array (0 .. 15) of Unsigned_8 :=
     (0 .. 14 => 0, 15 => 16#C2#);
   for Gen_Reduction_Poly'Alignment use 16;
"""


def regions():
    """name -> (file, text)."""
    out = {}
    ni = "src/sparktlscrypto-aes_ni.adb"
    avx2 = "src/sparktlscrypto-aes_gcm_avx2.adb"
    avx512 = "src/sparktlscrypto-aes_gcm_avx512.adb"
    out["aes_ni constants"] = (ni, constants(XMM, 4))
    out["avx2 constants"] = (avx2, constants(YMM, 16))
    out["avx512 constants"] = (avx512, constants(ZMM, 32))

    dec_comment = [
        "Decrypt one stripe in place: GHASH the ciphertext into S,",
        "interleaved with AES-CTR from CB; CB advances by the stripe."]
    for bits, rounds in ((128, 10), (256, 14)):
        text = ada_procedure(
            f"Decrypt_GCM_Stripe_4_{bits}", XMM, 4, rounds, True, True, 0, 4,
            f"Pre_Swapped_RKs_{bits}", "Pre_H_Powers", dec_comment)
        out[f"aes_ni decrypt {bits}"] = (ni, text)

        text = ada_procedure(
            f"Decrypt_GCM_Stripe_16_{bits}", YMM, 8, rounds, True, True, 0,
            16, f"AES_NI.Pre_Swapped_RKs_{bits}", "Pre_H_Powers_16",
            dec_comment)
        out[f"avx2 decrypt {bits}"] = (avx2, text)
        text = ada_procedure(
            f"Encrypt_CTR_16_{bits}", YMM, 8, rounds, True, False, 0, 16,
            f"AES_NI.Pre_Swapped_RKs_{bits}", "Pre_H_Powers_16",
            ["Encrypt the first stripe of a record (no GHASH yet)."])
        out[f"avx2 ctr {bits}"] = (avx2, text)
        text = ada_procedure(
            f"Encrypt_GHASH_Pipelined_16_{bits}", YMM, 8, rounds, True, True,
            256, 16, f"AES_NI.Pre_Swapped_RKs_{bits}", "Pre_H_Powers_16",
            ["Buf is a 512-byte window: GHASH the previous stripe's",
             "ciphertext (bytes 0 .. 255) while encrypting bytes 256 .. 511."])
        out[f"avx2 pipelined {bits}"] = (avx2, text)

        text = ada_procedure(
            f"Decrypt_GCM_Stripe_16_{bits}", ZMM, 4, rounds, True, True, 0,
            16, f"AES_NI.Pre_Swapped_RKs_{bits}", "Pre_H_Powers_16",
            dec_comment)
        out[f"avx512 decrypt {bits}"] = (avx512, text)
        text = ada_procedure(
            f"Decrypt_GCM_Stripe_32_{bits}", ZMM, 8, rounds, True, True, 0,
            32, f"AES_NI.Pre_Swapped_RKs_{bits}", "Pre_H_Powers_32",
            dec_comment)
        out[f"avx512 decrypt32 {bits}"] = (avx512, text)

    out["avx2 ghash"] = (avx2, ada_procedure(
        "GHASH_16_Blocks", YMM, 8, 10, False, True, 0, 16,
        "", "Pre_H_Powers_16",
        ["Fold 256 bytes into S: the last stripe of a pipelined record."]))
    return out


MARK = re.compile(r"^   --  BEGIN GENERATED (.+)\n(.*?)^   --  END GENERATED \1\n",
                  re.S | re.M)


def main():
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--check", action="store_true")
    group.add_argument("--write", action="store_true")
    group.add_argument("--print", metavar="REGION")
    args = parser.parse_args()
    wanted = regions()
    if args.print:
        sys.stdout.write(wanted[args.print][1])
        return 0
    by_file = {}
    for name, (path, text) in wanted.items():
        by_file.setdefault(path, {})[name] = text
    status = 0
    for path, texts in by_file.items():
        source = (ROOT / path).read_text()
        found = {m.group(1): m.group(2) for m in MARK.finditer(source)}
        for name in texts:
            if name not in found:
                print(f"FAIL: {path}: no region '{name}'")
                status = 1
        for name in found:
            if name not in texts:
                print(f"FAIL: {path}: unknown region '{name}'")
                status = 1
        if args.check:
            for name, text in texts.items():
                if name in found and found[name] != text:
                    print(f"FAIL: {path}: region '{name}' differs from "
                          "generator output; run with --write")
                    status = 1
        else:
            def put(match):
                name = match.group(1)
                return (f"   --  BEGIN GENERATED {name}\n" +
                        texts.get(name, match.group(2)) +
                        f"   --  END GENERATED {name}\n")
            (ROOT / path).write_text(MARK.sub(put, source))
    if args.check and status == 0:
        print(f"PASS: {len(wanted)} generated kernel regions match")
    return status


if __name__ == "__main__":
    sys.exit(main())
