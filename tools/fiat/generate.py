#!/usr/bin/env python3
"""
Generate a SPARK Ada Fiat_* body from one of fiat-crypto's generated C files.

    ./generate.py p384         > ../../src/sparktlscrypto-fiat_p384.adb
    ./generate.py p384_scalar  > ../../src/sparktlscrypto-fiat_p384_scalar.adb
    ./generate.py p256         > /tmp/regenerated_p256.adb   # validation only

See README.md for provenance, the pinned fiat-crypto revision, and the
validation procedure.
"""
import os
import sys
from translate import extract, translate_body, fmt_decls

LIMBS = {'p256': 4, 'p384': 6, 'p384_scalar': 6}

# (C name, Ada name, Ada signature)
FUNCS = [
    ('mul',             'Mul',             '(Arg1, Arg2 : FE) return FE'),
    ('square',          'Sqr',             '(Arg1 : FE) return FE'),
    ('add',             'Add',             '(Arg1, Arg2 : FE) return FE'),
    ('sub',             'Sub',             '(Arg1, Arg2 : FE) return FE'),
    ('opp',             'Opp',             '(Arg1 : FE) return FE'),
    ('from_montgomery', 'From_Montgomery', '(Arg1 : FE) return FE'),
    ('to_montgomery',   'To_Montgomery',   '(Arg1 : FE) return FE'),
    ('selectznz',       'Selectznz',
     '(Cond : Unsigned_64; Arg2, Arg3 : FE) return FE'),
]


def emit(csrc, prefix, cname, adaname, sig, limbs):
    body = extract(csrc, f'fiat_{prefix}_{cname}')
    if body is None:
        sys.exit(f'FATAL: fiat_{prefix}_{cname} not found')
    decls, stmts = translate_body(body)
    bad = [s for s in stmts if 'UNTRANSLATED' in s]
    if bad:
        sys.exit(f'FATAL: {cname} not fully translated:\n' + '\n'.join(bad))

    # The condition is arg1 in C but Cond in the Ada signature.
    if cname == 'selectznz':
        stmts = [s.replace('Arg1,', 'Cond,') for s in stmts]

    # Fold the out1(i) := xN assignments into one aggregate, matching the
    # existing hand-written Fiat_P256 body.
    outs, rest = {}, []
    for s in stmts:
        t = s.strip()
        if t.startswith('Out1 (') and ') :=' in t:
            outs[int(t.split('(')[1].split(')')[0])] = \
                t.split(':=')[1].strip().rstrip(';')
        else:
            rest.append(s)

    lines = [f'   function {adaname} {sig} is', '      Out1 : FE;']
    lines += fmt_decls(decls)
    lines += ['   begin'] + rest
    lines.append(f'      Out1 := ({", ".join(outs[i] for i in range(limbs))});')
    lines += ['      return Out1;', f'   end {adaname};']
    return '\n'.join(lines)


PKG = {'p256': 'Fiat_P256', 'p384': 'Fiat_P384',
       'p384_scalar': 'Fiat_P384_Scalar'}

HEADER = '''--  SPARKTLSCrypto {pkg} -- faithful port of fiat-crypto {cfile}
--
--  GENERATED FILE -- do not edit by hand. Regenerate with:
--      tools/fiat/generate.py {target} > src/sparktlscrypto-{low}.adb
--  See tools/fiat/README.md for the pinned fiat-crypto revision, the source
--  hashes, and the validation procedure.
--
--  Every arithmetic function is a line-by-line translation of the Coq-verified
--  C output. SSA form is preserved for performance (optimal register
--  allocation), matching the sibling Fiat_P256 port.
--
--  To_Bytes / From_Bytes are hand-written little-endian loops rather than
--  transliterated SSA -- the generated form is several hundred lines of byte
--  shuffling with semantics identical to an obvious loop. Same choice as
--  Fiat_P256.

with Interfaces; use Interfaces;

package body SPARKTLSCrypto.{pkg} with
   SPARK_Mode => On
is
   --  Bignum carry chains routinely discard the final carry-out of an
   --  Addcarryx / Subborrowx call. These show up as "unused assignment"
   --  on the inlined Out2 := ... line; the pattern is intentional and
   --  matches fiat-crypto's C reference output.
   pragma Warnings (GNATProve, Off, "unused assignment");

   ----------------------------------------------------------------
   --  Fiat primitives -- direct translation of the corresponding
   --  static inline helpers in the C source.
   ----------------------------------------------------------------

   procedure Addcarryx_U64
     (Out1 : out Unsigned_64;
      Out2 : out Unsigned_64;
      Arg1 :     Unsigned_64;
      Arg2 :     Unsigned_64;
      Arg3 :     Unsigned_64)
   with Inline
   is
      X : constant Unsigned_128 :=
         Unsigned_128 (Arg1) + Unsigned_128 (Arg2) + Unsigned_128 (Arg3);
   begin
      Out1 := Unsigned_64 (X and 16#FFFF_FFFF_FFFF_FFFF#);
      Out2 := Unsigned_64 (Shift_Right (X, 64));
   end Addcarryx_U64;

   procedure Subborrowx_U64
     (Out1 : out Unsigned_64;
      Out2 : out Unsigned_64;
      Arg1 :     Unsigned_64;
      Arg2 :     Unsigned_64;
      Arg3 :     Unsigned_64)
   with Inline
   is
      X : constant Unsigned_128 :=
         Unsigned_128 (Arg2) - Unsigned_128 (Arg1) - Unsigned_128 (Arg3);
   begin
      Out1 := Unsigned_64 (X and 16#FFFF_FFFF_FFFF_FFFF#);
      Out2 := Unsigned_64 (Shift_Right (X, 64)) and 1;
   end Subborrowx_U64;

   procedure Mulx_U64
     (Out1 : out Unsigned_64;
      Out2 : out Unsigned_64;
      Arg1 :     Unsigned_64;
      Arg2 :     Unsigned_64)
   with Inline
   is
      X : constant Unsigned_128 := Unsigned_128 (Arg1) * Unsigned_128 (Arg2);
   begin
      Out1 := Unsigned_64 (X and 16#FFFF_FFFF_FFFF_FFFF#);
      Out2 := Unsigned_64 (Shift_Right (X, 64));
   end Mulx_U64;

   procedure Cmovznz_U64
     (Out1 : out Unsigned_64;
      Arg1 :     Unsigned_64;
      Arg2 :     Unsigned_64;
      Arg3 :     Unsigned_64)
   with Inline
   is
      --  Branchless constant-time select, identical to the Fiat_P256 port.
      --  Negating on a modular type yields all-ones for 1 and zero for 0, so
      --  there is no comparison and no branch on the (secret) condition. An
      --  "if" here would be a genuine constant-time hazard: the compiler is
      --  free to emit a conditional jump on secret data.
      --
      --  NOTE: fiat's C additionally wraps both operands in value_barrier to
      --  block compiler reassociation. The Ada ports omit it -- a pre-existing
      --  decision shared with Fiat_P256, covered by the ctgrind/dudect suites
      --  rather than by construction.
      Mask : constant Unsigned_64 :=
         -(Arg1 and 1);
   begin
      Out1 := (Mask and Arg3) or ((not Mask) and Arg2);
   end Cmovznz_U64;

'''

TAIL = '''
   ----------------------------------------------------------------
   --  Serialisation -- hand-written loops, see the header note.
   ----------------------------------------------------------------

   procedure Nonzero (Out1 : out Unsigned_64; Arg1 : FE) is
      Acc : Unsigned_64 := 0;
   begin
      for I in 0 .. {last} loop
         Acc := Acc or Arg1 (I);
      end loop;
      Out1 := Acc;
   end Nonzero;

   --  to_bytes: field element to {nbytes} little-endian bytes
   procedure To_Bytes (Out1 : out Byte_Seq; Arg1 : FE) is
      F : constant I32 := Out1'First;
   begin
      Out1 := (others => 0);
      for Limb_Idx in 0 .. {last} loop
         declare
            V : Unsigned_64 := Arg1 (Limb_Idx);
            Base : constant I32 := F + I32 (Limb_Idx) * 8;
         begin
            for B in 0 .. 7 loop
               Out1 (Base + I32 (B)) := Byte (V and 16#FF#);
               V := Shift_Right (V, 8);
            end loop;
         end;
      end loop;
   end To_Bytes;

   --  from_bytes: {nbytes} little-endian bytes to field element
   function From_Bytes (Arg1 : Byte_Seq) return FE is
      Out1 : FE;
      F : constant I32 := Arg1'First;
   begin
      for Limb_Idx in 0 .. {last} loop
         declare
            V : Unsigned_64 := 0;
            Base : constant I32 := F + I32 (Limb_Idx) * 8;
         begin
            for B in reverse 0 .. 7 loop
               V := Shift_Left (V, 8) or Unsigned_64 (Arg1 (Base + I32 (B)));
            end loop;
            Out1 (Limb_Idx) := V;
         end;
      end loop;
      return Out1;
   end From_Bytes;

end SPARKTLSCrypto.{pkg};
'''

if __name__ == '__main__':
    if len(sys.argv) != 2 or sys.argv[1] not in LIMBS:
        sys.exit(f'usage: generate.py {{{"|".join(LIMBS)}}}')
    target = sys.argv[1]
    limbs = LIMBS[target]
    #  Resolve the C source next to this script, not relative to the caller's
    #  working directory -- ci/check-fiat-port.sh invokes it from the repo root.
    here = os.path.dirname(os.path.abspath(__file__))
    cfile = os.path.join(here, f'{target}_64.c')
    csrc = open(cfile).read()
    pkg = PKG[target]

    out = [HEADER.format(pkg=pkg, cfile=cfile, target=target,
                         low=pkg.lower())]
    for cname, adaname, sig in FUNCS:
        out.append(emit(csrc, target, cname, adaname, sig, limbs))
        out.append('')
    out.append(TAIL.format(pkg=pkg, last=limbs - 1, nbytes=limbs * 8))
    print('\n'.join(out))
