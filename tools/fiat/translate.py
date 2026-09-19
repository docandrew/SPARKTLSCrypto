#!/usr/bin/env python3
"""
Translate fiat-crypto's generated C (word-by-word Montgomery) into SPARK Ada
in the style of sparktlscrypto-fiat_p256.adb.

Scope: the regular SSA arithmetic functions only. to_bytes / from_bytes are
deliberately NOT transliterated -- the existing p256 port hand-writes those as
little-endian loops, which is shorter and obviously correct, and we match it.

Validation strategy: run this on p256_64.c and compare against the existing
hand port. If it reproduces known-good code, it is trustworthy for p384.
"""
import re
import sys

# ---------------------------------------------------------------- operands

def conv_operand(s):
    """Translate a single C operand/expression fragment to Ada."""
    s = s.strip()
    # strip redundant outer parens repeatedly
    while s.startswith('(') and s.endswith(')') and _balanced(s[1:-1]):
        s = s[1:-1].strip()

    # integer literal macros
    s = re.sub(r'UINT(?:8|16|32|64)_C\(0x([0-9a-fA-F]+)\)', _hex_ada, s)
    s = re.sub(r'\bfiat_[a-z0-9_]+_uint1\b', '', s)
    # casts we can drop (Ada vars are already Unsigned_64)
    s = re.sub(r'\(uint(?:8|16|32|64)_t\)\s*', '', s)
    # bare hex
    s = re.sub(r'\b0x([0-9a-fA-F]+)\b', lambda m: _hex_lit(m.group(1)), s)
    # array refs: arg1[3] -> Arg1 (3)
    s = re.sub(r'\barg(\d+)\[(\d+)\]', lambda m: f'Arg{m.group(1)} ({m.group(2)})', s)
    s = re.sub(r'\bout(\d+)\[(\d+)\]', lambda m: f'Out{m.group(1)} ({m.group(2)})', s)
    # bare scalar parameters (e.g. selectznz's condition arg1, passed by value
    # rather than indexed). Must run AFTER the array rules above, which have
    # already consumed the argN[i] forms.
    s = re.sub(r'\barg(\d+)\b', lambda m: f'Arg{m.group(1)}', s)
    s = re.sub(r'\bout(\d+)\b', lambda m: f'Out{m.group(1)}', s)
    # bitwise ops
    s = s.replace('&', ' and ').replace('|', ' or ').replace('^', ' xor ')
    # shifts: (X >> n) / (X << n)
    s = _conv_shifts(s)
    s = re.sub(r'\s+', ' ', s).strip()
    return s


def _balanced(s):
    d = 0
    for c in s:
        if c == '(':
            d += 1
        elif c == ')':
            d -= 1
            if d < 0:
                return False
    return d == 0


def _hex_ada(m):
    return _hex_lit(m.group(1))


def _hex_lit(h):
    h = h.upper().lstrip('0') or '0'
    # group in 4s from the right for readability
    grouped = ''
    while len(h) > 4:
        grouped = '_' + h[-4:] + grouped
        h = h[:-4]
    return f'16#{h}{grouped}#'


def _conv_shifts(s):
    # innermost-first: X >> n  ->  Shift_Right (X, n)
    pat = re.compile(r'([A-Za-z0-9_#\(\) ]+?)\s*(>>|<<)\s*(\d+)')
    prev = None
    while prev != s:
        prev = s
        s = pat.sub(lambda m: '%s (%s, %s)' % (
            'Shift_Right' if m.group(2) == '>>' else 'Shift_Left',
            m.group(1).strip(), m.group(3)), s, count=1)
    return s


# ---------------------------------------------------------------- statements

CALL = re.compile(
    r'^\s*fiat_[a-z0-9_]+_(mulx|addcarryx|subborrowx|cmovznz)_u64\((.*)\);\s*$')
ASSIGN = re.compile(r'^\s*(x\d+)\s*=\s*(.*);\s*$')
OUTIDX = re.compile(r'^\s*out(\d+)\[(\d+)\]\s*=\s*(.*);\s*$')
OUTPTR = re.compile(r'^\s*\*out(\d+)\s*=\s*(.*);\s*$')
DECL = re.compile(r'^\s*(?:uint(?:8|16|32|64)_t|fiat_[a-z0-9_]+_uint1)\s+(x\d+);\s*$')

ADA_CALL = {
    'mulx': 'Mulx_U64',
    'addcarryx': 'Addcarryx_U64',
    'subborrowx': 'Subborrowx_U64',
    'cmovznz': 'Cmovznz_U64',
}


def split_args(s):
    out, depth, cur = [], 0, ''
    for c in s:
        if c == ',' and depth == 0:
            out.append(cur)
            cur = ''
            continue
        if c == '(':
            depth += 1
        elif c == ')':
            depth -= 1
        cur += c
    if cur.strip():
        out.append(cur)
    return out


def translate_body(lines):
    decls, stmts = [], []
    for ln in lines:
        if not ln.strip() or ln.strip().startswith('//'):
            continue
        m = DECL.match(ln)
        if m:
            decls.append(m.group(1))
            continue
        m = CALL.match(ln)
        if m:
            kind, argstr = m.group(1), m.group(2)
            args = [a.strip() for a in split_args(argstr)]
            args = [a[1:] if a.startswith('&') else conv_operand(a) for a in args]
            stmts.append(f'      {ADA_CALL[kind]} ({", ".join(args)});')
            continue
        m = OUTIDX.match(ln)
        if m:
            stmts.append(f'      Out{m.group(1)} ({m.group(2)}) := {conv_operand(m.group(3))};')
            continue
        m = OUTPTR.match(ln)
        if m:
            stmts.append(f'      Out{m.group(1)} := {conv_operand(m.group(2))};')
            continue
        m = ASSIGN.match(ln)
        if m:
            stmts.append(f'      {m.group(1)} := {conv_operand(m.group(2))};')
            continue
        if ln.strip() in ('}', '{'):
            continue
        stmts.append(f'      --  UNTRANSLATED: {ln.strip()}')
    return decls, stmts


def fmt_decls(names, per_line=8):
    out = []
    for i in range(0, len(names), per_line):
        chunk = names[i:i + per_line]
        out.append('      ' + ', '.join(chunk) + ' : Unsigned_64;')
    return out


def extract(csrc, fname):
    """Return the body lines of function `fname`."""
    pat = re.compile(r'^\s*(?:static\s+)?[A-Z_0-9]*\s*(?:FIAT_[A-Z0-9_]+_FIAT_INLINE\s+)?void\s+'
                     + re.escape(fname) + r'\(')
    lines = csrc.splitlines()
    start = None
    for i, ln in enumerate(lines):
        if pat.match(ln):
            start = i
            break
    if start is None:
        return None
    depth = 0
    body = []
    for ln in lines[start:]:
        depth += ln.count('{') - ln.count('}')
        body.append(ln)
        if depth == 0 and len(body) > 1:
            break
    return body[1:-1]


if __name__ == '__main__':
    src = open(sys.argv[1]).read()
    prefix = sys.argv[2]          # e.g. fiat_p384
    for fn in sys.argv[3:]:
        body = extract(src, f'{prefix}_{fn}')
        if body is None:
            print(f'--  !! {fn} NOT FOUND', file=sys.stderr)
            continue
        decls, stmts = translate_body(body)
        print(f'   --  ==== {fn} ====')
        print('\n'.join(fmt_decls(decls)))
        print('   begin')
        print('\n'.join(stmts))
        print()
        n_untrans = sum(1 for s in stmts if 'UNTRANSLATED' in s)
        print(f'--  {fn}: {len(decls)} decls, {len(stmts)} stmts, '
              f'{n_untrans} untranslated', file=sys.stderr)
