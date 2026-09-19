# fiat-crypto → SPARK Ada transliteration

`SPARKTLSCrypto.Fiat_P384` and `SPARKTLSCrypto.Fiat_P384_Scalar` are generated
from [fiat-crypto](https://github.com/mit-plv/fiat-crypto)'s Coq-verified C
output by `generate.py`. They are **generated files — do not edit them by
hand**; `ci/check-fiat-port.sh` will fail if you do.

`SPARKTLSCrypto.Fiat_P256` and `Fiat_25519` predate this tool and are
hand-written. They are left alone (see "Validation" for why that matters).

## Provenance

Sources were taken from `fiat-c/src/` at fiat-crypto revision:

    c79cf6061a60ead08730658fa6f38a5f260ad7d3

with these hashes:

    d3cf74220c7b4c2e33e8e225ac91abcf54616140379b3f528ae5f380c4aa5698  p384_64.c
    d6ce4e2e18de71062e5679e54ae182c0b2e04b90fb3177ecc16035daa312a3e7  p384_scalar_64.c
    68cc5c4fa08de660a869a412618a30848f11d18051245013fe53fa4e313ec701  p256_64.c

`p256_64.c` is kept only for validation; nothing is generated from it.

Curve constants were cross-checked against the published NIST P-384
parameters before use: `p = 2**384 - 2**128 - 2**96 + 2**32 - 1` and the
standard group order `n`, both reconstructed from the limbs fiat emits in
`msat` and compared numerically.

## Regenerating

    cd tools/fiat
    ./generate.py p384        > ../../src/sparktlscrypto-fiat_p384.adb
    ./generate.py p384_scalar > ../../src/sparktlscrypto-fiat_p384_scalar.adb

The `.ads` specs are hand-written (they carry the curve constants and the
contracts) and are not regenerated.

## What is and is not translated

Translated line-by-line, preserving fiat's SSA form: `mul`, `square`, `add`,
`sub`, `opp`, `from_montgomery`, `to_montgomery`, `selectznz`.

**Not** translated: `to_bytes` / `from_bytes`. fiat emits several hundred
lines of unrolled byte shuffling for these; the ports use ordinary
little-endian loops with identical semantics. This matches the choice already
made in the hand-written `Fiat_P256`.

Also not translated: `msat`, `divstep`, `divstep_precomp` (fiat's inversion
support). Neither P-256 nor P-384 uses them here — inversion is done in the
curve layer.

## Validation

Three independent things back these files. Be precise about which is which.

1. **Translator checked against known-good code (one-time, manual).** The
   same translator was run over `p256_64.c` and its `Mul` body compared
   statement-by-statement against the pre-existing hand-written
   `Fiat_P256` — all 103 arithmetic statements identical, differing only in
   integer-literal formatting and in the final aggregate assignment.

   Caveat, so nobody over-claims this: the *rest* of the hand-written P-256
   port inlines some `Cmovznz`/`Addcarryx` calls into explicit mask and
   `Unsigned_128` expressions. Those are semantically equivalent but not
   textually mechanical, so this is **not** a whole-file match and
   `ci/check-fiat-port.sh` deliberately does not assert one.

2. **Arithmetic checked against an independent reference.** Both modules were
   exercised against a Python implementation of the same modular arithmetic:
   46 vectors per operation (`0`, `1`, `m-1`, `(m-1)^2`, plus 40 random),
   covering serialisation, the Montgomery round-trip, `mul`, `sqr`, `add`,
   `sub` and `opp`. `Fiat_P384` was checked mod *p*, `Fiat_P384_Scalar` mod
   *n*. All passed.

3. **The test suite**, which is what actually gates a release: P-384 KATs,
   CAVP, wycheproof, and the ECDSA/ECDHE integration tests.

`ci/check-fiat-port.sh` covers none of the above — it only proves the
committed files still match their generator. That is a rot check, not a
correctness proof.

## Constant-time note

`Cmovznz_U64` is branchless by construction (`-(Arg1 and 1)` masking), matching
`Fiat_P256`. An `if` there would be a real hazard: the compiler may emit a
conditional jump on secret data.

fiat's C additionally wraps both operands in `value_barrier` to block compiler
reassociation. **The Ada ports omit it** — a pre-existing decision shared with
`Fiat_P256`, covered by the ctgrind and dudect suites empirically rather than
guaranteed by construction. Worth revisiting if either suite ever flags the
P-384 path.

## Limits of "formally verified"

fiat-crypto proves the *field arithmetic* correct. It does not generate curve
arithmetic — there is no point addition, doubling or scalar multiplication in
any of its C output, for any curve. The P-384 point layer in
`SPARKTLSCrypto.P384.*` is hand-written, exactly as `P256.Point` is, and is
backed by tests rather than proof.
