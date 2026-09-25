# SPARKTLSCrypto CI

`ci/check.sh` is the local wrapper for the reproducible hosted-CI lane. Hosted
CI runs the same wrapper inside the Nix environment:

```shell
nix develop --command bash ci/check.sh
```

Formal proof is intentionally not part of default CI because `gnatprove` runs
are long and sensitive to prover/toolchain differences.

For manual proof of the crate with the pinned Nix/Alire tools:

```shell
nix develop --command bash ci/proof.sh
```

This scopes GNATprove to the SPARKTLSCrypto source units and fails only on
SPARKTLSCrypto findings. GNATprove may still report SPARKNaCl obligations pulled
in through semantic dependencies; those are classified separately.

Use `SPARKTLSCRYPTO_PROOF_LEVEL=2` to rerun the same crate-local proof at a
stronger prover level.

Timing checks are available as an optional lane:

```shell
nix develop --command bash ci/timing.sh ctgrind
nix develop --command bash ci/timing.sh dudect
```

`ctgrind` runs in the default hosted CI lane on x86_64 Linux. Any ctgrind
finding, harness canary failure, or Valgrind crash fails the job.

One harness is pinned to an exact count rather than zero: `ct_rsa_sign_crt`
must report exactly 3 memcheck errors. All three are one decision, the
verify-after-sign check on the RSA CRT path, whose outcome is public by
construction but whose operands derive from the poisoned key. The count is
enforced in both directions (more means a new key-dependent branch, fewer
means the poison stopped reaching the signer) and is not masked from the
tool. See the comment above that entry in `tests/timing/run_ctgrind.sh`.

`dudect` is statistical and machine-sensitive, so it should not be a default
required check.

## ci/mnemonics.sh: instruction-set gate for the tiers

Disassembles each hand-written tier object (default build) and fails on any
mnemonic outside its reviewed allowlist in `tests/timing/mnemonics/`, or on a
denied class (div/idiv, rep string ops, rdrand/rdseed, syscall). Units:
the ADX Montgomery kernel, the AVX2 fixed-base gather, AES-NI, PCLMULQDQ
GHASH, SHA-NI SHA-256, and the four AVX-512 tiers. The data-operating
mnemonics in each allowlist were reviewed against Intel's Data Operand
Independent Timing list
(https://www.intel.com/content/www/us/en/developer/articles/technical/software-security-guidance/resources/data-operand-independent-timing-instructions.html).
Three kinds of entry are outside that list and are allowed deliberately:
control-flow mnemonics (their conditions are checked by the ctgrind lane),
`cpuid`/`xgetbv` (each tier's one-time feature probe on public operands),
and `nop` padding. Instruction prefixes (`lock`, `data16`, `cs`, ...) are
skipped so the instruction behind them is what gets graded.
`ci/mnemonics.sh --record` regenerates the lists for review after an
intentional change.

## ci/fuzz.sh: differential fuzzing of the tiers

`tests/fuzz/diff_fuzz.adb` runs every accelerated tier against its proven
SPARK twin for a time budget (`ci/fuzz.sh SECONDS [SEED]`, CI uses 60 s
and the fixed default seed; nightly runs should vary the seed): the
Montgomery multiply at 4 to 64 words, the four-limb and P-256 cores, the
fixed-base gather, AES-NI against SPARKNaCl AES, PCLMULQDQ GF(2^128)
against the software multiply. Limbs come from a carry-adversarial mix
(random, 0, all ones, single bits, 2^64 - small, alternating). Every
Montgomery product is also checked against a third, structurally different
implementation (schoolbook product then separated REDC), and every P-256
field multiply and square against fiat-crypto's Coq-verified C
(`tools/fiat/p256_64.c`, compiled into the test binary through
`tests/fuzz/fiat_oracle.c`). Every Montgomery product with operands below
the modulus is further checked against HACL*'s F*-verified
`Hacl_Bignum_Montgomery_bn_mont_mul_u64`, and one round in 128 checks
`BigNat64.Modpow` against HACL*'s verified constant-time `mod_exp` at 4,
8 and 16 words (the HACL* sources are the pinned `hacl-star` flake input,
exported to the dev shell as `HACL_STAR_SRC`, compiled through
`tests/fuzz/hacl_oracle.c`; the library itself stays C-free). A mismatch
prints the operands in hex and fails the lane.

## Prepared AES-GCM

`ci/prepared.sh`, included in `ci/check.sh`, runs the independent OpenSSL EVP
comparison with runtime and contract checks enabled, in both accelerated and
portable configurations. It requires OpenSSL headers and libcrypto, supplied by
the development shell. The production library retains its Ada/assembly-only
linkage. See `tests/prepared/README.md` for alignment, lifecycle, timing, and
benchmark coverage. `ct_prepared` is included in the ctgrind lane.

## Field25519 carry widths

`ci/field25519.sh`, included in `ci/check.sh`, compares 31,800 results against
OpenSSL bignum arithmetic with runtime checks and contracts enabled, then
restores the caller's build configuration. It covers the full documented limb
bounds and checks the exact-limb digest captured before the carry-width change.
See `tests/field25519/README.md` for primitive benchmarks, timing checks and the
related X25519/Ed25519 validation commands.

## GHASH16 reduction

ci/ghash16.sh, included in ci/check.sh, verifies the Montgomery reduction
algebra on every operand basis pair and compares the compiled AVX-512 kernel
with independent bit-serial GHASH. The saved pre-change digest also has to
match. See tests/ghash16/README.md for the argument, coverage and limitations.
The instruction allowlist adds only immediate-control vpshufd, a fixed
shuffle with operand-independent timing and no new feature requirement.
