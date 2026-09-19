# SPARKTLSCrypto

SPARKTLSCrypto provides SPARK/Ada cryptographic primitives used by SPARKTLS.

This crate is under active development and should be treated as alpha-quality
software until the surrounding SPARKTLS stack reaches its verification and
release goals.

## Platform Support

The current crate is intended for `x86_64-linux` builds. SHA-256 has a
software fallback when SHA-NI is unavailable, but other accelerated units still
contain x86/x86_64 inline assembly and CPUID/XGETBV feature detection. ARM and
RISC-V support should be treated as future work until those units have
portable stubs or architecture-selected bodies.

The timing tests are also x86_64-specific: ctgrind and dudect harnesses use
Valgrind and `rdtsc`.

## Accelerated tiers and the portable build

Every hand-written x86_64 unit (AES-NI, PCLMULQDQ GHASH, the AVX-512
AEAD units, the BMI2/ADX Montgomery multiply behind RSA and the P-256
field) is chosen at run time from CPUID and falls back to the proven
SPARK implementation when the feature is absent. To turn all of them off
and run only the proven code, build with

```shell
SPARKTLSCRYPTO_ASM=disabled alr build
```

The choice is compiled in (`SPARKTLSCrypto.Tier_Config`, selected by
source directory, with its own `obj/disabled` and `lib/disabled`) and is
visible in the build. The library reads no environment variable, file or
other runtime input to make it, and needs no Ada runtime support beyond
what the arithmetic itself uses. The smoke tests check the BMI2/ADX tier
against the SPARK Montgomery multiply on random operands and print which
path is active.

Valgrind's virtual CPU does not advertise BMI2/ADX, so the ctgrind lane
builds with `SPARKTLSCRYPTO_ASM=assume_bmi2_adx`, which reports the tier
present without CPUID so memcheck's taint tracking runs the assembly
(Valgrind 3.22 executes the instructions). That build faults on a CPU
without the instructions and is for the test lanes only.
`CTGRIND_PORTABLE=1` runs the lane on the portable path instead.

## Build

Use Alire to build the library:

```shell
alr build
```

For a checked debug build:

```shell
SPARKTLSCRYPTO_BUILD_MODE=debug \
SPARKTLSCRYPTO_RUNTIME_CHECKS=enabled \
SPARKTLSCRYPTO_CONTRACTS=enabled \
alr build
```

Optimized builds default to a reproducible x86-64 configuration: the generic
code targets `x86-64-v2`, and the handwritten AVX-512 units are compiled with
their required feature flags for runtime dispatch. For local benchmarking on
the current host CPU, use:

```shell
SPARKTLSCRYPTO_BUILD_MODE=native alr build
```

## Reproducible CI Environment

The Nix flake pins the host tools used by CI:

```shell
nix develop --command alr build
```

The CI lane intentionally builds and checks the crate but does not run
`gnatprove`; proof runs are currently too expensive and toolchain-sensitive
for a default hosted CI gate.

## Formal Proof

Manual proof runs use the Alire-pinned GNATprove toolchain:

```shell
nix develop --command bash ci/proof.sh
```

This scopes GNATprove to the SPARKTLSCrypto source units, records the invocation
header, and classifies dependency findings separately. GNATprove may still
report SPARKNaCl obligations pulled in through semantic dependencies; reports
under `src/sparktlscrypto-*` are SPARKTLSCrypto findings, while SPARKNaCl
findings should be checked against the upstream crate's own proof expectations.

To increase prover strength for this crate-local proof:

```shell
SPARKTLSCRYPTO_PROOF_LEVEL=2 nix develop --command bash ci/proof.sh
```

Optional timing checks live under `tests/timing`:

```shell
nix develop --command bash ci/timing.sh ctgrind
nix develop --command bash ci/timing.sh dudect
```
