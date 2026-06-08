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
