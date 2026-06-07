# SPARKTLSCrypto CI

`ci/check.sh` is the local wrapper for the reproducible hosted-CI lane. Hosted
CI runs the same core command directly:

```shell
nix develop --command alr build
```

Formal proof is intentionally not part of default CI because `gnatprove` runs
are long and sensitive to prover/toolchain differences.

Timing checks are available as an optional lane:

```shell
nix develop --command bash ci/timing.sh ctgrind
nix develop --command bash ci/timing.sh dudect
```

`ctgrind` is suitable for occasional CI/manual runs on x86_64 Linux.
`dudect` is statistical and machine-sensitive, so it should not be a default
required check.
