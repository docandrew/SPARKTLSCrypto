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

`dudect` is statistical and machine-sensitive, so it should not be a default
required check.
