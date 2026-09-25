# Field25519 carry-width validation

The `Fiat_25519.Mul` optimization retains the original products and reduction
order, but stores carries in 64 bits once their bounds permit it. All products
and unreduced sums remain 128 bits. The existing input/output contracts are
unchanged. Explicit SPARK assertions establish that each narrowed value fits
and each subsequent 64-bit operation does not wrap.

From the crypto repository's Alire environment:

```sh
ci/field25519.sh
alr exec -- gprbuild -s -P tests/field25519/field25519.gpr
# Linux: select an idle physical core, e.g. the benchmark host's CPU 32.
taskset -c 32 tests/field25519/bin/bench_field25519
taskset -c 32 tests/field25519/bin/timing_field25519
```

`ci/field25519.sh` is part of `ci/check.sh`. It enables runtime checks and
contracts for the arithmetic tests and restores the caller's build configuration
on success. The OpenSSL headers and libcrypto are test dependencies only.

- `test_field25519` checks 31,800 multiplication, squaring and scalar-multiplication
  results against OpenSSL bignum arithmetic modulo 2^255-19. Its boundary cases
  include the full public input bound (each limb up to 2^53), all-limb and
  single-limb patterns, followed by 10,000 deterministic pseudorandom input pairs.
  Each result limb must also satisfy the existing bound of 2^51. The fixed
  digest of exact output limbs was captured from revision `46f7e24` before the
  optimization; it detects representation changes, including noncanonical ones.
- `bench_field25519` prints one warmup followed by 20 samples for field multiply,
  square, X25519 and Ed25519 signing. Field operations form dependent chains;
  times are batch means, not individual-operation tail latencies. Preserve the
  baseline executable before changing the library, then alternate old/new
  processes on the same core. Full handshakes are measured separately with the
  SPARKTLS comparison runner.
- `timing_field25519` tests X25519 and Ed25519 signing using 40,000 samples per
  key class, randomized class order, fixed input/output addresses, serialized
  timestamps and both raw and 99%-trimmed Welch statistics. It fails at |t| >= 4.5;
  its deliberate timing leak must exceed the threshold. Passing supplements
  secret-taint analysis; it is not a universal constant-time proof.

Also run the RFC 7748/8032 and field KAT executables in SPARKTLS,
`tests/timing/ct_x25519`, `tests/timing/ct_ed25519`, their negative control,
and `tests/residue/residue_scan`. Test the production optimization settings:
changing the compiler settings can change constant-time and erasure properties.

The Ed25519 benchmark and timing helper use a 96-byte signed-message buffer
for their 32-byte message, as required by Sign. Before this correction they
used 64 bytes and violated the API precondition. The old Ed25519 primitive
timing/performance numbers from those helpers are invalid; collect a fresh
baseline with this version. X25519 and field arithmetic measurements are
unaffected. The benchmark also reports fixed-base X25519 separately.
