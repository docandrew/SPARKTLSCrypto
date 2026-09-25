# Prepared AES-GCM checks

Run these from an Alire environment that resolves SPARKNaCl. For the sibling
SPARKTLS workspace, use `alr exec -- gprbuild -s -P
../sparktlscrypto/tests/prepared/prepared.gpr` from SPARKTLS. OpenSSL development
headers and libcrypto are required for the independent oracle.

- `bin/test_prepared` compares prepared encryption with OpenSSL EVP and the
  existing one-shot encryptor for AES-128 and AES-256. It covers every length
  from 1 through 1025, TLS record tails, empty and partial AAD, multiple keys,
  nonzero array bounds, 32 buffer alignments with canaries, decrypt round trips, bad tags, and context erasure.
- `bin/bench_prepared` interleaves one-shot and cached encryption. Sample zero
  is warmup; retain the following 20 observations for each key/record size.
- `bin/timing_prepared` randomizes two key classes, uses serialized cycle
  timestamps and the same memory addresses, and reports raw and 99%-trimmed
  Welch statistics. It fails at |t| >= 4.5. Its deliberate timing-leak control
  must exceed the threshold. Passing is evidence, not a constant-time proof.

Repeat the differential test with `SPARKTLSCRYPTO_ASM=disabled` and `-s` to
exercise the portable fallback. Valgrind on the validation Linux host exposes
AES-NI but not AVX-512, providing another dispatch tier. The test prints the
actual tier flags; do not infer tier coverage from the command alone.

`tests/timing/ct_prepared.adb` additionally propagates secret-key taint through
preparation, repeated encryption, both key sizes, tails, and erasure. It is
included in `tests/timing/run_ctgrind.sh`; run that lane in portable and normal
configurations, with its negative control.

The one-shot APIs remain an independent implementation during this change.
The prepared context contains no counter or nonce. TLS owns those values,
invalidates the cache on write-key changes, and wipes it on key/session cleanup.
