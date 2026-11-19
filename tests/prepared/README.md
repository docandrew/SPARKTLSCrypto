# Prepared AES-GCM checks

Run these from an Alire environment that resolves SPARKNaCl. For the sibling
SPARKTLS workspace, use `alr exec -- gprbuild -s -P
../sparktlscrypto/tests/prepared/prepared.gpr` from SPARKTLS. OpenSSL development
headers and libcrypto are required for the independent oracle.

- `bin/test_prepared` compares prepared encryption with OpenSSL EVP and the
  existing one-shot encryptor for AES-128 and AES-256. It covers every length
  from 1 through 1025, TLS record tails, empty and partial AAD, multiple keys,
  nonzero array bounds, 32 buffer alignments with canaries, decrypt round trips, bad tags, and context erasure.
- `bin/test_decrypt` checks `Decrypt_Prepared`, `Decrypt_InPlace(_256)` and
  the one-shot `Decrypt(_256)` against OpenSSL EVP on every AES-GCM tier the
  CPU has, switching tiers in one process by overwriting the CPUID flags
  (test-only): every ciphertext length 0 .. 300 and AAD length 0 .. 300,
  lengths around the 16/64/256/512-byte stripes up to 64 KiB, 64 buffer
  alignments with guard bytes, every single-bit flip of tag, ciphertext and
  AAD, equal flips at two tag positions, wrong nonce and key (all must fail
  with the buffer zeroed), and `Encrypt_Prepared` on every tier.
- `bin/bench_prepared` has two sections. `prepared` interleaves one-shot and
  cached encryption. `aead` times SPARKTLSCrypto encryption and decryption
  against OpenSSL EVP with a cached key schedule (the key is set once, each
  record installs only a nonce) for AES-128/256-GCM at 64 B, 1 KiB and
  16 KiB, rotating the order of the rows every sample, and prints a summary
  per row: median, interquartile range and extremes in ns per record, and
  MB/s at the median and quartiles. Decrypt rows always open an authentic
  record; `stc.decrypt_prepared+copy` copies the ciphertext into the buffer
  before each in-place decryption, and the `copy` row times that copy alone.
  Sample zero is warmup; the following 20 observations are retained
  for each key/record size. With no argument both sections run; a second
  argument (`portable`, `aes-ni`, `vaes-256`, `vaes-512`) restricts the
  library to one AES-GCM tier, as `test_decrypt` does. Pin the
  process to one core (`taskset -c N`) and quote the machine with numbers.
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
