# GHASH16 reduction checks

Run from an Alire environment resolving SPARKNaCl:

    python3 tests/ghash16/check_algebra.py
    SPARKTLSCRYPTO_RUNTIME_CHECKS=enabled SPARKTLSCRYPTO_CONTRACTS=enabled alr exec -- gprbuild -s -P tests/ghash16/ghash16.gpr test_ghash16.adb
    tests/ghash16/bin/test_ghash16

From the sibling SPARKTLS checkout, use its Alire environment with the
project path ../sparktlscrypto/tests/ghash16/ghash16.gpr.
ci/ghash16.sh runs this lane and restores the caller's library configuration.

The Ada test compares 20,480 assembled GHASH16 results with an independent
bit-serial implementation: all 16,384 pairs of operand basis bits, then 4,096
chained batches using all sixteen powers, nonzero accumulators, 64 buffer
alignments, nonzero array bounds, input immutability and guard checks.
It verifies a deterministic digest captured from the original implementation.
Unsupported CPUs explicitly skip the hardware test; they still run the
architecture-independent algebra check. OpenSSL EVP coverage of complete
AES-GCM records is in ../prepared.

## Arithmetic argument

Byte-reversed GHASH uses the reflected polynomial
Q(x) = x^128 + x^127 + x^126 + x^121 + 1.
After combining the carry-less products, the existing one-bit correction
multiplies the raw 256-bit value by x. The highest possible raw product degree
is 254, including an XOR sum of products, so this correction loses no bit.

Q's low 64-bit limb is 1, and its next limb is C = 0xc200000000000000.
For low half L = (L_hi:L_lo), one Montgomery cancellation is
L = swap64(L) XOR CLMUL(L_lo, C). Repeating this twice and XORing the
original high half yields T*x^-128 modulo Q. Together with the correction,
this is the same GHASH multiplication as the original shift reduction.

The Python model checks all 128*128 input basis pairs against bit-serial GHASH.
Both modeled maps are bilinear over GF(2), so equality on those pairs implies
equality on every input pair. This is a finite algebra check, not a machine-code
proof. The Ada test separately exercises the compiled assembly.

Combining the cross terms within each SIMD lane before the horizontal XOR
is valid because both transformations are linear. H powers, representation,
block ordering, counters, nonces, API contracts and CPU feature checks are
unchanged. No floating point or random-number generation is involved in the
production routine. Its addresses and instruction sequence are independent of
keys and data. The new vpshufd instruction has an immediate shuffle control,
uses VEX 128-bit encoding, and introduces no additional CPU feature requirement.
Native key-class timing checks remain in ../prepared/timing_prepared.adb;
Valgrind does not execute this AVX-512 path.

## Performance

bench_ghash16 reports 20 warmed batch means and a consumed output byte.
Each sample chains one million sixteen-block GHASH calls. Sample zero is
warmup. Compare preserved executables in alternating, CPU-pinned fresh
processes; these are batch means, not per-call tail latency measurements.
