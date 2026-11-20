# Fused sixteen-block AES-GCM stripes

Run ci/gcm16_fused.sh in the crate's Alire environment. The checked optimized
test performs 8,192 comparisons with the separate VAES and GHASH functions:
both key sizes, every 64-byte alignment, nonzero array bounds, arbitrary
counter blocks and incoming hash states, and zero/all-one hash keys. Buffer
and accumulator guards, immutable counters, powers and round keys are checked.
A deterministic digest pins the separate-kernel reference outputs.
Unsupported CPUs report an explicit skip.

The prepared AES-GCM oracle additionally checks complete ciphertext/tag results
against OpenSSL, all short tails and record lengths, both key sizes, decryption,
bad tags and context erasure. Native timing and instruction inspection cover
the AVX-512 tier; Valgrind does not execute AVX-512 on the validation host.

`bin/test_stripes` checks the generated stitched kernels
(tools/generate_gcm_kernels.py): the AES-NI 4-block and VAES 16/32-block
decryption stripes, and the VAES-256 encryption stripes (counter-only,
pipelined, GHASH-only), against a block-at-a-time reference made of
SPARKNaCl's software AES, an Ada inc32 and one GF(2^128) multiply per
block. Both key sizes, every 64-byte alignment, zero/all-one hash keys,
counters that wrap inside the stripe; guards around buffer, accumulator and
counter, and immutable round keys and powers; every case is rerun with the
buffer and the powers against PROT_NONE guard pages (both ends), so an
out-of-bounds read faults (a mutant kernel with one extra 16-byte load past
its stripe dies with SIGSEGV). Kernels the CPU lacks are
reported as skipped.
