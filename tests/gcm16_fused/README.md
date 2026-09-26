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
