/* Test-only oracle: fiat-crypto's Coq-verified C for P-256 (tools/fiat/
   p256_64.c, kept verbatim, functions are static) wrapped in two
   exported entry points for the differential fuzzer. The library itself
   contains no C; this file is linked into tests/fuzz only. */
#include <stdint.h>
#include "../../tools/fiat/p256_64.c"

void oracle_fiat_p256_mul(uint64_t out[4], const uint64_t a[4], const uint64_t b[4])
{
  fiat_p256_mul(out, a, b);
}

void oracle_fiat_p256_square(uint64_t out[4], const uint64_t a[4])
{
  fiat_p256_square(out, a);
}
