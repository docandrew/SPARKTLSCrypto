/* Test-only oracle: HACL*'s F*-verified generic bignum (Hacl_Bignum64,
   extracted C from the pinned hacl-star flake input), compiled into the
   differential fuzzer as one translation unit and wrapped in three exported
   entry points. The library itself contains no C; this file is linked into
   tests/fuzz only. HACL_STAR_SRC (the dev shell exports it) provides the
   include paths, see fuzz.gpr. */
#include <stdint.h>
#include <stdbool.h>
#include "Hacl_Bignum.c"
#include "Hacl_Bignum64.c"

/* resM = aM * bM * 2^(-64 len) mod n, for aM, bM < n; nInv = -n^-1 mod 2^64 */
void oracle_hacl_mont_mul(uint32_t len, uint64_t *n, uint64_t nInv,
                          uint64_t *aM, uint64_t *bM, uint64_t *resM)
{
  Hacl_Bignum_Montgomery_bn_mont_mul_u64(len, n, nInv, aM, bM, resM);
}

/* resM = aM^2 * 2^(-64 len) mod n, for aM < n */
void oracle_hacl_mont_sqr(uint32_t len, uint64_t *n, uint64_t nInv,
                          uint64_t *aM, uint64_t *resM)
{
  Hacl_Bignum_Montgomery_bn_mont_sqr_u64(len, n, nInv, aM, resM);
}

/* res = a ^ b mod n, b of bBits bits; returns 1 when HACL accepted the inputs */
int oracle_hacl_mod_exp(uint32_t len, uint64_t *n, uint64_t *a,
                        uint32_t bBits, uint64_t *b, uint64_t *res)
{
  return Hacl_Bignum64_mod_exp_consttime(len, n, a, bBits, b, res) ? 1 : 0;
}

/* nInv as HACL computes it, to confirm the convention matches ours */
uint64_t oracle_hacl_mod_inv_limb(uint64_t n0)
{
  return Hacl_Bignum_ModInvLimb_mod_inv_uint64(n0);
}
