#include <openssl/bn.h>
#include <stdint.h>

_Static_assert(sizeof(BN_ULONG) == sizeof(uint64_t), "64-bit OpenSSL required");

static int decode(BIGNUM *out, const uint64_t limbs[5], BIGNUM *tmp) {
    BN_zero(out);
    for (int i = 4; i >= 0; --i) {
        if (!BN_lshift(out, out, 51) || !BN_set_word(tmp, limbs[i]) ||
            !BN_add(out, out, tmp)) return 0;
    }
    return 1;
}

/* Independent mathematical oracle over the full public limb-input domain. */
int field25519_check(int op, const uint64_t r[5], const uint64_t a[5],
                     const uint64_t b[5], uint64_t scalar) {
    BN_CTX *ctx = BN_CTX_new();
    if (!ctx) return 0;
    BN_CTX_start(ctx);
    BIGNUM *aa = BN_CTX_get(ctx), *bb = BN_CTX_get(ctx);
    BIGNUM *rr = BN_CTX_get(ctx), *want = BN_CTX_get(ctx);
    BIGNUM *p = BN_CTX_get(ctx), *tmp = BN_CTX_get(ctx);
    int ok = tmp && BN_one(p) && BN_lshift(p, p, 255) && BN_sub_word(p, 19) &&
             decode(aa, a, tmp) && decode(bb, b, tmp) && decode(rr, r, tmp);
    for (int i = 0; i < 5; ++i) ok = ok && r[i] <= (UINT64_C(1) << 51);
    if (ok && op == 0) ok = BN_mod_mul(want, aa, bb, p, ctx);
    else if (ok && op == 1) ok = BN_mod_sqr(want, aa, p, ctx);
    else if (ok && op == 2)
        ok = BN_set_word(bb, scalar) && BN_mod_mul(want, aa, bb, p, ctx);
    else ok = 0;
    if (ok) ok = BN_nnmod(rr, rr, p, ctx) && BN_cmp(rr, want) == 0;
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    return ok;
}

#include <stdint.h>
#include <x86intrin.h>
uint64_t field25519_ticks(void) {
    _mm_lfence();
    uint64_t t = __rdtsc();
    _mm_lfence();
    return t;
}
void field25519_timing_canary(unsigned char secret) {
    volatile unsigned int sink = 0;
    for (unsigned int i = 0; i < (secret == 0 ? 100u : 1u); ++i) sink += i;
    (void)sink;
}
