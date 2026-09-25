#include <openssl/evp.h>
#include <stddef.h>
#include <string.h>
int base25519_check(const unsigned char *seed, const unsigned char *pk,
                    const unsigned char *sig, const unsigned char *msg,
                    size_t len, const unsigned char *xp) {
    unsigned char want_pk[32], want_sig[64], want_x[32];
    size_t pkl = 32, sigl = 64, xl = 32;
    EVP_PKEY *ed = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, seed, 32);
    EVP_PKEY *x = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, seed, 32);
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    int ok = ed && x && ctx &&
        EVP_PKEY_get_raw_public_key(ed, want_pk, &pkl) == 1 && pkl == 32 &&
        EVP_PKEY_get_raw_public_key(x, want_x, &xl) == 1 && xl == 32 &&
        EVP_DigestSignInit(ctx, NULL, NULL, NULL, ed) == 1 &&
        EVP_DigestSign(ctx, want_sig, &sigl, msg, len) == 1 && sigl == 64 &&
        memcmp(pk, want_pk, 32) == 0 && memcmp(sig, want_sig, 64) == 0 &&
        memcmp(xp, want_x, 32) == 0;
    EVP_MD_CTX_free(ctx); EVP_PKEY_free(ed); EVP_PKEY_free(x);
    return ok;
}
