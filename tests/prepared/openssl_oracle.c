#include <openssl/evp.h>
#include <stddef.h>
int openssl_gcm(const unsigned char *key, int bits, const unsigned char *iv,
                const unsigned char *aad, int aad_len, unsigned char *buf,
                int len, unsigned char *tag) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int n = 0, written = 0;
    if (!ctx) return 0;
    int ok = EVP_EncryptInit_ex(ctx, bits == 128 ? EVP_aes_128_gcm() : EVP_aes_256_gcm(),
                              NULL, key, iv) == 1 &&
             EVP_EncryptUpdate(ctx, NULL, &n, aad, aad_len) == 1 &&
             EVP_EncryptUpdate(ctx, buf, &written, buf, len) == 1 &&
             EVP_EncryptFinal_ex(ctx, buf + written, &n) == 1 &&
             written + n == len &&
             EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) == 1;
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

#include <stdint.h>
#include <x86intrin.h>
uint64_t prepared_ticks(void) {
    _mm_lfence();
    uint64_t t = __rdtsc();
    _mm_lfence();
    return t;
}
void prepared_timing_canary(unsigned char secret) {
    volatile unsigned int sink = 0;
    for (unsigned int i = 0; i < (secret == 0 ? 100u : 1u); ++i) sink += i;
    (void)sink;
}
