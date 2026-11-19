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

/* Decrypt oracle: one-shot EVP decrypt of len bytes from in to out (which
 * may alias). Returns 1 if the tag verified, 0 if it did not, -1 on an
 * OpenSSL error. On a tag failure OpenSSL leaves the unauthenticated
 * plaintext in out; callers that compare against SPARKTLSCrypto check
 * only the status in that case. */
int openssl_gcm_open(const unsigned char *key, int bits, const unsigned char *iv,
                     const unsigned char *aad, int aad_len,
                     const unsigned char *in, unsigned char *out, int len,
                     const unsigned char *tag) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int n = 0, written = 0, rc = -1;
    if (!ctx) return -1;
    if (EVP_DecryptInit_ex(ctx, bits == 128 ? EVP_aes_128_gcm() : EVP_aes_256_gcm(),
                           NULL, key, iv) == 1 &&
        EVP_DecryptUpdate(ctx, NULL, &n, aad, aad_len) == 1 &&
        EVP_DecryptUpdate(ctx, out, &written, in, len) == 1 &&
        written == len &&
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void *)tag) == 1)
        rc = EVP_DecryptFinal_ex(ctx, out + written, &n) == 1 ? 1 : 0;
    EVP_CIPHER_CTX_free(ctx);
    return rc;
}

/* Benchmark contexts: the key schedule is set once (the analogue of
 * Prepare_128/256), and each record only installs a nonce, as a TLS
 * record layer using EVP would. */
void *openssl_gcm_bench_new(const unsigned char *key, int bits, int decrypt) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    const EVP_CIPHER *c = bits == 128 ? EVP_aes_128_gcm() : EVP_aes_256_gcm();
    if (!ctx) return NULL;
    if ((decrypt ? EVP_DecryptInit_ex(ctx, c, NULL, key, NULL)
                 : EVP_EncryptInit_ex(ctx, c, NULL, key, NULL)) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }
    return ctx;
}

void openssl_gcm_bench_free(void *ctx) { EVP_CIPHER_CTX_free(ctx); }

int openssl_gcm_bench_seal(void *ctx, const unsigned char *iv,
                           const unsigned char *aad, int aad_len,
                           unsigned char *buf, int len, unsigned char *tag) {
    int n = 0, written = 0;
    return EVP_EncryptInit_ex(ctx, NULL, NULL, NULL, iv) == 1 &&
           EVP_EncryptUpdate(ctx, NULL, &n, aad, aad_len) == 1 &&
           EVP_EncryptUpdate(ctx, buf, &written, buf, len) == 1 &&
           EVP_EncryptFinal_ex(ctx, buf + written, &n) == 1 &&
           EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) == 1;
}

int openssl_gcm_bench_open(void *ctx, const unsigned char *iv,
                           const unsigned char *aad, int aad_len,
                           const unsigned char *in, unsigned char *out, int len,
                           const unsigned char *tag) {
    int n = 0, written = 0;
    return EVP_DecryptInit_ex(ctx, NULL, NULL, NULL, iv) == 1 &&
           EVP_DecryptUpdate(ctx, NULL, &n, aad, aad_len) == 1 &&
           EVP_DecryptUpdate(ctx, out, &written, in, len) == 1 &&
           EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void *)tag) == 1 &&
           EVP_DecryptFinal_ex(ctx, out + written, &n) == 1;
}

/* Opaque to the optimiser: the benchmark's copy-only row stays a copy. */
void bench_barrier(void *p) { __asm__ volatile("" : : "r"(p) : "memory"); }
