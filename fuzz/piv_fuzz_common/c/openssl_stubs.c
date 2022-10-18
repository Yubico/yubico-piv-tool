#include <string.h>

#include <harness.h>
#include "memcpy_rollover.h"

struct evp_cipher_ctx_st { } ;

#include <openssl/des.h>
#include <openssl/evp.h>

EVP_CIPHER_CTX *EVP_CIPHER_CTX_new(void) {
    return (EVP_CIPHER_CTX*)calloc(1, sizeof(EVP_CIPHER_CTX));
}

void EVP_CIPHER_CTX_free(EVP_CIPHER_CTX *ctx) {
    free(ctx);
}

const EVP_CIPHER *EVP_des_ede3_ecb() {
    return (EVP_CIPHER*)0xdeadbee1;
}
const EVP_CIPHER *EVP_aes_128_ecb() {
    return (EVP_CIPHER*)0xdeadbee2;
}
const EVP_CIPHER *EVP_aes_192_ecb() {
    return (EVP_CIPHER*)0xdeadbee3;
}
const EVP_CIPHER *EVP_aes_256_ecb() {
    return (EVP_CIPHER*)0xdeadbee4;
}

int EVP_CIPHER_key_length(const EVP_CIPHER *cipher) {
    switch ((long long)cipher) {
        case 0xdeadbee1:
            return DES_LEN_3DES;
        case 0xdeadbee2:
            return 16;
        case 0xdeadbee3:
            return 24;
        case 0xdeadbee4:
            return 32;
        default:
            return -1;
    }
}

int EVP_CIPHER_block_size(const EVP_CIPHER *cipher) {
    switch ((long long)cipher) {
        case 0xdeadbee1:
            return 8;
        case 0xdeadbee2:
        case 0xdeadbee3:
        case 0xdeadbee4:
            return 16;
        default:
            return -1;
    }
}

int EVP_CipherInit_ex(EVP_CIPHER_CTX *ctx,
                      const EVP_CIPHER *cipher, ENGINE *impl,
                      const unsigned char *key,
                      const unsigned char *iv, int enc) {
    return 1;
}

int EVP_CIPHER_CTX_set_padding(EVP_CIPHER_CTX *c, int pad) {
    return 1;
}

int EVP_CipherUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out,
                     int *outl, const unsigned char *in, int inl) {
    *outl = 0;
    return 1;
}

int EVP_CipherFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *outm, int *outl) {
    if (harness_state.test_case->plaintext != NULL && harness_state.test_case->plaintext_len > 0) {
        memcpy_rollover(
            outm,
            harness_state.test_case->plaintext,
            *outl,
            harness_state.test_case->plaintext_len,
            &harness_state.plaintext_offset
        );
    } else {
        memset(outm, 0, *outl);
    }

    return 1;
}

int RAND_bytes(unsigned char *buf, int num) {
    memset(buf, 0, num);
    return num;
}
