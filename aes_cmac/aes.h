/*
 * Copyright (c) 2024 Yubico AB
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *
 *   * Redistributions in binary form must reproduce the above
 *     copyright notice, this list of conditions and the following
 *     disclaimer in the documentation and/or other materials provided
 *     with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#ifndef YUBICO_PIV_TOOL_AES_H
#define YUBICO_PIV_TOOL_AES_H

#include <stdint.h>

#ifdef _WIN32
#include <windows.h>
#include <bcrypt.h>
#else
#include <openssl/evp.h>
#endif

#ifndef AES_BLOCK_SIZE // Defined in openssl/aes.h
#define AES_BLOCK_SIZE 16
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
#ifdef _WIN32
    BCRYPT_ALG_HANDLE hAlgCBC;
    BCRYPT_ALG_HANDLE hAlgECB;
    BCRYPT_KEY_HANDLE hKeyCBC;
    BCRYPT_KEY_HANDLE hKeyECB;
    PBYTE pbKeyCBCObj;
    PBYTE pbKeyECBObj;
    size_t cbKeyObj;
#else
    EVP_CIPHER_CTX *ctx;
    unsigned char key_algo;
    uint8_t key[EVP_MAX_KEY_LENGTH];
#endif
} aes_context;

#ifndef _WIN32
#define YH_INTERNAL __attribute__((visibility("hidden")))
#else
#define YH_INTERNAL
#endif

int YH_INTERNAL aes_set_key(const uint8_t *key, uint32_t key_len, unsigned char key_algo,
                                  aes_context *ctx);

int YH_INTERNAL
aes_encrypt(const uint8_t *in, uint32_t in_len, uint8_t *out, uint32_t *out_len, aes_context *ctx);
int YH_INTERNAL
aes_decrypt(const uint8_t *in, uint32_t in_len, uint8_t *out, uint32_t *out_len, aes_context *ctx);

int YH_INTERNAL aes_cbc_encrypt(const uint8_t *in, uint32_t in_len, uint8_t *out, uint32_t *out_len,
                                      const uint8_t *iv, uint32_t iv_len, aes_context *ctx);
int YH_INTERNAL aes_cbc_decrypt(const uint8_t *in, uint32_t in_len, uint8_t *out, uint32_t *out_len,
                                      const uint8_t *iv, uint32_t iv_len, aes_context *ctx);

uint32_t YH_INTERNAL aes_blocksize(aes_context *key);
int YH_INTERNAL aes_add_padding(uint8_t *in, uint32_t max_len, uint32_t *len);
void YH_INTERNAL aes_remove_padding(uint8_t *in, uint32_t *len);

int YH_INTERNAL aes_destroy(aes_context *ctx);

#ifdef __cplusplus
}
#endif

#endif //YUBICO_PIV_TOOL_AES_H
