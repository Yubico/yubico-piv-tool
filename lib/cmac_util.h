//
// Created by aveen on 12/12/24.
//

#ifndef YUBICO_PIV_TOOL_CMAC_H
#define YUBICO_PIV_TOOL_CMAC_H

#ifdef _WIN32
#include <windows.h>
#include <bcrypt.h>
#include <ntstatus.h>
#else
#include <openssl/evp.h>
#endif

#define AES_BLOCK_SIZE 16

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
    uint8_t key[AES_BLOCK_SIZE];
#endif
} cmac_context;


typedef struct {
    cmac_context *aes_ctx;
    uint8_t k1[AES_BLOCK_SIZE];
    uint8_t k2[AES_BLOCK_SIZE];
} aes_cmac_context_t;

#ifndef __WIN32
#define YH_INTERNAL __attribute__((visibility("hidden")))
#else
#define YH_INTERNAL
#endif

//int YH_INTERNAL aes_cmac_init(cmac_context *aes_ctx, aes_cmac_context_t *ctx);
//int YH_INTERNAL aes_cmac_encrypt(aes_cmac_context_t *ctx,
//                                 const uint8_t *message,
//                                 const uint16_t message_len, uint8_t *mac);
//void YH_INTERNAL aes_cmac_destroy(aes_cmac_context_t *ctx);

int compute_full_mac(const uint8_t *data, uint16_t data_len,
                       const uint8_t *key, uint16_t key_len,
                       uint8_t *mac);

#endif //YUBICO_PIV_TOOL_CMAC_H
