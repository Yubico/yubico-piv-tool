//
// Created by aveen on 12/12/24.
//
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "cmac_util.h"
#include "aes_util.h"
#include "internal.h"



static const uint8_t zero[AES_BLOCK_SIZE] = {0};

static void do_pad(uint8_t *data, uint8_t len) {

  for (uint8_t i = len; i < AES_BLOCK_SIZE; i++)
    if (i == len)
      data[i] = 0x80;
    else
      data[i] = 0x00;
}

static void do_xor(const uint8_t *a, uint8_t *b) {

  for (uint8_t i = 0; i < AES_BLOCK_SIZE; i++) {
    b[i] ^= a[i];
  }
}

static void do_shift_one_bit_left(const uint8_t *a, uint8_t *b,
                                  uint8_t *carry) {
  for (int8_t i = AES_BLOCK_SIZE - 1; i >= 0; i--) {
    b[i] = (a[i] << 1) | *carry;

    *carry = a[i] >> 7;
  }
}

static void cmac_generate_subkey(const uint8_t *key, uint8_t *subkey) {

  uint8_t carry = 0;

  do_shift_one_bit_left(key, subkey, &carry);

  subkey[AES_BLOCK_SIZE - 1] ^= 0x87 >> (8 - (carry * 8));
}

static int aes_cbc_encrypt(const uint8_t *in, uint16_t in_len, uint8_t *out, uint16_t *out_len,
                    const uint8_t *iv, cmac_context *ctx) {
#ifdef _WIN32
  NTSTATUS status = STATUS_SUCCESS;
  ULONG cbResult = 0;

  UCHAR _iv[AES_BLOCK_SIZE];
  memcpy(_iv, iv, AES_BLOCK_SIZE);

  if (!BCRYPT_SUCCESS(status = BCryptEncrypt(ctx->hKeyCBC, (PUCHAR) in, in_len,
                                             NULL, _iv, AES_BLOCK_SIZE, out,
                                             *out_len, &cbResult, 0))) {
    return -1;
  }

  if (cbResult != len) {
    return -2;
  }

  return 0;

#else

//  return aes_encrypt_ex(aes_cbc(ctx->key_len), in, out, len, iv, ctx);


  cipher_key enc_key = NULL;
  cipher_rc drc = cipher_import_key_cbc(YKPIV_ALGO_AES128, ctx->key, AES_BLOCK_SIZE, &enc_key);
  if (drc != CIPHER_OK) {
    DBG("%s: cipher_import_key: %d", ykpiv_strerror(YKPIV_ALGORITHM_ERROR), drc);
    return drc;
  }

  drc = cipher_encrypt(enc_key, in, in_len, iv, AES_BLOCK_SIZE, out, (uint32_t *) out_len);
  if (drc != CIPHER_OK) {
    DBG("%s: cipher_encrypt: %d", ykpiv_strerror(YKPIV_KEY_ERROR), drc);
    return drc;
  }

  return 0;
#endif
}

static int aes_encrypt(const uint8_t *in, uint16_t in_len, uint8_t *out, uint16_t *out_len, cmac_context *ctx) {
#ifdef _WIN32
  NTSTATUS status = STATUS_SUCCESS;
  ULONG cbResult = 0;

  if (!BCRYPT_SUCCESS(status = BCryptEncrypt(ctx->hKeyECB, (PUCHAR) in,
                                             AES_BLOCK_SIZE, NULL, NULL, 0, out,
                                             AES_BLOCK_SIZE, &cbResult, 0))) {
    return -1;
  }

  if (cbResult != AES_BLOCK_SIZE) {
    return -2;
  }

  return 0;

#else

//  return aes_encrypt_ex(aes_ecb(ctx->key_len), in, out, AES_BLOCK_SIZE, NULL, ctx);

  cipher_key enc_key = NULL;
  cipher_rc drc = cipher_import_key(YKPIV_ALGO_AES128, ctx->key, AES_BLOCK_SIZE, &enc_key);
  if (drc != CIPHER_OK) {
    DBG("%s: cipher_import_key: %d", ykpiv_strerror(YKPIV_ALGORITHM_ERROR), drc);
    return drc;
  }

  drc = cipher_encrypt(enc_key, in, in_len, NULL, 0, out, (uint32_t *) out_len);
  if (drc != CIPHER_OK) {
    DBG("%s: cipher_encrypt: %d", ykpiv_strerror(YKPIV_KEY_ERROR), drc);
    return drc;
  }

  return 0;

#endif
}

static int aes_cmac_encrypt(aes_cmac_context_t *ctx, const uint8_t *message,
                     const uint16_t message_len, uint8_t *mac) {

  uint8_t M[AES_BLOCK_SIZE] = {0};
  const uint8_t *ptr = message;

  memcpy(mac, zero, AES_BLOCK_SIZE);

  uint8_t n_blocks;
  if (message_len == 0)
    n_blocks = 0;
  else
    n_blocks = (message_len + (AES_BLOCK_SIZE - 1)) / AES_BLOCK_SIZE - 1;

  for (uint8_t i = 0; i < n_blocks; i++) {
    uint16_t out_len = AES_BLOCK_SIZE;
    int rc = aes_cbc_encrypt(ptr, AES_BLOCK_SIZE, mac, &out_len, mac, ctx->aes_ctx);
    if (rc) {
      return rc;
    }
    ptr += AES_BLOCK_SIZE;
  }

  uint8_t remaining_bytes = (message_len % AES_BLOCK_SIZE);

  if (remaining_bytes == 0) {
    if (message != NULL && message_len != 0) {
      memcpy(M, ptr, AES_BLOCK_SIZE);
      do_xor(ctx->k1, M);
    } else {
      do_pad(M, 0);
      do_xor(ctx->k2, M);
    }
  } else {
    memcpy(M, ptr, remaining_bytes);
    do_pad(M, remaining_bytes);
    do_xor(ctx->k2, M);
  }

  uint16_t out_len = AES_BLOCK_SIZE;
  return aes_cbc_encrypt(M, AES_BLOCK_SIZE, mac, &out_len, mac, ctx->aes_ctx);
}

static int aes_cmac_init(cmac_context *cmac_ctx, aes_cmac_context_t *ctx) {

  uint8_t L[AES_BLOCK_SIZE] = {0};

  ctx->aes_ctx = cmac_ctx;

  uint16_t out_len = AES_BLOCK_SIZE;
  int rc = aes_encrypt(zero, AES_BLOCK_SIZE, L, &out_len, ctx->aes_ctx);
  if (rc) {
    return rc;
  }

  cmac_generate_subkey(L, ctx->k1);
  cmac_generate_subkey(ctx->k1, ctx->k2);

  return 0;
}

static int aes_set_key(const uint8_t *key, cmac_context *ctx) {
#ifdef _WIN32_BCRYPT
  NTSTATUS status = STATUS_SUCCESS;

  if (!BCRYPT_SUCCESS(status = init_ctx(ctx))) {
    return -1;
  }

  if (!BCRYPT_SUCCESS(status = import_key(ctx->hAlgCBC, &(ctx->hKeyCBC),
                                          &(ctx->pbKeyCBCObj), ctx->cbKeyObj,
                                          key, AES_BLOCK_SIZE))) {
    return -2;
  }

  if (!BCRYPT_SUCCESS(status = import_key(ctx->hAlgECB, &(ctx->hKeyECB),
                                          &(ctx->pbKeyECBObj), ctx->cbKeyObj,
                                          key, AES_BLOCK_SIZE))) {
    return -3;
  }

#else

  if (key == NULL) {
    return -1;
  }
  if (!ctx->ctx) {
    ctx->ctx = EVP_CIPHER_CTX_new();
    if (!ctx->ctx) {
      return -2;
    }
  }
  memcpy(ctx->key, key, AES_BLOCK_SIZE);

#endif

  return 0;
}

static void aes_cmac_destroy(aes_cmac_context_t *ctx) {
  if (ctx) {
    memset(ctx, 0, sizeof(aes_cmac_context_t));
  }
}

static void cmac_destroy(cmac_context *ctx) {
  if (ctx) {
    memset(ctx, 0, sizeof(cmac_context));
  }
}


static int compute_full_mac_ex(const uint8_t *data, uint16_t data_len,
                                 cmac_context *aes_ctx, uint8_t *mac) {

  aes_cmac_context_t ctx = {0};

  if (aes_cmac_init(aes_ctx, &ctx)) {
    DBG("aes_cmac_init failed");
    return CIPHER_GENERAL_ERROR;
  }

  if (aes_cmac_encrypt(&ctx, data, data_len, mac)) {
    DBG("aes_cmac_encrypt failed");
    aes_cmac_destroy(&ctx);
    return CIPHER_GENERAL_ERROR;
  }

  aes_cmac_destroy(&ctx);
  return 0;
}


int compute_full_mac(const uint8_t *data, uint16_t data_len,
                       const uint8_t *key, uint16_t key_len,
                       uint8_t *mac) {

  cmac_context aes_ctx = {0};

  if (aes_set_key(key, &aes_ctx)) {
    DBG("aes_set_key failed");
    return CIPHER_GENERAL_ERROR;
  }

  int yrc = compute_full_mac_ex(data, data_len, &aes_ctx, mac);
  cmac_destroy(&aes_ctx);
  return yrc;
}