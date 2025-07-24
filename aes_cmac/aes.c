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

#include "ykpiv.h"
#include "aes.h"
#include "insecure_memzero.h"

#include <string.h>
#include <assert.h>
#include <stdlib.h>

#ifdef _WIN32
#define STATUS_SUCCESS 0
#endif

#ifdef _WIN32
static LPCWSTR bcrypt_algo(unsigned char algo) {
  switch (algo) {
  case YKPIV_ALGO_3DES:
    return BCRYPT_3DES_ALGORITHM;
  case YKPIV_ALGO_AES128:
  case YKPIV_ALGO_AES192:
  case YKPIV_ALGO_AES256:
    return BCRYPT_AES_ALGORITHM;
  default:
    return NULL;
  }
}

static NTSTATUS init_ctx(aes_context *ctx, unsigned char key_algo) {
  NTSTATUS status = STATUS_SUCCESS;
  BCRYPT_ALG_HANDLE hAlgCBC = 0;
  BCRYPT_ALG_HANDLE hAlgECB = 0;
  DWORD cbKeyObj = 0;
  DWORD cbData = 0;

  if (!ctx) {
    return STATUS_INVALID_PARAMETER;
  }

  if (ctx->hAlgCBC) {
    return STATUS_SUCCESS;
  }

  /* clear the context, to "reset" */

  insecure_memzero(ctx, sizeof(aes_context));

  if (!BCRYPT_SUCCESS(status = BCryptOpenAlgorithmProvider(&hAlgCBC,
                                                           bcrypt_algo(key_algo),
                                                           NULL, 0))) {
    goto cleanup;
  }

  if (!BCRYPT_SUCCESS(status =
                        BCryptSetProperty(hAlgCBC, BCRYPT_CHAINING_MODE,
                                          (PBYTE) BCRYPT_CHAIN_MODE_CBC,
                                          sizeof(BCRYPT_CHAIN_MODE_CBC), 0))) {
    goto cleanup;
  }

  if (!BCRYPT_SUCCESS(status = BCryptOpenAlgorithmProvider(&hAlgECB,
                                                           bcrypt_algo(key_algo),
                                                           NULL, 0))) {
    goto cleanup;
  }

  if (!BCRYPT_SUCCESS(status =
                        BCryptSetProperty(hAlgECB, BCRYPT_CHAINING_MODE,
                                          (PBYTE) BCRYPT_CHAIN_MODE_ECB,
                                          sizeof(BCRYPT_CHAIN_MODE_ECB), 0))) {
    goto cleanup;
  }

  if (!BCRYPT_SUCCESS(status = BCryptGetProperty(hAlgCBC, BCRYPT_OBJECT_LENGTH,
                                                 (PBYTE) &cbKeyObj,
                                                 sizeof(DWORD), &cbData, 0))) {
    goto cleanup;
  }

  ctx->hAlgCBC = hAlgCBC;
  hAlgCBC = 0;
  ctx->hAlgECB = hAlgECB;
  hAlgECB = 0;
  ctx->cbKeyObj = cbKeyObj;

cleanup:

  if (hAlgCBC) {
    BCryptCloseAlgorithmProvider(hAlgCBC, 0);
  }
  if (hAlgECB) {
    BCryptCloseAlgorithmProvider(hAlgECB, 0);
  }

  return status;
}

static NTSTATUS import_key(BCRYPT_ALG_HANDLE hAlg, BCRYPT_KEY_HANDLE *phKey,
                           PBYTE *ppbKeyObj, DWORD cbKeyObj, const uint8_t *key,
                           size_t key_len) {
  NTSTATUS status = STATUS_SUCCESS;
  PBYTE pbKeyObj = NULL;
  BCRYPT_KEY_HANDLE hKey = 0;
  PBYTE pbKeyBlob = NULL;
  DWORD cbKeyBlob = 0;

  if (!phKey || !ppbKeyObj) {
    return STATUS_INVALID_PARAMETER;
  }

  /* close existing key first */
  if (*phKey) {
    BCryptDestroyKey(*phKey);
    *phKey = 0;
  }

  /* free existing key object */
  if (*ppbKeyObj) {
    free(*ppbKeyObj);
    *ppbKeyObj = NULL;
  }

  /* allocate new key object */
  if (!(pbKeyObj = (PBYTE) malloc(cbKeyObj))) {
    status = STATUS_NO_MEMORY;
    goto cleanup;
  }

  cbKeyBlob = (DWORD) (sizeof(BCRYPT_KEY_DATA_BLOB_HEADER) + key_len);

  if (!(pbKeyBlob = (PBYTE) malloc(cbKeyBlob))) {
    status = STATUS_NO_MEMORY;
    goto cleanup;
  }

  /* set up BCrypt Key Blob for import */
  ((BCRYPT_KEY_DATA_BLOB_HEADER *) pbKeyBlob)->dwMagic =
    BCRYPT_KEY_DATA_BLOB_MAGIC;
  ((BCRYPT_KEY_DATA_BLOB_HEADER *) pbKeyBlob)->dwVersion =
    BCRYPT_KEY_DATA_BLOB_VERSION1;
  ((BCRYPT_KEY_DATA_BLOB_HEADER *) pbKeyBlob)->cbKeyData = (DWORD) key_len;
  memcpy(pbKeyBlob + sizeof(BCRYPT_KEY_DATA_BLOB_HEADER), key, key_len);

  if (!BCRYPT_SUCCESS(status = BCryptImportKey(hAlg, NULL, BCRYPT_KEY_DATA_BLOB,
                                               &hKey, pbKeyObj, cbKeyObj,
                                               pbKeyBlob, cbKeyBlob, 0))) {
    goto cleanup;
  }

  /* set output params */
  *phKey = hKey;
  hKey = 0;
  *ppbKeyObj = pbKeyObj;
  pbKeyObj = 0;

cleanup:

  if (hKey) {
    BCryptDestroyKey(hKey);
  }
  if (pbKeyObj) {
    free(pbKeyObj);
  }
  if (pbKeyBlob) {
    free(pbKeyBlob);
  }

  return !BCRYPT_SUCCESS(status);
}

#else

static const EVP_CIPHER *aes_ecb(unsigned char algo) {
  switch (algo) {
    case YKPIV_ALGO_3DES:
      return EVP_des_ede3_ecb();
    case YKPIV_ALGO_AES128:
      return EVP_aes_128_ecb();
    case YKPIV_ALGO_AES192:
      return EVP_aes_192_ecb();
    case YKPIV_ALGO_AES256:
      return EVP_aes_256_ecb();
    default:
      return NULL;
  }
}

static const EVP_CIPHER *aes_cbc(unsigned char algo) {
  switch (algo) {
    case YKPIV_ALGO_3DES:
      return EVP_des_ede3_cbc();
    case YKPIV_ALGO_AES128:
      return EVP_aes_128_cbc();
    case YKPIV_ALGO_AES192:
      return EVP_aes_192_cbc();
    case YKPIV_ALGO_AES256:
      return EVP_aes_256_cbc();
    default:
      return NULL;
  }
}

static int aes_encrypt_ex(const EVP_CIPHER *cipher, const uint8_t *in, uint32_t in_len,
                          uint8_t *out, uint32_t *out_len, const uint8_t *iv,
                          aes_context *ctx, int enc) {
  if (EVP_CipherInit_ex(ctx->ctx, cipher, NULL, ctx->key, iv, enc) != 1) {
    return -1;
  }
  if (EVP_CIPHER_CTX_set_padding(ctx->ctx, 0) != 1) {
    return -2;
  }
  int update_len = in_len;
  if (EVP_CipherUpdate(ctx->ctx, out, &update_len, in, in_len) != 1) {
    return -3;
  }
  int final_len = in_len - update_len;
  if (EVP_CipherFinal_ex(ctx->ctx, out + update_len, &final_len) != 1) {
    return -4;
  }
  if (update_len + final_len != update_len) {
    return -5;
  }
  *out_len = update_len;
  return 0;
}

#endif

int aes_set_key(const uint8_t *key, uint32_t key_len, unsigned char key_algo, aes_context *ctx) {
#ifdef _WIN32
  NTSTATUS status = STATUS_SUCCESS;

  if (!BCRYPT_SUCCESS(status = init_ctx(ctx, key_algo))) {
    return -1;
  }

  if (!BCRYPT_SUCCESS(status = import_key(ctx->hAlgCBC, &(ctx->hKeyCBC),
                                          &(ctx->pbKeyCBCObj), (DWORD)ctx->cbKeyObj,
                                          key, key_len))) {
    return -2;
  }

  if (!BCRYPT_SUCCESS(status = import_key(ctx->hAlgECB, &(ctx->hKeyECB),
                                          &(ctx->pbKeyECBObj), (DWORD)ctx->cbKeyObj,
                                          key, key_len))) {
    return -3;
  }

#else

  if (key == NULL || aes_ecb(key_algo) == NULL) {
    return -1;
  }
  if (!ctx->ctx) {
    ctx->ctx = EVP_CIPHER_CTX_new();
    if (!ctx->ctx) {
      return -2;
    }
  }
  ctx->key_algo = key_algo;
  memcpy(ctx->key, key, key_len);

#endif

  return 0;
}

int aes_encrypt(const uint8_t *in, uint32_t in_len, uint8_t *out, uint32_t *out_len, aes_context *ctx) {
#ifdef _WIN32
  NTSTATUS status = STATUS_SUCCESS;
  ULONG cbResult = 0;

  if (!BCRYPT_SUCCESS(status = BCryptEncrypt(ctx->hKeyECB, (PUCHAR) in,
                                             in_len, NULL, NULL, 0, out,
                                             in_len, &cbResult, 0))) {
    return -1;
  }

  if (cbResult != aes_blocksize(ctx)) {
    return -2;
  }
  *out_len = in_len;

  return 0;

#else

  return aes_encrypt_ex(aes_ecb(ctx->key_algo), in, in_len, out, out_len, NULL, ctx, 1);

#endif
}

int aes_decrypt(const uint8_t *in, uint32_t in_len, uint8_t *out, uint32_t *out_len, aes_context *ctx) {
#ifdef _WIN32
  NTSTATUS status = STATUS_SUCCESS;
  ULONG cbResult = 0;

  if (!BCRYPT_SUCCESS(status = BCryptDecrypt(ctx->hKeyECB, (PUCHAR) in,
                                             in_len, NULL, NULL, 0, out,
                                             in_len, &cbResult, 0))) {
    return -1;
  }
  if (cbResult != aes_blocksize(ctx)) {
    return -2;
  }
  *out_len = in_len;
  return 0;

#else

  return aes_encrypt_ex(aes_ecb(ctx->key_algo), in, in_len, out, out_len, NULL, ctx, 0);

#endif
}

int aes_cbc_encrypt(const uint8_t *in, uint32_t in_len, uint8_t *out, uint32_t *out_len,
                    const uint8_t *iv, uint32_t iv_len, aes_context *ctx) {
#ifdef _WIN32
  NTSTATUS status = STATUS_SUCCESS;
  ULONG cbResult = 0;

  if (!BCRYPT_SUCCESS(status = BCryptEncrypt(ctx->hKeyCBC, (PUCHAR)in, in_len,
                                             NULL, (PUCHAR)iv, iv_len, out,
                                             in_len, &cbResult, 0))) {
    return -1;
  }

  if (cbResult != in_len) {
    return -2;
  }
  *out_len = in_len;

  return 0;

#else

  return aes_encrypt_ex(aes_cbc(ctx->key_algo), in, in_len, out, out_len, iv, ctx, 1);

#endif
}

int aes_cbc_decrypt(const uint8_t *in, uint32_t in_len, uint8_t *out, uint32_t *out_len,
                    const uint8_t *iv, uint32_t iv_len, aes_context *ctx) {
#ifdef _WIN32
  NTSTATUS status = STATUS_SUCCESS;
  ULONG cbResult = 0;

  if (!BCRYPT_SUCCESS(status = BCryptDecrypt(ctx->hKeyCBC, (PUCHAR)in, in_len,
                                             NULL, (PUCHAR)iv, iv_len, out,
                                             in_len, &cbResult, 0))) {
    return -1;
  }

  if (cbResult != in_len) {
    return -2;
  }
  *out_len = in_len;

  return 0;

#else

  return aes_encrypt_ex(aes_cbc(ctx->key_algo), in, in_len, out, out_len, iv, ctx, 0);

#endif
}

uint32_t aes_blocksize(aes_context *key) {
  if (!key) {
    return 0;
  }
#ifdef _WIN32
  DWORD size = 0;
  ULONG len = 0;
	if(!BCRYPT_SUCCESS(BCryptGetProperty(key->hKeyECB, BCRYPT_BLOCK_LENGTH, (PUCHAR)&size, sizeof(size), &len, 0))) {
    return 0;
  }

  return size;
#else
  return EVP_CIPHER_block_size(aes_ecb(key->key_algo));
#endif
}

int aes_add_padding(uint8_t *in, uint32_t max_len, uint32_t *len) {
  uint32_t new_len = *len;

  if (in) {
    if (new_len >= max_len) {
      return -1;
    }
    in[new_len] = 0x80;
  }
  new_len++;

  while (new_len % AES_BLOCK_SIZE != 0) {
    if (in) {
      if (new_len >= max_len) {
        return -2;
      }
      in[new_len] = 0x00;
    }
    new_len++;
  }

  *len = new_len;
  return 0;
}

void aes_remove_padding(uint8_t *in, uint32_t *len) {

  while ((*len) > 1 && in[(*len) - 1] == 0) {
    (*len)--;
  }

  if (*len > 0)
    (*len)--;
}

int aes_destroy(aes_context *ctx) {
  if (!ctx) {
    return 0;
  }

#ifdef _WIN32

  if (ctx->hKeyCBC) {
    BCryptDestroyKey(ctx->hKeyCBC);
  }
  if (ctx->pbKeyCBCObj) {
    free(ctx->pbKeyCBCObj);
  }
  if (ctx->hKeyECB) {
    BCryptDestroyKey(ctx->hKeyECB);
  }
  if (ctx->pbKeyECBObj) {
    free(ctx->pbKeyECBObj);
  }
  if (ctx->hAlgCBC) {
    BCryptCloseAlgorithmProvider(ctx->hAlgCBC, 0);
  }
  if (ctx->hAlgECB) {
    BCryptCloseAlgorithmProvider(ctx->hAlgECB, 0);
  }
#else

  EVP_CIPHER_CTX_free(ctx->ctx);

#endif

  insecure_memzero(ctx, sizeof(aes_context));
  return 0;
}
