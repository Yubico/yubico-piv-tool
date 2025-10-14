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

#include <string.h>

#include "internal.h"
#include "ykpiv.h"
#include "scp11_util.h"
#include "../aes_cmac/aes_cmac.h"

#ifdef _WIN32
#include <winsock.h>
#else
#include <arpa/inet.h>
#endif

#ifndef AES_BLOCK_SIZE // Defined in openssl/aes.h
#define AES_BLOCK_SIZE 16
#endif


static ykpiv_rc compute_full_mac_ex(const uint8_t *data, uint32_t data_len,
                                 aes_context *aes_ctx, uint8_t *mac) {

  aes_cmac_context_t ctx = {0};

  if (aes_cmac_init(aes_ctx, &ctx)) {
    DBG("aes_cmac_init failed");
    return YKPIV_AUTHENTICATION_ERROR;
  }

  int drc = aes_cmac_encrypt(&ctx, data, data_len, mac);
  if (drc) {
    DBG("%s: aes_cmac_encrypt: %d", ykpiv_strerror(YKPIV_AUTHENTICATION_ERROR), drc);
    aes_cmac_destroy(&ctx);
    return YKPIV_AUTHENTICATION_ERROR;
  }

  aes_cmac_destroy(&ctx);
  return YKPIV_OK;
}

static ykpiv_rc compute_full_mac(const uint8_t *data, uint32_t data_len,
                              const uint8_t *key, uint32_t key_len,
                              uint8_t *mac) {

  aes_context aes_ctx = { 0 };
  int drc = aes_set_key(key, key_len, YKPIV_ALGO_AES128, &aes_ctx);
  if (drc) {
    DBG("%s: aes_set_key: %d", ykpiv_strerror(YKPIV_KEY_ERROR), drc);
    return YKPIV_KEY_ERROR;
  }

  ykpiv_rc rc = compute_full_mac_ex(data, data_len, &aes_ctx, mac);
  aes_destroy(&aes_ctx);
  return rc;
}

ykpiv_rc scp11_mac_data(uint8_t *key, uint8_t *mac_chain, uint8_t *data, uint32_t data_len, uint8_t *mac_out) {
  int res;
  if(mac_chain) {
    uint8_t buf[YKPIV_OBJ_MAX_SIZE] = {0};
    memcpy(buf, mac_chain, SCP11_MAC_LEN);
    memcpy(buf + SCP11_MAC_LEN, data, data_len);
    size_t buf_len = SCP11_MAC_LEN + data_len;
    res = compute_full_mac(buf, (uint32_t)buf_len, key, AES_BLOCK_SIZE, mac_out);
  } else {
    res = compute_full_mac(data, data_len, key, AES_BLOCK_SIZE, mac_out);
  }
  return res;
}

ykpiv_rc scp11_unmac_data(uint8_t *key, uint8_t *mac_chain, uint8_t *data, uint32_t data_len, uint16_t sw) {

  uint8_t resp[YKPIV_OBJ_MAX_SIZE] = {0};
  memcpy(resp, data, (data_len - SCP11_HALF_MAC_LEN));
  resp[data_len - SCP11_HALF_MAC_LEN] = sw >> 8;
  resp[data_len - SCP11_HALF_MAC_LEN + 1] = sw & 0xff;

  uint8_t rmac[SCP11_MAC_LEN] = {0};
  ykpiv_rc rc = scp11_mac_data(key, mac_chain, resp, data_len - SCP11_HALF_MAC_LEN + 2, rmac);
  if (rc != YKPIV_OK) {
    DBG("Failed to calculate rmac");
    return rc;
  }

  if (memcmp(rmac, data + data_len - SCP11_HALF_MAC_LEN, SCP11_HALF_MAC_LEN) != 0) {
    DBG("Response MAC and message MAC mismatch");
    return YKPIV_AUTHENTICATION_ERROR;
  }
  return YKPIV_OK;
}

static ykpiv_rc get_iv(aes_context *key, uint32_t counter, uint8_t *iv, bool decrypt) {
  uint8_t iv_data[AES_BLOCK_SIZE] = {0};
  if (decrypt) {
    iv_data[0] = 0x80;
  }
  uint32_t c = htonl(counter);
  memcpy(iv_data + AES_BLOCK_SIZE - sizeof(int), &c, sizeof(int));

  uint32_t len = AES_BLOCK_SIZE;
  int drc = aes_encrypt(iv_data, sizeof(iv_data), iv, &len, key);
  if (drc) {
    DBG("%s: cipher_encrypt: %d", ykpiv_strerror(YKPIV_KEY_ERROR), drc);
    return YKPIV_KEY_ERROR;
  }
  return YKPIV_OK;
}

ykpiv_rc
scp11_encrypt_data(uint8_t *key, uint32_t counter, const uint8_t *data, uint32_t data_len, uint8_t *enc, uint32_t *enc_len) {
  ykpiv_rc rc;
  aes_context enc_key = {0};
  int drc = aes_set_key(key, SCP11_SESSION_KEY_LEN, YKPIV_ALGO_AES128, &enc_key);
  if (drc) {
    DBG("%s: cipher_import_key: %d", ykpiv_strerror(YKPIV_KEY_ERROR), drc);
    rc = YKPIV_KEY_ERROR;
    goto enc_clean;
  }

  uint8_t iv[AES_BLOCK_SIZE] = {0};
  if ((rc = get_iv(&enc_key, counter, iv, false)) != YKPIV_OK) {
    DBG("Failed to calculate encryption IV");
    goto enc_clean;
  }

  size_t pad_len = AES_BLOCK_SIZE - (data_len % AES_BLOCK_SIZE);
  uint8_t padded[YKPIV_OBJ_MAX_SIZE] = {0};
  memcpy(padded, data, data_len);
  if((drc = aes_add_padding(padded, data_len + (uint32_t)pad_len, &data_len)) != 0) {
    DBG("%s: aes_add_padding: %d", ykpiv_strerror(YKPIV_MEMORY_ERROR), drc);
    rc = YKPIV_MEMORY_ERROR;
    goto enc_clean;
  }

  if ((drc = aes_cbc_encrypt(padded, data_len, enc, enc_len, iv, AES_BLOCK_SIZE, &enc_key)) != 0) {
    DBG("%s: cipher_encrypt: %d", ykpiv_strerror(YKPIV_KEY_ERROR), drc);
    rc = YKPIV_KEY_ERROR;
    goto enc_clean;
  }

enc_clean:
  aes_destroy(&enc_key);
  return rc;
}

ykpiv_rc
scp11_decrypt_data(uint8_t *key, uint32_t counter, uint8_t *enc, uint32_t enc_len, uint8_t *data, uint32_t *data_len) {
  if(enc_len <= 0) {
    DBG("No data to decrypt");
    *data_len = 0;
    return YKPIV_OK;
  }

  ykpiv_rc rc;
  aes_context dec_key = {0};
  int drc = aes_set_key(key, SCP11_SESSION_KEY_LEN, YKPIV_ALGO_AES128, &dec_key);
  if (drc) {
    DBG("%s: cipher_import_key: %d", ykpiv_strerror(YKPIV_KEY_ERROR), drc);
    rc = YKPIV_KEY_ERROR;
    goto aes_dec_clean;
  }

  uint8_t iv[AES_BLOCK_SIZE] = {0};
  if ((rc = get_iv(&dec_key, counter, iv, true)) != YKPIV_OK) {
    DBG("Failed to calculate decryption IV");
    goto aes_dec_clean;
  }

  drc = aes_cbc_decrypt(enc, enc_len, data, data_len, iv, AES_BLOCK_SIZE, &dec_key);
  if (drc) {
    DBG("%s: cipher_decrypt: %d", ykpiv_strerror(YKPIV_KEY_ERROR), drc);
    rc = YKPIV_KEY_ERROR;
    goto aes_dec_clean;
  }

  aes_remove_padding(data, data_len);

aes_dec_clean:
  aes_destroy(&dec_key);

  return rc;
}