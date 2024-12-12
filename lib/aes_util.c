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
#include "aes_util.h"
#include "cmac_util.h"

#ifdef _WIN32
#include <winsock.h>
#else
#include <arpa/inet.h>
#endif

//static void dump_byte_array(uint8_t *a, size_t len, const char* label) {
//    fprintf(stderr, "---------------- %s - %ld : ", label, len);
//    for(int i=0; i<len; i++) {
//        fprintf(stderr, "%02x ", a[i]);
//    }
//    fprintf(stderr, "\n");
//}


ykpiv_rc calculate_cmac(uint8_t *key, uint8_t *mac_chain, uint8_t *data, size_t data_len, uint8_t *mac_out) {

  int res;
  if(mac_chain) {
    uint8_t buf[YKPIV_OBJ_MAX_SIZE] = {0};
    memcpy(buf, mac_chain, SCP11_MAC_LEN);
    memcpy(buf + SCP11_MAC_LEN, data, data_len);
    size_t buf_len = SCP11_MAC_LEN + data_len;
    res = compute_full_mac(buf, buf_len, key, AES_BLOCK_SIZE, mac_out);
  } else {
    res = compute_full_mac(data, data_len, key, AES_BLOCK_SIZE, mac_out);
  }
  if(res != 0) {
    return YKPIV_KEY_ERROR;
  }
  return YKPIV_OK;
}

ykpiv_rc unmac_data(uint8_t *key, uint8_t *mac_chain, uint8_t *data, size_t data_len, uint16_t sw) {
  ykpiv_rc rc;
  uint8_t resp[YKPIV_OBJ_MAX_SIZE] = {0};
  memcpy(resp, data, (data_len - SCP11_HALF_MAC_LEN));
  resp[data_len - SCP11_HALF_MAC_LEN] = sw >> 8;
  resp[data_len - SCP11_HALF_MAC_LEN + 1] = sw & 0xff;

  uint8_t rmac[SCP11_MAC_LEN] = {0};
  if ((rc = calculate_cmac(key, mac_chain, resp, data_len - SCP11_HALF_MAC_LEN + 2, rmac)) != YKPIV_OK) {
    DBG("Failed to calculate rmac");
    return rc;
  }

  if (memcmp(rmac, data + data_len - SCP11_HALF_MAC_LEN, SCP11_HALF_MAC_LEN) != 0) {
    DBG("Response MAC and message MAC mismatch");
    rc = YKPIV_AUTHENTICATION_ERROR;
    return rc;
  }

  return YKPIV_OK;
}

static ykpiv_rc scp11_get_iv(uint8_t *key, uint32_t counter, uint8_t *iv, bool decrypt) {
  ykpiv_rc res = YKPIV_OK;
  uint8_t iv_data[SCP11_AES_BLOCK_SIZE] = {0};
  if (decrypt) {
    iv_data[0] = 0x80;
  }
  uint32_t c = htonl(counter);
  memcpy(iv_data + SCP11_AES_BLOCK_SIZE - sizeof(int), &c, sizeof(int));

  cipher_key enc_key = NULL;
  cipher_rc drc = cipher_import_key(YKPIV_ALGO_AES128, key, SCP11_SESSION_KEY_LEN, &enc_key);
  if (drc != CIPHER_OK) {
    DBG("%s: cipher_import_key: %d", ykpiv_strerror(YKPIV_ALGORITHM_ERROR), drc);
    res = YKPIV_ALGORITHM_ERROR;
    goto enc_clean;
  }

  int len = SCP11_AES_BLOCK_SIZE;
  drc = cipher_encrypt(enc_key, iv_data, sizeof(iv_data), NULL, 0, iv, &len);
  if (drc != CIPHER_OK) {
    DBG("%s: cipher_encrypt: %d", ykpiv_strerror(YKPIV_KEY_ERROR), drc);
    res = YKPIV_KEY_ERROR;
    goto enc_clean;
  }

enc_clean:
  cipher_destroy_key(enc_key);
  return res;
}

ykpiv_rc
aescbc_encrypt_data(uint8_t *key, uint32_t counter, const uint8_t *data, size_t data_len, uint8_t *enc, size_t *enc_len) {
  ykpiv_rc rc;
  uint8_t iv[SCP11_AES_BLOCK_SIZE] = {0};
  if ((rc = scp11_get_iv(key, counter, iv, false)) != YKPIV_OK) {
    DBG("Failed to calculate encryption IV");
    return rc;
  }

  size_t pad_len = SCP11_AES_BLOCK_SIZE - (data_len % SCP11_AES_BLOCK_SIZE);
  uint8_t padded[YKPIV_OBJ_MAX_SIZE] = {0};
  memcpy(padded, data, data_len);
  padded[data_len] = 0x80;

  cipher_key enc_key = NULL;
  cipher_rc drc = cipher_import_key_cbc(YKPIV_ALGO_AES128, key, SCP11_SESSION_KEY_LEN, &enc_key);
  if (drc != CIPHER_OK) {
    DBG("%s: cipher_import_key: %d", ykpiv_strerror(YKPIV_ALGORITHM_ERROR), drc);
    rc = YKPIV_ALGORITHM_ERROR;
    goto enc_clean;
  }

  drc = cipher_encrypt(enc_key, padded, data_len + pad_len, iv, SCP11_AES_BLOCK_SIZE, enc, (uint32_t *) enc_len);
  if (drc != CIPHER_OK) {
    DBG("%s: cipher_encrypt: %d", ykpiv_strerror(YKPIV_KEY_ERROR), drc);
    rc = YKPIV_KEY_ERROR;
    goto enc_clean;
  }

enc_clean:
  cipher_destroy_key(enc_key);
  return rc;
}

ykpiv_rc
aescbc_decrypt_data(uint8_t *key, uint32_t counter, uint8_t *enc, size_t enc_len, uint8_t *data, size_t *data_len) {
  ykpiv_rc rc;
  if(enc_len <= 0) {
    DBG("No data to decrypt");
    *data_len = 0;
    return YKPIV_OK;
  }

  uint8_t iv[SCP11_AES_BLOCK_SIZE] = {0};
  if ((rc = scp11_get_iv(key, counter, iv, true)) != YKPIV_OK) {
    DBG("Failed to calculate decryption IV");
    return rc;
  }

  cipher_key dec_key = NULL;
  cipher_rc drc = cipher_import_key_cbc(YKPIV_ALGO_AES128, key, SCP11_SESSION_KEY_LEN, &dec_key);
  if (drc != CIPHER_OK) {
    DBG("%s: cipher_import_key: %d", ykpiv_strerror(YKPIV_ALGORITHM_ERROR), drc);
    rc = YKPIV_ALGORITHM_ERROR;
    goto aes_dec_clean;
  }

  drc = cipher_decrypt(dec_key, enc, enc_len, iv, SCP11_AES_BLOCK_SIZE, data, (uint32_t *) data_len);
  if (drc != CIPHER_OK) {
    DBG("%s: cipher_decrypt: %d", ykpiv_strerror(YKPIV_KEY_ERROR), drc);
    rc = YKPIV_KEY_ERROR;
    goto aes_dec_clean;
  }

  // Remove padding
  while (data[(*data_len) - 1] == 0x00) {
    (*data_len)--;
  }
  if (data[(*data_len) - 1] == 0x80) {
    (*data_len)--;
  }

aes_dec_clean:
  cipher_destroy_key(dec_key);
  return rc;
}