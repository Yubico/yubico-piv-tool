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


#include "internal.h"
#include "ykpiv.h"
#include "aes_util.h"

#ifdef _WIN32
#include <winsock.h>
#else
#include <arpa/inet.h>
#endif

#include <openssl/x509.h>
#include <openssl/core_names.h>

//static void dump_byte_array(uint8_t *a, size_t len, const char* label) {
//    fprintf(stderr, "---------------- %s - %ld : ", label, len);
//    for(int i=0; i<len; i++) {
//        fprintf(stderr, "%02x ", a[i]);
//    }
//    fprintf(stderr, "\n");
//}


ykpiv_rc calculate_cmac(uint8_t *key, uint8_t *mac_chain, uint8_t *data, size_t data_len, uint8_t *mac_out) {
  ykpiv_rc res = YKPIV_OK;
  /* Fetch the CMAC implementation */
  EVP_MAC *mac = EVP_MAC_fetch(NULL, "CMAC", NULL);
  if (mac == NULL) {
    DBG("Failed to fetch CMAC implementation");
    return YKPIV_AUTHENTICATION_ERROR;
  }

  /* Create a context for the CMAC operation */
  EVP_MAC_CTX *mctx = EVP_MAC_CTX_new(mac);
  if (mctx == NULL) {
    DBG("Failed to create CMAC context");
    return YKPIV_AUTHENTICATION_ERROR;
  }

  OSSL_PARAM params[3];
  size_t params_n = 0;

  char cipher_name[] = "AES-128-CBC";
  params[params_n++] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_CIPHER, (char *) cipher_name, 0);
  params[params_n] = OSSL_PARAM_construct_end();

  /* Initialise the CMAC operation */
  if (!EVP_MAC_init(mctx, key, SCP11_SESSION_KEY_LEN, params)) {
    DBG("Failed to initiate CMAC function");
    res = YKPIV_KEY_ERROR;
    goto cmac_free;
  }

  /* Make one or more calls to process the data to be authenticated */
  if (mac_chain) {
    if (!EVP_MAC_update(mctx, mac_chain, SCP11_MAC_LEN)) {
      DBG("Failed to set mac chain data");
      res = YKPIV_AUTHENTICATION_ERROR;
      goto cmac_free;
    }
  }

  if (!EVP_MAC_update(mctx, data, data_len)) {
    DBG("Failed to set CMAC input data");
    res = YKPIV_AUTHENTICATION_ERROR;
    goto cmac_free;
  }


  /* Make a call to the final with a NULL buffer to get the length of the MAC */
  size_t out_len = 0;
  if (!EVP_MAC_final(mctx, NULL, &out_len, 0)) {
    DBG("Failed to retrieve CMAC length");
    res = YKPIV_AUTHENTICATION_ERROR;
    goto cmac_free;
  }

  if (out_len != SCP11_MAC_LEN) {
    DBG("Unexpected MAC length. Expected %d. Found %ld\n", SCP11_MAC_LEN, out_len);
    res = YKPIV_AUTHENTICATION_ERROR;
    goto cmac_free;
  }

  /* Make one call to the final to get the MAC */
  if (!EVP_MAC_final(mctx, mac_out, &out_len, out_len)) {
    DBG("Failed to calculate CMAC value");
    res = YKPIV_KEY_ERROR;
    goto cmac_free;
  }

cmac_free:
  EVP_MAC_CTX_free(mctx);
  return res;
}

ykpiv_rc unmac_data(uint8_t *key, uint8_t *mac_chain, uint8_t *data, size_t data_len, uint16_t sw) {
  ykpiv_rc rc;
  uint8_t *resp = malloc(data_len - SCP11_HALF_MAC_LEN + 2);
  memcpy(resp, data, (data_len - SCP11_HALF_MAC_LEN));
  resp[data_len - SCP11_HALF_MAC_LEN] = sw >> 8;
  resp[data_len - SCP11_HALF_MAC_LEN + 1] = sw & 0xff;

  uint8_t rmac[SCP11_MAC_LEN] = {0};
  if ((rc = calculate_cmac(key, mac_chain, resp, data_len - SCP11_HALF_MAC_LEN + 2, rmac)) != YKPIV_OK) {
    DBG("Failed to calculate rmac");
    goto unmac_clean;
  }

  if (memcmp(rmac, data + data_len - SCP11_HALF_MAC_LEN, SCP11_HALF_MAC_LEN) != 0) {
    DBG("Response MAC and message MAC mismatch");
    rc = YKPIV_AUTHENTICATION_ERROR;
    goto unmac_clean;
  }

unmac_clean:
  free(resp);
  return rc;
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
  if(enc_key) {
    cipher_destroy_key(enc_key);
  }
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
  uint8_t *padded = malloc(data_len + pad_len);
  memcpy(padded, data, data_len);
  padded[data_len] = 0x80;
  memset(padded + data_len + 1, 0, pad_len - 1);

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
  free(padded);
  if(enc_key) {
    cipher_destroy_key(enc_key);
  }
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
  if(dec_key) {
    cipher_destroy_key(dec_key);
  }
  return rc;
}