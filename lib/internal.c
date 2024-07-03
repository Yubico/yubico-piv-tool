/*
 * Copyright (c) 2014-2020 Yubico AB
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
#ifdef _WIN32
#include <windows.h>
#include <bcrypt.h>
#include <strsafe.h>
#else
#include <ctype.h>
#include <syslog.h>
#include <openssl/des.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#endif

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
** Definitions
*/

/* crypt defines */

#ifdef _WIN32

#define strcasecmp _stricmp

struct _cipher_key {
    BCRYPT_KEY_HANDLE hKey;
};

#else

struct _cipher_key {
  const EVP_CIPHER *cipher;
  EVP_CIPHER_CTX *ctx;
  unsigned char key[EVP_MAX_KEY_LENGTH];
};

#endif

/* config defines */

#ifdef _WIN32
#define _CONFIG_REGKEY "Software\\Yubico\\yubikeypiv"
#else
#define _CONFIG_FILE   "/etc/yubico/yubikeypiv.conf"
#endif

#define _ENV_PREFIX    "YUBIKEY_PIV_"

char *_strip_ws(char *sz);
setting_bool_t _get_bool_config(const char *sz_setting);
setting_bool_t _get_bool_env(const char *sz_setting);

/*
** Methods
*/

#ifdef _WIN32

static BCRYPT_ALG_HANDLE bcrypt_algo(unsigned char algo) {
	switch (algo) {
	case YKPIV_ALGO_3DES:
    return BCRYPT_3DES_ECB_ALG_HANDLE;
	case YKPIV_ALGO_AES128:
  case YKPIV_ALGO_AES192:
  case YKPIV_ALGO_AES256:
    return BCRYPT_AES_ECB_ALG_HANDLE;
  default:
    return NULL;
	}
}

cipher_rc cipher_import_key(unsigned char algo, const unsigned char *keyraw, uint32_t keyrawlen, cipher_key *key) {
  *key = calloc(1, sizeof(**key));
	if (!*key) {
    return CIPHER_MEMORY_ERROR;
  }
	if(!BCRYPT_SUCCESS(BCryptGenerateSymmetricKey(bcrypt_algo(algo), &(*key)->hKey, NULL, 0, (PUCHAR)keyraw, keyrawlen, 0))) {
		return CIPHER_INVALID_PARAMETER;
	}
	return 0;
}

cipher_rc cipher_destroy_key(cipher_key key) {
	if (key == NULL) {
    return CIPHER_MEMORY_ERROR;
  }
	if(!BCRYPT_SUCCESS(BCryptDestroyKey(key->hKey))) {
    return CIPHER_INVALID_PARAMETER;
  }
	free(key);
	return CIPHER_OK;
}

cipher_rc cipher_encrypt(cipher_key key, const unsigned char* in, uint32_t inlen, unsigned char* out, uint32_t* outlen) {
	if (key == NULL) {
    return CIPHER_MEMORY_ERROR;
  }
	if(!BCRYPT_SUCCESS(BCryptEncrypt(key->hKey, (PUCHAR)in, inlen, NULL, NULL, 0, out, *outlen, (PULONG)outlen, 0))) {
    return CIPHER_INVALID_PARAMETER;
  }
  return CIPHER_OK;
}

cipher_rc cipher_decrypt(cipher_key key, const unsigned char* in, uint32_t inlen, unsigned char* out, uint32_t* outlen) {
	if (key == NULL) {
    return CIPHER_MEMORY_ERROR;
  }
	if(!BCRYPT_SUCCESS(BCryptDecrypt(key->hKey, (PUCHAR)in, inlen, NULL, NULL, 0, out, *outlen, (PULONG)outlen, 0))) {
    return CIPHER_INVALID_PARAMETER;
  }
  return CIPHER_OK;
}

uint32_t cipher_blocksize(cipher_key key) {
	if (key == NULL) {
    return 0;
  }
  DWORD size = 0;
  ULONG len = 0;
	if(!BCRYPT_SUCCESS(BCryptGetProperty(key->hKey, BCRYPT_BLOCK_LENGTH, (PUCHAR)&size, sizeof(size), &len, 0))) {
    return 0;
  }
  return size;
}

#else

static int encrypt_ex(const uint8_t *in, uint8_t *out, int len,
                      const uint8_t *iv, int enc, cipher_key ctx) {
  if (EVP_CipherInit_ex(ctx->ctx, ctx->cipher, NULL, ctx->key, iv, enc) != 1) {
    return -1;
  }
  if (EVP_CIPHER_CTX_set_padding(ctx->ctx, 0) != 1) {
    return -2;
  }
  int update_len = len;
  if (EVP_CipherUpdate(ctx->ctx, out, &update_len, in, len) != 1) {
    return -3;
  }
  int final_len = len - update_len;
  if (EVP_CipherFinal_ex(ctx->ctx, out + update_len, &final_len) != 1) {
    return -4;
  }
  if (update_len + final_len != len) {
    return -5;
  }
  return 0;
}

cipher_rc cipher_import_key(unsigned char algo, const unsigned char* keyraw, uint32_t keyrawlen, cipher_key* key) {
  cipher_rc rc = CIPHER_OK;

  *key = calloc(1, sizeof(**key));
  (*key)->ctx = EVP_CIPHER_CTX_new();

  switch (algo) {
  case YKPIV_ALGO_3DES:
    (*key)->cipher = EVP_des_ede3_ecb();
    break;
  case YKPIV_ALGO_AES128:
    (*key)->cipher = EVP_aes_128_ecb();
    break;
  case YKPIV_ALGO_AES192:
    (*key)->cipher = EVP_aes_192_ecb();
    break;
  case YKPIV_ALGO_AES256:
    (*key)->cipher = EVP_aes_256_ecb();
    break;
  default:
    rc = CIPHER_INVALID_PARAMETER;
    goto ERROR_EXIT;
  }

  if((*key)->cipher == NULL || EVP_CIPHER_key_length((*key)->cipher) != keyrawlen) {
    rc = CIPHER_INVALID_PARAMETER;
    goto ERROR_EXIT;
  }

  memcpy((*key)->key, keyraw, keyrawlen);

EXIT:
  return rc;

ERROR_EXIT:
  if (key) {
    cipher_destroy_key(*key);
    *key = NULL;
  }
  goto EXIT;
}

cipher_rc cipher_destroy_key(cipher_key key) {
  if (key) {
    EVP_CIPHER_CTX_free(key->ctx);
    memset(key, 0, sizeof(*key));
    free(key);
  }
  return CIPHER_OK;
}

cipher_rc cipher_encrypt(cipher_key key, const unsigned char* in, uint32_t inlen, unsigned char* out, uint32_t* outlen) {
  cipher_rc rc = CIPHER_OK;

  if (!key || !outlen || (*outlen < inlen) || !in || !out) { rc = CIPHER_INVALID_PARAMETER; goto EXIT; }

  rc = encrypt_ex(in, out, inlen, NULL, 1, key);

EXIT:
  return rc;
}

cipher_rc cipher_decrypt(cipher_key key, const unsigned char* in, uint32_t inlen, unsigned char* out, uint32_t* outlen) {
  cipher_rc rc = CIPHER_OK;

  if (!key || !outlen || (*outlen < inlen) || !in || !out) { rc = CIPHER_INVALID_PARAMETER; goto EXIT; }

  rc = encrypt_ex(in, out, inlen, NULL, 0, key);

EXIT:
  return rc;
}

uint32_t cipher_blocksize(cipher_key key) {
  if(key) {
    return EVP_CIPHER_block_size(key->cipher);
  }
  return 0;
}

#endif

bool yk_des_is_weak_key(const unsigned char *key, const size_t cb_key) {
#ifdef _WIN32
  bool rv = false;
  /* defined weak keys, borrowed from openssl to be consistent across platforms */
  static const unsigned char weak_keys[][DES_LEN_DES] = {
    /* weak keys */
    {0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01},
    {0xFE,0xFE,0xFE,0xFE,0xFE,0xFE,0xFE,0xFE},
    {0x1F,0x1F,0x1F,0x1F,0x0E,0x0E,0x0E,0x0E},
    {0xE0,0xE0,0xE0,0xE0,0xF1,0xF1,0xF1,0xF1},
    /* semi-weak keys */
    {0x01,0xFE,0x01,0xFE,0x01,0xFE,0x01,0xFE},
    {0xFE,0x01,0xFE,0x01,0xFE,0x01,0xFE,0x01},
    {0x1F,0xE0,0x1F,0xE0,0x0E,0xF1,0x0E,0xF1},
    {0xE0,0x1F,0xE0,0x1F,0xF1,0x0E,0xF1,0x0E},
    {0x01,0xE0,0x01,0xE0,0x01,0xF1,0x01,0xF1},
    {0xE0,0x01,0xE0,0x01,0xF1,0x01,0xF1,0x01},
    {0x1F,0xFE,0x1F,0xFE,0x0E,0xFE,0x0E,0xFE},
    {0xFE,0x1F,0xFE,0x1F,0xFE,0x0E,0xFE,0x0E},
    {0x01,0x1F,0x01,0x1F,0x01,0x0E,0x01,0x0E},
    {0x1F,0x01,0x1F,0x01,0x0E,0x01,0x0E,0x01},
    {0xE0,0xFE,0xE0,0xFE,0xF1,0xFE,0xF1,0xFE},
    {0xFE,0xE0,0xFE,0xE0,0xFE,0xF1,0xFE,0xF1} };

  unsigned char tmp[DES_LEN_3DES] = { 0 };
  int i = 0;
  unsigned char c = 0x00;

  if (sizeof(tmp) != cb_key) return true;

  /* set odd parity of key */

  for (i = 0; i < sizeof(tmp); i++) {
    /* count number of set bits in byte, excluding the low-order bit - SWAR method */
    c = key[i] & 0xFE;

    c = (c & 0x55) + ((c >> 1) & 0x55);
    c = (c & 0x33) + ((c >> 2) & 0x33);
    c = (c & 0x0F) + ((c >> 4) & 0x0F);

    /* if count is even, set low key bit to 1, otherwise 0 */
    tmp[i] = (key[i] & 0xFE) | ((c & 0x01) ? 0x00 : 0x01);
  }

  /* check odd parity key against table by DES key block*/

  for (i = 0; i < sizeof(weak_keys) / sizeof(weak_keys[0]); i++) {
    if ((0 == memcmp(weak_keys[i], tmp, DES_LEN_DES)) ||
        (0 == memcmp(weak_keys[i], tmp + DES_LEN_DES, DES_LEN_DES)) ||
        (0 == memcmp(weak_keys[i], tmp + 2*DES_LEN_DES, DES_LEN_DES))) {
      rv = true;
      break;
    }
  }

  yc_memzero(tmp, DES_LEN_3DES);
  return rv;
#else
  (void)cb_key; /* unused */

  return DES_is_weak_key((const_DES_cblock *)key);
#endif
}

prng_rc _ykpiv_prng_generate(unsigned char *buffer, const size_t cb_req) {
  prng_rc rc = PRNG_OK;

#ifdef _WIN32
  if (!BCRYPT_SUCCESS(BCryptGenRandom(BCRYPT_RNG_ALG_HANDLE, buffer, (ULONG)cb_req, 0))) {
    rc = PRNG_GENERAL_ERROR;
  }
#else
  if (RAND_bytes(buffer, cb_req) <= 0) {
    rc = PRNG_GENERAL_ERROR;
  }
#endif

  return rc;
}

pkcs5_rc pkcs5_pbkdf2_sha1(const uint8_t* password, const size_t cb_password, const uint8_t* salt, const size_t cb_salt, uint64_t iterations, const uint8_t* key, const size_t cb_key) {
  pkcs5_rc rc = PKCS5_OK;

#ifdef _WIN32
  /* mingw64 defines the BCryptDeriveKeyPBKDF2 function, but its dll link library doesn't include the export.
  **
  ** In case this is needed, we'll need to dynamically load the function:
  **
  ** typedef NTSTATUS WINAPI (*PFN_BCryptDeriveKeyPBKDF2) (BCRYPT_ALG_HANDLE hPrf, PUCHAR pbPassword, ULONG cbPassword, PUCHAR pbSalt, ULONG cbSalt, ULONGLONG cIterations, PUCHAR pbDerivedKey, ULONG cbDerivedKey, ULONG dwFlags);
  ** HMODULE hBCrypt = LoadLibrary("bcrypt.dll");
  ** PFN_BCryptDeriveKeyPBKDF2 pbkdf2 = GetProcAddress(hBCrypt, "BCryptDeriveKeyPBKDF2");
  */

    /* suppress const qualifier warning b/c BCrypt doesn't take const input buffers */
#pragma warning(suppress: 4090)
  if (!BCRYPT_SUCCESS(BCryptDeriveKeyPBKDF2(BCRYPT_HMAC_SHA1_ALG_HANDLE, (PUCHAR)password, (ULONG)cb_password, (PUCHAR)salt, (ULONG)cb_salt, iterations, key, (ULONG)cb_key, 0)))
  {
    rc = PKCS5_GENERAL_ERROR;
  }

#else

  if(PKCS5_PBKDF2_HMAC_SHA1((const char*)password, cb_password, salt, cb_salt, iterations, cb_key, (unsigned char*)key) <= 0)
    rc = PKCS5_GENERAL_ERROR;

#endif

  return rc;
}

/* settings */

char *_strip_ws(char *sz) {
  char *psz_head = sz;
  char *psz_tail = sz + strlen(sz) - 1;

  /* strip leading whitespace */
  while (isspace(*psz_head)) {
    psz_head++;
  }

  /* strip trailing whitespace */
  while ((psz_tail >= psz_head) && isspace(*psz_tail)) {
    *psz_tail-- = '\0';
  }

  return psz_head;
}

setting_bool_t _get_bool_config(const char *sz_setting) {
  setting_bool_t setting = { false, SETTING_SOURCE_DEFAULT };

#ifdef _WIN32
  HKEY hKey = 0;
  DWORD dwValue = 0;
  DWORD dwType = 0;
  DWORD cbValue = sizeof(dwValue);

  /* MINGW doesn't define RRF_SUBKEY_WOW6464KEY for RegGetValue, so read the traditional way */
  if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, _CONFIG_REGKEY, 0, KEY_READ | KEY_WOW64_64KEY, &hKey) == 0) {
    if (RegQueryValueExA(hKey, sz_setting, NULL, &dwType, (LPBYTE)&dwValue, &cbValue) == 0) {
      setting.value = ((dwType == REG_DWORD) && (dwValue == 1));
      setting.source = SETTING_SOURCE_ADMIN;
    }
    RegCloseKey(hKey);
    hKey = 0;
  }

#else
  /* read from config file*/
  char sz_line[256] = { 0 };
  char *psz_name = 0;
  char *psz_value = 0;
  char sz_name[256] = { 0 };
  char sz_value[256] = { 0 };
  FILE *pf = 0;

  if ((pf = fopen(_CONFIG_FILE, "r"))) {
    while (!feof(pf)) {
      if (fgets(sz_line, sizeof(sz_line), pf)) {
        if (*sz_line == '#') continue;
        if (*sz_line == '\r') continue;
        if (*sz_line == '\n') continue;

        if (sscanf(sz_line, "%255[^=]=%255s", sz_name, sz_value) == 2) {
          /* strip leading/trailing whitespace */
          psz_name = _strip_ws(sz_name);

          if (!strcasecmp(psz_name, sz_setting)) {
            psz_value = _strip_ws(sz_value);

            setting.source = SETTING_SOURCE_ADMIN;
            setting.value = (!strcmp(psz_value, "1") || !strcasecmp(psz_value, "true"));
            break;
          }
        }
      }
    }
    fclose(pf);
  }

#endif

  return setting;
}

setting_bool_t _get_bool_env(const char *sz_setting) {
  setting_bool_t setting = { false, SETTING_SOURCE_DEFAULT };
  char *psz_value = NULL;
  char sz_name[256] = { 0 };
  snprintf(sz_name, sizeof(sz_name) - 1, "%s%s", _ENV_PREFIX, sz_setting);
  psz_value = getenv(sz_name);
  if (psz_value) {
    setting.source = SETTING_SOURCE_USER;
    setting.value = (!strcmp(psz_value, "1") || !strcasecmp(psz_value, "true"));
  }

  return setting;
}

setting_bool_t setting_get_bool(const char *sz_setting, bool def) {
  setting_bool_t setting = { def, SETTING_SOURCE_DEFAULT };

  setting = _get_bool_config(sz_setting);

  if (setting.source == SETTING_SOURCE_DEFAULT) {
    setting = _get_bool_env(sz_setting);
  }

  if (setting.source == SETTING_SOURCE_DEFAULT) {
    setting.value = def;
  }

  return setting;
}

/* logging */

void yc_log_event(const char *sz_source, uint32_t id, yc_log_level_t level, const char * sz_format, ...) {
  char rgsz_message[4096] = {0};
  va_list vl;

#ifdef _WIN32
  HANDLE hLog = NULL;
  LPCSTR sz_message = rgsz_message;
  WORD   w_type = EVENTLOG_SUCCESS;
#else
  int priority = LOG_INFO;
#endif

  va_start(vl, sz_format);

#ifdef _WIN32

  switch (level) {
    case YC_LOG_LEVEL_ERROR:
      w_type = EVENTLOG_ERROR_TYPE;
      break;
    case YC_LOG_LEVEL_WARN:
      w_type = EVENTLOG_WARNING_TYPE;
      break;
    case YC_LOG_LEVEL_INFO:
      w_type = EVENTLOG_INFORMATION_TYPE;
      break;
    case YC_LOG_LEVEL_VERBOSE:
      w_type = EVENTLOG_INFORMATION_TYPE;
      break;
    default:
    case YC_LOG_LEVEL_DEBUG:
      w_type = EVENTLOG_SUCCESS;
      break;
  }

  if (!(hLog = RegisterEventSourceA(NULL, sz_source))) {
    goto Cleanup;
  }

  /* format message */

  if (FAILED(StringCbVPrintfA(
    rgsz_message,
    sizeof(rgsz_message),
    sz_format,
    vl))) {
      goto Cleanup;
    };

  // write to the local event log

  ReportEventA(
    hLog,
    w_type,
    0,
    (DWORD)id,
    NULL,
    1,
    0,
    (LPCSTR *)&sz_message,
    NULL);

#else

   switch (level) {
     case YC_LOG_LEVEL_ERROR:
       priority = LOG_ERR;
       break;
     case YC_LOG_LEVEL_WARN:
       priority = LOG_WARNING;
       break;
     case YC_LOG_LEVEL_INFO:
       priority = LOG_NOTICE;
       break;
     case YC_LOG_LEVEL_VERBOSE:
       priority = LOG_INFO;
       break;
     default:
     case YC_LOG_LEVEL_DEBUG:
       priority = LOG_DEBUG;
       break;
   }

   if (vsnprintf(rgsz_message, sizeof(rgsz_message), sz_format, vl) < 0) {
     goto Cleanup;
   }

   openlog(sz_source, LOG_PID | LOG_NDELAY, LOG_USER);
   syslog(priority, "%s", rgsz_message);
   closelog();

#endif

Cleanup:

  va_end(vl);
#ifdef _WIN32
  if (hLog) {
    DeregisterEventSource(hLog);
  }
#endif

}
