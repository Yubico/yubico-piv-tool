#ifdef _WIN32
#include <windows.h>
#ifdef _MSC_VER
#define strcasecmp _stricmp
#endif
#else
#include <ctype.h>
#include <syslog.h>
#endif

/* the _WINDOWS define really means Windows native crypto-api/CNG */
#ifdef _WINDOWS
#include <wincrypt.h>
#include <bcrypt.h>
#else
#include <openssl/des.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#endif

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <strsafe.h> /* must be included after openssl headers */
#endif

#include "internal.h"

/*
** Definitions
*/

/* crypt defines */

#ifdef _WINDOWS

#define STATUS_SUCCESS                   ((NTSTATUS)0x00000000L)

struct des_key {
  HCRYPTPROV hProv;
  HCRYPTKEY  hKey;
  ALG_ID     alg;
};

static const BYTE PRIVATEKEY_EXPOF1_BLOB[] =
{
  0x07, 0x02, 0x00, 0x00, 0x00, 0xA4, 0x00, 0x00,
  0x52, 0x53, 0x41, 0x32, 0x00, 0x02, 0x00, 0x00,
  0x01, 0x00, 0x00, 0x00, 0xAB, 0xEF, 0xFA, 0xC6,
  0x7D, 0xE8, 0xDE, 0xFB, 0x68, 0x38, 0x09, 0x92,
  0xD9, 0x42, 0x7E, 0x6B, 0x89, 0x9E, 0x21, 0xD7,
  0x52, 0x1C, 0x99, 0x3C, 0x17, 0x48, 0x4E, 0x3A,
  0x44, 0x02, 0xF2, 0xFA, 0x74, 0x57, 0xDA, 0xE4,
  0xD3, 0xC0, 0x35, 0x67, 0xFA, 0x6E, 0xDF, 0x78,
  0x4C, 0x75, 0x35, 0x1C, 0xA0, 0x74, 0x49, 0xE3,
  0x20, 0x13, 0x71, 0x35, 0x65, 0xDF, 0x12, 0x20,
  0xF5, 0xF5, 0xF5, 0xC1, 0xED, 0x5C, 0x91, 0x36,
  0x75, 0xB0, 0xA9, 0x9C, 0x04, 0xDB, 0x0C, 0x8C,
  0xBF, 0x99, 0x75, 0x13, 0x7E, 0x87, 0x80, 0x4B,
  0x71, 0x94, 0xB8, 0x00, 0xA0, 0x7D, 0xB7, 0x53,
  0xDD, 0x20, 0x63, 0xEE, 0xF7, 0x83, 0x41, 0xFE,
  0x16, 0xA7, 0x6E, 0xDF, 0x21, 0x7D, 0x76, 0xC0,
  0x85, 0xD5, 0x65, 0x7F, 0x00, 0x23, 0x57, 0x45,
  0x52, 0x02, 0x9D, 0xEA, 0x69, 0xAC, 0x1F, 0xFD,
  0x3F, 0x8C, 0x4A, 0xD0,

  0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

  0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

  0x64, 0xD5, 0xAA, 0xB1,
  0xA6, 0x03, 0x18, 0x92, 0x03, 0xAA, 0x31, 0x2E,
  0x48, 0x4B, 0x65, 0x20, 0x99, 0xCD, 0xC6, 0x0C,
  0x15, 0x0C, 0xBF, 0x3E, 0xFF, 0x78, 0x95, 0x67,
  0xB1, 0x74, 0x5B, 0x60,

  0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

const DWORD PRIVATEKEY_EXPOF1_BITLEN = 512;
const ALG_ID PRIVATEKEY_EXPOF1_ALG = CALG_RSA_KEYX;

#else

struct des_key {
  DES_key_schedule ks1;
  DES_key_schedule ks2;
  DES_key_schedule ks3;
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

/* log */

const char szLOG_SOURCE[] = "YubiKey PIV Library";

/*
** Methods
*/

des_rc des_import_key(const int type, const unsigned char* keyraw, const size_t keyrawlen, des_key** key) {
  des_rc rc = DES_OK;
  size_t cb_expectedkey = DES_LEN_3DES;

#ifdef _WINDOWS

  HCRYPTKEY hNullKey = 0;
  ALG_ID alg = 0;
  unsigned char* pbSessionBlob = NULL;
  DWORD cbSessionBlob = 0;
  DWORD cbRandom = 0;
  unsigned char* pbTmp = NULL;
  size_t n = 0;

  switch (type) {
  case DES_TYPE_3DES:
    alg = CALG_3DES;
    cb_expectedkey = DES_LEN_3DES;
    break;
  default:
    rc = DES_INVALID_PARAMETER;
    goto ERROR_EXIT;
  }

  if (!keyraw) { rc = DES_INVALID_PARAMETER; goto ERROR_EXIT; }
  if (keyrawlen != cb_expectedkey) { rc = DES_INVALID_PARAMETER; goto ERROR_EXIT; }
  if (!key) { rc = DES_INVALID_PARAMETER; goto ERROR_EXIT; }
  if (!(*key = (des_key*)malloc(sizeof(des_key)))) { rc = DES_MEMORY_ERROR; goto ERROR_EXIT; }

  memset(*key, 0, sizeof(des_key));

  (*key)->alg = alg;

  if (!CryptAcquireContext(&((*key)->hProv), NULL, MS_ENHANCED_PROV, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) { rc = DES_GENERAL_ERROR; goto ERROR_EXIT; }

  // Import the exponent-of-one private key.
  if (!CryptImportKey((*key)->hProv, PRIVATEKEY_EXPOF1_BLOB, sizeof(PRIVATEKEY_EXPOF1_BLOB), 0, 0, &hNullKey)) { rc = DES_GENERAL_ERROR; goto ERROR_EXIT; }

  // calculate Simple blob's length
  cbSessionBlob = (PRIVATEKEY_EXPOF1_BITLEN / 8) + sizeof(ALG_ID) + sizeof(BLOBHEADER);

  // allocate simple blob buffer
  if (!(pbSessionBlob = malloc(cbSessionBlob))) { rc = DES_MEMORY_ERROR; goto ERROR_EXIT; }
  memset(pbSessionBlob, 0, cbSessionBlob);

  pbTmp = pbSessionBlob;

  // SIMPLEBLOB Format is documented in SDK
  // Copy header to buffer
  ((BLOBHEADER *)pbTmp)->bType = SIMPLEBLOB;
  ((BLOBHEADER *)pbTmp)->bVersion = 2;
  ((BLOBHEADER *)pbTmp)->reserved = 0;
  ((BLOBHEADER *)pbTmp)->aiKeyAlg = alg;
  pbTmp += sizeof(BLOBHEADER);

  // Copy private key algorithm to buffer
  *((DWORD *)pbTmp) = PRIVATEKEY_EXPOF1_ALG;
  pbTmp += sizeof(ALG_ID);

  // Place the key material in reverse order
  for (n = 0; n < keyrawlen; n++) {
    pbTmp[n] = keyraw[keyrawlen - n - 1];
  }

  // 3 is for the first reserved byte after the key material + the 2 reserved bytes at the end.
  cbRandom = cbSessionBlob - (sizeof(ALG_ID) + sizeof(BLOBHEADER) + (DWORD)keyrawlen + 3);
  pbTmp += (keyrawlen + 1);

  // Generate random data for the rest of the buffer
  // (except that last two bytes)
  if (!CryptGenRandom((*key)->hProv, cbRandom, pbTmp)) { rc = DES_GENERAL_ERROR; goto ERROR_EXIT; }

  for (n = 0; n < cbRandom; n++) {
    if (pbTmp[n] == 0) pbTmp[n] = 1;
  }

  pbSessionBlob[cbSessionBlob - 2] = 2;

  if (!CryptImportKey((*key)->hProv, pbSessionBlob, cbSessionBlob, hNullKey, CRYPT_EXPORTABLE, &((*key)->hKey))) { rc = DES_GENERAL_ERROR; goto ERROR_EXIT; }

#else

  const_DES_cblock key_tmp;
  size_t cb_keysize = 8;


  switch (type) {
  case DES_TYPE_3DES:
    cb_expectedkey = DES_LEN_3DES;
    cb_keysize = 8;
    break;
  default:
    rc = DES_INVALID_PARAMETER;
    goto ERROR_EXIT;
  }

  if (cb_keysize > sizeof(key_tmp)) { rc = DES_MEMORY_ERROR; goto ERROR_EXIT; }
  if (!keyraw) { rc = DES_INVALID_PARAMETER; goto ERROR_EXIT; }
  if (keyrawlen != cb_expectedkey) { rc = DES_INVALID_PARAMETER; goto ERROR_EXIT; }
  if (!key) { rc = DES_INVALID_PARAMETER; goto ERROR_EXIT; }
  if (!(*key = (des_key*)malloc(sizeof(des_key)))) { rc = DES_MEMORY_ERROR; goto ERROR_EXIT; }

  memset(*key, 0, sizeof(des_key));

  memcpy(key_tmp, keyraw, cb_keysize);
  DES_set_key_unchecked(&key_tmp, &((*key)->ks1));
  memcpy(key_tmp, keyraw + cb_keysize, cb_keysize);
  DES_set_key_unchecked(&key_tmp, &((*key)->ks2));
  memcpy(key_tmp, keyraw + (2 * cb_keysize), cb_keysize);
  DES_set_key_unchecked(&key_tmp, &((*key)->ks3));

#endif

EXIT:
#ifdef _WINDOWS
  if (pbSessionBlob) {
    yc_memzero(pbSessionBlob, cbSessionBlob);
    free(pbSessionBlob);
    pbSessionBlob = NULL;
  }

  if (hNullKey) {
    CryptDestroyKey(hNullKey);
    hNullKey = 0;
  }
#endif
  return rc;

ERROR_EXIT:
  if (key) {
    des_destroy_key(*key);
    *key = NULL;
  }
  goto EXIT;


}

des_rc des_destroy_key(des_key* key) {
  if (key) {
#ifdef _WINDOWS
    if (key->hKey) {
      CryptDestroyKey(key->hKey);
      key->hKey = 0;
    }

    if (key->hProv) {
      CryptReleaseContext(key->hProv, 0);
      key->hProv = 0;
    }
#endif
    free(key);
  }

  return DES_OK;
}

des_rc des_encrypt(des_key* key, const unsigned char* in, const size_t inlen, unsigned char* out, size_t* outlen) {
  des_rc rc = DES_OK;

#ifdef _WINDOWS
  unsigned char buf[8] = { 0 };
  size_t buflen = sizeof(buf);
#endif

  if (!key || !outlen || (*outlen < inlen) || !in || !out) { rc = DES_INVALID_PARAMETER; goto EXIT; }

#ifdef _WINDOWS

  if (!key->hKey) { rc = DES_INVALID_PARAMETER; goto EXIT; }

  memcpy(out, in, inlen);
  *outlen = inlen;

  if (!CryptEncrypt(key->hKey, 0, FALSE, 0, out, (DWORD*)&inlen, (DWORD)*outlen)) { fwprintf(stderr, L"GetLastError = %x\n", GetLastError()); rc = DES_GENERAL_ERROR; goto EXIT; }
  // reset key usage by encrypting a fake padded block
  CryptEncrypt(key->hKey, 0, TRUE, 0, buf, (DWORD*)&buflen, (DWORD)buflen);

#else

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-qual"
  /* openssl returns void */
  DES_ecb3_encrypt((const_DES_cblock *)in, (DES_cblock*)out, &(key->ks1), &(key->ks2), &(key->ks3), 1);
#pragma GCC diagnostic pop

#endif

EXIT:
  return rc;
}

des_rc des_decrypt(des_key* key, const unsigned char* in, const size_t inlen, unsigned char* out, size_t* outlen) {
  des_rc rc = DES_OK;

#ifdef _WINDOWS
  unsigned char buf[8] = { 0 };
  size_t buflen = sizeof(buf);
#endif

  if (!key || !outlen || (*outlen < inlen) || !in || !out) { rc = DES_INVALID_PARAMETER; goto EXIT; }

#ifdef _WINDOWS

  if (!key->hKey) { rc = DES_INVALID_PARAMETER; goto EXIT; }

  memcpy(out, in, inlen);
  *outlen = inlen;

  if (!CryptDecrypt(key->hKey, 0, FALSE, 0, out, (DWORD*)outlen)) { fwprintf(stderr, L"GetLastError = %x\n", GetLastError()); rc = DES_GENERAL_ERROR; goto EXIT; }
  // reset key usage by decrypting a fake padded block
  CryptDecrypt(key->hKey, 0, TRUE, 0, buf, (DWORD*)&buflen);

#else

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-qual"
  /* openssl returns void */
  DES_ecb3_encrypt((const_DES_cblock*)in, (DES_cblock*)out, &(key->ks1), &(key->ks2), &(key->ks3), 0);
#pragma GCC diagnostic pop

#endif

EXIT:
  return rc;
}

bool yk_des_is_weak_key(const unsigned char *key, const size_t cb_key) {
#ifdef _WINDOWS
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

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-qual"
  return DES_is_weak_key((const_DES_cblock *)key);
#pragma GCC diagnostic pop
#endif
}

prng_rc _ykpiv_prng_generate(unsigned char *buffer, const size_t cb_req) {
  prng_rc rc = PRNG_OK;

#ifdef _WINDOWS
  HCRYPTPROV hProv = 0;

  if (CryptAcquireContext(&hProv, NULL, MS_ENHANCED_PROV, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
    if (!CryptGenRandom(hProv, (DWORD)cb_req, buffer)) {
      rc = PRNG_GENERAL_ERROR;
    }

    CryptReleaseContext(hProv, 0);
  }
  else {
    rc = PRNG_GENERAL_ERROR;
  }

#else
  if (-1 == RAND_bytes(buffer, cb_req)) {
    rc = PRNG_GENERAL_ERROR;
  }

#endif

  return rc;
}

pkcs5_rc pkcs5_pbkdf2_sha1(const uint8_t* password, const size_t cb_password, const uint8_t* salt, const size_t cb_salt, uint64_t iterations, const uint8_t* key, const size_t cb_key) {
  pkcs5_rc rc = PKCS5_OK;

#ifdef _WINDOWS
  BCRYPT_ALG_HANDLE hAlg = 0;

  /* mingw64 defines the BCryptDeriveKeyPBKDF2 function, but its dll link library doesn't include the export.
  **
  ** In case this is needed, we'll need to dynamically load the function:
  **
  ** typedef NTSTATUS WINAPI (*PFN_BCryptDeriveKeyPBKDF2) (BCRYPT_ALG_HANDLE hPrf, PUCHAR pbPassword, ULONG cbPassword, PUCHAR pbSalt, ULONG cbSalt, ULONGLONG cIterations, PUCHAR pbDerivedKey, ULONG cbDerivedKey, ULONG dwFlags);
  ** HMODULE hBCrypt = LoadLibrary("bcrypt.dll");
  ** PFN_BCryptDeriveKeyPBKDF2 pbkdf2 = GetProcAddress(hBCrypt, "BCryptDeriveKeyPBKDF2");
  */

  if (STATUS_SUCCESS == BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA1_ALGORITHM, NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG)) {
    /* suppress const qualifier warning b/c BCrypt doesn't take const input buffers */
#pragma warning(suppress: 4090)
    if (STATUS_SUCCESS != BCryptDeriveKeyPBKDF2(hAlg, (PUCHAR)password, (ULONG)cb_password, (PUCHAR)salt, (ULONG)cb_salt, iterations, key, (ULONG)cb_key, 0)) {
      rc = PKCS5_GENERAL_ERROR;
    }

    BCryptCloseAlgorithmProvider(hAlg, 0);
  }
  else {
    rc = PKCS5_GENERAL_ERROR;
  }

#else

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-qual"
  /* for some reason openssl always returns 1 for PBKDF2 */
  PKCS5_PBKDF2_HMAC_SHA1((const char*)password, cb_password, salt, cb_salt, iterations, cb_key, (unsigned char*)key);
#pragma GCC diagnostic pop

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
  char sz_line[256];
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

  /* MINGW does not implement getenv_s, only _wgetenv_s */
#ifdef _MSC_VER
  size_t cb_value = 0;
  char sz_value[100] = { 0 };

  if ((getenv_s(&cb_value, sz_value, sizeof(sz_value) - 1, sz_name) == 0) && (cb_value > 0)) {
    psz_value = sz_value;
  }

#else
  psz_value = getenv(sz_name);

#endif

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

void yc_log_event(uint32_t id, yc_log_level_t level, const char * sz_format, ...) {
  char rgsz_message[4096];
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

  if (!(hLog = RegisterEventSourceA(NULL, szLOG_SOURCE))) {
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

   openlog(szLOG_SOURCE, LOG_PID | LOG_NDELAY, LOG_USER);
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
