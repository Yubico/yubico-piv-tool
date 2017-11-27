
#ifdef _WINDOWS
#include <windows.h>
#include <wincrypt.h>
#include <bcrypt.h>
#else
#include <openssl/des.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <string.h>
#endif

#include <stdio.h>
#include <stdlib.h>

#include "internal.h"

/*
** Definitions
*/

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

  //if (CALG_3DES == key->alg) {
  //  // truncate the final pad block
  //  *outlen = inlen - 8;
  //}
  //else {
  //  *outlen = inlen;
  //}

#else

  /* openssl returns void */
  DES_ecb3_encrypt((const_DES_cblock *)in, (DES_cblock*)out, &(key->ks1), &(key->ks2), &(key->ks3), 1);

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

  /* openssl returns void */
  DES_ecb3_encrypt((const_DES_cblock*)in, (DES_cblock*)out, &(key->ks1), &(key->ks2), &(key->ks3), 0);

#endif

EXIT:
  return rc;
}

bool yk_des_is_weak_key(const unsigned char *key, const size_t cb_key) {
#ifdef _WINDOWS
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
      return true;
    }
  }

  return false;
#else
  return DES_is_weak_key((const_DES_cblock *)key);
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

pkcs5_rc pkcs5_pbkdf2_sha1(const unsigned char* password, const size_t cb_password, const unsigned char* salt, const size_t cb_salt, unsigned long long iterations, unsigned char* key, const size_t cb_key) {
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
    if (STATUS_SUCCESS != BCryptDeriveKeyPBKDF2(hAlg, (PUCHAR)password, (ULONG)cb_password, (PUCHAR)salt, (ULONG)cb_salt, iterations, key, (ULONG)cb_key, 0)) {
      rc = PKCS5_GENERAL_ERROR;
    }

    BCryptCloseAlgorithmProvider(hAlg, 0);
  }
  else {
    rc = PKCS5_GENERAL_ERROR;
  }

#else

  /* for some reason openssl always returns 1 for PBKDF2 */
  PKCS5_PBKDF2_HMAC_SHA1((const char*)password, cb_password, salt, cb_salt, iterations, cb_key, key);

#endif

  return rc;
}
