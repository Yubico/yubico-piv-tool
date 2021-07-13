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

#ifndef YKPIV_INTERNAL_H
#define YKPIV_INTERNAL_H

#include "ykpiv-config.h"
#include "ykpiv.h"

#include <stdbool.h>

#ifdef BACKEND_PCSC
#ifdef HAVE_PCSC_WINSCARD_H
# include <PCSC/wintypes.h>
# include <PCSC/winscard.h>
#else
# include <winscard.h>
#endif
#endif

// Typedef DWORD (defined by pcsc lib) to pcsc_word to make it clear that this
// is not the Windows meaning of DWORD, but the PCSC library's meaning.  This
// differs: Windows defines a DWORD as 32-bits, but pcsclite defines it as
// 'unsigned long' on x86_64 Linux, which is often 64-bits.
typedef DWORD pcsc_word;

#ifdef __cplusplus
extern "C"
{
#endif

#define DES_TYPE_3DES 1

#define DES_LEN_DES   8
#define DES_LEN_3DES  DES_LEN_DES*3

#define READER_LEN  32
#define MAX_READERS 16

#define CB_MGM_KEY DES_LEN_3DES

// the object size is restricted to the firmware's message buffer size, which
// always contains 0x5C + 1 byte len + 3 byte id + 0x53 + 3 byte len = 9 bytes,
// so while the message buffer == CB_BUF_MAX, the maximum object we can store
// is CB_BUF_MAX - 9
#define CB_OBJ_MAX_NEO      (CB_BUF_MAX_NEO - 9)
#define CB_OBJ_MAX_YK4      (CB_BUF_MAX_YK4 - 9)
#define CB_OBJ_MAX          CB_OBJ_MAX_YK4

#define CB_BUF_MAX_NEO      2048
#define CB_BUF_MAX_YK4      3072
#define CB_BUF_MAX          CB_BUF_MAX_YK4

#define CB_ATR_MAX          33

#define CHREF_ACT_CHANGE_PIN 0
#define CHREF_ACT_UNBLOCK_PIN 1
#define CHREF_ACT_CHANGE_PUK 2

#define TAG_CERT              0x70
#define TAG_CERT_COMPRESS     0x71
#define TAG_CERT_LRC          0xFE
#define TAG_ADMIN             0x80
#define TAG_ADMIN_FLAGS_1     0x81
#define TAG_ADMIN_SALT        0x82
#define TAG_ADMIN_TIMESTAMP   0x83
#define TAG_PROTECTED         0x88
#define TAG_PROTECTED_FLAGS_1 0x81
#define TAG_PROTECTED_MGM     0x89
#define TAG_MSCMAP            0x81
#define TAG_MSROOTS_END       0x82
#define TAG_MSROOTS_MID       0x83

#define TAG_RSA_MODULUS       0x81
#define TAG_RSA_EXP           0x82
#define TAG_ECC_POINT         0x86

#define CB_ECC_POINTP256    65
#define CB_ECC_POINTP384    97

#define YKPIV_OBJ_ADMIN_DATA 0x5fff00
#define YKPIV_OBJ_ATTESTATION 0x5fff01
#define	YKPIV_OBJ_MSCMAP      0x5fff10
#define	YKPIV_OBJ_MSROOTS1    0x5fff11
#define YKPIV_OBJ_MSROOTS2    0x5fff12
#define YKPIV_OBJ_MSROOTS3    0x5fff13
#define YKPIV_OBJ_MSROOTS4    0x5fff14
#define YKPIV_OBJ_MSROOTS5    0x5fff15

#define ADMIN_FLAGS_1_PUK_BLOCKED    0x01
#define ADMIN_FLAGS_1_PROTECTED_MGM  0x02

#define CB_ADMIN_SALT         16
#define CB_ADMIN_TIMESTAMP    4

#define ITER_MGM_PBKDF2       10000

#define PROTECTED_FLAGS_1_PUK_NOBLOCK 0x01

#define CB_OBJ_TAG_MIN      2                       // 1 byte tag + 1 byte len
#define CB_OBJ_TAG_MAX      (CB_OBJ_TAG_MIN + 2)      // 1 byte tag + 3 bytes len

#define CB_PIN_MAX          8
#define member_size(type, member) sizeof(((type*)0)->member)

typedef enum {
  DES_OK = 0,
  DES_INVALID_PARAMETER = -1,
  DES_BUFFER_TOO_SMALL = -2,
  DES_MEMORY_ERROR = -3,
  DES_GENERAL_ERROR = -4
} des_rc;

typedef enum {
    PKCS5_OK = 0,
    PKCS5_GENERAL_ERROR = -1
} pkcs5_rc;

typedef enum {
  PRNG_OK = 0,
  PRNG_GENERAL_ERROR = -1
} prng_rc;

typedef struct _ykpiv_version_t {
  uint8_t major;
  uint8_t minor;
  uint8_t patch;
} ykpiv_version_t;

struct ykpiv_state {
  SCARDCONTEXT context;
  SCARDHANDLE card;
  int  verbose;
  int tries;
  char *pin;
  uint8_t *mgm_key;
  ykpiv_allocator allocator;
  uint32_t model;
  ykpiv_version_t ver;
  uint32_t serial;
  pcsc_word card_protocol;
};

union u_APDU {
  struct {
    unsigned char cla;
    unsigned char ins;
    unsigned char p1;
    unsigned char p2;
    unsigned char lc;
    unsigned char data[0xff];
  } st;
  unsigned char raw[0xff + 5 + 1]; // 1 byte for Le
};

typedef union u_APDU APDU;
typedef struct des_key des_key;

des_rc des_import_key(const int type, const unsigned char* keyraw, const size_t keyrawlen, des_key** key);
des_rc des_destroy_key(des_key* key);
des_rc des_encrypt(des_key* key, const unsigned char* in, const size_t inlen, unsigned char* out, size_t* outlen);
des_rc des_decrypt(des_key* key, const unsigned char* in, const size_t inlen, unsigned char* out, size_t* outlen);
pkcs5_rc pkcs5_pbkdf2_sha1(const uint8_t* password, const size_t cb_password, const uint8_t* salt, const size_t cb_salt, uint64_t iterations, const uint8_t* key, const size_t cb_key);
bool   yk_des_is_weak_key(const unsigned char *key, const size_t cb_key);

prng_rc _ykpiv_prng_generate(unsigned char *buffer, const size_t cb_req);
ykpiv_rc _ykpiv_begin_transaction(ykpiv_state *state);
ykpiv_rc _ykpiv_end_transaction(ykpiv_state *state);
ykpiv_rc _ykpiv_ensure_application_selected(ykpiv_state *state);
ykpiv_rc _ykpiv_select_application(ykpiv_state *state);
size_t _ykpiv_get_length_size(size_t length);
size_t _ykpiv_set_length(unsigned char *buffer, size_t length);
size_t _ykpiv_get_length(const unsigned char *buffer, const unsigned char* end, size_t *len);

void* _ykpiv_alloc(ykpiv_state *state, size_t size);
void* _ykpiv_realloc(ykpiv_state *state, void *address, size_t size);
void _ykpiv_free(ykpiv_state *state, void *data);
ykpiv_rc _ykpiv_save_object(ykpiv_state *state, int object_id, unsigned char *indata, size_t len);
ykpiv_rc _ykpiv_fetch_object(ykpiv_state *state, int object_id, unsigned char *data, unsigned long *len);
ykpiv_rc _send_data(ykpiv_state *state, APDU *apdu, unsigned char *data, uint32_t *recv_len, int *sw);
ykpiv_rc _ykpiv_transfer_data(
    ykpiv_state *state,
    const unsigned char *templ,
    const unsigned char *in_data,
    long in_len,
    unsigned char *out_data,
    unsigned long *out_len,
    int *sw);

/* authentication functions not ready for public api */
ykpiv_rc ykpiv_auth_getchallenge(ykpiv_state *state, uint8_t *challenge, const size_t challenge_len);
ykpiv_rc ykpiv_auth_verifyresponse(ykpiv_state *state, uint8_t *response, const size_t response_len);
ykpiv_rc ykpiv_auth_deauthenticate(ykpiv_state *state);

typedef enum _setting_source_t {
  SETTING_SOURCE_USER,
  SETTING_SOURCE_ADMIN,
  SETTING_SOURCE_DEFAULT
} setting_source_t;

typedef struct _setting_bool_t {
  bool value;
  setting_source_t source;
} setting_bool_t;

setting_bool_t setting_get_bool(const char *sz_setting, bool f_default);

typedef enum _yc_log_level_t {
  YC_LOG_LEVEL_ERROR,
  YC_LOG_LEVEL_WARN,
  YC_LOG_LEVEL_INFO,
  YC_LOG_LEVEL_VERBOSE,
  YC_LOG_LEVEL_DEBUG
} yc_log_level_t;

void yc_log_event(uint32_t id, yc_log_level_t level, const char *sz_format, ...);

#ifdef _WIN32
#include <windows.h>
#define yc_memzero SecureZeroMemory
#elif defined(HAVE_EXPLICIT_BZERO)
#include <strings.h>
#define yc_memzero explicit_bzero
#elif defined(__linux__)
#include <openssl/crypto.h>
#define yc_memzero OPENSSL_cleanse
#else
#define __STDC_WANT_LIB_EXT1__ 1
#include <string.h>
#define yc_memzero(_p, _n) (void)memset_s(_p, (rsize_t)_n, 0, (rsize_t)_n)
#endif

#ifdef __cplusplus
}
#endif

#endif
