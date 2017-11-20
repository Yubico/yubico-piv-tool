/*
 * Copyright (c) 2014-2016 Yubico AB
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

#include "ykpiv.h"

#include <stdbool.h>

#if BACKEND_PCSC
#if defined HAVE_PCSC_WINSCARD_H
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

struct ykpiv_state {
  SCARDCONTEXT context;
  SCARDHANDLE card;
  int  verbose;
  char *pin;
  ykpiv_allocator allocator;
  bool isNEO;
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
  unsigned char raw[0xff + 5];
};

typedef union u_APDU APDU;
typedef struct des_key des_key;

extern unsigned const char aid[];

des_rc des_import_key(const int type, const unsigned char* keyraw, const size_t keyrawlen, des_key** key);
des_rc des_destroy_key(des_key* key);
des_rc des_encrypt(des_key* key, const unsigned char* in, const size_t inlen, unsigned char* out, size_t* outlen);
des_rc des_decrypt(des_key* key, const unsigned char* in, const size_t inlen, unsigned char* out, size_t* outlen);
pkcs5_rc pkcs5_pbkdf2_sha1(const unsigned char* password, const size_t cb_password, const unsigned char* salt, const size_t cb_salt, unsigned long long iterations, unsigned char* key, const size_t cb_key);
bool   yk_des_is_weak_key(const unsigned char *key, const size_t cb_key);

prng_rc _ykpiv_prng_generate(unsigned char *buffer, const size_t cb_req);
ykpiv_rc _ykpiv_begin_transaction(ykpiv_state *state);
ykpiv_rc _ykpiv_end_transaction(ykpiv_state *state);
ykpiv_rc _ykpiv_ensure_application_selected(ykpiv_state *state);
int _ykpiv_set_length(unsigned char *buffer, size_t length);
int _ykpiv_get_length(const unsigned char *buffer, size_t *len);

void* _ykpiv_alloc(ykpiv_state *state, size_t size);
void* _ykpiv_realloc(ykpiv_state *state, void *address, size_t size);
void _ykpiv_free(ykpiv_state *state, void *data);
ykpiv_rc _ykpiv_save_object(ykpiv_state *state, int object_id, unsigned char *indata, size_t len);
ykpiv_rc _ykpiv_fetch_object(ykpiv_state *state, int object_id, unsigned char *data, unsigned long *len);

#ifdef __cplusplus
}
#endif

#endif
