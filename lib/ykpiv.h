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

#ifndef YKPIV_H
#define YKPIV_H

#include <stdint.h>
#include <stddef.h>

#include <ykpiv-version.h>

#ifdef __cplusplus
extern "C"
{
#endif

  typedef struct ykpiv_state ykpiv_state;

  typedef enum {
    YKPIV_OK = 0,
    YKPIV_MEMORY_ERROR = -1,
    YKPIV_PCSC_ERROR = -2,
    YKPIV_SIZE_ERROR = -3,
    YKPIV_APPLET_ERROR = -4,
    YKPIV_AUTHENTICATION_ERROR = -5,
    YKPIV_RANDOMNESS_ERROR = -6,
    YKPIV_GENERIC_ERROR = -7,
    YKPIV_KEY_ERROR = -8,
    YKPIV_PARSE_ERROR = -9,
    YKPIV_WRONG_PIN = -10,
    YKPIV_INVALID_OBJECT = -11,
    YKPIV_ALGORITHM_ERROR = -12,
    YKPIV_PIN_LOCKED = -13,
  } ykpiv_rc;

  const char *ykpiv_strerror(ykpiv_rc err);
  const char *ykpiv_strerror_name(ykpiv_rc err);

  ykpiv_rc ykpiv_init(ykpiv_state **state, int verbose);
  ykpiv_rc ykpiv_done(ykpiv_state *state);
  ykpiv_rc ykpiv_connect(ykpiv_state *state, const char *wanted);
  ykpiv_rc ykpiv_list_readers(ykpiv_state *state, char *readers, size_t *len);
  ykpiv_rc ykpiv_disconnect(ykpiv_state *state);
  ykpiv_rc ykpiv_transfer_data(ykpiv_state *state, const unsigned char *templ,
                               const unsigned char *in_data, long in_len,
                               unsigned char *out_data, unsigned long *out_len, int *sw);
  ykpiv_rc ykpiv_authenticate(ykpiv_state *state, const unsigned char *key);
  ykpiv_rc ykpiv_set_mgmkey(ykpiv_state *state, const unsigned char *new_key);
  ykpiv_rc ykpiv_hex_decode(const char *hex_in, size_t in_len,
                            unsigned char *hex_out, size_t *out_len);
  ykpiv_rc ykpiv_sign_data(ykpiv_state *state, const unsigned char *sign_in,
                           size_t in_len, unsigned char *sign_out, size_t *out_len,
                           unsigned char algorithm, unsigned char key);
  ykpiv_rc ykpiv_sign_data2(ykpiv_state *state, const unsigned char *sign_in,
                            size_t in_len, unsigned char *sign_out, size_t *out_len,
                            unsigned char algorithm, unsigned char key, int padding); // Allow not to add padding
  ykpiv_rc ykpiv_decipher_data(ykpiv_state *state, const unsigned char *enc_in,
                               size_t in_len, unsigned char *enc_out, size_t *out_len,
                               unsigned char algorithm, unsigned char key);
  ykpiv_rc ykpiv_get_version(ykpiv_state *state, char *version, size_t len);
  ykpiv_rc ykpiv_verify(ykpiv_state *state, const char *pin, int *tries);
  ykpiv_rc ykpiv_change_pin(ykpiv_state *state, const char * current_pin, size_t current_pin_len,
                            const char * new_pin, size_t new_pin_len,
                            int *tries);
  ykpiv_rc ykpiv_change_puk(ykpiv_state *state, const char * current_puk, size_t current_puk_len,
                            const char * new_puk, size_t new_puk_len,
                            int *tries);
  ykpiv_rc ykpiv_unblock_pin(ykpiv_state *state, const char * puk, size_t puk_len,
                             const char * new_pin, size_t new_pin_len,
                             int *tries);
  ykpiv_rc ykpiv_fetch_object(ykpiv_state *state, int object_id,
                              unsigned char *data, unsigned long *len);
  ykpiv_rc ykpiv_set_mgmkey2(ykpiv_state *state, const unsigned char *new_key,
      const unsigned char touch);
  ykpiv_rc ykpiv_save_object(ykpiv_state *state, int object_id,
                             unsigned char *indata, size_t len);
  ykpiv_rc ykpiv_import_private_key(ykpiv_state *state, const unsigned char key, unsigned char algorithm,
                                    const unsigned char *p, size_t p_len,
                                    const unsigned char *q, size_t q_len,
                                    const unsigned char *dp, size_t dp_len,
                                    const unsigned char *dq, size_t dq_len,
                                    const unsigned char *qinv, size_t qinv_len,
                                    const unsigned char *ec_data, unsigned char ec_data_len,
                                    const unsigned char pin_policy, const unsigned char touch_policy);

#define YKPIV_ALGO_TAG 0x80
#define YKPIV_ALGO_3DES 0x03
#define YKPIV_ALGO_RSA1024 0x06
#define YKPIV_ALGO_RSA2048 0x07
#define YKPIV_ALGO_ECCP256 0x11
#define YKPIV_ALGO_ECCP384 0x14

#define YKPIV_KEY_AUTHENTICATION 0x9a
#define YKPIV_KEY_CARDMGM 0x9b
#define YKPIV_KEY_SIGNATURE 0x9c
#define YKPIV_KEY_KEYMGM 0x9d
#define YKPIV_KEY_CARDAUTH 0x9e
#define YKPIV_KEY_RETIRED1 0x82
#define YKPIV_KEY_RETIRED2 0x83
#define YKPIV_KEY_RETIRED3 0x84
#define YKPIV_KEY_RETIRED4 0x85
#define YKPIV_KEY_RETIRED5 0x86
#define YKPIV_KEY_RETIRED6 0x87
#define YKPIV_KEY_RETIRED7 0x88
#define YKPIV_KEY_RETIRED8 0x89
#define YKPIV_KEY_RETIRED9 0x8a
#define YKPIV_KEY_RETIRED10 0x8b
#define YKPIV_KEY_RETIRED11 0x8c
#define YKPIV_KEY_RETIRED12 0x8d
#define YKPIV_KEY_RETIRED13 0x8e
#define YKPIV_KEY_RETIRED14 0x8f
#define YKPIV_KEY_RETIRED15 0x90
#define YKPIV_KEY_RETIRED16 0x91
#define YKPIV_KEY_RETIRED17 0x92
#define YKPIV_KEY_RETIRED18 0x93
#define YKPIV_KEY_RETIRED19 0x94
#define YKPIV_KEY_RETIRED20 0x95
#define YKPIV_KEY_ATTESTATION 0xf9

#define YKPIV_OBJ_CAPABILITY 0x5fc107
#define YKPIV_OBJ_CHUID 0x5fc102
#define YKPIV_OBJ_AUTHENTICATION 0x5fc105 /* cert for 9a key */
#define YKPIV_OBJ_FINGERPRINTS 0x5fc103
#define YKPIV_OBJ_SECURITY 0x5fc106
#define YKPIV_OBJ_FACIAL 0x5fc108
#define YKPIV_OBJ_PRINTED 0x5fc109
#define YKPIV_OBJ_SIGNATURE 0x5fc10a /* cert for 9c key */
#define YKPIV_OBJ_KEY_MANAGEMENT 0x5fc10b /* cert for 9d key */
#define YKPIV_OBJ_CARD_AUTH 0x5fc101 /* cert for 9e key */
#define YKPIV_OBJ_DISCOVERY 0x7e
#define YKPIV_OBJ_KEY_HISTORY 0x5fc10c
#define YKPIV_OBJ_IRIS 0x5fc121

#define YKPIV_OBJ_RETIRED1  0x5fc10d
#define YKPIV_OBJ_RETIRED2  0x5fc10e
#define YKPIV_OBJ_RETIRED3  0x5fc10f
#define YKPIV_OBJ_RETIRED4  0x5fc110
#define YKPIV_OBJ_RETIRED5  0x5fc111
#define YKPIV_OBJ_RETIRED6  0x5fc112
#define YKPIV_OBJ_RETIRED7  0x5fc113
#define YKPIV_OBJ_RETIRED8  0x5fc114
#define YKPIV_OBJ_RETIRED9  0x5fc115
#define YKPIV_OBJ_RETIRED10 0x5fc116
#define YKPIV_OBJ_RETIRED11 0x5fc117
#define YKPIV_OBJ_RETIRED12 0x5fc118
#define YKPIV_OBJ_RETIRED13 0x5fc119
#define YKPIV_OBJ_RETIRED14 0x5fc11a
#define YKPIV_OBJ_RETIRED15 0x5fc11b
#define YKPIV_OBJ_RETIRED16 0x5fc11c
#define YKPIV_OBJ_RETIRED17 0x5fc11d
#define YKPIV_OBJ_RETIRED18 0x5fc11e
#define YKPIV_OBJ_RETIRED19 0x5fc11f
#define YKPIV_OBJ_RETIRED20 0x5fc120

#define YKPIV_OBJ_ATTESTATION 0x5fff01

#define YKPIV_INS_VERIFY 0x20
#define YKPIV_INS_CHANGE_REFERENCE 0x24
#define YKPIV_INS_RESET_RETRY 0x2c
#define YKPIV_INS_GENERATE_ASYMMETRIC 0x47
#define YKPIV_INS_AUTHENTICATE 0x87
#define YKPIV_INS_GET_DATA 0xcb
#define YKPIV_INS_PUT_DATA 0xdb

/* sw is status words, see NIST special publication 800-73-4, section 5.6 */
#define SW_SUCCESS 0x9000
#define SW_ERR_SECURITY_STATUS 0x6982
#define SW_ERR_AUTH_BLOCKED 0x6983
#define SW_ERR_INCORRECT_PARAM 0x6a80
/* this is a custom sw for yubikey */
#define SW_ERR_INCORRECT_SLOT 0x6b00

  /* Yubico vendor specific instructions */
#define YKPIV_INS_SET_MGMKEY 0xff
#define YKPIV_INS_IMPORT_KEY 0xfe
#define YKPIV_INS_GET_VERSION 0xfd
#define YKPIV_INS_RESET 0xfb
#define YKPIV_INS_SET_PIN_RETRIES 0xfa
#define YKPIV_INS_ATTEST 0xf9

#define YKPIV_PINPOLICY_TAG 0xaa
#define YKPIV_PINPOLICY_DEFAULT 0
#define YKPIV_PINPOLICY_NEVER 1
#define YKPIV_PINPOLICY_ONCE 2
#define YKPIV_PINPOLICY_ALWAYS 3

#define YKPIV_TOUCHPOLICY_TAG 0xab
#define YKPIV_TOUCHPOLICY_DEFAULT 0
#define YKPIV_TOUCHPOLICY_NEVER 1
#define YKPIV_TOUCHPOLICY_ALWAYS 2
#define YKPIV_TOUCHPOLICY_CACHED 3

#define YKPIV_IS_EC(a) ((a == YKPIV_ALGO_ECCP256 || a == YKPIV_ALGO_ECCP384))
#define YKPIV_IS_RSA(a) ((a == YKPIV_ALGO_RSA1024 || a == YKPIV_ALGO_RSA2048))

#ifdef __cplusplus
}
#endif

#endif
