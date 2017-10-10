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
#include <stdbool.h>

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

    YKPIV_ARGUMENT_ERROR = -14, //i.e. invalid input argument
    YKPIV_RANGE_ERROR = -15 //i.e. value range error
  } ykpiv_rc;

  typedef void* (*ykpiv_pfn_alloc)(void* alloc_data, size_t size);
  typedef void* (*ykpiv_pfn_realloc)(void* alloc_data, void* address, size_t size);
  typedef void  (*ykpiv_pfn_free)(void* alloc_data, void* address);
  typedef struct ykpiv_allocator {
    ykpiv_pfn_alloc   pfn_alloc;
    ykpiv_pfn_realloc pfn_realloc;
    ykpiv_pfn_free    pfn_free;
    void *            alloc_data;
  } ykpiv_allocator;

  const char *ykpiv_strerror(ykpiv_rc err);
  const char *ykpiv_strerror_name(ykpiv_rc err);

  ykpiv_rc ykpiv_init(ykpiv_state **state, int verbose);
  ykpiv_rc ykpiv_init_with_allocator(ykpiv_state **state, int verbose, const ykpiv_allocator *allocator);
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
  // TODO (TREV): minidriver has ykpiv_sign_data2
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
  // TREV TODO: document that this only works when NOT verified, as per spec (NIST SP 800-73-3 part 2 page 11)
  ykpiv_rc ykpiv_get_pin_retries(ykpiv_state *state, int* tries);
  // TREV TODO: document that 0 == successful no-op.
  ykpiv_rc ykpiv_set_pin_retries(ykpiv_state *state, int pin_tries, int puk_tries);
  ykpiv_rc ykpiv_attest(ykpiv_state *state, const unsigned char key, unsigned char *data, size_t *data_len);

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

#define YKPIV_OBJ_MAX_SIZE 3072

#define YKPIV_INS_VERIFY 0x20
#define YKPIV_INS_CHANGE_REFERENCE 0x24
#define YKPIV_INS_RESET_RETRY 0x2c
#define YKPIV_INS_GENERATE_ASYMMETRIC 0x47
#define YKPIV_INS_AUTHENTICATE 0x87
#define YKPIV_INS_GET_DATA 0xcb
#define YKPIV_INS_PUT_DATA 0xdb
  // TREV TODO: why aren't all of them here?  ex: select app (0xa4)

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

#define YKPIV_RETRIES_DEFAULT 3
#define YKPIV_RETRIES_MAX 0xff

#define YKPIV_CERTINFO_UNCOMPRESSED 0
#define YKPIV_CERTINFO_GZIP 1

//
// UTIL
//

#define YKPIV_ATR_NEO_R3 "\x3b\xfc\x13\x00\x00\x81\x31\xfe\x15\x59\x75\x62\x69\x6b\x65\x79\x4e\x45\x4f\x72\x33\xe1"
#define YKPIV_ATR_YK4    "\x3b\xf8\x13\x00\x00\x81\x31\xfe\x15\x59\x75\x62\x69\x6b\x65\x79\x34\xd4"

#define DEVTYPE_UNKNOWN  0x00000000
#define DEVTYPE_NEO      0x4E450000 //"NE"
#define DEVTYPE_YK       0x594B0000 //"YK"
#define DEVTYPE_NEOr3    (DEVTYPE_NEO | 0x00007233) //"r3"
#define DEVTYPE_YK4      (DEVTYPE_YK  | 0x00000034) // "4"

  typedef uint32_t ykpiv_devmodel;

  /**
   * Card identifier
   */
  #define YKPIV_CARDID_SIZE 16
  typedef struct {
    uint8_t data[YKPIV_CARDID_SIZE];
  } ykpiv_cardid;

  /**
   * Card Capability
   */
  #define YKPIV_CCCID_SIZE 14
  typedef struct {
    uint8_t data[YKPIV_CCCID_SIZE];
  } ykpiv_cccid;

#pragma pack(push, 1)

  typedef struct _ykpiv_key {
    uint8_t slot;
    uint16_t cert_len;
    uint8_t cert[1];
  } ykpiv_key;

  typedef struct _ykpiv_container {
    wchar_t name[40];
    uint8_t slot;
    uint8_t key_spec;
    uint16_t key_size_bits;
    uint8_t flags;
    uint8_t pin_id;
    uint8_t associated_echd_container;
    uint8_t cert_fingerprint[20];
  } ykpiv_container;

#pragma pack(pop)

  /* Util api always allocates data on your behalf, if data = 0, *data != 0, or data_len = 0 an invalid parameter will be returned; to free data, call ykpiv_util_free(). */

  /**
   * Free allocated data
   *
   * @param state state
   * @param data pointer to buffer allocated by ykpiv
   *
   * @return ypiv_rc error code
   */
  ykpiv_rc ykpiv_util_free(ykpiv_state *state, void *data);

  ykpiv_rc ykpiv_util_list_keys(ykpiv_state *state, uint8_t *key_count, ykpiv_key **data, size_t *data_len);
  ykpiv_rc ykpiv_util_read_cert(ykpiv_state *state, uint8_t slot, uint8_t **data, size_t *data_len);
  ykpiv_rc ykpiv_util_write_cert(ykpiv_state *state, uint8_t slot, uint8_t *data, size_t data_len, uint8_t certinfo);
  ykpiv_rc ykpiv_util_delete_cert(ykpiv_state *state, uint8_t slot);

  /**
   * Generate Key
   *
   * @param state state
   * @param slot key slot
   * @param algorithm algorithm
   *
   * @return ykpiv_rc error code
   *
   * If algorithm is RSA1024 or RSA2048, the modulus, modulus_len, exp, and exp_len output parameters must be supplied.  They are filled with with public modulus (big-endian), its size, the public exponent (big-endian), and its size respectively.
   * If algorithm is ECCP256 or ECCP384, the point and point_len output parameters must be supplied.  They are filled with the public point (uncompressed octet-string encoded per SEC1 section 2.3.4)
   * If algorithm is ECCP256, the curve is always ANSI X9.62 Prime 256v1
   * If algorithm is ECCP384, the curve is always secp384r1
   */
  ykpiv_rc ykpiv_util_generate_key(ykpiv_state *state, uint8_t slot, uint8_t algorithm, uint8_t pin_policy, uint8_t touch_policy, uint8_t **modulus, size_t *modulus_len, uint8_t **exp, size_t *exp_len, uint8_t **point, size_t *point_len);

  ykpiv_rc ykpiv_util_read_mscmap(ykpiv_state *state, ykpiv_container **containers, size_t *n_containers);
  ykpiv_rc ykpiv_util_write_mscmap(ykpiv_state *state, ykpiv_container *containers, size_t n_containers);
  ykpiv_rc ykpiv_util_read_msroots(ykpiv_state  *state, uint8_t **data, size_t *data_len);
  ykpiv_rc ykpiv_util_write_msroots(ykpiv_state *state, uint8_t *data, size_t data_len);

  typedef enum {
    YKPIV_CONFIG_MGM_MANUAL = 0,
    YKPIV_CONFIG_MGM_DERIVED = 1,
    YKPIV_CONFIG_MGM_PROTECTED = 2
  } ykpiv_config_mgm_type;

#pragma pack(push, 1)
  typedef struct _ykpiv_config {
    uint8_t               protected_data_available;
    uint8_t               puk_blocked;
    uint8_t               puk_noblock_on_upgrade;
    uint32_t              pin_last_changed;
    ykpiv_config_mgm_type mgm_type;
  } ykpiv_config;

  typedef struct _ykpiv_mgm {
    uint8_t data[24];
  } ykpiv_mgm;
#pragma pack(pop)

    /**
  * Get current PIV applet administration configuration state
  *
  * @param state  [in] state
  * @param config [out] output ykpiv_config struct with current applet data
  *
  * @return ykpiv_rc error code
  */
  ykpiv_rc ykpiv_util_get_config(ykpiv_state *state, ykpiv_config *config);

  /**
   * Set last pin changed time to current time
   *
   * The applet must be authenticated to call this function
   *
   * @param state state
   *
   * @return ykpiv_rc error code
   */
  ykpiv_rc ykpiv_util_set_pin_last_changed(ykpiv_state *state);

  /**
   * Get Derived MGM key
   *
   * @param state   [in] state
   * @param pin     [in] pin used to derive mgm key
   * @param pin_len [in] length of pin
   * @param mgm     [out] protected mgm key
   *
   * @return ykpiv_rc error code
   */
  ykpiv_rc ykpiv_util_get_derived_mgm(ykpiv_state *state, const uint8_t *pin, const size_t pin_len, ykpiv_mgm *mgm);

  /**
   * Get Protected MGM key
   *
   * The user pin must be verified to call this function
   *
   * @param state [in] state
   * @param mgm   [out] returns protected mgm key
   *
   * @return ykpiv_rc error code
   */
  ykpiv_rc ykpiv_util_get_protected_mgm(ykpiv_state *state, ykpiv_mgm *mgm);

  /**
   * Set Protected MGM key
   *
   * The applet must be authenticated and the user pin verified to call this function
   *
   * @param state state
   * @param mgm   [in] if mgm is NULL or mgm.data is all zeroes, generate mgm, otherwise set specified key; [out] returns generated mgm key
   *
   * @return ykpiv_rc error code
   */
  ykpiv_rc ykpiv_util_set_protected_mgm(ykpiv_state *state, ykpiv_mgm *mgm);

  /**
  * Reset PIV applet
  *
  * The user pin and puk must be blocked to call this function.
  *
  * @param state state
  *
  * @return ykpiv_rc error code
  */
  ykpiv_rc ykpiv_util_reset(ykpiv_state *state);

  /**
   * Get card identifier
   *
   * @param state state
   * @param cardid ykpiv_cardid return value
   *
   * @return ykpiv_rc error code
   */
  ykpiv_rc ykpiv_util_get_cardid(ykpiv_state *state, ykpiv_cardid *cardid);

  /**
   * Set card identifier
   *
   * The card must be authenticated to call this function.
   *
   * @param state state
   * @param cardid cardid to set, if NULL, randomly generate
   *
   * @return ypiv_rc error code
   *
   */
  ykpiv_rc ykpiv_util_set_cardid(ykpiv_state *state, const ykpiv_cardid *cardid);

  /**
   * Get card capabilities identifier
   *
   * @param state state
   * @param cardid ykpiv_cardid return value
   *
   * @return ykpiv_rc error code
   */
  ykpiv_rc ykpiv_util_get_cccid(ykpiv_state *state, ykpiv_cccid *ccc);

  /**
   * Set card capabilities identifier
   *
   * The card must be authenticated to call this function.
   *
   * @param state state
   * @param ccc card ID to set. if NULL, randomly generate
   *
   * @return ypiv_rc error code
   *
   */
  ykpiv_rc ykpiv_util_set_cccid(ykpiv_state *state, const ykpiv_cccid *ccc);

  /**
   * Get device model
   *
   * The card must be connected to call this function.
   *
   * @param state state
   *
   * @return device model
   *
   */
  ykpiv_devmodel ykpiv_util_devicemodel(ykpiv_state *state);

  /**
   * Block PUK
   *
   * Utility function to block the PUK.
   *
   * To set the PUK blocked flag in the admin data, the applet must be authenticated.
   */
  ykpiv_rc ykpiv_util_block_puk(ykpiv_state *state);

  /**
   * Object ID of given slot.
   *
   * @param slot key slot
   */
  uint32_t ykpiv_util_slot_object(uint8_t slot);

  ykpiv_rc ykpiv_connect_with_exteral_card(ykpiv_state *state, uint64_t context, uint64_t card, bool select);
  ykpiv_rc ykpiv_done_with_external_card(ykpiv_state *state);
  ykpiv_rc ykpiv_verify_select(ykpiv_state *state, const char *pin, const size_t pin_len, int *tries, bool force_select);

#ifdef __cplusplus
}
#endif

#endif
