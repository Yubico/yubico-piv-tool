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

/**
 * @mainpage
 *
 * See ykpiv.h
 *
 * @file ykpiv.h
 * libykpiv API
 */
#ifndef YKPIV_H
#define YKPIV_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include "ykpiv-config.h"

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
    YKPIV_RANGE_ERROR = -15, //i.e. value range error
    YKPIV_NOT_SUPPORTED = -16,
    YKPIV_PCSC_SERVICE_ERROR = -17,
    YKPIV_CONDITION_ERROR = -18,
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
  ykpiv_rc ykpiv_validate(ykpiv_state *state, const char *wanted);
  ykpiv_rc ykpiv_connect(ykpiv_state *state, const char *wanted);
  ykpiv_rc ykpiv_connect_ex(ykpiv_state *state, const char *wanted, bool scp11);
  ykpiv_rc ykpiv_list_readers(ykpiv_state *state, char *readers, size_t *len);
  ykpiv_rc ykpiv_disconnect(ykpiv_state *state);
  ykpiv_rc ykpiv_translate_sw(int sw);
  ykpiv_rc ykpiv_translate_sw_ex(const char *whence, int sw);
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
  ykpiv_rc ykpiv_decipher_data(ykpiv_state *state, const unsigned char *enc_in,
                               size_t in_len, unsigned char *enc_out, size_t *out_len,
                               unsigned char algorithm, unsigned char key);
  ykpiv_rc ykpiv_get_version(ykpiv_state *state, char *version, size_t len);
  ykpiv_rc ykpiv_verify(ykpiv_state *state, const char *pin, int *tries);
  ykpiv_rc ykpiv_verify_bio(ykpiv_state *state, uint8_t* spin, size_t* spin_len, int *tries, bool verify_spin);
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
  ykpiv_rc ykpiv_authenticate2(ykpiv_state *state, unsigned const char *key, size_t len);
  ykpiv_rc ykpiv_set_mgmkey2(ykpiv_state *state, const unsigned char *new_key,
                             const unsigned char touch);
  ykpiv_rc ykpiv_set_mgmkey3(ykpiv_state *state, const unsigned char *new_key, size_t len, unsigned char algorithm,
                             unsigned char touch);
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
  ykpiv_rc ykpiv_attest(ykpiv_state *state, const unsigned char key, unsigned char *data, size_t *data_len);
  ykpiv_rc ykpiv_get_metadata(ykpiv_state *state, const unsigned char key, unsigned char *data, size_t *data_len);

  bool is_version_compatible(ykpiv_state *state, uint8_t major, uint8_t minor, uint8_t patch);
  ykpiv_rc ykpiv_move_key(ykpiv_state *state, const unsigned char from_slot, const unsigned char to_slot);
  ykpiv_rc ykpiv_global_reset(ykpiv_state *state);

  /**
   * Return the number of PIN attempts remaining before PIN is locked.
   *
   * **NOTE:** If PIN is already verified, calling ykpiv_get_pin_retries() will unverify the PIN.
   *
   * @param state State handle from ykpiv_init()
   * @param tries [out] Number of attempts remaining
   *
   * @return Error code
   */
  ykpiv_rc ykpiv_get_pin_retries(ykpiv_state *state, int *tries);

  /**
   * Set number of attempts before locking for PIN and PUK codes.
   *
   * **NOTE:** If either \p pin_tries or \p puk_tries is 0, ykpiv_set_pin_retries() immediately returns YKPIV_OK.
   *
   * @param state State handle from ykpiv_init()
   * @param pin_tries Number of attempts to permit for PIN code
   * @param puk_tries Number of attempts to permit for PUK code
   *
   * @return Error code
   */
  ykpiv_rc ykpiv_set_pin_retries(ykpiv_state *state, int pin_tries, int puk_tries);

  /**
   * Variant of ykpiv_connect() that accepts a card context obtained externally.
   *
   * Not for generic use.  Use ykpiv_connect() instead.
   *
   * @param state State handle
   * @param context Card context returned from SCardConnect() or equivalent.
   * @param card Card ID returned from SCardConnect() or equivalent.
   *
   * @return Error code
   */
  ykpiv_rc ykpiv_connect_with_external_card(ykpiv_state *state, uintptr_t context, uintptr_t card);

  /**
   * Variant of ykpiv_done() for external cards connected with ykpiv_connect_with_external_card()
   *
   * Card is not disconnected, unlike with normal calls to ykpiv_done().
   *
   * @param state State handle
   *
   * @return Error code
   */
  ykpiv_rc ykpiv_done_with_external_card(ykpiv_state *state);

  /**
   * Variant of ykpiv_verify() that optionally selects the PIV applet first.
   *
   * @param state State handle
   * @param pin PIN code to verify with
   * @param pin_len Length of \p pin
   * @param tries [out] Number of attempts remaining (if non-NULL)
   * @param bio if true verify using fingerprint
   * @param tpin if true set temporary pin, otherwise verify with temp pin
   * @param force_select Whether to select the PIV applet before verifying.
   *
   * @return Error code
   */
  ykpiv_rc ykpiv_verify_select(ykpiv_state *state, const char *pin, const size_t pin_len, int *tries, bool force_select);

  /**
   * Get serial number
   *
   * The card must be connected to call this function.
   *
   * @param state [in] State handle
   * @param p_serial [out] uint32 to store retrieved serial number
   *
   * @return ykpiv_rc error code
   *
   */
  ykpiv_rc ykpiv_get_serial(ykpiv_state *state, uint32_t* p_serial);

////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
////
////
//// High-level Util API
////
////
//// Util api always allocates data on your behalf, if data = 0, *data != 0,
//// or data_len = 0 an invalid parameter will be returned; to free data, call
//// ykpiv_util_free().
////
////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

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

  typedef enum {
    YKPIV_CONFIG_MGM_INVALID = -1,
    YKPIV_CONFIG_MGM_MANUAL = 0,
    YKPIV_CONFIG_MGM_DERIVED = 1,
    YKPIV_CONFIG_MGM_PROTECTED = 2
  } ykpiv_config_mgm_type;

#pragma pack(push, 1)
  typedef struct _ykpiv_config {
    uint8_t               puk_blocked;
    uint8_t               puk_noblock_on_upgrade;
    uint32_t              pin_last_changed;
    ykpiv_config_mgm_type mgm_type;
    size_t                mgm_len;
    uint8_t               mgm_key[32];
  } ykpiv_config;

  typedef struct _ykpiv_mgm {
    size_t len;
    uint8_t data[32];
  } ykpiv_mgm;
#pragma pack(pop)

  typedef struct _ykpiv_metadata {
    uint8_t algorithm;
    uint8_t pin_policy;
    uint8_t touch_policy;
    uint8_t origin;
    size_t pubkey_len;
    uint8_t pubkey[1024];
  } ykpiv_metadata;

  /**
   * Free allocated data
   *
   * Frees a buffer previously allocated by one of the other \p ykpiv_util functions.
   *
   * @param state State handle
   * @param data Buffer previously allocated by a \p ykpiv_util function
   *
   * @return ypiv_rc error code
   */
  ykpiv_rc ykpiv_util_free(ykpiv_state *state, void *data);

  /**
   * Returns a list of all saved certificates.
   *
   * \p data should be freed with \p ykpiv_util_free() after use.
   *
   * @param state State handle
   * @param key_count [out] Number of certificates returned
   * @param data      [out] Set to a dynamically allocated list of certificates.
   * @param data_len  [out] Set to size of \p data in bytes
   *
   * @return Error code
   */
  ykpiv_rc ykpiv_util_list_keys(ykpiv_state *state, uint8_t *key_count, ykpiv_key **data, size_t *data_len);

  /**
   * Read a certificate stored in the given slot
   *
   * \p data should be freed with \p ykpiv_util_free() after use.
   *
   * @param state State handle
   * @param slot Slot to read from
   * @param data Pointer to buffer to store the read data
   * @param data_len Pointer to size of input buffer, in bytes.  Update to length of read data after call.
   *
   * @return Error code
   */
  ykpiv_rc ykpiv_util_read_cert(ykpiv_state *state, uint8_t slot, uint8_t **data, size_t *data_len);

  /**
   * Decompresses a certificate if it was compressed
   *
   * @param buf Fetched certificate data
   * @param buf_len Length of fetched certificate data
   * @param certdata Raw certificate bytes
   * @param certdata_len Length of raw certificate bytes
   *
   * @return Error code
   */
  ykpiv_rc ykpiv_util_get_certdata(uint8_t *buf, size_t buf_len, uint8_t* certdata, size_t *certdata_len);

  /**
   * Construct cert data to store
   *
   * @param data Raw certificate data
   * @param data_len Length of raw certificate data
   * @param compress_info Certificate compression state
   * @param certdata Constructed certificate data
   * @param certdata_len Length of constructed certificate data
   *
   * @return Error code
   */
  ykpiv_rc ykpiv_util_write_certdata(uint8_t *data, size_t data_len, uint8_t compress_info, uint8_t* certdata, size_t *certdata_len);

  /**
   * Write a certificate to a given slot
   *
   * \p certinfo should be \p YKPIV_CERTINFO_UNCOMPRESSED for uncompressed certificates, which is the most
   * common case, or \p YKPIV_CERTINFO_GZIP if the certificate in \p data is already compressed with gzip.
   *
   * @param state State handle
   * @param slot Slot to write to
   * @param data Buffer of data to write
   * @param data_len Number of bytes to write
   * @param certinfo Hint about type of certificate.  Use the \p YKPIV_CERTINFO* defines.
   *
   * @return Error code
   */
  ykpiv_rc ykpiv_util_write_cert(ykpiv_state *state, uint8_t slot, uint8_t *data, size_t data_len, uint8_t certinfo);

  /**
   * Delete the certificate stored in the given slot
   *
   * @param state State handle
   * @param slot Slot to delete certificate from
   *
   * @return Error code
   */
  ykpiv_rc ykpiv_util_delete_cert(ykpiv_state *state, uint8_t slot);

  /**
   * Generate key in given slot with specified parameters
   *
   * \p modulus, \p exp, and \p point should be freed with \p ykpiv_util_free() after use.
   *
   * If algorithm is RSA1024 or RSA2048, the modulus, modulus_len, exp, and exp_len output parameters must be supplied.  They are filled with with public modulus (big-endian), its size, the public exponent (big-endian), and its size respectively.
   *
   * If algorithm is ECCP256 or ECCP384, the point and point_len output parameters must be supplied.  They are filled with the public point (uncompressed octet-string encoded per SEC1 section 2.3.4)
   *
   * If algorithm is ECCP256, the curve is always ANSI X9.62 Prime 256v1
   *
   * If algorithm is ECCP384, the curve is always secp384r1
   *
   * @param state        State handle
   * @param slot         Slot to generate key in
   * @param algorithm    Key algorithm, specified as one of the \p YKPIV_ALGO_* options
   * @param pin_policy   Per-slot PIN policy, specified as one of the \p YKPIV_PINPOLICY_* options
   * @param touch_policy Per-slot touch policy, specified as one of the \p YKPIV_TOUCHPOLICY_* options.
   * @param modulus      [out] RSA public modulus (RSA-only)
   * @param modulus_len  [out] Size of \p modulus (RSA-only)
   * @param exp          [out] RSA public exponent (RSA-only)
   * @param exp_len      [out] Size of \p exp (RSA-only)
   * @param point        [out] Public curve point (ECC-only)
   * @param point_len    [out] Size of \p point (ECC-only)
   *
   * @return ykpiv_rc error code
   */
  ykpiv_rc ykpiv_util_generate_key(ykpiv_state *state, uint8_t slot, uint8_t algorithm, uint8_t pin_policy, uint8_t touch_policy, uint8_t **modulus, size_t *modulus_len, uint8_t **exp, size_t *exp_len, uint8_t **point, size_t *point_len);

  /**
   * Get current PIV applet administration configuration state
   *
   * @param state  State handle
   * @param config [out] ykpiv_config struct filled with current applet data
   *
   * @return ykpiv_rc error code
   */
  ykpiv_rc ykpiv_util_get_config(ykpiv_state *state, ykpiv_config *config);

  /**
   * Set last pin changed time to current time
   *
   * The applet must be authenticated to call this function
   *
   * @param state State handle
   *
   * @return ykpiv_rc error code
   */
  ykpiv_rc ykpiv_util_set_pin_last_changed(ykpiv_state *state);

  /**
   * Get Derived MGM key
   *
   * @param state   State handle
   * @param pin     PIN used to derive mgm key
   * @param pin_len Length of pin in bytes
   * @param mgm     [out] Protected MGM key
   *
   * @return ykpiv_rc error code
   */
  ykpiv_rc ykpiv_util_get_derived_mgm(ykpiv_state *state, const uint8_t *pin, const size_t pin_len, ykpiv_mgm *mgm);

  /**
   * Get Protected MGM key
   *
   * The user pin must be verified to call this function
   *
   * @param state State handle
   * @param mgm   [out] Protected MGM key
   *
   * @return ykpiv_rc error code
   */
  ykpiv_rc ykpiv_util_get_protected_mgm(ykpiv_state *state, ykpiv_mgm *mgm);

  /**
   * Update Protected MGM key. Should only be used when mgm_type is YKPIV_CONFIG_MGM_PROTECTED.
   *
   * The user pin must be verified to call this function
   *
   * @param state State handle
   * @param mgm   [in] Protected MGM key
   *
   * @return ykpiv_rc error code
   */
  ykpiv_rc ykpiv_util_update_protected_mgm(ykpiv_state *state, ykpiv_mgm *mgm);

  /**
   * Set Protected MGM key
   *
   * The applet must be authenticated and the user pin verified to call this function
   *
   * If \p mgm is NULL or \p mgm.data is all zeroes, generate MGM, otherwise set specified key.
   *
   * @param state State handle
   * @param mgm   [in, out] Input: NULL or new MGM key.  Output: Generated MGM key
   *
   * @return ykpiv_rc error code
   */
  ykpiv_rc ykpiv_util_set_protected_mgm(ykpiv_state *state, ykpiv_mgm *mgm);

  /**
   * Reset PIV applet
   *
   * The user PIN and PUK must be blocked to call this function.
   *
   * @param state State handle
   *
   * @return ykpiv_rc error code
   */
  ykpiv_rc ykpiv_util_reset(ykpiv_state *state);

  /**
   * Get card identifier
   *
   * Gets the card identifier from the Cardholder Unique Identifier (CHUID).
   *
   * ID can be set with \p ykpiv_util_set_cardid().
   *
   * @param state State handle
   * @param cardid [out] Unique Card ID stored in the CHUID
   *
   * @return ykpiv_rc error code
   */
  ykpiv_rc ykpiv_util_get_cardid(ykpiv_state *state, ykpiv_cardid *cardid);

  /**
   * Set card identifier
   *
   * Set the card identifier in the Cardholder Unique Identifier (CHUID).
   *
   * The card must be authenticated to call this function.
   *
   * See also: \p ykpiv_util_set_cccid()
   *
   * @param state State handle
   * @param cardid Unique Card ID to set. If NULL, randomly generate.
   *
   * @return ypiv_rc error code
   *
   */
  ykpiv_rc ykpiv_util_set_cardid(ykpiv_state *state, const ykpiv_cardid *cardid);

  /**
   * Get card capabilities identifier
   *
   * Gets the card identifier from the Card Capability Container (CCC).
   *
   * ID can be set with \p ykpiv_util_set_cccid().
   *
   * @param state State handle
   * @param ccc [out] Unique Card ID stored in the CCC
   *
   * @return ykpiv_rc error code
   */
  ykpiv_rc ykpiv_util_get_cccid(ykpiv_state *state, ykpiv_cccid *ccc);

  /**
   * Set card capabilities identifier
   *
   * Sets the card identifier in the Card Capability Container (CCC).
   *
   * The card must be authenticated to call this function.
   *
   * See also: \p ykpiv_util_set_cardid()
   *
   * @param state state
   * @param ccc Unique Card ID to set. If NULL, randomly generate.
   *
   * @return ykpiv_rc error code
   *
   */
  ykpiv_rc ykpiv_util_set_cccid(ykpiv_state *state, const ykpiv_cccid *ccc);

  /**
   * Get device model
   *
   * The card must be connected to call this function.
   *
   * @param state State handle
   *
   * @return Device model
   *
   */
  ykpiv_devmodel ykpiv_util_devicemodel(ykpiv_state *state);

  /**
   * Block PUK
   *
   * Utility function to block the PUK.
   *
   * To set the PUK blocked flag in the admin data, the applet must be authenticated.
   *
   * @param state State handle
   *
   * @return Error code
   *
   */
  ykpiv_rc ykpiv_util_block_puk(ykpiv_state *state);

  /**
   * Object ID of given slot.
   *
   * @param slot Key slot
   */
  uint32_t ykpiv_util_slot_object(uint8_t slot);

  ykpiv_rc ykpiv_util_read_mscmap(ykpiv_state *state, ykpiv_container **containers, size_t *n_containers);
  ykpiv_rc ykpiv_util_write_mscmap(ykpiv_state *state, ykpiv_container *containers, size_t n_containers);
  ykpiv_rc ykpiv_util_read_msroots(ykpiv_state  *state, uint8_t **data, size_t *data_len);
  ykpiv_rc ykpiv_util_write_msroots(ykpiv_state *state, uint8_t *data, size_t data_len);
  ykpiv_rc ykpiv_util_parse_metadata(uint8_t *data, size_t data_len, ykpiv_metadata *metadata);

////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
////
////
//// Defines
////
////
////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

#define YKPIV_ALGO_TAG 0x80
#define YKPIV_ALGO_3DES 0x03
#define YKPIV_ALGO_AES128 0x08
#define YKPIV_ALGO_AES192 0x0a
#define YKPIV_ALGO_AES256 0x0c
#define YKPIV_ALGO_RSA1024 0x06
#define YKPIV_ALGO_RSA2048 0x07
#define YKPIV_ALGO_RSA3072 0x05
#define YKPIV_ALGO_RSA4096 0x16
#define YKPIV_ALGO_ECCP256 0x11
#define YKPIV_ALGO_ECCP384 0x14
#define YKPIV_ALGO_ED25519 0xE0
#define YKPIV_ALGO_X25519 0xE1

#define YKPIV_ALGO_AUTO 0xff

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
#define YKPIV_OBJ_BITGT 0x7f61
#define YKPIV_OBJ_SM_SIGNER 0x5fc122
#define YKPIV_OBJ_PC_REF_DATA 0x5fc123

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

#define TAG_CERT              0x70
#define TAG_CERT_COMPRESS     0x71
#define TAG_CERT_LRC          0xFE

#define YKPIV_OBJ_MAX_SIZE 3072

#define YKPIV_INS_VERIFY 0x20
#define YKPIV_INS_CHANGE_REFERENCE 0x24
#define YKPIV_INS_RESET_RETRY 0x2c
#define YKPIV_INS_GENERATE_ASYMMETRIC 0x47
#define YKPIV_INS_AUTHENTICATE 0x87
#define YKPIV_INS_GET_DATA 0xcb
#define YKPIV_INS_PUT_DATA 0xdb
#define YKPIV_INS_MOVE_KEY 0xf6
#define YKPIV_INS_SELECT_APPLICATION 0xa4
#define YKPIV_INS_GET_RESPONSE_APDU 0xc0

#define GP_INS_GET_DATA              0xca
#define GP_INS_INTERNAL_AUTHENTICATE 0x88

/* sw is status words, see NIST special publication 800-73-4, section 5.6 */
#define SW_SUCCESS 0x9000
#define SW_ERR_SECURITY_STATUS 0x6982
#define SW_ERR_AUTH_BLOCKED 0x6983
#define SW_ERR_CONDITIONS_OF_USE 0x6985 // CONDITIONS_NOT_SATISFIED
#define SW_ERR_INCORRECT_PARAM 0x6a80
#define SW_ERR_FILE_NOT_FOUND 0x6a82
#define SW_ERR_REFERENCE_NOT_FOUND 0x6a88
/* this is a custom sw for yubikey */
#define SW_ERR_INCORRECT_SLOT 0x6b00 // WRONG_PARAMETERS_P1P2
#define SW_ERR_NOT_SUPPORTED 0x6d00 // INVALID_INSTRUCTION

#define SW_ERR_NO_INPUT_DATA 0x6285
#define SW_ERR_VERIFY_FAIL_NO_RETRY 0x63C0
#define SW_ERR_MEMORY_ERROR 0x6581
#define SW_ERR_WRONG_LENGTH 0x6700
#define SW_ERR_DATA_INVALID 0x6984
#define SW_ERR_COMMAND_NOT_ALLOWED 0x6986
#define SW_ERR_NO_SPACE 0x6A84
#define SW_ERR_CLASS_NOT_SUPPORTED 0x6E00
#define SW_ERR_COMMAND_ABORTED 0x6F00

/* Yubico vendor specific instructions */
#define YKPIV_INS_SET_MGMKEY 0xff
#define YKPIV_INS_IMPORT_KEY 0xfe
#define YKPIV_INS_GET_VERSION 0xfd
#define YKPIV_INS_RESET 0xfb
#define YKPIV_INS_SET_PIN_RETRIES 0xfa
#define YKPIV_INS_ATTEST 0xf9
#define YKPIV_INS_GET_SERIAL 0xf8
#define YKPIV_INS_GET_METADATA 0xf7

#define MGM_INS_GLOBAL_RESET 0x1f

#define YKPIV_PINPOLICY_TAG 0xaa
#define YKPIV_PINPOLICY_DEFAULT 0
#define YKPIV_PINPOLICY_NEVER 1
#define YKPIV_PINPOLICY_ONCE 2
#define YKPIV_PINPOLICY_ALWAYS 3
#define YKPIV_PINPOLICY_MATCH_ONCE 4
#define YKPIV_PINPOLICY_MATCH_ALWAYS 5

#define YKPIV_TOUCHPOLICY_TAG 0xab
#define YKPIV_TOUCHPOLICY_DEFAULT 0
#define YKPIV_TOUCHPOLICY_NEVER 1
#define YKPIV_TOUCHPOLICY_ALWAYS 2
#define YKPIV_TOUCHPOLICY_CACHED 3

#define YKPIV_TOUCHPOLICY_AUTO 255

#define YKPIV_METADATA_ALGORITHM_TAG 0x01 // See values for YKPIV_ALGO_TAG

#define YKPIV_METADATA_POLICY_TAG 0x02 // Two bytes, see values for YKPIV_PINPOLICY_TAG and YKPIV_TOUCHPOLICY_TAG

#define YKPIV_METADATA_ORIGIN_TAG 0x03
#define YKPIV_METADATA_ORIGIN_GENERATED 0x01
#define YKPIV_METADATA_ORIGIN_IMPORTED 0x02

#define YKPIV_METADATA_PUBKEY_TAG 0x04 // RSA: DER-encoded sequence N, E; EC: Uncompressed EC point X, Y

#define YKPIV_IS_EC(a) ((a == YKPIV_ALGO_ECCP256 || a == YKPIV_ALGO_ECCP384))
#define YKPIV_IS_RSA(a) ((a == YKPIV_ALGO_RSA1024 || a == YKPIV_ALGO_RSA2048 || a == YKPIV_ALGO_RSA3072 || a == YKPIV_ALGO_RSA4096))
#define YKPIV_IS_25519(a) ((a == YKPIV_ALGO_ED25519 || a == YKPIV_ALGO_X25519))

#define YKPIV_MIN_PIN_LEN 6
#define YKPIV_MAX_PIN_LEN 8
#define YKPIV_MIN_MGM_KEY_LEN 32
#define YKPIV_MAX_MGM_KEY_LEN 64

#define YKPIV_RETRIES_DEFAULT 3
#define YKPIV_RETRIES_MAX 0xff

#define YKPIV_CERTINFO_UNCOMPRESSED 0
#define YKPIV_CERTINFO_GZIP 1

#define YKPIV_OID_FIRMWARE_VERSION "1.3.6.1.4.1.41482.3.3"
#define YKPIV_OID_SERIAL_NUMBER "1.3.6.1.4.1.41482.3.7"
#define YKPIV_OID_USAGE_POLICY "1.3.6.1.4.1.41482.3.8"
#define YKPIV_OID_FORM_FACTOR "1.3.6.1.4.1.41482.3.9"

#define YKPIV_ATR_NEO_R3 "\x3b\xfc\x13\x00\x00\x81\x31\xfe\x15\x59\x75\x62\x69\x6b\x65\x79\x4e\x45\x4f\x72\x33\xe1"
#define YKPIV_ATR_NEO_R3_NFC "\x3b\x8c\x80\x01\x59\x75\x62\x69\x6b\x65\x79\x4e\x45\x4f\x72\x33\x58"
#define YKPIV_ATR_YK4    "\x3b\xf8\x13\x00\x00\x81\x31\xfe\x15\x59\x75\x62\x69\x6b\x65\x79\x34\xd4"
#define YKPIV_ATR_YK5_P1 "\x3b\xf8\x13\x00\x00\x81\x31\xfe\x15\x01\x59\x75\x62\x69\x4b\x65\x79\xc1"
#define YKPIV_ATR_YK5    "\x3b\xfd\x13\x00\x00\x81\x31\xfe\x15\x80\x73\xc0\x21\xc0\x57\x59\x75\x62\x69\x4b\x65\x79\x40"
#define YKPIV_ATR_YK5_NFC "\x3b\x8d\x80\x01\x80\x73\xc0\x21\xc0\x57\x59\x75\x62\x69\x4b\x65\x79\xf9"

#define DEVTYPE_UNKNOWN  0x00000000
#define DEVTYPE_NEO      0x4E450000 //"NE"
#define DEVTYPE_YK       0x594B0000 //"YK"
#define DEVTYPE_NEOr3    (DEVTYPE_NEO | 0x00007233) //"r3"
#define DEVTYPE_YK4      (DEVTYPE_YK  | 0x00000034) // "4"
#define DEVTYPE_YK5      (DEVTYPE_YK  | 0x00000035) // "5"
#define DEVYTPE_YK5      DEVTYPE_YK5 // Keep old typo for backwards compatibility

#ifdef __cplusplus
}
#endif

#endif
