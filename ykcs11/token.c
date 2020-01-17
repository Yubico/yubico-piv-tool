/*
 * Copyright (c) 2015-2016 Yubico AB
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
#include "utils.h"
#include "token.h"
#include "debug.h"
#include "objects.h"
#include "openssl_utils.h"

#include <stdbool.h>
#include "../tool/util.h"

#define MIN_RSA_KEY_SIZE 1024
#define MAX_RSA_KEY_SIZE 2048
#define MIN_ECC_KEY_SIZE 256
#define MAX_ECC_KEY_SIZE 384

static const char *token_model = "YubiKey XXX";

static const token_mechanism token_mechanisms[] = {
  CKM_RSA_PKCS_KEY_PAIR_GEN, {MIN_RSA_KEY_SIZE, MAX_RSA_KEY_SIZE, CKF_HW | CKF_GENERATE_KEY_PAIR},
  CKM_RSA_PKCS, {MIN_RSA_KEY_SIZE, MAX_RSA_KEY_SIZE, CKF_HW | CKF_ENCRYPT | CKF_DECRYPT | CKF_SIGN | CKF_VERIFY},
  CKM_RSA_PKCS_PSS, {MIN_RSA_KEY_SIZE, MAX_RSA_KEY_SIZE, CKF_HW | CKF_SIGN | CKF_VERIFY},
  CKM_RSA_PKCS_OAEP, {MIN_RSA_KEY_SIZE, MAX_RSA_KEY_SIZE, CKF_HW | CKF_ENCRYPT | CKF_DECRYPT},
  CKM_RSA_X_509, {MIN_RSA_KEY_SIZE, MAX_RSA_KEY_SIZE, CKF_HW | CKF_ENCRYPT | CKF_DECRYPT | CKF_SIGN | CKF_VERIFY},
  CKM_SHA1_RSA_PKCS, {MIN_RSA_KEY_SIZE, MAX_RSA_KEY_SIZE, CKF_HW | CKF_SIGN | CKF_VERIFY},
  CKM_SHA256_RSA_PKCS, {MIN_RSA_KEY_SIZE, MAX_RSA_KEY_SIZE, CKF_HW | CKF_SIGN | CKF_VERIFY},
  CKM_SHA384_RSA_PKCS, {MIN_RSA_KEY_SIZE, MAX_RSA_KEY_SIZE, CKF_HW | CKF_SIGN | CKF_VERIFY},
  CKM_SHA512_RSA_PKCS, {MIN_RSA_KEY_SIZE, MAX_RSA_KEY_SIZE, CKF_HW | CKF_SIGN | CKF_VERIFY},
  CKM_SHA1_RSA_PKCS_PSS, {MIN_RSA_KEY_SIZE, MAX_RSA_KEY_SIZE, CKF_HW | CKF_SIGN | CKF_VERIFY},
  CKM_SHA256_RSA_PKCS_PSS, {MIN_RSA_KEY_SIZE, MAX_RSA_KEY_SIZE, CKF_HW | CKF_SIGN | CKF_VERIFY},
  CKM_SHA384_RSA_PKCS_PSS, {MIN_RSA_KEY_SIZE, MAX_RSA_KEY_SIZE, CKF_HW | CKF_SIGN | CKF_VERIFY},
  CKM_SHA512_RSA_PKCS_PSS, {MIN_RSA_KEY_SIZE, MAX_RSA_KEY_SIZE, CKF_HW | CKF_SIGN | CKF_VERIFY},
  CKM_EC_KEY_PAIR_GEN, {MIN_ECC_KEY_SIZE, MAX_ECC_KEY_SIZE, CKF_HW | CKF_GENERATE_KEY_PAIR},
  //CKM_ECDSA_KEY_PAIR_GEN, {MIN_ECC_KEY_SIZE, MAX_ECC_KEY_SIZE, CKF_HW | CKF_GENERATE_KEY_PAIR}, //Same as CKM_EC_KEY_PAIR_GEN, deprecated in 2.11
  CKM_ECDSA, {MIN_ECC_KEY_SIZE, MAX_ECC_KEY_SIZE, CKF_HW | CKF_SIGN | CKF_VERIFY},
  CKM_ECDSA_SHA1, {MIN_ECC_KEY_SIZE, MAX_ECC_KEY_SIZE, CKF_HW | CKF_SIGN | CKF_VERIFY},
  CKM_ECDSA_SHA256, {MIN_ECC_KEY_SIZE, MAX_ECC_KEY_SIZE, CKF_HW | CKF_SIGN | CKF_VERIFY},
  CKM_ECDSA_SHA384, {MIN_ECC_KEY_SIZE, MAX_ECC_KEY_SIZE, CKF_HW | CKF_SIGN | CKF_VERIFY},
  CKM_SHA_1, {0, 0, CKF_DIGEST},
  CKM_SHA256, {0, 0, CKF_DIGEST},
  CKM_SHA384, {0, 0, CKF_DIGEST},
  CKM_SHA512, {0, 0, CKF_DIGEST}
};

static const piv_obj_id_t token_objects[] = { // TODO: is there a way to get this from the token?
    PIV_DATA_OBJ_X509_PIV_AUTH,   // PIV authentication
    PIV_DATA_OBJ_X509_DS,         // digital signature
    PIV_DATA_OBJ_X509_KM,         // key management
    PIV_DATA_OBJ_X509_CARD_AUTH,  // card authentication
    PIV_DATA_OBJ_X509_RETIRED1,   // Retired key 1
    PIV_DATA_OBJ_X509_RETIRED2,   // Retired key 2
    PIV_DATA_OBJ_X509_RETIRED3,   // Retired key 3
    PIV_DATA_OBJ_X509_RETIRED4,   // Retired key 4
    PIV_DATA_OBJ_X509_RETIRED5,   // Retired key 5
    PIV_DATA_OBJ_X509_RETIRED6,   // Retired key 6
    PIV_DATA_OBJ_X509_RETIRED7,   // Retired key 7
    PIV_DATA_OBJ_X509_RETIRED8,   // Retired key 8
    PIV_DATA_OBJ_X509_RETIRED9,   // Retired key 9
    PIV_DATA_OBJ_X509_RETIRED10,  // Retired key 10
    PIV_DATA_OBJ_X509_RETIRED11,  // Retired key 11
    PIV_DATA_OBJ_X509_RETIRED12,  // Retired key 12
    PIV_DATA_OBJ_X509_RETIRED13,  // Retired key 13
    PIV_DATA_OBJ_X509_RETIRED14,  // Retired key 14
    PIV_DATA_OBJ_X509_RETIRED15,  // Retired key 15
    PIV_DATA_OBJ_X509_RETIRED16,  // Retired key 16
    PIV_DATA_OBJ_X509_RETIRED17,  // Retired key 17
    PIV_DATA_OBJ_X509_RETIRED18,  // Retired key 18
    PIV_DATA_OBJ_X509_RETIRED19,  // Retired key 19
    PIV_DATA_OBJ_X509_RETIRED20,  // Retired key 20
    PIV_DATA_OBJ_X509_ATTESTATION,// Attestation key
    PIV_DATA_OBJ_CCC,             // Card capability container
    PIV_DATA_OBJ_CHUI,            // Cardholder unique id
    PIV_DATA_OBJ_CHF,             // Cardholder fingerprints
    PIV_DATA_OBJ_SEC_OBJ,         // Security object
    PIV_DATA_OBJ_CHFI,            // Cardholder facial images
    PIV_DATA_OBJ_PI,              // Cardholder printed information
    PIV_DATA_OBJ_DISCOVERY,       // Discovery object
    PIV_DATA_OBJ_HISTORY,         // History object
    PIV_DATA_OBJ_IRIS_IMAGE,      // Cardholder iris images
    //PIV_DATA_OBJ_BITGT,         // Biometric information templates group template
    //PIV_DATA_OBJ_SM_SIGNER,     // Secure messaging signer
    //PIV_DATA_OBJ_PC_REF_DATA,   // Pairing code reference data
};

CK_RV get_token_model(ykpiv_state *state, CK_UTF8CHAR_PTR str, CK_ULONG len) {

  if (strlen(token_model) > len)
    return CKR_BUFFER_TOO_SMALL;

  ykpiv_devmodel model = ykpiv_util_devicemodel(state);

  memset(str, ' ', len);
  uint8_t *ptr = str + memstrcpy(str, token_model) - 3;

  switch(model) {
    case DEVTYPE_NEO:
      memstrcpy(ptr, "NEO");
      break;
    case DEVTYPE_YK4:
      memstrcpy(ptr, "YK4");
      break;
    case DEVTYPE_YK5:
      memstrcpy(ptr, "YK5");
      break;
  }

  return CKR_OK;
}

CK_RV get_token_version(ykpiv_state *state, CK_VERSION_PTR version) {

  char buf[16];

  if (version == NULL)
    return CKR_ARGUMENTS_BAD;

  if (ykpiv_get_version(state, buf, sizeof(buf)) != YKPIV_OK) {
    version->major = 0;
    version->minor = 0;
    return CKR_FUNCTION_FAILED;
  }

  version->major = (buf[0] - '0');
  version->minor = (buf[2] - '0') * 10 + (buf[4] - '0');

  return CKR_OK;
}

CK_RV get_token_serial(ykpiv_state *state, CK_CHAR_PTR str, CK_ULONG len) {

  uint32_t serial;
  char buf[64];
  int actual;

  CK_RV rv = ykpiv_get_serial(state, &serial);

  actual = snprintf(buf, sizeof(buf), "%u", serial);

  if(actual < 0)
    return CKR_FUNCTION_FAILED;

  if(actual >= len)
    return CKR_BUFFER_TOO_SMALL;

  memset(str, ' ', len);
  memstrcpy(str, buf);

  return rv;
}

CK_RV get_token_label(ykpiv_state *state, CK_CHAR_PTR str, CK_ULONG len) {

  uint32_t serial;
  char buf[64];
  int actual;

  CK_RV rv = ykpiv_get_serial(state, &serial);

  actual = snprintf(buf, sizeof(buf), "YubiKey PIV #%u", serial);

  if(actual < 0)
    return CKR_FUNCTION_FAILED;

  if(actual >= len)
    return CKR_BUFFER_TOO_SMALL;

  memset(str, ' ', len);
  memstrcpy(str, buf);

  return rv;
}

CK_RV get_token_mechanism_list(CK_MECHANISM_TYPE_PTR mec, CK_ULONG_PTR num) {

  if(mec) {
    if (*num < sizeof(token_mechanisms) / sizeof(token_mechanisms[0])) {
      return CKR_BUFFER_TOO_SMALL;
    }

    for (CK_ULONG i = 0; i < sizeof(token_mechanisms) / sizeof(token_mechanisms[0]); i++) {
      mec[i] = token_mechanisms[i].type;
    }
  }

  *num = sizeof(token_mechanisms) / sizeof(token_mechanisms[0]);
  return CKR_OK;
}

CK_RV get_token_mechanism_info(CK_MECHANISM_TYPE mec, CK_MECHANISM_INFO_PTR info) {

  for (CK_ULONG i = 0; i < sizeof(token_mechanisms) / sizeof(token_mechanisms[0]); i++) {
    if (token_mechanisms[i].type == mec) {
      memcpy(info, &token_mechanisms[i].info, sizeof(CK_MECHANISM_INFO));
      return CKR_OK;
    }
  }

  return CKR_MECHANISM_INVALID;
}

CK_RV get_token_object_ids(const piv_obj_id_t **obj, CK_ULONG_PTR len) {

  *obj = token_objects;
  *len = sizeof(token_objects) / sizeof(token_objects[0]);

  return CKR_OK;
}

CK_RV token_change_pin(ykpiv_state *state, CK_USER_TYPE user_type, CK_UTF8CHAR_PTR pOldPin, CK_ULONG ulOldLen, CK_UTF8CHAR_PTR pNewPin, CK_ULONG ulNewLen) {
  int tries;
  ykpiv_rc res;

  switch(user_type){
    case CKU_SO:{
      unsigned char new_key[24];
      size_t new_key_len = sizeof(new_key);
      if(ykpiv_hex_decode((const char*)pNewPin, ulNewLen, new_key, &new_key_len) != YKPIV_OK) {
        DBG("Failed to decode new pin")
        return CKR_PIN_INVALID;
      }
      res = ykpiv_set_mgmkey(state, new_key);
      break;
    }
    case CKU_USER:
      if(ulOldLen >= 4 && strncmp((const char*)pOldPin, "puk:", 4) == 0){
        DBG("Changing PUK pin")
        res = ykpiv_change_puk(state, (const char*)pOldPin + 4, ulOldLen - 4, (const char*)pNewPin, ulNewLen, &tries);
      }else{
        DBG("Changing USER pin")
        res = ykpiv_change_pin(state, (const char*)pOldPin, ulOldLen, (const char*)pNewPin, ulNewLen, &tries);
      }
      break;
    default:
      DBG("TODO implement other context specific pin change");
      return CKR_FUNCTION_FAILED;
  }

  switch (res) {
    case YKPIV_OK:
      return CKR_OK;
    case YKPIV_SIZE_ERROR:
      return CKR_PIN_LEN_RANGE;
    case YKPIV_WRONG_PIN:
      return CKR_PIN_INCORRECT;
    case YKPIV_PIN_LOCKED:
      return CKR_PIN_LOCKED;
    default:
      return CKR_FUNCTION_FAILED;
  }
}

CK_RV token_login(ykpiv_state *state, CK_USER_TYPE user, CK_UTF8CHAR_PTR pin, CK_ULONG pin_len) {

  int tries = 0; // TODO: this is effectively disregarded, should we add a better value in ykpiv_verify?
  unsigned char key[24];
  size_t key_len = sizeof(key);
  unsigned char *term_pin;
  ykpiv_rc res;

  if (user == CKU_USER) {
    // add null termination for the pin
    term_pin = malloc(pin_len + 1);
    if (term_pin == NULL) {
      return CKR_HOST_MEMORY;
    }
    memcpy(term_pin, pin, pin_len);
    term_pin[pin_len] = 0;

    res = ykpiv_verify(state, (char *)term_pin, &tries);

    OPENSSL_cleanse(term_pin, pin_len);
    free(term_pin);

    if (res != YKPIV_OK) {
      DBG("Failed to login");
      return CKR_PIN_INCORRECT;
    }
  }
  else if (user == CKU_SO) {
    if(ykpiv_hex_decode((char *)pin, pin_len, key, &key_len) != YKPIV_OK) {
      DBG("Failed decoding key");
      return CKR_PIN_INVALID;
    }

    if(ykpiv_authenticate(state, key) != YKPIV_OK) {
      DBG("Failed to authenticate");
      return CKR_PIN_INCORRECT;
    }
  }

  return CKR_OK;
}

CK_RV token_generate_key(ykpiv_state *state, CK_BYTE algorithm, CK_BYTE key, CK_BYTE_PTR cert_data, CK_ULONG_PTR cert_len) {
  // TODO: make a function in ykpiv for this
  unsigned char in_data[11];
  unsigned char *in_ptr = in_data;
  unsigned char data[1024];
  unsigned char templ[] = {0, YKPIV_INS_GENERATE_ASYMMETRIC, 0, 0};
  unsigned char *certptr;
  unsigned long len, offset, recv_len = sizeof(data);
  char version[7];
  char label[32];
  int len_bytes;
  int sw;

  switch(algorithm) {
    case YKPIV_ALGO_RSA1024:
    case YKPIV_ALGO_RSA2048:
      if(ykpiv_get_version(state, version, sizeof(version)) == YKPIV_OK) {
        int major, minor, build;
        int match = sscanf(version, "%d.%d.%d", &major, &minor, &build);
        if(match == 3 && major == 4 && (minor < 3 || (minor == 3 && build < 5))) {
          DBG("On-chip RSA key generation on this YubiKey has been blocked.");
          DBG("Please see https://yubi.co/ysa201701/ for details.");
          return CKR_FUNCTION_FAILED;
        }
      } else {
        DBG("Failed to communicate.");
        return CKR_DEVICE_ERROR;
      }
      offset = 5;
      break;

    case YKPIV_ALGO_ECCP256:
    case YKPIV_ALGO_ECCP384:
      offset = 3;
      break;

    default:
      return CKR_FUNCTION_FAILED;
  }

  templ[3] = key;

  *in_ptr++ = 0xac;
  *in_ptr++ = 3;
  *in_ptr++ = YKPIV_ALGO_TAG;
  *in_ptr++ = 1;
  *in_ptr++ = algorithm;

  if(ykpiv_transfer_data(state, templ, in_data, in_ptr - in_data, data, &recv_len, &sw) != YKPIV_OK || sw != 0x9000) {
    DBG("Failed to generate key, sw = %04x.", sw);
    return CKR_DEVICE_ERROR;
  }

  snprintf(label, sizeof(label), "YubiKey PIV Slot %x", key);

  // Create a new empty certificate for the key
  len = recv_len;
  recv_len = sizeof(data);
  CK_RV rv = do_create_empty_cert(data + offset, len - offset, algorithm, label, data, &recv_len);
  if(rv != CKR_OK)
    return rv;

  if (recv_len < 0x80)
    len_bytes = 1;
  else if (recv_len < 0xff)
    len_bytes = 2;
  else
    len_bytes = 3;

  certptr = data;
  memmove(data + len_bytes + 1, data, recv_len);

  *certptr++ = 0x70;
  certptr += set_length(certptr, recv_len);
  certptr += recv_len;
  *certptr++ = 0x71;
  *certptr++ = 1;
  *certptr++ = 0; /* certinfo (gzip etc) */
  *certptr++ = 0xfe; /* LRC */
  *certptr++ = 0;

  if(*cert_len < certptr - data) {
    DBG("Certificate buffer too small.");
    return CKR_BUFFER_TOO_SMALL;
  }

  // Store the certificate into the token
  if (ykpiv_save_object(state, ykpiv_util_slot_object(key), data, certptr - data) != YKPIV_OK)
    return CKR_DEVICE_ERROR;

  memcpy(cert_data, data, certptr - data);
  *cert_len = certptr - data;

  return CKR_OK;
}

CK_RV token_import_cert(ykpiv_state *state, CK_ULONG cert_id, CK_BYTE_PTR in) {

  unsigned char certdata[YKPIV_OBJ_MAX_SIZE + 16];
  unsigned char *certptr;
  CK_ULONG cert_len;

  CK_RV rv;

  // Check whether or not we have a valid cert
  if ((rv = do_check_cert(in, &cert_len)) != CKR_OK)
    return rv;

  if (cert_len > YKPIV_OBJ_MAX_SIZE)
    return CKR_FUNCTION_FAILED;

  certptr = certdata;

  *certptr++ = 0x70;
  certptr += set_length(certptr, cert_len);
  memcpy(certptr, in, cert_len);
  certptr += cert_len;

  *certptr++ = 0x71;
  *certptr++ = 1;
  *certptr++ = 0; /* certinfo (gzip etc) */
  *certptr++ = 0xfe; /* LRC */
  *certptr++ = 0;

  // Store the certificate into the token
  if (ykpiv_save_object(state, cert_id, certdata, (size_t)(certptr - certdata)) != YKPIV_OK)
    return CKR_DEVICE_ERROR;

  return CKR_OK;
}

CK_RV token_import_private_key(ykpiv_state *state, CK_BYTE key_id,
                                      CK_BYTE_PTR p, CK_ULONG p_len,
                                      CK_BYTE_PTR q, CK_ULONG q_len,
                                      CK_BYTE_PTR dp, CK_ULONG dp_len,
                                      CK_BYTE_PTR dq, CK_ULONG dq_len,
                                      CK_BYTE_PTR qinv, CK_ULONG qinv_len,
                                      CK_BYTE_PTR ec_data, CK_ULONG ec_data_len) {

  CK_BYTE  pin_policy;
  CK_BYTE  touch_policy;
  CK_BYTE  algo;
  ykpiv_rc rc;

  if (p == NULL) {
    if (ec_data_len == 32 || ec_data_len == 31)
      algo = YKPIV_ALGO_ECCP256;
    else
      algo = YKPIV_ALGO_ECCP384;
  }
  else if (ec_data == NULL) {
    if (p_len == 64)
      algo = YKPIV_ALGO_RSA1024;
    else
      algo = YKPIV_ALGO_RSA2048;
  }
  else
    return CKR_FUNCTION_FAILED;

  pin_policy = YKPIV_PINPOLICY_DEFAULT;
  touch_policy = YKPIV_TOUCHPOLICY_DEFAULT;

  rc = ykpiv_import_private_key(state, key_id, algo,
                                p, p_len,
                                q, q_len,
                                dp, dp_len,
                                dq, dq_len,
                                qinv, qinv_len,
                                ec_data, ec_data_len,
                                pin_policy, touch_policy);

  if (rc != YKPIV_OK) {
    DBG("ykpiv_import_private_key failed: %s", ykpiv_strerror(rc));
    return CKR_FUNCTION_FAILED;
  }

  return CKR_OK;
}

CK_RV token_delete_cert(ykpiv_state *state, CK_ULONG cert_id) {

  if (ykpiv_save_object(state, cert_id, NULL, 0) != YKPIV_OK)
    return CKR_DEVICE_ERROR;

  return CKR_OK;
}
