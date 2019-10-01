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

#include "token.h"
#include "pkcs11.h"
#include <string.h>
#include "debug.h"
#include "objects.h"
#include "openssl_utils.h"

#include <stdbool.h>
#include "../tool/util.h"




#define MIN_RSA_KEY_SIZE 1024
#define MAX_RSA_KEY_SIZE 2048
#define MIN_ECC_KEY_SIZE 256
#define MAX_ECC_KEY_SIZE 384

static const char *token_label = "YubiKey PIV";
static const char *token_manufacturer = "Yubico";
static const char *token_model = "YubiKey XXX";
static const CK_FLAGS token_flags = CKF_RNG | CKF_LOGIN_REQUIRED | CKF_USER_PIN_INITIALIZED | CKF_TOKEN_INITIALIZED;
static const CK_MECHANISM_TYPE token_mechanisms[] = { // KEEP ALIGNED WITH token_mechanism_infos
    CKM_RSA_PKCS_KEY_PAIR_GEN,
    CKM_RSA_PKCS,
    CKM_RSA_PKCS_PSS,
    CKM_RSA_X_509,
    CKM_SHA1_RSA_PKCS,
    CKM_SHA256_RSA_PKCS,
    CKM_SHA384_RSA_PKCS,
    CKM_SHA512_RSA_PKCS,
    CKM_SHA1_RSA_PKCS_PSS,
    CKM_SHA256_RSA_PKCS_PSS,
    CKM_SHA384_RSA_PKCS_PSS,
    CKM_SHA512_RSA_PKCS_PSS,
    CKM_EC_KEY_PAIR_GEN,
    //CKM_ECDSA_KEY_PAIR_GEN, Same as CKM_EC_KEY_PAIR_GEN, deprecated in 2.11
    CKM_ECDSA,
    CKM_ECDSA_SHA1,
    CKM_ECDSA_SHA256,
    CKM_ECDSA_SHA384,
    CKM_SHA_1,
    CKM_SHA256,
    CKM_SHA384,
    CKM_SHA512
    // SUPPORT FOR OATH?
};
static const CK_ULONG token_mechanisms_num = sizeof(token_mechanisms) / sizeof(CK_MECHANISM_TYPE);

static const CK_MECHANISM_INFO token_mechanism_infos[] = { // KEEP ALIGNED WITH token_mechanisms
    {MIN_RSA_KEY_SIZE, MAX_RSA_KEY_SIZE, CKF_HW | CKF_GENERATE_KEY_PAIR}, // CKM_RSA_PKCS_KEY_PAIR_GEN
    {MIN_RSA_KEY_SIZE, MAX_RSA_KEY_SIZE, CKF_HW | CKF_DECRYPT | CKF_SIGN}, // CKM_RSA_PKCS
    {MIN_RSA_KEY_SIZE, MAX_RSA_KEY_SIZE, CKF_HW | CKF_SIGN}, // CKM_RSA_PKCS_PSS
    {MIN_RSA_KEY_SIZE, MAX_RSA_KEY_SIZE, CKF_HW | CKF_DECRYPT | CKF_SIGN}, // CKM_RSA_X_509
    {MIN_RSA_KEY_SIZE, MAX_RSA_KEY_SIZE, CKF_HW | CKF_SIGN}, // CKM_SHA1_RSA_PKCS
    {MIN_RSA_KEY_SIZE, MAX_RSA_KEY_SIZE, CKF_HW | CKF_SIGN}, // CKM_SHA256_RSA_PKCS
    {MIN_RSA_KEY_SIZE, MAX_RSA_KEY_SIZE, CKF_HW | CKF_SIGN}, // CKM_SHA384_RSA_PKCS
    {MIN_RSA_KEY_SIZE, MAX_RSA_KEY_SIZE, CKF_HW | CKF_SIGN}, // CKM_SHA512_RSA_PKCS
    {MIN_RSA_KEY_SIZE, MAX_RSA_KEY_SIZE, CKF_HW | CKF_SIGN}, // CKM_SHA1_RSA_PKCS_PSS
    {MIN_RSA_KEY_SIZE, MAX_RSA_KEY_SIZE, CKF_HW | CKF_SIGN}, // CKM_SHA256_RSA_PKCS_PSS
    {MIN_RSA_KEY_SIZE, MAX_RSA_KEY_SIZE, CKF_HW | CKF_SIGN}, // CKM_SHA384_RSA_PKCS_PSS
    {MIN_RSA_KEY_SIZE, MAX_RSA_KEY_SIZE, CKF_HW | CKF_SIGN}, // CKM_SHA512_RSA_PKCS_PSS
    {MIN_ECC_KEY_SIZE, MAX_ECC_KEY_SIZE, CKF_HW | CKF_GENERATE_KEY_PAIR}, // CKM_EC_KEY_PAIR_GEN
    //{, , }, // CKM_ECDSA_KEY_PAIR_GEN Same as CKM_EC_KEY_PAIR_GEN deprecated in 2.11
    {MIN_ECC_KEY_SIZE, MAX_ECC_KEY_SIZE, CKF_HW | CKF_SIGN}, // CKM_ECDSA
    {MIN_ECC_KEY_SIZE, MAX_ECC_KEY_SIZE, CKF_HW | CKF_SIGN}, // CKM_ECDSA_SHA1
    {MIN_ECC_KEY_SIZE, MAX_ECC_KEY_SIZE, CKF_HW | CKF_SIGN}, // CKM_ECDSA_SHA256
    {MIN_ECC_KEY_SIZE, MAX_ECC_KEY_SIZE, CKF_HW | CKF_SIGN}, // CKM_ECDSA_SHA348
    {0, 0, CKF_DIGEST}, // CKM_SHA_1
    {0, 0, CKF_DIGEST}, // CKM_SHA256
    {0, 0, CKF_DIGEST}, // CKM_SHA384
    {0, 0, CKF_DIGEST}  // CKM_SHA512
};

static const piv_obj_id_t token_objects[] = { // TODO: is there a way to get this from the token?
    PIV_DATA_OBJ_X509_PIV_AUTH,   // PIV authentication
    PIV_DATA_OBJ_X509_CARD_AUTH,  // card authentication
    PIV_DATA_OBJ_X509_DS,         // digital signature
    PIV_DATA_OBJ_X509_KM,         // key management
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
    PIV_DATA_OBJ_CCC,             // Card capability container
    PIV_DATA_OBJ_CHUI,            // Cardholder unique id
    PIV_DATA_OBJ_CHF,             // Cardholder fingerprints
    PIV_DATA_OBJ_SEC_OBJ,         // Security object
    PIV_DATA_OBJ_CHFI,            // Cardholder facial images
    //PIV_DATA_OBJ_PI,            // Cardholder printed information
    //PIV_DATA_OBJ_DISCOVERY,     // Discovery object
    //PIV_DATA_OBJ_HISTORY,       // History object
    //PIV_DATA_OBJ_IRIS_IMAGE,    // Cardholder iris images
    //PIV_DATA_OBJ_BITGT,         // Biometric information templates group template
    //PIV_DATA_OBJ_SM_SIGNER,     // Secure messaging signer
    //PIV_DATA_OBJ_PC_REF_DATA,   // Pairing code reference data
};
static const CK_ULONG neo_token_objects_num = sizeof(token_objects) / sizeof(piv_obj_id_t) - 20;
static const CK_ULONG yk4_token_objects_num = sizeof(token_objects) / sizeof(piv_obj_id_t);

CK_RV get_token_label(CK_UTF8CHAR_PTR str, CK_ULONG len) {

  if (strlen(token_label) > len)
    return CKR_BUFFER_TOO_SMALL;

  memcpy(str, token_label, strlen(token_label));
  return CKR_OK;

}

CK_RV get_token_manufacturer(CK_UTF8CHAR_PTR str, CK_ULONG len) {

  if (strlen(token_manufacturer) > len)
    return CKR_BUFFER_TOO_SMALL;

  memcpy(str, token_manufacturer, strlen(token_manufacturer));
  return CKR_OK;

}

CK_RV get_token_model(ykpiv_state *state, CK_UTF8CHAR_PTR str, CK_ULONG len) {

  char buf[16];

  if (strlen(token_model) > len)
    return CKR_BUFFER_TOO_SMALL;

  if (ykpiv_get_version(state, buf, sizeof(buf)) != YKPIV_OK)
    return CKR_FUNCTION_FAILED;

  memcpy(str, token_model, strlen(token_model));

  if (buf[0] >= '4')
    memcpy(str + strlen(token_model) - 3, "YK4", 3);
  else
    memcpy(str + strlen(token_model) - 3, "NEO", 3);

  return CKR_OK;

}

CK_RV get_token_flags(CK_FLAGS_PTR flags) {

  *flags = token_flags;
  return CKR_OK;

}

CK_RV get_token_version(ykpiv_state *state, CK_VERSION_PTR version) {

  char buf[16];

  if (version == NULL)
    return CKR_ARGUMENTS_BAD;

  if (ykpiv_get_version(state, buf, sizeof(buf)) != YKPIV_OK)
    return CKR_FUNCTION_FAILED;

  version->major = (buf[0] - '0');
  version->minor = (buf[2] - '0') * 100 + (buf[4] - '0');

  return CKR_OK;
}

CK_RV get_token_serial(ykpiv_state *state, CK_CHAR_PTR str, CK_ULONG len) {

  uint32_t serial;
  char buf[16];
  int actual;

  if(ykpiv_get_serial(state, &serial) != YKPIV_OK)
    return CKR_FUNCTION_FAILED;

  actual = sprintf(buf, "%d", serial);

  if(actual >= len)
    return CKR_BUFFER_TOO_SMALL;

  memcpy(str, buf, strlen(buf));
  return CKR_OK;
}

CK_RV get_token_mechanisms_num(CK_ULONG_PTR num) {

  *num = token_mechanisms_num;
  return CKR_OK;

}

CK_RV get_token_mechanism_list(CK_MECHANISM_TYPE_PTR mec, CK_ULONG num) {

  if (token_mechanisms_num > num)
    return CKR_BUFFER_TOO_SMALL;

  memcpy(mec, token_mechanisms, token_mechanisms_num * sizeof(CK_MECHANISM_TYPE));
  return CKR_OK;

}

CK_RV get_token_mechanism_info(CK_MECHANISM_TYPE mec, CK_MECHANISM_INFO_PTR info) {

  CK_ULONG i;

  for (i = 0; i < token_mechanisms_num; i++)
    if (token_mechanisms[i] == mec) {
      memcpy((CK_BYTE_PTR) info, (CK_BYTE_PTR) (token_mechanism_infos + i), sizeof(CK_MECHANISM_INFO));
      return CKR_OK;
    }

  return CKR_MECHANISM_INVALID;

}

static CK_RV get_objects(ykpiv_state *state, CK_BBOOL num_only,
                         piv_obj_id_t *obj, CK_ULONG_PTR len, CK_ULONG_PTR num_certs) {
  CK_BYTE      buf[2048];
  CK_ULONG     buf_len;
  CK_BYTE      major;
  CK_ULONG     i;

  piv_obj_id_t certs[24];
  piv_obj_id_t pvtkeys[24];
  piv_obj_id_t pubkeys[24];
  CK_ULONG     n_cert = 0;
  CK_ULONG     token_objects_num = neo_token_objects_num;

  if (state == NULL || len == NULL_PTR)
    return CKR_ARGUMENTS_BAD;

  if (num_only == CK_FALSE && obj == NULL)
    return CKR_ARGUMENTS_BAD;

  if (ykpiv_get_version(state, (char *) buf, sizeof(buf)) != YKPIV_OK)
    return CKR_FUNCTION_FAILED;

  major = buf[0] - '0';

  buf_len = sizeof(buf);
  if (ykpiv_fetch_object(state, YKPIV_OBJ_AUTHENTICATION, buf, &buf_len) == YKPIV_OK) {
    certs[n_cert] = PIV_CERT_OBJ_X509_PIV_AUTH;
    pvtkeys[n_cert] = PIV_PVTK_OBJ_PIV_AUTH;
    pubkeys[n_cert] = PIV_PUBK_OBJ_PIV_AUTH;
    n_cert++;
    DBG("Found AUTH cert (9a)");
  }

  buf_len = sizeof(buf);
  if (ykpiv_fetch_object(state, YKPIV_OBJ_CARD_AUTH, buf, &buf_len) == YKPIV_OK) {
    certs[n_cert] = PIV_CERT_OBJ_X509_CARD_AUTH;
    pvtkeys[n_cert] = PIV_PVTK_OBJ_CARD_AUTH;
    pubkeys[n_cert] = PIV_PUBK_OBJ_CARD_AUTH;
    n_cert++;
    DBG("Found CARD AUTH cert (9e)");
  }

  buf_len = sizeof(buf);
  if (ykpiv_fetch_object(state, YKPIV_OBJ_SIGNATURE, buf, &buf_len) == YKPIV_OK) {
    certs[n_cert] = PIV_CERT_OBJ_X509_DS;
    pvtkeys[n_cert] = PIV_PVTK_OBJ_DS;
    pubkeys[n_cert] = PIV_PUBK_OBJ_DS;
    n_cert++;
    DBG("Found SIGNATURE cert (9c)");
  }

  buf_len = sizeof(buf);
  if (ykpiv_fetch_object(state, YKPIV_OBJ_KEY_MANAGEMENT, buf, &buf_len) == YKPIV_OK) {
    certs[n_cert] = PIV_CERT_OBJ_X509_KM;
    pvtkeys[n_cert] = PIV_PVTK_OBJ_KM;
    pubkeys[n_cert] = PIV_PUBK_OBJ_KM;
    n_cert++;
    DBG("Found KMK cert (9d)");
  }

  if (major >= 4) {
    for (i = 0; i < 20; i++) {
      buf_len = sizeof(buf);
      if (ykpiv_fetch_object(state, YKPIV_OBJ_RETIRED1 + i, buf, &buf_len) == YKPIV_OK) {
        certs[n_cert] = PIV_CERT_OBJ_X509_RETIRED1 + i;
        pvtkeys[n_cert] = PIV_PVTK_OBJ_RETIRED1 + i;
        pubkeys[n_cert] = PIV_PUBK_OBJ_RETIRED1 + i;
        n_cert++;
        DBG("Found RETIRED cert (%lx)", 0x82 + i);
      }
    }
    token_objects_num = yk4_token_objects_num;
  }

  DBG("The total number of objects for this token is %lu", (n_cert * 3) + token_objects_num);

  if (num_only == CK_TRUE) {
    // We just want the number of objects
    // Each cert object counts for 3: cert, pub key, pvt key
    *len = (n_cert * 3) + token_objects_num;
    if (num_certs != NULL)
      *num_certs = n_cert;
    return CKR_OK;
  }

  if (*len < (n_cert * 3) + token_objects_num)
    return CKR_BUFFER_TOO_SMALL;

  // Copy data objects
  if (major >= 4) {
    // YK4: just copy all the objects
    memcpy(obj, token_objects, token_objects_num * sizeof(piv_obj_id_t));
  }
  else {
    // NEO: remove retired keys
    memcpy(obj, token_objects, 4 * sizeof(piv_obj_id_t));
    memcpy(obj + 4, token_objects + 24, (neo_token_objects_num - 4) * sizeof(piv_obj_id_t));
  }

  // Copy certificates
  if (n_cert > 0) {
    memcpy(obj + token_objects_num, certs, n_cert * sizeof(piv_obj_id_t));
    memcpy(obj + token_objects_num + n_cert, pvtkeys, n_cert * sizeof(piv_obj_id_t));
    memcpy(obj + token_objects_num + (2 * n_cert), pubkeys, n_cert * sizeof(piv_obj_id_t));
  }

  return CKR_OK;
}

CK_RV get_token_objects_num(ykpiv_state *state, CK_ULONG_PTR num, CK_ULONG_PTR num_certs) {
  return get_objects(state, CK_TRUE, NULL, num, num_certs);
}

CK_RV get_token_object_list(ykpiv_state *state, piv_obj_id_t *obj, CK_ULONG num) {
  return get_objects(state, CK_FALSE, obj, &num, NULL);
}

CK_RV get_token_raw_certificate(ykpiv_state *state, piv_obj_id_t obj, CK_BYTE_PTR data, CK_ULONG_PTR len) {

  if (ykpiv_fetch_object(state, piv_2_ykpiv(obj), data, len) != YKPIV_OK)
    return CKR_FUNCTION_FAILED;

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
        return CKR_ARGUMENTS_BAD;
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
      return CKR_FUNCTION_FAILED;
    }

    if(ykpiv_authenticate(state, key) != YKPIV_OK) {
      DBG("Failed to authenticate");
      return CKR_PIN_INCORRECT;
    }
  }

  return CKR_OK;
}

CK_RV token_generate_key(ykpiv_state *state, CK_BBOOL rsa,
                                       CK_BYTE key, CK_ULONG key_len) {
  // TODO: make a function in ykpiv for this
  unsigned char in_data[11];
  unsigned char *in_ptr = in_data;
  unsigned char data[1024];
  unsigned char templ[] = {0, YKPIV_INS_GENERATE_ASYMMETRIC, 0, 0};
  unsigned char *certptr;
  unsigned char key_algorithm;
  unsigned long recv_len = sizeof(data);
  int len_bytes;
  int sw;

  CK_RV rv;

  if(rsa) {
    char version[7];
    if(ykpiv_get_version(state, version, sizeof(version)) == YKPIV_OK) {
      int major, minor, build;
      int match = sscanf(version, "%d.%d.%d", &major, &minor, &build);
      if(match == 3 && major == 4 && (minor < 3 || (minor == 3 && build < 5))) {
        DBG("On-chip RSA key generation on this YubiKey has been blocked.\n");
        DBG("Please see https://yubi.co/ysa201701/ for details.\n");
        return CKR_FUNCTION_FAILED;
      }
    } else {
      DBG("Failed to communicate.\n");
      return CKR_DEVICE_ERROR;
    }
  }

  templ[3] = key;

  *in_ptr++ = 0xac;
  *in_ptr++ = 3;
  *in_ptr++ = YKPIV_ALGO_TAG;
  *in_ptr++ = 1;

  switch(key_len) {
    case 2048:
      if (rsa == CK_TRUE)
        key_algorithm = YKPIV_ALGO_RSA2048;
      else
        return CKR_FUNCTION_FAILED;

      break;

    case 1024:
      if (rsa == CK_TRUE)
        key_algorithm = YKPIV_ALGO_RSA1024;
      else
        return CKR_FUNCTION_FAILED;

      break;

    case 256:
      if (rsa == CK_FALSE)
        key_algorithm = YKPIV_ALGO_ECCP256;
      else
        return CKR_FUNCTION_FAILED;

      break;

    case 384:
      if (rsa == CK_FALSE)
        key_algorithm = YKPIV_ALGO_ECCP384;
      else
        return CKR_FUNCTION_FAILED;

      break;

    default:
      return CKR_FUNCTION_FAILED;
  }

  *in_ptr++ = key_algorithm;

  if(ykpiv_transfer_data(state, templ, in_data, in_ptr - in_data, data, &recv_len, &sw) != YKPIV_OK ||
     sw != 0x9000)
    return CKR_DEVICE_ERROR;

  // Create a new empty certificate for the key
  recv_len = sizeof(data);
  if ((rv = do_create_empty_cert(data, recv_len, rsa, key_algorithm, data, &recv_len)) != CKR_OK)
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

  // Store the certificate into the token
  if (ykpiv_save_object(state, ykpiv_util_slot_object(key), data, (size_t)(certptr - data)) != YKPIV_OK)
    return CKR_DEVICE_ERROR;

  return CKR_OK;
}

CK_RV token_import_cert(ykpiv_state *state, CK_ULONG cert_id, CK_BYTE_PTR in) {

  unsigned char certdata[3072];
  unsigned char *certptr;
  CK_ULONG cert_len;

  CK_RV rv;

  // Check whether or not we have a valid cert
  if ((rv = do_check_cert(in, &cert_len)) != CKR_OK)
    return rv;

  if (cert_len > 3072)
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

  if (rc != YKPIV_OK)
    return CKR_FUNCTION_FAILED;

  return CKR_OK;
}

CK_RV token_delete_cert(ykpiv_state *state, CK_ULONG cert_id) {

  if (ykpiv_save_object(state, cert_id, NULL, 0) != YKPIV_OK)
    return CKR_DEVICE_ERROR;

  return CKR_OK;
}
