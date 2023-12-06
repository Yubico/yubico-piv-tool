/*
 * Copyright (c) 2015-2016,2019-2020 Yubico AB
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
#include "../common/util.h"

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
  CKM_EC_KEY_PAIR_GEN, {MIN_ECC_KEY_SIZE, MAX_ECC_KEY_SIZE, CKF_HW | CKF_GENERATE_KEY_PAIR | CKF_EC_F_P | CKF_EC_NAMEDCURVE | CKF_EC_UNCOMPRESS},
  //CKM_ECDSA_KEY_PAIR_GEN, {MIN_ECC_KEY_SIZE, MAX_ECC_KEY_SIZE, CKF_HW | CKF_GENERATE_KEY_PAIR | CKF_EC_F_P | CKF_EC_NAMEDCURVE | CKF_EC_UNCOMPRESS}, //Same as CKM_EC_KEY_PAIR_GEN, deprecated in 2.11
  CKM_ECDSA, {MIN_ECC_KEY_SIZE, MAX_ECC_KEY_SIZE, CKF_HW | CKF_SIGN | CKF_VERIFY | CKF_EC_F_P | CKF_EC_NAMEDCURVE | CKF_EC_UNCOMPRESS},
  CKM_ECDSA_SHA1, {MIN_ECC_KEY_SIZE, MAX_ECC_KEY_SIZE, CKF_HW | CKF_SIGN | CKF_VERIFY | CKF_EC_F_P | CKF_EC_NAMEDCURVE | CKF_EC_UNCOMPRESS},
  CKM_ECDSA_SHA224, {MIN_ECC_KEY_SIZE, MAX_ECC_KEY_SIZE, CKF_HW | CKF_SIGN | CKF_VERIFY | CKF_EC_F_P | CKF_EC_NAMEDCURVE | CKF_EC_UNCOMPRESS},
  CKM_ECDSA_SHA256, {MIN_ECC_KEY_SIZE, MAX_ECC_KEY_SIZE, CKF_HW | CKF_SIGN | CKF_VERIFY | CKF_EC_F_P | CKF_EC_NAMEDCURVE | CKF_EC_UNCOMPRESS},
  CKM_ECDSA_SHA384, {MIN_ECC_KEY_SIZE, MAX_ECC_KEY_SIZE, CKF_HW | CKF_SIGN | CKF_VERIFY | CKF_EC_F_P | CKF_EC_NAMEDCURVE | CKF_EC_UNCOMPRESS},
  CKM_ECDSA_SHA512, {MIN_ECC_KEY_SIZE, MAX_ECC_KEY_SIZE, CKF_HW | CKF_SIGN | CKF_VERIFY | CKF_EC_F_P | CKF_EC_NAMEDCURVE | CKF_EC_UNCOMPRESS},
  CKM_ECDH1_DERIVE, {MIN_ECC_KEY_SIZE, MAX_ECC_KEY_SIZE, CKF_HW | CKF_DERIVE | CKF_EC_F_P | CKF_EC_NAMEDCURVE | CKF_EC_UNCOMPRESS},
  CKM_SHA_1, {0, 0, CKF_DIGEST},
  CKM_SHA256, {0, 0, CKF_DIGEST},
  CKM_SHA384, {0, 0, CKF_DIGEST},
  CKM_SHA512, {0, 0, CKF_DIGEST}
};

// The commented out objects below are either not supported (PIV_DATA_OBJ_BITGT) or requires authentication.
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
    //PIV_DATA_OBJ_CHF,           // Cardholder fingerprints
    PIV_DATA_OBJ_SEC_OBJ,         // Security object
    //PIV_DATA_OBJ_CHFI,          // Cardholder facial images
    //PIV_DATA_OBJ_PI,            // Cardholder printed information
    PIV_DATA_OBJ_DISCOVERY,       // Discovery object
    PIV_DATA_OBJ_HISTORY,         // History object
    //PIV_DATA_OBJ_IRIS_IMAGE,    // Cardholder iris images
    //PIV_DATA_OBJ_BITGT,         // Biometric information templates group template
    PIV_DATA_OBJ_SM_SIGNER,       // Secure messaging signer
    PIV_DATA_OBJ_PC_REF_DATA,     // Pairing code reference data
};

CK_RV get_token_model(ykpiv_state *state, CK_UTF8CHAR_PTR str, CK_ULONG len) {

  if (strlen(token_model) > len)
    return CKR_BUFFER_TOO_SMALL;

  ykpiv_devmodel model = ykpiv_util_devicemodel(state);

  uint8_t *ptr = str + memstrcpy(str, len, token_model) - 3;

  switch(model) {
    case DEVTYPE_NEOr3:
      memstrcpy(ptr, 3, "NEO");
      break;
    case DEVTYPE_YK4:
      memstrcpy(ptr, 3, "YK4");
      break;
    case DEVTYPE_YK5:
      memstrcpy(ptr, 3, "YK5");
      break;
  }

  return CKR_OK;
}

CK_RV get_token_version(ykpiv_state *state, CK_VERSION_PTR version) {

  char buf[16] = {0};
  ykpiv_rc rc;

  if (version == NULL)
    return CKR_ARGUMENTS_BAD;

  if ((rc = ykpiv_get_version(state, buf, sizeof(buf))) != YKPIV_OK) {
    version->major = 0;
    version->minor = 0;
    return yrc_to_rv(rc);
  }

  version->major = (buf[0] - '0');
  version->minor = (buf[2] - '0') * 10 + (buf[4] - '0');

  return CKR_OK;
}

CK_RV get_token_serial(ykpiv_state *state, CK_CHAR_PTR str, CK_ULONG len) {

  uint32_t serial = 0;
  char buf[64] = {0};

  ykpiv_rc rc = ykpiv_get_serial(state, &serial);

  int actual = snprintf(buf, sizeof(buf), "%u", serial);

  if(actual < 0)
    return CKR_FUNCTION_FAILED;

  if((CK_ULONG)actual >= len)
    return CKR_BUFFER_TOO_SMALL;

  memstrcpy(str, len, buf);

  return yrc_to_rv(rc);
}

CK_RV get_token_label(ykpiv_state *state, CK_CHAR_PTR str, CK_ULONG len) {

  uint32_t serial = 0;
  char buf[64] = {0};

  ykpiv_rc rc = ykpiv_get_serial(state, &serial);

  int actual = snprintf(buf, sizeof(buf), "YubiKey PIV #%u", serial);

  if(actual < 0)
    return CKR_FUNCTION_FAILED;

  if((CK_ULONG)actual >= len)
    return CKR_BUFFER_TOO_SMALL;

  memstrcpy(str, len, buf);

  return yrc_to_rv(rc);
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
      ykpiv_mgm new_key = {0};
      new_key.len = sizeof(new_key.data);
      if(ykpiv_hex_decode((const char*)pNewPin, ulNewLen, new_key.data, &new_key.len) != YKPIV_OK) {
        DBG("Failed to decode new pin");
        return CKR_PIN_INVALID;
      }
      DBG("Changing SO PIN");
      // Set new mgm key (SO PIN) with the same algorithm and touch policy the old one had
      res = ykpiv_set_mgmkey3(state, new_key.data, new_key.len, YKPIV_ALGO_AUTO, YKPIV_TOUCHPOLICY_AUTO);
      if(res == YKPIV_OK) {
        ykpiv_config config = {0};
        res = ykpiv_util_get_config(state, &config);
        if(res == YKPIV_OK && config.mgm_type == YKPIV_CONFIG_MGM_PROTECTED) {
          res = ykpiv_util_update_protected_mgm(state, &new_key);
          if(res != YKPIV_OK) {
            DBG("Failed to update pin protected management key metadata");
          }
        }
      } else {
        DBG("Failed to set new management key: %s", ykpiv_strerror(res));
      }
      OPENSSL_cleanse(new_key.data, sizeof(new_key.data));
      break;
    }
    case CKU_USER:
      if(ulOldLen >= 4 && strncmp((const char*)pOldPin, "puk:", 4) == 0){
        if(ulNewLen >= 4 && strncmp((const char*)pNewPin, "pin:", 4) == 0) {
          DBG("Unblocking PIN with PUK");
          res = ykpiv_unblock_pin(state, (const char*)pOldPin + 4, ulOldLen - 4, (const char*)pNewPin + 4, ulNewLen - 4, &tries);
        } else {
          DBG("Changing PUK");
          if(ulNewLen >= 4 && strncmp((const char*)pNewPin, "puk:", 4) == 0) {
            res = ykpiv_change_puk(state, (const char*)pOldPin + 4, ulOldLen - 4, (const char*)pNewPin + 4, ulNewLen - 4, &tries);
          } else {
            res = ykpiv_change_puk(state, (const char*)pOldPin + 4, ulOldLen - 4, (const char*)pNewPin, ulNewLen, &tries);
          }
        }
      }else{
        DBG("Changing PIN");
        res = ykpiv_change_pin(state, (const char*)pOldPin, ulOldLen, (const char*)pNewPin, ulNewLen, &tries);
      }
      break;
    default:
      DBG("TODO implement other context specific pin change");
      return CKR_FUNCTION_FAILED;
  }

  switch (res) {
    case YKPIV_SIZE_ERROR:
      return CKR_PIN_LEN_RANGE;
    default:
      return yrc_to_rv(res);
  }
}

CK_RV token_login(ykpiv_state *state, CK_USER_TYPE user, CK_UTF8CHAR_PTR pin, CK_ULONG pin_len) {

  ykpiv_rc res;

  if (pin_len >= YKPIV_MIN_PIN_LEN && pin_len <= YKPIV_MAX_PIN_LEN) {
    char term_pin[YKPIV_MAX_PIN_LEN + 1] = {0};

    memcpy(term_pin, pin, pin_len);
    term_pin[pin_len] = 0;

    int tries = 0;
    res = ykpiv_verify(state, term_pin, &tries);

    OPENSSL_cleanse(term_pin, pin_len);

    if (res != YKPIV_OK) {
      DBG("Failed to login: %s, %d tries left", ykpiv_strerror(res), tries);

      return yrc_to_rv(res);
    }
  } else if(pin_len < YKPIV_MIN_MGM_KEY_LEN || pin_len > YKPIV_MAX_MGM_KEY_LEN || user != CKU_SO) {
    DBG("PIN is wrong length");
    return CKR_ARGUMENTS_BAD;
  }

  if (user == CKU_SO) {
    ykpiv_config cfg = {0};

    if (pin_len >= YKPIV_MIN_MGM_KEY_LEN && pin_len <= YKPIV_MAX_MGM_KEY_LEN) {
      cfg.mgm_len = sizeof(cfg.mgm_key);
      if((res = ykpiv_hex_decode((char *)pin, pin_len, cfg.mgm_key, &cfg.mgm_len)) != YKPIV_OK) {
        DBG("Failed decoding key");
        OPENSSL_cleanse(cfg.mgm_key, sizeof(cfg.mgm_key));
        return yrc_to_rv(res);
      }
    } else {
      res = ykpiv_util_get_config(state, &cfg);
      if(res != YKPIV_OK) {
        DBG("Failed to get device configuration: %s", ykpiv_strerror(res));
        OPENSSL_cleanse(cfg.mgm_key, sizeof(cfg.mgm_key));
        return yrc_to_rv(res);
      }

      if(cfg.mgm_type != YKPIV_CONFIG_MGM_PROTECTED) {
        DBG("Device configuration invalid, no PIN-protected MGM key available");
        OPENSSL_cleanse(cfg.mgm_key, sizeof(cfg.mgm_key));
        return CKR_USER_PIN_NOT_INITIALIZED;
      }
    }

    if((res = ykpiv_authenticate2(state, cfg.mgm_key, cfg.mgm_len)) != YKPIV_OK) {
      DBG("Failed to authenticate: %s", ykpiv_strerror(res));
      OPENSSL_cleanse(cfg.mgm_key, sizeof(cfg.mgm_key));

      if(res == YKPIV_AUTHENTICATION_ERROR)
        return CKR_PIN_INCORRECT;

      return yrc_to_rv(res);
    }

    OPENSSL_cleanse(cfg.mgm_key, sizeof(cfg.mgm_key));
  }

  return CKR_OK;
}

CK_RV token_generate_key(ykpiv_state *state, gen_info_t *gen, CK_BYTE key, CK_BYTE_PTR cert_data, CK_ULONG_PTR cert_len) {
  // TODO: make a function in ykpiv for this
  unsigned char in_data[11] = {0};
  unsigned char *in_ptr = in_data;
  unsigned char data[1024] = {0};
  unsigned char templ[] = {0, YKPIV_INS_GENERATE_ASYMMETRIC, 0, 0};
  uint8_t certdata[YKPIV_OBJ_MAX_SIZE + 16] = {0};
  size_t certdata_len = sizeof(certdata);
  unsigned long len, offs, recv_len = sizeof(data);
  char version[7] = {0};
  char label[32] = {0};
  ykpiv_rc res;
  int sw;

  switch(gen->algorithm) {
    case YKPIV_ALGO_RSA1024:
    case YKPIV_ALGO_RSA2048:
      if((res = ykpiv_get_version(state, version, sizeof(version))) == YKPIV_OK) {
        int major, minor, build;
        int match = sscanf(version, "%d.%d.%d", &major, &minor, &build);
        if(match == 3 && major == 4 && (minor < 3 || (minor == 3 && build < 5))) {
          DBG("On-chip RSA key generation on this YubiKey has been blocked.");
          DBG("Please see https://yubi.co/ysa201701/ for details.");
          return CKR_FUNCTION_FAILED;
        }
      } else {
        DBG("Failed to communicate.");
        return yrc_to_rv(res);
      }
      break;

    case YKPIV_ALGO_ECCP256:
    case YKPIV_ALGO_ECCP384:
      break;

    default:
      return CKR_FUNCTION_FAILED;
  }

  switch (gen->touch_policy) {
    case YKPIV_TOUCHPOLICY_DEFAULT:
    case YKPIV_TOUCHPOLICY_ALWAYS:
    case YKPIV_TOUCHPOLICY_CACHED:
    case YKPIV_TOUCHPOLICY_NEVER:
        break;
    default: 
        return CKR_FUNCTION_FAILED;
  }

  switch (gen->pin_policy) {
    case YKPIV_PINPOLICY_DEFAULT:
    case YKPIV_PINPOLICY_ALWAYS:
    case YKPIV_PINPOLICY_ONCE:
    case YKPIV_PINPOLICY_NEVER:
        break;
    default: 
        return CKR_FUNCTION_FAILED;
  }

  templ[3] = key;

  *in_ptr++ = 0xac;
  *in_ptr++ = 3;
  *in_ptr++ = YKPIV_ALGO_TAG;
  *in_ptr++ = 1;
  *in_ptr++ = gen->algorithm;

  if (gen->touch_policy != YKPIV_TOUCHPOLICY_DEFAULT) {
      in_data[1] += 3;
      *in_ptr++ = YKPIV_TOUCHPOLICY_TAG;
      *in_ptr++ = 0x01;
      *in_ptr++ = gen->touch_policy;
  }

  if (gen->pin_policy != YKPIV_PINPOLICY_DEFAULT) {
      in_data[1] += 3;
      *in_ptr++ = YKPIV_PINPOLICY_TAG;
      *in_ptr++ = 0x01;
      *in_ptr++ = gen->pin_policy;
  }

  if((res = ykpiv_transfer_data(state, templ, in_data, in_ptr - in_data, data, &recv_len, &sw)) != YKPIV_OK) {
    return yrc_to_rv(res);
  }
  if((res = ykpiv_translate_sw(sw)) != YKPIV_OK) {
    return yrc_to_rv(res);
  }

  snprintf(label, sizeof(label), "YubiKey PIV Slot %x", key);

  // Create a new empty certificate for the key
  offs = 2 + get_length(data + 2, data + recv_len, &len);
  if(offs == 2)
    return CKR_DEVICE_ERROR;

  len = recv_len;
  recv_len = sizeof(data);
  CK_RV rv = do_create_empty_cert(data + offs, len - offs, gen->algorithm, label, data, &recv_len);
  if(rv != CKR_OK)
    return rv;

  ykpiv_util_write_certdata(data, recv_len, YKPIV_CERTINFO_UNCOMPRESSED, certdata, &certdata_len);

  if(*cert_len < (CK_ULONG)certdata_len) {
    DBG("Certificate buffer too small.");
    return CKR_BUFFER_TOO_SMALL;
  }

  // Store the certificate into the token
  if ((res = ykpiv_save_object(state, ykpiv_util_slot_object(key), certdata, certdata_len)) != YKPIV_OK)
    return yrc_to_rv(res);

  memcpy(cert_data, data, (unsigned long) certdata_len);
  *cert_len = certdata_len;

  return CKR_OK;
}

CK_RV token_import_cert(ykpiv_state *state, CK_ULONG cert_id, CK_BYTE_PTR in, CK_ULONG in_len) {

  unsigned char certdata[YKPIV_OBJ_MAX_SIZE + 16] = {0};
  size_t certdata_len = sizeof(certdata);
  CK_ULONG cert_len;
  ykpiv_rc res;
  CK_RV rv;

  // Check whether or not we have a valid cert
  if ((rv = do_check_cert(in, in_len, &cert_len)) != CKR_OK) {
    DBG("Certificate not valid.");
    return rv;
  }

  ykpiv_util_write_certdata(in, cert_len, YKPIV_CERTINFO_UNCOMPRESSED, certdata, &certdata_len);

  // Store the certificate into the token
  if ((res = ykpiv_save_object(state, cert_id, certdata, certdata_len)) != YKPIV_OK)
    return yrc_to_rv(res);

  return CKR_OK;
}

CK_RV token_delete_cert(ykpiv_state *state, CK_ULONG cert_id) {
  ykpiv_rc res;

  if ((res = ykpiv_save_object(state, cert_id, NULL, 0)) != YKPIV_OK)
    return yrc_to_rv(res);

  return CKR_OK;
}
