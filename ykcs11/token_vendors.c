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

#include "token_vendors.h"
#include "yubico_token.h"
#include "openssl_utils.h"
#include <string.h>
#include "debug.h"

#include <stdbool.h>
#include "../tool/util.h"

static CK_RV COMMON_token_login(ykpiv_state *state, CK_USER_TYPE user, CK_UTF8CHAR_PTR pin, CK_ULONG pin_len) {

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

static CK_RV COMMON_token_generate_key(ykpiv_state *state, CK_BBOOL rsa,
                                       CK_BYTE key, CK_ULONG key_len, CK_ULONG vendor_defined) {
  // TODO: make a function in ykpiv for this
  unsigned char in_data[11];
  unsigned char *in_ptr = in_data;
  unsigned char data[1024];
  unsigned char templ[] = {0, YKPIV_INS_GENERATE_ASYMMETRIC, 0, 0};
  unsigned char *certptr;
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
      *in_ptr++ = YKPIV_ALGO_RSA2048;
    else
      return CKR_FUNCTION_FAILED;

    break;

  case 1024:
    if (rsa == CK_TRUE)
      *in_ptr++ = YKPIV_ALGO_RSA1024;
    else
      return CKR_FUNCTION_FAILED;

    break;

  case 256:
    if (rsa == CK_FALSE)
      *in_ptr++ = YKPIV_ALGO_ECCP256;
    else
      return CKR_FUNCTION_FAILED;

    break;

  default:
    return CKR_FUNCTION_FAILED;
  }
  // PIN policy and touch
  if (vendor_defined != 0) {
    if (vendor_defined & CKA_PIN_ONCE) {
      in_data[1] += 3;
      *in_ptr++ = YKPIV_PINPOLICY_TAG;
      *in_ptr++ = 0x01;
      *in_ptr++ = YKPIV_PINPOLICY_ONCE;
    }
    else if (vendor_defined & CKA_PIN_ALWAYS) {
      in_data[1] += 3;
      *in_ptr++ = YKPIV_PINPOLICY_TAG;
      *in_ptr++ = 0x01;
      *in_ptr++ = YKPIV_PINPOLICY_ALWAYS;
    }

    if (vendor_defined & CKA_TOUCH_ALWAYS) {
      in_data[1] += 3;
      *in_ptr++ = YKPIV_TOUCHPOLICY_TAG;
      *in_ptr++ = 0x01;
      *in_ptr++ = YKPIV_TOUCHPOLICY_ALWAYS;
    }
  }

  if(ykpiv_transfer_data(state, templ, in_data, in_ptr - in_data, data, &recv_len, &sw) != YKPIV_OK ||
     sw != 0x9000)
    return CKR_DEVICE_ERROR;

  // Create a new empty certificate for the key
  recv_len = sizeof(data);
  if ((rv = do_create_empty_cert(data, recv_len, rsa, data, &recv_len)) != CKR_OK)
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
  if (ykpiv_save_object(state, key_to_object_id(key), data, (size_t)(certptr - data)) != YKPIV_OK)
    return CKR_DEVICE_ERROR;

  return CKR_OK;
}

static CK_RV COMMON_token_import_cert(ykpiv_state *state, CK_ULONG cert_id, CK_BYTE_PTR in) {

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

CK_RV COMMON_token_import_private_key(ykpiv_state *state, CK_BYTE key_id,
                                      CK_BYTE_PTR p, CK_ULONG p_len,
                                      CK_BYTE_PTR q, CK_ULONG q_len,
                                      CK_BYTE_PTR dp, CK_ULONG dp_len,
                                      CK_BYTE_PTR dq, CK_ULONG dq_len,
                                      CK_BYTE_PTR qinv, CK_ULONG qinv_len,
                                      CK_BYTE_PTR ec_data, CK_ULONG ec_data_len,
                                      CK_ULONG vendor_defined) {

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
  if (vendor_defined != 0) {
    if (vendor_defined & CKA_PIN_ONCE) {
      pin_policy = YKPIV_PINPOLICY_ONCE;
    }
    else if (vendor_defined & CKA_PIN_ALWAYS) {
      pin_policy = YKPIV_PINPOLICY_ALWAYS;
    }
    else if (vendor_defined & CKA_PIN_NEVER) {
      pin_policy = YKPIV_PINPOLICY_NEVER;
    }
    else
      return CKR_ATTRIBUTE_VALUE_INVALID;

    if (vendor_defined & CKA_TOUCH_ALWAYS) {
      touch_policy = YKPIV_TOUCHPOLICY_ALWAYS;
    }
    else if (vendor_defined & CKA_TOUCH_NEVER) {
      touch_policy = YKPIV_TOUCHPOLICY_NEVER;
    }
    else
      return CKR_ATTRIBUTE_VALUE_INVALID;
  }

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

CK_RV COMMON_token_delete_cert(ykpiv_state *state, CK_ULONG cert_id) {

  if (ykpiv_save_object(state, cert_id, NULL, 0) != YKPIV_OK)
    return CKR_DEVICE_ERROR;

  return CKR_OK;
}

token_vendor_t get_token_vendor(vendor_id_t vid) {
  token_vendor_t v;

  switch (vid) {
  case YUBICO:
    v.get_token_label           = YUBICO_get_token_label;
    v.get_token_manufacturer    = YUBICO_get_token_manufacturer;
    v.get_token_model           = YUBICO_get_token_model;
    v.get_token_flags           = YUBICO_get_token_flags;
    v.get_token_version         = YUBICO_get_token_version;
    v.get_token_serial          = YUBICO_get_token_serial;
    v.get_token_mechanisms_num  = YUBICO_get_token_mechanisms_num;
    v.get_token_mechanism_list  = YUBICO_get_token_mechanism_list;
    v.get_token_mechanism_info  = YUBICO_get_token_mechanism_info;
    v.get_token_objects_num     = YUBICO_get_token_objects_num;
    v.get_token_object_list     = YUBICO_get_token_object_list;
    v.get_token_raw_certificate = YUBICO_get_token_raw_certificate;
    v.token_login               = COMMON_token_login;
    v.token_generate_key        = COMMON_token_generate_key;
    v.token_import_cert         = COMMON_token_import_cert;
    v.token_import_private_key  = COMMON_token_import_private_key;
    v.token_delete_cert         = COMMON_token_delete_cert;
    v.token_change_pin          = YUBICO_token_change_pin;
    break;

  case UNKNOWN:
  default:
    v.get_token_label           = NULL;
    v.get_token_manufacturer    = NULL;
    v.get_token_model           = NULL;
    v.get_token_flags           = NULL;
    v.get_token_version         = NULL;
    v.get_token_serial          = NULL;
    v.get_token_mechanisms_num  = NULL;
    v.get_token_mechanism_list  = NULL;
    v.get_token_mechanism_info  = NULL;
    v.get_token_objects_num     = NULL;
    v.get_token_object_list     = NULL;
    v.get_token_raw_certificate = NULL;
    v.token_login               = NULL;
    v.token_generate_key        = NULL;
    v.token_import_cert         = NULL;
    v.token_import_private_key  = NULL;
    v.token_delete_cert         = NULL;
  }

  return v;

}
