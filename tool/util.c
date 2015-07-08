 /*
 * Copyright (c) 2014-2015 Yubico AB
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

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#endif

#include <openssl/x509.h>

#include <ykpiv.h>

#include "cmdline.h"
#include "util.h"

FILE *open_file(const char *file_name, int mode) {
  FILE *file;
  if(!strcmp(file_name, "-")) {
    file = mode == INPUT ? stdin : stdout;
  } else {
    file = fopen(file_name, mode == INPUT ? "r" : "w");
    if(!file) {
      fprintf(stderr, "Failed opening '%s'!\n", file_name);
      return NULL;
    }
  }
  return file;
}

unsigned char get_algorithm(EVP_PKEY *key) {
  int type = EVP_PKEY_type(key->type);
  switch(type) {
    case EVP_PKEY_RSA:
      {
        RSA *rsa = EVP_PKEY_get1_RSA(key);
        int size = RSA_size(rsa);
        if(size == 256) {
          return YKPIV_ALGO_RSA2048;
        } else if(size == 128) {
          return YKPIV_ALGO_RSA1024;
        } else {
          fprintf(stderr, "Unuseable key of %d bits, only 1024 and 2048 is supported.\n", size * 8);
          return 0;
        }
      }
    case EVP_PKEY_EC:
      {
        EC_KEY *ec = EVP_PKEY_get1_EC_KEY(key);
        const EC_GROUP *group = EC_KEY_get0_group(ec);
        int curve = EC_GROUP_get_curve_name(group);
        if(curve == NID_X9_62_prime256v1) {
          return YKPIV_ALGO_ECCP256;
        } else if(curve == NID_secp384r1) {
          return YKPIV_ALGO_ECCP384;
        } else {
          fprintf(stderr, "Unknown EC curve %d\n", curve);
          return 0;
        }
      }
    default:
      fprintf(stderr, "Unknown algorithm %d.\n", type);
      return 0;
  }
}

X509_NAME *parse_name(const char *orig_name) {
  char name[1025];
  X509_NAME *parsed = NULL;
  char *ptr = name;
  char *part;

  if(strlen(orig_name) > 1024) {
    fprintf(stderr, "Name is to long!\n");
    return NULL;
  }
  strcpy(name, orig_name);

  if(*name != '/') {
    fprintf(stderr, "Name does not start with '/'!\n");
    return NULL;
  }
  parsed = X509_NAME_new();
  if(!parsed) {
    fprintf(stderr, "Failed to allocate memory\n");
    return NULL;
  }
  while((part = strtok(ptr, "/"))) {
    char *key;
    char *value;
    char *equals = strchr(part, '=');
    if(!equals) {
      fprintf(stderr, "The part '%s' doesn't seem to contain a =.\n", part);
      goto parse_err;
    }
    *equals++ = '\0';
    value = equals;
    key = part;

    ptr = NULL;
    if(!key) {
      fprintf(stderr, "Malformed name (%s)\n", part);
      goto parse_err;
    }
    if(!value) {
      fprintf(stderr, "Malformed name (%s)\n", part);
      goto parse_err;
    }
    if(!X509_NAME_add_entry_by_txt(parsed, key, MBSTRING_UTF8, (unsigned char*)value, -1, -1, 0)) {
      fprintf(stderr, "Failed adding %s=%s to name.\n", key, value);
      goto parse_err;
    }
  }
  return parsed;
parse_err:
  X509_NAME_free(parsed);
  return NULL;
}

void dump_hex(const unsigned char *buf, unsigned int len, FILE *output, bool space) {
  unsigned int i;
  for (i = 0; i < len; i++) {
    fprintf(output, "%02x%s", buf[i], space == true ? " " : "");
  }
  fprintf(output, "\n");
}

int get_length(const unsigned char *buffer, int *len) {
  if(buffer[0] < 0x81) {
    *len = buffer[0];
    return 1;
  } else if((*buffer & 0x7f) == 1) {
    *len = buffer[1];
    return 2;
  } else if((*buffer & 0x7f) == 2) {
    *len = (buffer[1] << 8) + buffer[2];
    return 3;
  }
  return 0;
}

int set_length(unsigned char *buffer, int length) {
  if(length < 0x80) {
    *buffer++ = length;
    return 1;
  } else if(length < 0xff) {
    *buffer++ = 0x81;
    *buffer++ = length;
    return 2;
  } else {
    *buffer++ = 0x82;
    *buffer++ = (length >> 8) & 0xff;
    *buffer++ = length & 0xff;
    return 3;
  }
}

int get_object_id(enum enum_slot slot) {
  int object;

  switch(slot) {
    case slot_arg_9a:
      object = YKPIV_OBJ_AUTHENTICATION;
      break;
    case slot_arg_9c:
      object = YKPIV_OBJ_SIGNATURE;
      break;
    case slot_arg_9d:
      object = YKPIV_OBJ_KEY_MANAGEMENT;
      break;
    case slot_arg_9e:
      object = YKPIV_OBJ_CARD_AUTH;
      break;
    case slot_arg_82:
      object = YKPIV_OBJ_RETIRED1;
      break;
    case slot_arg_83:
      object = YKPIV_OBJ_RETIRED2;
      break;
    case slot_arg_84:
      object = YKPIV_OBJ_RETIRED3;
      break;
    case slot_arg_85:
      object = YKPIV_OBJ_RETIRED4;
      break;
    case slot_arg_86:
      object = YKPIV_OBJ_RETIRED5;
      break;
    case slot_arg_87:
      object = YKPIV_OBJ_RETIRED6;
      break;
    case slot_arg_88:
      object = YKPIV_OBJ_RETIRED7;
      break;
    case slot_arg_89:
      object = YKPIV_OBJ_RETIRED8;
      break;
    case slot_arg_8a:
      object = YKPIV_OBJ_RETIRED9;
      break;
    case slot_arg_8b:
      object = YKPIV_OBJ_RETIRED10;
      break;
    case slot_arg_8c:
      object = YKPIV_OBJ_RETIRED11;
      break;
    case slot_arg_8d:
      object = YKPIV_OBJ_RETIRED12;
      break;
    case slot_arg_8e:
      object = YKPIV_OBJ_RETIRED13;
      break;
    case slot_arg_8f:
      object = YKPIV_OBJ_RETIRED14;
      break;
    case slot_arg_90:
      object = YKPIV_OBJ_RETIRED15;
      break;
    case slot_arg_91:
      object = YKPIV_OBJ_RETIRED16;
      break;
    case slot_arg_92:
      object = YKPIV_OBJ_RETIRED17;
      break;
    case slot_arg_93:
      object = YKPIV_OBJ_RETIRED18;
      break;
    case slot_arg_94:
      object = YKPIV_OBJ_RETIRED19;
      break;
    case slot_arg_95:
      object = YKPIV_OBJ_RETIRED20;
      break;
    case slot__NULL:
    default:
      object = 0;
  }
  return object;
}

bool set_component_with_len(unsigned char **in_ptr, const BIGNUM *bn, int element_len) {
  int real_len = BN_num_bytes(bn);
  *in_ptr += set_length(*in_ptr, element_len);
  if(real_len > element_len) {
    return false;
  }
  memset(*in_ptr, 0, (size_t)(element_len - real_len));
  *in_ptr += element_len - real_len;
  *in_ptr += BN_bn2bin(bn, *in_ptr);
  return true;
}

bool prepare_rsa_signature(const unsigned char *in, unsigned int in_len, unsigned char *out, unsigned int *out_len, int nid) {
  X509_SIG digestInfo;
  X509_ALGOR algor;
  ASN1_TYPE parameter;
  ASN1_OCTET_STRING digest;
  unsigned char data[1024];

  memcpy(data, in, in_len);

  digestInfo.algor = &algor;
  digestInfo.algor->algorithm = OBJ_nid2obj(nid);
  digestInfo.algor->parameter = &parameter;
  digestInfo.algor->parameter->type = V_ASN1_NULL;
  digestInfo.algor->parameter->value.ptr = NULL;
  digestInfo.digest = &digest;
  digestInfo.digest->data = data;
  digestInfo.digest->length = (int)in_len;
  *out_len = (unsigned int)i2d_X509_SIG(&digestInfo, &out);
  return true;
}

static unsigned const char sha1oid[] = {
  0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2B, 0x0E, 0x03, 0x02, 0x1A, 0x05, 0x00,
  0x04, 0x14
};

static unsigned const char sha256oid[] = {
  0x30, 0x31, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04,
  0x02, 0x01, 0x05, 0x00, 0x04, 0x20
};

static unsigned const char sha384oid[] = {
  0x30, 0x41, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04,
  0x02, 0x02, 0x05, 0x00, 0x04, 0x30
};

static unsigned const char sha512oid[] = {
  0x30, 0x51, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04,
  0x02, 0x03, 0x05, 0x00, 0x04, 0x40
};

const EVP_MD *get_hash(enum enum_hash hash, const unsigned char **oid, size_t *oid_len) {
  switch(hash) {
    case hash_arg_SHA1:
      if(oid) {
        *oid = sha1oid;
        *oid_len = sizeof(sha1oid);
      }
      return EVP_sha1();
    case hash_arg_SHA256:
      if(oid) {
        *oid = sha256oid;
        *oid_len = sizeof(sha256oid);
      }
      return EVP_sha256();
    case hash_arg_SHA384:
      if(oid) {
        *oid = sha384oid;
        *oid_len = sizeof(sha384oid);
      }
      return EVP_sha384();
    case hash_arg_SHA512:
      if(oid) {
        *oid = sha512oid;
        *oid_len = sizeof(sha512oid);
      }
      return EVP_sha512();
    case hash__NULL:
    default:
      return NULL;
  }
}

int get_hashnid(enum enum_hash hash, unsigned char algorithm) {
  switch(algorithm) {
    case YKPIV_ALGO_RSA1024:
    case YKPIV_ALGO_RSA2048:
      switch(hash) {
        case hash_arg_SHA1:
          return NID_sha1WithRSAEncryption;
        case hash_arg_SHA256:
          return NID_sha256WithRSAEncryption;
        case hash_arg_SHA384:
          return NID_sha384WithRSAEncryption;
        case hash_arg_SHA512:
          return NID_sha512WithRSAEncryption;
        case hash__NULL:
        default:
          return 0;
      }
    case YKPIV_ALGO_ECCP256:
    case YKPIV_ALGO_ECCP384:
      switch(hash) {
        case hash_arg_SHA1:
          return NID_ecdsa_with_SHA1;
        case hash_arg_SHA256:
          return NID_ecdsa_with_SHA256;
        case hash_arg_SHA384:
          return NID_ecdsa_with_SHA384;
        case hash_arg_SHA512:
          return NID_ecdsa_with_SHA512;
        case hash__NULL:
        default:
          return 0;
      }
    default:
      return 0;
  }
}

unsigned char get_piv_algorithm(enum enum_algorithm algorithm) {
  switch(algorithm) {
    case algorithm_arg_RSA2048:
      return YKPIV_ALGO_RSA2048;
    case algorithm_arg_RSA1024:
      return YKPIV_ALGO_RSA1024;
    case algorithm_arg_ECCP256:
      return YKPIV_ALGO_ECCP256;
    case algorithm_arg_ECCP384:
      return YKPIV_ALGO_ECCP384;
    case algorithm__NULL:
    default:
      return 0;
  }
}

unsigned char get_pin_policy(enum enum_pin_policy policy) {
  switch(policy) {
    case pin_policy_arg_never:
      return YKPIV_PINPOLICY_NEVER;
    case pin_policy_arg_once:
      return YKPIV_PINPOLICY_ONCE;
    case pin_policy_arg_always:
      return YKPIV_PINPOLICY_ALWAYS;
    case pin_policy__NULL:
    default:
      return 0;
  }
}

unsigned char get_touch_policy(enum enum_touch_policy policy) {
  switch(policy) {
    case touch_policy_arg_never:
      return YKPIV_TOUCHPOLICY_NEVER;
    case touch_policy_arg_always:
      return YKPIV_TOUCHPOLICY_ALWAYS;
    case touch_policy__NULL:
    default:
      return 0;
  }
}
