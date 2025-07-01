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

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#endif

#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/rsa.h>

#include "openssl-compat.h"
#include "ykpiv.h"

#include "util.h"

FILE *open_file(const char *file_name, enum file_mode mode) {
  FILE *file;
  const char *mod;
  if(!strcmp(file_name, "-")) {
    file = (mode == INPUT_TEXT || mode == INPUT_BIN) ? stdin : stdout;
  } else {
    switch (mode) {
    case INPUT_TEXT:
      mod = "r";
      break;
    case INPUT_BIN:
      mod = "rb";
      break;
    case OUTPUT_TEXT:
      mod = "w";
      break;
    case OUTPUT_BIN:
      mod = "wb";
      break;
    default:
      fprintf(stderr, "Invalid file mode.\n");
      return NULL;
      break;
    }
    file = fopen(file_name, mod);
    if(!file) {
      fprintf(stderr, "Failed opening '%s'!\n", file_name);
      return NULL;
    }
  }
  return file;
}

unsigned char get_algorithm(EVP_PKEY *key) {
  int type = EVP_PKEY_base_id(key);
  int size = EVP_PKEY_bits(key);
  switch(type) {
    case EVP_PKEY_RSA:
      {
        switch (size) {
          case 1024:
            return YKPIV_ALGO_RSA1024;
          case 2048:
            return YKPIV_ALGO_RSA2048;
          case 3072:
            return YKPIV_ALGO_RSA3072;
          case 4096:
            return YKPIV_ALGO_RSA4096;
          default:
            fprintf(stderr, "Unusable RSA key of %d bits, only 1024, 2048 3072 and 4096 are supported.\n", size);
            return 0;
        }
      }
    case EVP_PKEY_EC:
      {
        if(size == 256) {
          return YKPIV_ALGO_ECCP256;
        } else if(size == 384) {
          return YKPIV_ALGO_ECCP384;
        } else {
          fprintf(stderr, "Unusable EC key of %d bits, only 256 and 384 are supported.\n", size);
          return 0;
        }
      }
#if (OPENSSL_VERSION_NUMBER >= 0x10100000L)
    case EVP_PKEY_ED25519:
      return YKPIV_ALGO_ED25519;
    case EVP_PKEY_X25519:
      return YKPIV_ALGO_X25519;
#endif
    default:
      fprintf(stderr, "Unknown algorithm %d.\n", type);
      return 0;
  }
}

static char *string_parser(char *str_orig, char delimiter, char *str_found) {
  char escape_char = '\\';
  int f = 0;
  char *p = str_orig;
  while (*p == delimiter) {
    p++;
  }
  for (; *p; p++) {
    if (*p != delimiter) {
      str_found[f++] = *p;
    } else if (*p == delimiter) {
      if ((*(p - 1) == escape_char &&
           *(p - 2) == escape_char)) { // The escape_char before the delimiter is escaped => the delimiter is still in effect
        str_found[f - 1] = '\0';
        return ++p;
      } else if (*(p - 1) == escape_char && *(p - 2) != escape_char) { // the delimiter is escaped
        str_found[f - 1] = delimiter;
      } else { // nothing is escaped
        str_found[f] = '\0';
        return ++p;
      }
    }
  }
  str_found[f] = '\0';
  return NULL;
}

X509_NAME *parse_name(const char *orig_name) {
  char name[1025] = {0};
  char part[1025] = {0};
  X509_NAME *parsed = NULL;
  char *ptr = name;

  if(strlen(orig_name) > 1024) {
    fprintf(stderr, "Name is too long!\n");
    return NULL;
  }
  strncpy(name, orig_name, sizeof(name));
  name[sizeof(name) - 1] = 0;

  if(*name != '/' || name[strlen(name)-1] != '/') {
    fprintf(stderr, "Name does not start or does not end with '/'!\n");
    return NULL;
  }
  parsed = X509_NAME_new();
  if(!parsed) {
    fprintf(stderr, "Failed to allocate memory\n");
    return NULL;
  }
  while((ptr = string_parser(ptr, '/', part))) {
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

size_t read_data(unsigned char *buf, size_t len, FILE* input, enum enum_format format) {
  char raw_buf[YKPIV_OBJ_MAX_SIZE * 2 + 1] = {0};
  size_t raw_len = fread(raw_buf, 1, sizeof(raw_buf), input);
  switch(format) {
    case format_arg_hex:
      if(raw_len > 0 && raw_buf[raw_len - 1] == '\n') {
        raw_len -= 1;
      }
      if(ykpiv_hex_decode(raw_buf, raw_len, buf, &len) != YKPIV_OK) {
        return 0;
      }
      return len;
    case format_arg_base64:
      {
        int read;
        BIO *b64 = BIO_new(BIO_f_base64());
        BIO *bio = BIO_new_mem_buf(raw_buf, raw_len);
        BIO_push(b64, bio);
        read = BIO_read(b64, buf, len);
        BIO_free_all(b64);
        if(read <= 0) {
          return 0;
        } else {
          return (size_t)read;
        }
      }
      break;
    case format_arg_binary:
      if(raw_len > len) {
        return 0;
      }
      memcpy(buf, raw_buf, raw_len);
      return raw_len;
    case format__NULL:
    default:
      return 0;
  }
}

void dump_data(const unsigned char *buf, unsigned int len, FILE *output, bool space, enum enum_format format) {
  switch(format) {
    case format_arg_hex:
      {
        char tmp[YKPIV_OBJ_MAX_SIZE * 3 + 1] = {0};
        unsigned int i;
        unsigned int step = 2;
        if(space) step += 1;
        if(len > YKPIV_OBJ_MAX_SIZE) {
          return;
        }
        for (i = 0; i < len; i++) {
          sprintf(tmp + i * step, "%02x%s", buf[i], space == true ? " " : "");
        }
        fprintf(output, "%s\n", tmp);
      }
      return;
    case format_arg_base64:
      {
        BIO *b64 = BIO_new(BIO_f_base64());
        BIO *bio = BIO_new_fp(output, BIO_NOCLOSE);
        BIO_push(b64, bio);
        if(BIO_write(b64, buf, (int)len) <= 0) {
          fprintf(stderr, "Failed to write data in base64 format\n");
        }
        (void)BIO_flush(b64);
        BIO_free_all(b64);
      }
      return;
    case format_arg_binary:
      fwrite(buf, 1, len, output);
      return;
    case format__NULL:
    default:
      return;
  }
}

unsigned long get_length_size(unsigned long length) {
  if (length < 0x80) {
    return 1;
  } else if (length < 0x100) {
    return 2;
  } else {
    return 3;
  }
}

unsigned long set_length(unsigned char *buffer, unsigned long length) {
  if(length < 0x80) {
    *buffer++ = length;
    return 1;
  } else if(length < 0x100) {
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

unsigned long get_length(const unsigned char *buffer, const unsigned char *end, unsigned long *len) {
  if(buffer + 1 <= end && buffer[0] < 0x80) {
    *len = buffer[0];
    return buffer + 1 + *len <= end ? 1 : 0;
  } else if(buffer + 2 <= end && buffer[0] == 0x81) {
    *len = buffer[1];
    return buffer + 2 + *len <= end ? 2 : 0;
  } else if(buffer + 3 <= end && buffer[0] == 0x82) {
    size_t tmp = buffer[1];
    *len = (tmp << 8) + buffer[2];
    return buffer + 3 + *len <= end ? 3 : 0;
  }
  *len = 0;
  return 0;
}

int get_curve_name(int key_algorithm) {
  if(key_algorithm == YKPIV_ALGO_ECCP256) {
    return NID_X9_62_prime256v1;
  } else if(key_algorithm == YKPIV_ALGO_ECCP384) {
    return NID_secp384r1;
#if (OPENSSL_VERSION_NUMBER >= 0x10100000L)
  } else if(key_algorithm == YKPIV_ALGO_ED25519) {
    return NID_ED25519;
  } else if(key_algorithm == YKPIV_ALGO_X25519) {
    return NID_X25519;
#endif
  }
  return 0;
}

int get_slot_hex(enum enum_slot slot_enum) {
  int slot = -1;

  switch (slot_enum) {
    case slot_arg_9a:
      slot = 0x9a;
      break;
    case slot_arg_9c:
    case slot_arg_9d:
    case slot_arg_9e:
      slot = 0x9c + ((int)slot_enum - (int)slot_arg_9c);
      break;
    case slot_arg_82:
    case slot_arg_83:
    case slot_arg_84:
    case slot_arg_85:
    case slot_arg_86:
    case slot_arg_87:
    case slot_arg_88:
    case slot_arg_89:
    case slot_arg_8a:
    case slot_arg_8b:
    case slot_arg_8c:
    case slot_arg_8d:
    case slot_arg_8e:
    case slot_arg_8f:
    case slot_arg_90:
    case slot_arg_91:
    case slot_arg_92:
    case slot_arg_93:
    case slot_arg_94:
    case slot_arg_95:
      slot = 0x82 + ((int)slot_enum - (int)slot_arg_82);
      break;
    case slot_arg_f9:
      slot = 0xf9;
      break;
    case slot__NULL:
    default:
      slot = -1;
  }

  return slot;
}

bool set_component(unsigned char *in_ptr, const BIGNUM *bn, int *element_len) {
  if(BN_num_bytes(bn) > *element_len) return false;
  *element_len = BN_bn2bin(bn, in_ptr);
  return true;
}

bool prepare_rsa_signature(const unsigned char *in, unsigned int in_len, unsigned char *out, unsigned int *out_len, int nid) {
  X509_SIG *digestInfo;
  X509_ALGOR *algor;
  ASN1_OCTET_STRING *digest;
  unsigned char data[1024] = {0};

  if(in_len > sizeof(data))
    return false;

  memcpy(data, in, in_len);

  digestInfo = X509_SIG_new();
  X509_SIG_getm(digestInfo, &algor, &digest);
  algor->algorithm = OBJ_nid2obj(nid);
  if(X509_ALGOR_set0(algor, OBJ_nid2obj(nid), V_ASN1_NULL, NULL) == 0) {
    fprintf(stderr, "Failed to set X509 Algorithm\n");
    X509_SIG_free(digestInfo);
    return false;
  }
  ASN1_STRING_set(digest, data, in_len);
  *out_len = (unsigned int)i2d_X509_SIG(digestInfo, &out);
  X509_SIG_free(digestInfo);
  return true;
}

bool read_pw(const char *name, char *pwbuf, size_t pwbuflen, int verify, int stdin_input) {
  #define READ_PW_PROMPT_BASE "Enter %s: "
  char prompt[sizeof(READ_PW_PROMPT_BASE) + 32] = {0};
  int ret;

  if (pwbuflen < 1) {
    fprintf(stderr, "Failed to read %s: buffer too small.", name);
    return false;
  }

  if(stdin_input) {
    fprintf(stdout, "%s\n", name);
    if(fgets(pwbuf, pwbuflen, stdin)) {
      if(pwbuf[strlen(pwbuf) - 1] == '\n') {
        pwbuf[strlen(pwbuf) - 1] = '\0';
      }
      return true;
    } else {
      return false;
    }
  }

  ret = snprintf(prompt, sizeof(prompt), READ_PW_PROMPT_BASE, name);
  if (ret < 0 || ret >= sizeof(prompt)) {
    fprintf(stderr, "Failed to read %s: snprintf failed.\n", name);
    return false;
  }

  if (0 != EVP_read_pw_string(pwbuf, pwbuflen-1, prompt, verify)) {
    fprintf(stderr, "Retrieving %s failed.\n", name);
    return false;
  }
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
    case YKPIV_ALGO_RSA3072:
    case YKPIV_ALGO_RSA4096:
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
#if (OPENSSL_VERSION_NUMBER >= 0x10100000L)
    case YKPIV_ALGO_ED25519:
      return  NID_ED25519;
    case YKPIV_ALGO_X25519:
      return NID_X25519;
#endif
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
    case algorithm_arg_RSA3072:
      return YKPIV_ALGO_RSA3072;
    case algorithm_arg_RSA4096:
      return YKPIV_ALGO_RSA4096;
    case algorithm_arg_ECCP256:
      return YKPIV_ALGO_ECCP256;
    case algorithm_arg_ECCP384:
      return YKPIV_ALGO_ECCP384;
    case algorithm_arg_ED25519:
      return YKPIV_ALGO_ED25519;
    case algorithm_arg_X25519:
      return YKPIV_ALGO_X25519;
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
    case pin_policy_arg_matchonce:
      return YKPIV_PINPOLICY_MATCH_ONCE;
    case pin_policy_arg_matchalways:
      return YKPIV_PINPOLICY_MATCH_ALWAYS;
    case pin_policy__NULL:
    default:
      return YKPIV_PINPOLICY_DEFAULT;
  }
}

unsigned char get_touch_policy(enum enum_touch_policy policy) {
  switch(policy) {
    case touch_policy_arg_never:
      return YKPIV_TOUCHPOLICY_NEVER;
    case touch_policy_arg_always:
      return YKPIV_TOUCHPOLICY_ALWAYS;
    case touch_policy_arg_cached:
      return YKPIV_TOUCHPOLICY_CACHED;
    case touch_policy__NULL:
    default:
      return YKPIV_TOUCHPOLICY_DEFAULT;
  }
}

int SSH_write_X509(FILE *fp, X509 *x) {

  EVP_PKEY *pkey = NULL;
  int ret = 0;

  pkey = X509_get_pubkey(x);

  if (pkey == NULL) {
    return ret;
  }

  switch (EVP_PKEY_base_id(pkey)) {
  case EVP_PKEY_RSA: {
    const RSA *rsa;
    unsigned char n[256] = {0};
    const BIGNUM *bn_n;

    char rsa_id[] = "\x00\x00\x00\x07ssh-rsa";
    char rsa_f4[] = "\x00\x00\x00\x03\x01\x00\x01";

    rsa = EVP_PKEY_get0_RSA(pkey);
    if(rsa == NULL) {
      break;
    }
    RSA_get0_key(rsa, &bn_n, NULL, NULL);

    int len = RSA_size(rsa);
    if (!set_component(n, bn_n, &len)) {
      break;
    }

    uint32_t bytes = len;
    char len_buf[5] = {0};
    len = 4;

    len_buf[0] = (bytes >> 24) & 0x000000ff;
    len_buf[1] = (bytes << 16) & 0x000000ff;
    len_buf[2] = (bytes >> 8) & 0x000000ff;
    len_buf[3] = (bytes) & 0x000000ff;

    if (n[0] >= 0x80) {
      // High bit set, need an extra byte
      len++;
      len_buf[3]++;
      len_buf[4] = 0;
    }

    fprintf(fp, "ssh-rsa ");

    BIO *b64 = BIO_new(BIO_f_base64());
    BIO *bio = BIO_new_fp(fp, BIO_NOCLOSE);

    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO_push(b64, bio);

    if(BIO_write(b64, rsa_id, sizeof(rsa_id) - 1) <= 0 ) {
      fprintf(stderr, "Failed to write RSA ID\n");
      BIO_free_all(b64);
      break;
    }
    if(BIO_write(b64, rsa_f4, sizeof(rsa_f4) - 1) <= 0) {
      fprintf(stderr, "Failed to write RSA f4\n");
      BIO_free_all(b64);
      break;
    }
    if(BIO_write(b64, len_buf, len) <= 0) {
      fprintf(stderr, "Failed to write RSA length\n");
      BIO_free_all(b64);
      break;
    }
    if(BIO_write(b64, n, bytes) <= 0) {
      fprintf(stderr, "Failed to write RSA n component\n");
      BIO_free_all(b64);
      break;
    }
    (void)BIO_flush(b64);
    BIO_free_all(b64);

    ret = 1;

  } break;

  case EVP_PKEY_EC:
    break;
  }

  EVP_PKEY_free(pkey);

  return ret;

}

int get_ec_pubkey_from_bytes(int curve_name, uint8_t *point, size_t point_len, EVP_PKEY **pkey) {
  int rc = 0;
  EC_POINT *ecpoint = NULL;
  EC_KEY *eckey = NULL;
  EC_GROUP *group = EC_GROUP_new_by_curve_name(curve_name);
  if(group == NULL)
    return YKPIV_MEMORY_ERROR;
  EC_GROUP_set_asn1_flag(group, OPENSSL_EC_NAMED_CURVE);
  eckey = EC_KEY_new();
  if(eckey == NULL) {
    rc = YKPIV_MEMORY_ERROR;
    goto create_ec_cleanup;
  }
  if(EC_KEY_set_group(eckey, group) <= 0) {
    rc = YKPIV_GENERIC_ERROR;
    goto create_ec_cleanup;
  }
  ecpoint = EC_POINT_new(group);
  if(ecpoint == NULL) {
    rc = YKPIV_MEMORY_ERROR;
    goto create_ec_cleanup;
  }
  if(EC_POINT_oct2point(group, ecpoint, point, point_len, NULL) <= 0) {
    rc = YKPIV_ARGUMENT_ERROR;
    goto create_ec_cleanup;
  }
  if(EC_KEY_set_public_key(eckey, ecpoint) <= 0) {
    rc = YKPIV_GENERIC_ERROR;
    goto create_ec_cleanup;
  }
  *pkey = EVP_PKEY_new();
  if(*pkey == NULL) {
    rc = YKPIV_MEMORY_ERROR;
    goto create_ec_cleanup;
  }
  if(EVP_PKEY_assign_EC_KEY(*pkey, eckey) <= 0) {
    rc = YKPIV_GENERIC_ERROR;
    goto create_ec_cleanup;
  }

create_ec_cleanup:
  EC_GROUP_clear_free(group);
  if(ecpoint != NULL) {
    EC_POINT_clear_free(ecpoint);
  }
  if(rc != YKPIV_OK && eckey != NULL) {
    EC_KEY_free(eckey);
  }
  return rc;
}

static int do_create_rsa_key(uint8_t *mod, size_t mod_len, uint8_t *exp, size_t exp_len, EVP_PKEY **pkey) {
  ykpiv_rc rc;
  RSA *rsa = NULL;
  BIGNUM *n = BN_bin2bn(mod, mod_len, 0);
  if(n == NULL)
    return YKPIV_MEMORY_ERROR;
  BIGNUM *e = BN_bin2bn(exp, exp_len, 0);
  if(e == NULL) {
    rc = YKPIV_MEMORY_ERROR;
    goto create_rsa_cleanup;
  }
  rsa = RSA_new();
  if(rsa == NULL) {
    rc = YKPIV_MEMORY_ERROR;
    goto create_rsa_cleanup;
  }
  if(RSA_set0_key(rsa, n, e, NULL) <= 0) {
    rc = YKPIV_GENERIC_ERROR;
    goto create_rsa_cleanup;
  }
  EVP_PKEY_free(*pkey);
  *pkey = EVP_PKEY_new();
  if(*pkey == NULL) {
    rc = YKPIV_MEMORY_ERROR;
    goto create_rsa_cleanup;
  }
  if(EVP_PKEY_assign_RSA(*pkey, rsa) <= 0) {
    rc = YKPIV_GENERIC_ERROR;
    goto create_rsa_cleanup;
  }
  return YKPIV_OK;
create_rsa_cleanup:
  BN_free(n);
  if(e != NULL) {
    BN_free(e);
  }
  if(rsa != NULL) {
    RSA_free(rsa);
  }
  return rc;
}

int do_create_public_key(uint8_t *in, size_t in_len, uint8_t algorithm, EVP_PKEY **pkey) {
  uint8_t *eob = in + in_len;
  unsigned long offs, len;
  if (YKPIV_IS_RSA(algorithm)) {
    if(in >= eob)
      return YKPIV_GENERIC_ERROR;

    if (*in++ != 0x81)
      return YKPIV_GENERIC_ERROR;

    offs = get_length(in, eob, &len);
    if(!offs)
      return YKPIV_GENERIC_ERROR;

    in += offs;

    uint8_t *mod = in;
    size_t mod_len = len;

    in += len;

    if(in >= eob)
      return YKPIV_GENERIC_ERROR;

    if (*in++ != 0x82)
      return YKPIV_GENERIC_ERROR;

    offs = get_length(in, eob, &len);
    if(!offs)
      return YKPIV_GENERIC_ERROR;

    in += offs;
    return do_create_rsa_key(mod, mod_len, in, len, pkey);
  } else {
    if(in >= eob)
      return YKPIV_GENERIC_ERROR;

    if(*in++ != 0x86)
      return YKPIV_GENERIC_ERROR;

    offs = get_length(in, eob, &len);
    if(!offs)
      return YKPIV_GENERIC_ERROR;

    in += offs;

    if (YKPIV_IS_EC(algorithm)) {
      int curve_name = get_curve_name(algorithm);
      return get_ec_pubkey_from_bytes(curve_name, in, len, pkey);
#if (OPENSSL_VERSION_NUMBER >= 0x10100000L)
    } else if (YKPIV_IS_25519(algorithm)) {
      if (algorithm == YKPIV_ALGO_ED25519) {
        *pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, in, len);
      } else {
        *pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, in, len);
      }
      if (*pkey == NULL) {
        return YKPIV_MEMORY_ERROR;
      }
      return YKPIV_OK;
#endif
    }
  }
  fprintf(stderr, "Unsupported key algorithm\n");
  return YKPIV_NOT_SUPPORTED;
}