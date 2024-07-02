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
#include <locale.h>
#include <limits.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "ykpiv.h"

#ifdef _WIN32
#include <windows.h>
#include <openssl/applink.c>
#else
#include <unistd.h>
#endif

#include "../common/openssl-compat.h"
#include <openssl/bn.h>
#include <openssl/des.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/x509v3.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>
#include <zlib.h>

#include "cmdline.h"
#include "../common/util.h"

#define MAX(a,b) (a) > (b) ? (a) : (b)

#define CHUID 0
#define CCC 1

#define MAX_OID_LEN 19

#define KEY_LEN 32

#define YKPIV_ATTESTATION_OID "1.3.6.1.4.1.41482.3"

static enum file_mode key_file_mode(enum enum_key_format fmt, bool output) {
  if (fmt == key_format_arg_PEM) {
    if (output) {
      return OUTPUT_TEXT;
    }
    return INPUT_TEXT;
  }
  if (output) {
    return OUTPUT_BIN;
  }
  return INPUT_BIN;
}

static enum file_mode data_file_mode(enum enum_format fmt, bool output) {
  if (fmt == format_arg_binary) {
    if (output) {
      return OUTPUT_BIN;
    }
    return INPUT_BIN;
  }
  if (output) {
    return OUTPUT_TEXT;
  }
  return INPUT_TEXT;
}

static void print_version(ykpiv_state *state, const char *output_file_name) {
  char version[7] = {0};
  FILE *output_file = open_file(output_file_name, OUTPUT_TEXT);
  if(!output_file) {
    return;
  }

  if(ykpiv_get_version(state, version, sizeof(version)) == YKPIV_OK) {
    fprintf(output_file, "Application version %s found.\n", version);
  } else {
    fprintf(stderr, "Failed to retrieve application version.\n");
  }

  if(output_file != stdout) {
    fclose(output_file);
  }
}

static bool sign_data(ykpiv_state *state, const unsigned char *in, size_t len, unsigned char *out,
    size_t *out_len, unsigned char algorithm, int key) {

  unsigned char signinput[1024] = {0};
  if(YKPIV_IS_RSA(algorithm)) {
    size_t padlen = 0;
    switch (algorithm) {
      case YKPIV_ALGO_RSA1024:
        padlen = 128;
        break;
      case YKPIV_ALGO_RSA2048:
        padlen = 256;
        break;
      case YKPIV_ALGO_RSA3072:
        padlen = 384;
        break;
      case YKPIV_ALGO_RSA4096:
        padlen = 512;
        break;
      default:
        fprintf(stderr, "Unknown RSA algorithm.\n");
        return false;
    }
    if (RSA_padding_add_PKCS1_type_1(signinput, padlen, in, len) == 0) {
      fprintf(stderr, "Failed adding padding.\n");
      return false;
    }
    in = signinput;
    len = padlen;
  }
  ykpiv_rc rc;
  if((rc = ykpiv_sign_data(state, in, len, out, out_len, algorithm, key)) == YKPIV_OK) {
    return true;
  }
  fprintf(stderr, "Failed signing data: %s.\n", ykpiv_strerror(rc));
  return false;
}

#if !((OPENSSL_VERSION_NUMBER < 0x10100000L) || defined(LIBRESSL_VERSION_NUMBER))
static int ec_key_ex_data_idx = -1;

struct internal_key {
  ykpiv_state *state;
  int algorithm;
  int key;
  const unsigned char *oid;
  size_t oid_len;
};

static int yk_rsa_meth_finish(RSA *rsa) {
  free(RSA_meth_get0_app_data(RSA_get_method(rsa)));
  return 1;
}

static int yk_rsa_meth_sign(int dtype, const unsigned char *m, unsigned int m_length,
    unsigned char *sigret, unsigned int *siglen, const RSA *rsa) {
  size_t yk_siglen = RSA_size(rsa);
  const RSA_METHOD *meth = RSA_get_method(rsa);
  const struct internal_key *key = RSA_meth_get0_app_data(meth);
  unsigned char message[256] = {0};

  if(key->oid_len) {
    memcpy(message, key->oid, key->oid_len);
    memcpy(message + key->oid_len, m, m_length);
    m_length += key->oid_len;
    m = message;
  }
  if (sign_data(key->state, m, m_length, sigret, &yk_siglen, key->algorithm, key->key)) {
    *siglen = (unsigned int)yk_siglen;
    return 1;
  }

  return 0;
}

static void yk_ec_meth_finish(EC_KEY *ec) {
  free(EC_KEY_get_ex_data(ec, ec_key_ex_data_idx));
}

static int yk_ec_meth_sign(int type, const unsigned char *dgst, int dlen,
    unsigned char *sig, unsigned int *siglen, const BIGNUM *kinv,
    const BIGNUM *r, EC_KEY *ec) {
  size_t yk_siglen = ECDSA_size(ec);
  const struct internal_key *key = EC_KEY_get_ex_data(ec, ec_key_ex_data_idx);
  if (sign_data(key->state, dgst, dlen, sig, &yk_siglen, key->algorithm, key->key)) {
    *siglen = (unsigned int)yk_siglen;
    return 1;
  }

  return 0;
}

static EVP_PKEY* wrap_public_key(ykpiv_state *state, int algorithm, EVP_PKEY *public_key, 
    int key, const unsigned char *oid, size_t oid_len) {
  struct internal_key *int_key = malloc(sizeof(struct internal_key));
  int_key->state = state;
  int_key->algorithm = algorithm;
  int_key->key = key;
  int_key->oid = oid;
  int_key->oid_len = oid_len;
  EVP_PKEY *pkey = EVP_PKEY_new();
  if (YKPIV_IS_RSA(algorithm)) {
    const RSA *pk = EVP_PKEY_get0_RSA(public_key);
    RSA_METHOD *meth = RSA_meth_dup(RSA_get_default_method());
    if(RSA_meth_set0_app_data(meth, int_key) != 1) {
      fprintf(stderr, "Failed to set RSA data\n");
    }
    if(RSA_meth_set_finish(meth, yk_rsa_meth_finish) != 1) {
      fprintf(stderr, "Failed to set RSA finish method\n");
    }
    if(RSA_meth_set_sign(meth, yk_rsa_meth_sign) != 1) {
      fprintf(stderr, "Failed to set RSA sign method\n");
    }
    RSA *sk = RSA_new();
    RSA_set0_key(sk, BN_dup(RSA_get0_n(pk)), BN_dup(RSA_get0_e(pk)), NULL);
    if(RSA_set_method(sk, meth) != 1) {
      fprintf(stderr, "Failed to set RSA key method\n");
    }
    EVP_PKEY_assign_RSA(pkey, sk);
  }
  else if(YKPIV_IS_EC(algorithm)){
    const EC_KEY *ec = EVP_PKEY_get0_EC_KEY(public_key);
    EC_KEY_METHOD *meth = EC_KEY_METHOD_new(EC_KEY_get_method(ec));
    EC_KEY_METHOD_set_init(meth, NULL, yk_ec_meth_finish, NULL, NULL, NULL, NULL);
    EC_KEY_METHOD_set_sign(meth, yk_ec_meth_sign, NULL, NULL);
    EC_KEY *sk = EC_KEY_new();
    EC_KEY_set_group(sk, EC_KEY_get0_group(ec));
    EC_KEY_set_public_key(sk, EC_KEY_get0_public_key(ec));
    if (ec_key_ex_data_idx == -1)
      ec_key_ex_data_idx = EC_KEY_get_ex_new_index(0, NULL, NULL, NULL, NULL);
    if(EC_KEY_set_ex_data(sk, ec_key_ex_data_idx, int_key) != 1) {
      fprintf(stderr, "Failed to set EC data\n");
    }
    if(EC_KEY_set_method(sk, meth) != 1) {
      fprintf(stderr, "Failed to wrap public EC key\n");
    }
    EVP_PKEY_assign_EC_KEY(pkey, sk);
  }
  return pkey;
}
#endif

static bool move_key(ykpiv_state *state, int from_slot, int to_slot) {
  bool ret = false;
  ykpiv_rc res;

  res = ykpiv_move_key(state, (uint8_t) (from_slot & 0xFF), (uint8_t) (to_slot & 0xFF));
  if (res != YKPIV_OK) {
    fprintf(stderr, "Failed to move key.\n");
  } else {
    ret = true;
  }
  return ret;
}

static bool generate_key(ykpiv_state *state, enum enum_slot slot,
    enum enum_algorithm algorithm, const char *output_file_name,
    enum enum_key_format key_format, enum enum_pin_policy pin_policy,
    enum enum_touch_policy touch_policy) {
  int key = 0;
  bool ret = false;
  ykpiv_rc res;
  FILE *output_file = NULL;
  EVP_PKEY *public_key = NULL;
  RSA *rsa = NULL;
  EC_KEY *eckey = NULL;
  EC_GROUP *group = NULL;
  EC_POINT *ecpoint = NULL;
  uint8_t *mod = NULL;
  uint8_t *exp = NULL;
  uint8_t *point = NULL;
  size_t mod_len = 0;
  size_t exp_len = 0;
  size_t point_len = 0;

  key = get_slot_hex(slot);

  output_file = open_file(output_file_name, key_file_mode(key_format, true));
  if(!output_file) {
    return false;
  }

  if(algorithm == algorithm_arg_RSA1024) {
    fprintf(stderr, "\nWARNING. The use of RSA1024 is discouraged by the National Institute of Standards "
                         "and Technology (NIST). See https://www.yubico.com/blog/comparing-asymmetric-encryption-algorithms\n\n");
  }

  res = ykpiv_util_generate_key(state,
                                (uint8_t)(key & 0xFF),
                                get_piv_algorithm(algorithm),
                                get_pin_policy(pin_policy),
                                get_touch_policy(touch_policy),
                                &mod,
                                &mod_len,
                                &exp,
                                &exp_len,
                                &point,
                                &point_len);
  if (res != YKPIV_OK) {
    fprintf(stderr, "Key generation failed.\n");
    goto generate_out;
  }

  if (key_format == key_format_arg_PEM) {
    public_key = EVP_PKEY_new();
    switch (algorithm) {
      case algorithm_arg_RSA1024:
      case algorithm_arg_RSA2048:
      case algorithm_arg_RSA3072:
      case algorithm_arg_RSA4096: {
        BIGNUM *bignum_n = NULL;
        BIGNUM *bignum_e = NULL;
        rsa = RSA_new();
        bignum_n = BN_bin2bn(mod, mod_len, NULL);
        if (bignum_n == NULL) {
          fprintf(stderr, "Failed to parse public key modulus.\n");
          goto generate_out;
        }
        bignum_e = BN_bin2bn(exp, exp_len, NULL);
        if (bignum_e == NULL) {
          fprintf(stderr, "Failed to parse public key exponent.\n");
          goto generate_out;
        }

        if (RSA_set0_key(rsa, bignum_n, bignum_e, NULL) != 1) {
          fprintf(stderr, "Failed to set RSA key\n");
          goto generate_out;
        }
        if (EVP_PKEY_set1_RSA(public_key, rsa) != 1) {
          fprintf(stderr, "Failed to set RSA public key\n");
          goto generate_out;
        }
      }
        break;
      case algorithm_arg_ECCP256:
      case algorithm_arg_ECCP384: {
        int nid;

        if (algorithm == algorithm_arg_ECCP256) {
          nid = NID_X9_62_prime256v1;
        } else {
          nid = NID_secp384r1;
        }
        eckey = EC_KEY_new();
        group = EC_GROUP_new_by_curve_name(nid);
        EC_GROUP_set_asn1_flag(group, OPENSSL_EC_NAMED_CURVE);
        if (EC_KEY_set_group(eckey, group) != 1) {
          fprintf(stderr, "Failed to set EC group.\n");
          goto generate_out;
        }
        ecpoint = EC_POINT_new(group);

        if (!EC_POINT_oct2point(group, ecpoint, point, point_len, NULL)) {
          fprintf(stderr, "Failed to load public point.\n");
          goto generate_out;
        }
        if (!EC_KEY_set_public_key(eckey, ecpoint)) {
          fprintf(stderr, "Failed to set the public key.\n");
          goto generate_out;
        }
        if (EVP_PKEY_set1_EC_KEY(public_key, eckey) != 1) {
          fprintf(stderr, "Failed to set EC public key.\n");
          goto generate_out;
        }
      }
        break;
#if (OPENSSL_VERSION_NUMBER >= 0x10100000L)
      case algorithm_arg_ED25519:
        public_key = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, point, point_len);
        break;
      case algorithm_arg_X25519:
        public_key = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, point, point_len);
        break;
#else
      case algorithm_arg_ED25519:
      case algorithm_arg_X25519:
        fprintf(stderr, "Key was generated successfully but a public key cannot be parsed due to too old OpenSSL version. "
                        "Upgrade OpenSSL to at least 1.1 or use attestation command to get a signed certificate instead.\n");
        return true;
#endif
      default:
        fprintf(stderr, "Wrong algorithm.\n");
    }
    if(PEM_write_PUBKEY(output_file, public_key) == 1) {
      ret = true;
    } else {
      fprintf(stderr, "Failed to write public key in PEM format\n");
      goto generate_out;
    }
  } else {
    fprintf(stderr, "Only PEM is supported as public_key output.\n");
    goto generate_out;
  }

generate_out:
  if (output_file != stdout) {
    fclose(output_file);
  }
  if (group) {
    EC_GROUP_clear_free(group);
  }
  if (ecpoint) {
    EC_POINT_free(ecpoint);
  }
  if (eckey) {
    EC_KEY_free(eckey);
  }
  if (rsa) {
    RSA_free(rsa);
  }
  if (public_key) {
    EVP_PKEY_free(public_key);
  }
  if (point) {
    ykpiv_util_free(state, point);
  }
  if (mod) {
    ykpiv_util_free(state, mod);
  }
  if (exp) {
    ykpiv_util_free(state, exp);
  }

  return ret;
}

static bool reset(ykpiv_state *state) {
  return ykpiv_util_reset(state) == YKPIV_OK;
}

static bool set_pin_retries(ykpiv_state *state, int pin_retries, int puk_retries, int verbose) {
  ykpiv_rc res;

  if(verbose) {
    fprintf(stderr, "Setting pin retries to %d and puk retries to %d.\n", pin_retries, puk_retries);
  }
  res = ykpiv_set_pin_retries(state, pin_retries, puk_retries);
  if (res == YKPIV_RANGE_ERROR) {
    fprintf(stderr, "pin and puk retries must be between 1 and 255.\n");
  }
  return res == YKPIV_OK;
}

static bool import_key(ykpiv_state *state, enum enum_key_format key_format,
                       const char *input_file_name, enum enum_slot slot, char *password,
                       enum enum_pin_policy pin_policy, enum enum_touch_policy touch_policy) {
  int key = 0;
  FILE *input_file = NULL;
  EVP_PKEY *private_key = NULL;
  PKCS12 *p12 = NULL;
  X509 *cert = NULL;
  bool ret = false;
  ykpiv_rc rc = YKPIV_GENERIC_ERROR;

  key = get_slot_hex(slot);

  input_file = open_file(input_file_name, key_file_mode(key_format, false));
  if(!input_file) {
    return false;
  }

  if(isatty(fileno(input_file))) {
    fprintf(stderr, "Please paste the private key...\n");
  }

  if(key_format == key_format_arg_PEM) {
    private_key = PEM_read_PrivateKey(input_file, NULL, NULL, password);
    if(!private_key) {
      fprintf(stderr, "Failed loading private key for import.\n");
      goto import_out;
    }
  } else if(key_format == key_format_arg_PKCS12) {
    p12 = d2i_PKCS12_fp(input_file, NULL);
    if(!p12) {
      fprintf(stderr, "Failed to load PKCS12 from file.\n");
      goto import_out;
    }
    if(PKCS12_parse(p12, password, &private_key, &cert, NULL) == 0 || private_key == NULL) {
      fprintf(stderr, "Failed to parse PKCS12 structure. (wrong password?)\n");
      goto import_out;
    }
  } else {
    /* TODO: more formats go here */
    fprintf(stderr, "Unknown key format.\n");
    goto import_out;
  }

  {
    unsigned char algorithm = get_algorithm(private_key);
    unsigned char pp = get_pin_policy(pin_policy);
    unsigned char tp = get_touch_policy(touch_policy);

    if(algorithm == 0) {
      goto import_out;
    }

    if(YKPIV_IS_RSA(algorithm)) {
      RSA *rsa_private_key = EVP_PKEY_get1_RSA(private_key);
      unsigned char e[4] = {0};
      unsigned char p[256] = {0};
      unsigned char q[256] = {0};
      unsigned char dmp1[256] = {0};
      unsigned char dmq1[256] = {0};
      unsigned char iqmp[256] = {0};
      const BIGNUM *bn_e, *bn_p, *bn_q, *bn_dmp1, *bn_dmq1, *bn_iqmp;

      int element_len = 0;
      switch(algorithm) {
        case YKPIV_ALGO_RSA1024:
          element_len = 64;
          break;
        case YKPIV_ALGO_RSA2048:
          element_len = 128;
          break;
        case YKPIV_ALGO_RSA3072:
          element_len = 192;
          break;
        case YKPIV_ALGO_RSA4096:
          element_len = 256;
          break;
        default:
          fprintf(stderr, "Unsupported RSA algorithm\n");
          goto import_out;
      }

      RSA_get0_key(rsa_private_key, NULL, &bn_e, NULL);
      RSA_get0_factors(rsa_private_key, &bn_p, &bn_q);
      RSA_get0_crt_params(rsa_private_key, &bn_dmp1, &bn_dmq1, &bn_iqmp);
      if((set_component(e, bn_e, 3) == false) ||
         !(e[0] == 0x01 && e[1] == 0x00 && e[2] == 0x01)) {
        fprintf(stderr, "Invalid public exponent for import (only 0x10001 supported)\n");
        goto import_out;
      }

      if(set_component(p, bn_p, element_len) == false) {
        fprintf(stderr, "Failed setting p component.\n");
        goto import_out;
      }

      if(set_component(q, bn_q, element_len) == false) {
        fprintf(stderr, "Failed setting q component.\n");
        goto import_out;
      }

      if(set_component(dmp1, bn_dmp1, element_len) == false) {
        fprintf(stderr, "Failed setting dmp1 component.\n");
        goto import_out;
      }

      if(set_component(dmq1, bn_dmq1, element_len) == false) {
        fprintf(stderr, "Failed setting dmq1 component.\n");
        goto import_out;
      }

      if(set_component(iqmp, bn_iqmp, element_len) == false) {
        fprintf(stderr, "Failed setting iqmp component.\n");
        goto import_out;
      }

      rc = ykpiv_import_private_key(state, key, algorithm,
                                    p, element_len,
                                    q, element_len,
                                    dmp1, element_len,
                                    dmq1, element_len,
                                    iqmp, element_len,
                                    NULL, 0,
                                    pp, tp);
    }
    else if(YKPIV_IS_EC(algorithm)) {
      EC_KEY *ec = EVP_PKEY_get1_EC_KEY(private_key);
      const BIGNUM *s = EC_KEY_get0_private_key(ec);
      unsigned char s_ptr[48] = {0};

      int element_len = 32;
      if(algorithm == YKPIV_ALGO_ECCP384) {
        element_len = 48;
      }

      if(set_component(s_ptr, s, element_len) == false) {
        fprintf(stderr, "Failed setting ec private key.\n");
        goto import_out;
      }

      rc = ykpiv_import_private_key(state, key, algorithm,
                                    NULL, 0,
                                    NULL, 0,
                                    NULL, 0,
                                    NULL, 0,
                                    NULL, 0,
                                    s_ptr, element_len,
                                    pp, tp);
    }
#if (OPENSSL_VERSION_NUMBER >= 0x10100000L)
    else if(YKPIV_IS_25519(algorithm)) {
      unsigned char s_ptr[48] = {0};
      size_t element_len = sizeof(s_ptr);

      if (EVP_PKEY_get_raw_private_key(private_key, s_ptr, &element_len) != 1) {
        fprintf(stderr, "Failed to extract private key.\n");
        goto import_out;
      }

      rc = ykpiv_import_private_key(state, key, algorithm,
                                    NULL, 0,
                                    NULL, 0,
                                    NULL, 0,
                                    NULL, 0,
                                    NULL, 0,
                                    s_ptr, element_len,
                                    pp, tp);
    }
#endif

    ret = true;
    if(rc != YKPIV_OK) {
      ret = false;
    }
  }

import_out:
  if(private_key) {
    EVP_PKEY_free(private_key);
  }

  if(p12) {
    PKCS12_free(p12);
  }

  if(cert) {
    X509_free(cert);
  }

  if(input_file != stdin) {
    fclose(input_file);
  }

  return ret;
}

static bool import_cert(ykpiv_state *state, enum enum_key_format cert_format, int perform_compress,
    const char *input_file_name, enum enum_slot slot, char *password) {
  bool ret = false;
  FILE *input_file = NULL;
  X509 *cert = NULL;
  PKCS12 *p12 = NULL;
  EVP_PKEY *private_key = NULL;
  int compress = YKPIV_CERTINFO_UNCOMPRESSED;
  int cert_len = -1;

  input_file = open_file(input_file_name, key_file_mode(cert_format, false));
  if(!input_file) {
    return false;
  }

  if(isatty(fileno(input_file))) {
    fprintf(stderr, "Please paste the certificate...\n");
  }

  if(cert_format == key_format_arg_PEM) {
    cert = PEM_read_X509(input_file, NULL, NULL, password);
    if(!cert) {
      fprintf(stderr, "Failed loading certificate for import.\n");
      goto import_cert_out;
    }
  } else if(cert_format == key_format_arg_DER) {
    cert = d2i_X509_fp(input_file, NULL);
    if(!cert) {
      fprintf(stderr, "Failed loading certificate for import.\n");
      goto import_cert_out;
    }
  } else if(cert_format == key_format_arg_PKCS12) {
    p12 = d2i_PKCS12_fp(input_file, NULL);
    if(!p12) {
      fprintf(stderr, "Failed to load PKCS12 from file.\n");
      goto import_cert_out;
    }
    if(!PKCS12_parse(p12, password, &private_key, &cert, NULL)) {
      fprintf(stderr, "Failed to parse PKCS12 structure.\n");
      goto import_cert_out;
    }
  } else if (cert_format == key_format_arg_GZIP) {
    struct stat st;

    if(fstat(fileno(input_file), &st) == -1) {
      fprintf(stderr, "Failed checking input GZIP file.\n");
      goto import_cert_out;
    }
    if (st.st_size > INT_MAX) {
      fprintf(stderr, "Size of certificate file too large.\n");
      goto import_cert_out;
    }
    cert_len = st.st_size;
    compress = YKPIV_CERTINFO_GZIP;
  } else {
    /* TODO: more formats go here */
    fprintf(stderr, "Unknown key format.\n");
    goto import_cert_out;
  }
  if(cert_len == -1) {
    cert_len = i2d_X509(cert, NULL);
  }

  {
    unsigned char certdata[YKPIV_OBJ_MAX_SIZE] = {0};
    unsigned char *certptr = certdata;
    ykpiv_rc res;

    if((cert_len > YKPIV_OBJ_MAX_SIZE && !perform_compress) || cert_len < 0) {
      fprintf(stderr, "Length of certificate is more than can fit. Consider using the 'compress' flag\n");
      goto import_cert_out;
    }

    if (compress) {
      if (fread(certdata, 1, (size_t)cert_len, input_file) != (size_t)cert_len) {
        fprintf(stderr, "Failed to read compressed certificate\n");
        goto import_cert_out;
      }
    } else if(perform_compress) {
      unsigned char uncompressed_certdata[YKPIV_OBJ_MAX_SIZE*10] = {0};
      unsigned char *uncompressed_certptr = uncompressed_certdata;
      if(i2d_X509(cert, &uncompressed_certptr) < 0) {
        fprintf(stderr, "Failed to encode X509 certificate before compression\n");
        goto import_cert_out;
      }

      z_stream zs;
      zs.zalloc = Z_NULL;
      zs.zfree = Z_NULL;
      zs.opaque = Z_NULL;
      zs.avail_in = (uInt)cert_len;
      zs.next_in = (Bytef *)uncompressed_certdata;
      zs.avail_out = (uInt) sizeof(certdata);
      zs.next_out = (Bytef *)certdata;

      if(deflateInit2(&zs, Z_DEFAULT_COMPRESSION, Z_DEFLATED, MAX_WBITS | 16, 8, Z_DEFAULT_STRATEGY) != Z_OK) {
        fprintf(stderr, "Failed to compress certificate\n");
        goto import_cert_out;
      }
      if(deflate(&zs, Z_FINISH) != Z_STREAM_END) {
        fprintf(stderr, "Failed to compress certificate\n");
        goto import_cert_out;
      }
      if(deflateEnd(&zs) != Z_OK) {
        fprintf(stderr, "Failed to compress certificate\n");
        goto import_cert_out;
      }
      cert_len = zs.total_out;
      compress = YKPIV_CERTINFO_GZIP;
    } else {
      if(i2d_X509(cert, &certptr) < 0) {
        fprintf(stderr, "Failed to encode X509 certificate\n");
        goto import_cert_out;
      }
    }

    if ((res = ykpiv_util_write_cert(state, get_slot_hex(slot), certdata, (size_t)cert_len, compress)) != YKPIV_OK) {
      fprintf(stderr, "Failed commands with device: %s\n", ykpiv_strerror(res));
    } else {
      ret = true;
    }
  }

import_cert_out:
  if(cert) {
    X509_free(cert);
  }
  if(input_file != stdin) {
    fclose(input_file);
  }
  if(p12) {
    PKCS12_free(p12);
  }
  if(private_key) {
    EVP_PKEY_free(private_key);
  }

  return ret;
}

static bool set_cardid(ykpiv_state *state, int verbose, int type) {
  ykpiv_rc res;
  unsigned char id[MAX(sizeof(ykpiv_cardid), sizeof(ykpiv_cccid))] = {0};

  if(type == CHUID) {
    res = ykpiv_util_set_cardid(state, NULL);
  } else {
    res = ykpiv_util_set_cccid(state, NULL);
  }

  if(res == YKPIV_OK && verbose) {
    if (type == CHUID) {
      res = ykpiv_util_get_cardid(state, (ykpiv_cardid*)id);
    } else {
      res = ykpiv_util_get_cccid(state, (ykpiv_cccid*)id);
    }
    if (res == YKPIV_OK) {
      fprintf(stderr, "Set the %s ID to: ", type == CHUID ? "CHUID" : "CCC");
      dump_data(id, type == CHUID ? YKPIV_CARDID_SIZE : YKPIV_CCCID_SIZE, stderr, true, format_arg_hex);
    }
  }
  return res == YKPIV_OK;
}

static X509_EXTENSION *create_ext(const char *oid, const char *name, const char *descr, const unsigned char *data, int len) {
  int nid = OBJ_txt2nid(oid);
  if(nid <= 0) {
    nid = OBJ_create(oid, name, descr);
    if (nid <= 0) {
      fprintf(stderr, "Failed creating %s extension object.\n", name);
      return 0;
    }
  }
  ASN1_OCTET_STRING *octets = ASN1_OCTET_STRING_new();
  if(!octets) {
    fprintf(stderr, "Failed allocating octets for %s extension.\n", name);
    return 0;
  }
  if(!ASN1_OCTET_STRING_set(octets, data, len)) {
    fprintf(stderr, "Failed setting octets for %s extension.\n", name);
    return 0;
  }
  X509_EXTENSION *ext = X509_EXTENSION_create_by_NID(NULL, nid, 0, octets);
  if(!ext) {
    fprintf(stderr, "Failed creating %s extension.\n", name);
  }
  return ext;
}

static int add_ext(STACK_OF(X509_EXTENSION) * exts, const char *oid, const char *name, const char *descr, const unsigned char *data, int len)
{
  X509_EXTENSION *ext = create_ext(oid, name, descr, data, len);
  if (!ext) {
    return 0;
  }
  if (!sk_X509_EXTENSION_push(exts, ext)) {
    fprintf(stderr, "Failed pushing %s extension.\n", name);
    return 0;
  }
  return 1;
}

static bool request_certificate(ykpiv_state *state, enum enum_key_format key_format,
    const char *input_file_name, enum enum_slot slot, char *subject, enum enum_hash hash,
    const char *output_file_name, int attest) {
  X509_REQ *req = NULL;
  X509_NAME *name = NULL;
  FILE *input_file = NULL;
  FILE *output_file = NULL;
  EVP_PKEY *public_key = NULL;
  const EVP_MD *md = NULL;
  bool ret = false;
  unsigned char algorithm;
  int key = 0;
  size_t oid_len = 0;
  const unsigned char *oid = NULL;
#if (OPENSSL_VERSION_NUMBER < 0x10100000L) || defined(LIBRESSL_VERSION_NUMBER)
  unsigned char digest[EVP_MAX_MD_SIZE + MAX_OID_LEN] = {0};
  unsigned int md_len;
  unsigned int digest_len;
  unsigned char *signinput;
  size_t len = 0;
  int nid;
  ASN1_TYPE null_parameter;
#endif

  key = get_slot_hex(slot);

  input_file = open_file(input_file_name, key_file_mode(key_format, false));
  output_file = open_file(output_file_name, key_file_mode(key_format, true));
  if(!input_file || !output_file) {
    goto request_out;
  }

  req = X509_REQ_new();
  if(!req) {
    fprintf(stderr, "Failed to allocate request structure.\n");
    goto request_out;
  }

  if(attest) {
    unsigned char buf[YKPIV_OBJ_MAX_SIZE] = {0};
    size_t buflen = sizeof(buf);
    ykpiv_rc rc;

    if((rc = ykpiv_attest(state, key, buf, &buflen)) == YKPIV_OK) {
      STACK_OF(X509_EXTENSION) *exts = sk_X509_EXTENSION_new_null();
      add_ext(exts, YKPIV_ATTESTATION_OID ".11", "ykpiv attestation", "Yubico PIV X.509 Attestation", buf, buflen);

      unsigned char *pb = 0;
      size_t pblen = 0;
      if((rc = ykpiv_util_read_cert(state, YKPIV_KEY_ATTESTATION, &pb, &pblen)) == YKPIV_OK && pblen > 0) {
        add_ext(exts, YKPIV_ATTESTATION_OID ".2", "ykpiv attest cert", "Yubico PIV Attestation Certificate", pb, pblen);
        ykpiv_util_free(state, pb);
      } else {
        fprintf(stderr, "Failed reading attestation certificate: %s.\n", ykpiv_strerror(rc));        
      }

      if(!X509_REQ_add_extensions(req, exts)) {
        fprintf(stderr, "Failed setting the request extensions.\n");
        sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
        goto request_out;
      }
      sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);

      // Extract the public key for the request from the attestation
      const unsigned char *ptr = buf;
      X509 *x509 = d2i_X509(NULL, &ptr, buflen);
      if(x509) {
        public_key = X509_get_pubkey(x509);
        X509_free(x509);
      }
      if(!public_key) {
        fprintf(stderr, "Failed extracting public key for request from attestation.\n");
        goto request_out;
      }
    } else {
      fprintf(stderr, "Failed creating attestation: %s.\n", ykpiv_strerror(rc));
      goto request_out;
    }
  } else {
    if(isatty(fileno(input_file))) {
      fprintf(stderr, "Please paste the public key...\n");
    }

    if(key_format == key_format_arg_PEM) {
      public_key = PEM_read_PUBKEY(input_file, NULL, NULL, NULL);
      if(!public_key) {
        fprintf(stderr, "Failed loading public key for request.\n");
        goto request_out;
      }
    } else {
      fprintf(stderr, "Only PEM supported for public key input.\n");
      goto request_out;
    }
  }

  algorithm = get_algorithm(public_key);
  if(algorithm == 0) {
    goto request_out;
  }
  if (!YKPIV_IS_25519(algorithm)) {
    md = get_hash(hash, &oid, &oid_len);
    if (md == NULL) {
      goto request_out;
    }
  }

  if(!X509_REQ_set_pubkey(req, public_key)) {
    fprintf(stderr, "Failed setting the request public key.\n");
    goto request_out;
  }

  if(X509_REQ_set_version(req, 0) != 1) {
    fprintf(stderr, "Failed setting the certificate request version.\n");
  }

  name = parse_name(subject);
  if(!name) {
    fprintf(stderr, "Failed encoding subject as name.\n");
    goto request_out;
  }
  if(!X509_REQ_set_subject_name(req, name)) {
    fprintf(stderr, "Failed setting the request subject.\n");
    goto request_out;
  }

#if (OPENSSL_VERSION_NUMBER < 0x10100000L) || defined(LIBRESSL_VERSION_NUMBER)
  null_parameter.type = V_ASN1_NULL;
  null_parameter.value.ptr = NULL;

  md_len = (unsigned int)EVP_MD_size(md);
  digest_len = sizeof(digest) - md_len;

  memcpy(digest, oid, oid_len);
  /* XXX: this should probably use X509_REQ_digest() but that's buggy */
  if(!ASN1_item_digest(ASN1_ITEM_rptr(X509_REQ_INFO), md, req->req_info,
              digest + oid_len, &digest_len)) {
    fprintf(stderr, "Failed doing digest of request.\n");
    goto request_out;
  }

  nid = get_hashnid(hash, algorithm);
  if(nid == 0) {
    fprintf(stderr, "Unsupported algorithm %x or hash %x\n", algorithm, hash);
    goto request_out;
  }

  if(YKPIV_IS_RSA(algorithm)) {
    signinput = digest;
    len = oid_len + digest_len;
    /* if it's RSA the parameter must be NULL, if ec non-present */
    req->sig_alg->parameter = &null_parameter;
  } else {
    signinput = digest + oid_len;
    len = digest_len;
  }

  req->sig_alg->algorithm = OBJ_nid2obj(nid);
  {
    unsigned char signature[1024] = {0};
    size_t sig_len = sizeof(signature);
    if(!sign_data(state, signinput, len, signature, &sig_len, algorithm, key)) {
      fprintf(stderr, "Failed signing request.\n");
      goto request_out;
    }
    ASN1_STRING_set(req->signature, signature, sig_len);
    /* mark that all bits should be used. */
    req->signature->flags = ASN1_STRING_FLAG_BITS_LEFT;
  }
#else

#if (OPENSSL_VERSION_NUMBER >= 0x10100000L)
  if (algorithm == YKPIV_ALGO_ED25519) {

    // Generate a dummy ED25519 to sign with OpenSSL
    EVP_PKEY *ed_key = NULL;
    EVP_PKEY_CTX *ed_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);
    EVP_PKEY_keygen_init(ed_ctx);
    EVP_PKEY_keygen(ed_ctx, &ed_key);
    EVP_PKEY_CTX_free(ed_ctx);

    // Sign the request object using the dummy key
    if (X509_REQ_sign(req, ed_key, md) == 0) {
      fprintf(stderr, "Failed signing certificate.\n");
      ERR_print_errors_fp(stderr);
      EVP_PKEY_free(ed_key);
      goto request_out;
    }
    EVP_PKEY_free(ed_key);

    // Extract the request data without the signature
    unsigned char *tbs_data = NULL;
    int tbs_len = i2d_re_X509_REQ_tbs(req, &tbs_data);

    // Sign the request data using the YubiKey
    unsigned char yk_sig[64] = {0};
    size_t yk_siglen = sizeof(yk_sig);
    if (!sign_data(state, tbs_data, tbs_len, yk_sig, &yk_siglen, algorithm, key)) {
      fprintf(stderr, "Failed signing tbs request portion.\n");
      goto request_out;
    }

    // Replace the dummy signature with the signature from the yubikey
    ASN1_BIT_STRING *psig;
    const X509_ALGOR *palg;
    X509_REQ_get0_signature(req, (const ASN1_BIT_STRING **) &psig, &palg);
    ASN1_BIT_STRING_set(psig, yk_sig, yk_siglen);

  } else {
#endif
    /* With opaque structures we can not touch whatever we want, but we need
     * to embed the sign_data function in the RSA/EC key structures  */
    EVP_PKEY *sk = wrap_public_key(state, algorithm, public_key, key, oid, oid_len);

    if(X509_REQ_sign(req, sk, md) == 0) {
      fprintf(stderr, "Failed signing request.\n");
      ERR_print_errors_fp(stderr);
      EVP_PKEY_free(sk);
      goto request_out;
    }
    EVP_PKEY_free(sk);
#if (OPENSSL_VERSION_NUMBER >= 0x10100000L)
  }
#endif

#endif

  if(key_format == key_format_arg_PEM) {
    if(PEM_write_X509_REQ(output_file, req) == 1) {
      ret = true;
    } else {
      fprintf(stderr, "Failed writing x509 information\n");
    }
  } else if(key_format == key_format_arg_DER) {
    if(i2d_X509_REQ_fp(output_file, req)) {
      ret = true;
    } else {
      fprintf(stderr, "Failed writing DER information\n");
    }
  } else {
    fprintf(stderr, "Only PEM support available for certificate requests.\n");
  }

request_out:
  if(input_file && input_file != stdin) {
    fclose(input_file);
  }
  if(output_file && output_file != stdout) {
    fclose(output_file);
  }
  EVP_PKEY_free(public_key);
#if (OPENSSL_VERSION_NUMBER < 0x10100000L) || defined(LIBRESSL_VERSION_NUMBER)
  if(req) {
    if(req->sig_alg->parameter) {
      req->sig_alg->parameter = NULL;
    }
  }
#endif
  X509_REQ_free(req);
  X509_NAME_free(name);
  return ret;
}

static const struct {
  int nid;
  const char *ext;
  int critical;
} selfsign_extensions[] = {
  {NID_subject_key_identifier, "hash", 0},
  {NID_authority_key_identifier, "keyid", 0},
  {NID_basic_constraints, "CA:true", 1},
};

static bool selfsign_certificate(ykpiv_state *state, enum enum_key_format key_format,
    const char *input_file_name, enum enum_slot slot, char *subject, enum enum_hash hash,
    const int *serial, int validDays, const char *output_file_name, int attest) {
  bool ret = false;
  X509_EXTENSION *attestation = NULL;
  X509_EXTENSION *attest_cert = NULL;
  X509 *x509 = NULL;
  EVP_PKEY *public_key = NULL;
  X509_NAME *name = NULL;
  ASN1_INTEGER *sno = ASN1_INTEGER_new();
  BIGNUM *ser = NULL;

  int key = get_slot_hex(slot);

  FILE *input_file = open_file(input_file_name, key_file_mode(key_format, false));
  FILE *output_file = open_file(output_file_name, key_file_mode(key_format, true));
  if(!input_file || !output_file) {
    goto selfsign_out;
  }

  if (attest) {
    unsigned char buf[YKPIV_OBJ_MAX_SIZE] = {0};
    size_t buflen = sizeof(buf);
    ykpiv_rc rc = 0;

    if ((rc = ykpiv_attest(state, key, buf, &buflen)) == YKPIV_OK) {
      // Extract the public key for the request from the attestation
      const unsigned char *ptr = buf;
      X509 *cert = d2i_X509(NULL, &ptr, buflen);
      if (cert) {
        public_key = X509_get_pubkey(cert);
        if (!public_key) {
          fprintf(stderr, "Failed extracting public key from attestation.\n");
        }
        X509_free(cert);
      } else {
        fprintf(stderr, "Failed extracting attestation.\n");
      }

      attestation = create_ext(YKPIV_ATTESTATION_OID ".11", "ykpiv attestation", "Yubico PIV X.509 Attestation", buf, buflen);
      if (!attestation) {
        fprintf(stderr, "Failed creating attestation extension.\n");
      }

      unsigned char *pb = 0;
      size_t pblen = 0;
      if ((rc = ykpiv_util_read_cert(state, YKPIV_KEY_ATTESTATION, &pb, &pblen)) == YKPIV_OK && pblen > 0) {
        attest_cert = create_ext(YKPIV_ATTESTATION_OID ".2", "ykpiv attest cert", "Yubico PIV Attestation Certificate", pb, pblen);
        if (!attest_cert) {
          fprintf(stderr, "Failed creating attestation certificate extension.\n");
        }
        ykpiv_util_free(state, pb);
      }
      else {
        fprintf(stderr, "Failed reading attestation certificate: %s.\n", ykpiv_strerror(rc));
      }
    }
    else {
      fprintf(stderr, "Failed creating attestation: %s.\n", ykpiv_strerror(rc));
    }
  }

  if(!public_key) {
    if(isatty(fileno(input_file))) {
      fprintf(stderr, "Please paste the public key...\n");
    }

    if(key_format == key_format_arg_PEM) {
      public_key = PEM_read_PUBKEY(input_file, NULL, NULL, NULL);
      if(!public_key) {
        fprintf(stderr, "Failed loading public key for certificate.\n");
        goto selfsign_out;
      }
    } else {
      fprintf(stderr, "Only PEM supported for public key input.\n");
      goto selfsign_out;
    }
  }

  unsigned char algorithm = get_algorithm(public_key);
  if(algorithm == 0) {
    goto selfsign_out;
  }
  if(algorithm == YKPIV_ALGO_X25519) {
    fprintf(stderr, "Signing with X25519 keys is not supported.\n");
    goto selfsign_out;
  }

  size_t oid_len = 0;
  const unsigned char *oid = 0;
  const EVP_MD *md = NULL;
  if (algorithm != YKPIV_ALGO_ED25519) {
    md = get_hash(hash, &oid, &oid_len);
    if (md == NULL) {
      goto selfsign_out;
    }
  }
  x509 = X509_new();
  if(!x509) {
    fprintf(stderr, "Failed to allocate certificate structure.\n");
    goto selfsign_out;
  }
  if(!X509_set_version(x509, 2)) {
    fprintf(stderr, "Failed to set certificate version.\n");
    goto selfsign_out;
  }
  if(!X509_set_pubkey(x509, public_key)) {
    fprintf(stderr, "Failed to set the certificate public key.\n");
    goto selfsign_out;
  }
  if(serial) {
    if(ASN1_INTEGER_set(sno, *serial) != 1) {
      fprintf(stderr, "Failed to read serial number.\n");
      goto selfsign_out;
    }
  } else {
    ser = BN_new();
    if(!ser) {
      fprintf(stderr, "Failed to allocate BIGNUM.\n");
      goto selfsign_out;
    }
    if(!BN_pseudo_rand(ser, 64, 0, 0)) {
      fprintf(stderr, "Failed to generate randomness.\n");
      goto selfsign_out;
    }
    if(!BN_to_ASN1_INTEGER(ser, sno)) {
      fprintf(stderr, "Failed to set random serial.\n");
      goto selfsign_out;
    }
  }
  if(!X509_set_serialNumber(x509, sno)) {
    fprintf(stderr, "Failed to set certificate serial.\n");
    goto selfsign_out;
  }
  if(!X509_gmtime_adj(X509_get_notBefore(x509), 0)) {
    fprintf(stderr, "Failed to set certificate notBefore.\n");
    goto selfsign_out;
  }
  if(!X509_gmtime_adj(X509_get_notAfter(x509), 60L * 60L * 24L * validDays)) {
    fprintf(stderr, "Failed to set certificate notAfter.\n");
    goto selfsign_out;
  }
  name = parse_name(subject);
  if(!name) {
    fprintf(stderr, "Failed encoding subject as name.\n");
    goto selfsign_out;
  }
  if(!X509_set_subject_name(x509, name)) {
    fprintf(stderr, "Failed setting certificate subject.\n");
    goto selfsign_out;
  }
  if(!X509_set_issuer_name(x509, name)) {
    fprintf(stderr, "Failed setting certificate issuer.\n");
    goto selfsign_out;
  }
  int nid = get_hashnid(hash, algorithm);
  if(nid == 0) {
    goto selfsign_out;
  }

  {
    X509V3_CTX ctx;
    int i;
    X509V3_set_ctx(&ctx, x509, x509, NULL, NULL, 0);

    for(i = 0; i < sizeof(selfsign_extensions) / sizeof(selfsign_extensions[0]); i++) {
      X509_EXTENSION *ext = NULL;
      void *ext_struc;
      const X509V3_EXT_METHOD *method = X509V3_EXT_get_nid(selfsign_extensions[i].nid);

      if(!method) {
        fprintf(stderr, "Failed to get extension method for nid %d.\n", selfsign_extensions[i].nid);
        goto selfsign_out;
      }
      if(method->v2i) {
        STACK_OF(CONF_VALUE) *nval = X509V3_parse_list(selfsign_extensions[i].ext);
        if(!nval) {
          fprintf(stderr, "Failed parsing extension value for nid %d.\n", selfsign_extensions[i].nid);
          goto selfsign_out;
        }
        ext_struc = method->v2i(method, &ctx, nval);
      } else if(method->s2i) {
        ext_struc = method->s2i(method, &ctx, selfsign_extensions[i].ext);
      } else {
        fprintf(stderr, "Unknown way to construct extension for nid %d.\n", selfsign_extensions[i].nid);
        goto selfsign_out;
      }

      if(!ext_struc) {
        fprintf(stderr, "Failed constructing extension value for nid %d.\n", selfsign_extensions[i].nid);
        goto selfsign_out;
      }

      ext = X509V3_EXT_i2d(selfsign_extensions[i].nid, selfsign_extensions[i].critical, ext_struc);
      if(!X509_add_ext(x509, ext, -1)) {
        fprintf(stderr, "Failed adding extension %d (%d).\n", i, selfsign_extensions[i].nid);
        goto selfsign_out;
      }
    }

    if(attestation && !X509_add_ext(x509, attestation, -1)) {
      fprintf(stderr, "Failed adding attestation extension.\n");
      goto selfsign_out;
    }

    if(attest_cert && !X509_add_ext(x509, attest_cert, -1)) {
      fprintf(stderr, "Failed adding attestation certificate extension.\n");
      goto selfsign_out;
    }
  }

#if (OPENSSL_VERSION_NUMBER < 0x10100000L) || defined(LIBRESSL_VERSION_NUMBER)
  unsigned char digest[EVP_MAX_MD_SIZE + MAX_OID_LEN] = {0};
  unsigned char *signinput;
  size_t len = 0;

  ASN1_TYPE null_parameter;
  null_parameter.type = V_ASN1_NULL;
  null_parameter.value.ptr = NULL;

  unsigned int md_len = (unsigned int)EVP_MD_size(md);
  unsigned int digest_len = sizeof(digest) - md_len;

  if(YKPIV_IS_RSA(algorithm)) {
    signinput = digest;
    len = oid_len + md_len;
    /* for RSA parameter must be NULL, for ec non-present */
    x509->sig_alg->parameter = &null_parameter;
    x509->cert_info->signature->parameter = &null_parameter;
  } else {
    signinput = digest + oid_len;
    len = md_len;
  }

  x509->sig_alg->algorithm = OBJ_nid2obj(nid);
  x509->cert_info->signature->algorithm = x509->sig_alg->algorithm;
  memcpy(digest, oid, oid_len);
  /* XXX: this should probably use X509_digest() but that looks buggy */
  if(!ASN1_item_digest(ASN1_ITEM_rptr(X509_CINF), md, x509->cert_info,
              digest + oid_len, &digest_len)) {
    fprintf(stderr, "Failed doing digest of certificate.\n");
    goto selfsign_out;
  }
  {
    unsigned char signature[1024] = {0};
    size_t sig_len = sizeof(signature);
    if(!sign_data(state, signinput, len, signature, &sig_len, algorithm, key)) {
      fprintf(stderr, "Failed signing certificate.\n");
      goto selfsign_out;
    }
    ASN1_STRING_set(x509->signature, signature, sig_len);
    /* setting flags to ASN1_STRING_FLAG_BITS_LEFT here marks that no bits
     * should be subtracted from the bit string, thus making sure that the
     * certificate can be validated. */
    x509->signature->flags = ASN1_STRING_FLAG_BITS_LEFT;
  }
#else

#if (OPENSSL_VERSION_NUMBER >= 0x10100000L)
  if (algorithm == YKPIV_ALGO_ED25519) {

    // Generate a dummy ED25519 to sign with OpenSSL
    EVP_PKEY *ed_key = NULL;
    EVP_PKEY_CTX *ed_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);
    EVP_PKEY_keygen_init(ed_ctx);
    EVP_PKEY_keygen(ed_ctx, &ed_key);
    EVP_PKEY_CTX_free(ed_ctx);

    // Sign the X509 object using the dummy key
    if (X509_sign(x509, ed_key, md) == 0) {
      fprintf(stderr, "Failed signing certificate.\n");
      ERR_print_errors_fp(stderr);
      EVP_PKEY_free(ed_key);
      goto selfsign_out;
    }
    EVP_PKEY_free(ed_key);

    // Extract the certificate data without the signature
    unsigned char *tbs_data = NULL;
    int tbs_len = i2d_re_X509_tbs(x509, &tbs_data);

    // Sign the certificate data using the YubiKey
    unsigned char yk_sig[64] = {0};
    size_t yk_siglen = sizeof(yk_sig);
    if (!sign_data(state, tbs_data, tbs_len, yk_sig, &yk_siglen, algorithm, key)) {
      fprintf(stderr, "Failed signing tbs certificate portion.\n");
      goto selfsign_out;
    }

    // Replace the dummy signature with the signature from the yubikey
    ASN1_BIT_STRING *psig;
    const X509_ALGOR *palg;
    X509_get0_signature((const ASN1_BIT_STRING **) &psig, &palg, x509);
    ASN1_BIT_STRING_set(psig, yk_sig, yk_siglen);
  } else {
#endif
    /* With opaque structures we can not touch whatever we want, but we need
     * to embed the sign_data function in the RSA/EC key structures  */
    EVP_PKEY *sk = wrap_public_key(state, algorithm, public_key, key, oid, oid_len);

    if(X509_sign(x509, sk, md) == 0) {
      fprintf(stderr, "Failed signing certificate.\n");
      ERR_print_errors_fp(stderr);
      EVP_PKEY_free(sk);
      goto selfsign_out;
    }
    EVP_PKEY_free(sk);
#if (OPENSSL_VERSION_NUMBER >= 0x10100000L)
  }
#endif

#endif

  if(key_format == key_format_arg_PEM) {
    if(PEM_write_X509(output_file, x509) == 1) {
      ret = true;
    } else {
      fprintf(stderr, "Failed writing x509 information\n");
    }
  } else if(key_format == key_format_arg_DER) {
    if(i2d_X509_fp(output_file, x509)) {
      ret = true;
    } else {
      fprintf(stderr, "Failed writing DER information\n");
    }
  } else {
    fprintf(stderr, "Only PEM and DER support available for certificates.\n");
  }

selfsign_out:
  if(input_file && input_file != stdin) {
    fclose(input_file);
  }
  if(output_file && output_file != stdout) {
    fclose(output_file);
  }
 #if (OPENSSL_VERSION_NUMBER < 0x10100000L) || defined(LIBRESSL_VERSION_NUMBER)
  if(x509) {
   if(x509->sig_alg->parameter) {
      x509->sig_alg->parameter = NULL;
      x509->cert_info->signature->parameter = NULL;
    }
  }
#endif
  X509_free(x509);
  EVP_PKEY_free(public_key);
  X509_NAME_free(name);
  BN_free(ser);
  ASN1_INTEGER_free(sno);
  return ret;
}

static bool verify_pin(ykpiv_state *state, const char *pin) {
  int tries = -1;
  ykpiv_rc res;
  int len;
  len = strlen(pin);

  if(len > 8) {
    fprintf(stderr, "Maximum 8 digits of PIN supported.\n");
  }

  res = ykpiv_verify(state, pin, &tries);
  if(res == YKPIV_OK) {
    return true;
  } else if(res == YKPIV_WRONG_PIN || res == YKPIV_PIN_LOCKED) {
    if(tries > 0) {
      fprintf(stderr, "Pin verification failed, %d tries left before pin is blocked.\n", tries);
    } else {
      fprintf(stderr, "Pin code blocked, use unblock-pin action to unblock.\n");
    }
  } else {
    fprintf(stderr, "Pin code verification failed: '%s'\n", ykpiv_strerror(res));
  }
  return false;
}

/* this function is called for all three of change-pin, change-puk and unblock pin
 * since they're very similar in what data they use. */
static bool change_pin(ykpiv_state *state, enum enum_action action, const char *pin,
    const char *new_pin) {
  const char *name = action == action_arg_changeMINUS_pin ? "pin" : "puk";
  ykpiv_rc (*op)(ykpiv_state *state, const char * puk, size_t puk_len,
            const char * new_pin, size_t new_pin_len, int *tries) = ykpiv_change_pin;
  size_t pin_len;
  size_t new_len;
  int tries;
  ykpiv_rc res;

  pin_len = strlen(pin);
  new_len = strlen(new_pin);

  if(pin_len > 8 || new_len > 8) {
    fprintf(stderr, "Maximum 8 digits of PIN supported.\n");
    return false;
  }

  if(new_len < 6) {
    fprintf(stderr, "Minimum 6 digits of PIN supported.\n");
    return false;
  }

  if(action == action_arg_unblockMINUS_pin) {
    op = ykpiv_unblock_pin;
  }
  else if(action == action_arg_changeMINUS_puk) {
    op = ykpiv_change_puk;
  }
  res = op(state, pin, pin_len, new_pin, new_len, &tries);

  switch (res) {
    case YKPIV_OK:
      return true;

    case YKPIV_WRONG_PIN:
      fprintf(stderr, "Failed verifying %s code, now %d tries left before blocked.\n",
              name, tries);
      return false;

    case YKPIV_PIN_LOCKED:
      if(action == action_arg_changeMINUS_pin) {
        fprintf(stderr, "The pin code is blocked, use the unblock-pin action to unblock it.\n");
      } else {
        fprintf(stderr, "The puk code is blocked, you will have to reinitialize the application.\n");
      }
      return false;

    default:
      fprintf(stderr, "Failed changing/unblocking code, error: %s\n", ykpiv_strerror(res));
      return false;
  }
}

static bool delete_certificate(ykpiv_state *state, enum enum_slot slot) {
  return ykpiv_util_delete_cert(state, get_slot_hex(slot)) == YKPIV_OK;
}

static bool read_certificate(ykpiv_state *state, enum enum_slot slot,
    enum enum_key_format key_format, const char *output_file_name) {
  FILE *output_file;
  uint8_t *data = NULL;
  const unsigned char *ptr = NULL;
  X509 *x509 = NULL;
  bool ret = false;
  size_t cert_len = 0;

  if (key_format != key_format_arg_PEM &&
      key_format != key_format_arg_DER &&
      key_format != key_format_arg_SSH) {
    fprintf(stderr, "Only PEM, DER and SSH format are supported for read-certificate.\n");
    return false;
  }

  output_file = open_file(output_file_name, key_file_mode(key_format, true));
  if (!output_file) {
    return false;
  }

  if (ykpiv_util_read_cert(state, get_slot_hex(slot), &data, &cert_len) != YKPIV_OK) {
    fprintf(stderr, "Failed fetching certificate.\n");
    goto read_cert_out;
  }
  ptr = data;

  if (key_format == key_format_arg_PEM ||
      key_format == key_format_arg_SSH) {
    x509 = d2i_X509(NULL, (const unsigned char**)&ptr, cert_len);
    if (!x509) {
      fprintf(stderr, "Failed parsing x509 information.\n");
      goto read_cert_out;
    }

    if (key_format == key_format_arg_PEM) {
      if(PEM_write_X509(output_file, x509) == 1) {
        ret = true;
      } else {
        fprintf(stderr, "Failed writing x509 information\n");
      }
    }
    else {
      if (!SSH_write_X509(output_file, x509)) {
        fprintf(stderr, "Unable to extract public key or not an RSA key.\n");
        goto read_cert_out;
      }
      ret = true;
    }
  } else { /* key_format_arg_DER */
    /* XXX: This will just dump the raw data in tag 0x70.. */
    fwrite(ptr, (size_t)cert_len, 1, output_file);
    ret = true;
  }

read_cert_out:
  if (output_file != stdout) {
    fclose(output_file);
  }
  if (x509) {
    X509_free(x509);
  }
  if (data) {
    ykpiv_util_free(state, data);
  }
  return ret;
}

static bool sign_file(ykpiv_state *state, const char *input, const char *output,
    enum enum_slot slot, enum enum_algorithm algorithm, enum enum_hash hash,
    int verbosity) {
  FILE *input_file = NULL;
  FILE *output_file = NULL;
  int key;
  unsigned int hash_len;
  unsigned char hashed[YKPIV_OBJ_MAX_SIZE] = {0};
  bool ret = false;
  int algo;
  const EVP_MD *md = NULL;

  key = get_slot_hex(slot);

  input_file = open_file(input, INPUT_BIN);
  if(!input_file) {
    return false;
  }

  if(isatty(fileno(input_file))) {
    fprintf(stderr, "Please paste the input...\n");
  }

  output_file = open_file(output, OUTPUT_BIN);
  if(!output_file) {
    if(input_file && input_file != stdin) {
      fclose(input_file);
    }
    return false;
  }

  algo = get_piv_algorithm(algorithm);
  if(algo == 0) {
    goto out;
  }

  {
    EVP_MD_CTX *mdctx;
    if(algo == YKPIV_ALGO_X25519) {
      fprintf(stderr, "Signing with X25519 key is not supported\n");
      goto out;
    } else if (algo == YKPIV_ALGO_ED25519) {
      hash_len = fread(hashed, 1, sizeof(hashed), input_file);
      if(hash_len >= sizeof(hashed)) {
        fprintf(stderr, "Cannot perform signature. File too big.\n");
        goto out;
      }
    } else {
      md = get_hash(hash, NULL, NULL);
      if (md == NULL) {
        goto out;
      }

      mdctx = EVP_MD_CTX_create();
      if (EVP_DigestInit_ex(mdctx, md, NULL) != 1) {
        fprintf(stderr, "Failed to initialize digest operation\n");
        goto out;
      }
      while (!feof(input_file)) {
        char buf[8192] = {0};
        size_t len = fread(buf, 1, sizeof(buf), input_file);
        if (EVP_DigestUpdate(mdctx, buf, len) != 1) {
          fprintf(stderr, "Failed to update digest data\n");
          goto out;
        }
      }
      if (EVP_DigestFinal_ex(mdctx, hashed, &hash_len) != 1) {
        fprintf(stderr, "Failed to finalize digest operation\n");
        goto out;
      }

      if (verbosity) {
        fprintf(stderr, "File hashed as: ");
        dump_data(hashed, hash_len, stderr, true, format_arg_hex);
      }
      EVP_MD_CTX_destroy(mdctx);
    }
  }

  if(YKPIV_IS_RSA(algo)) {
    prepare_rsa_signature(hashed, hash_len, hashed, &hash_len, EVP_MD_type(md));
  }

  {
    unsigned char buf[1024] = {0};
    size_t len = sizeof(buf);
    if(!sign_data(state, hashed, hash_len, buf, &len, algo, key)) {
      fprintf(stderr, "Failed signing file\n");
      goto out;
    }

    if(verbosity) {
      fprintf(stderr, "File signed as: ");
      dump_data(buf, len, stderr, true, format_arg_hex);
    }
    fwrite(buf, 1, len, output_file);
    ret = true;
  }

out:
  if(input_file && input_file != stdin) {
    fclose(input_file);
  }

  if(output_file && output_file != stdout) {
    fclose(output_file);
  }

  return ret;
}

static void print_cert_info(ykpiv_state *state, enum enum_slot slot, const EVP_MD *md,
    FILE *output) {
  int object = (int)ykpiv_util_slot_object(get_slot_hex(slot));
  int slot_name;
  unsigned char data[YKPIV_OBJ_MAX_SIZE] = {0};
  unsigned long len = sizeof(data);
  X509 *x509 = NULL;
  X509_NAME *subj;
  BIO *bio = NULL;

  if(ykpiv_fetch_object(state, object, data, &len) != YKPIV_OK) {
    return;
  }

  slot_name = get_slot_hex(slot);

  fprintf(output, "Slot %x:\t", slot_name);

  unsigned char certdata[YKPIV_OBJ_MAX_SIZE * 10] = {0};
  size_t certdata_len = sizeof(certdata);
  if(ykpiv_util_get_certdata(data, len, certdata, &certdata_len) != YKPIV_OK) {
    fprintf(output, "Failed to get certificate data\n");
    return;
  }

  const unsigned char *certdata_ptr = certdata;
  x509 = d2i_X509(NULL, &certdata_ptr, certdata_len);
  if (x509 == NULL) {
    fprintf(output, "Parse error.\n");
    return;
  }

  unsigned int md_len = sizeof(data);
  const ASN1_TIME *not_before, *not_after;

  EVP_PKEY *key = X509_get_pubkey(x509);
  if(!key) {
    fprintf(output, "Parse error.\n");
    goto cert_out;
  }
  fprintf(output, "\n\tAlgorithm:\t");
  switch(get_algorithm(key)) {
    case YKPIV_ALGO_RSA1024:
      fprintf(output, "RSA1024\n");
      break;
    case YKPIV_ALGO_RSA2048:
      fprintf(output, "RSA2048\n");
      break;
    case YKPIV_ALGO_RSA3072:
      fprintf(output, "RSA3072\n");
      break;
    case YKPIV_ALGO_RSA4096:
      fprintf(output, "RSA4096\n");
      break;
    case YKPIV_ALGO_ECCP256:
      fprintf(output, "ECCP256\n");
      break;
    case YKPIV_ALGO_ECCP384:
      fprintf(output, "ECCP384\n");
      break;
    case YKPIV_ALGO_ED25519:
      fprintf(output, "ED25519\n");
      break;
    case YKPIV_ALGO_X25519:
      fprintf(output, "X25519\n");
      break;
    default:
      fprintf(output, "Unknown\n");
  }
  EVP_PKEY_free(key);

  subj = X509_get_subject_name(x509);
  if(!subj) {
    fprintf(output, "Parse error.\n");
    goto cert_out;
  }
  fprintf(output, "\tSubject DN:\t");
  if(X509_NAME_print_ex_fp(output, subj, 0, XN_FLAG_COMPAT) != 1) {
    fprintf(output, "Failed to write Subject DN.\n");
    goto cert_out;
  }
  fprintf(output, "\n");
  subj = X509_get_issuer_name(x509);
  if(!subj) {
    fprintf(output, "Parse error.\n");
    goto cert_out;
  }
  fprintf(output, "\tIssuer DN:\t");
  if(X509_NAME_print_ex_fp(output, subj, 0, XN_FLAG_COMPAT) != 1) {
    fprintf(output, "Failed to write Issuer DN.\n");
    goto cert_out;
  }
  fprintf(output, "\n");
  if(X509_digest(x509, md, data, &md_len) != 1) {
    fprintf(output, "Failed to digest data.\n");
    goto cert_out;
  }
  fprintf(output, "\tFingerprint:\t");
  dump_data(data, md_len, output, false, format_arg_hex);

  bio = BIO_new_fp(output, BIO_NOCLOSE | BIO_FP_TEXT);
  not_before = X509_get_notBefore(x509);
  if(not_before) {
    fprintf(output, "\tNot Before:\t");
    if(ASN1_TIME_print(bio, not_before) != 1) {
      fprintf(output, "Failed to write Not Before time.\n");
      goto cert_out;
    }
    fprintf(output, "\n");
  }
  not_after = X509_get_notAfter(x509);
  if(not_after) {
    fprintf(output, "\tNot After:\t");
    if(ASN1_TIME_print(bio, not_after) != 1) {
      fprintf(output, "Failed to write Not After time.\n");
      goto cert_out;
    }
    fprintf(output, "\n");
  }
cert_out:
  if(x509) {
    X509_free(x509);
  }
  if(bio) {
    BIO_free(bio);
  }
}

static bool status(ykpiv_state *state, enum enum_hash hash,
                   enum enum_slot slot,
                   const char *output_file_name) {
  const EVP_MD *md;
  unsigned char buf[YKPIV_OBJ_MAX_SIZE] = {0};
  long unsigned len = sizeof(buf);
  int i;
  uint32_t serial = 0;
  FILE *output_file = open_file(output_file_name, OUTPUT_TEXT);

  if(!output_file) {
    return false;
  }

  md = get_hash(hash, NULL, NULL);
  if(md == NULL) {
    return false;
  }

  fprintf(output_file, "Version:\t");
  if (ykpiv_get_version(state, (char*)buf, (size_t)len) != YKPIV_OK) {
    fprintf(output_file, "No data available\n");
  } else {
    fprintf(output_file, "%s\n", (char*)buf);
  }

  fprintf(output_file, "Serial Number:\t");
  if (ykpiv_get_serial(state, &serial) != YKPIV_OK) {
    fprintf(output_file, "No data available\n");
  } else {
    fprintf(output_file, "%d\n", serial);
  }

  fprintf(output_file, "CHUID:\t");
  if(ykpiv_fetch_object(state, YKPIV_OBJ_CHUID, buf, &len) != YKPIV_OK) {
    fprintf(output_file, "No data available\n");
  } else {
    dump_data(buf, len, output_file, false, format_arg_hex);
  }

  len = sizeof(buf);
  fprintf(output_file, "CCC:\t");
  if(ykpiv_fetch_object(state, YKPIV_OBJ_CAPABILITY, buf, &len) != YKPIV_OK) {
    fprintf(output_file, "No data available\n");
  } else {
    dump_data(buf, len, output_file, false, format_arg_hex);
  }

  if (slot == slot__NULL)
    for (i = 0; i < 24; i++) {
      print_cert_info(state, i, md, output_file);
    }
  else
    print_cert_info(state, slot, md, output_file);

  {
    int tries;
    ykpiv_verify(state, NULL, &tries);
    fprintf(output_file, "PIN tries left:\t%d\n", tries);
  }

  if(output_file != stdout) {
    fclose(output_file);
  }
  return true;
}

static bool test_signature(ykpiv_state *state, enum enum_slot slot,
    enum enum_hash hash, const char *input_file_name,
    enum enum_key_format cert_format, int verbose) {
  const EVP_MD *md;
  bool ret = false;
  unsigned char data[1024] = {0};
  unsigned int data_len;
  X509 *x509 = NULL;
  EVP_PKEY *pubkey = NULL;
  FILE *input_file = open_file(input_file_name, key_file_mode(cert_format, false));

  if(!input_file) {
    fprintf(stderr, "Failed opening input file %s.\n", input_file_name);
    return false;
  }

  if(isatty(fileno(input_file))) {
    fprintf(stderr, "Please paste the certificate to verify against...\n");
  }

  if(cert_format == key_format_arg_PEM) {
    x509 = PEM_read_X509(input_file, NULL, NULL, NULL);
  } else if(cert_format == key_format_arg_DER) {
    x509 = d2i_X509_fp(input_file, NULL);
  } else {
    fprintf(stderr, "Only PEM or DER format is supported for test-signature.\n");
    goto test_out;
  }
  if(!x509) {
    fprintf(stderr, "Failed loading certificate for test-signature.\n");
    goto test_out;
  }

  md = get_hash(hash, NULL, NULL);
  if(md == NULL) {
    goto test_out;
  }

  {
    unsigned char rand[128] = {0};
    EVP_MD_CTX *mdctx;
    if(RAND_bytes(rand, sizeof(rand)) <= 0) {
      fprintf(stderr, "error: no randomness.\n");
      goto test_out;
    }

    mdctx = EVP_MD_CTX_create();
    if(EVP_DigestInit_ex(mdctx, md, NULL) != 1) {
      fprintf(stderr, "Failed to initialize digest operation\n");
      goto test_out;
    }
    if(EVP_DigestUpdate(mdctx, rand, 128) != 1) {
      fprintf(stderr, "Failed to update digest data\n");
      goto test_out;
    }
    if(EVP_DigestFinal_ex(mdctx, data, &data_len) != 1) {
      fprintf(stderr, "Failed to finalize digest operation\n");
      goto test_out;
    }
    if(verbose) {
      fprintf(stderr, "Test data hashes as: ");
      dump_data(data, data_len, stderr, true, format_arg_hex);
    }
    EVP_MD_CTX_destroy(mdctx);
  }

  {
    unsigned char signature[1024] = {0};
    unsigned char encoded[1024] = {0};
    unsigned char *ptr = data;
    unsigned int enc_len;
    size_t sig_len = sizeof(signature);
    int key = 0;
    unsigned char algorithm;

    pubkey = X509_get_pubkey(x509);
    if(!pubkey) {
      fprintf(stderr, "Parse error.\n");
      goto test_out;
    }
    algorithm = get_algorithm(pubkey);
    if(algorithm == 0) {
      goto test_out;
    }
    key = get_slot_hex(slot);
    if(YKPIV_IS_RSA(algorithm)) {
      prepare_rsa_signature(data, data_len, encoded, &enc_len, EVP_MD_type(md));
      ptr = encoded;
    } else {
      enc_len = data_len;
    }
    if(!sign_data(state, ptr, enc_len, signature, &sig_len, algorithm, key)) {
      fprintf(stderr, "Failed signing test data.\n");
      goto test_out;
    }

    switch(algorithm) {
      case YKPIV_ALGO_RSA1024:
      case YKPIV_ALGO_RSA2048:
      case YKPIV_ALGO_RSA3072:
      case YKPIV_ALGO_RSA4096:
        {
          RSA *rsa = EVP_PKEY_get1_RSA(pubkey);
          if(!rsa) {
            fprintf(stderr, "Failed getting RSA pubkey.\n");
            goto test_out;
          }

          if(RSA_verify(EVP_MD_type(md), data, data_len, signature, sig_len, rsa) == 1) {
            fprintf(stderr, "Successful RSA verification.\n");
            ret = true;
            goto test_out;
          } else {
            fprintf(stderr, "Failed RSA verification.\n");
            goto test_out;
          }
        }

        break;
      case YKPIV_ALGO_ECCP256:
      case YKPIV_ALGO_ECCP384:
        {
          EC_KEY *ec = EVP_PKEY_get1_EC_KEY(pubkey);
          if(ECDSA_verify(0, data, (int)data_len, signature, (int)sig_len, ec) == 1) {
            fprintf(stderr, "Successful ECDSA verification.\n");
            ret = true;
            goto test_out;
          } else {
            fprintf(stderr, "Failed ECDSA verification.\n");
            goto test_out;
          }
        }
        break;
      case YKPIV_ALGO_ED25519:
        {
          EVP_MD_CTX *ctx;
          int rc;
          ctx = EVP_MD_CTX_new();
          if (!ctx || EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, pubkey) <= 0) {
            fprintf(stderr, "Failed routine initialization\n");
            EVP_MD_CTX_free(ctx); // It's OK if ctx is NULL
            goto test_out;
          }
          rc = EVP_DigestVerify(ctx, signature, (int)sig_len, data, (int)data_len);
          EVP_MD_CTX_free(ctx);
          if(rc == 1) {
            fprintf(stderr, "Successful EDDSA verification.\n");
            ret = true;
            goto test_out;
          } else {
            fprintf(stderr, "Failed EDDSA verification.\n");
            goto test_out;
          }
        }
        break;
      default:
        fprintf(stderr, "Unknown algorithm.\n");
        goto test_out;
    }
  }
test_out:
  if(pubkey) {
    EVP_PKEY_free(pubkey);
  }
  if(x509) {
    X509_free(x509);
  }
  if(input_file != stdin) {
    fclose(input_file);
  }
  return ret;
}

static bool test_decipher(ykpiv_state *state, enum enum_slot slot,
    const char *input_file_name, enum enum_key_format cert_format, int verbose) {
  bool ret = false;
  X509 *x509 = NULL;
  EVP_PKEY *pubkey = NULL;
  EC_KEY *tmpkey = NULL;
  FILE *input_file = open_file(input_file_name, key_file_mode(cert_format, false));

  if(!input_file) {
    fprintf(stderr, "Failed opening input file %s.\n", input_file_name);
    return false;
  }

  if(isatty(fileno(input_file))) {
    fprintf(stderr, "Please paste the certificate to encrypt for...\n");
  }

  if(cert_format == key_format_arg_PEM) {
    x509 = PEM_read_X509(input_file, NULL, NULL, NULL);
  } else if(cert_format == key_format_arg_DER) {
    x509 = d2i_X509_fp(input_file, NULL);
  } else {
    fprintf(stderr, "Only PEM or DER format is supported for test-decipher.\n");
    goto decipher_out;
  }
  if(!x509) {
    fprintf(stderr, "Failed loading certificate for test-decipher.\n");
    goto decipher_out;
  }

  {
    int key = 0;
    unsigned char algorithm;

    pubkey = X509_get_pubkey(x509);
    if(!pubkey) {
      fprintf(stderr, "Parse error.\n");
      goto decipher_out;
    }
    algorithm = get_algorithm(pubkey);
    if(algorithm == 0) {
      goto decipher_out;
    }
    key = get_slot_hex(slot);
    if(YKPIV_IS_RSA(algorithm)) {
      unsigned char secret[32] = {0};
      unsigned char secret2[32] = {0};
      unsigned char data[512] = {0};
      int len;
      size_t len2 = sizeof(data);
      RSA *rsa = EVP_PKEY_get1_RSA(pubkey);

      if(RAND_bytes(secret, sizeof(secret)) <= 0) {
        fprintf(stderr, "error: no randomness.\n");
        ret = false;
        goto decipher_out;
      }

      len = RSA_public_encrypt(sizeof(secret), secret, data, rsa, RSA_PKCS1_PADDING);
      if(len < 0) {
        fprintf(stderr, "Failed performing RSA encryption!\n");
        goto decipher_out;
      }
      if(ykpiv_decipher_data(state, data, (size_t)len, data, &len2, algorithm, key) != YKPIV_OK) {
        fprintf(stderr, "RSA decrypt failed!\n");
        goto decipher_out;
      }
      /* for some reason we have to give the padding check function data + 1 */
      len = RSA_padding_check_PKCS1_type_2(secret2, sizeof(secret2), data + 1, len2 - 1, RSA_size(rsa));
      if(len == sizeof(secret)) {
        if(verbose) {
          fprintf(stderr, "Generated nonce: ");
          dump_data(secret, sizeof(secret), stderr, true, format_arg_hex);
          fprintf(stderr, "Decrypted nonce: ");
          dump_data(secret2, sizeof(secret2), stderr, true, format_arg_hex);
        }
        if(memcmp(secret, secret2, sizeof(secret)) == 0) {
          fprintf(stderr, "Successfully performed RSA decryption!\n");
          ret = true;
        } else {
          fprintf(stderr, "Failed performing RSA decryption!\n");
        }
      } else {
        fprintf(stderr, "Failed unwrapping PKCS1 envelope.\n");
      }
    } else if(YKPIV_IS_EC(algorithm)) {
      unsigned char secret[48] = {0};
      unsigned char secret2[48] = {0};
      unsigned char public_key[97] = {0};
      unsigned char *ptr = public_key;
      size_t len = sizeof(secret);
      EC_KEY *ec = EVP_PKEY_get1_EC_KEY(pubkey);
      int nid;
      size_t key_len;

      if(algorithm == YKPIV_ALGO_ECCP256) {
        nid = NID_X9_62_prime256v1;
        key_len = 32;
      } else {
        nid = NID_secp384r1;
        key_len = 48;
      }

      tmpkey = EC_KEY_new_by_curve_name(nid);
      if(EC_KEY_generate_key(tmpkey) != 1) {
        fprintf(stderr, "Failed to generate EC key\n");
        goto decipher_out;
      }
      if(ECDH_compute_key(secret, len, EC_KEY_get0_public_key(ec), tmpkey, NULL) == -1) {
        fprintf(stderr, "Failed to compute ECDH key\n");
        goto decipher_out;
      }

      if(i2o_ECPublicKey(tmpkey, &ptr) < 0) {
        fprintf(stderr, "Failed to parse EC public key\n");
        goto decipher_out;
      }
      if(ykpiv_decipher_data(state, public_key, (key_len * 2) + 1, secret2, &len, algorithm, key) != YKPIV_OK) {
        fprintf(stderr, "Failed ECDH exchange!\n");
        goto decipher_out;
      }
      if(verbose) {
        fprintf(stderr, "ECDH host generated: ");
        dump_data(secret, len, stderr, true, format_arg_hex);
        fprintf(stderr, "ECDH card generated: ");
        dump_data(secret2, len, stderr, true, format_arg_hex);
      }
      if(memcmp(secret, secret2, key_len) == 0) {
        fprintf(stderr, "Successfully performed ECDH exchange with card.\n");
        ret = true;
      } else {
        fprintf(stderr, "ECDH exchange with card failed!\n");
      }
    }
  }

decipher_out:
  if(tmpkey) {
    EC_KEY_free(tmpkey);
  }
  if(pubkey) {
    EVP_PKEY_free(pubkey);
  }
  if(x509) {
    X509_free(x509);
  }
  if(input_file != stdin) {
    fclose(input_file);
  }
  return ret;
}

static bool list_readers(ykpiv_state *state) {
  char readers[2048] = {0};
  char *reader_ptr;
  size_t len = sizeof(readers);
  ykpiv_rc rc = ykpiv_list_readers(state, readers, &len);
  if(rc != YKPIV_OK) {
    fprintf(stderr, "Failed listing readers.\n");
    return false;
  }
  for(reader_ptr = readers; *reader_ptr != '\0'; reader_ptr += strlen(reader_ptr) + 1) {
    printf("%s\n", reader_ptr);
  }
  return true;
}

static bool attest(ykpiv_state *state, enum enum_slot slot,
    enum enum_key_format key_format, const char *output_file_name) {
  unsigned char data[2048] = {0};
  size_t len = sizeof(data);
  bool ret = false;
  X509 *x509 = NULL;
  int key;
  FILE *output_file = open_file(output_file_name, key_file_mode(key_format, true));
  if(!output_file) {
    return false;
  }

  if(key_format != key_format_arg_PEM && key_format != key_format_arg_DER) {
    fprintf(stderr, "Only PEM and DER format are supported for attest..\n");
    return false;
  }

  key = get_slot_hex(slot);
  if (ykpiv_attest(state, key, data, &len) != YKPIV_OK) {
    fprintf(stderr, "Failed to attest data.\n");
    goto attest_out;
  }

  if(key_format == key_format_arg_PEM) {
    const unsigned char *ptr = data;
    int len2 = (int)len;
    x509 = d2i_X509(NULL, &ptr, len2);
    if(!x509) {
      fprintf(stderr, "Failed parsing x509 information.\n");
      goto attest_out;
    }
    if(PEM_write_X509(output_file, x509) != 1){
      fprintf(stderr, "Failed writing x509 information\n");
    }
  } else {
    fwrite(data, len, 1, output_file);
  }
  ret = true;

attest_out:
  if(output_file != stdout) {
    fclose(output_file);
  }
  if(x509) {
    X509_free(x509);
  }
  return ret;
}

static bool write_object(ykpiv_state *state, int id,
    const char *input_file_name, int verbosity, enum enum_format format) {
  bool ret = false;
  FILE *input_file = NULL;
  unsigned char data[YKPIV_OBJ_MAX_SIZE] = {0};
  size_t len = sizeof(data);
  ykpiv_rc res;

  input_file = open_file(input_file_name, data_file_mode(format, false));
  if(!input_file) {
    return false;
  }

  if(isatty(fileno(input_file))) {
    fprintf(stderr, "Please paste the data...\n");
  }

  len = read_data(data, len, input_file, format);
  if(len == 0) {
    fprintf(stderr, "Failed reading data\n");
    goto write_out;
  }

  if(verbosity) {
    fprintf(stderr, "Writing %lu bytes of data to object %x.\n", (long unsigned int)len, id);
  }

  if((res = ykpiv_save_object(state, id, data, len)) != YKPIV_OK) {
    fprintf(stderr, "Failed writing data to device: %s\n", ykpiv_strerror(res));
  } else {
    ret = true;
  }

write_out:
  if(input_file != stdin) {
    fclose(input_file);
  }
  return ret;
}

static bool read_object(ykpiv_state *state, int id, const char *output_file_name,
    enum enum_format format) {
  FILE *output_file = NULL;
  unsigned char data[YKPIV_OBJ_MAX_SIZE] = {0};
  unsigned long len = sizeof(data);
  bool ret = false;

  output_file = open_file(output_file_name, data_file_mode(format, true));
  if(!output_file) {
    return false;
  }

  if(ykpiv_fetch_object(state, id, data, &len) != YKPIV_OK) {
    fprintf(stderr, "Failed fetching object.\n");
    goto read_out;
  }

  dump_data(data, len, output_file, false, format);
  ret = true;

read_out:
  if(output_file != stdout) {
    fclose(output_file);
  }
  return ret;
}

int main(int argc, char *argv[]) {
  struct gengetopt_args_info args_info;
  const uint8_t mgm_algo[] = {YKPIV_ALGO_3DES, YKPIV_ALGO_AES128, YKPIV_ALGO_AES192, YKPIV_ALGO_AES256};
  ykpiv_state *state;
  ykpiv_rc rc;
  int verbosity;
  enum enum_action action;
  unsigned int i;
  int ret = EXIT_SUCCESS;
  bool authed = false;
  char pwbuf[128] = {0};
  char *password;

  if (setlocale(LC_ALL, "") == NULL) {
    fprintf(stderr, "Warning, unable to reset locale\n");
  }

  if(cmdline_parser(argc, argv, &args_info) != 0) {
    return EXIT_FAILURE;
  }

  verbosity = args_info.verbose_arg ? args_info.verbose_arg : (int)args_info.verbose_given;
  password = args_info.password_arg;

  for(i = 0; i < args_info.action_given; i++) {
    action = *(args_info.action_arg + i);
    switch(action) {
      case action_arg_requestMINUS_certificate:
      case action_arg_selfsignMINUS_certificate:
        if(!args_info.subject_arg) {
          fprintf(stderr, "The '%s' action needs a subject (-S) to operate on.\n",
              cmdline_parser_action_values[action]);
          cmdline_parser_free(&args_info);
          return EXIT_FAILURE;
        }
        /* fall through */
      case action_arg_generate:
      case action_arg_importMINUS_key:
      case action_arg_importMINUS_certificate:
      case action_arg_deleteMINUS_certificate:
      case action_arg_readMINUS_certificate:
      case action_arg_testMINUS_signature:
      case action_arg_testMINUS_decipher:
      case action_arg_attest:
      case action_arg_deleteMINUS_key:
        if(args_info.slot_arg == slot__NULL) {
          fprintf(stderr, "The '%s' action needs a slot (-s) to operate on.\n",
              cmdline_parser_action_values[action]);
          cmdline_parser_free(&args_info);
          return EXIT_FAILURE;
        }
        break;
      case action_arg_moveMINUS_key:
        if(args_info.slot_arg == slot__NULL || args_info.to_slot_arg == to_slot__NULL) {
          fprintf(stderr, "The '%s' action needs both a slot (-s) to operate on and a --to-slot to move the key to.\n",
                  cmdline_parser_action_values[action]);
          cmdline_parser_free(&args_info);
          return EXIT_FAILURE;
        }
        break;
      case action_arg_pinMINUS_retries:
        if(!args_info.pin_retries_given || !args_info.puk_retries_given) {
          fprintf(stderr, "The '%s' action needs both --pin-retries and --puk-retries arguments.\n",
              cmdline_parser_action_values[action]);
          cmdline_parser_free(&args_info);
          return EXIT_FAILURE;
        }
        break;
      case action_arg_writeMINUS_object:
      case action_arg_readMINUS_object:
        if(!args_info.id_given) {
          fprintf(stderr, "The '%s' action needs the --id argument.\n",
              cmdline_parser_action_values[action]);
          cmdline_parser_free(&args_info);
          return EXIT_FAILURE;
        }
        break;
      case action_arg_changeMINUS_pin:
      case action_arg_changeMINUS_puk:
      case action_arg_unblockMINUS_pin:
      case action_arg_verifyMINUS_pin:
      case action_arg_setMINUS_mgmMINUS_key:
      case action_arg_setMINUS_chuid:
      case action_arg_setMINUS_ccc:
      case action_arg_version:
      case action_arg_reset:
      case action_arg_status:
      case action_arg_listMINUS_readers:
      case action__NULL:
      default:
        continue;
    }
  }

  /* openssl setup.. */
#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
  OpenSSL_add_all_algorithms();
#else
  OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, 0);
#endif

  if((rc = ykpiv_init(&state, verbosity)) != YKPIV_OK) {
    fprintf(stderr, "Failed initializing library: %s.\n", ykpiv_strerror(rc));
    cmdline_parser_free(&args_info);
    return EXIT_FAILURE;
  }

  if((rc = ykpiv_connect(state, args_info.reader_arg)) != YKPIV_OK) {
    fprintf(stderr, "Failed to connect to yubikey: %s.\n", ykpiv_strerror(rc));
    if (rc == YKPIV_PCSC_SERVICE_ERROR) {
      fprintf(stderr, "Try restarting the PCSC subsystem.\n");
    } else if (rc == YKPIV_PCSC_ERROR) {
      fprintf(stderr, "Try removing and reconnecting the device.\n");
    }
    ykpiv_done(state);
    cmdline_parser_free(&args_info);
    return EXIT_FAILURE;
  }

  for(i = 0; i < args_info.action_given; i++) {
    action = *(args_info.action_arg + i);
    if(verbosity) {
      fprintf(stderr, "Now processing for action '%s'.\n",
          cmdline_parser_action_values[action]);
    }
    switch(action) {
      case action_arg_importMINUS_key:
      case action_arg_importMINUS_certificate:
        if(args_info.key_format_arg == key_format_arg_PKCS12 && !password) {
          if(verbosity) {
            fprintf(stderr, "Asking for password since action '%s' needs it.\n", cmdline_parser_action_values[action]);
          }
          if(!read_pw("Password", pwbuf, sizeof(pwbuf), false, args_info.stdin_input_flag)) {
            fprintf(stderr, "Failed to get password.\n");
            ykpiv_done(state);
            cmdline_parser_free(&args_info);
            return EXIT_FAILURE;
          }
          password = pwbuf;
        }
        /* fall through */
      case action_arg_generate:
      case action_arg_setMINUS_mgmMINUS_key:
      case action_arg_pinMINUS_retries:
      case action_arg_setMINUS_chuid:
      case action_arg_setMINUS_ccc:
      case action_arg_deleteMINUS_certificate:
      case action_arg_writeMINUS_object:
      case action_arg_moveMINUS_key:
      case action_arg_deleteMINUS_key:
        if(!authed) {
          if(verbosity) {
            fprintf(stderr, "Authenticating since action '%s' needs that.\n", cmdline_parser_action_values[action]);
          }
          ykpiv_config cfg = {0};
          if((rc = ykpiv_util_get_config(state, &cfg)) != YKPIV_OK) {
            fprintf(stderr, "Failed to get config metadata: %s.\n", ykpiv_strerror(rc));
            ykpiv_done(state);
            cmdline_parser_free(&args_info);
            return EXIT_FAILURE;
          }
          if(cfg.mgm_type != YKPIV_CONFIG_MGM_PROTECTED) {
            char keybuf[KEY_LEN * 2 + 2] = {0}; /* one extra byte for potential \n */
            char *key_ptr = args_info.key_arg;
            if(args_info.key_given && args_info.key_orig == NULL) {
              if(!read_pw("management key", keybuf, sizeof(keybuf), false, args_info.stdin_input_flag)) {
                fprintf(stderr, "Failed to read management key from stdin,\n");
                ykpiv_done(state);
                cmdline_parser_free(&args_info);
                return EXIT_FAILURE;
              }
              key_ptr = keybuf;
            }
            cfg.mgm_len = sizeof(cfg.mgm_key);
            if((rc = ykpiv_hex_decode(key_ptr, strlen(key_ptr), cfg.mgm_key, &cfg.mgm_len)) != YKPIV_OK) {
              fprintf(stderr, "Failed decoding key: %s.\n", ykpiv_strerror(rc));
              ykpiv_done(state);
              cmdline_parser_free(&args_info);
              return EXIT_FAILURE;
            }
          }
          if((rc = ykpiv_authenticate2(state, cfg.mgm_key, cfg.mgm_len)) != YKPIV_OK) {
            fprintf(stderr, "Failed authentication with the application: %s.\n", ykpiv_strerror(rc));
            ykpiv_done(state);
            cmdline_parser_free(&args_info);
            return EXIT_FAILURE;
          }
          if(verbosity) {
            fprintf(stderr, "Successful application authentication.\n");
          }
          authed = true;
        } else {
          if(verbosity) {
            fprintf(stderr, "Skipping authentication for action '%s' since it's already done.\n", cmdline_parser_action_values[action]);
          }
        }
        break;
      case action_arg_version:
      case action_arg_reset:
      case action_arg_requestMINUS_certificate:
      case action_arg_verifyMINUS_pin:
      case action_arg_changeMINUS_pin:
      case action_arg_changeMINUS_puk:
      case action_arg_unblockMINUS_pin:
      case action_arg_selfsignMINUS_certificate:
      case action_arg_readMINUS_certificate:
      case action_arg_status:
      case action_arg_testMINUS_signature:
      case action_arg_testMINUS_decipher:
      case action_arg_listMINUS_readers:
      case action_arg_attest:
      case action_arg_readMINUS_object:
      case action__NULL:
      default:
        if(verbosity) {
          fprintf(stderr, "Action '%s' does not need authentication.\n", cmdline_parser_action_values[action]);
        }
    }
    switch(action) {
      case action_arg_version:
        print_version(state, args_info.output_arg);
        break;
      case action_arg_generate:
        if(generate_key(state, args_info.slot_arg, args_info.algorithm_arg, args_info.output_arg, args_info.key_format_arg,
              args_info.pin_policy_arg, args_info.touch_policy_arg) == false) {
          ret = EXIT_FAILURE;
        } else {
          fprintf(stderr, "Successfully generated a new private key.\n");
        }
        break;
      case action_arg_setMINUS_mgmMINUS_key:
        {
          char new_keybuf[KEY_LEN * 2 + 2] = {0}; /* one extra byte for potential \n */
          char *new_mgm_key = args_info.new_key_arg;
          if(!new_mgm_key) {
            if(!read_pw("new management key", new_keybuf, sizeof(new_keybuf), true, args_info.stdin_input_flag)) {
              fprintf(stderr, "Failed to read management key from stdin,\n");
              ret = EXIT_FAILURE;
              break;
            }
            new_mgm_key = new_keybuf;
          }
          ykpiv_mgm new_key = {KEY_LEN};
          if((rc = ykpiv_hex_decode(new_mgm_key, strlen(new_mgm_key), new_key.data, &new_key.len)) != YKPIV_OK) {
            fprintf(stderr, "Failed decoding new key: %s.\n", ykpiv_strerror(rc));
            ret = EXIT_FAILURE;
          } else if((rc = ykpiv_set_mgmkey3(state, new_key.data, new_key.len, mgm_algo[args_info.new_key_algo_arg],
                        get_touch_policy(args_info.touch_policy_arg))) != YKPIV_OK) {
            fprintf(stderr, "Failed setting the new key: %s.\n", ykpiv_strerror(rc));
            if(args_info.touch_policy_arg != touch_policy__NULL) {
              fprintf(stderr, " Maybe this touch policy or algorithm is not supported on this key?");
            }
            fprintf(stderr, "\n");
            ret = EXIT_FAILURE;
          } else {
            fprintf(stderr, "Successfully set new management key.\n");
            ykpiv_config config = {0};
            if((rc = ykpiv_util_get_config(state, &config)) != YKPIV_OK) {
              fprintf(stderr, "Failed reading configuration metadata: %s.\n", ykpiv_strerror(rc));
            } else {
              if (config.mgm_type == YKPIV_CONFIG_MGM_PROTECTED) {
                if((rc = ykpiv_util_update_protected_mgm(state, &new_key)) != YKPIV_OK) {
                  fprintf(stderr, "Failed updating pin-protected management key metadata: %s.\n", ykpiv_strerror(rc));
                } else {
                  fprintf(stderr, "Successfully updated pin-protected management key metadata.\n");
                }
              }
            }
          }
        }
        break;
      case action_arg_reset:
        if(reset(state) == false) {
          fprintf(stderr, "Reset failed, are pincodes blocked?\n");
          ret = EXIT_FAILURE;
        } else {
          fprintf(stderr, "Successfully reset the application.\n");
        }
        break;
      case action_arg_pinMINUS_retries:
        if(set_pin_retries(state, args_info.pin_retries_arg, args_info.puk_retries_arg, verbosity) == false) {
          fprintf(stderr, "Failed changing pin retries.\n");
          ret = EXIT_FAILURE;
        } else {
          fprintf(stderr, "Successfully changed pin retries to %d and puk retries to %d, both codes have been reset to default now.\n",
              args_info.pin_retries_arg, args_info.puk_retries_arg);
        }
        break;
      case action_arg_importMINUS_key:
        if(import_key(state, args_info.key_format_arg, args_info.input_arg, args_info.slot_arg, password,
              args_info.pin_policy_arg, args_info.touch_policy_arg) == false) {
          fprintf(stderr, "Unable to import private key\n");
          ret = EXIT_FAILURE;
        } else {
          fprintf(stderr, "Successfully imported a new private key.\n");
        }
        break;
      case action_arg_importMINUS_certificate:
        if(import_cert(state, args_info.key_format_arg, args_info.compress_flag, args_info.input_arg, args_info.slot_arg, password) == false) {
          ret = EXIT_FAILURE;
        } else {
          fprintf(stderr, "Successfully imported a new certificate.\n");
        }
        break;
      case action_arg_setMINUS_ccc:
      case action_arg_setMINUS_chuid:
        if(set_cardid(state, verbosity, action == action_arg_setMINUS_chuid ? CHUID : CCC) == false) {
          ret = EXIT_FAILURE;
        } else {
          fprintf(stderr, "Successfully set new %s.\n", action == action_arg_setMINUS_chuid ? "CHUID" : "CCC");
        }
        break;
      case action_arg_requestMINUS_certificate:
        if(request_certificate(state, args_info.key_format_arg, args_info.input_arg,
              args_info.slot_arg, args_info.subject_arg, args_info.hash_arg,
              args_info.output_arg, args_info.attestation_flag) == false) {
          ret = EXIT_FAILURE;
        } else {
          fprintf(stderr, "Successfully generated a certificate request.\n");
        }
        break;
      case action_arg_verifyMINUS_pin: {
        char pinbuf[8+2] = {0};
        char *pin = args_info.pin_arg;

        if(!pin) {
          if (!read_pw("PIN", pinbuf, sizeof(pinbuf), false, args_info.stdin_input_flag)) {
            fprintf(stderr, "Failed to get PIN.\n");
            ykpiv_done(state);
            cmdline_parser_free(&args_info);
            return EXIT_FAILURE;
          }
          pin = pinbuf;
        }
        if(verify_pin(state, pin)) {
          fprintf(stderr, "Successfully verified PIN.\n");
        } else {
          ret = EXIT_FAILURE;
        }
        break;
      }
      case action_arg_changeMINUS_pin:
      case action_arg_changeMINUS_puk:
      case action_arg_unblockMINUS_pin: {
        char pinbuf[8+2] = {0};
        char new_pinbuf[8+2] = {0};
        char *pin = args_info.pin_arg;
        char *new_pin = args_info.new_pin_arg;
        const char *name = action == action_arg_changeMINUS_pin ? "pin" : "puk";
        const char *new_name = action == action_arg_changeMINUS_puk ? "new puk" : "new pin";

        if(!pin) {
          if (!read_pw(name, pinbuf, sizeof(pinbuf), false, args_info.stdin_input_flag)) {
            fprintf(stderr, "Failed to get %s.\n", name);
            ykpiv_done(state);
            cmdline_parser_free(&args_info);
            return EXIT_FAILURE;
          }
          pin = pinbuf;
        }
        if(!new_pin) {
          if (!read_pw(new_name, new_pinbuf, sizeof(new_pinbuf), true, args_info.stdin_input_flag)) {
            fprintf(stderr, "Failed to get %s.\n", new_name);
            ykpiv_done(state);
            cmdline_parser_free(&args_info);
            return EXIT_FAILURE;
          }
          new_pin = new_pinbuf;
        }
        if(change_pin(state, action, pin, new_pin)) {
          if(action == action_arg_unblockMINUS_pin) {
            fprintf(stderr, "Successfully unblocked the pin code.\n");
          } else {
            fprintf(stderr, "Successfully changed the %s code.\n",
                action == action_arg_changeMINUS_pin ? "pin" : "puk");
          }
        } else {
          ret = EXIT_FAILURE;
        }
        break;
      }
      case action_arg_selfsignMINUS_certificate:
        if(selfsign_certificate(state, args_info.key_format_arg, args_info.input_arg,
              args_info.slot_arg, args_info.subject_arg, args_info.hash_arg,
              args_info.serial_given ? &args_info.serial_arg : NULL, args_info.valid_days_arg,
              args_info.output_arg, args_info.attestation_flag) == false) {
          ret = EXIT_FAILURE;
        } else {
          fprintf(stderr, "Successfully generated a new self signed certificate.\n");
        }
        break;
      case action_arg_deleteMINUS_certificate:
        if(delete_certificate(state, args_info.slot_arg) == false) {
          ret = EXIT_FAILURE;
        }
        break;
      case action_arg_readMINUS_certificate:
        if(read_certificate(state, args_info.slot_arg, args_info.key_format_arg,
              args_info.output_arg) == false) {
          ret = EXIT_FAILURE;
        }
        break;
      case action_arg_status:
        if(status(state, args_info.hash_arg, args_info.slot_arg, args_info.output_arg) == false) {
          ret = EXIT_FAILURE;
        }
        break;
      case action_arg_testMINUS_signature:
        if(test_signature(state, args_info.slot_arg, args_info.hash_arg,
              args_info.input_arg, args_info.key_format_arg, verbosity) == false) {
          ret = EXIT_FAILURE;
        }
        break;
      case action_arg_testMINUS_decipher:
        if(test_decipher(state, args_info.slot_arg, args_info.input_arg,
              args_info.key_format_arg, verbosity) == false) {
          ret = EXIT_FAILURE;
        }
        break;
      case action_arg_listMINUS_readers:
        if(list_readers(state) == false) {
          ret = EXIT_FAILURE;
        }
        break;
      case action_arg_writeMINUS_object:
        if(write_object(state, args_info.id_arg, args_info.input_arg, verbosity,
              args_info.format_arg) == false) {
          ret = EXIT_FAILURE;
        }
        break;
      case action_arg_readMINUS_object:
        if(read_object(state, args_info.id_arg, args_info.output_arg,
              args_info.format_arg) == false) {
          ret = EXIT_FAILURE;
        }
        break;
      case action_arg_attest:
        if(attest(state, args_info.slot_arg, args_info.key_format_arg,
              args_info.output_arg) == false) {
          ret = EXIT_FAILURE;
        }
        break;
      case action_arg_moveMINUS_key: {
        int from_slot = get_slot_hex(args_info.slot_arg);
        int to_slot = get_slot_hex((enum enum_slot) args_info.to_slot_arg);
        if (move_key(state, from_slot, to_slot) == false) {
          ret = EXIT_FAILURE;
        } else {
          fprintf(stderr, "Successfully moved key.\n");
        }
        break;
      }
      case action_arg_deleteMINUS_key:
        if(move_key(state, get_slot_hex(args_info.slot_arg), 0xFF) == false) {
          ret = EXIT_FAILURE;
        } else {
          fprintf(stderr, "Successfully deleted key.\n");
        }
        break;
      case action__NULL:
      default:
        fprintf(stderr, "Wrong action. %d.\n", action);
        ret = EXIT_FAILURE;
    }
    if(ret == EXIT_FAILURE) {
      break;
    }
  }

  if(ret == EXIT_SUCCESS && args_info.sign_flag) {
    if(args_info.slot_arg == slot__NULL) {
      fprintf(stderr, "The sign action needs a slot (-s) to operate on.\n");
      ret = EXIT_FAILURE;
    }
    else if(sign_file(state, args_info.input_arg, args_info.output_arg,
        args_info.slot_arg, args_info.algorithm_arg, args_info.hash_arg,
        verbosity)) {
      fprintf(stderr, "Signature successful!\n");
    } else {
      ret = EXIT_FAILURE;
    }
  }

  ykpiv_done(state);
#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
  EVP_cleanup();
#endif
  cmdline_parser_free(&args_info);
  return ret;
}
