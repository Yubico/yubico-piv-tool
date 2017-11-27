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

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "ykpiv.h"

#ifdef _WIN32
#include <windows.h>
#endif

#include "openssl-compat.h"
#include <openssl/des.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/rand.h>

#include "cmdline.h"
#include "util.h"

#define MAX(a,b) (a) > (b) ? (a) : (b)
#define MIN(a,b) (a) < (b) ? (a) : (b)

#define CHUID 0
#define CCC 1

#define MAX_OID_LEN 19

#define KEY_LEN 24

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
  char version[7];
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

  unsigned char signinput[1024];
  if(YKPIV_IS_RSA(algorithm)) {
    size_t padlen = algorithm == YKPIV_ALGO_RSA1024 ? 128 : 256;
    if(RSA_padding_add_PKCS1_type_1(signinput, padlen, in, len) == 0) {
      fprintf(stderr, "Failed adding padding.\n");
      return false;
    }
    in = signinput;
    len = padlen;
  }
  if(ykpiv_sign_data(state, in, len, out, out_len, algorithm, key) == YKPIV_OK) {
    return true;
  }
  return false;
}

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
static int ec_key_ex_data_idx = -1;

struct internal_key {
  ykpiv_state *state;
  int algorithm;
  int key;
};

int yk_rsa_meth_sign(int dtype, const unsigned char *m, unsigned int m_length,
    unsigned char *sigret, unsigned int *siglen, const RSA *rsa) {
  const RSA_METHOD *meth = RSA_get_method(rsa);
  const struct internal_key *key = RSA_meth_get0_app_data(meth);
  if (sign_data(key->state, m, m_length, sigret, (size_t *)siglen, key->algorithm, key->key))
    return 0;

  return 1;
}

int yk_ec_meth_sign(int type, const unsigned char *dgst, int dlen,
    unsigned char *sig, unsigned int *siglen, const BIGNUM *kinv,
    const BIGNUM *r, EC_KEY *ec) {
  const struct internal_key *key = EC_KEY_get_ex_data(ec, ec_key_ex_data_idx);
  if (sign_data(key->state, dgst, dlen, sig, (size_t *)siglen, key->algorithm, key->key))
    return 0;

  return 1;
}

static int wrap_public_key(ykpiv_state *state, int algorithm, EVP_PKEY *public_key,
    int key) {
  if(YKPIV_IS_RSA(algorithm)) {
    RSA_METHOD *meth = RSA_meth_dup(RSA_get_default_method());
    RSA *rsa = EVP_PKEY_get0_RSA(public_key);
    struct internal_key int_key = {state, algorithm, key};
    RSA_meth_set0_app_data(meth, &int_key);
    RSA_meth_set_sign(meth, yk_rsa_meth_sign);
    RSA_set_method(rsa, meth);
  } else {
    EC_KEY *ec = EVP_PKEY_get0_EC_KEY(public_key);
    EC_KEY_METHOD *meth = EC_KEY_METHOD_new(EC_KEY_get_method(ec));
    struct internal_key int_key = {state, algorithm, key};
    if (ec_key_ex_data_idx == -1)
      ec_key_ex_data_idx = EC_KEY_get_ex_new_index(0, NULL, NULL, NULL, 0);
    EC_KEY_set_ex_data(ec, ec_key_ex_data_idx, &int_key);
    EC_KEY_METHOD_set_sign(meth, yk_ec_meth_sign, NULL, NULL); /* XXX ?? */
    EC_KEY_set_method(ec, meth);
  }
  return 0;
}
#endif

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

  if(key_format == key_format_arg_PEM) {
    public_key = EVP_PKEY_new();
    if(algorithm == algorithm_arg_RSA1024 || algorithm == algorithm_arg_RSA2048) {
      BIGNUM *bignum_n = NULL;
      BIGNUM *bignum_e = NULL;
      rsa = RSA_new();
      bignum_n = BN_bin2bn(mod, mod_len, NULL);
      if (bignum_n == NULL) {
        fprintf(stderr, "Failed to parse public key modulus.\n");
        goto generate_out;
      }
      bignum_e = BN_bin2bn(exp, exp_len, NULL);
      if(bignum_e == NULL) {
        fprintf(stderr, "Failed to parse public key exponent.\n");
        goto generate_out;
      }

      RSA_set0_key(rsa, bignum_n, bignum_e, NULL);
      EVP_PKEY_set1_RSA(public_key, rsa);
    } else if(algorithm == algorithm_arg_ECCP256 || algorithm == algorithm_arg_ECCP384) {
      EC_GROUP *group;
      int nid;

      if(algorithm == algorithm_arg_ECCP256) {
        nid = NID_X9_62_prime256v1;
      } else {
        nid = NID_secp384r1;
      }
      eckey = EC_KEY_new();
      group = EC_GROUP_new_by_curve_name(nid);
      EC_GROUP_set_asn1_flag(group, nid);
      EC_KEY_set_group(eckey, group);
      ecpoint = EC_POINT_new(group);

      if(!EC_POINT_oct2point(group, ecpoint, point, point_len, NULL)) {
        fprintf(stderr, "Failed to load public point.\n");
        goto generate_out;
      }
      if(!EC_KEY_set_public_key(eckey, ecpoint)) {
        fprintf(stderr, "Failed to set the public key.\n");
        goto generate_out;
      }
      EVP_PKEY_set1_EC_KEY(public_key, eckey);
    } else {
      fprintf(stderr, "Wrong algorithm.\n");
    }
    PEM_write_PUBKEY(output_file, public_key);
    ret = true;
  } else {
    fprintf(stderr, "Only PEM is supported as public_key output.\n");
    goto generate_out;
  }

generate_out:
  if (output_file != stdout) {
    fclose(output_file);
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
    if(PKCS12_parse(p12, password, &private_key, &cert, NULL) == 0) {
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
    unsigned char pp = YKPIV_PINPOLICY_DEFAULT;
    unsigned char tp = YKPIV_TOUCHPOLICY_DEFAULT;

    if(algorithm == 0) {
      goto import_out;
    }

    if(pin_policy != pin_policy__NULL) {
        pp = get_pin_policy(pin_policy);
    }

    if(touch_policy != touch_policy__NULL) {
      tp = get_touch_policy(touch_policy);
    }

    if(YKPIV_IS_RSA(algorithm)) {
      RSA *rsa_private_key = EVP_PKEY_get1_RSA(private_key);
      unsigned char e[4];
      unsigned char p[128];
      unsigned char q[128];
      unsigned char dmp1[128];
      unsigned char dmq1[128];
      unsigned char iqmp[128];
      const BIGNUM *bn_e, *bn_p, *bn_q, *bn_dmp1, *bn_dmq1, *bn_iqmp;

      int element_len = 128;
      if(algorithm == YKPIV_ALGO_RSA1024) {
        element_len = 64;
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
      unsigned char s_ptr[48];

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

static bool import_cert(ykpiv_state *state, enum enum_key_format cert_format,
    const char *input_file_name, enum enum_slot slot, char *password) {
  bool ret = false;
  FILE *input_file = NULL;
  X509 *cert = NULL;
  PKCS12 *p12 = NULL;
  EVP_PKEY *private_key = NULL;
  int compress = 0;
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
    cert_len = st.st_size;
    compress = 0x01;
  } else {
    /* TODO: more formats go here */
    fprintf(stderr, "Unknown key format.\n");
    goto import_cert_out;
  }
  if(cert_len == -1) {
    cert_len = i2d_X509(cert, NULL);
  }

  {
    unsigned char certdata[YKPIV_OBJ_MAX_SIZE];
    unsigned char *certptr = certdata;
    ykpiv_rc res;
    if (compress) {
      if (fread(certdata, 1, (size_t)cert_len, input_file) != (size_t)cert_len) {
        fprintf(stderr, "Failed to read compressed certificate\n");
        goto import_cert_out;
      }
    } else {
      i2d_X509(cert, &certptr);
    }
    if ((res = ykpiv_util_write_cert(state, get_slot_hex(slot), certdata, cert_len, compress)) != YKPIV_OK) {
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
  unsigned char id[MAX(sizeof(ykpiv_cardid), sizeof(ykpiv_cccid))];

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

static bool request_certificate(ykpiv_state *state, enum enum_key_format key_format,
    const char *input_file_name, enum enum_slot slot, char *subject, enum enum_hash hash,
    const char *output_file_name) {
  X509_REQ *req = NULL;
  X509_NAME *name = NULL;
  FILE *input_file = NULL;
  FILE *output_file = NULL;
  EVP_PKEY *public_key = NULL;
  const EVP_MD *md;
  bool ret = false;
  unsigned char digest[EVP_MAX_MD_SIZE + MAX_OID_LEN];
  unsigned int digest_len;
  unsigned int md_len;
  unsigned char algorithm;
  int key = 0;
  unsigned char *signinput;
  size_t len = 0;
  size_t oid_len;
  const unsigned char *oid;
  int nid;
  ASN1_TYPE null_parameter;

  null_parameter.type = V_ASN1_NULL;
  null_parameter.value.ptr = NULL;

  key = get_slot_hex(slot);

  input_file = open_file(input_file_name, key_file_mode(key_format, false));
  output_file = open_file(output_file_name, key_file_mode(key_format, true));
  if(!input_file || !output_file) {
    goto request_out;
  }

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
  algorithm = get_algorithm(public_key);
  if(algorithm == 0) {
    goto request_out;
  }

  md = get_hash(hash, &oid, &oid_len);
  if(md == NULL) {
    goto request_out;
  }

  md_len = (unsigned int)EVP_MD_size(md);
  digest_len = sizeof(digest) - md_len;

  req = X509_REQ_new();
  if(!req) {
    fprintf(stderr, "Failed to allocate request structure.\n");
    goto request_out;
  }
  if(!X509_REQ_set_pubkey(req, public_key)) {
    fprintf(stderr, "Failed setting the request public key.\n");
    goto request_out;
  }

  X509_REQ_set_version(req, 0);

  name = parse_name(subject);
  if(!name) {
    fprintf(stderr, "Failed encoding subject as name.\n");
    goto request_out;
  }
  if(!X509_REQ_set_subject_name(req, name)) {
    fprintf(stderr, "Failed setting the request subject.\n");
    goto request_out;
  }

#if OPENSSL_VERSION_NUMBER < 0x10100000L
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
    unsigned char signature[1024];
    size_t sig_len = sizeof(signature);
    if(!sign_data(state, signinput, len, signature, &sig_len, algorithm, key)) {
      fprintf(stderr, "Failed signing request.\n");
      goto request_out;
    }
    M_ASN1_BIT_STRING_set(req->signature, signature, sig_len);
    /* mark that all bits should be used. */
    req->signature->flags = ASN1_STRING_FLAG_BITS_LEFT;
  }
#else
  /* With opaque structures we can not touch whatever we want, but we need
   * to embed the sign_data function in the RSA/EC key structures  */
  wrap_public_key(state, algorithm, public_key, key);

  X509_REQ_sign(req, public_key, md);
#endif

  if(key_format == key_format_arg_PEM) {
    PEM_write_X509_REQ(output_file, req);
    ret = true;
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
  if(public_key) {
    EVP_PKEY_free(public_key);
  }
  if(req) {
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    if(req->sig_alg->parameter) {
      req->sig_alg->parameter = NULL;
    }
#endif
    X509_REQ_free(req);
  }
  if(name) {
    X509_NAME_free(name);
  }
  return ret;
}

static bool selfsign_certificate(ykpiv_state *state, enum enum_key_format key_format,
    const char *input_file_name, enum enum_slot slot, char *subject, enum enum_hash hash,
    const int *serial, int validDays, const char *output_file_name) {
  FILE *input_file = NULL;
  FILE *output_file = NULL;
  bool ret = false;
  EVP_PKEY *public_key = NULL;
  X509 *x509 = NULL;
  X509_NAME *name = NULL;
  const EVP_MD *md;
  unsigned char digest[EVP_MAX_MD_SIZE + MAX_OID_LEN];
  unsigned int digest_len;
  unsigned char algorithm;
  int key = 0;
  unsigned char *signinput;
  size_t len = 0;
  size_t oid_len;
  const unsigned char *oid;
  int nid;
  unsigned int md_len;
  ASN1_INTEGER *sno = ASN1_INTEGER_new();
  BIGNUM *ser = NULL;
  ASN1_TYPE null_parameter;

  null_parameter.type = V_ASN1_NULL;
  null_parameter.value.ptr = NULL;

  key = get_slot_hex(slot);

  input_file = open_file(input_file_name, key_file_mode(key_format, false));
  output_file = open_file(output_file_name, key_file_mode(key_format, true));
  if(!input_file || !output_file) {
    goto selfsign_out;
  }

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
  algorithm = get_algorithm(public_key);
  if(algorithm == 0) {
    goto selfsign_out;
  }

  md = get_hash(hash, &oid, &oid_len);
  if(md == NULL) {
    goto selfsign_out;
  }
  md_len = (unsigned int)EVP_MD_size(md);
  digest_len = sizeof(digest) - md_len;

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
    ASN1_INTEGER_set(sno, *serial);
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
  nid = get_hashnid(hash, algorithm);
  if(nid == 0) {
    goto selfsign_out;
  }
#if OPENSSL_VERSION_NUMBER < 0x10100000L
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
    unsigned char signature[1024];
    size_t sig_len = sizeof(signature);
    if(!sign_data(state, signinput, len, signature, &sig_len, algorithm, key)) {
      fprintf(stderr, "Failed signing certificate.\n");
      goto selfsign_out;
    }
    M_ASN1_BIT_STRING_set(x509->signature, signature, sig_len);
    /* setting flags to ASN1_STRING_FLAG_BITS_LEFT here marks that no bits
     * should be subtracted from the bit string, thus making sure that the
     * certificate can be validated. */
    x509->signature->flags = ASN1_STRING_FLAG_BITS_LEFT;
  }
#else
  /* With opaque structures we can not touch whatever we want, but we need
   * to embed the sign_data function in the RSA/EC key structures  */
  wrap_public_key(state, algorithm, public_key, key);

  X509_sign(x509, public_key, md);
#endif

  if(key_format == key_format_arg_PEM) {
    PEM_write_X509(output_file, x509);
    ret = true;
  } else {
    fprintf(stderr, "Only PEM support available for certificate requests.\n");
  }

selfsign_out:
  if(input_file && input_file != stdin) {
    fclose(input_file);
  }
  if(output_file && output_file != stdout) {
    fclose(output_file);
  }
  if(x509) {
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    if(x509->sig_alg->parameter) {
      x509->sig_alg->parameter = NULL;
      x509->cert_info->signature->parameter = NULL;
    }
#endif
    X509_free(x509);
  }
  if(public_key) {
    EVP_PKEY_free(public_key);
  }
  if(name) {
    X509_NAME_free(name);
  }
  if(ser) {
    BN_free(ser);
  }
  if(sno) {
    ASN1_INTEGER_free(sno);
  }
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
  } else if(res == YKPIV_WRONG_PIN) {
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
  int (*op)(ykpiv_state *state, const char * puk, size_t puk_len,
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
    x509 = X509_new();
    if (!x509) {
      fprintf(stderr, "Failed allocating x509 structure.\n");
      goto read_cert_out;
    }
    x509 = d2i_X509(NULL, (const unsigned char**)&ptr, cert_len);
    if (!x509) {
      fprintf(stderr, "Failed parsing x509 information.\n");
      goto read_cert_out;
    }

    if (key_format == key_format_arg_PEM) {
      PEM_write_X509(output_file, x509);
      ret = true;
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
  unsigned char hashed[EVP_MAX_MD_SIZE];
  bool ret = false;
  int algo;
  const EVP_MD *md;

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

    md = get_hash(hash, NULL, NULL);
    if(md == NULL) {
      goto out;
    }

    mdctx = EVP_MD_CTX_create();
    EVP_DigestInit_ex(mdctx, md, NULL);
    while(!feof(input_file)) {
      char buf[1024];
      size_t len = fread(buf, 1, 1024, input_file);
      EVP_DigestUpdate(mdctx, buf, len);
    }
    EVP_DigestFinal_ex(mdctx, hashed, &hash_len);

    if(verbosity) {
      fprintf(stderr, "file hashed as: ");
      dump_data(hashed, hash_len, stderr, true, format_arg_hex);
    }
    EVP_MD_CTX_destroy(mdctx);
  }

  if(YKPIV_IS_RSA(algo)) {
    prepare_rsa_signature(hashed, hash_len, hashed, &hash_len, EVP_MD_type(md));
  }

  {
    unsigned char buf[1024];
    size_t len = sizeof(buf);
    if(!sign_data(state, hashed, hash_len, buf, &len, algo, key)) {
      fprintf(stderr, "failed signing file\n");
      goto out;
    }

    if(verbosity) {
      fprintf(stderr, "file signed as: ");
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
  int object = ykpiv_util_slot_object(get_slot_hex(slot));
  int slot_name;
  unsigned char data[3072];
  const unsigned char *ptr = data;
  unsigned long len = sizeof(data);
  int cert_len;
  X509 *x509 = NULL;
  X509_NAME *subj;
  BIO *bio = NULL;

  if(ykpiv_fetch_object(state, object, data, &len) != YKPIV_OK) {
    return;
  }

  slot_name = get_slot_hex(slot);

  fprintf(output, "Slot %x:\t", slot_name);

  if(*ptr++ == 0x70) {
    unsigned int md_len = sizeof(data);
    ASN1_TIME *not_before, *not_after;

    ptr += get_length(ptr, &cert_len);
    x509 = X509_new();
    if(!x509) {
      fprintf(output, "Allocation failure.\n");
      return;
    }
    x509 = d2i_X509(NULL, &ptr, cert_len);
    if(!x509) {
      fprintf(output, "Unknown data present.\n");
      goto cert_out;
    }
    {
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
        case YKPIV_ALGO_ECCP256:
          fprintf(output, "ECCP256\n");
          break;
        case YKPIV_ALGO_ECCP384:
          fprintf(output, "ECCP384\n");
          break;
        default:
          fprintf(output, "Unknown\n");
      }
    }
    subj = X509_get_subject_name(x509);
    if(!subj) {
      fprintf(output, "Parse error.\n");
      goto cert_out;
    }
    fprintf(output, "\tSubject DN:\t");
    X509_NAME_print_ex_fp(output, subj, 0, XN_FLAG_COMPAT);
    fprintf(output, "\n");
    subj = X509_get_issuer_name(x509);
    if(!subj) {
      fprintf(output, "Parse error.\n");
      goto cert_out;
    }
    fprintf(output, "\tIssuer DN:\t");
    X509_NAME_print_ex_fp(output, subj, 0, XN_FLAG_COMPAT);
    fprintf(output, "\n");
    X509_digest(x509, md, data, &md_len);
    fprintf(output, "\tFingerprint:\t");
    dump_data(data, md_len, output, false, format_arg_hex);

    bio = BIO_new_fp(output, BIO_NOCLOSE | BIO_FP_TEXT);
    not_before = X509_get_notBefore(x509);
    if(not_before) {
      fprintf(output, "\tNot Before:\t");
      ASN1_TIME_print(bio, not_before);
      fprintf(output, "\n");
    }
    not_after = X509_get_notAfter(x509);
    if(not_after) {
      fprintf(output, "\tNot After:\t");
      ASN1_TIME_print(bio, not_after);
      fprintf(output, "\n");
    }
  } else {
    fprintf(output, "Parse error.\n");
    return;
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
  unsigned char buf[3072];
  long unsigned len = sizeof(buf);
  int i;
  FILE *output_file = open_file(output_file_name, OUTPUT_TEXT);
  if(!output_file) {
    return false;
  }

  md = get_hash(hash, NULL, NULL);
  if(md == NULL) {
    return false;
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
  unsigned char data[1024];
  unsigned int data_len;
  X509 *x509 = NULL;
  EVP_PKEY *pubkey;
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
    return false;
  }

  {
    unsigned char rand[128];
    EVP_MD_CTX *mdctx;
    if(RAND_bytes(rand, 128) == -1) {
      fprintf(stderr, "error: no randomness.\n");
      return false;
    }

    mdctx = EVP_MD_CTX_create();
    EVP_DigestInit_ex(mdctx, md, NULL);
    EVP_DigestUpdate(mdctx, rand, 128);
    EVP_DigestFinal_ex(mdctx, data, &data_len);
    if(verbose) {
      fprintf(stderr, "Test data hashes as: ");
      dump_data(data, data_len, stderr, true, format_arg_hex);
    }
  }

  {
    unsigned char signature[1024];
    unsigned char encoded[1024];
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
      default:
        fprintf(stderr, "Unknown algorithm.\n");
        goto test_out;
    }
  }
test_out:
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
  EVP_PKEY *pubkey;
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
      unsigned char secret[32];
      unsigned char secret2[32];
      unsigned char data[256];
      int len;
      size_t len2 = sizeof(data);
      RSA *rsa = EVP_PKEY_get1_RSA(pubkey);

      if(RAND_bytes(secret, sizeof(secret)) == -1) {
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
      unsigned char secret[48];
      unsigned char secret2[48];
      unsigned char public_key[97];
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
      EC_KEY_generate_key(tmpkey);
      ECDH_compute_key(secret, len, EC_KEY_get0_public_key(ec), tmpkey, NULL);

      i2o_ECPublicKey(tmpkey, &ptr);
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
  if(x509) {
    X509_free(x509);
  }
  if(input_file != stdin) {
    fclose(input_file);
  }
  return ret;
}

static bool list_readers(ykpiv_state *state) {
  char readers[2048];
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
  unsigned char data[2048];
  unsigned long len = sizeof(data);
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
    int len2 = len;
    x509 = X509_new();
    if(!x509) {
      fprintf(stderr, "Failed allocating x509 structure.\n");
      goto attest_out;
    }
    x509 = d2i_X509(NULL, &ptr, len2);
    if(!x509) {
      fprintf(stderr, "Failed parsing x509 information.\n");
      goto attest_out;
    }
    PEM_write_X509(output_file, x509);
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
  unsigned char data[3072];
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
    fprintf(stderr, "Writing %lu bytes of data to object %x.\n", len, id);
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
  unsigned char data[3072];
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
  ykpiv_state *state;
  int verbosity;
  enum enum_action action;
  unsigned int i;
  int ret = EXIT_SUCCESS;
  bool authed = false;
  char pwbuf[128];
  char *password;

  if(cmdline_parser(argc, argv, &args_info) != 0) {
    return EXIT_FAILURE;
  }

  verbosity = args_info.verbose_arg + (int)args_info.verbose_given;
  password = args_info.password_arg;

  for(i = 0; i < args_info.action_given; i++) {
    action = *(args_info.action_arg + i);
    switch(action) {
      case action_arg_requestMINUS_certificate:
      case action_arg_selfsignMINUS_certificate:
        if(!args_info.subject_arg) {
          fprintf(stderr, "The '%s' action needs a subject (-S) to operate on.\n",
              cmdline_parser_action_values[action]);
          return EXIT_FAILURE;
        }
      case action_arg_generate:
      case action_arg_importMINUS_key:
      case action_arg_importMINUS_certificate:
      case action_arg_deleteMINUS_certificate:
      case action_arg_readMINUS_certificate:
      case action_arg_testMINUS_signature:
      case action_arg_testMINUS_decipher:
      case action_arg_attest:
        if(args_info.slot_arg == slot__NULL) {
          fprintf(stderr, "The '%s' action needs a slot (-s) to operate on.\n",
              cmdline_parser_action_values[action]);
          return EXIT_FAILURE;
        }
        break;
      case action_arg_pinMINUS_retries:
        if(!args_info.pin_retries_given || !args_info.puk_retries_given) {
          fprintf(stderr, "The '%s' action needs both --pin-retries and --puk-retries arguments.\n",
              cmdline_parser_action_values[action]);
          return EXIT_FAILURE;
        }
        break;
      case action_arg_writeMINUS_object:
      case action_arg_readMINUS_object:
        if(!args_info.id_given) {
          fprintf(stderr, "The '%s' action needs the --id argument.\n",
              cmdline_parser_action_values[action]);
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

  if(ykpiv_init(&state, verbosity) != YKPIV_OK) {
    fprintf(stderr, "Failed initializing library.\n");
    return EXIT_FAILURE;
  }

  if(ykpiv_connect(state, args_info.reader_arg) != YKPIV_OK) {
    fprintf(stderr, "Failed to connect to reader.\n");
    return EXIT_FAILURE;
  }

  for(i = 0; i < args_info.action_given; i++) {
    action = *(args_info.action_arg + i);
    switch(action) {
      case action_arg_importMINUS_key:
      case action_arg_importMINUS_certificate:
        if(args_info.key_format_arg == key_format_arg_PKCS12 && !password) {
          if(verbosity) {
            fprintf(stderr, "Asking for password since '%s' needs it.\n", cmdline_parser_action_values[action]);
          }
          if(!read_pw("Password", pwbuf, sizeof(pwbuf), false, args_info.stdin_input_flag)) {
            fprintf(stderr, "Failed to get password.\n");
            return false;
          }
          password = pwbuf;
        }
      case action_arg_generate:
      case action_arg_setMINUS_mgmMINUS_key:
      case action_arg_pinMINUS_retries:
      case action_arg_setMINUS_chuid:
      case action_arg_setMINUS_ccc:
      case action_arg_deleteMINUS_certificate:
      case action_arg_writeMINUS_object:
        if(!authed) {
          unsigned char key[KEY_LEN];
          size_t key_len = sizeof(key);
          char keybuf[KEY_LEN*2+2]; /* one extra byte for potential \n */
          char *key_ptr = args_info.key_arg;
          if(verbosity) {
            fprintf(stderr, "Authenticating since action '%s' needs that.\n", cmdline_parser_action_values[action]);
          }
          if(args_info.key_given && args_info.key_orig == NULL) {
            if(!read_pw("management key", keybuf, sizeof(keybuf), false, args_info.stdin_input_flag)) {
              fprintf(stderr, "Failed to read management key from stdin,\n");
              return EXIT_FAILURE;
            }
            key_ptr = keybuf;
          }
          if(ykpiv_hex_decode(key_ptr, strlen(key_ptr), key, &key_len) != YKPIV_OK) {
            fprintf(stderr, "Failed decoding key!\n");
            return EXIT_FAILURE;
          }

          if(ykpiv_authenticate(state, key) != YKPIV_OK) {
            fprintf(stderr, "Failed authentication with the application.\n");
            return EXIT_FAILURE;
          }
          if(verbosity) {
            fprintf(stderr, "Successful application authentication.\n");
          }
          authed = true;
        } else {
          if(verbosity) {
            fprintf(stderr, "Skipping authentication for '%s' since it's already done.\n", cmdline_parser_action_values[action]);
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
  }


  /* openssl setup.. */
  OpenSSL_add_all_algorithms();


  for(i = 0; i < args_info.action_given; i++) {
    char new_keybuf[KEY_LEN*2+2] = {0}; /* one extra byte for potential \n */
    char *new_mgm_key = args_info.new_key_arg;
    action = *(args_info.action_arg + i);
    if(verbosity) {
      fprintf(stderr, "Now processing for action '%s'.\n",
          cmdline_parser_action_values[action]);
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
        if(!new_mgm_key) {
          if(!read_pw("new management key", new_keybuf, sizeof(new_keybuf), true, args_info.stdin_input_flag)) {
            fprintf(stderr, "Failed to read management key from stdin,\n");
            ret = EXIT_FAILURE;
            break;
          }
          new_mgm_key = new_keybuf;
        }
        if(strlen(new_mgm_key) == (KEY_LEN * 2)){
          unsigned char new_key[KEY_LEN];
          size_t new_key_len = sizeof(new_key);
          if(ykpiv_hex_decode(new_mgm_key, strlen(new_mgm_key), new_key, &new_key_len) != YKPIV_OK) {
            fprintf(stderr, "Failed decoding new key!\n");
            ret = EXIT_FAILURE;
          } else if(ykpiv_set_mgmkey2(state, new_key, args_info.touch_policy_arg == touch_policy_arg_always ? 1 : 0) != YKPIV_OK) {
            fprintf(stderr, "Failed setting the new key!");
            if(args_info.touch_policy_arg != touch_policy__NULL) {
              fprintf(stderr, " Maybe touch policy is not supported on this key?");
            }
            fprintf(stderr, "\n");
            ret = EXIT_FAILURE;
          } else {
            fprintf(stderr, "Successfully set new management key.\n");
          }
        } else {
          fprintf(stderr, "The new management key has to be exactly %d character.\n", KEY_LEN * 2);
          ret = EXIT_FAILURE;
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
        if(import_cert(state, args_info.key_format_arg, args_info.input_arg, args_info.slot_arg, password) == false) {
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
              args_info.output_arg) == false) {
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
            return false;
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
            return false;
          }
          pin = pinbuf;
        }
        if(!new_pin) {
          if (!read_pw(new_name, new_pinbuf, sizeof(new_pinbuf), true, args_info.stdin_input_flag)) {
            return false;
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
              args_info.output_arg) == false) {
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
      fprintf(stderr, "Failed signing!\n");
      ret = EXIT_FAILURE;
    }
  }

  ykpiv_done(state);
  EVP_cleanup();
  return ret;
}
