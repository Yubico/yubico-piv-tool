/*
 * Copyright (c) 2015-2020 Yubico AB
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

#include "openssl_utils.h"
#include <stdbool.h>
#include "ykpiv.h"
#include "../common/util.h"
#include "../common/openssl-compat.h"
#include "debug.h"
#include <string.h>

CK_RV do_rand_seed(CK_BYTE_PTR data, CK_ULONG len) {
  RAND_seed(data, len);
  return CKR_OK;
}

CK_RV do_rand_bytes(CK_BYTE_PTR data, CK_ULONG len) {
  return RAND_bytes(data, len) <= 0 ? CKR_FUNCTION_FAILED : CKR_OK;
}

CK_RV do_rsa_encrypt(ykcs11_pkey_t *key, int padding, const ykcs11_md_t* oaep_md, const ykcs11_md_t* oaep_mgf1, 
                     unsigned char *oaep_label, CK_ULONG oaep_label_len,
                     CK_BYTE_PTR data, CK_ULONG data_len, CK_BYTE_PTR enc, CK_ULONG_PTR enc_len) {

  if (!key || EVP_PKEY_base_id(key) != EVP_PKEY_RSA) { // EVP_PKEY_base_id doesn't handle NULL
    return CKR_KEY_TYPE_INCONSISTENT;
  }

  CK_RV rv;
  ykcs11_pkey_ctx_t *ctx = EVP_PKEY_CTX_new(key, NULL);
  if(ctx == NULL) {
    return CKR_FUNCTION_FAILED;
  }

  if(EVP_PKEY_encrypt_init(ctx) <= 0) {
    rv = CKR_FUNCTION_FAILED;
    goto rsa_enc_cleanup;
  }

  if(padding != RSA_NO_PADDING) {
    if(EVP_PKEY_CTX_set_rsa_padding(ctx, padding) <= 0) {
      rv = CKR_FUNCTION_FAILED;
      goto rsa_enc_cleanup;
    }
  }

  if(oaep_md != NULL && oaep_mgf1 != NULL && oaep_label != NULL) {
    if(EVP_PKEY_CTX_set_rsa_oaep_md(ctx, oaep_md) >= 0) {
      rv = CKR_FUNCTION_FAILED;
      goto rsa_enc_cleanup;
    }
    
    if(EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, oaep_mgf1) >= 0) {
      rv = CKR_FUNCTION_FAILED;
      goto rsa_enc_cleanup;
    }

    if(EVP_PKEY_CTX_set0_rsa_oaep_label(ctx, oaep_label, oaep_label_len) >= 0) {
      rv = CKR_FUNCTION_FAILED;
      goto rsa_enc_cleanup;
    }
  }
 
  size_t cbLen = *enc_len;
  if(EVP_PKEY_encrypt(ctx, enc, &cbLen, data, data_len) <= 0) {
    rv = CKR_FUNCTION_FAILED;
    goto rsa_enc_cleanup;
  }

  *enc_len = cbLen;
  rv = CKR_OK;

rsa_enc_cleanup:
  if(rv != CKR_OK) {
    free(oaep_label);
  }
  EVP_PKEY_CTX_free(ctx);
  return rv;
}

CK_RV do_store_cert(CK_BYTE_PTR data, CK_ULONG len, ykcs11_x509_t **cert) {

  unsigned char certdata[YKPIV_OBJ_MAX_SIZE * 10] = {0};
  size_t certdata_len = sizeof (certdata);

  if(ykpiv_util_get_certdata(data, len, certdata, &certdata_len) != YKPIV_OK) {
    DBG("Failed to get certificate data");
    return CKR_DATA_INVALID;
  }

  if(*cert) {
    X509_free(*cert);
  }

  const unsigned char *p = certdata; // Mandatory temp variable required by OpenSSL
  *cert = d2i_X509(NULL, &p, certdata_len);
  if (*cert == NULL)
    return CKR_FUNCTION_FAILED;

  return CKR_OK;

}

CK_RV do_generate_ec_key(int curve_name, ykcs11_pkey_t **pkey) {
  CK_RV rv;
  EC_KEY *eckey = NULL;
  EC_GROUP *group = EC_GROUP_new_by_curve_name(curve_name);
  if(group == NULL) {
    return CKR_HOST_MEMORY;
  }
  EC_GROUP_set_asn1_flag(group, OPENSSL_EC_NAMED_CURVE);
  eckey = EC_KEY_new();
  if(eckey == NULL) {
    rv = CKR_HOST_MEMORY;
    goto gen_ec_key_cleanup;
  }
  if(EC_KEY_set_group(eckey, group) <= 0) {
    rv = CKR_GENERAL_ERROR;
    goto gen_ec_key_cleanup;
  }
  if(EC_KEY_generate_key(eckey) <= 0) {
    rv = CKR_GENERAL_ERROR;
    goto gen_ec_key_cleanup;
  }
  *pkey = EVP_PKEY_new();
  if(*pkey == NULL) {
    rv = CKR_HOST_MEMORY;
    goto gen_ec_key_cleanup;
  }
  if(EVP_PKEY_assign_EC_KEY(*pkey, eckey) <= 0) {
    rv = CKR_GENERAL_ERROR;
    goto gen_ec_key_cleanup;
  }
  rv = CKR_OK;
gen_ec_key_cleanup:
  EC_GROUP_clear_free(group);
  return rv;
}

CK_RV do_create_rsa_key(CK_BYTE_PTR mod, CK_ULONG mod_len, CK_BYTE_PTR exp, CK_ULONG exp_len, ykcs11_pkey_t **pkey) {
  CK_RV rv;
  RSA *rsa = NULL;
  BIGNUM *n = BN_bin2bn(mod, mod_len, 0);
  if(n == NULL)
    return CKR_HOST_MEMORY;
  BIGNUM *e = BN_bin2bn(exp, exp_len, 0);
  if(e == NULL) {
    rv = CKR_HOST_MEMORY;
    goto create_rsa_cleanup;
  }
  rsa = RSA_new();
  if(rsa == NULL) {
    rv = CKR_HOST_MEMORY;
    goto create_rsa_cleanup;
  }
  if(RSA_set0_key(rsa, n, e, NULL) <= 0) {
    rv = CKR_GENERAL_ERROR;
    goto create_rsa_cleanup;
  }
  EVP_PKEY_free(*pkey);
  *pkey = EVP_PKEY_new();
  if(*pkey == NULL) {
    rv = CKR_HOST_MEMORY;
    goto create_rsa_cleanup;
  }
  if(EVP_PKEY_assign_RSA(*pkey, rsa) <= 0) {
    rv = CKR_GENERAL_ERROR;
    goto create_rsa_cleanup;
  }
  return CKR_OK;
create_rsa_cleanup:
  BN_free(n);
  if(e != NULL) {
    BN_free(e);
  }
  if(rsa != NULL) {
    RSA_free(rsa);
  }
  return rv;
}

CK_RV do_create_public_key(CK_BYTE_PTR in, CK_ULONG in_len, CK_ULONG algorithm, ykcs11_pkey_t **pkey) {
  CK_BYTE_PTR eob = in + in_len;
  unsigned long offs, len;
  if (YKPIV_IS_RSA(algorithm)) {
    if(in >= eob)
      return CKR_GENERAL_ERROR;

    if (*in++ != 0x81)
      return CKR_GENERAL_ERROR;

    offs = get_length(in, eob, &len);
    if(!offs)
      return CKR_GENERAL_ERROR;

    in += offs;

    CK_BYTE_PTR mod = in;
    CK_ULONG mod_len = len;

    in += len;

    if(in >= eob)
      return CKR_GENERAL_ERROR;

    if (*in++ != 0x82)
      return CKR_GENERAL_ERROR;

    offs = get_length(in, eob, &len);
    if(!offs)
      return CKR_GENERAL_ERROR;

    in += offs;    
    return do_create_rsa_key(mod, mod_len, in, len, pkey);
  } else {
    if(in >= eob)
      return CKR_GENERAL_ERROR;

    if(*in++ != 0x86)
      return CKR_GENERAL_ERROR;

    offs = get_length(in, eob, &len);
    if(!offs)
      return CKR_GENERAL_ERROR;

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
        return CKR_HOST_MEMORY;
      }
      return CKR_OK;
#endif
    }
  }
  DBG("Unsupported key algorithm");
  return CKR_DATA_INVALID;
}

CK_RV do_sign_empty_cert(const char *cn, ykcs11_pkey_t *pubkey, ykcs11_pkey_t *pvtkey, ykcs11_x509_t **cert) {
  *cert = X509_new();
  if (*cert == NULL) {
    return CKR_HOST_MEMORY;
  }
  X509_set_version(*cert, 2); // Version 3
  X509_NAME_add_entry_by_txt(X509_get_issuer_name(*cert), "CN", MBSTRING_ASC, (const unsigned char*)cn, -1, -1, 0);
  X509_NAME_add_entry_by_txt(X509_get_subject_name(*cert), "CN", MBSTRING_ASC, (const unsigned char*)cn, -1, -1, 0);
  ASN1_INTEGER_set(X509_get_serialNumber(*cert), 0);
  X509_gmtime_adj(X509_get_notBefore(*cert), 0);
  X509_gmtime_adj(X509_get_notAfter(*cert), 0);
  X509_set_pubkey(*cert, pubkey);
  if (X509_sign(*cert, pvtkey, EVP_sha1()) <= 0) {
    return CKR_GENERAL_ERROR;
  }
  return CKR_OK;
}

CK_RV do_create_empty_cert(CK_BYTE_PTR in, CK_ULONG in_len, CK_ULONG algorithm,
                          const char *cn, CK_BYTE_PTR out, CK_ULONG_PTR out_len) {

  EVP_PKEY  *pubkey = NULL;
  EVP_PKEY  *pvtkey = NULL;
  X509      *cert = NULL;
  CK_RV     rv;

  if((rv = do_create_public_key(in, in_len, algorithm, &pubkey)) != CKR_OK) {
    goto create_empty_cert_cleanup;
  }

  if((rv = do_generate_ec_key(NID_X9_62_prime256v1, &pvtkey)) != CKR_OK) {
    goto create_empty_cert_cleanup;
  }
  
  if((rv = do_sign_empty_cert(cn, pubkey, pvtkey, &cert)) != CKR_OK) {
    goto create_empty_cert_cleanup;
  }

  int len = i2d_X509(cert, NULL);
  if (len <= 0) {
    rv = CKR_GENERAL_ERROR;
    goto create_empty_cert_cleanup;
  }

  if ((CK_ULONG)len > *out_len) {
    rv = CKR_BUFFER_TOO_SMALL;
    goto create_empty_cert_cleanup;
  }

  len = i2d_X509(cert, &out);
  if (len <= 0) {
    rv = CKR_GENERAL_ERROR;
    goto create_empty_cert_cleanup;
  }

  *out_len = len;
  rv = CKR_OK;

create_empty_cert_cleanup:
  if (pubkey != NULL) {
    EVP_PKEY_free(pubkey);
  }
  if (pvtkey != NULL) {
    EVP_PKEY_free(pvtkey);
  }
  if (cert != NULL) {
    X509_free(cert);
  }
  return rv;
}

CK_RV do_check_cert(CK_BYTE_PTR in, CK_ULONG in_len, CK_ULONG_PTR cert_len) {

  const unsigned char *p = in; // Mandatory temp variable required by OpenSSL
  X509 *cert = d2i_X509(NULL, &p, in_len);
  if (cert == NULL)
    return CKR_FUNCTION_FAILED;
  X509_free(cert);
  *cert_len = p - in;
  return CKR_OK;
}

CK_RV do_get_raw_cert(ykcs11_x509_t *cert, CK_BYTE_PTR out, CK_ULONG_PTR out_len) {

  CK_BYTE_PTR p;
  int         len;

  len = i2d_X509(cert, NULL);

  if (len < 0)
    return CKR_FUNCTION_FAILED;

  if ((CK_ULONG)len > *out_len)
    return CKR_BUFFER_TOO_SMALL;

  p = out;
  if ((*out_len = (CK_ULONG) i2d_X509(cert, &p)) == 0)
    return CKR_FUNCTION_FAILED;

  return CKR_OK;
}

CK_RV do_get_raw_name(ykcs11_x509_name_t *name, CK_BYTE_PTR out, CK_ULONG_PTR out_len) {

  CK_BYTE_PTR p;
  int         len;

  len = i2d_X509_NAME(name, NULL);

  if (len < 0)
    return CKR_FUNCTION_FAILED;

  if ((CK_ULONG)len > *out_len)
    return CKR_BUFFER_TOO_SMALL;

  p = out;
  if ((*out_len = (CK_ULONG) i2d_X509_NAME(name, &p)) == 0)
    return CKR_FUNCTION_FAILED;

  return CKR_OK;
}

CK_RV do_get_raw_integer(ykcs11_asn1_integer_t *serial, CK_BYTE_PTR out, CK_ULONG_PTR out_len) {

  CK_BYTE_PTR p;
  int         len;

  len = i2d_ASN1_INTEGER(serial, NULL);

  if (len < 0)
    return CKR_FUNCTION_FAILED;

  if ((CK_ULONG)len > *out_len)
    return CKR_BUFFER_TOO_SMALL;

  p = out;
  if ((*out_len = (CK_ULONG) i2d_ASN1_INTEGER(serial, &p)) == 0)
    return CKR_FUNCTION_FAILED;

  return CKR_OK;
}

CK_RV do_delete_cert(ykcs11_x509_t **cert) {

  X509_free(*cert);
  *cert = NULL;

  return CKR_OK;

}

CK_RV do_store_pubk(ykcs11_x509_t *cert, ykcs11_pkey_t **key) {

  if(*key) {
    EVP_PKEY_free(*key);
  }

  *key = X509_get_pubkey(cert);

  if (*key == NULL) {
    return CKR_FUNCTION_FAILED;
  }

  return CKR_OK;

}

static int OBJ_get_nid(const char *oid, const char *name, const char *descr) {
  int nid = OBJ_txt2nid(oid);
  if (nid <= 0) {
    nid = OBJ_create(oid, name, descr);
  }
  return nid;
}

CK_RV do_parse_attestation(ykcs11_x509_t *cert, CK_BYTE_PTR pin_policy, CK_BYTE_PTR touch_policy) {

  int nid = OBJ_get_nid(YKPIV_OID_USAGE_POLICY, "KeyUsagePolicy", "Yubico PIV key usage policy");
  if(nid < 0)
    return CKR_FUNCTION_FAILED;

  int pos = X509_get_ext_by_NID(cert, nid, -1);
  if (pos < 0)
    return CKR_FUNCTION_FAILED;

  X509_EXTENSION *ext = X509_get_ext(cert, pos);
  if (ext == NULL)
    return CKR_FUNCTION_FAILED;

  ASN1_OCTET_STRING *oct = X509_EXTENSION_get_data(ext);
  if (oct == NULL)
    return CKR_FUNCTION_FAILED;

  const unsigned char *p = ASN1_STRING_get0_data(oct);
  *pin_policy = p[0];
  *touch_policy = p[1];

  return CKR_OK;
}

CK_KEY_TYPE do_get_key_type(ykcs11_pkey_t *key) {

  if(key) { // EVP_PKEY_base_id doesn't handle NULL
    switch (EVP_PKEY_base_id(key)) {
    case EVP_PKEY_RSA:
      return CKK_RSA;
    case EVP_PKEY_EC:
      return CKK_EC;
#if (OPENSSL_VERSION_NUMBER >= 0x10100000L)
    case EVP_PKEY_ED25519:
      return CKK_EC_EDWARDS;
    case EVP_PKEY_X25519:
      return CKK_EC_MONTGOMERY;
#endif
    }
  }
  return CKK_VENDOR_DEFINED; // Actually an error
}

CK_ULONG do_get_key_bits(ykcs11_pkey_t *key) {
  return EVP_PKEY_bits(key);
}

CK_ULONG do_get_key_size(ykcs11_pkey_t *key) {
  return EVP_PKEY_size(key);
}

CK_ULONG do_get_signature_size(ykcs11_pkey_t *key) {

  if(key) { // EVP_PKEY_base_id doesn't handle NULL
    switch (EVP_PKEY_base_id(key)) {
    case EVP_PKEY_RSA:
      return EVP_PKEY_size(key);
    case EVP_PKEY_EC:
#if (OPENSSL_VERSION_NUMBER >= 0x10100000L)
    case EVP_PKEY_ED25519:
#endif
      switch(EVP_PKEY_bits(key)) {
      case 256:
        return 64;
      case 384:
        return 96;
      }
    }
  }
  return 0;
}

CK_BYTE do_get_key_algorithm(ykcs11_pkey_t *key) {

  if(key) { // EVP_PKEY_base_id doesn't handle NULL
    switch (EVP_PKEY_base_id(key)) {
    case EVP_PKEY_RSA:
      switch(EVP_PKEY_bits(key)) {
      case 1024:
        return YKPIV_ALGO_RSA1024;
      case 2048:
        return YKPIV_ALGO_RSA2048;
      case 3072:
        return YKPIV_ALGO_RSA3072;
      case 4096:
        return YKPIV_ALGO_RSA4096;
      }
    case EVP_PKEY_EC:
      switch(EVP_PKEY_bits(key)) {
      case 256:
        return YKPIV_ALGO_ECCP256;
      case 384:
        return YKPIV_ALGO_ECCP384;
      }
#if (OPENSSL_VERSION_NUMBER >= 0x10100000L)
    case EVP_PKEY_ED25519:
      return YKPIV_ALGO_ED25519;
    case EVP_PKEY_X25519:
      return YKPIV_ALGO_X25519;
#endif
    }
  }
  return 0;
}

CK_RV do_get_modulus(ykcs11_pkey_t *key, CK_BYTE_PTR data, CK_ULONG len) {
  const RSA *rsa = NULL;
  const BIGNUM *n = NULL;

  rsa = key ? EVP_PKEY_get0_RSA(key) : 0;
  if (rsa == NULL)
    return CKR_ATTRIBUTE_TYPE_INVALID;

  RSA_get0_key(rsa, &n, NULL, NULL);

  if(BN_bn2binpad(n, data, len) < 0)
    return CKR_DATA_LEN_RANGE;

  return CKR_OK;
}

CK_BBOOL do_check_public_exponent(CK_BYTE_PTR data, CK_ULONG len) {
  BIGNUM *bn = BN_bin2bn(data, len, NULL);
  BIGNUM *f4 = BN_new();
  BN_set_word(f4, 0x10001);
  CK_BBOOL ret = BN_cmp(bn, f4) ? CK_FALSE : CK_TRUE;
  BN_free(f4);
  BN_free(bn);
  return ret;
}

CK_RV do_get_public_exponent(ykcs11_pkey_t *key, CK_BYTE_PTR data, CK_ULONG_PTR len) {

  const RSA *rsa = key ? EVP_PKEY_get0_RSA(key) : 0;
  if (rsa == NULL)
    return CKR_ATTRIBUTE_TYPE_INVALID;

  const BIGNUM *bn_e = NULL;
  RSA_get0_key(rsa, NULL, &bn_e, NULL);

  if (bn_e == NULL)
    return CKR_ATTRIBUTE_TYPE_INVALID;

  if(*len < BN_num_bytes(bn_e))
    return CKR_DATA_LEN_RANGE;

  *len = BN_bn2bin(bn_e, data);

  return CKR_OK;
}

CK_RV do_get_public_key(ykcs11_pkey_t *key, CK_BYTE_PTR data, CK_ULONG_PTR len) {

  switch(EVP_PKEY_base_id(key)) {
  case EVP_PKEY_RSA: {
      const RSA *rsa = EVP_PKEY_get0_RSA(key);

      if (RSA_size(rsa) > *len) {
        return CKR_BUFFER_TOO_SMALL;
      }

      CK_BYTE_PTR p = data;
      if ((*len = i2d_RSAPublicKey(rsa, &p)) == 0) {
        return CKR_FUNCTION_FAILED;
      }
    }
    break;

  case EVP_PKEY_EC: {
      const EC_KEY *eck = EVP_PKEY_get0_EC_KEY(key);
      const EC_GROUP *ecg = EC_KEY_get0_group(eck);
      const EC_POINT *ecp = EC_KEY_get0_public_key(eck);

      // Add the DER structure with length after extracting the point
      data[0] = 0x04;

      if ((*len = EC_POINT_point2oct(ecg, ecp, POINT_CONVERSION_UNCOMPRESSED, data + 2, *len - 2, NULL)) == 0) {
        return CKR_FUNCTION_FAILED;
      }

      data[1] = *len;
      *len += 2;
    }
    break;
  case EVP_PKEY_ED25519:
  case EVP_PKEY_X25519: {
      size_t n = *len;
      if(EVP_PKEY_get_raw_public_key(key, data, &n) != 1) {
        return CKR_FUNCTION_FAILED;
      }
      ASN1_OCTET_STRING *a = ASN1_OCTET_STRING_new();
      ASN1_OCTET_STRING_set(a, data, n);
      if(i2d_ASN1_OCTET_STRING(a, NULL) > *len) {
        ASN1_OCTET_STRING_free(a);
        return CKR_BUFFER_TOO_SMALL;
      }
      CK_BYTE_PTR p = data;
      *len = i2d_ASN1_OCTET_STRING(a, &p);
      ASN1_OCTET_STRING_free(a);
    }
    break;

  default:
    return CKR_FUNCTION_FAILED;
  }

  return CKR_OK;
}

CK_RV do_get_curve_parameters(ykcs11_pkey_t *key, CK_BYTE_PTR data, CK_ULONG_PTR len) {
  const EC_KEY *eck = NULL;
  const EC_GROUP *ecg;
  unsigned char *p;

  eck = EVP_PKEY_get0_EC_KEY(key);
  if(eck == NULL) {
    return CKR_FUNCTION_FAILED;
  }
  ecg = EC_KEY_get0_group(eck);

  p = data;

  if ((*len = (CK_ULONG) i2d_ECPKParameters(ecg, &p)) == 0) {
    return CKR_FUNCTION_FAILED;
  }

  return CKR_OK;
}

CK_RV do_delete_pubk(EVP_PKEY **key) {

  EVP_PKEY_free(*key);
  *key = NULL;

  return CKR_OK;

}

CK_RV do_apply_DER_encoding_to_ECSIG(CK_BYTE_PTR signature, CK_ULONG_PTR signature_len, CK_ULONG buf_size) {

  ECDSA_SIG *sig = ECDSA_SIG_new();
  CK_RV rv = CKR_FUNCTION_FAILED;

  if (sig == NULL) {
    return rv;
  }

  BIGNUM *r = BN_bin2bn(signature, *signature_len / 2, NULL);
  BIGNUM *s = BN_bin2bn(signature + *signature_len / 2, *signature_len / 2, NULL);
  if (r == NULL || s == NULL) {
    goto adete_out;
  }

  if (ECDSA_SIG_set0(sig, r, s) == 0) {
    goto adete_out;
  }

  r = s = NULL;

  int len = i2d_ECDSA_SIG(sig, NULL);
  if (len <= 0) {
    goto adete_out;
  }

  if ((CK_ULONG)len > buf_size) {
    rv = CKR_BUFFER_TOO_SMALL;
    goto adete_out;
  }

  len = i2d_ECDSA_SIG(sig, &signature);
  if (len <= 0) {
    goto adete_out;
  }

  *signature_len = len;
  rv = CKR_OK;

adete_out:
  ECDSA_SIG_free(sig);
  if (r != NULL) {
    BN_free(r);
  }
  if (s != NULL) {
    BN_free(s);
  }

  return rv;
}

CK_RV do_strip_DER_encoding_from_ECSIG(CK_BYTE_PTR data, CK_ULONG len, CK_ULONG sig_len) {
  CK_RV rv;
  const CK_BYTE *p = data;

  ECDSA_SIG *sig = d2i_ECDSA_SIG(NULL, &p, len);
  if(sig == NULL)
    return CKR_DATA_INVALID;

  const BIGNUM *x, *y;
  ECDSA_SIG_get0(sig, &x, &y);

  if(BN_bn2binpad(x, data, sig_len / 2) <= 0) {
    rv = CKR_DATA_INVALID;
    goto strip_der_cleanup;
  }

  if(BN_bn2binpad(y, data + sig_len / 2, sig_len / 2) <= 0) {
    rv = CKR_DATA_INVALID;
    goto strip_der_cleanup;
  }

  rv = CKR_OK;
strip_der_cleanup:
  ECDSA_SIG_free(sig);
  return rv;
}
