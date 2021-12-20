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

  if (EVP_PKEY_base_id(key) != EVP_PKEY_RSA) {
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

  const unsigned char *p = data; // Mandatory temp variable required by OpenSSL
  unsigned long       offs, cert_len;

  if (*p == TAG_CERT) {
    // The certificate is in "PIV" format 0x70 len 0x30 len ...
    p++;
    offs = get_length(p, data + len, &cert_len);
    if(!offs)
      return CKR_ARGUMENTS_BAD;
    p += offs;
  }
  else {
    // Raw certificate ...
    cert_len = len;
  }

  if(*cert)
    X509_free(*cert);

  *cert = d2i_X509(NULL, &p, cert_len);
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
  EC_GROUP_set_asn1_flag(group, curve_name);
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

CK_RV do_create_ec_key(CK_BYTE_PTR point, CK_ULONG point_len, int curve_name, ykcs11_pkey_t **pkey) {
  CK_RV rv;
  EC_POINT *ecpoint = NULL;
  EC_KEY *eckey = NULL;
  EC_GROUP *group = EC_GROUP_new_by_curve_name(curve_name);
  if(group == NULL)
    return CKR_HOST_MEMORY;
  EC_GROUP_set_asn1_flag(group, curve_name);
  eckey = EC_KEY_new();
  if(eckey == NULL) {
    rv = CKR_HOST_MEMORY;
    goto create_ec_cleanup;
  }
  if(EC_KEY_set_group(eckey, group) <= 0) {
    rv = CKR_GENERAL_ERROR;
    goto create_ec_cleanup;
  }
  ecpoint = EC_POINT_new(group);
  if(ecpoint == NULL) {
    rv = CKR_HOST_MEMORY;
    goto create_ec_cleanup;
  }
  if(EC_POINT_oct2point(group, ecpoint, point, point_len, NULL) <= 0) {
    rv = CKR_ARGUMENTS_BAD;
    goto create_ec_cleanup;
  }
  if(EC_KEY_set_public_key(eckey, ecpoint) <= 0) {
    rv = CKR_GENERAL_ERROR;
    goto create_ec_cleanup;
  }
  EVP_PKEY_free(*pkey);
  *pkey = EVP_PKEY_new();
  if(*pkey == NULL) {
    rv = CKR_HOST_MEMORY;
    goto create_ec_cleanup;
  }
  if(EVP_PKEY_assign_EC_KEY(*pkey, eckey) <= 0) {
    rv = CKR_GENERAL_ERROR;
    goto create_ec_cleanup;
  }
  rv = CKR_OK;
create_ec_cleanup:
  EC_GROUP_clear_free(group);
  if(ecpoint != NULL) {
    EC_POINT_clear_free(ecpoint);
  }
  if(rv != CKR_OK && eckey != NULL) {
    EC_KEY_free(eckey);
  }
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
  int curve_name = get_curve_name(algorithm);
  CK_BYTE_PTR eob = in + in_len;
  unsigned long offs, len;

  if (curve_name == 0) {
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
  }
  else {
    if(in >= eob)
      return CKR_GENERAL_ERROR;

    if(*in++ != 0x86)
      return CKR_GENERAL_ERROR;

    offs = get_length(in, eob, &len);
    if(!offs)
      return CKR_GENERAL_ERROR;

    in += offs;
    return do_create_ec_key(in, len, curve_name, pkey);
  }
}

CK_RV do_sign_empty_cert(const char *cn, ykcs11_pkey_t *pubkey, ykcs11_pkey_t *pvtkey, ykcs11_x509_t **cert) {
  *cert = X509_new();
  if (*cert == NULL)
    return CKR_HOST_MEMORY;
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

  if (len > *out_len) {
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

  if(!key) // EVP_PKEY_base_id doesn't handle NULL
    return CKK_VENDOR_DEFINED; // Actually an error

  switch (EVP_PKEY_base_id(key)) {
  case EVP_PKEY_RSA:
    return CKK_RSA;

  case EVP_PKEY_EC:
    return CKK_ECDSA;

  default:
    return CKK_VENDOR_DEFINED; // Actually an error
  }
}

CK_ULONG do_get_key_size(ykcs11_pkey_t *key) {
  return EVP_PKEY_bits(key);
}

CK_ULONG do_get_signature_size(ykcs11_pkey_t *key) {

  switch (EVP_PKEY_base_id(key)) {
  case EVP_PKEY_RSA:
    return EVP_PKEY_size(key);
  case EVP_PKEY_EC:
    switch(EVP_PKEY_bits(key)) {
    case 256:
      return 64;
    case 384:
      return 96;
    }
  }
  return 0; // Actually an error
}

CK_BYTE do_get_key_algorithm(ykcs11_pkey_t *key) {

  switch (EVP_PKEY_base_id(key)) {
  case EVP_PKEY_RSA:
    switch(EVP_PKEY_bits(key)) {
    case 1024:
      return YKPIV_ALGO_RSA1024;
    case 2048:
      return YKPIV_ALGO_RSA2048;
    }
  case EVP_PKEY_EC:
    switch(EVP_PKEY_bits(key)) {
    case 256:
      return YKPIV_ALGO_ECCP256;
    case 384:
      return YKPIV_ALGO_ECCP384;
    }
  }
  return 0; // Actually an error
}

CK_RV do_get_modulus(ykcs11_pkey_t *key, CK_BYTE_PTR data, CK_ULONG_PTR len) {
  const RSA *rsa = NULL;
  const BIGNUM *n = NULL;

  rsa = EVP_PKEY_get0_RSA(key);
  if (rsa == NULL)
    return CKR_FUNCTION_FAILED;

  RSA_get0_key(rsa, &n, NULL, NULL);
  if ((CK_ULONG)BN_num_bytes(n) > *len) {
    return CKR_BUFFER_TOO_SMALL;
  }

  *len = (CK_ULONG)BN_bn2bin(n, data);

  return CKR_OK;
}

CK_RV do_get_public_exponent(ykcs11_pkey_t *key, CK_BYTE_PTR data, CK_ULONG_PTR len) {

  const RSA *rsa = NULL;
  const BIGNUM *bn_e;

  rsa = EVP_PKEY_get0_RSA(key);
  if (rsa == NULL)
    return CKR_FUNCTION_FAILED;

  RSA_get0_key(rsa, NULL, &bn_e, NULL);
  if ((CK_ULONG)BN_num_bytes(bn_e) > *len) {
    return CKR_BUFFER_TOO_SMALL;
  }

  *len = (CK_ULONG)BN_bn2bin(bn_e, data);
  return CKR_OK;
}

/* #include <stdio.h> */
/* #include <openssl/err.h> */
/*   ERR_load_crypto_strings(); */
/* //SSL_load_error_strings(); */
/*   fprintf(stderr, "ERROR %s\n", ERR_error_string(ERR_get_error(), NULL)); */
CK_RV do_get_public_key(ykcs11_pkey_t *key, CK_BYTE_PTR data, CK_ULONG_PTR len) {
  const RSA *rsa = NULL;
  unsigned char *p;

  const EC_KEY *eck = NULL;
  const EC_GROUP *ecg; // Alternative solution is to get i2d_PUBKEY and manually offset
  const EC_POINT *ecp;
  point_conversion_form_t pcf = POINT_CONVERSION_UNCOMPRESSED;

  switch(EVP_PKEY_base_id(key)) {
  case EVP_PKEY_RSA:

    rsa = EVP_PKEY_get0_RSA(key);

    if ((CK_ULONG)RSA_size(rsa) > *len) {
      return CKR_BUFFER_TOO_SMALL;
    }

    p = data;

    if ((*len = (CK_ULONG) i2d_RSAPublicKey(rsa, &p)) == 0) {
      return CKR_FUNCTION_FAILED;
    }

    // TODO: this is the correct thing to do so that we strip out the exponent
    // OTOH we also need a function to get the exponent out with CKA_PUBLIC_EXPONENT
    /*BN_bn2bin(rsa->n, data);
     *len = 256;*/

    /* fprintf(stderr, "Public key is: \n"); */
    /* dump_hex(data, *len, stderr, CK_TRUE); */

    break;

  case EVP_PKEY_EC:
    eck = EVP_PKEY_get0_EC_KEY(key);
    ecg = EC_KEY_get0_group(eck);
    ecp = EC_KEY_get0_public_key(eck);

    // Add the DER structure with length after extracting the point
    data[0] = 0x04;

    if ((*len = EC_POINT_point2oct(ecg, ecp, pcf, data + 2, *len - 2, NULL)) == 0) {
      return CKR_FUNCTION_FAILED;
    }

    data[1] = *len;
    *len += 2;

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

  if (len > buf_size) {
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

static int BN_bn2bin_fixed(const BIGNUM *bn, CK_BYTE_PTR out, CK_ULONG len) {

  CK_BYTE buf[1024] = {0};
  int actual = BN_bn2bin(bn, buf);
  if(actual <= 0)
    return actual;
  if(actual < len) {
    memset(out,  0, len - actual);
    memcpy(out + len - actual, buf, actual);
  } else {
    for(CK_ULONG i = 0; i < actual - len; i++) {
      if(buf[i])
        return -1; // Non-zero byte would have been lost
    }
    memcpy(out, buf + actual - len, len);
  }
  return len;
}

CK_RV do_strip_DER_encoding_from_ECSIG(CK_BYTE_PTR data, CK_ULONG len, CK_ULONG sig_len) {
  CK_RV rv;
  const CK_BYTE *p = data;

  ECDSA_SIG *sig = d2i_ECDSA_SIG(NULL, &p, len);
  if(sig == NULL)
    return CKR_DATA_INVALID;

  const BIGNUM *x, *y;
  ECDSA_SIG_get0(sig, &x, &y);

  if(BN_bn2bin_fixed(x, data, sig_len / 2) <= 0) {
    rv = CKR_DATA_INVALID;
    goto strip_der_cleanup;
  }

  if(BN_bn2bin_fixed(y, data + sig_len / 2, sig_len / 2) <= 0) {
    rv = CKR_DATA_INVALID;
    goto strip_der_cleanup;
  }

  rv = CKR_OK;
strip_der_cleanup:
  ECDSA_SIG_free(sig);
  return rv;
}
