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

#include "openssl_utils.h"
#include <stdbool.h>
#include "../tool/util.h" // TODO: share this better?
#include "../tool/openssl-compat.h" // TODO: share this better?
#include "debug.h"
#include <string.h>

CK_RV do_store_cert(CK_BYTE_PTR data, CK_ULONG len, X509 **cert) {

  const unsigned char *p = data; // Mandatory temp variable required by OpenSSL
  int                 cert_len;

  if (*p == 0x70) {
    // The certificate is in "PIV" format 0x70 len 0x30 len ...
    p++;
    p += get_length(p, &cert_len);
  }
  else {
    // Raw certificate 0x30 len ...
    cert_len = 0;
    cert_len += get_length(p + 1, &cert_len) + 1;
  }

  if ((CK_ULONG)cert_len > len)
    return CKR_ARGUMENTS_BAD;

  *cert = d2i_X509(NULL, &p, cert_len);
  if (*cert == NULL)
    return CKR_FUNCTION_FAILED;

  return CKR_OK;

}

CK_RV do_create_empty_cert(CK_BYTE_PTR in, CK_ULONG in_len, CK_BBOOL is_rsa,
                           CK_BYTE_PTR out, CK_ULONG_PTR out_len) {

  X509      *cert = NULL;
  EVP_PKEY  *key = NULL;
  RSA       *rsa = NULL;
  BIGNUM    *bignum_n = NULL;
  BIGNUM    *bignum_e = NULL;
  EC_KEY    *eck = NULL;
  EC_GROUP  *ecg = NULL;
  EC_POINT  *ecp = NULL;
  ASN1_TIME *tm = NULL;

  unsigned char *data_ptr;
  unsigned char *p;
  int len;

  CK_RV rv = CKR_FUNCTION_FAILED;

  cert = X509_new();
  if (cert == NULL)
    goto create_empty_cert_cleanup;

  key = EVP_PKEY_new();
  if (key == NULL)
    goto create_empty_cert_cleanup;

  if (is_rsa) {
    // RSA
    rsa = RSA_new();
    if (rsa == NULL)
      goto create_empty_cert_cleanup;

    data_ptr = in + 5;
    if (*data_ptr != 0x81)
      goto create_empty_cert_cleanup;

    data_ptr++;
    data_ptr += get_length(data_ptr, &len);
    bignum_n = BN_bin2bn(data_ptr, len, NULL);
    if(bignum_n == NULL)
      goto create_empty_cert_cleanup;

    data_ptr += len;

    if(*data_ptr != 0x82)
      goto create_empty_cert_cleanup;

    data_ptr++;
    data_ptr += get_length(data_ptr, &len);
    bignum_e = BN_bin2bn(data_ptr, len, NULL);
    if(bignum_e == NULL)
      goto create_empty_cert_cleanup;

    RSA_set0_key(rsa, bignum_n, bignum_e, NULL);

    if (EVP_PKEY_set1_RSA(key, rsa) == 0)
      goto create_empty_cert_cleanup;
  }
  else {
    // ECCP256
    data_ptr = in + 3;

    eck = EC_KEY_new();
    if (eck == NULL)
      goto create_empty_cert_cleanup;

    ecg = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    if (ecg == NULL)
      goto create_empty_cert_cleanup;

    EC_GROUP_set_asn1_flag(ecg, NID_X9_62_prime256v1);
    EC_KEY_set_group(eck, ecg);
    ecp = EC_POINT_new(ecg);

    if(*data_ptr++ != 0x86)
      goto create_empty_cert_cleanup;

    // The curve point should always be 65 bytes
    if (*data_ptr++ != 65)
      goto create_empty_cert_cleanup;

    if (EC_POINT_oct2point(ecg, ecp, data_ptr, 65, NULL) == 0)
      goto create_empty_cert_cleanup;

    if (EC_KEY_set_public_key(eck, ecp) == 0)
      goto create_empty_cert_cleanup;

    if (EVP_PKEY_set1_EC_KEY(key, eck) == 0)
      goto create_empty_cert_cleanup;
  }

  if (X509_set_pubkey(cert, key) == 0) // TODO: there is also X509_PUBKEY_set(X509_PUBKEY **x, EVP_PKEY *pkey);
    goto create_empty_cert_cleanup;

  tm = ASN1_TIME_new();
  if (tm == NULL)
    goto create_empty_cert_cleanup;

  ASN1_TIME_set_string(tm, "000001010000Z");
  X509_set_notBefore(cert, tm);
  X509_set_notAfter(cert, tm);

#if OPENSSL_VERSION_NUMBER < 10100000L
  // Manually set the signature algorithms.
  // OpenSSL 1.0.1i complains about empty DER fields
  // 8 => md5WithRsaEncryption
  cert->sig_alg->algorithm = OBJ_nid2obj(8);
  cert->cert_info->signature->algorithm = OBJ_nid2obj(8);

  // Manually set a signature (same reason as before)
  ASN1_BIT_STRING_set_bit(cert->signature, 8, 1);
  ASN1_BIT_STRING_set(cert->signature, (unsigned char*)"\x00", 1);
  ASN1_BIT_STRING_set(cert->signature, (unsigned char*)"\x00", 1);
#endif

  len = i2d_X509(cert, NULL);
  if (len < 0)
    goto create_empty_cert_cleanup;

  if ((CK_ULONG)len > *out_len) {
    rv = CKR_BUFFER_TOO_SMALL;
    goto create_empty_cert_cleanup;
  }

  p = out;
  if ((*out_len = (CK_ULONG) i2d_X509(cert, &p)) == 0)
    goto create_empty_cert_cleanup;

  /********************/
  /*BIO *STDout = BIO_new_fp(stderr, BIO_NOCLOSE);

  X509_print_ex(STDout, cert, 0, 0);

  BIO_free(STDout);*/
  /********************/

  rv = CKR_OK;

create_empty_cert_cleanup:

  if (tm != NULL) {
    ASN1_STRING_free(tm);
    tm = NULL;
  }

  if (bignum_n != NULL) {
    BN_free(bignum_n);
    bignum_n = NULL;
  }

  if (bignum_e != NULL) {
    BN_free(bignum_e);
    bignum_e = NULL;
  }

/*  if (rsa != NULL) { // TODO: adding this generates an error. Automatically free'd by EVP_PKEY_free ?
    RSA_free(rsa);
    rsa = NULL;
    }*/

  if (ecp != NULL) {
    EC_POINT_free(ecp);
    ecp = NULL;
  }

  if (ecg != NULL) {
    EC_GROUP_free(ecg);
    ecg = NULL;
  }

  if (eck != NULL) {
    EC_KEY_free(eck);
    eck = NULL;
  }

  if (key != NULL) {
    EVP_PKEY_free(key);
    key = NULL;
  }

  if (cert != NULL) {
    X509_free(cert);
    cert = NULL;
  }

  return rv;
}

CK_RV do_check_cert(CK_BYTE_PTR in, CK_ULONG_PTR cert_len) {

  X509                *cert;
  const unsigned char *p = in; // Mandatory temp variable required by OpenSSL
  int                 len;

  len = 0;
  len += get_length(p + 1, &len) + 1;

  *cert_len = (CK_ULONG) len;

  cert = d2i_X509(NULL, &p, (long) *cert_len);
  if (cert == NULL)
    return CKR_FUNCTION_FAILED;

  return CKR_OK;
}

CK_RV do_get_raw_cert(X509 *cert, CK_BYTE_PTR out, CK_ULONG_PTR out_len) {

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

CK_RV do_delete_cert(X509 **cert) {

  X509_free(*cert);
  cert = NULL;

  return CKR_OK;

}

/*CK_RV free_cert(X509 *cert) {

  X509_free((X509 *) cert);

  return CKR_OK;
}*/


CK_RV do_store_pubk(X509 *cert, EVP_PKEY **key) {

  *key = X509_get_pubkey(cert);

  if (*key == NULL)
    return CKR_FUNCTION_FAILED;

  return CKR_OK;

}

CK_KEY_TYPE do_get_key_type(EVP_PKEY *key) {

  switch (EVP_PKEY_id(key)) {
  case EVP_PKEY_RSA:
  case EVP_PKEY_RSA2:
    return CKK_RSA;

  case EVP_PKEY_EC:
    return CKK_ECDSA;

  default:
    return CKK_VENDOR_DEFINED; // Actually an error
  }
}

CK_ULONG do_get_rsa_modulus_length(EVP_PKEY *key) {

  CK_ULONG key_len = 0;
  RSA *rsa;

  rsa = EVP_PKEY_get1_RSA(key);
  if (rsa == NULL)
    return 0;

  key_len = (CK_ULONG) (RSA_size(rsa) * 8); // There is also RSA_bits but only in >= 1.1.0

  RSA_free(rsa);
  rsa = NULL;

  return key_len;

}

CK_RV do_get_modulus(EVP_PKEY *key, CK_BYTE_PTR data, CK_ULONG_PTR len) {
  RSA *rsa;
  const BIGNUM *n;

  rsa = EVP_PKEY_get1_RSA(key);
  if (rsa == NULL)
    return CKR_FUNCTION_FAILED;

  RSA_get0_key(rsa, &n, NULL, NULL);
  if ((CK_ULONG)BN_num_bytes(n) > *len) {
    RSA_free(rsa);
    rsa = NULL;
    return CKR_BUFFER_TOO_SMALL;
  }

  *len = (CK_ULONG)BN_bn2bin(n, data);

  RSA_free(rsa);
  rsa = NULL;

  return CKR_OK;
}

CK_RV do_get_public_exponent(EVP_PKEY *key, CK_BYTE_PTR data, CK_ULONG_PTR len) {

  CK_ULONG e = 0;
  RSA *rsa;
  const BIGNUM *bn_e;

  rsa = EVP_PKEY_get1_RSA(key);
  if (rsa == NULL)
    return CKR_FUNCTION_FAILED;

  RSA_get0_key(rsa, NULL, &bn_e, NULL);
  if ((CK_ULONG)BN_num_bytes(bn_e) > *len) {
    RSA_free(rsa);
    rsa = NULL;
    return CKR_BUFFER_TOO_SMALL;
  }

  *len = (CK_ULONG)BN_bn2bin(bn_e, data);

  RSA_free(rsa);
  rsa = NULL;

  return e;
}

/* #include <stdio.h> */
/* #include <openssl/err.h> */
/*   ERR_load_crypto_strings(); */
/* //SSL_load_error_strings(); */
/*   fprintf(stderr, "ERROR %s\n", ERR_error_string(ERR_get_error(), NULL)); */
CK_RV do_get_public_key(EVP_PKEY *key, CK_BYTE_PTR data, CK_ULONG_PTR len) {

  RSA *rsa;
  unsigned char *p;

  EC_KEY *eck;
  const EC_GROUP *ecg; // Alternative solution is to get i2d_PUBKEY and manually offset
  const EC_POINT *ecp;
  point_conversion_form_t pcf = POINT_CONVERSION_UNCOMPRESSED;

  switch(EVP_PKEY_id(key)) {
  case EVP_PKEY_RSA:
  case EVP_PKEY_RSA2:

    rsa = EVP_PKEY_get1_RSA(key);

    if ((CK_ULONG)RSA_size(rsa) > *len) {
      RSA_free(rsa);
      rsa = NULL;
      return CKR_BUFFER_TOO_SMALL;
    }

    p = data;

    if ((*len = (CK_ULONG) i2d_RSAPublicKey(rsa, &p)) == 0) {
      RSA_free(rsa);
      rsa = NULL;
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
    eck = EVP_PKEY_get1_EC_KEY(key);
    ecg = EC_KEY_get0_group(eck);
    ecp = EC_KEY_get0_public_key(eck);

    // Add the DER structure with length after extracting the point
    data[0] = 0x04;

    if ((*len = EC_POINT_point2oct(ecg, ecp, pcf, data + 2, *len - 2, NULL)) == 0) {
      EC_KEY_free(eck);
      eck = NULL;
      return CKR_FUNCTION_FAILED;
    }

    data[1] = *len;

    *len += 2;

    EC_KEY_free(eck);
    eck = NULL;

    break;

  default:
    return CKR_FUNCTION_FAILED;
  }

  return CKR_OK;

}

CK_RV do_encode_rsa_public_key(ykcs11_rsa_key_t **key, CK_BYTE_PTR modulus,
          CK_ULONG mlen, CK_BYTE_PTR exponent, CK_ULONG elen) {
  ykcs11_rsa_key_t *k;
  BIGNUM *k_n = NULL, *k_e = NULL;
  if (modulus == NULL || exponent == NULL)
    return CKR_ARGUMENTS_BAD;

  if ((k = RSA_new()) == NULL)
    return CKR_HOST_MEMORY;

  if ((k_n = BN_bin2bn(modulus, mlen, NULL)) == NULL)
    return CKR_FUNCTION_FAILED;

  if ((k_e = BN_bin2bn(exponent, elen, NULL)) == NULL)
    return CKR_FUNCTION_FAILED;

  if (RSA_set0_key(k, k_n, k_e, NULL) == 0)
    return CKR_FUNCTION_FAILED;

  *key = k;
  return CKR_OK;
}

CK_RV do_free_rsa_public_key(ykcs11_rsa_key_t *key) {
  RSA_free(key);
  return CKR_OK;
}

CK_RV do_get_curve_parameters(EVP_PKEY *key, CK_BYTE_PTR data, CK_ULONG_PTR len) {

  EC_KEY *eck;
  const EC_GROUP *ecg;
  unsigned char *p;

  eck = EVP_PKEY_get1_EC_KEY(key);
  ecg = EC_KEY_get0_group(eck);

  p = data;

  if ((*len = (CK_ULONG) i2d_ECPKParameters(ecg, &p)) == 0) {
    EC_KEY_free(eck);
    eck = NULL;
    return CKR_FUNCTION_FAILED;
  }

  EC_KEY_free(eck);
  eck = NULL;

  return CKR_OK;
}

CK_RV do_delete_pubk(EVP_PKEY **key) {

  EVP_PKEY_free(*key);
  key = NULL;

  return CKR_OK;

}

/*CK_RV free_key(EVP_PKEY *key) {

  EVP_PKEY_free(key);

  return CKR_OK;

  }*/

CK_RV do_pkcs_1_t1(CK_BYTE_PTR in, CK_ULONG in_len, CK_BYTE_PTR out, CK_ULONG_PTR out_len, CK_ULONG key_len) {
  unsigned char buffer[512];

  key_len /= 8;
  DBG("Apply padding to %lu bytes and get %lu\n", in_len, key_len);

  // TODO: rand must be seeded first (should be automatic)
  if (*out_len < key_len)
    return CKR_BUFFER_TOO_SMALL;

  if (RSA_padding_add_PKCS1_type_1(buffer, key_len, in, in_len) == 0)
    return CKR_FUNCTION_FAILED;

  memcpy(out, buffer, key_len);
  *out_len = key_len;

  return CKR_OK;
}

CK_RV do_pkcs_1_digest_info(CK_BYTE_PTR in, CK_ULONG in_len, int nid, CK_BYTE_PTR out, CK_ULONG_PTR out_len) {

  unsigned int len;
  CK_RV rv;

  rv = prepare_rsa_signature(in, in_len, out, &len, nid);
  if (!rv)
    return CKR_FUNCTION_FAILED;

  *out_len = len;

  return CKR_OK;

}

CK_RV do_pkcs_pss(ykcs11_rsa_key_t *key, CK_BYTE_PTR in, CK_ULONG in_len,
          int nid, CK_BYTE_PTR out, CK_ULONG_PTR out_len) {
  unsigned char em[RSA_size(key)];

  OpenSSL_add_all_digests();

  DBG("Apply PSS padding to %lu bytes and get %d", in_len, RSA_size(key));

  // TODO: rand must be seeded first (should be automatic)
  if (out != in)
    memcpy(out, in, in_len);

  // In case of raw PSS (no hash) this function will fail because OpenSSL requires an MD
  if (RSA_padding_add_PKCS1_PSS(key, em, out, EVP_get_digestbynid(nid), -2) == 0) {
    EVP_cleanup();
    return CKR_FUNCTION_FAILED;
  }

  memcpy(out, em, sizeof(em));
  *out_len = (CK_ULONG) sizeof(em);

  EVP_cleanup();

  return CKR_OK;
}

CK_RV do_md_init(hash_t hash, ykcs11_md_ctx_t **ctx) {

  const EVP_MD *md;

  switch (hash) {
  case YKCS11_NO_HASH:
    return CKR_FUNCTION_FAILED;

  case YKCS11_SHA1:
    md = EVP_sha1();
    break;

    //case YKCS11_SHA224:

  case YKCS11_SHA256:
    md = EVP_sha256();
    break;

  case YKCS11_SHA384:
    md = EVP_sha384();
    break;

  case YKCS11_SHA512:
    md = EVP_sha512();
    break;

  //case YKCS11_RIPEMD128_RSA_PKCS_HASH:
  //case YKCS11_RIPEMD160_HASH:

  default:
    return CKR_FUNCTION_FAILED;
  }

  *ctx = EVP_MD_CTX_create();

  // The OpenSSL function above never fail
  if (EVP_DigestInit_ex(*ctx, md, NULL) == 0) {
    EVP_MD_CTX_destroy((EVP_MD_CTX *)*ctx);
    return CKR_FUNCTION_FAILED;
  }

  return CKR_OK;
}

CK_RV do_md_update(ykcs11_md_ctx_t *ctx, CK_BYTE_PTR in, CK_ULONG in_len) {

  if (EVP_DigestUpdate(ctx, in, in_len) != 1) {
    EVP_MD_CTX_destroy(ctx);
    return CKR_FUNCTION_FAILED;
  }

  return CKR_OK;

}

CK_RV do_md_finalize(ykcs11_md_ctx_t *ctx, CK_BYTE_PTR out, CK_ULONG_PTR out_len, int *nid) {

  int rv;
  unsigned int len;

  // Keep track of the md type if requested
  if (nid != NULL)
    *nid = EVP_MD_CTX_type(ctx);

  // Finalize digest and store result
  rv = EVP_DigestFinal_ex(ctx, out, &len);

  // Destroy the md context
  EVP_MD_CTX_destroy(ctx);

  // Error if the previous call failed
  if (rv != 1)
    return CKR_FUNCTION_FAILED;

  *out_len = len;

  return CKR_OK;
}

CK_RV do_md_cleanup(ykcs11_md_ctx_t *ctx) {

  EVP_MD_CTX_destroy((EVP_MD_CTX *) ctx);

  return CKR_OK;
}
