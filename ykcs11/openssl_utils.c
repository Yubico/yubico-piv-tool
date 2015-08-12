#include "openssl_utils.h"
#include <stdbool.h>
#include "../tool/util.h" // TODO: share this better?
#include "debug.h"
#include <string.h>

CK_RV do_store_cert(CK_BYTE_PTR data, CK_ULONG len, X509 **cert) {

  const unsigned char *p = data; // Mandatory temp variable required by OpenSSL
  int                 cert_len;

  /**cert = X509_new();
  if (*cert == NULL)
  return CKR_HOST_MEMORY;*/
  //dump_hex(data, len, stderr, CK_TRUE);

  if (*p++ != 0x70)
    return CKR_FUNCTION_FAILED;

  p += get_length(p, &cert_len);

  *cert = d2i_X509(NULL, &p, cert_len);
  if (*cert == NULL)
    return CKR_FUNCTION_FAILED;

  /*
  BIO *STDout = BIO_new_fp(stderr, BIO_NOCLOSE);

  X509_print_ex(STDout, *cert, 0, 0);

  BIO_free(STDout);
  */

  return CKR_OK;

}

CK_RV do_create_empty_cert(CK_BYTE_PTR in, CK_ULONG in_len, CK_BBOOL is_rsa, CK_ULONG key_len,
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
  time_t    t;

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

    rsa->n = bignum_n;
    rsa->e = bignum_e;

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

  // TODO: add more info like issuer?
  tm = ASN1_TIME_new();
  if (tm == NULL)
    goto create_empty_cert_cleanup;

  ASN1_TIME_set_string(tm, "000001010000Z");
  X509_set_notBefore(cert, tm);
  X509_set_notAfter(cert, tm);

  len = i2d_X509(cert, NULL);
  if (len < 0)
    goto create_empty_cert_cleanup;

  if (len > *out_len) {
    rv = CKR_BUFFER_TOO_SMALL;
    goto create_empty_cert_cleanup;
  }

  p = in;
  if ((*out_len = i2d_X509(cert, &p)) == 0)
    goto create_empty_cert_cleanup;

  /* TODO REMOVE THIS */
  BIO *STDout = BIO_new_fp(stderr, BIO_NOCLOSE);

  X509_print_ex(STDout, cert, 0, 0);

  BIO_free(STDout);
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

CK_RV free_cert(X509 *cert) {

  X509_free((X509 *) cert);

  return CKR_OK;
}


CK_RV do_store_pubk(X509 *cert, EVP_PKEY **key) {

  *key = X509_get_pubkey(cert);

  if (*key == NULL)
    return CKR_FUNCTION_FAILED;

  return CKR_OK;

}

CK_KEY_TYPE do_get_key_type(EVP_PKEY *key) {

  switch (key->type) {
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

  return RSA_size(rsa) * 8; // There is also RSA_bits but only in >= 1.1.0

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

  switch(key->type) {
  case EVP_PKEY_RSA:
  case EVP_PKEY_RSA2:

    rsa = EVP_PKEY_get1_RSA(key);

    if (RSA_size(rsa) > *len)
      return CKR_BUFFER_TOO_SMALL;

    p = data;

    if ((*len = i2d_RSAPublicKey(rsa, &p)) == 0)
      return CKR_FUNCTION_FAILED;

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

    // Adde the DER structure with length after extracting the point
    data[0] = 0x04;

    if ((*len = EC_POINT_point2oct(ecg, ecp, pcf, data + 2, *len - 2, NULL)) == 0)
      return CKR_FUNCTION_FAILED;

    data[1] = *len;

    *len += 2;

    break;

  default:
    return CKR_FUNCTION_FAILED;
  }

  EC_KEY_free(eck);
  eck = NULL;

    return CKR_OK;

}

CK_RV do_encode_rsa_public_key(CK_BYTE_PTR data, CK_ULONG len, RSA **key) {

  const unsigned char *p = data;

  if (data == NULL)
    return CKR_ARGUMENTS_BAD;

  if ((*key = d2i_RSAPublicKey(NULL, &p, len)) == NULL)
    return CKR_FUNCTION_FAILED;

  return CKR_OK;

}

CK_RV do_get_curve_parameters( EVP_PKEY *key, CK_BYTE_PTR data, CK_ULONG_PTR len) {

  EC_KEY *eck;
  const EC_GROUP *ecg;
  unsigned char *p;

  eck = EVP_PKEY_get1_EC_KEY(key);
  ecg = EC_KEY_get0_group(eck);

  p = data;

  if ((*len = i2d_ECPKParameters(ecg, &p)) == 0)
      return CKR_FUNCTION_FAILED;

  return CKR_OK;
}

CK_RV free_key(EVP_PKEY *key) {

  EVP_PKEY_free(key);

  return CKR_OK;

}

CK_RV do_pkcs_1_t1(CK_BYTE_PTR in, CK_ULONG in_len, CK_BYTE_PTR out, CK_ULONG_PTR out_len, CK_ULONG key_len) {
  unsigned char buffer[512];
  
  key_len /= 8;
  DBG(("Apply padding to %lu bytes and get %lu\n", in_len, key_len));

  // TODO: rand must be seeded first (should be automatic)
  if (*out_len < key_len)
    CKR_BUFFER_TOO_SMALL;

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

CK_RV do_pkcs_pss(RSA *key, CK_BYTE_PTR in, CK_ULONG in_len, int nid,
                  CK_BYTE_PTR out, CK_ULONG_PTR out_len) {
  unsigned char em[512]; // Max for this is ceil((|key_len_bits| - 1) / 8)

  // TODO: rand must be seeded first (should be automatic)
  if (*out_len < RSA_size(key))
    CKR_BUFFER_TOO_SMALL;

  DBG(("Apply PSS padding to %lu bytes and get %d\n", in_len, RSA_size(key)));

  if (RSA_padding_add_PKCS1_PSS(key, em, in, EVP_get_digestbynid(nid), -2) == 0)
    return CKR_FUNCTION_FAILED;

  *out_len = RSA_size(key);

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
