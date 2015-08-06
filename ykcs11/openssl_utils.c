#include "openssl_utils.h"
#include <stdbool.h>
#include "../tool/util.h" // TODO: share this better?


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
  key_len /= 8;
  DBG(("Apply padding to %lu bytes and get %lu\n", in_len, key_len));

  // TODO: rand must be seeded first (should be automatic)
  if (*out_len < key_len)
    CKR_BUFFER_TOO_SMALL;

  if (RSA_padding_add_PKCS1_type_1(out, key_len, in, in_len) == 0)
    return CKR_FUNCTION_FAILED;

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
