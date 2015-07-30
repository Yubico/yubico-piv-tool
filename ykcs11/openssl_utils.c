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

CK_RV free_key(EVP_PKEY *key) {

  EVP_PKEY_free(key);
  
  return CKR_OK;
  
}
/* #include <stdio.h> */
/* #include <openssl/err.h> */
/*   ERR_load_crypto_strings(); */
/* //SSL_load_error_strings(); */
CK_RV do_pkcs_t1(CK_BYTE_PTR in, CK_ULONG in_len, CK_BYTE_PTR out, CK_ULONG out_len, CK_ULONG key_len) {
  fprintf(stderr, "Apply padding to %lu bytes and get %lu\n", in_len, key_len);


  if (out_len < key_len)
    CKR_BUFFER_TOO_SMALL;

  if (RSA_padding_add_PKCS1_type_1(out, key_len, in, in_len) == 0)
    return CKR_FUNCTION_FAILED;

  return CKR_OK;
}
