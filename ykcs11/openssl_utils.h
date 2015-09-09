#ifndef OPENSSL_UTIL_H
#define OPENSSL_UTIL_H

/* #include <openssl/x509.h> */
/* #include <openssl/evp.h> */
/* #include <openssl/rsa.h> */
/* #include <openssl/ec.h> */

#include "openssl_types.h"
#include "pkcs11t.h"

CK_RV do_store_cert(CK_BYTE_PTR data, CK_ULONG len, X509 **cert);
CK_RV do_create_empty_cert(CK_BYTE_PTR in, CK_ULONG in_len, CK_BBOOL is_rsa,
                           CK_BYTE_PTR out, CK_ULONG_PTR out_len);
CK_RV do_check_cert(CK_BYTE_PTR in, CK_ULONG_PTR cert_len);
CK_RV free_cert(X509 *cert);

CK_RV       do_store_pubk(X509 *cert, EVP_PKEY **key);
CK_KEY_TYPE do_get_key_type(EVP_PKEY *key);
CK_ULONG    do_get_rsa_modulus_length(EVP_PKEY *key);
CK_RV       do_get_public_key(EVP_PKEY *key, CK_BYTE_PTR data, CK_ULONG_PTR len);
CK_RV       do_encode_rsa_public_key(CK_BYTE_PTR data, CK_ULONG len, RSA **key);
CK_RV       do_get_curve_parameters(EVP_PKEY *key, CK_BYTE_PTR data, CK_ULONG_PTR len);
CK_RV       free_key(EVP_PKEY *key);

CK_RV do_pkcs_1_t1(CK_BYTE_PTR in, CK_ULONG in_len, CK_BYTE_PTR out, CK_ULONG_PTR out_len, CK_ULONG key_len);
CK_RV do_pkcs_1_digest_info(CK_BYTE_PTR in, CK_ULONG in_len, int nid, CK_BYTE_PTR out, CK_ULONG_PTR out_len);

CK_RV do_pkcs_pss(RSA *key, CK_BYTE_PTR in, CK_ULONG in_len, int nid,
                  CK_BYTE_PTR out, CK_ULONG_PTR out_len);

CK_RV do_md_init(hash_t hash, ykcs11_md_ctx_t **ctx);
CK_RV do_md_update(ykcs11_md_ctx_t *ctx, CK_BYTE_PTR in, CK_ULONG in_len);
CK_RV do_md_finalize(ykcs11_md_ctx_t *ctx, CK_BYTE_PTR out, CK_ULONG_PTR out_len, int *nid);
CK_RV do_md_cleanup(ykcs11_md_ctx_t *ctx);

#endif
