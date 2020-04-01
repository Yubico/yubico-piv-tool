/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef LIBCRYPTO_COMPAT_H
#define LIBCRYPTO_COMPAT_H

#ifndef _WINDOWS

#include <openssl/opensslv.h>
#if (OPENSSL_VERSION_NUMBER < 0x10100000L) || defined(LIBRESSL_VERSION_NUMBER)

#include <openssl/rsa.h>
#include <openssl/dsa.h>
#include <openssl/ecdsa.h>
#include <openssl/dh.h>
#include <openssl/evp.h>
#include <openssl/x509.h>

#ifndef HAVE_DECL_RSA_SET0_KEY
int yubico_RSA_set0_key(RSA *r, BIGNUM *n, BIGNUM *e, BIGNUM *d);
#define RSA_set0_key yubico_RSA_set0_key
void yubico_RSA_get0_key(const RSA *r,
                  const BIGNUM **n, const BIGNUM **e, const BIGNUM **d);
#define RSA_get0_key yubico_RSA_get0_key
#endif /* HAVE_DECL_RSA_SET0_KEY */

#ifndef HAVE_DECL_RSA_GET0_FACTORS
void yubico_RSA_get0_factors(const RSA *r, const BIGNUM **p, const BIGNUM **q);
#define RSA_get0_factors yubico_RSA_get0_factors
#endif /* HAVE_DECL_RSA_GET0_FACTORS */

#ifndef HAVE_DECL_RSA_GET0_CRT_PARAMS
void yubico_RSA_get0_crt_params(const RSA *r,
                         const BIGNUM **dmp1, const BIGNUM **dmq1,
                         const BIGNUM **iqmp);
#define RSA_get0_crt_params yubico_RSA_get0_crt_params
#endif /* HAVE_DECL_RSA_GET0_CRT_PARAMS */

#ifndef HAVE_DECL_X509_SIG_GETM
void yubico_X509_SIG_getm(X509_SIG *sig, X509_ALGOR **palg,
                   ASN1_OCTET_STRING **pdigest);
#define X509_SIG_getm yubico_X509_SIG_getm
#endif /* HAVE_DECL_X509_SIG_GETM */

#ifndef HAVE_DECL_ECDSA_SIG_SET0
int yubico_ECDSA_SIG_set0(ECDSA_SIG *sig, BIGNUM *r, BIGNUM *s);
#define ECDSA_SIG_set0 yubico_ECDSA_SIG_set0
void yubico_ECDSA_SIG_get0(const ECDSA_SIG *sig, const BIGNUM **pr, const BIGNUM **ps);
#define ECDSA_SIG_get0 yubico_ECDSA_SIG_get0
#endif /* HAVE_DECL_ECDSA_SIG_SET0 */

#ifndef HAVE_DECL_EVP_PKEY_GET0_RSA
RSA *yubico_EVP_PKEY_get0_RSA(const EVP_PKEY *pkey);
#define EVP_PKEY_get0_RSA yubico_EVP_PKEY_get0_RSA
#endif /* HAVE_DECL_EVP_PKEY_GET0_RSA */

#ifndef HAVE_DECL_EVP_PKEY_GET0_EC_KEY
EC_KEY *yubico_EVP_PKEY_get0_EC_KEY(const EVP_PKEY *pkey);
#define EVP_PKEY_get0_EC_KEY yubico_EVP_PKEY_get0_EC_KEY
#endif /* HAVE_DECL_EVP_PKEY_GET0_EC_KEY */

#ifndef EVP_PKEY_CTRL_RSA_OAEP_MD
#define EVP_PKEY_CTRL_RSA_OAEP_MD		(EVP_PKEY_ALG_CTRL + 9)
#define EVP_PKEY_CTRL_RSA_OAEP_LABEL		(EVP_PKEY_ALG_CTRL + 10)
#define EVP_PKEY_CTX_set_rsa_oaep_md(ctx, md) \
	EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_RSA, EVP_PKEY_OP_TYPE_CRYPT, \
	    EVP_PKEY_CTRL_RSA_OAEP_MD, 0, (void *)(md))

#define EVP_PKEY_CTX_set0_rsa_oaep_label(ctx, l, llen) \
	EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_RSA, EVP_PKEY_OP_TYPE_CRYPT, \
	    EVP_PKEY_CTRL_RSA_OAEP_LABEL, llen, (void *)(l))

#endif /* EVP_PKEY_CTRL_RSA_OAEP_MD */

#endif /* _WINDOWS */
#endif /* OPENSSL_VERSION_NUMBER || LIBRESSL_VERSION_NUMBER */
#endif /* LIBCRYPTO_COMPAT_H */
