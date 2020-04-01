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

int yubico_RSA_set0_key(RSA *r, BIGNUM *n, BIGNUM *e, BIGNUM *d);
#define RSA_set0_key yubico_RSA_set0_key
void yubico_RSA_get0_key(const RSA *r,
                  const BIGNUM **n, const BIGNUM **e, const BIGNUM **d);
#define RSA_get0_key yubico_RSA_get0_key

void yubico_RSA_get0_factors(const RSA *r, const BIGNUM **p, const BIGNUM **q);
#define RSA_get0_factors yubico_RSA_get0_factors

void yubico_RSA_get0_crt_params(const RSA *r,
                         const BIGNUM **dmp1, const BIGNUM **dmq1,
                         const BIGNUM **iqmp);
#define RSA_get0_crt_params yubico_RSA_get0_crt_params

void yubico_X509_SIG_getm(X509_SIG *sig, X509_ALGOR **palg,
                   ASN1_OCTET_STRING **pdigest);
#define X509_SIG_getm yubico_X509_SIG_getm

int yubico_ECDSA_SIG_set0(ECDSA_SIG *sig, BIGNUM *r, BIGNUM *s);
#define ECDSA_SIG_set0 yubico_ECDSA_SIG_set0
void yubico_ECDSA_SIG_get0(const ECDSA_SIG *sig, const BIGNUM **pr, const BIGNUM **ps);
#define ECDSA_SIG_get0 yubico_ECDSA_SIG_get0

RSA *yubico_EVP_PKEY_get0_RSA(const EVP_PKEY *pkey);
#define EVP_PKEY_get0_RSA yubico_EVP_PKEY_get0_RSA

EC_KEY *yubico_EVP_PKEY_get0_EC_KEY(const EVP_PKEY *pkey);
#define EVP_PKEY_get0_EC_KEY yubico_EVP_PKEY_get0_EC_KEY

#endif /* _WINDOWS */
#endif /* OPENSSL_VERSION_NUMBER || LIBRESSL_VERSION_NUMBER */
#endif /* LIBCRYPTO_COMPAT_H */
