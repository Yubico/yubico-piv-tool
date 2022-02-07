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

#include <openssl/opensslv.h>
#if (OPENSSL_VERSION_NUMBER < 0x10100000L) || defined(LIBRESSL_VERSION_NUMBER)

#include <openssl/rsa.h>
#include <openssl/dsa.h>
#include <openssl/ecdsa.h>
#include <openssl/dh.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/rand.h>
#include <openssl/err.h>

int RSA_set0_key(RSA *r, BIGNUM *n, BIGNUM *e, BIGNUM *d);
void RSA_get0_key(const RSA *r,
                  const BIGNUM **n, const BIGNUM **e, const BIGNUM **d);
void RSA_get0_factors(const RSA *r, const BIGNUM **p, const BIGNUM **q);
void RSA_get0_crt_params(const RSA *r,
                         const BIGNUM **dmp1, const BIGNUM **dmq1,
                         const BIGNUM **iqmp);
void X509_SIG_getm(X509_SIG *sig, X509_ALGOR **palg,
                   ASN1_OCTET_STRING **pdigest);
int ECDSA_SIG_set0(ECDSA_SIG *sig, BIGNUM *r, BIGNUM *s);
void ECDSA_SIG_get0(const ECDSA_SIG *sig, const BIGNUM **pr, const BIGNUM **ps);

#if (LIBRESSL_VERSION_NUMBER < 0x2070500fL)

#define ASN1_STRING_get0_data ASN1_STRING_data

RSA *EVP_PKEY_get0_RSA(const EVP_PKEY *pkey);
EC_KEY *EVP_PKEY_get0_EC_KEY(const EVP_PKEY *pkey);

#endif

#if (LIBRESSL_VERSION_NUMBER > 0L) && (LIBRESSL_VERSION_NUMBER < 0x31000000L)

#define EVP_PKEY_CTRL_RSA_OAEP_MD		(EVP_PKEY_ALG_CTRL + 9)
#define EVP_PKEY_CTRL_RSA_OAEP_LABEL		(EVP_PKEY_ALG_CTRL + 10)

#define EVP_PKEY_CTX_set_rsa_oaep_md(ctx, md) \
	EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_RSA, EVP_PKEY_OP_TYPE_CRYPT, \
	    EVP_PKEY_CTRL_RSA_OAEP_MD, 0, (void *)(md))

#define EVP_PKEY_CTX_set0_rsa_oaep_label(ctx, l, llen) \
	EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_RSA, EVP_PKEY_OP_TYPE_CRYPT, \
	    EVP_PKEY_CTRL_RSA_OAEP_LABEL, llen, (void *)(l))

int RSA_padding_add_PKCS1_OAEP_mgf1(unsigned char *to, int tlen,
                                    const unsigned char *from, int flen,
                                    const unsigned char *param, int plen,
                                    const EVP_MD *md, const EVP_MD *mgf1md);

int RSA_padding_check_PKCS1_OAEP_mgf1(unsigned char *to, int tlen,
                                       const unsigned char *f, int fl, int rsa_len,
                                       const unsigned char *p, int pl,
                                       const EVP_MD *md, const EVP_MD *mgf1md);

#endif

#endif /* OPENSSL_VERSION_NUMBER || LIBRESSL_VERSION_NUMBER */
#endif /* LIBCRYPTO_COMPAT_H */
