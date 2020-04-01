/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "openssl-compat.h"
#if (OPENSSL_VERSION_NUMBER < 0x10100000L) || defined(LIBRESSL_VERSION_NUMBER)

#include <string.h>
#include <openssl/engine.h>

#ifndef HAVE_DECL_RSA_SET0_KEY
int yubico_RSA_set0_key(RSA *r, BIGNUM *n, BIGNUM *e, BIGNUM *d)
{
    /* If the fields n and e in r are NULL, the corresponding input
     * parameters MUST be non-NULL for n and e.  d may be
     * left NULL (in case only the public key is used).
     */
    if ((r->n == NULL && n == NULL)
        || (r->e == NULL && e == NULL))
        return 0;

    if (n != NULL) {
        BN_free(r->n);
        r->n = n;
    }
    if (e != NULL) {
        BN_free(r->e);
        r->e = e;
    }
    if (d != NULL) {
        BN_free(r->d);
        r->d = d;
    }
    return 1;
}

void yubico_RSA_get0_key(const RSA *r,
                  const BIGNUM **n, const BIGNUM **e, const BIGNUM **d)
{
    if (n != NULL)
        *n = r->n;
    if (e != NULL)
        *e = r->e;
    if (d != NULL)
        *d = r->d;
}
#endif /* HAVE_DECL_RSA_SET0_KEY */

#ifndef HAVE_DECL_RSA_GET0_FACTORS
void yubico_RSA_get0_factors(const RSA *r, const BIGNUM **p, const BIGNUM **q)
{
    if (p != NULL)
        *p = r->p;
    if (q != NULL)
        *q = r->q;
}
#endif /* HAVE_DECL_RSA_GET0_FACTORS */

#ifndef HAVE_DECL_RSA_GET0_CRT_PARAMS
void yubico_RSA_get0_crt_params(const RSA *r,
                         const BIGNUM **dmp1, const BIGNUM **dmq1,
                         const BIGNUM **iqmp)
{
    if (dmp1 != NULL)
        *dmp1 = r->dmp1;
    if (dmq1 != NULL)
        *dmq1 = r->dmq1;
    if (iqmp != NULL)
        *iqmp = r->iqmp;
}
#endif /* HAVE_DECL_RSA_GET0_CRT_PARAMS */

#ifndef HAVE_DECL_X509_SIG_GETM
void yubico_X509_SIG_getm(X509_SIG *sig, X509_ALGOR **palg,
                   ASN1_OCTET_STRING **pdigest)
{
    if (palg)
        *palg = sig->algor;
    if (pdigest)
        *pdigest = sig->digest;
}
#endif /* HAVE_DECL_X509_SIG_GETM */

#ifndef HAVE_DECL_ECDSA_SIG_SET0
int yubico_ECDSA_SIG_set0(ECDSA_SIG *sig, BIGNUM *r, BIGNUM *s)
{
    if (r == NULL || s == NULL)
        return 0;
    BN_clear_free(sig->r);
    BN_clear_free(sig->s);
    sig->r = r;
    sig->s = s;
    return 1;
}

void yubico_ECDSA_SIG_get0(const ECDSA_SIG *sig, const BIGNUM **pr, const BIGNUM **ps) {
    if (pr != NULL)
        *pr = sig->r;
    if (ps != NULL)
        *ps = sig->s;
}
#endif /* HAVE_DECL_ECDSA_SIG_SET0 */

#ifndef HAVE_DECL_EVP_PKEY_GET0_RSA
RSA *yubico_EVP_PKEY_get0_RSA(const EVP_PKEY *pkey) {
  if (pkey->type != EVP_PKEY_RSA) {
    return NULL;
  }
  return pkey->pkey.rsa;
}
#endif /* HAVE_DECL_EVP_PKEY_GET0_RSA */

#ifndef HAVE_DECL_EVP_PKEY_GET0_EC_KEY
EC_KEY *yubico_EVP_PKEY_get0_EC_KEY(const EVP_PKEY *pkey) {
  if (pkey->type != EVP_PKEY_EC) {
    return NULL;
  }
  return pkey->pkey.ec;
}
#endif /* HAVE_DECL_EVP_PKEY_GET0_EC_KEY */

#endif /* OPENSSL_VERSION_NUMBER || LIBRESSL_VERSION_NUMBER */
