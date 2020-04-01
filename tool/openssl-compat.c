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

#ifdef LIBRESSL_VERSION_NUMBER

#ifndef RSAerror
#define RSAerror(e) RSAerr(0xfff,e)
#endif
int timingsafe_memcmp(const void*, const void*, size_t);
uint32_t arc4random_buf(void *, size_t);
void freezero(void *, size_t);

#ifndef HAVE_DECL_RSA_PADDING_CHECK_PKCS1_OAEP_MGF1
int yubico_RSA_padding_check_PKCS1_OAEP_mgf1(unsigned char *to, int tlen,
    const unsigned char *from, int flen, int num, const unsigned char *param,
    int plen, const EVP_MD *md, const EVP_MD *mgf1md)
{
	int i, dblen, mlen = -1;
	const unsigned char *maskeddb;
	int lzero;
	unsigned char *db = NULL;
	unsigned char seed[EVP_MAX_MD_SIZE], phash[EVP_MAX_MD_SIZE];
	unsigned char *padded_from;
	int bad = 0;
	int mdlen;

	if (md == NULL)
		md = EVP_sha1();
	if (mgf1md == NULL)
		mgf1md = md;

	if ((mdlen = EVP_MD_size(md)) <= 0)
		goto err;

	if (--num < 2 * mdlen + 1)
		/*
		 * 'num' is the length of the modulus, i.e. does not depend
		 * on the particular ciphertext.
		 */
		goto decoding_err;

	lzero = num - flen;
	if (lzero < 0) {
		/*
		 * signalling this error immediately after detection might allow
		 * for side-channel attacks (e.g. timing if 'plen' is huge
		 * -- cf. James H. Manger, "A Chosen Ciphertext Attack on RSA
		 * Optimal Asymmetric Encryption Padding (OAEP) [...]",
		 * CRYPTO 2001), so we use a 'bad' flag
		 */
		bad = 1;
		lzero = 0;
		flen = num; /* don't overflow the memcpy to padded_from */
	}

	dblen = num - mdlen;
	if ((db = malloc(dblen + num)) == NULL) {
		RSAerror(ERR_R_MALLOC_FAILURE);
		return -1;
	}

	/*
	 * Always do this zero-padding copy (even when lzero == 0)
	 * to avoid leaking timing info about the value of lzero.
	 */
	padded_from = db + dblen;
	memset(padded_from, 0, lzero);
	memcpy(padded_from + lzero, from, flen);

	maskeddb = padded_from + mdlen;

	if (PKCS1_MGF1(seed, mdlen, maskeddb, dblen, mgf1md))
		goto err;
	for (i = 0; i < mdlen; i++)
		seed[i] ^= padded_from[i];
	if (PKCS1_MGF1(db, dblen, seed, mdlen, mgf1md))
		goto err;
	for (i = 0; i < dblen; i++)
		db[i] ^= maskeddb[i];

	if (!EVP_Digest((void *)param, plen, phash, NULL, md, NULL))
		goto err;

	if (timingsafe_memcmp(db, phash, mdlen) != 0 || bad)
		goto decoding_err;
	else {
		for (i = mdlen; i < dblen; i++)
			if (db[i] != 0x00)
				break;
		if (i == dblen || db[i] != 0x01)
			goto decoding_err;
		else {
			/* everything looks OK */

			mlen = dblen - ++i;
			if (tlen < mlen) {
				RSAerror(RSA_R_DATA_TOO_LARGE);
				mlen = -1;
			} else
				memcpy(to, db + i, mlen);
		}
	}
	free(db);
	return mlen;

 decoding_err:
	/*
	 * To avoid chosen ciphertext attacks, the error message should not
	 * reveal which kind of decoding error happened
	 */
	RSAerror(RSA_R_OAEP_DECODING_ERROR);
 err:
	free(db);
	return -1;
}
#endif /* HAVE_DECL_RSA_PADDING_CHECK_PKCS1_OAEP_MGF1 */

#ifndef HAVE_DECL_RSA_PADDING_ADD_PKCS1_OAEP_MGF1
int yubico_RSA_padding_add_PKCS1_OAEP_mgf1(unsigned char *to, int tlen,
    const unsigned char *from, int flen, const unsigned char *param, int plen,
    const EVP_MD *md, const EVP_MD *mgf1md)
{
	int i, emlen = tlen - 1;
	unsigned char *db, *seed;
	unsigned char *dbmask = NULL;
	unsigned char seedmask[EVP_MAX_MD_SIZE];
	int mdlen, dbmask_len = 0;
	int rv = 0;

	if (md == NULL)
		md = EVP_sha1();
	if (mgf1md == NULL)
		mgf1md = md;

	if ((mdlen = EVP_MD_size(md)) <= 0)
		goto err;

	if (flen > emlen - 2 * mdlen - 1) {
		RSAerror(RSA_R_DATA_TOO_LARGE_FOR_KEY_SIZE);
		goto err;
	}

	if (emlen < 2 * mdlen + 1) {
		RSAerror(RSA_R_KEY_SIZE_TOO_SMALL);
		goto err;
	}

	to[0] = 0;
	seed = to + 1;
	db = to + mdlen + 1;

	if (!EVP_Digest((void *)param, plen, db, NULL, md, NULL))
		goto err;

	memset(db + mdlen, 0, emlen - flen - 2 * mdlen - 1);
	db[emlen - flen - mdlen - 1] = 0x01;
	memcpy(db + emlen - flen - mdlen, from, flen);
	arc4random_buf(seed, mdlen);

	dbmask_len = emlen - mdlen;
	if ((dbmask = malloc(dbmask_len)) == NULL) {
		RSAerror(ERR_R_MALLOC_FAILURE);
		goto err;
	}

	if (PKCS1_MGF1(dbmask, dbmask_len, seed, mdlen, mgf1md) < 0)
		goto err;
	for (i = 0; i < dbmask_len; i++)
		db[i] ^= dbmask[i];
	if (PKCS1_MGF1(seedmask, mdlen, db, dbmask_len, mgf1md) < 0)
		goto err;
	for (i = 0; i < mdlen; i++)
		seed[i] ^= seedmask[i];

	rv = 1;

 err:
	explicit_bzero(seedmask, sizeof(seedmask));
	freezero(dbmask, dbmask_len);

	return rv;
}

#endif /* HAVE_DECL_RSA_PADDING_ADD_PKCS1_OAEP_MGF1 */

#endif /* LIBRESSL_VERSION_NUMBER */

#endif /* OPENSSL_VERSION_NUMBER || LIBRESSL_VERSION_NUMBER */
