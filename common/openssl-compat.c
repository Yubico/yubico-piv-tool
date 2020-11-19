/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "openssl-compat.h"

int make_iso_compilers_happy;

#if (OPENSSL_VERSION_NUMBER < 0x10100000L) || defined(LIBRESSL_VERSION_NUMBER)

#include <string.h>
#include <limits.h>

void X509_SIG_getm(X509_SIG *sig, X509_ALGOR **palg,
                   ASN1_OCTET_STRING **pdigest)
{
    if (palg)
        *palg = sig->algor;
    if (pdigest)
        *pdigest = sig->digest;
}

#if (LIBRESSL_VERSION_NUMBER < 0x2070000fL)

int RSA_set0_key(RSA *r, BIGNUM *n, BIGNUM *e, BIGNUM *d)
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

void RSA_get0_key(const RSA *r,
                  const BIGNUM **n, const BIGNUM **e, const BIGNUM **d)
{
    if (n != NULL)
        *n = r->n;
    if (e != NULL)
        *e = r->e;
    if (d != NULL)
        *d = r->d;
}

void RSA_get0_factors(const RSA *r, const BIGNUM **p, const BIGNUM **q)
{
    if (p != NULL)
        *p = r->p;
    if (q != NULL)
        *q = r->q;
}

void RSA_get0_crt_params(const RSA *r,
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

int ECDSA_SIG_set0(ECDSA_SIG *sig, BIGNUM *r, BIGNUM *s)
{
    if (r == NULL || s == NULL)
        return 0;
    BN_clear_free(sig->r);
    BN_clear_free(sig->s);
    sig->r = r;
    sig->s = s;
    return 1;
}

void ECDSA_SIG_get0(const ECDSA_SIG *sig, const BIGNUM **pr, const BIGNUM **ps) {
    if (pr != NULL)
        *pr = sig->r;
    if (ps != NULL)
        *ps = sig->s;
}

RSA *EVP_PKEY_get0_RSA(const EVP_PKEY *pkey) {
  if (pkey->type != EVP_PKEY_RSA) {
    return NULL;
  }
  return pkey->pkey.rsa;
}

EC_KEY *EVP_PKEY_get0_EC_KEY(const EVP_PKEY *pkey) {
  if (pkey->type != EVP_PKEY_EC) {
    return NULL;
  }
  return pkey->pkey.ec;
}

#endif

#if (LIBRESSL_VERSION_NUMBER > 0L) && (LIBRESSL_VERSION_NUMBER < 0x3010000fL)

static inline unsigned int constant_time_msb(unsigned int a)
{
    return 0 - (a >> (sizeof(a) * 8 - 1));
}

static inline unsigned int constant_time_lt(unsigned int a, unsigned int b)
{
    return constant_time_msb(a ^ ((a ^ b) | ((a - b) ^ b)));
}

static inline unsigned char constant_time_lt_8(unsigned int a, unsigned int b)
{
    return (unsigned char)(constant_time_lt(a, b));
}

static inline unsigned int constant_time_ge(unsigned int a, unsigned int b)
{
    return ~constant_time_lt(a, b);
}

static inline unsigned char constant_time_ge_8(unsigned int a, unsigned int b)
{
    return (unsigned char)(constant_time_ge(a, b));
}

static inline unsigned int constant_time_is_zero(unsigned int a)
{
    return constant_time_msb(~a & (a - 1));
}

static inline unsigned char constant_time_is_zero_8(unsigned int a)
{
    return (unsigned char)(constant_time_is_zero(a));
}

static inline unsigned int constant_time_eq(unsigned int a, unsigned int b)
{
    return constant_time_is_zero(a ^ b);
}

static inline unsigned char constant_time_eq_8(unsigned int a, unsigned int b)
{
    return (unsigned char)(constant_time_eq(a, b));
}

static inline unsigned int constant_time_eq_int(int a, int b)
{
    return constant_time_eq((unsigned)(a), (unsigned)(b));
}

static inline unsigned char constant_time_eq_int_8(int a, int b)
{
    return constant_time_eq_8((unsigned)(a), (unsigned)(b));
}

static inline unsigned int constant_time_select(unsigned int mask,
                                                unsigned int a,
                                                unsigned int b)
{
    return (mask & a) | (~mask & b);
}

static inline unsigned char constant_time_select_8(unsigned char mask,
                                                   unsigned char a,
                                                   unsigned char b)
{
    return (unsigned char)(constant_time_select(mask, a, b));
}

static inline int constant_time_select_int(unsigned int mask, int a, int b)
{
    return (int)(constant_time_select(mask, (unsigned)(a), (unsigned)(b)));
}

static inline void err_clear_last_constant_time(int clear) {
}

static inline void freezero(void *p, size_t s) {
    memset(p, 0, s);
    free(p);
}

static int timingsafe_memcmp(const void *b1, const void *b2, size_t len)
{
    const unsigned char *p1 = b1, *p2 = b2;
    size_t i;
    int res = 0, done = 0;

    for (i = 0; i < len; i++) {
        /* lt is -1 if p1[i] < p2[i]; else 0. */
        int lt = (p1[i] - p2[i]) >> CHAR_BIT;

        /* gt is -1 if p1[i] > p2[i]; else 0. */
        int gt = (p2[i] - p1[i]) >> CHAR_BIT;

        /* cmp is 1 if p1[i] > p2[i]; -1 if p1[i] < p2[i]; else 0. */
        int cmp = lt - gt;

        /* set res = cmp if !done. */
        res |= cmp & ~done;

        /* set done if p1[i] != p2[i]. */
        done |= lt | gt;
    }

    return (res);
}

static inline void RSAerror(int err) {
}

int RSA_padding_add_PKCS1_OAEP_mgf1(unsigned char *to, int tlen,
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
	if(RAND_bytes(seed, mdlen) <= 0) {
		goto err;
	}

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
	memset(seedmask, 0, sizeof(seedmask));
	freezero(dbmask, dbmask_len);

	return rv;
}

int RSA_padding_check_PKCS1_OAEP_mgf1(unsigned char *to, int tlen,
    const unsigned char *from, int flen, int num, const unsigned char *param,
    int plen, const EVP_MD *md, const EVP_MD *mgf1md)
{
	int i, dblen = 0, mlen = -1, one_index = 0, msg_index;
	unsigned int good = 0, found_one_byte, mask;
	const unsigned char *maskedseed, *maskeddb;
	unsigned char seed[EVP_MAX_MD_SIZE], phash[EVP_MAX_MD_SIZE];
	unsigned char *db = NULL, *em = NULL;
	int mdlen;

	if (md == NULL)
		md = EVP_sha1();
	if (mgf1md == NULL)
		mgf1md = md;

	if ((mdlen = EVP_MD_size(md)) <= 0)
		return -1;

	if (tlen <= 0 || flen <= 0)
		return -1;

	/*
	 * |num| is the length of the modulus; |flen| is the length of the
	 * encoded message. Therefore, for any |from| that was obtained by
	 * decrypting a ciphertext, we must have |flen| <= |num|. Similarly,
	 * |num| >= 2 * |mdlen| + 2 must hold for the modulus irrespective
	 * of the ciphertext, see PKCS #1 v2.2, section 7.1.2.
	 * This does not leak any side-channel information.
	 */
	if (num < flen || num < 2 * mdlen + 2) {
		RSAerror(RSA_R_OAEP_DECODING_ERROR);
		return -1;
	}

	dblen = num - mdlen - 1;
	if ((db = malloc(dblen)) == NULL) {
		RSAerror(ERR_R_MALLOC_FAILURE);
		goto cleanup;
	}
	if ((em = malloc(num)) == NULL) {
		RSAerror(ERR_R_MALLOC_FAILURE);
		goto cleanup;
	}

	/*
	 * Caller is encouraged to pass zero-padded message created with
	 * BN_bn2binpad. Trouble is that since we can't read out of |from|'s
	 * bounds, it's impossible to have an invariant memory access pattern
	 * in case |from| was not zero-padded in advance.
	 */
	for (from += flen, em += num, i = 0; i < num; i++) {
		mask = ~constant_time_is_zero(flen);
		flen -= 1 & mask;
		from -= 1 & mask;
		*--em = *from & mask;
	}
	from = em;

	/*
	 * The first byte must be zero, however we must not leak if this is
	 * true. See James H. Manger, "A Chosen Ciphertext Attack on RSA
	 * Optimal Asymmetric Encryption Padding (OAEP) [...]", CRYPTO 2001).
	 */
	good = constant_time_is_zero(from[0]);

	maskedseed = from + 1;
	maskeddb = from + 1 + mdlen;

	if (PKCS1_MGF1(seed, mdlen, maskeddb, dblen, mgf1md))
		goto cleanup;
	for (i = 0; i < mdlen; i++)
		seed[i] ^= maskedseed[i];

	if (PKCS1_MGF1(db, dblen, seed, mdlen, mgf1md))
		goto cleanup;
	for (i = 0; i < dblen; i++)
		db[i] ^= maskeddb[i];

	if (!EVP_Digest((void *)param, plen, phash, NULL, md, NULL))
		goto cleanup;

	good &= constant_time_is_zero(timingsafe_memcmp(db, phash, mdlen));

	found_one_byte = 0;
	for (i = mdlen; i < dblen; i++) {
		/*
		 * Padding consists of a number of 0-bytes, followed by a 1.
		 */
		unsigned int equals1 = constant_time_eq(db[i], 1);
		unsigned int equals0 = constant_time_is_zero(db[i]);

		one_index = constant_time_select_int(~found_one_byte & equals1,
		    i, one_index);
		found_one_byte |= equals1;
		good &= (found_one_byte | equals0);
	}

	good &= found_one_byte;

	/*
	 * At this point |good| is zero unless the plaintext was valid,
	 * so plaintext-awareness ensures timing side-channels are no longer a
	 * concern.
	 */
	msg_index = one_index + 1;
	mlen = dblen - msg_index;

	/*
	 * For good measure, do this check in constant time as well.
	 */
	good &= constant_time_ge(tlen, mlen);

	/*
	 * Even though we can't fake result's length, we can pretend copying
	 * |tlen| bytes where |mlen| bytes would be real. The last |tlen| of
	 * |dblen| bytes are viewed as a circular buffer starting at |tlen|-|mlen'|,
	 * where |mlen'| is the "saturated" |mlen| value. Deducing information
	 * about failure or |mlen| would require an attacker to observe
	 * memory access patterns with byte granularity *as it occurs*. It
	 * should be noted that failure is indistinguishable from normal
	 * operation if |tlen| is fixed by protocol.
	 */
	tlen = constant_time_select_int(constant_time_lt(dblen, tlen), dblen, tlen);
	msg_index = constant_time_select_int(good, msg_index, dblen - tlen);
	mlen = dblen - msg_index;
	for (from = db + msg_index, mask = good, i = 0; i < tlen; i++) {
		unsigned int equals = constant_time_eq(i, mlen);

		from -= dblen & equals; /* if (i == mlen) rewind   */
		mask &= mask ^ equals;  /* if (i == mlen) mask = 0 */
		to[i] = constant_time_select_8(mask, from[i], to[i]);
	}

	/*
	 * To avoid chosen ciphertext attacks, the error message should not
	 * reveal which kind of decoding error happened.
	 */
	RSAerror(RSA_R_OAEP_DECODING_ERROR);
	err_clear_last_constant_time(1 & good);

 cleanup:
	memset(seed, 0, sizeof(seed));
	freezero(db, dblen);
	freezero(em, num);

	return constant_time_select_int(good, mlen, -1);
}

#endif

#endif /* OPENSSL_VERSION_NUMBER || LIBRESSL_VERSION_NUMBER */
