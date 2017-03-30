/*
 * Copyright (c) 2015-2016 Yubico AB
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *
 *   * Redistributions in binary form must reproduce the above
 *     copyright notice, this list of conditions and the following
 *     disclaimer in the documentation and/or other materials provided
 *     with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#ifndef OPENSSL_UTIL_H
#define OPENSSL_UTIL_H

/* #include <openssl/x509.h> */
/* #include <openssl/evp.h> */
/* #include <openssl/rsa.h> */
/* #include <openssl/ec.h> */

#include "openssl_types.h"
#include "pkcs11y.h"

CK_RV do_store_cert(CK_BYTE_PTR data, CK_ULONG len, X509 **cert);
CK_RV do_create_empty_cert(CK_BYTE_PTR in, CK_ULONG in_len, CK_BBOOL is_rsa,
                           CK_BYTE_PTR out, CK_ULONG_PTR out_len);
CK_RV do_check_cert(CK_BYTE_PTR in, CK_ULONG_PTR cert_len);
CK_RV do_get_raw_cert(X509 *cert, CK_BYTE_PTR out, CK_ULONG_PTR out_len);
CK_RV do_delete_cert(X509 **cert);
//CK_RV free_cert(X509 *cert);

CK_RV       do_store_pubk(X509 *cert, EVP_PKEY **key);
CK_KEY_TYPE do_get_key_type(EVP_PKEY *key);
CK_ULONG    do_get_rsa_modulus_length(EVP_PKEY *key);
CK_RV       do_get_public_exponent(EVP_PKEY *key, CK_BYTE_PTR data, CK_ULONG_PTR len);
CK_RV       do_get_public_key(EVP_PKEY *key, CK_BYTE_PTR data, CK_ULONG_PTR len);
CK_RV       do_get_modulus(EVP_PKEY *key, CK_BYTE_PTR data, CK_ULONG_PTR len);
CK_RV       do_get_curve_parameters(EVP_PKEY *key, CK_BYTE_PTR data, CK_ULONG_PTR len);
CK_RV       do_delete_pubk(EVP_PKEY **key);
//CK_RV       free_key(EVP_PKEY *key);

CK_RV do_encode_rsa_public_key(ykcs11_rsa_key_t **key, CK_BYTE_PTR modulus, CK_ULONG mlen, CK_BYTE_PTR exponent, CK_ULONG elen);
CK_RV do_free_rsa_public_key(ykcs11_rsa_key_t *key);

CK_RV do_pkcs_1_t1(CK_BYTE_PTR in, CK_ULONG in_len, CK_BYTE_PTR out, CK_ULONG_PTR out_len, CK_ULONG key_len);
CK_RV do_pkcs_1_digest_info(CK_BYTE_PTR in, CK_ULONG in_len, int nid, CK_BYTE_PTR out, CK_ULONG_PTR out_len);

CK_RV do_pkcs_pss(RSA *key, CK_BYTE_PTR in, CK_ULONG in_len, int nid,
                  CK_BYTE_PTR out, CK_ULONG_PTR out_len);

CK_RV do_md_init(hash_t hash, ykcs11_md_ctx_t **ctx);
CK_RV do_md_update(ykcs11_md_ctx_t *ctx, CK_BYTE_PTR in, CK_ULONG in_len);
CK_RV do_md_finalize(ykcs11_md_ctx_t *ctx, CK_BYTE_PTR out, CK_ULONG_PTR out_len, int *nid);
CK_RV do_md_cleanup(ykcs11_md_ctx_t *ctx);

#endif
