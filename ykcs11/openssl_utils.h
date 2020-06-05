/*
 * Copyright (c) 2015-2017,2019-2020 Yubico AB
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

#include "openssl_types.h"
#include "pkcs11y.h"

CK_RV do_rand_seed(CK_BYTE_PTR data, CK_ULONG len);
CK_RV do_rand_bytes(CK_BYTE_PTR data, CK_ULONG len);
CK_RV do_rsa_encrypt(ykcs11_pkey_t *key, int padding, const ykcs11_md_t* oaep_md, const ykcs11_md_t* oaep_mgf1, 
                     unsigned char *oaep_label, CK_ULONG oaep_label_len,
                     CK_BYTE_PTR data, CK_ULONG data_len, CK_BYTE_PTR enc, CK_ULONG_PTR enc_len);
CK_RV do_store_cert(CK_BYTE_PTR data, CK_ULONG len, ykcs11_x509_t **cert);
CK_RV do_generate_ec_key(int curve_name, ykcs11_pkey_t **pkey);
CK_RV do_create_ec_key(CK_BYTE_PTR point, CK_ULONG point_len, int curve_name, ykcs11_pkey_t **pkey);
CK_RV do_create_rsa_key(CK_BYTE_PTR mod, CK_ULONG mod_len, CK_BYTE_PTR exp, CK_ULONG exp_len, ykcs11_pkey_t **pkey);
CK_RV do_create_public_key(CK_BYTE_PTR in, CK_ULONG in_len, CK_ULONG algorithm, ykcs11_pkey_t **pkey);
CK_RV do_sign_empty_cert(const char *cn, ykcs11_pkey_t *pubkey, ykcs11_pkey_t *pvtkey, ykcs11_x509_t **cert);
CK_RV do_create_empty_cert(CK_BYTE_PTR in, CK_ULONG in_len, CK_ULONG algorithm,
                           const char *cn, CK_BYTE_PTR out, CK_ULONG_PTR out_len);
CK_RV do_check_cert(CK_BYTE_PTR in, CK_ULONG in_len, CK_ULONG_PTR cert_len);
CK_RV do_get_raw_cert(ykcs11_x509_t *cert, CK_BYTE_PTR out, CK_ULONG_PTR out_len);
CK_RV do_get_raw_name(ykcs11_x509_name_t *name, CK_BYTE_PTR out, CK_ULONG_PTR out_len);
CK_RV do_get_raw_integer(ykcs11_asn1_integer_t *serial, CK_BYTE_PTR out, CK_ULONG_PTR out_len);
CK_RV do_delete_cert(ykcs11_x509_t **cert);

CK_RV       do_store_pubk(ykcs11_x509_t *cert, ykcs11_pkey_t **key);
CK_KEY_TYPE do_get_key_type(ykcs11_pkey_t *key);
CK_ULONG    do_get_key_size(ykcs11_pkey_t *key);
CK_ULONG    do_get_signature_size(ykcs11_pkey_t *key);
CK_BYTE     do_get_key_algorithm(ykcs11_pkey_t *key);
CK_RV       do_get_public_exponent(ykcs11_pkey_t *key, CK_BYTE_PTR data, CK_ULONG_PTR len);
CK_RV       do_get_public_key(ykcs11_pkey_t *key, CK_BYTE_PTR data, CK_ULONG_PTR len);
CK_RV       do_get_modulus(ykcs11_pkey_t *key, CK_BYTE_PTR data, CK_ULONG_PTR len);
CK_RV       do_get_curve_parameters(ykcs11_pkey_t *key, CK_BYTE_PTR data, CK_ULONG_PTR len);
CK_RV       do_delete_pubk(ykcs11_pkey_t **key);

CK_RV do_apply_DER_encoding_to_ECSIG(CK_BYTE_PTR signature, CK_ULONG_PTR len, CK_ULONG buf_size);
CK_RV do_strip_DER_encoding_from_ECSIG(CK_BYTE_PTR data, CK_ULONG len, CK_ULONG sig_len);

#endif
