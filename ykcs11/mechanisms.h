/*
 * Copyright (c) 2015 Yubico AB
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

#ifndef MECHANISMS_H
#define MECHANISMS_H

#include "ykcs11.h"

CK_RV    check_sign_mechanism(const ykcs11_session_t *s, CK_MECHANISM_PTR m);
CK_BBOOL is_RSA_mechanism(CK_MECHANISM_TYPE m);
CK_BBOOL is_PSS_mechanism(CK_MECHANISM_TYPE m);
CK_BBOOL is_hashed_mechanism(CK_MECHANISM_TYPE m);

CK_RV apply_sign_mechanism_init(op_info_t *op_info);
CK_RV apply_sign_mechanism_update(op_info_t *op_info, CK_BYTE_PTR in, CK_ULONG in_len);
CK_RV apply_sign_mechanism_finalize(op_info_t *op_info);
CK_RV sign_mechanism_cleanup(op_info_t *op_info);

CK_RV check_generation_mechanism(const ykcs11_session_t *s, CK_MECHANISM_PTR m);
CK_RV check_pubkey_template(op_info_t *op_info, CK_ATTRIBUTE_PTR templ, CK_ULONG n); // TODO: Move to objects.c
CK_RV check_pvtkey_template(op_info_t *op_info, CK_ATTRIBUTE_PTR templ, CK_ULONG n); // TODO: Move to objects.c

CK_RV check_hash_mechanism(const ykcs11_session_t *s, CK_MECHANISM_PTR m);

#endif
