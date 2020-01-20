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

#ifndef MECHANISMS_H
#define MECHANISMS_H

#include "ykcs11.h"

CK_RV sign_mechanism_init(ykcs11_session_t *session, ykcs11_pkey_t *key, CK_MECHANISM_PTR mech);
CK_RV sign_mechanism_final(ykcs11_session_t *session, CK_BYTE_PTR sig, CK_ULONG_PTR sig_len);
CK_RV sign_mechanism_cleanup(ykcs11_session_t *session);

CK_RV verify_mechanism_init(ykcs11_session_t *session, ykcs11_pkey_t *key, CK_MECHANISM_PTR mech);
CK_RV verify_mechanism_final(ykcs11_session_t *session, CK_BYTE_PTR sig, CK_ULONG sig_len);
CK_RV verify_mechanism_cleanup(ykcs11_session_t *session);

CK_RV check_generation_mechanism(CK_MECHANISM_PTR m);
CK_RV check_pubkey_template(gen_info_t *gen_info, CK_MECHANISM_PTR mech, CK_ATTRIBUTE_PTR templ, CK_ULONG n); // TODO: Move to objects.c
CK_RV check_pvtkey_template(gen_info_t *gen_info, CK_MECHANISM_PTR mech, CK_ATTRIBUTE_PTR templ, CK_ULONG n); // TODO: Move to objects.c

CK_RV digest_mechanism_init(ykcs11_session_t *session);
CK_RV digest_mechanism_update(ykcs11_session_t *session, CK_BYTE_PTR in, CK_ULONG in_len);
CK_RV digest_mechanism_final(ykcs11_session_t *session, CK_BYTE_PTR pDigest, CK_ULONG_PTR pDigestLength);

CK_RV decrypt_mechanism_init(ykcs11_session_t *session, CK_MECHANISM_PTR mech);
CK_RV decrypt_mechanism_final(ykcs11_session_t *session, CK_BYTE_PTR dec, CK_ULONG_PTR dec_len, CK_ULONG key_len);

#endif
