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

#ifndef OBJECTS_H
#define OBJECTS_H

#include "ykcs11.h"

CK_ULONG piv_2_ykpiv(piv_obj_id_t obj);
CK_BYTE get_key_id(piv_obj_id_t obj);

piv_obj_id_t find_data_object(CK_BYTE key_id);
piv_obj_id_t find_cert_object(CK_BYTE key_id);
piv_obj_id_t find_pubk_object(CK_BYTE key_id);
piv_obj_id_t find_pvtk_object(CK_BYTE key_id);

CK_RV    get_attribute(ykcs11_session_t *s, CK_OBJECT_HANDLE obj, CK_ATTRIBUTE_PTR template);
CK_BBOOL attribute_match(ykcs11_session_t *s, CK_OBJECT_HANDLE obj, CK_ATTRIBUTE_PTR attribute);
CK_BBOOL is_private_object(ykcs11_session_t *s, CK_OBJECT_HANDLE obj);

CK_RV    store_data(ykcs11_session_t *s, piv_obj_id_t cert_id, CK_BYTE_PTR data, CK_ULONG len);
CK_RV    store_cert(ykcs11_session_t *s, piv_obj_id_t cert_id, CK_BYTE_PTR data, CK_ULONG len);
CK_RV    delete_cert(ykcs11_session_t *s, piv_obj_id_t cert_id);

CK_RV check_create_cert(CK_ATTRIBUTE_PTR templ, CK_ULONG n, CK_BYTE_PTR id,
                        CK_BYTE_PTR *value, CK_ULONG_PTR cert_len);
CK_RV check_create_ec_key(CK_ATTRIBUTE_PTR templ, CK_ULONG n, CK_BYTE_PTR id,
                          CK_BYTE_PTR *value, CK_ULONG_PTR value_len);
CK_RV check_create_rsa_key(CK_ATTRIBUTE_PTR templ, CK_ULONG n, CK_BYTE_PTR id,
                           CK_BYTE_PTR *p, CK_ULONG_PTR p_len,
                           CK_BYTE_PTR *q, CK_ULONG_PTR q_len,
                           CK_BYTE_PTR *dp, CK_ULONG_PTR dp_len,
                           CK_BYTE_PTR *dq, CK_ULONG_PTR dq_len,
                           CK_BYTE_PTR *qinv, CK_ULONG_PTR qinv_len);
CK_RV check_delete_cert(CK_OBJECT_HANDLE hObject, CK_BYTE_PTR id);

#endif
