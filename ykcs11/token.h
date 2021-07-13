/*
 * Copyright (c) 2015-2016,2019-2020 Yubico AB
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
#ifndef YUBICO_PIV_TOOL_TOKEN_H
#define YUBICO_PIV_TOOL_TOKEN_H

#include "pkcs11y.h"
#include "obj_types.h"
#include "ykpiv.h"

CK_RV get_token_model(ykpiv_state *state, CK_UTF8CHAR_PTR str, CK_ULONG len);
CK_RV get_token_serial(ykpiv_state *state, CK_CHAR_PTR str, CK_ULONG len);
CK_RV get_token_version(ykpiv_state *state, CK_VERSION_PTR version);
CK_RV get_token_label(ykpiv_state *state, CK_CHAR_PTR str, CK_ULONG len);

CK_RV get_token_mechanism_list(CK_MECHANISM_TYPE_PTR mec, CK_ULONG_PTR num);
CK_RV get_token_mechanism_info(CK_MECHANISM_TYPE mec, CK_MECHANISM_INFO_PTR info);

CK_RV get_token_object_ids(const piv_obj_id_t **obj, CK_ULONG *num);
CK_RV token_change_pin(ykpiv_state *state, CK_USER_TYPE user_type, CK_UTF8CHAR_PTR pOldPin, CK_ULONG ulOldLen,
                              CK_UTF8CHAR_PTR pNewPin, CK_ULONG ulNewLen);

CK_RV token_login(ykpiv_state *state, CK_USER_TYPE user, CK_UTF8CHAR_PTR pin, CK_ULONG pin_len);
CK_RV token_generate_key(ykpiv_state *state, CK_BYTE algorithm, CK_BYTE key, CK_BYTE_PTR cert_data, CK_ULONG_PTR cert_len);
CK_RV token_import_cert(ykpiv_state *state, CK_ULONG cert_id, CK_BYTE_PTR in, CK_ULONG in_len);
CK_RV token_delete_cert(ykpiv_state *state, CK_ULONG cert_id);

#endif //YUBICO_PIV_TOOL_TOKEN_H
