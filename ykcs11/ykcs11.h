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

#ifndef YKCS11_H
#define YKCS11_H

#include "ykpiv.h"
#include "pkcs11y.h"
#include "obj_types.h"
#include "openssl_types.h"

typedef enum {
  YKCS11_PUBLIC,
  YKCS11_USER,
  YKCS11_SO
} ykcs11_login_state_t;

typedef struct {
  CK_SLOT_INFO  slot_info;
  CK_TOKEN_INFO token_info;
  ykpiv_state   *piv_state;
  ykcs11_login_state_t login_state;
  void* mutex;
} ykcs11_slot_t;

typedef enum {
  YKCS11_NOOP,
  YKCS11_SIGN,
  YKCS11_VERIFY,
  YKCS11_HASH,
  YKCS11_DECRYPT,
  YKCS11_ENCRYPT
} ykcs11_op_type_t;

typedef struct {
  CK_BBOOL rsa;            // RSA or EC key
  CK_BYTE  key_id;         // Key id
  CK_ULONG key_len;        // Length in bits
} gen_info_t;

typedef struct {
  CK_BYTE           key;     // PIV Key id
  CK_BYTE           algorithm; // PIV Key algorithm
  CK_ULONG          sig_len; // Signature length in bytes
  ykcs11_pkey_ctx_t *pkey_ctx; // Signature context
  ykcs11_md_ctx_t   *md_ctx; // Digest context (null for non-hashed signatures)
} sign_info_t;

typedef struct {
  CK_KEY_TYPE       key_type; // Key type
  ykcs11_pkey_ctx_t *pkey_ctx; // Signature context
  ykcs11_md_ctx_t   *md_ctx; // Digest context (null for non-hashed signatures)
} verify_info_t;

typedef struct {
  CK_BYTE  key_id;
} decrypt_info_t;

typedef struct {
  CK_BYTE  key_id;
  CK_ULONG padding; // padding in the rsa case
} encrypt_info_t;

typedef struct {
  CK_ULONG          length; // Length in bits
  ykcs11_md_ctx_t   *md_ctx;  // Digest context
} digest_info_t;

typedef union {
  sign_info_t    sign;
  verify_info_t  verify;
  decrypt_info_t decrypt;
  encrypt_info_t encrypt;
  digest_info_t  digest;
} op_t;

typedef struct {
  ykcs11_op_type_t type;
  CK_MECHANISM_TYPE mechanism;
  op_t             op;
  CK_BYTE          buf[4096];
  CK_ULONG         buf_len;
} op_info_t;

typedef struct {
  CK_BBOOL        active;     
  CK_ULONG        idx;
  CK_ULONG        n_objects;
  piv_obj_id_t    objects[PIV_OBJ_COUNT];
} ykcs11_find_t;

typedef struct {
  CK_ULONG        len;
  CK_BYTE_PTR     data;
} ykcs11_data_t;

typedef struct {
  CK_SESSION_INFO info;        // slotid, state, flags, deviceerror
  ykcs11_slot_t   *slot;       // slot for open session, or NULL 
  CK_ULONG        n_objects;   // TOTAL number of objects in the token
  piv_obj_id_t    objects[PIV_OBJ_COUNT]; // List of objects in the token
  ykcs11_data_t   data[38];    // Raw data, stored by sub_id 1-37
  ykcs11_x509_t   *certs[26];  // Certificates, stored by sub_id 1-25
  ykcs11_x509_t   *atst[26];   // Attestations, stored by sub_id 1-25
  ykcs11_pkey_t   *pkeys[26];  // Public keys, stored by sub_id 1-25
  ykcs11_find_t   find_obj;    // Active find operation (if any)
  op_info_t       op_info;
} ykcs11_session_t;

#endif
