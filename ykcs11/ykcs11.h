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

#define YKCS11_OP_BUFSIZE  4096

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
  YKCS11_DECRYPT
} ykcs11_op_type_t;

typedef struct {
  CK_BBOOL rsa;            // RSA or EC key
  CK_BYTE  key_id;         // Key id
  CK_ULONG key_len;        // Length in bits
  CK_ULONG vendor_defined; // Additional parameters (touch and PIN policy)
} gen_info_t;

typedef struct {
  ykcs11_md_ctx_t   *md_ctx; // Digest context
  ykcs11_rsa_key_t  *key;    // Raw public key (needed for PSS)
  CK_BYTE           algo;    // Algo for ykpiv // TODO: infer this from the key length?
  CK_BYTE           key_id;  // Key id for ykpiv // TODO: make this a BYTE and store the key_id {0, 1, 2, 3}
  CK_ULONG          key_len; // Length in bits
  CK_ULONG          sig_len; // Length of the signature in bytes
} sign_info_t;

typedef struct {
  ykcs11_md_ctx_t   *md_ctx;          // running hash
  const ykcs11_md_t *md;              // digest used
  CK_ULONG          padding;          // padding in the rsa case
  CK_BYTE           key_id;           // Key id
  CK_ULONG          key_len;          // Length in bits
} verify_info_t;

typedef struct {
  ykcs11_md_ctx_t   *md_ctx; // Digest context
  CK_ULONG          hash_len; // Length in bits
} hash_info_t;

typedef struct {
  CK_BYTE  key_id;
  CK_ULONG key_len; // Length in bits
  CK_BYTE  algo;    // Algo for ykpiv // TODO: infer this from the key length?
} decrypt_info_t;

typedef union {
  sign_info_t    sign;
  verify_info_t  verify;
  hash_info_t    hash;
  decrypt_info_t decrypt;
} op_t;

typedef struct {
  ykcs11_op_type_t type;
  CK_MECHANISM     mechanism;
  op_t             op;
  CK_BYTE          buf[YKCS11_OP_BUFSIZE];
  CK_ULONG         buf_len;
} op_info_t;

typedef struct {
  CK_BBOOL        active;     
  CK_ULONG        idx;
  piv_obj_id_t    objects[30 * 4];
  CK_ULONG        n_objects;
} ykcs11_find_t;

typedef struct {
  CK_ULONG        len;
  CK_BYTE_PTR     data;
} ykcs11_data_t;

typedef struct {
  CK_SESSION_INFO info;        // slotid, state, flags, deviceerror
  ykcs11_slot_t   *slot;       // slot for open session, or NULL 
  piv_obj_id_t    objects[30 * 4]; // List of objects in the token
  CK_ULONG        n_objects;   // TOTAL number of objects in the token
  ykcs11_data_t   data[38];    // Raw data, stored by sub_id 1-37
  ykcs11_x509_t   *certs[26];  // Certificates, stored by sub_id 1-25
  ykcs11_x509_t   *atst[26];   // Attestations, stored by sub_id 1-25
  ykcs11_evp_pkey_t *pkeys[26];  // Public keys, stored by sub_id 1-25
  ykcs11_find_t   find_obj;    // Active find operation (if any)
  op_info_t       op_info;
} ykcs11_session_t;

#endif
