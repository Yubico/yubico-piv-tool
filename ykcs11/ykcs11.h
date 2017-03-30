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

#include "pkcs11y.h"
#include "obj_types.h"
#include "openssl_types.h"
#include "vendors.h"

#define YKCS11_OP_BUFSIZE  4096

typedef struct {
  vendor_id_t   vid;
  CK_TOKEN_INFO info;
  piv_obj_id_t  *objects;  // List of objects in the token
  CK_ULONG      n_objects; // TOTAL number of objects in the token
  CK_ULONG      n_certs;   // Number of certificate objects in the token (portion of n_objects)
} ykcs11_token_t;

typedef struct {
  vendor_id_t    vid;
  CK_SLOT_INFO   info;
  ykcs11_token_t *token;
} ykcs11_slot_t;

typedef struct {
  CK_SESSION_HANDLE handle;
  CK_SESSION_INFO   info; /* slotid, state, flags, deviceerror */
  ykcs11_slot_t     *slot;
} ykcs11_session_t;

typedef enum {
  YKCS11_NOOP,
  YKCS11_GEN,
  YKCS11_SIGN,
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
  CK_ULONG          key_id;  // Key id for ykpiv // TODO: make this a BYTE and store the id {0, 1, 2, 3}
  CK_ULONG          key_len; // Length in bits
} sign_info_t;

typedef struct {
  CK_BYTE todo;
} hash_info_t;

typedef struct {
  CK_BYTE todo;
} decrypt_info_t;

typedef union {
  gen_info_t     gen;
  sign_info_t    sign;
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

#endif
