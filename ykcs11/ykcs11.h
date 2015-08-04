#ifndef YKCS11_H
#define YKCS11_H

#include "pkcs11t.h"
#include "obj_types.h"
#include "openssl_types.h"
#include "vendors.h"

#define  YKCS11_OP_BUFSIZE  4096

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
  YKCS11_SIGN,
  YKCS11_HASH,
  YKCS11_DECRYPT
} ykcs11_op_type_t;

typedef struct {
  ykcs11_md_ctx_t *md_ctx;
  CK_BYTE         algo;
  CK_ULONG        key;
  CK_ULONG        key_len;
} sign_info_t;

typedef struct {
  CK_BYTE todo;
} hash_info_t;

typedef struct {
  CK_BYTE todo;
} decrypt_info_t;

typedef union {
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
