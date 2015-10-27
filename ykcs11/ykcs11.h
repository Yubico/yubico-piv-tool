#ifndef YKCS11_H
#define YKCS11_H

#include "pkcs11t.h"
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
  CK_BBOOL rsa;     // RSA or EC key
  CK_BYTE  key_id;  // Key id
  CK_ULONG key_len; // Length in bits
} gen_info_t;

typedef struct {
  ykcs11_md_ctx_t   *md_ctx; // Digest context
  CK_BYTE_PTR       key;     // Raw public key (needed for PSS)
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
