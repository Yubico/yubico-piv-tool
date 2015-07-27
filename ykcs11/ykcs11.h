#ifndef YKCS11_H
#define YKCS11_H

#include "pkcs11t.h"
#include "vendors.h"

typedef struct {
  vendor_id_t   vid;
  CK_TOKEN_INFO info;
  piv_obj_id_t  *objects;
  CK_ULONG      n_objects;
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

#endif
