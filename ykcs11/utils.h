#ifndef UTILS_H
#define UTILS_H

#include "pkcs11.h"
#include "vendors.h"

typedef struct {
  vendor_id_t  vid;
  CK_SLOT_INFO info;
} ykcs11_slot_t; // TODO: move this

CK_BBOOL has_token(const ykcs11_slot_t *slot);
CK_BBOOL parse_readers(const CK_BYTE_PTR readers, const CK_ULONG len,
                       ykcs11_slot_t *slots, CK_ULONG_PTR n_slots, CK_ULONG_PTR n_with_token);

#endif
