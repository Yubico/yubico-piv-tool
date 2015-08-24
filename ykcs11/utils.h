#ifndef UTILS_H
#define UTILS_H

#include "ykcs11.h"

CK_BBOOL has_token(const ykcs11_slot_t *slot);
CK_RV parse_readers(const CK_BYTE_PTR readers, const CK_ULONG len,
                       ykcs11_slot_t *slots, CK_ULONG_PTR n_slots, CK_ULONG_PTR n_with_token);
CK_RV create_token(CK_BYTE_PTR p, ykcs11_slot_t *slot);
void  destroy_token(ykcs11_slot_t *slot);

CK_BBOOL is_valid_key_id(CK_BYTE id);

void strip_DER_encoding_from_ECSIG(CK_BYTE_PTR data, CK_ULONG_PTR len);

#endif
