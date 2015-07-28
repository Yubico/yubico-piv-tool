#ifndef YUBICO_SLOT_H
#define YUBICO_SLOT_H

#include "pkcs11.h"

CK_RV YUBICO_get_slot_description(CK_UTF8CHAR_PTR str, CK_ULONG len);
CK_RV YUBICO_get_slot_manufacturer(CK_UTF8CHAR_PTR str, CK_ULONG len);
CK_RV YUBICO_get_slot_flags(CK_FLAGS_PTR flags);
CK_RV YUBICO_get_slot_version(CK_VERSION_PTR version);

#endif
