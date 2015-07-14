#ifndef YUBICO_H
#define YUBICO_H

#include "pkcs11.h"

CK_UTF8CHAR_PTR YUBICO_get_slot_description(void);
CK_UTF8CHAR_PTR YUBICO_get_slot_manufacturer(void);
CK_FLAGS        YUBICO_get_slot_flags(void);
CK_VERSION      YUBICO_get_slot_version(CK_UTF8CHAR_PTR version, CK_ULONG len);
CK_UTF8CHAR_PTR YUBICO_get_token_label(void);
CK_UTF8CHAR_PTR YUBICO_get_token_manufacturer(void);
CK_UTF8CHAR_PTR YUBICO_get_token_model(void);
CK_FLAGS        YUBICO_get_token_flags(void);
CK_CHAR_PTR     YUBICO_get_token_serial(void);
CK_VERSION      YUBICO_get_token_version(CK_UTF8CHAR_PTR version, CK_ULONG len);

#endif
