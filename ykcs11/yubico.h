#ifndef YUBICO_H
#define YUBICO_H

#include "pkcs11.h"

CK_VERSION      YUBICO_get_version(CK_UTF8CHAR_PTR version, CK_ULONG len);
CK_UTF8CHAR_PTR YUBICO_get_label(void);
CK_UTF8CHAR_PTR YUBICO_get_manufacturer(void);
CK_UTF8CHAR_PTR YUBICO_get_model(void);
CK_FLAGS        YUBICO_get_flags(void);

#endif
