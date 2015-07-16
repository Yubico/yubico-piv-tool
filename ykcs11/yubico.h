#ifndef YUBICO_H
#define YUBICO_H

#include "pkcs11.h"

CK_RV YUBICO_get_slot_description(CK_UTF8CHAR_PTR str, CK_ULONG len);
CK_RV YUBICO_get_slot_manufacturer(CK_UTF8CHAR_PTR str, CK_ULONG len);
CK_RV YUBICO_get_slot_flags(CK_FLAGS_PTR flags);
CK_RV YUBICO_get_slot_version(CK_VERSION_PTR version);
CK_RV YUBICO_get_token_label(CK_UTF8CHAR_PTR str, CK_ULONG len);
CK_RV YUBICO_get_token_manufacturer(CK_UTF8CHAR_PTR str, CK_ULONG len);
CK_RV YUBICO_get_token_model(CK_UTF8CHAR_PTR str, CK_ULONG len);
CK_RV YUBICO_get_token_flags(CK_FLAGS_PTR flags);
CK_RV YUBICO_get_token_serial(CK_CHAR_PTR str, CK_ULONG len);
CK_RV YUBICO_get_token_version(CK_UTF8CHAR_PTR v_str, CK_ULONG v_str_len, CK_VERSION_PTR version);
CK_RV YUBICO_get_token_mechanisms_num(CK_ULONG_PTR num);

#endif
