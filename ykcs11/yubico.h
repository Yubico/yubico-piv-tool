#ifndef YUBICO_H
#define YUBICO_H

#include "pkcs11.h"
#include "obj_types.h"

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
CK_RV YUBICO_get_token_mechanism_list(CK_MECHANISM_TYPE_PTR mec, CK_ULONG num);
CK_RV YUBICO_get_token_mechanism_info(CK_MECHANISM_TYPE mec, CK_MECHANISM_INFO_PTR info);
CK_RV YUBICO_get_token_objects_num(CK_ULONG_PTR num);
CK_RV YUBICO_get_token_object_list(piv_obj_id_t * obj, CK_ULONG num);

#endif
