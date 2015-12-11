#ifndef YUBICO_TOKEN_H
#define YUBICO_TOKEN_H

#include "pkcs11.h"
#include "obj_types.h"
#include <ykpiv.h>

CK_RV YUBICO_get_token_label(CK_UTF8CHAR_PTR str, CK_ULONG len);
CK_RV YUBICO_get_token_manufacturer(CK_UTF8CHAR_PTR str, CK_ULONG len);
CK_RV YUBICO_get_token_model(ykpiv_state *state, CK_UTF8CHAR_PTR str, CK_ULONG len);
CK_RV YUBICO_get_token_flags(CK_FLAGS_PTR flags);
CK_RV YUBICO_get_token_serial(CK_CHAR_PTR str, CK_ULONG len);
CK_RV YUBICO_get_token_version(ykpiv_state *state, CK_VERSION_PTR version);
CK_RV YUBICO_get_token_mechanisms_num(CK_ULONG_PTR num);
CK_RV YUBICO_get_token_mechanism_list(CK_MECHANISM_TYPE_PTR mec, CK_ULONG num);
CK_RV YUBICO_get_token_mechanism_info(CK_MECHANISM_TYPE mec, CK_MECHANISM_INFO_PTR info);
CK_RV YUBICO_get_token_objects_num(ykpiv_state *state, CK_ULONG_PTR num, CK_ULONG_PTR num_certs);
CK_RV YUBICO_get_token_object_list(ykpiv_state *state, piv_obj_id_t *obj, CK_ULONG num);
CK_RV YUBICO_get_token_raw_certificate(ykpiv_state *state, piv_obj_id_t obj, CK_BYTE_PTR data, CK_ULONG_PTR len);
CK_RV YUBICO_token_change_pin(ykpiv_state *state, CK_USER_TYPE user_type, CK_UTF8CHAR_PTR pOldPin, CK_ULONG ulOldLen,
                              CK_UTF8CHAR_PTR pNewPin, CK_ULONG ulNewLen);

#endif
