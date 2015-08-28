#ifndef OBJECTS_H
#define OBJECTS_H

#include "ykcs11.h"

CK_ULONG piv_2_ykpiv(piv_obj_id_t id);

CK_RV    get_attribute(ykcs11_session_t *s, CK_OBJECT_HANDLE obj, CK_ATTRIBUTE_PTR template);
CK_BBOOL attribute_match(ykcs11_session_t *s, CK_OBJECT_HANDLE obj, CK_ATTRIBUTE_PTR attribute);
CK_BBOOL is_private_object(ykcs11_session_t *s, CK_OBJECT_HANDLE obj);

CK_RV    get_available_certificate_ids(ykcs11_session_t *s, piv_obj_id_t *cert_ids, CK_ULONG n_certs);
CK_RV    store_cert(piv_obj_id_t cert_id, CK_BYTE_PTR data, CK_ULONG len);

CK_RV check_create_cert(CK_ATTRIBUTE_PTR templ, CK_ULONG n, CK_BYTE_PTR id,
                        CK_BYTE_PTR *value, CK_ULONG_PTR cert_len);

#endif
