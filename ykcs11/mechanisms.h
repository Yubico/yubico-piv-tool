#ifndef MECHANISMS_H
#define MECHANISMS_H

#include "ykcs11.h"

CK_RV    check_sign_mechanism(const ykcs11_session_t *s, CK_MECHANISM_PTR m);
CK_BBOOL is_RSA_mechanism(CK_MECHANISM_TYPE m);
CK_BBOOL is_PSS_mechanism(CK_MECHANISM_TYPE m);
CK_BBOOL is_hashed_mechanism(CK_MECHANISM_TYPE m);

CK_RV apply_sign_mechanism_init(op_info_t *op_info);
CK_RV apply_sign_mechanism_update(op_info_t *op_info, CK_BYTE_PTR in, CK_ULONG in_len);
CK_RV apply_sign_mechanism_finalize(op_info_t *op_info);

CK_RV check_generation_mechanism(const ykcs11_session_t *s, CK_MECHANISM_PTR m);
CK_RV check_pubkey_template(op_info_t *op_info, CK_ATTRIBUTE_PTR templ, CK_ULONG n);
CK_RV check_pvtkey_template(op_info_t *op_info, CK_ATTRIBUTE_PTR templ, CK_ULONG n);

CK_RV check_hash_mechanism(const ykcs11_session_t *s, CK_MECHANISM_PTR m);

#endif
