#ifndef MECHANISMS_H
#define MECHANISMS_H

#include "ykcs11.h"


CK_RV check_sign_mechanism(const ykcs11_session_t *s, CK_MECHANISM_PTR m);
CK_BBOOL is_RSA_mechanism(CK_MECHANISM_TYPE m);

CK_RV apply_sign_mechanism(CK_MECHANISM_PTR m, CK_BYTE_PTR in, CK_ULONG in_len,
                           CK_BYTE_PTR out, CK_ULONG out_len, CK_ULONG key_len);

#endif
