#ifndef MECHANISMS_H
#define MECHANISMS_H

#include "ykcs11.h"


CK_RV check_sign_mechanism(const ykcs11_session_t *s, CK_MECHANISM_PTR m);
CK_BBOOL is_RSA_mechanism(CK_MECHANISM_TYPE m);

#endif
