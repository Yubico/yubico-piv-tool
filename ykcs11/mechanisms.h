#ifndef MECHANISMS_H
#define MECHANISMS_H

#include "pkcs11t.h"


CK_RV check_sign_mechanism(const CK_MECHANISM_PTR m, const CK_OBJECT_HANDLE k);


#endif
