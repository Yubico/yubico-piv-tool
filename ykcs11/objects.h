#ifndef OBJECTS_H
#define OBJECTS_H

#include "ykcs11.h"

#include <stdio.h> // TODO: delete

CK_RV get_attribute(ykcs11_session_t *s, CK_OBJECT_HANDLE obj, CK_ATTRIBUTE_PTR template);

#endif
