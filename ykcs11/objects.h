#ifndef OBJECTS_H
#define OBJECTS_H

#include "pkcs11t.h"
#include "obj_types.h"

#include <stdio.h> // TODO: delete

CK_RV get_attribute(CK_OBJECT_HANDLE obj, CK_ATTRIBUTE_PTR template);
//CK_RV get_object_class(CK_OBJECT_HANDLE obj, CK_OBJECT_CLASS_PTR class);

#endif
