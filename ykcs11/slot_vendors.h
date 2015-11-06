#ifndef SLOT_VENDORS_H
#define SLOT_VENDORS_H

#include "pkcs11.h"
#include "vendor_ids.h"

typedef CK_RV (*get_s_manufacturer_f)(CK_UTF8CHAR_PTR, CK_ULONG);
typedef CK_RV (*get_s_flags_f)(CK_FLAGS_PTR);
typedef CK_RV (*get_s_version_f)(CK_VERSION_PTR);


typedef struct {
  get_s_manufacturer_f   get_slot_manufacturer;
  get_s_flags_f          get_slot_flags;
  get_s_version_f        get_slot_version;
} slot_vendor_t;

slot_vendor_t get_slot_vendor(vendor_id_t vid);

#endif
