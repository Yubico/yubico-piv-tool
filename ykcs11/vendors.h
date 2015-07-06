#ifndef VENDORS_H
#define VENDORS_H

#include "pkcs11.h"

typedef enum {
  UNKNOWN = 0x00,
  YUBICO = 0x01
} vendor_id_t;

typedef CK_VERSION (*get_version_f)(CK_UTF8CHAR_PTR, CK_ULONG);
typedef CK_UTF8CHAR_PTR (*get_label_f)(void);
typedef CK_UTF8CHAR_PTR (*get_manufacturer_f)(void);
typedef CK_UTF8CHAR_PTR (*get_model_f)(void);
typedef CK_FLAGS (*get_flags_f)(void);

typedef struct {
  get_version_f      get_version;
  get_label_f        get_label;
  get_manufacturer_f get_manufacturer;
  get_model_f        get_model;
  get_flags_f        get_flags;
} vendor_t;

vendor_id_t get_vendor_id(char *vendor_name);
vendor_t get_vendor(vendor_id_t vid);

#endif
