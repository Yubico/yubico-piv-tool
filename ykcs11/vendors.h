#ifndef VENDORS_H
#define VENDORS_H

#include "pkcs11.h"

typedef enum {
  UNKNOWN = 0x00,
  YUBICO = 0x01
} vendor_id_t;

typedef CK_VERSION (*get_version_f)(char *, int);

typedef struct {
  get_version_f get_version;
} vendor_t;

vendor_id_t get_vendor_id(char *vendor_name);
vendor_t get_vendor(vendor_id_t vid);

#endif
