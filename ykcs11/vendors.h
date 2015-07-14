#ifndef VENDORS_H
#define VENDORS_H

#include "pkcs11.h"

typedef enum {
  UNKNOWN = 0x00,
  YUBICO = 0x01
} vendor_id_t;

typedef CK_UTF8CHAR_PTR (*get_s_description_f)(void);
typedef CK_UTF8CHAR_PTR (*get_s_manufacturer_f)(void);
typedef CK_FLAGS        (*get_s_flags_f)(void);
typedef CK_VERSION      (*get_s_version_f)(CK_UTF8CHAR_PTR, CK_ULONG);
typedef CK_UTF8CHAR_PTR (*get_t_label_f)(void);
typedef CK_UTF8CHAR_PTR (*get_t_manufacturer_f)(void);
typedef CK_UTF8CHAR_PTR (*get_t_model_f)(void);
typedef CK_FLAGS        (*get_t_flags_f)(void);
typedef CK_VERSION      (*get_t_version_f)(CK_UTF8CHAR_PTR, CK_ULONG);
typedef CK_CHAR_PTR     (*get_t_serial_f)(void);


typedef struct {
  get_s_description_f  get_slot_description;
  get_s_manufacturer_f get_slot_manufacturer;
  get_s_flags_f        get_slot_flags;
  get_s_version_f      get_slot_version;
  get_t_label_f        get_token_label;
  get_t_manufacturer_f get_token_manufacturer;
  get_t_model_f        get_token_model;
  get_t_flags_f        get_token_flags;
  get_t_version_f      get_token_version;
  get_t_serial_f       get_token_serial;
} vendor_t;

vendor_id_t get_vendor_id(char *vendor_name);
vendor_t get_vendor(vendor_id_t vid);

#endif
