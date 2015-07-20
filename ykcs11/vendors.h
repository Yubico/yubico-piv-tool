#ifndef VENDORS_H
#define VENDORS_H

#include "pkcs11.h"
#include "objects.h"

typedef enum {
  UNKNOWN = 0x00,
  YUBICO = 0x01
} vendor_id_t;

typedef CK_RV (*get_s_description_f)(CK_UTF8CHAR_PTR, CK_ULONG);
typedef CK_RV (*get_s_manufacturer_f)(CK_UTF8CHAR_PTR, CK_ULONG);
typedef CK_RV (*get_s_flags_f)(CK_FLAGS_PTR);
typedef CK_RV (*get_s_version_f)(CK_VERSION_PTR);
typedef CK_RV (*get_t_label_f)(CK_UTF8CHAR_PTR, CK_ULONG);
typedef CK_RV (*get_t_manufacturer_f)(CK_UTF8CHAR_PTR, CK_ULONG);
typedef CK_RV (*get_t_model_f)(CK_UTF8CHAR_PTR, CK_ULONG);
typedef CK_RV (*get_t_flags_f)(CK_FLAGS_PTR);
typedef CK_RV (*get_t_version_f)(CK_UTF8CHAR_PTR, CK_ULONG, CK_VERSION_PTR);
typedef CK_RV (*get_t_serial_f)(CK_CHAR_PTR, CK_ULONG);
typedef CK_RV (*get_t_mechanisms_num_f)(CK_ULONG_PTR);
typedef CK_RV (*get_t_mechanism_list_f)(CK_MECHANISM_TYPE_PTR, CK_ULONG);
typedef CK_RV (*get_t_mechanism_info_f)(CK_MECHANISM_TYPE, CK_MECHANISM_INFO_PTR);
typedef CK_RV (*get_t_objects_num_f)(CK_ULONG_PTR);
typedef CK_RV (*get_t_object_list_f)(piv_obj_id_t *, CK_ULONG);


typedef struct {
  get_s_description_f    get_slot_description;
  get_s_manufacturer_f   get_slot_manufacturer;
  get_s_flags_f          get_slot_flags;
  get_s_version_f        get_slot_version;
  get_t_label_f          get_token_label;
  get_t_manufacturer_f   get_token_manufacturer;
  get_t_model_f          get_token_model;
  get_t_flags_f          get_token_flags;
  get_t_version_f        get_token_version;
  get_t_serial_f         get_token_serial;
  get_t_mechanisms_num_f get_token_mechanisms_num;
  get_t_mechanism_list_f get_token_mechanism_list;
  get_t_mechanism_info_f get_token_mechanism_info;
  get_t_objects_num_f    get_token_objects_num;
  get_t_object_list_f    get_token_object_list;
} vendor_t;

vendor_id_t get_vendor_id(char *vendor_name);
vendor_t get_vendor(vendor_id_t vid);

#endif
