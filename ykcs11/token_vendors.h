#ifndef TOKEN_VENDORS_H
#define TOKEN_VENDORS_H

#include "pkcs11.h"
#include "vendor_ids.h"
#include "obj_types.h"
#include <ykpiv.h>

typedef CK_RV (*get_t_label_f)(CK_UTF8CHAR_PTR, CK_ULONG);
typedef CK_RV (*get_t_manufacturer_f)(CK_UTF8CHAR_PTR, CK_ULONG);
typedef CK_RV (*get_t_model_f)(ykpiv_state *, CK_UTF8CHAR_PTR, CK_ULONG);
typedef CK_RV (*get_t_flags_f)(CK_FLAGS_PTR);
typedef CK_RV (*get_t_version_f)(CK_UTF8CHAR_PTR, CK_ULONG, CK_VERSION_PTR);
typedef CK_RV (*get_t_serial_f)(CK_CHAR_PTR, CK_ULONG);
typedef CK_RV (*get_t_mechanisms_num_f)(CK_ULONG_PTR);
typedef CK_RV (*get_t_mechanism_list_f)(CK_MECHANISM_TYPE_PTR, CK_ULONG);
typedef CK_RV (*get_t_mechanism_info_f)(CK_MECHANISM_TYPE, CK_MECHANISM_INFO_PTR);
typedef CK_RV (*get_t_objects_num_f)(ykpiv_state *, CK_ULONG_PTR, CK_ULONG_PTR);
typedef CK_RV (*get_t_object_list_f)(ykpiv_state *, piv_obj_id_t *, CK_ULONG);
typedef CK_RV (*get_t_raw_certificate_f)(ykpiv_state *, piv_obj_id_t, CK_BYTE_PTR, CK_ULONG_PTR);

// Common token functions below
typedef CK_RV (*t_login_f)(ykpiv_state *, CK_USER_TYPE, CK_UTF8CHAR_PTR, CK_ULONG);
typedef CK_RV (*t_generate_key_f)(ykpiv_state *, CK_BBOOL, CK_BYTE, CK_ULONG);
typedef CK_RV (*t_import_cert_f)(ykpiv_state *, CK_ULONG, CK_BYTE_PTR);
typedef CK_RV (*t_import_private_key_f)(ykpiv_state *, CK_BYTE, CK_BYTE_PTR, CK_BYTE_PTR, CK_BYTE_PTR,
                                        CK_BYTE_PTR, CK_BYTE_PTR, CK_BYTE_PTR, CK_ULONG);

// TODO: replace all the common calls with functions defined in .c that use libykpiv

typedef struct {
  get_t_label_f           get_token_label;
  get_t_manufacturer_f    get_token_manufacturer;
  get_t_model_f           get_token_model;
  get_t_flags_f           get_token_flags;
  get_t_version_f         get_token_version;
  get_t_serial_f          get_token_serial;
  get_t_mechanisms_num_f  get_token_mechanisms_num;
  get_t_mechanism_list_f  get_token_mechanism_list;
  get_t_mechanism_info_f  get_token_mechanism_info;
  get_t_objects_num_f     get_token_objects_num;
  get_t_object_list_f     get_token_object_list;
  get_t_raw_certificate_f get_token_raw_certificate;
  t_login_f               token_login;
  t_generate_key_f        token_generate_key;
  t_import_cert_f         token_import_cert;
  t_import_private_key_f  token_import_private_key;
} token_vendor_t;

token_vendor_t get_token_vendor(vendor_id_t vid);

#endif
