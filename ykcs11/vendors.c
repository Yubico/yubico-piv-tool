#include "vendors.h"
#include "yubico.h"
#include <string.h>

vendor_id_t get_vendor_id(char *vendor_name) {
  vendor_id_t vid;

  if (strstr(vendor_name, "Yubico") != NULL)
    return YUBICO;

  return UNKNOWN;
}

vendor_t get_vendor(vendor_id_t vid) {
  vendor_t v;

  switch (vid) {
  case YUBICO:
    v.get_slot_description     = YUBICO_get_slot_description;
    v.get_slot_manufacturer    = YUBICO_get_slot_manufacturer;
    v.get_slot_flags           = YUBICO_get_slot_flags;
    v.get_slot_version         = YUBICO_get_slot_version;
    v.get_token_label          = YUBICO_get_token_label;
    v.get_token_manufacturer   = YUBICO_get_token_manufacturer;
    v.get_token_model          = YUBICO_get_token_model;
    v.get_token_flags          = YUBICO_get_token_flags;
    v.get_token_version        = YUBICO_get_token_version;
    v.get_token_serial         = YUBICO_get_token_serial;
    v.get_token_mechanisms_num = YUBICO_get_token_mechanisms_num;
    v.get_token_mechanism_list = YUBICO_get_token_mechanism_list;
    v.get_token_mechanism_info = YUBICO_get_token_mechanism_info;
    break;

  case UNKNOWN:
  default:
    v.get_slot_description     = NULL;
    v.get_slot_manufacturer    = NULL;
    v.get_slot_flags           = NULL;
    v.get_slot_version         = NULL;
    v.get_token_label          = NULL;
    v.get_token_manufacturer   = NULL;
    v.get_token_model          = NULL;
    v.get_token_flags          = NULL;
    v.get_token_version        = NULL;
    v.get_token_serial         = NULL;
    v.get_token_mechanisms_num = NULL;
    v.get_token_mechanism_list = NULL;
    v.get_token_mechanism_info = NULL;
  }

  return v;

}
