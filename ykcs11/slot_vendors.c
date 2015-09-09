#include "slot_vendors.h"
#include "yubico_slot.h"
#include <stdlib.h>

slot_vendor_t get_slot_vendor(vendor_id_t vid) {
  slot_vendor_t v;

  switch (vid) {
  case YUBICO:
    v.get_slot_manufacturer    = YUBICO_get_slot_manufacturer;
    v.get_slot_flags           = YUBICO_get_slot_flags;
    v.get_slot_version         = YUBICO_get_slot_version;
    break;

  case UNKNOWN:
  default:
    v.get_slot_manufacturer    = NULL;
    v.get_slot_flags           = NULL;
    v.get_slot_version         = NULL;
  }

  return v;

}
