#include "vendors.h"
#include "yubico.h"

vendor_id_t get_vendor_id(char *vendor_name) {
  vendor_id_t vid;

  if (strncmp(vendor_name, "Yubico", 6) == 0)
    return YUBICO;

  return UNKNOWN;
}

vendor_t get_vendor(vendor_id_t vid) {
  vendor_t v;

  switch (vid) {
  case YUBICO:
    v.get_version = YUBICO_get_version;
    break;

  case UNKNOWN:
    v.get_version = NULL;

  }

  return v;

}
