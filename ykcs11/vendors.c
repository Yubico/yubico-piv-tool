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
    v.get_version      = YUBICO_get_version;
    v.get_label        = YUBICO_get_label;
    v.get_manufacturer = YUBICO_get_manufacturer;
    v.get_model        = YUBICO_get_model;
    v.get_flags        = YUBICO_get_flags;
    break;

  case UNKNOWN:
    v.get_version      = NULL; // TODO: make up dummy functions?
    v.get_label        = NULL;
    v.get_manufacturer = NULL;
    v.get_model        = NULL;
    v.get_flags        = NULL;

  }

  return v;

}
