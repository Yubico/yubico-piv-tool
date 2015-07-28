#include "vendors.h"
#include <string.h>

vendor_id_t get_vendor_id(char *vendor_name) {
  vendor_id_t vid;

  if (strstr(vendor_name, "Yubico") != NULL)
    return YUBICO;

  return UNKNOWN;
}
