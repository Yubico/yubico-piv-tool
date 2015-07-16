#include "utils.h"
#include <string.h>

CK_BBOOL has_token(const ykcs11_slot_t *slot) {

  return (slot->info.flags & CKF_TOKEN_PRESENT);

}

CK_BBOOL parse_readers(const CK_BYTE_PTR readers, const CK_ULONG len,
                       ykcs11_slot_t *slots, CK_ULONG_PTR n_slots, CK_ULONG_PTR n_with_token) {

  CK_BYTE     i;
  CK_BYTE_PTR p;
  CK_BYTE_PTR s;
  CK_ULONG    l;
  vendor_t    vendor;

  *n_slots = 0;
  *n_with_token = 0;
  p = readers;

  /*
   * According to pcsc-lite, the format of a reader name is:
   * name [interface] (serial) index slot
   * http://ludovicrousseau.blogspot.se/2010/05/what-is-in-pcsc-reader-name.html
   */

  for (i = 0; i < len; i++)
    if (readers[i] == '\0' && i != len - 1) {
      slots[*n_slots].vid = get_vendor_id(p);

      if (slots[*n_slots].vid == UNKNOWN) { // TODO: distinguish between tokenless and unsupported?
        // Unknown slot, just save what info we have
        memset(&slots[*n_slots].info, 0, sizeof(CK_SLOT_INFO));
        memset(slots[*n_slots].info.slotDescription, ' ', sizeof(slots[*n_slots].info.slotDescription));
        if (strlen(p) <= sizeof(slots[*n_slots].info.slotDescription))
          strncpy(slots[*n_slots].info.slotDescription, p, strlen(p));
        else
          strncpy(slots[*n_slots].info.slotDescription, p, sizeof(slots[*n_slots].info.slotDescription));
      }
      else {
        vendor = get_vendor(slots[*n_slots].vid);

        // Values must NOT be null terminated and ' ' padded

        memset(slots[*n_slots].info.slotDescription, ' ', sizeof(slots[*n_slots].info.slotDescription));
        s = slots[*n_slots].info.slotDescription;
        l = sizeof(slots[*n_slots].info.slotDescription);
        if (vendor.get_slot_description(s, l) != CKR_OK)
          return CK_FALSE;

        memset(slots[*n_slots].info.manufacturerID, ' ', sizeof(slots[*n_slots].info.manufacturerID));
        s = slots[*n_slots].info.manufacturerID;
        l = sizeof(slots[*n_slots].info.manufacturerID);
        if(vendor.get_slot_manufacturer(s, l) != CKR_OK)
          return CK_FALSE;

        if (vendor.get_slot_flags(&slots[*n_slots].info.flags) != CKR_OK)
          return CK_FALSE;

        // Treating hw and fw version the same
        if (vendor.get_slot_version(&slots[*n_slots].info.hardwareVersion) != CKR_OK)
          return CK_FALSE;

        if (vendor.get_slot_version(&slots[*n_slots].info.firmwareVersion) != CKR_OK)
          return CK_FALSE;

        if (has_token(slots + *n_slots))
          (*n_with_token)++;
      }
      (*n_slots)++;
      p += i + 1;
    }

  return CK_TRUE;
  
}
