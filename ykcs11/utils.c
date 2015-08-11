#include "utils.h"
#include <stdlib.h>
#include <string.h>

CK_BBOOL has_token(const ykcs11_slot_t *slot) {

  return (slot->info.flags & CKF_TOKEN_PRESENT);

}

CK_RV parse_readers(const CK_BYTE_PTR readers, const CK_ULONG len,
                       ykcs11_slot_t *slots, CK_ULONG_PTR n_slots, CK_ULONG_PTR n_with_token) {

  CK_BYTE        i;
  CK_BYTE_PTR    p;
  CK_BYTE_PTR    s;
  CK_ULONG       l;
  slot_vendor_t  slot;

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
        // Supported slot
        slot = get_slot_vendor(slots[*n_slots].vid);

        // Values must NOT be null terminated and ' ' padded

        memset(slots[*n_slots].info.slotDescription, ' ', sizeof(slots[*n_slots].info.slotDescription));
        s = slots[*n_slots].info.slotDescription;
        l = sizeof(slots[*n_slots].info.slotDescription);
        if (slot.get_slot_description(s, l) != CKR_OK)
          goto failure;

        memset(slots[*n_slots].info.manufacturerID, ' ', sizeof(slots[*n_slots].info.manufacturerID));
        s = slots[*n_slots].info.manufacturerID;
        l = sizeof(slots[*n_slots].info.manufacturerID);
        if(slot.get_slot_manufacturer(s, l) != CKR_OK)
          goto failure;

        if (slot.get_slot_flags(&slots[*n_slots].info.flags) != CKR_OK)
          goto failure;

        // Treating hw and fw version the same
        if (slot.get_slot_version(&slots[*n_slots].info.hardwareVersion) != CKR_OK)
          goto failure;

        if (slot.get_slot_version(&slots[*n_slots].info.firmwareVersion) != CKR_OK)
          goto failure;

        if (has_token(slots + *n_slots)) {
          // Save token information
          (*n_with_token)++;

          if (create_token(p, slots + *n_slots) != CKR_OK)
            goto failure;
        }
      }
      (*n_slots)++;
      p += i + 1;
    }

  return CKR_OK;

failure:
  // TODO: destroy all token objects
  for (i = 0; i < *n_slots; i++)
    if (has_token(slots + i))
      destroy_token(slots + i);
  
  return CKR_FUNCTION_FAILED;
}

CK_RV create_token(CK_BYTE_PTR p, ykcs11_slot_t *slot) {

  token_vendor_t token;
  CK_TOKEN_INFO_PTR t_info;

  slot->token = malloc(sizeof(ykcs11_token_t)); // TODO: free
  if (slot->token == NULL)
    return CKR_HOST_MEMORY;

  slot->token->vid = YUBICO; // TODO: this must become "slot_vendor.get_token_vid()"
  token = get_token_vendor(slot->token->vid);

  t_info = &slot->token->info;

  memset(t_info->label, ' ', sizeof(t_info->label));
  if (token.get_token_label(t_info->label, sizeof(t_info->label)) != CKR_OK)
    return CKR_FUNCTION_FAILED;

  memset(t_info->manufacturerID, ' ', sizeof(t_info->manufacturerID));
  if(token.get_token_manufacturer(t_info->manufacturerID, sizeof(t_info->manufacturerID)) != CKR_OK)
    return CKR_FUNCTION_FAILED;

  memset(t_info->model, ' ', sizeof(t_info->model));
  if(token.get_token_model(t_info->model, sizeof(t_info->model)) != CKR_OK)
    return CKR_FUNCTION_FAILED;

  memset(t_info->serialNumber, ' ', sizeof(t_info->serialNumber));
  if(token.get_token_serial(t_info->serialNumber, sizeof(t_info->serialNumber)) != CKR_OK)
    return CKR_FUNCTION_FAILED;

  if (token.get_token_flags(&t_info->flags) != CKR_OK)
    return CKR_FUNCTION_FAILED;

  t_info->ulMaxSessionCount = CK_UNAVAILABLE_INFORMATION;

  t_info->ulSessionCount = CK_UNAVAILABLE_INFORMATION;

  t_info->ulMaxRwSessionCount = CK_UNAVAILABLE_INFORMATION;

  t_info->ulRwSessionCount =  CK_UNAVAILABLE_INFORMATION;

  t_info->ulMaxPinLen = 8;

  t_info->ulMinPinLen = 6;

  t_info->ulTotalPublicMemory = CK_UNAVAILABLE_INFORMATION;

  t_info->ulFreePublicMemory = CK_UNAVAILABLE_INFORMATION;

  t_info->ulTotalPrivateMemory = CK_UNAVAILABLE_INFORMATION;

  t_info->ulFreePrivateMemory = CK_UNAVAILABLE_INFORMATION;

  //ykpiv_get_version(piv_state, buf, sizeof(buf));
  //if (token_vendor.get_token_version(buf, strlen(buf), &ver) != CKR_OK) // TODO: fix this
  //  return CKR_FUNCTION_FAILED;

  //t_info->hardwareVersion = ver; // version number of hardware // TODO: fix

  //t_info->firmwareVersion = ver; // version number of firmware // TODO: fix

  memset(t_info->utcTime, ' ', sizeof(t_info->utcTime)); // No clock present, clear

  // TODO: also get token objects here? (and destroy on failure)
  slot->token->objects = NULL;
  slot->token->n_objects = 0;
  
  return CKR_OK;
}

void destroy_token(ykcs11_slot_t *slot) {
  free(slot->token);
  slot->token = NULL;
}

CK_BBOOL is_valid_key_id(CK_BYTE id) {

  // Valid ids are 0, 1, 2, 3
  if (id > 3)
    return CK_FALSE;

  return CK_TRUE;
  
}
