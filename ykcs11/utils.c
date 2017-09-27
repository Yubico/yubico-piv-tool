/*
 * Copyright (c) 2015-2016 Yubico AB
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *
 *   * Redistributions in binary form must reproduce the above
 *     copyright notice, this list of conditions and the following
 *     disclaimer in the documentation and/or other materials provided
 *     with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include "utils.h"
#include <stdlib.h>
#include <string.h>

CK_BBOOL has_token(const ykcs11_slot_t *slot) {

  return (slot->info.flags & CKF_TOKEN_PRESENT);

}

CK_RV parse_readers(ykpiv_state *state, const CK_BYTE_PTR readers, const CK_ULONG len,
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
   * https://ludovicrousseau.blogspot.se/2010/05/what-is-in-pcsc-reader-name.html
   */

  for (i = 0; i < len; i++)
    if (readers[i] == '\0' && i != len - 1) {
      slots[*n_slots].vid = get_vendor_id((char *)p);

      if (slots[*n_slots].vid == UNKNOWN) { // TODO: distinguish between tokenless and unsupported?
        // Unknown slot, just save what info we have
        memset(&slots[*n_slots].info, 0, sizeof(CK_SLOT_INFO));
        memset(slots[*n_slots].info.slotDescription, ' ', sizeof(slots[*n_slots].info.slotDescription));
        if (strlen((char *)p) <= sizeof(slots[*n_slots].info.slotDescription))
          memcpy(slots[*n_slots].info.slotDescription, p, strlen((char *)p));
        else
          memcpy(slots[*n_slots].info.slotDescription, p, sizeof(slots[*n_slots].info.slotDescription));
      }
      else {
        // Supported slot
        slot = get_slot_vendor(slots[*n_slots].vid);

        // Values must NOT be null terminated and ' ' padded

        memset(slots[*n_slots].info.slotDescription, ' ', sizeof(slots[*n_slots].info.slotDescription));
        s = slots[*n_slots].info.slotDescription;
        l = sizeof(slots[*n_slots].info.slotDescription);
        memcpy((char *)s, (char*)p, l);

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

          if (create_token(state, p, slots + *n_slots) != CKR_OK)
            goto failure;
        }
      }
      (*n_slots)++;
      p = readers + i + 1;
    }

  return CKR_OK;

failure:
  // TODO: destroy all token objects
  for (i = 0; i < *n_slots; i++)
    if (has_token(slots + i))
      destroy_token(slots + i);

  return CKR_FUNCTION_FAILED;
}

CK_RV create_token(ykpiv_state *state, CK_BYTE_PTR p, ykcs11_slot_t *slot) {

  token_vendor_t    token;
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

  if (ykpiv_connect(state, (char *)p) != YKPIV_OK)
    return CKR_FUNCTION_FAILED;

  memset(t_info->model, ' ', sizeof(t_info->model));
  if(token.get_token_model(state, t_info->model, sizeof(t_info->model)) != CKR_OK) {
    ykpiv_disconnect(state);
    return CKR_FUNCTION_FAILED;
  }

  memset(t_info->serialNumber, ' ', sizeof(t_info->serialNumber));
  if(token.get_token_serial(t_info->serialNumber, sizeof(t_info->serialNumber)) != CKR_OK) {
    ykpiv_disconnect(state);
    return CKR_FUNCTION_FAILED;
  }

  if (token.get_token_flags(&t_info->flags) != CKR_OK) {
    ykpiv_disconnect(state);
    return CKR_FUNCTION_FAILED;
  }

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

  memset(&t_info->hardwareVersion, 0, sizeof(t_info->hardwareVersion));
  // Ignore hardware version, report firmware version
  if (token.get_token_version(state, &t_info->firmwareVersion) != CKR_OK) {
    ykpiv_disconnect(state);
    return CKR_FUNCTION_FAILED;
  }

  memset(t_info->utcTime, ' ', sizeof(t_info->utcTime)); // No clock present, clear

  slot->token->objects = NULL;
  slot->token->n_objects = 0;

  ykpiv_disconnect(state);

  return CKR_OK;
}

void destroy_token(ykcs11_slot_t *slot) {
  free(slot->token);
  slot->token = NULL;
}

CK_BBOOL is_valid_key_id(CK_BYTE id) {

  // Valid ids are [0, 23] aka [0x00, 0x17]
  if (id > 23)
    return CK_FALSE;

  return CK_TRUE;
}

void strip_DER_encoding_from_ECSIG(CK_BYTE_PTR data, CK_ULONG_PTR len) {

  CK_BYTE_PTR  data_ptr;
  CK_ULONG     sig_halflen;
  CK_BYTE      buf[128];
  CK_BYTE_PTR  buf_ptr;
  CK_BYTE      elem_len;

  // Maximum DER length for P256 is 2 + 2 + 33 + 2 + 33 = 72
  if (*len <= 72)
    sig_halflen = 32;
  else
    sig_halflen = 48;

  memset(buf, 0, sizeof(buf));
  data_ptr = data + 3;
  buf_ptr = buf;

  // copy r
  elem_len = *data_ptr;
  if (elem_len == (sig_halflen - 1))
    buf_ptr++; // One shorter, prepend a zero
  else if (elem_len == (sig_halflen + 1)) {
    data_ptr++; // One longer, skip a zero
    elem_len--;
  }

  data_ptr++;
  memcpy(buf_ptr, data_ptr, elem_len);
  data_ptr += elem_len;
  buf_ptr += elem_len;

  data_ptr++;

  // copy s
  elem_len = *data_ptr;
  if (elem_len == (sig_halflen - 1))
    buf_ptr++; // One shorter, prepend a zero
  else if (elem_len == (sig_halflen + 1)) {
    data_ptr++; // One longer, skip a zero
    elem_len --;
  }

  data_ptr++;
  memcpy(buf_ptr, data_ptr, elem_len);

  *len = sig_halflen * 2;
  memcpy(data, buf, *len);

}
