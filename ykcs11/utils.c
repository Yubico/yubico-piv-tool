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
#include "slot.h"
#include "token.h"
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

CK_BBOOL is_yubico_reader(char* reader_name) {
  return !strncmp(reader_name, "Yubico", 6);
}

void* memstrcpy(unsigned char *dst, char *src) {
  return memcpy(dst, src, strlen(src));
}

CK_RV parse_readers(ykpiv_state *state, char* readers, const CK_ULONG len,
                       ykcs11_slot_t *slots, CK_ULONG_PTR n_slots, CK_ULONG_PTR n_with_token) {

  CK_BYTE        i;
  CK_BYTE_PTR    s;
  CK_ULONG       l;

  *n_slots = 0;
  *n_with_token = 0;
  char *p;

  /*
   * According to pcsc-lite, the format of a reader name is:
   * name [interface] (serial) index slot
   * https://ludovicrousseau.blogspot.se/2010/05/what-is-in-pcsc-reader-name.html
   */

  for (p = readers; *p; p += strlen(p) + 1) {

    if(is_yubico_reader(p)) {
      // Values must NOT be null terminated and ' ' padded

      ykcs11_slot_t *slot = slots + *n_slots;

      ykpiv_init(&slot->state, YKCS11_DBG);

      memset(slot->info.slotDescription, ' ', sizeof(slot->info.slotDescription));
      memstrcpy(slot->info.slotDescription, p);

      memset(slot->info.manufacturerID, ' ', sizeof(slot->info.manufacturerID));
      memcpy(slot->info.manufacturerID, p, 6);

      slot->info.flags = CKF_TOKEN_PRESENT | CKF_HW_SLOT;

      // Treating hw and fw version the same
      if (get_slot_version(&slot->info.hardwareVersion) != CKR_OK)
        goto failure;

      if (get_slot_version(&slot->info.firmwareVersion) != CKR_OK)
        goto failure;

      // Save token information
      (*n_with_token)++;

      if (create_token(p, slot) != CKR_OK)
        goto failure;
    }

    (*n_slots)++;
  }

  return CKR_OK;

failure:
  // TODO: destroy all token objects
  for (i = 0; i < *n_slots; i++)
    destroy_token(slots + i);

  return CKR_FUNCTION_FAILED;
}

CK_RV create_token(char *p, ykcs11_slot_t *slot) {

  CK_TOKEN_INFO_PTR t_info;

  slot->token = malloc(sizeof(ykcs11_token_t)); // TODO: free
  if (slot->token == NULL)
    return CKR_HOST_MEMORY;

  t_info = &slot->token->info;

  memset(t_info->label, ' ', sizeof(t_info->label));
  if (get_token_label(t_info->label, sizeof(t_info->label)) != CKR_OK)
    return CKR_FUNCTION_FAILED;

  memset(t_info->manufacturerID, ' ', sizeof(t_info->manufacturerID));
  if(get_token_manufacturer(t_info->manufacturerID, sizeof(t_info->manufacturerID)) != CKR_OK)
    return CKR_FUNCTION_FAILED;

  if (ykpiv_connect(slot->state, (char *)p) != YKPIV_OK)
    return CKR_FUNCTION_FAILED;

  memset(t_info->model, ' ', sizeof(t_info->model));
  if(get_token_model(slot->state, t_info->model, sizeof(t_info->model)) != CKR_OK) {
    ykpiv_disconnect(slot->state);
    return CKR_FUNCTION_FAILED;
  }

  memset(t_info->serialNumber, ' ', sizeof(t_info->serialNumber));
  if(get_token_serial(slot->state, t_info->serialNumber, sizeof(t_info->serialNumber)) != CKR_OK) {
    ykpiv_disconnect(slot->state);
    return CKR_FUNCTION_FAILED;
  }

  if (get_token_flags(&t_info->flags) != CKR_OK) {
    ykpiv_disconnect(slot->state);
    return CKR_FUNCTION_FAILED;
  }

  t_info->ulMaxSessionCount = 1;

  t_info->ulSessionCount = CK_UNAVAILABLE_INFORMATION;

  t_info->ulMaxRwSessionCount = 1;

  t_info->ulRwSessionCount =  CK_UNAVAILABLE_INFORMATION;

  t_info->ulMaxPinLen = 8;

  t_info->ulMinPinLen = 6;

  t_info->ulTotalPublicMemory = CK_UNAVAILABLE_INFORMATION;

  t_info->ulFreePublicMemory = CK_UNAVAILABLE_INFORMATION;

  t_info->ulTotalPrivateMemory = CK_UNAVAILABLE_INFORMATION;

  t_info->ulFreePrivateMemory = CK_UNAVAILABLE_INFORMATION;

  memset(&t_info->hardwareVersion, 0, sizeof(t_info->hardwareVersion));
  // Ignore hardware version, report firmware version
  if (get_token_version(slot->state, &t_info->firmwareVersion) != CKR_OK) {
    ykpiv_disconnect(slot->state);
    return CKR_FUNCTION_FAILED;
  }

  memset(t_info->utcTime, ' ', sizeof(t_info->utcTime)); // No clock present, clear

  slot->token->objects = NULL;
  slot->token->n_objects = 0;

  ykpiv_disconnect(slot->state);

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

CK_RV noop_create_mutex(void **mutex) {
  *mutex = (void*)0xf00f;
  return CKR_OK;
}

CK_RV noop_mutex_fn(void *mutex) {
  return CKR_OK;
}

CK_RV native_create_mutex(void **mutex) {

#ifdef __WIN32
  CRITICAL_SECTION *mtx = calloc(1, sizeof(CRITICAL_SECTION));
  if (mtx == NULL) {
    return CKR_GENERAL_ERROR;
  }
  InitializeCriticalSection(mtx);
#else
  pthread_mutex_t *mtx = calloc(1, sizeof(pthread_mutex_t));
  if (mtx == NULL) {
    return CKR_GENERAL_ERROR;
  }

  pthread_mutex_init(mtx, NULL);
#endif

  *mutex = mtx;
  return CKR_OK;
}

CK_RV native_destroy_mutex(void *mutex) {

#ifdef __WIN32
  DeleteCriticalSection(mutex);
#else
  pthread_mutex_destroy(mutex);
#endif

  free(mutex);

  return CKR_OK;
}

CK_RV native_lock_mutex(void *mutex) {

#ifdef __WIN32
  EnterCriticalSection(mutex);
#else
  if (pthread_mutex_lock(mutex) != 0) {
    return CKR_GENERAL_ERROR;
  }
#endif

  return CKR_OK;
}

CK_RV native_unlock_mutex(void *mutex) {

#ifdef __WIN32
  LeaveCriticalSection(mutex);
#else
  if (pthread_mutex_unlock(mutex) != 0) {
    return CKR_GENERAL_ERROR;
  }
#endif

  return CKR_OK;
}
