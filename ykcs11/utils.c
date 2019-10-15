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
