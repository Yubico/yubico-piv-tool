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
#include "mechanisms.h"
#include "debug.h"
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>

CK_BBOOL is_yubico_reader(const char* reader_name) {
  return !strncmp(reader_name, "Yubico", 6);
}

size_t memstrcpy(void *dst, const char *src) {
  size_t len = strlen(src);
  memcpy(dst, src, len);
  return len;
}

size_t lastnon(unsigned const char *src, size_t len, unsigned char c) {
  size_t last = len;
  for(size_t pos = 0; pos < len; pos++)
    if(src[pos] != c)
      last = pos;
  return last;
}

typedef struct {
#ifdef __WIN32
  CRITICAL_SECTION mutex;
#else
  pthread_mutex_t mutex;
  pid_t pid;
#endif
} native_mutex_t;

CK_RV noop_create_mutex(void **mutex) {
  native_mutex_t *mtx = calloc(1, sizeof(native_mutex_t));
  if (mtx == NULL) {
    return CKR_HOST_MEMORY;
  }
#ifndef __WIN32
  mtx->pid = getpid();
#endif
  *mutex = mtx;
  return CKR_OK;
}

CK_RV noop_destroy_mutex(void *mutex) {
  free(mutex);
  return CKR_OK;
}

CK_RV noop_mutex_fn(void *mutex) {
  return CKR_OK;
}

CK_RV native_create_mutex(void **mutex) {
  native_mutex_t *mtx = calloc(1, sizeof(native_mutex_t));
  if (mtx == NULL) {
    return CKR_HOST_MEMORY;
  }
#ifdef __WIN32
  InitializeCriticalSection(&mtx->mutex);
#else
  pthread_mutexattr_t mattr;
  if(pthread_mutexattr_init(&mattr))
    return CKR_CANT_LOCK;
  if(pthread_mutexattr_settype(&mattr, PTHREAD_MUTEX_ERRORCHECK))
    return CKR_CANT_LOCK;
  if(pthread_mutexattr_setpshared(&mattr, PTHREAD_PROCESS_SHARED))
    return CKR_CANT_LOCK;
  if(pthread_mutex_init(&mtx->mutex, &mattr))
    return CKR_CANT_LOCK;
  if(pthread_mutexattr_destroy(&mattr))
    return CKR_CANT_LOCK;
  mtx->pid = getpid();
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
    return CKR_CANT_LOCK;
  }
#endif

  return CKR_OK;
}

CK_RV native_unlock_mutex(void *mutex) {

#ifdef __WIN32
  LeaveCriticalSection(mutex);
#else
  if (pthread_mutex_unlock(mutex) != 0) {
    return CKR_CANT_LOCK;
  }
#endif

  return CKR_OK;
}

CK_RV check_mutex(void *mutex) {
  if(mutex == NULL)
    return CKR_OK;
#ifndef __WIN32
  native_mutex_t *mtx = (native_mutex_t*)mutex;
  if(mtx->pid == getppid()) // Inherited mutex from parent, ignore
    return CKR_OK;
#endif
  return CKR_CRYPTOKI_ALREADY_INITIALIZED;
}
