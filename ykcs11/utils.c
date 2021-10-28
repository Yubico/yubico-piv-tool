/*
 * Copyright (c) 2015-2017,2019-2020 Yubico AB
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

#include "ykpiv-config.h"

#ifdef _WIN32
#include <windows.h>
#include <winsock.h>
#else
#include <unistd.h>
#include <pthread.h>
#endif

#include "utils.h"
#include "token.h"
#include "mechanisms.h"
#include "debug.h"
#include <stdlib.h>
#include <string.h>

size_t memstrcpy(unsigned char *dst, size_t size, const char *src) {
  size_t len = strnlen(src, size);
  memcpy(dst, src, len);
  memset(dst + len, ' ', size - len);
  return len;
}

CK_RV noop_create_mutex(void **mutex) {
  *mutex = (void*)0xbaadf00d;
  return CKR_OK;
}

CK_RV noop_destroy_mutex(void *mutex) {
  return CKR_OK;
}

CK_RV noop_mutex_fn(void *mutex) {
  return CKR_OK;
}

CK_RV native_create_mutex(void **mutex) {
#ifdef _WIN32
  CRITICAL_SECTION *mtx = calloc(1, sizeof(CRITICAL_SECTION));
  if (mtx == NULL) {
    return CKR_HOST_MEMORY;
  }
  InitializeCriticalSection(mtx);
#else
  pthread_mutex_t *mtx = calloc(1, sizeof(pthread_mutex_t));
  if (mtx == NULL) {
    return CKR_HOST_MEMORY;
  }
  pthread_mutexattr_t mattr;
  if(pthread_mutexattr_init(&mattr)) {
    free(mtx);
    return CKR_CANT_LOCK;
  }
  if(pthread_mutexattr_settype(&mattr, PTHREAD_MUTEX_ERRORCHECK)) {
    pthread_mutexattr_destroy(&mattr);
    free(mtx);
    return CKR_CANT_LOCK;
  }
  if(pthread_mutexattr_setpshared(&mattr, PTHREAD_PROCESS_SHARED)) {
    pthread_mutexattr_destroy(&mattr);
    free(mtx);
    return CKR_CANT_LOCK;
  }
  if(pthread_mutex_init(mtx, &mattr)) {
    pthread_mutexattr_destroy(&mattr);
    free(mtx);
    return CKR_CANT_LOCK;
  }
  pthread_mutexattr_destroy(&mattr);
#endif
  *mutex = mtx;
  return CKR_OK;
}

CK_RV native_destroy_mutex(void *mutex) {
#ifdef _WIN32
  DeleteCriticalSection(mutex);
#else
  pthread_mutex_destroy(mutex);
#endif
  free(mutex);
  return CKR_OK;
}

CK_RV native_lock_mutex(void *mutex) {
#ifdef _WIN32
  EnterCriticalSection(mutex);
#else
  if(pthread_mutex_lock(mutex)) {
    return CKR_CANT_LOCK;
  }
#endif
  return CKR_OK;
}

CK_RV native_unlock_mutex(void *mutex) {
#ifdef _WIN32
  LeaveCriticalSection(mutex);
#else
  if(pthread_mutex_unlock(mutex)) {
    return CKR_CANT_LOCK;
  }
#endif
  return CKR_OK;
}

CK_RV get_pid(uint64_t *pid) {
#ifdef _WIN32
  *pid = _getpid();
#else
  *pid = getpid();
#endif
  return CKR_OK;
}

CK_RV check_pid(uint64_t pid) {
#ifdef _WIN32
  if(pid)
    return CKR_CRYPTOKI_ALREADY_INITIALIZED;
#else
  if(pid && pid != getppid())
    return CKR_CRYPTOKI_ALREADY_INITIALIZED;
#endif
  return CKR_OK;
}
