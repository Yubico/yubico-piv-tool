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

#include "../tool/openssl-compat.h" // TODO: share this better?

static CK_BYTE SHA1OID[] = {0x30, 0x21, 0x30, 0x09, 0x06,
                            0x05, 0x2B, 0x0E, 0x03, 0x02,
                            0x1A, 0x05, 0x00, 0x04, 0x14};

static CK_BYTE SHA256OID[] = {0x30, 0x31, 0x30, 0x0D, 0x06,
                              0x09, 0x60, 0x86, 0x48, 0x01,
                              0x65, 0x03, 0x04, 0x02, 0x01,
                              0x05, 0x00, 0x04, 0x20};

static CK_BYTE SHA384OID[] = {0x30, 0x41, 0x30, 0x0D, 0x06,
                              0x09, 0x60, 0x86, 0x48, 0x01,
                              0x65, 0x03, 0x04, 0x02, 0x02,
                              0x05, 0x00, 0x04, 0x30};

static CK_BYTE SHA512OID[] = {0x30, 0x51, 0x30, 0x0D, 0x06,
                              0x09, 0x60, 0x86, 0x48, 0x01,
                              0x65, 0x03, 0x04, 0x02, 0x03,
                              0x05, 0x00, 0x04, 0x40};

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

static CK_BBOOL apply_DER_encoding_to_ECSIG(CK_BYTE *signature,
                                            CK_ULONG *signature_len) {
  ECDSA_SIG *sig = ECDSA_SIG_new();
  BIGNUM *r = NULL;
  BIGNUM *s = NULL;
  bool ret = CK_FALSE;

  if (sig == NULL) {
    return CK_FALSE;
  }

  r = BN_bin2bn(signature, *signature_len / 2, NULL);
  s = BN_bin2bn(signature + *signature_len / 2, *signature_len / 2, NULL);
  if (r == NULL || s == NULL) {
    goto adete_out;
  }

  if (ECDSA_SIG_set0(sig, r, s) == 0) {
    goto adete_out;
  }

  r = s = NULL;

  unsigned char *pp = signature;
  *signature_len = i2d_ECDSA_SIG(sig, &pp);

  if (*signature_len == 0) {
    goto adete_out;
  } else {
    ret = CK_TRUE;
  }

adete_out:
  if (sig != NULL) {
    ECDSA_SIG_free(sig);
  }
  if (r != NULL) {
    BN_free(r);
  }
  if (s != NULL) {
    BN_free(s);
  }

  return ret;
}

static void parse_NID(uint8_t *data, uint16_t data_len, const EVP_MD **md_type,
               int *digestinfo_len) {
  
  if (data_len >= sizeof(SHA1OID) &&
      memcmp(SHA1OID, data, sizeof(SHA1OID)) == 0) {
    *md_type = EVP_sha1();
    *digestinfo_len = sizeof(SHA1OID);
  } else if (data_len >= sizeof(SHA256OID) &&
             memcmp(SHA256OID, data, sizeof(SHA256OID)) == 0) {
    *md_type = EVP_sha256();
    *digestinfo_len = sizeof(SHA256OID);
  } else if (data_len >= sizeof(SHA384OID) &&
             memcmp(SHA384OID, data, sizeof(SHA384OID)) == 0) {
    *md_type = EVP_sha384();
    *digestinfo_len = sizeof(SHA384OID);
  } else if (data_len >= sizeof(SHA512OID) &&
             memcmp(SHA512OID, data, sizeof(SHA512OID)) == 0) {
    *md_type = EVP_sha512();
    *digestinfo_len = sizeof(SHA512OID);
  } else {
    *md_type = NULL;
    *digestinfo_len = 0;
  }
}

CK_RV verify_signature(ykcs11_session_t *session, op_info_t *op_info, 
                  CK_BYTE_PTR signature, CK_ULONG signature_len) {

  CK_RV rv = CKR_OK;
  EVP_PKEY *key = EVP_PKEY_new();
  CK_BYTE md_data[EVP_MAX_MD_SIZE];
  CK_BYTE *md = md_data;
  unsigned int md_len = sizeof(md_data);
  EVP_PKEY_CTX *ctx = NULL;
  CK_ULONG i;

  if (key == NULL) {
    rv = CKR_FUNCTION_FAILED;
    goto pv_failure;
  }

  key = session->pkeys[op_info->op.verify.key_id];
  //X509 *cert = session->certs[op_info->op.verify.key_id];
  //key = X509_get_pubkey(cert);

  ctx = EVP_PKEY_CTX_new(key, NULL);
  if (ctx == NULL) {
    rv = CKR_FUNCTION_FAILED;
    goto pv_failure;
  }
  if (EVP_PKEY_verify_init(ctx) <= 0) {
    rv = CKR_FUNCTION_FAILED;
    goto pv_failure;
  }

  int res;
  unsigned char data[2048];
  if (is_hashed_mechanism(op_info->mechanism.mechanism)) {
    if (EVP_DigestFinal_ex(op_info->op.verify.md_ctx, md,  &md_len) <= 0) {
      rv = CKR_FUNCTION_FAILED;
      goto pv_failure;
    }
  } else if (EVP_PKEY_base_id(key) == EVP_PKEY_RSA) {
    const EVP_MD *md_type;
    int di_len;

    parse_NID(op_info->buf, op_info->buf_len, &md_type, &di_len);
    op_info->op.verify.md = md_type;
    md = op_info->buf + di_len;
    md_len = op_info->buf_len - di_len;
      
  } else if (EVP_PKEY_base_id(key) == EVP_PKEY_EC) {
    
    md = op_info->buf;
    md_len = op_info->buf_len;
    if (md_len == 20) {
      op_info->op.verify.md = EVP_sha1();
    } else if (md_len == 32) {
      op_info->op.verify.md = EVP_sha256();
    } else if (md_len == 48) {
      op_info->op.verify.md = EVP_sha384();
    } else {
      op_info->op.verify.md = EVP_sha256();
    }
  } else {
    rv = CKR_FUNCTION_FAILED;
    goto pv_failure;
  }
  
  if (EVP_PKEY_CTX_set_signature_md(ctx, op_info->op.verify.md) <= 0) {
    rv = CKR_FUNCTION_FAILED;
    goto pv_failure;
  }
  if (op_info->op.verify.padding) {
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, op_info->op.verify.padding) <= 0) {
      rv = CKR_FUNCTION_FAILED;
      goto pv_failure;
    }
  }
  if (is_EC_sign_mechanism(op_info->mechanism.mechanism)) {
    memcpy(data, signature, signature_len);
    signature = data;
    if (apply_DER_encoding_to_ECSIG(signature, &signature_len) == CK_FALSE) {
      DBG("Failed to apply DER encoding to ECDSA signature");
      rv = CKR_FUNCTION_FAILED;
      goto pv_failure;
    }
  }
  res = EVP_PKEY_verify(ctx, signature, signature_len, md, md_len);
  
  if (res == 1) {
    rv = CKR_OK;
  } else if (res == 0) {
    rv = CKR_SIGNATURE_INVALID;
  } else {
    rv = CKR_FUNCTION_FAILED;
  }

pv_failure:
  if (ctx != NULL) {
    EVP_PKEY_CTX_free(ctx);
    ctx = NULL;
  }

  return rv;
}