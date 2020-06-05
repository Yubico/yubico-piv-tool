/*
 * Copyright (c) 2015-2016,2019 Yubico AB
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

#ifndef PKCS11Y_H
#define PKCS11Y_H

#include "pkcs11.h"

typedef CK_FLAGS * CK_FLAGS_PTR;

// YUBICO specific attributes
#define CKA_TOUCH_PIN_DEFAULT 0x00000000U
#define CKA_TOUCH_ALWAYS      0x00000001U
#define CKA_PIN_ONCE          0x00000002U
#define CKA_PIN_ALWAYS        0x00000004U
#define CKA_PIN_NEVER         0x00000008U
#define CKA_TOUCH_NEVER       0x00000016U

// Standard stuff that we use but is not in pkcs11.h

#define CKG_MGF1_SHA1			  (0x1UL)
#define CKG_MGF1_SHA256			(0x2UL)
#define CKG_MGF1_SHA384			(0x3UL)
#define CKG_MGF1_SHA512			(0x4UL)
#define CKG_MGF1_SHA224			(0x5UL)

#define CKZ_DATA_SPECIFIED  (0x1UL) // = CK_BYTE. The only supported option for CK_RSA_PKCS_OAEP_SOURCE_TYPE

typedef unsigned long CK_RSA_PKCS_MGF_TYPE;
typedef unsigned long CK_RSA_PKCS_OAEP_SOURCE_TYPE;

typedef struct {
  CK_MECHANISM_TYPE       hashAlg;
  CK_RSA_PKCS_MGF_TYPE    mgf;
  CK_ULONG                sLen;
} CK_RSA_PKCS_PSS_PARAMS, *CK_RSA_PKCS_PSS_PARAMS_PTR;

typedef struct {
  CK_MECHANISM_TYPE             hashAlg;
  CK_RSA_PKCS_MGF_TYPE          mgf;
  CK_RSA_PKCS_OAEP_SOURCE_TYPE  source;
  CK_VOID_PTR                   pSourceData;
  CK_ULONG                      ulSourceDataLen;
} CK_RSA_PKCS_OAEP_PARAMS, *CK_RSA_PKCS_OAEP_PARAMS_PTR;

#endif
