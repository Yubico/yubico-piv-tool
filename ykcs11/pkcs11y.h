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

/* This is an offset for the vendor definitions to avoid clashes */
#define YUBICO_BASE_VENDOR 0x59554200
#define CKA_YUBICO (CKA_VENDOR_DEFINED + YUBICO_BASE_VENDOR)

#define CKA_YUBICO_TOUCH_POLICY (CKA_YUBICO + 1)
#define CKA_YUBICO_PIN_POLICY (CKA_YUBICO + 2)

/* Values for CKA_YUBICO_[TOUCH,PIN]_POLICY. Must match defines in ykpiv.h */
#define YKPIV_TOUCHPOLICY_DEFAULT 0
#define YKPIV_TOUCHPOLICY_NEVER 1
#define YKPIV_TOUCHPOLICY_ALWAYS 2
#define YKPIV_TOUCHPOLICY_CACHED 3
#define YKPIV_PINPOLICY_DEFAULT 0
#define YKPIV_PINPOLICY_NEVER 1
#define YKPIV_PINPOLICY_ONCE 2
#define YKPIV_PINPOLICY_ALWAYS 3

#endif
