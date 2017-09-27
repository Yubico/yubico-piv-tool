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

#include "yubico_slot.h"
#include "pkcs11.h"
#include <string.h>

static const CK_UTF8CHAR_PTR slot_manufacturer = (const CK_UTF8CHAR_PTR)"Yubico";
static const CK_FLAGS slot_flags = CKF_TOKEN_PRESENT | CKF_HW_SLOT;
static const CK_VERSION slot_version = {1, 0};

CK_RV YUBICO_get_slot_manufacturer(CK_UTF8CHAR_PTR str, CK_ULONG len) {

  if (strlen((const char*)slot_manufacturer) > len)
    return CKR_BUFFER_TOO_SMALL;

  memcpy(str, slot_manufacturer, strlen((const char*)slot_manufacturer));
  return CKR_OK;

}

CK_RV YUBICO_get_slot_flags(CK_FLAGS_PTR flags) {

  *flags = slot_flags;
  return CKR_OK;

}

CK_RV YUBICO_get_slot_version(CK_VERSION_PTR version) {

  version->major = slot_version.major;
  version->minor = slot_version.minor;

  return CKR_OK;

}
