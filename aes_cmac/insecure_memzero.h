/*
 * Copyright (c) 2024 Yubico AB
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

#ifndef YUBICO_PIV_TOOL_INSECURE_MEMZERO_H
#define YUBICO_PIV_TOOL_INSECURE_MEMZERO_H

#ifdef _WIN32
#include <windows.h>
#define insecure_memzero(buf, len) SecureZeroMemory(buf, len)
#elif HAVE_MEMSET_S
#include <string.h>
#define insecure_memzero(buf, len) memset_s(buf, len, 0, len)
#elif HAVE_EXPLICIT_BZERO
#include <string.h>
#define insecure_memzero(buf, len) explicit_bzero(buf, len)
#else
#include <openssl/crypto.h>
#define insecure_memzero(buf, len) OPENSSL_cleanse(buf, len)
#endif

#endif //YUBICO_PIV_TOOL_INSECURE_MEMZERO_H
