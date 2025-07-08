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

#ifndef YUBICO_PIV_TOOL_ECDH_H
#define YUBICO_PIV_TOOL_ECDH_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef _WIN32
#define YH_INTERNAL __attribute__((visibility("hidden")))
#else
#define YH_INTERNAL
#endif

int YH_INTERNAL ecdh_curve_p256(void);
int YH_INTERNAL ecdh_calculate_public_key(int curve, const uint8_t *privkey,
                                          size_t cb_privkey, uint8_t *pubkey,
                                          size_t cb_pubkey);
int YH_INTERNAL ecdh_generate_keypair(int curve, uint8_t *privkey,
                                      size_t cb_privkey, uint8_t *pubkey,
                                      size_t cb_pubkey);
int YH_INTERNAL ecdh_calculate_secret(int curve, const uint8_t *privkey,
                                      size_t cb_privkey, const uint8_t *pubkey,
                                      size_t cb_pubkey, uint8_t *secret,
                                      size_t cb_secret);
#ifdef _WIN32
void YH_INTERNAL ecdh_init(void);
void YH_INTERNAL ecdh_done(void);
#else
#define ecdh_init()
#define ecdh_done()
#endif

#ifdef __cplusplus
}
#endif

#endif //YUBICO_PIV_TOOL_ECDH_H
