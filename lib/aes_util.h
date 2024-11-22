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

#ifndef YUBICO_PIV_TOOL_AES_UTIL_H
#define YUBICO_PIV_TOOL_AES_UTIL_H

#include "ykpiv.h"

ykpiv_rc calculate_cmac(uint8_t *key, uint8_t *data, size_t data_len, uint8_t *mac_out, uint8_t *mac_chain,
                        size_t mac_chain_len);

ykpiv_rc unmac_data(uint8_t *key, uint8_t *mac_chain, uint8_t *data, size_t data_len, uint16_t sw);

//ykpiv_rc scp11_get_iv(uint8_t *key, uint8_t counter, uint8_t *iv);

ykpiv_rc
aescbc_encrypt_data(uint8_t *key, uint8_t counter, const uint8_t *data, size_t data_len, uint8_t *enc, size_t *enc_len);

ykpiv_rc
aesecb_decrypt_data(uint8_t *key, uint8_t counter, uint8_t *enc, size_t enc_len, uint8_t *data, size_t *data_len);


#endif //YUBICO_PIV_TOOL_AES_UTIL_H
