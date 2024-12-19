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

// AES-CMAC implementation as defined in SP-800-38B
// AES key length can be one of 128, 192, 256
// Output length is one full block (16 bytes)

#include <string.h>

#include "aes_cmac.h"
#include "insecure_memzero.h"

static const uint8_t zero[AES_BLOCK_SIZE] = {0};

static void do_pad(uint8_t *data, uint8_t len) {

  for (uint8_t i = len; i < AES_BLOCK_SIZE; i++)
    if (i == len)
      data[i] = 0x80;
    else
      data[i] = 0x00;
}

static void do_xor(const uint8_t *a, uint8_t *b) {

  for (uint8_t i = 0; i < AES_BLOCK_SIZE; i++) {
    b[i] ^= a[i];
  }
}

static void do_shift_one_bit_left(const uint8_t *a, uint8_t *b,
                                  uint8_t *carry) {
  for (int8_t i = AES_BLOCK_SIZE - 1; i >= 0; i--) {
    b[i] = (a[i] << 1) | *carry;

    *carry = a[i] >> 7;
  }
}

static void cmac_generate_subkey(const uint8_t *key, uint8_t *subkey) {

  uint8_t carry = 0;

  do_shift_one_bit_left(key, subkey, &carry);

  subkey[AES_BLOCK_SIZE - 1] ^= 0x87 >> (8 - (carry * 8));
}

int aes_cmac_encrypt(aes_cmac_context_t *ctx, const uint8_t *message,
                     const uint32_t message_len, uint8_t *mac) {

  uint8_t M[AES_BLOCK_SIZE] = {0};
  const uint8_t *ptr = message;

  memcpy(mac, zero, AES_BLOCK_SIZE);

  uint8_t n_blocks;
  if (message_len == 0)
    n_blocks = 0;
  else
    n_blocks = (message_len + (AES_BLOCK_SIZE - 1)) / AES_BLOCK_SIZE - 1;

  uint32_t out_len = AES_BLOCK_SIZE;
  for (uint8_t i = 0; i < n_blocks; i++) {
    int rc = aes_cbc_encrypt(ptr, AES_BLOCK_SIZE, mac, &out_len, mac, AES_BLOCK_SIZE, ctx->aes_ctx);
    if (rc) {
      return rc;
    }
    ptr += AES_BLOCK_SIZE;
  }

  uint8_t remaining_bytes = (message_len % AES_BLOCK_SIZE);

  if (remaining_bytes == 0) {
    if (message != NULL && message_len != 0) {
      memcpy(M, ptr, AES_BLOCK_SIZE);
      do_xor(ctx->k1, M);
    } else {
      do_pad(M, 0);
      do_xor(ctx->k2, M);
    }
  } else {
    memcpy(M, ptr, remaining_bytes);
    do_pad(M, remaining_bytes);
    do_xor(ctx->k2, M);
  }

  return aes_cbc_encrypt(M, AES_BLOCK_SIZE, mac, &out_len, mac, AES_BLOCK_SIZE, ctx->aes_ctx);
}

int aes_cmac_init(aes_context *aes_ctx, aes_cmac_context_t *ctx) {

  uint8_t L[AES_BLOCK_SIZE] = {0};

  ctx->aes_ctx = aes_ctx;

  uint32_t out_len = AES_BLOCK_SIZE;
  int rc = aes_encrypt(zero, AES_BLOCK_SIZE, L, &out_len, ctx->aes_ctx);
  if (rc) {
    return rc;
  }

  cmac_generate_subkey(L, ctx->k1);
  cmac_generate_subkey(ctx->k1, ctx->k2);

  return 0;
}

void aes_cmac_destroy(aes_cmac_context_t *ctx) {
  if (ctx) {
    insecure_memzero(ctx, sizeof(aes_cmac_context_t));
  }
}
