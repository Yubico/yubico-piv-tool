 /*
 * Copyright (c) 2014-2017,2019-2020 Yubico AB
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

#ifndef YUBICO_PIV_TOOL_INTERNAL_H
#define YUBICO_PIV_TOOL_INTERNAL_H

#include <stdbool.h>

#include <openssl/x509.h>

#include "../tool/cmdline.h"

enum file_mode {
  INPUT_TEXT,
  OUTPUT_TEXT,
  INPUT_BIN,
  OUTPUT_BIN,
};

size_t read_data(unsigned char*, size_t, FILE*, enum enum_format);
void dump_data(unsigned const char*, unsigned int, FILE*, bool, enum enum_format);
unsigned long set_length(unsigned char*, unsigned long);
unsigned long get_length(const unsigned char*, unsigned long*);
bool has_valid_length(const unsigned char*, ptrdiff_t);
int get_curve_name(int);
X509_NAME *parse_name(const char*);
unsigned char get_algorithm(EVP_PKEY*);
FILE *open_file(const char *file_name, enum file_mode mode);
int get_slot_hex(enum enum_slot slot_enum);
bool set_component(unsigned char *in_ptr, const BIGNUM *bn, int element_len);
bool prepare_rsa_signature(const unsigned char*, unsigned int, unsigned char*,
    unsigned int*, int);
bool read_pw(const char*, char*, size_t, int, int);
const EVP_MD *get_hash(enum enum_hash, const unsigned char**, size_t*);
int get_hashnid(enum enum_hash, unsigned char);
unsigned char get_piv_algorithm(enum enum_algorithm);
unsigned char get_pin_policy(enum enum_pin_policy);
unsigned char get_touch_policy(enum enum_touch_policy);
int SSH_write_X509(FILE *fp, X509 *x);
bool is_rsa_key_algorithm(unsigned char);
bool is_ec_key_algorithm(unsigned char);

#endif
