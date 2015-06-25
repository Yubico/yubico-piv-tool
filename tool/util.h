 /*
 * Copyright (c) 2014 Yubico AB
 * All rights reserved.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 * Additional permission under GNU GPL version 3 section 7
 *
 * If you modify this program, or any covered work, by linking or
 * combining it with the OpenSSL project's OpenSSL library (or a
 * modified version of that library), containing parts covered by the
 * terms of the OpenSSL or SSLeay licenses, We grant you additional 
 * permission to convey the resulting work. Corresponding Source for a
 * non-source form of such a combination shall include the source code
 * for the parts of OpenSSL used as well as that of the covered work.
 *
 */

#ifndef YUBICO_PIV_TOOL_INTERNAL_H
#define YUBICO_PIV_TOOL_INTERNAL_H

#include <openssl/x509.h>

#include "cmdline.h"

#define INPUT 1
#define OUTPUT 2

void dump_hex(unsigned const char*, unsigned int, FILE*, bool);
int set_length(unsigned char*, int);
int get_length(const unsigned char*, int*);
X509_NAME *parse_name(const char*);
unsigned char get_algorithm(EVP_PKEY*);
FILE *open_file(const char*, int);
int get_object_id(enum enum_slot slot);
bool set_component_with_len(unsigned char**, const BIGNUM*, int);
bool prepare_rsa_signature(const unsigned char*, unsigned int, unsigned char*,
    unsigned int*, int);
const EVP_MD *get_hash(enum enum_hash, const unsigned char**, size_t*);
int get_hashnid(enum enum_hash, unsigned char);
unsigned char get_piv_algorithm(enum enum_algorithm);
unsigned char get_pin_policy(enum enum_pin_policy);
unsigned char get_touch_policy(enum enum_touch_policy);

#endif
