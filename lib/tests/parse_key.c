 /*
 * Copyright (c) 2014-2016 Yubico AB
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ykpiv.h"

struct key {
	const char text[49];
	const unsigned char formatted[24];
	int valid;
} keys[] = {
	{"010203040506070801020304050607080102030405060708",
		{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
		1},
	{"a1a2a3a4a5a6a7a8a1a2a3a4a5a6a7a8a1a2a3a4a5a6a7a8",
		{0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8,0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8},
		1},
	{"A1A2A3A4A5A6A7A8A1A2A3A4A5A6A7A8A1A2A3A4A5A6A7A8",
		{0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8,0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8},
		1},
	{"This is not something considered valid hex......",
		{},
		0},
};

static int parse_key(const char *text, const unsigned char *expected, int valid) {
	unsigned char key[24];
	size_t len = sizeof(key);
	ykpiv_rc res = ykpiv_hex_decode(text, strlen(text), key, &len);
	if(res != YKPIV_OK && valid == 1) {
		printf("key check failed for %s!\n", text);
		return EXIT_FAILURE;
	} else if(res != YKPIV_OK && valid == 0) {
		return EXIT_SUCCESS;
	}

	if(memcmp(expected, key, 24) != 0) {
		printf("keys not matching for %s!\n", text);
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

int main(void) {
	size_t i;

	for(i = 0; i < sizeof(keys) / sizeof(struct key); i++) {
		int res = parse_key(keys[i].text, keys[i].formatted, keys[i].valid);
		if(res != EXIT_SUCCESS) {
			return res;
		}
	}

	return EXIT_SUCCESS;
}
