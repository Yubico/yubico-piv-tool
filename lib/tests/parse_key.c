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
