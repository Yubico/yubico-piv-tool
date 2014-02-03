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

#ifdef __APPLE__
#include <PCSC/wintypes.h>
#else
#include <winscard.h>
#endif

#include "cmdline.h"

unsigned const char default_key[] =
    { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03, 0x04,
	0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08
};

typedef struct {
	unsigned char cla;
	unsigned char ins;
	unsigned char p1;
	unsigned char p2;
	unsigned char lc;
	unsigned char data[0xff];
} APDU;

static void dump_hex(const unsigned char *buf, int len)
{
	int i;
	printf("length: %d\n", len);
	for (i = 0; i < len; i++) {
		printf("0x%02x ", buf[i]);
		if (i % 8 == 7) {
			printf("\n");
		}
	}
	printf("\n");
}

int main(int argc, char *argv[])
{
	struct gengetopt_args_info args_info;

	if (cmdline_parser(argc, argv, &args_info) != 0) {
		return EXIT_FAILURE;
  }

	dump_hex(default_key, 24);

	return EXIT_SUCCESS;
}
