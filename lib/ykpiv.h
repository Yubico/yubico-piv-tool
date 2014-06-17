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

#ifndef YKPIV_H
#define YKPIV_H

#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif

	typedef struct ykpiv_state ykpiv_state;

	typedef enum {
		YKPIV_OK = 0,
		YKPIV_MEMORY_ERROR = -1,
		YKPIV_PCSC_ERROR = -2,
		YKPIV_SIZE_ERROR = -3,
		YKPIV_APPLET_ERROR = -4,
		YKPIV_AUTHENTICATION_ERROR = -5,
		YKPIV_RANDOMNESS_ERROR = -6,
	} ykpiv_rc;

	const char *ykpiv_strerror(ykpiv_rc err);
	const char *ykpiv_strerror_name(ykpiv_rc err);

	ykpiv_rc ykpiv_init(ykpiv_state **state, int verbose);
	ykpiv_rc ykpiv_done(ykpiv_state *state);
	ykpiv_rc ykpiv_connect(ykpiv_state *state, const char *wanted);
	ykpiv_rc ykpiv_transfer_data(ykpiv_state *state, const unsigned char *templ,
			const unsigned char *in_data, long in_len,
			unsigned char *out_data, unsigned long *out_len, int *sw);
	ykpiv_rc ykpiv_send_data(ykpiv_state *state, unsigned char *apdu,
			unsigned char *data, unsigned long *recv_len, int *sw);
	ykpiv_rc ykpiv_authenticate(ykpiv_state *state, const unsigned char *key);

#define YKPIV_ALGO_3DES 0x03;
#define YKPIV_ALGO_RSA1024 0x06;
#define YKPIV_ALGO_RSA2048 0x07;
#define YKPIV_ALGO_ECCP256 0x11;

#define YKPIV_KEY_AUTHENTICATION 0x9a;
#define YKPIV_KEY_CARDMGM 0x9b;
#define YKPIV_KEY_SIGNATURE 0x9c;
#define YKPIV_KEY_KEYMGM 0x9d;
#define YKPIV_KEY_CARDAUTH 0x9e;

#define YKPIV_INS_AUTHENTICATE 0x87;

#ifdef __cplusplus
}
#endif

#endif
