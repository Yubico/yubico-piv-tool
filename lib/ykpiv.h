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
#include <stddef.h>

#include <ykpiv-version.h>

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
		YKPIV_GENERIC_ERROR = -7,
		YKPIV_KEY_ERROR = -8,
		YKPIV_PARSE_ERROR = -9,
		YKPIV_WRONG_PIN = -10,
		YKPIV_INVALID_OBJECT = -11,
		YKPIV_ALGORITHM_ERROR = -12,
	} ykpiv_rc;

	const char *ykpiv_strerror(ykpiv_rc err);
	const char *ykpiv_strerror_name(ykpiv_rc err);

	ykpiv_rc ykpiv_init(ykpiv_state **state, int verbose);
	ykpiv_rc ykpiv_done(ykpiv_state *state);
	ykpiv_rc ykpiv_connect(ykpiv_state *state, const char *wanted);
	ykpiv_rc ykpiv_disconnect(ykpiv_state *state);
	ykpiv_rc ykpiv_transfer_data(ykpiv_state *state, const unsigned char *templ,
			const unsigned char *in_data, long in_len,
			unsigned char *out_data, unsigned long *out_len, int *sw);
	ykpiv_rc ykpiv_authenticate(ykpiv_state *state, const unsigned char *key);
	ykpiv_rc ykpiv_set_mgmkey(ykpiv_state *state, const unsigned char *new_key);
	ykpiv_rc ykpiv_hex_decode(const char *hex_in, size_t in_len,
	            unsigned char *hex_out, size_t *out_len);
	ykpiv_rc ykpiv_sign_data(ykpiv_state *state, const unsigned char *sign_in,
			size_t in_len,unsigned char *sign_out, size_t *out_len,
			unsigned char algorithm, unsigned char key);
	ykpiv_rc ykpiv_get_version(ykpiv_state *state, char *version, size_t len);
	ykpiv_rc ykpiv_verify(ykpiv_state *state, const char *pin, int *tries);
	ykpiv_rc ykpiv_fetch_object(ykpiv_state *state, int object_id,
			unsigned char *data, unsigned long *len);
  ykpiv_rc ykpiv_save_object(ykpiv_state *state, int object_id,
      unsigned char *indata, size_t len);

#define YKPIV_ALGO_3DES 0x03
#define YKPIV_ALGO_RSA1024 0x06
#define YKPIV_ALGO_RSA2048 0x07
#define YKPIV_ALGO_ECCP256 0x11

#define YKPIV_KEY_AUTHENTICATION 0x9a
#define YKPIV_KEY_CARDMGM 0x9b
#define YKPIV_KEY_SIGNATURE 0x9c
#define YKPIV_KEY_KEYMGM 0x9d
#define YKPIV_KEY_CARDAUTH 0x9e

#define YKPIV_OBJ_CAPABILITY 0x5fc107
#define YKPIV_OBJ_CHUID 0x5fc102
#define YKPIV_OBJ_AUTHENTICATION 0x5fc105 /* cert for 9a key */
#define YKPIV_OBJ_FINGERPRINTS 0x5fc103
#define YKPIV_OBJ_SECURITY 0x5fc106
#define YKPIV_OBJ_FACIAL 0x5fc108
#define YKPIV_OBJ_PRINTED 0x5fc109
#define YKPIV_OBJ_SIGNATURE 0x5fc10a /* cert for 9c key */
#define YKPIV_OBJ_KEY_MANAGEMENT 0x5fc10b /* cert for 9d key */
#define YKPIV_OBJ_CARD_AUTH 0x5fc101 /* cert for 9e key */
#define YKPIV_OBJ_DISCOVERY 0x7e
#define YKPIV_OBJ_KEY_HISTORY 0x5fc10c
#define YKPIV_OBJ_IRIS 0x5fc121

#define YKPIV_INS_VERIFY 0x20
#define YKPIV_INS_CHANGE_REFERENCE 0x24
#define YKPIV_INS_RESET_RETRY 0x2c
#define YKPIV_INS_GENERATE_ASYMMERTRIC 0x47
#define YKPIV_INS_AUTHENTICATE 0x87
#define YKPIV_INS_GET_DATA 0xcb
#define YKPIV_INS_PUT_DATA 0xdb

	/* Yubico vendor specific instructions */
#define YKPIV_INS_SET_MGMKEY 0xff
#define YKPIV_INS_IMPORT_KEY 0xfe
#define YKPIV_INS_GET_VERSION 0xfd
#define YKPIV_INS_RESET 0xfb
#define YKPIV_INS_SET_PIN_RETRIES 0xfa

#ifdef __cplusplus
}
#endif

#endif
