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

#include "ykpiv.h"

#include <stddef.h>

#define ERR(name, desc) { name, #name, desc }

typedef struct
{
  ykpiv_rc rc;
  const char *name;
  const char *description;
} err_t;

static const err_t errors[] = {
  ERR (YKPIV_OK, "Successful return"),
  ERR (YKPIV_MEMORY_ERROR, "Error allocating memory"),
  ERR (YKPIV_PCSC_ERROR, "Error in PCSC call"),
  ERR (YKPIV_SIZE_ERROR, "Wrong buffer size"),
  ERR (YKPIV_APPLET_ERROR, "No PIV applet found"),
  ERR (YKPIV_AUTHENTICATION_ERROR, "Error during authentication"),
  ERR (YKPIV_RANDOMNESS_ERROR, "Error getting randomness"),
  ERR (YKPIV_GENERIC_ERROR, "Something went wrong."),
  ERR (YKPIV_KEY_ERROR, "Error in key"),
  ERR (YKPIV_PARSE_ERROR, "Parse error"),
};

/**
 * ykpiv_strerror:
 * @err: error code
 *
 * Convert return code to human readable string explanation of the
 * reason for the particular error code.
 *
 * This string can be used to output a diagnostic message to the user.
 *
 * Return value: Returns a pointer to a statically allocated string
 *   containing an explanation of the error code @err.
 **/
const char *ykpiv_strerror(ykpiv_rc err) {
  static const char *unknown = "Unknown ykpiv error";
  const char *p;

  if (-err < 0 || -err >= (int) (sizeof (errors) / sizeof (errors[0])))
    return unknown;

  p = errors[-err].description;
  if (!p)
    p = unknown;

  return p;
}


/**
 * ykpiv_strerror_name:
 * @err: error code
 *
 * Convert return code to human readable string representing the error
 * code symbol itself.  For example, ykpiv_strerror_name(%YKPIV_OK)
 * returns the string "YKPIV_OK".
 *
 * This string can be used to output a diagnostic message to the user.
 *
 * Return value: Returns a pointer to a statically allocated string
 *   containing a string version of the error code @err, or NULL if
 *   the error code is not known.
 **/
const char *ykpiv_strerror_name(ykpiv_rc err) {
  if (-err < 0 || -err >= (int) (sizeof (errors) / sizeof (errors[0])))
    return NULL;

  return errors[-err].name;
}
