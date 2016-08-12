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
  ERR (YKPIV_APPLET_ERROR, "No PIV application found"),
  ERR (YKPIV_AUTHENTICATION_ERROR, "Error during authentication"),
  ERR (YKPIV_RANDOMNESS_ERROR, "Error getting randomness"),
  ERR (YKPIV_GENERIC_ERROR, "Something went wrong."),
  ERR (YKPIV_KEY_ERROR, "Error in key"),
  ERR (YKPIV_PARSE_ERROR, "Parse error"),
  ERR (YKPIV_WRONG_PIN, "Wrong PIN code"),
  ERR (YKPIV_INVALID_OBJECT, "Object invalid"),
  ERR (YKPIV_ALGORITHM_ERROR, "Algorithm error"),
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
