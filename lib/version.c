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

#include "ykpiv-version.h"

#include <stddef.h>

#include <string.h>

/* From http://article.gmane.org/gmane.os.freebsd.devel.hackers/23606 */
static int my_strverscmp (const char *s1, const char *s2)
{
  static const char *digits = "0123456789";
  size_t p1, p2;

  p1 = strcspn (s1, digits);
  p2 = strcspn (s2, digits);
  while (p1 == p2 && s1[p1] != '\0' && s2[p2] != '\0') {
    int ret, lz1, lz2;
    /* Different prefix */
    if ((ret = strncmp (s1, s2, p1)) != 0)
      return ret;

    s1 += p1;
    s2 += p2;

    lz1 = lz2 = 0;
    if (*s1 == '0')
      lz1 = 1;
    if (*s2 == '0')
      lz2 = 1;

    if (lz1 > lz2)
      return -1;
    else if (lz1 < lz2)
      return 1;
    else if (lz1 == 1) {
      /*
       * If the common prefix for s1 and s2 consists only of zeros, then the
       * "longer" number has to compare less. Otherwise the comparison needs
       * to be numerical (just fallthrough). See
       * http://refspecs.freestandards.org/LSB_2.0.1/LSB-generic/
       *                                 LSB-generic/baselib-strverscmp.html
       */
      while (*s1 == '0' && *s2 == '0') {
	++s1;
	++s2;
      }

      p1 = strspn (s1, digits);
      p2 = strspn (s2, digits);

      /* Catch empty strings */
      if (p1 == 0 && p2 > 0)
	return 1;
      else if (p2 == 0 && p1 > 0)
	return -1;

      /* Prefixes are not same */
      if (*s1 != *s2 && *s1 != '0' && *s2 != '0') {
	if (p1 < p2)
	  return 1;
	else if (p1 > p2)
	  return -1;
      } else {
	if (p1 < p2)
	  ret = strncmp (s1, s2, p1);
	else if (p1 > p2)
	  ret = strncmp (s1, s2, p2);
	if (ret != 0)
	  return ret;
      }
    }

    p1 = strspn (s1, digits);
    p2 = strspn (s2, digits);

    if (p1 < p2)
      return -1;
    else if (p1 > p2)
      return 1;
    else if ((ret = strncmp (s1, s2, p1)) != 0)
      return ret;

    /* Numbers are equal or not present, try with next ones. */
    s1 += p1;
    s2 += p2;
    p1 = strcspn (s1, digits);
    p2 = strcspn (s2, digits);
  }

  return strcmp (s1, s2);
}

/**
 * ykpiv_check_version:
 * @req_version: Required version number, or NULL.
 *
 * Check that the version of the library is at minimum the requested
 * one and return the version string; return NULL if the condition is
 * not satisfied.  If a NULL is passed to this function, no check is
 * done, but the version string is simply returned.
 *
 * See %YKPIV_VERSION_STRING for a suitable @req_version string.
 *
 * Return value: Version string of run-time library, or NULL if the
 * run-time library does not meet the required version number.
 */
const char * ykpiv_check_version (const char *req_version)
{
  if (!req_version
      || my_strverscmp (req_version, YKPIV_VERSION_STRING) <= 0)
    return YKPIV_VERSION_STRING;

  return NULL;
}
