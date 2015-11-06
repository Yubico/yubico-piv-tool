/*
 * Copyright (c) 2015 Yubico AB
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

#include "ykcs11-version.h"

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
 * ykcs11_check_version:
 * @req_version: Required version number, or NULL.
 *
 * Check that the version of the library is at minimum the requested
 * one and return the version string; return NULL if the condition is
 * not satisfied.  If a NULL is passed to this function, no check is
 * done, but the version string is simply returned.
 *
 * See %YKCS11_VERSION_STRING for a suitable @req_version string.
 *
 * Return value: Version string of run-time library, or NULL if the
 * run-time library does not meet the required version number.
 */
const char * ykcs11_check_version (const char *req_version)
{
  if (!req_version
      || my_strverscmp (req_version, YKCS11_VERSION_STRING) <= 0)
    return YKCS11_VERSION_STRING;

  return NULL;
}
