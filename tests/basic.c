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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void)
{
  if(strcmp(YKPIV_VERSION_STRING, ykpiv_check_version (NULL)) != 0) {
    printf("version mismatch %s != %s\n", YKPIV_VERSION_STRING,
	ykpiv_check_version(NULL));
    return EXIT_FAILURE;
  }

  if(ykpiv_check_version(YKPIV_VERSION_STRING) == NULL) {
    printf("version NULL?\n");
    return EXIT_FAILURE;
  }

  if(ykpiv_check_version("99.99.99") != NULL) {
    printf ("version not NULL?\n");
    return EXIT_FAILURE;
  }

  printf ("ykpiv version: header %s library %s\n",
	  YKPIV_VERSION_STRING, ykpiv_check_version (NULL));


  if(ykpiv_strerror(YKPIV_OK) == NULL) {
    printf ("ykpiv_strerror NULL\n");
    return EXIT_FAILURE;
  }

  {
    const char *s;
    s = ykpiv_strerror_name(YKPIV_OK);
    if(s == NULL || strcmp(s, "YKPIV_OK") != 0) {
      printf("ykpiv_strerror_name %s\n", s);
      return EXIT_FAILURE;
    }
  }

  return EXIT_SUCCESS;
}
