 /*
 * Copyright (c) 2014 Yubico AB
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
