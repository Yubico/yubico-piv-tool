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
 */

#include <string.h>
#include <stdbool.h>

#ifdef _WIN32
#include <windows.h>
#endif

#include <openssl/x509.h>

#include "util.h"

static void test_name(const char *name, const char *expected, bool fail) {
  char buf[1024];
  BIO *bio;
  const char none[] = {0};
  X509_NAME *parsed = parse_name(name);
  if(parsed == NULL) {
    if(fail) {
      return;
    } else {
      printf("Failed parsing of '%s'!\n", name);
      exit(EXIT_FAILURE);
    }
  }

  bio = BIO_new(BIO_s_mem());

  X509_NAME_print_ex(bio, parsed, 0, XN_FLAG_ONELINE);
  BIO_write(bio, none, 1);
  BIO_read(bio, buf, 1024);
  BIO_free(bio);
  X509_NAME_free(parsed);
  if(strcmp(buf, expected) != 0) {
    printf("Names not matching: '%s' != '%s'\n", expected, buf);
    exit(EXIT_FAILURE);
  }
}

int main(void) {
  test_name("/CN=test foo/", "CN = test foo", false);
  test_name("/CN=test/OU=bar/O=EXAMPLE/", "CN = test, OU = bar, O = EXAMPLE", false);
  test_name("/foo/", "", true);
  test_name("/CN=test/foobar/", "", true);
  test_name("/CN=test/foo=bar/", "", true);

  return EXIT_SUCCESS;
}
