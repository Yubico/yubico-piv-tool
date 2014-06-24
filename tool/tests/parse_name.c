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
 */

#include <string.h>

#ifdef _WIN32
#include <windows.h>
#endif

#include <openssl/x509.h>

#include "util.h"

static void test_name(char *name, char *expected) {
  char buf[1024];
  X509_NAME *parsed = parse_name(name);
  BIO *bio = BIO_new(BIO_s_mem());
  const char none[] = {0};

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
  test_name("/CN=test foo/", "CN = test foo");
  test_name("/CN=test/OU=bar/O=EXAMPLE/", "CN = test, OU = bar, O = EXAMPLE");
  return EXIT_SUCCESS;
}
