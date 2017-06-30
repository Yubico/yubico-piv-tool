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

#include <check.h>

#include <string.h>
#include <stdbool.h>

#ifdef _WIN32
#include <windows.h>
#endif

#include <openssl/x509.h>

#include "util.h"

struct name {
  const char *name;
  const char *parsed_name;
  bool valid;
} names[] = {
  {"/CN=test foo/", "CN = test foo", true},
  {"/CN=test/OU=bar/O=EXAMPLE/", "CN = test, OU = bar, O = EXAMPLE", true},
  {"/CN=test/OU=bar/O=EXAMPLE/", "CN = test, OU = wrong, O = EXAMPLE", false},
  {"/foo/", "", false},
  {"/CN=test/foobar/", "", false},
  {"/CN=test/foo=bar/", "", false},
};

static bool test_name(const char *name, const char *expected) {
  char buf[1024];
  BIO *bio;
  const char none[] = {0};
  X509_NAME *parsed = parse_name(name);
  if(parsed == NULL) {
    return false;
  }

  bio = BIO_new(BIO_s_mem());

  X509_NAME_print_ex(bio, parsed, 0, XN_FLAG_ONELINE);
  BIO_write(bio, none, 1);
  BIO_read(bio, buf, 1024);
  BIO_free(bio);
  X509_NAME_free(parsed);
  if(strcmp(buf, expected) != 0) {
    fprintf(stderr, "Names not matching: '%s' != '%s'\n", expected, buf);
    return false;
  }
  return true;
}

START_TEST(test_parse_name) {
  ck_assert(test_name(names[_i].name, names[_i].parsed_name) == names[_i].valid);
}
END_TEST

Suite *test_suite(void) {
  Suite *s;
  TCase *tc;

  s = suite_create("yubico-piv-tool parse_name");
  tc = tcase_create("parse_name");
  tcase_add_loop_test(tc, test_parse_name, 0, sizeof(names) / sizeof(struct name));
  suite_add_tcase(s, tc);

  return s;
}

int main(void)
{
  int number_failed;
  Suite *s;
  SRunner *sr;

  s = test_suite();
  sr = srunner_create(s);
  srunner_run_all(sr, CK_NORMAL);
  number_failed = srunner_ntests_failed(sr);
  srunner_free(sr);
  return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
