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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <check.h>

#include "ykpiv.h"

struct key {
	const char text[49];
	const unsigned char formatted[24];
	int valid;
} keys[] = {
	{"010203040506070801020304050607080102030405060708",
		{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
		1},
	{"a1a2a3a4a5a6a7a8a1a2a3a4a5a6a7a8a1a2a3a4a5a6a7a8",
		{0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8,0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8},
		1},
	{"A1A2A3A4A5A6A7A8A1A2A3A4A5A6A7A8A1A2A3A4A5A6A7A8",
		{0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8,0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8},
		1},
	{"This is not something considered valid hex......",
		{},
		0},
};

static int parse_key(const char *text, const unsigned char *expected, int valid) {
	unsigned char key[24];
	size_t len = sizeof(key);
	ykpiv_rc res = ykpiv_hex_decode(text, strlen(text), key, &len);
  if (valid) {
    ck_assert(res == YKPIV_OK);
    ck_assert(memcmp(expected, key, 24) == 0);
  } else {
    ck_assert(res != YKPIV_OK);
  }
	return EXIT_SUCCESS;
}

START_TEST(test_parse_key) {
  int res = parse_key(keys[_i].text, keys[_i].formatted, keys[_i].valid);
  ck_assert(res == EXIT_SUCCESS);
}
END_TEST

Suite *parsekey_suite(void) {
  Suite *s;
  TCase *tc;

  s = suite_create("libykpiv parsekey");
  tc = tcase_create("parsekey");
  tcase_add_loop_test(tc, test_parse_key, 0, sizeof(keys) / sizeof(struct key));
  suite_add_tcase(s, tc);

  return s;
}

int main(void)
{
  int number_failed;
  Suite *s;
  SRunner *sr;

  s = parsekey_suite();
  sr = srunner_create(s);
  srunner_run_all(sr, CK_NORMAL);
  number_failed = srunner_ntests_failed(sr);
  srunner_free(sr);
  return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
