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
#include "internal.h"

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <check.h>

int confirm_destruction(void);

ykpiv_state *g_state;
const uint8_t g_cert[] = {
  "0123456789ABCDEFGHIK0123456789ABCDEFGHIK0123456789ABCDEFGHIK0123456789ABCDEFGHIK"
  "0123456789ABCDEFGHIK0123456789ABCDEFGHIK0123456789ABCDEFGHIK0123456789ABCDEFGHIK"
  "0123456789ABCDEFGHIK0123456789ABCDEFGHIK0123456789ABCDEFGHIK0123456789ABCDEFGHIK"
  "0123456789ABCDEFGHIK0123456789ABCDEFGHIK0123456789ABCDEFGHIK0123456789ABCDEFGHIK"
  "0123456789ABCDEFGHIK0123456789ABCDEFGHIK0123456789ABCDEFGHIK0123456789ABCDEFGHIK"
};

void setup(void) {
  ykpiv_rc res;

  // Require user confirmation to continue, since this test suite will clear
  // any data stored on connected keys.
  ck_assert(confirm_destruction());

  res = ykpiv_init(&g_state, true);
  ck_assert_int_eq(res, YKPIV_OK);
  ck_assert_ptr_nonnull(g_state);

  res = ykpiv_connect(g_state, NULL);
  ck_assert_int_eq(res, YKPIV_OK);
}

void teardown(void) {
  ykpiv_rc res;

  // This is the expected case, if the allocator test ran, since it de-inits.
  if (NULL == g_state)
    return;

  res = ykpiv_disconnect(g_state);
  ck_assert_int_eq(res, YKPIV_OK);

  res = ykpiv_done(g_state);
  ck_assert_int_eq(res, YKPIV_OK);
}

START_TEST(test_devicemodel) {
  ykpiv_devmodel model;
  model = ykpiv_util_devicemodel(g_state);
  fprintf(stdout, "Model: %u\n", model);
  ck_assert(model == DEVTYPE_YK4);
}
END_TEST

START_TEST(test_get_set_cardid) {
  ykpiv_rc res;
  ykpiv_cardid set_id;
  ykpiv_cardid get_id;

  memset(&set_id.data, 'i', sizeof(set_id.data));
  memset(&get_id.data, 0, sizeof(get_id.data));

  res = ykpiv_util_set_cardid(g_state, &set_id);
  ck_assert_int_eq(res, YKPIV_OK);

  res = ykpiv_util_get_cardid(g_state, &get_id);
  ck_assert_int_eq(res, YKPIV_OK);
  ck_assert_mem_eq(&set_id.data, &get_id.data, sizeof(set_id.data));
}
END_TEST

START_TEST(test_list_readers) {
  ykpiv_rc res;
  char reader_buf[2048];
  size_t num_readers = sizeof(reader_buf);
  char *reader_ptr;
  res = ykpiv_list_readers(g_state, reader_buf, &num_readers);
  ck_assert_int_eq(res, YKPIV_OK);
  ck_assert_int_gt(num_readers, 0);
  for(reader_ptr = reader_buf; *reader_ptr != '\0'; reader_ptr += strlen(reader_ptr) + 1) {
    fprintf(stdout, "Found device: %s\n", reader_ptr);
  }
}
END_TEST

START_TEST(test_read_write_list_delete_cert) {
  ykpiv_rc res;
  uint8_t *read_cert = NULL;
  size_t read_cert_len = 0;

  {
    res = ykpiv_util_write_cert(g_state, YKPIV_KEY_AUTHENTICATION, (uint8_t*)g_cert, sizeof(g_cert));
    ck_assert_int_eq(res, YKPIV_OK);

    res = ykpiv_util_read_cert(g_state, YKPIV_KEY_AUTHENTICATION, &read_cert, &read_cert_len);
    ck_assert_int_eq(res, YKPIV_OK);
    ck_assert_ptr_nonnull(read_cert);
    ck_assert_int_eq(read_cert_len, sizeof(g_cert));
    ck_assert_mem_eq(g_cert, read_cert, sizeof(g_cert));

    res = ykpiv_util_free(g_state, read_cert);
    ck_assert_int_eq(res, YKPIV_OK);
  }

  {
    ykpiv_key *keys = NULL;
    size_t data_len;
    uint8_t key_count;
    res = ykpiv_util_list_keys(g_state, &key_count, &keys, &data_len);
    ck_assert_int_eq(res, YKPIV_OK);
    ck_assert_ptr_nonnull(keys);
    ck_assert_int_gt(key_count, 0);

    res = ykpiv_util_free(g_state, keys);
    ck_assert_int_eq(res, YKPIV_OK);
  }

  {
    res = ykpiv_util_delete_cert(g_state, YKPIV_KEY_AUTHENTICATION);
    ck_assert_int_eq(res, YKPIV_OK);

    res = ykpiv_util_read_cert(g_state, YKPIV_KEY_AUTHENTICATION, &read_cert, &read_cert_len);
    ck_assert_int_eq(res, YKPIV_GENERIC_ERROR);

    res = ykpiv_util_free(g_state, read_cert);
    ck_assert_int_eq(res, YKPIV_OK);
  }
}
END_TEST

START_TEST(test_generate_key) {
  ykpiv_rc res;
  uint8_t *mod, *exp;
  size_t mod_len, exp_len;
  res = ykpiv_util_write_cert(g_state, YKPIV_KEY_AUTHENTICATION, (uint8_t*)g_cert, sizeof(g_cert));
  ck_assert_int_eq(res, YKPIV_OK);
  res = ykpiv_util_generate_key(g_state,
                                YKPIV_KEY_AUTHENTICATION,
                                YKPIV_ALGO_RSA2048,
                                YKPIV_PINPOLICY_ONCE,
                                YKPIV_TOUCHPOLICY_DEFAULT,
                                &mod,
                                &mod_len,
                                &exp,
                                &exp_len,
                                NULL,
                                NULL);
  ck_assert_int_eq(res, YKPIV_OK);
  res = ykpiv_util_free(g_state, mod);
  ck_assert_int_eq(res, YKPIV_OK);
  res = ykpiv_util_free(g_state, exp);
  ck_assert_int_eq(res, YKPIV_OK);
  // TODO: and??
}
END_TEST

START_TEST(test_read_write_mscmap) {
}
END_TEST

START_TEST(test_read_write_msroots) {
}
END_TEST

START_TEST(test_authenticate) {
  ykpiv_rc res;
  const char *default_mgm_key = "010203040506070801020304050607080102030405060708";
  const char *mgm_key = "112233445566778811223344556677881122334455667788";
  unsigned char key[24];
  size_t key_len = sizeof(key);

  // Try new key, fail.
  res = ykpiv_hex_decode(mgm_key, strlen(mgm_key), key, &key_len);
  ck_assert_int_eq(res, YKPIV_OK);
  res = ykpiv_authenticate(g_state, key);
  ck_assert_int_eq(res, YKPIV_AUTHENTICATION_ERROR);

  // Try default key, succeed
  res = ykpiv_hex_decode(default_mgm_key, strlen(default_mgm_key), key, &key_len);
  ck_assert_int_eq(res, YKPIV_OK);
  res = ykpiv_authenticate(g_state, key);
  ck_assert_int_eq(res, YKPIV_OK);

  // Change to new key
  res = ykpiv_hex_decode(mgm_key, strlen(mgm_key), key, &key_len);
  ck_assert_int_eq(res, YKPIV_OK);
  res = ykpiv_set_mgmkey(g_state, key);
  ck_assert_int_eq(res, YKPIV_OK);

  // Try new key, succeed.
  res = ykpiv_hex_decode(mgm_key, strlen(mgm_key), key, &key_len);
  ck_assert_int_eq(res, YKPIV_OK);
  res = ykpiv_authenticate(g_state, key);
  ck_assert_int_eq(res, YKPIV_OK);

  // Change back to default key
  res = ykpiv_hex_decode(default_mgm_key, strlen(default_mgm_key), key, &key_len);
  ck_assert_int_eq(res, YKPIV_OK);
  res = ykpiv_set_mgmkey(g_state, key);
  ck_assert_int_eq(res, YKPIV_OK);

  // Try default key, succeed
  res = ykpiv_hex_decode(default_mgm_key, strlen(default_mgm_key), key, &key_len);
  ck_assert_int_eq(res, YKPIV_OK);
  res = ykpiv_authenticate(g_state, key);
  ck_assert_int_eq(res, YKPIV_OK);
}
END_TEST

START_TEST(test_reset) {
  ykpiv_rc res;
  int tries = 100;
  int i;

  while (tries) {
    res = ykpiv_verify(g_state, "AAAAAA", &tries);
    if (res == YKPIV_PIN_LOCKED)
      break;
    ck_assert_int_eq(res, YKPIV_WRONG_PIN);
  }
  tries = 100;
  while (tries) {
    res = ykpiv_change_puk(g_state, "AAAAAAAA", 8, "AAAAAAAA", 8, &tries);
    if (res == YKPIV_PIN_LOCKED)
      break;
    ck_assert_int_eq(res, YKPIV_WRONG_PIN);
  }
  res = ykpiv_util_reset(g_state);
  ck_assert_int_eq(res, YKPIV_OK);
}
END_TEST


struct t_alloc_data{
  uint32_t count;
} g_alloc_data;

static void* _test_alloc(void *data, size_t cb) {
  ck_assert_ptr_eq(data, &g_alloc_data);
  ((struct t_alloc_data*)data)->count++;
  return calloc(cb, 1);
}

static void * _test_realloc(void *data, void *p, size_t cb) {
  ck_assert_ptr_eq(data, &g_alloc_data);
  return realloc(p, cb);
}

static void _test_free(void *data, void *p) {
  fflush(stderr);
  ck_assert_ptr_eq(data, &g_alloc_data);
  ((struct t_alloc_data*)data)->count--;
  free(p);
}

ykpiv_allocator test_allocator_cbs = {
  .pfn_alloc = _test_alloc,
  .pfn_realloc = _test_realloc,
  .pfn_free = _test_free,
  .alloc_data = &g_alloc_data
};

uint8_t *alloc_auth_cert() {
  ykpiv_rc res;
  uint8_t *read_cert = NULL;
  size_t read_cert_len = 0;

  res = ykpiv_util_write_cert(g_state, YKPIV_KEY_AUTHENTICATION, (uint8_t*)g_cert, sizeof(g_cert));
  ck_assert_int_eq(res, YKPIV_OK);

  res = ykpiv_util_read_cert(g_state, YKPIV_KEY_AUTHENTICATION, &read_cert, &read_cert_len);
  ck_assert_int_eq(res, YKPIV_OK);
  ck_assert_ptr_nonnull(read_cert);
  ck_assert_int_eq(read_cert_len, sizeof(g_cert));
  ck_assert_mem_eq(g_cert, read_cert, sizeof(g_cert));
  return read_cert;
}

START_TEST(test_allocator) {
  ykpiv_rc res;
  const ykpiv_allocator allocator;
  uint8_t *cert1, *cert2;

  res = ykpiv_done(g_state);
  ck_assert_int_eq(res, YKPIV_OK);
  g_state = NULL;

  res = ykpiv_init_with_allocator(&g_state, false, &test_allocator_cbs);
  ck_assert_int_eq(res, YKPIV_OK);
  ck_assert_ptr_nonnull(g_state);

  // Verify we can communicate with device and make some allocations
  res = ykpiv_connect(g_state, NULL);
  ck_assert_int_eq(res, YKPIV_OK);
  test_authenticate(0);
  cert1 = alloc_auth_cert();
  cert2 = alloc_auth_cert();

  // Verify allocations went through custom allocator, and still live
  ck_assert_int_gt(g_alloc_data.count, 1);

  // Free and shutdown everything
  ykpiv_util_free(g_state, cert2);
  ykpiv_util_free(g_state, cert1);
  res = ykpiv_disconnect(g_state);
  ck_assert_int_eq(res, YKPIV_OK);
  res = ykpiv_done(g_state);
  ck_assert_int_eq(res, YKPIV_OK);

  // Verify equal number of frees as allocations
  ck_assert_int_eq(g_alloc_data.count, 0);

  // Clear g_state so teardown() is skipped
  g_state = NULL;
}
END_TEST

int confirm_destruction(void) {
  char verify[16];

  // Use dprintf() to write directly to stdout, since automake eats the standard stdout/stderr pointers.
  dprintf(0, "******* ******* ******* ******* ******* ******* ******* ******* ******* ******* ******* ******* ******* ******* *******\n");
  dprintf(0, "WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING\n");
  dprintf(0, "WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING\n");
  dprintf(0, "\n");

  dprintf(0, "******* ******* ******* ******* ******* ******* ******* ******* ******* ******* ******* ******* ******* ******* *******\n");
  dprintf(0, "\n");
  dprintf(0, "                            ALL DATA WILL BE ERASED ON CONNECTED YUBIKEYS                                              \n");
  dprintf(0, "\n");
  dprintf(0, "******* ******* ******* ******* ******* ******* ******* ******* ******* ******* ******* ******* ******* ******* *******\n");
  dprintf(0, "\n");

  dprintf(0, "WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING\n");
  dprintf(0, "WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING\n");
  dprintf(0, "******* ******* ******* ******* ******* ******* ******* ******* ******* ******* ******* ******* ******* ******* *******\n");
  dprintf(0, "\n");
  dprintf(0, "Are you SURE you wish to proceed?  If so, type 'CONFIRM': ");
  fgets(verify, 32, stdin);
  return strncmp(verify, "CONFIRM", 7) == 0;
}

Suite *test_suite(void) {
  Suite *s;
  TCase *tc;

  s = suite_create("libykpiv util");
  tc = tcase_create("util");
#ifdef HW_TESTS
  tcase_add_unchecked_fixture(tc, setup, teardown);

  // Must be first: Reset device.  Tests run serially, and depend on a clean slate.
  tcase_add_test(tc, test_reset);

  // Authenticate after reset.
  tcase_add_test(tc, test_authenticate);

  // Test util functionality
  tcase_add_test(tc, test_devicemodel);
  tcase_add_test(tc, test_get_set_cardid);
  tcase_add_test(tc, test_list_readers);
  tcase_add_test(tc, test_read_write_list_delete_cert);
  tcase_add_test(tc, test_generate_key);

  // Must be last: tear down and re-test with custom memory allocator
  tcase_add_test(tc, test_allocator);
#endif
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
  srunner_set_fork_status(sr, CK_NOFORK);
  srunner_run_all(sr, CK_VERBOSE);
  number_failed = srunner_ntests_failed(sr);
  srunner_free(sr);

  return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
