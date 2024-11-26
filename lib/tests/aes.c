/*
* Copyright (c) 2014-2017,2020 Yubico AB
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
#include <stdlib.h>
#include <check.h>

#include "../aes_util.h"

struct enc_test_data {
    uint8_t enc_key[16];
    uint8_t counter;
    uint8_t plain_text[5];
    uint8_t enc_text[16];
} enc_data[] = {
        {{0x3a, 0x37, 0x9f, 0x12, 0x97, 0x13, 0xae, 0xfe, 0x54, 0x94, 0xa9, 0xe1, 0x27, 0x7a, 0x5b, 0x96},
                8,
                {0x5c, 0x03, 0x5f, 0xc1, 0x02},
                {0x93, 0xdd, 0x4e, 0x94, 0xdc, 0x00, 0xed, 0x23, 0x10, 0x2b, 0xc9, 0x94, 0x12, 0x90, 0xfa, 0x14}},

        {{0x47, 0x2c, 0xe4, 0xc2, 0xc4, 0x31, 0x84, 0xed, 0xb6, 0x15, 0xb6, 0xc4, 0x94, 0x8a, 0x97, 0x4b},
                8,
                {0x5c, 0x03, 0x5f, 0xc1, 0x02},
                {0x36, 0xd7, 0xcf, 0xf9, 0x1e, 0xe6, 0x3a, 0x74, 0x7a, 0x65, 0x67, 0xe8, 0xf4, 0x9e, 0xa0, 0x0d}}
};

struct dec_test_data {
    uint8_t dec_key[16];
    uint8_t counter;
    uint8_t enc_text[64];
    uint8_t plain_text[64];
} dec_data[] = {
        {{0xd1, 0xad, 0x52, 0xc5, 0xe8, 0x4d, 0xcc, 0x33, 0x28, 0x26, 0xe5, 0x06, 0xc8, 0x57, 0xef, 0x52},
         8,
         {0x57, 0x89, 0x96, 0x44, 0xd4, 0xc8, 0x3e, 0x55, 0xf4, 0xe7, 0xdd, 0xc2, 0x03, 0x14, 0xbd, 0xc7, 0xb4, 0xe5,
          0xae, 0x30, 0x8f, 0x27, 0x06, 0xbb, 0xc9, 0x16, 0x58, 0x94, 0x5f, 0xf1, 0x3f, 0xf5, 0x6c, 0x21, 0xa0, 0x2c,
          0x26, 0xc7, 0xb6, 0xc4, 0x15, 0xbc, 0x90, 0x43, 0x84, 0x8b, 0xa6, 0x9d, 0x82, 0x34, 0xe6, 0x07, 0x42, 0xcb,
          0xd8, 0x6b, 0x04, 0xdd, 0xd0, 0x99, 0x42, 0xf2, 0x85, 0x32},
         {0x53, 0x3b, 0x30, 0x19, 0xd4, 0xe7, 0x39, 0xda, 0x73, 0x9c, 0xed, 0x39, 0xce, 0x73, 0x9d, 0x83, 0x68, 0x58,
          0x21, 0x08, 0x42, 0x10, 0x84, 0x21, 0xc8, 0x42, 0x10, 0xc3, 0xeb, 0x34, 0x10, 0x19, 0x9e, 0xe7, 0x77, 0x16,
          0x57, 0xcf, 0xde, 0x06, 0x1b, 0x74, 0x57, 0x15, 0x1a, 0xc4, 0x6d, 0x35, 0x08, 0x32, 0x30, 0x33, 0x30, 0x30,
          0x31, 0x30, 0x31, 0x3e, 0x00, 0xfe, 0x00, 0x80, 0x00, 0x00}}
};

struct mac_test_data {
    uint8_t mac_key[16];
    uint8_t mac_chain[16];
    uint8_t input_text[23];
    uint8_t mac[16];
} mac_data[] = {
        {{0x65, 0xdc, 0x5e, 0x18, 0xac, 0xe9, 0xd3, 0xf2, 0x79, 0x95, 0xff, 0x14, 0xa8, 0x3a, 0xb1, 0x3c},
                {0x2f, 0x4d, 0x61, 0x4d, 0x4c, 0x70, 0xa9, 0x17, 0xa6, 0xba, 0x4e, 0x2c, 0x1b, 0x1b, 0xef, 0x08},
                {0x04, 0xcb, 0x3f, 0xff, 0x00, 0x00, 0x18, 0x93, 0xdd, 0x4e, 0x94, 0xdc, 0x00, 0xed, 0x23, 0x10, 0x2b, 0xc9, 0x94, 0x12, 0x90, 0xfa, 0x14},
                {0x25, 0xcc, 0xda, 0xba, 0x6f, 0x57, 0x01, 0x4d, 0xd2, 0x4b, 0x83, 0x24, 0x95, 0xb0, 0xe8, 0x67}},
        {{0x60, 0x50, 0x15, 0xd4, 0x93, 0xcc, 0x7c, 0x14, 0x28, 0x2c, 0x1a, 0x15, 0x7a, 0x56, 0x29, 0x2a},
                {0x03, 0x56, 0x2b, 0xde, 0xd1, 0x79, 0x65, 0xc6, 0xf9, 0xaa, 0x04, 0x3e, 0xa4, 0x3e, 0x84, 0x61},
                {0x04, 0xcb, 0x3f, 0xff, 0x00, 0x00, 0x18, 0xdb, 0x5d, 0x97, 0x4a, 0x25, 0xb5, 0x97, 0xc7, 0x32, 0x37, 0x69, 0x35, 0x29, 0x94, 0x4c, 0x04},
                {0x7e, 0x22, 0x04, 0xe4, 0x58, 0xea, 0xfb, 0xb4, 0xc8, 0xe7, 0x8a, 0x4a, 0x48, 0x4f, 0x6f, 0x3d}}
};


static int
encryption(uint8_t *key, uint8_t counter, uint8_t *plaintext, size_t plaintext_len, uint8_t *enc, size_t enc_len) {
  uint8_t e[255] = {0};
  size_t e_len = sizeof(e);
  ykpiv_rc rc = aescbc_encrypt_data(key, counter, plaintext, plaintext_len, e, &e_len);

  ck_assert(rc == YKPIV_OK);
  ck_assert(e_len == enc_len);
  ck_assert(memcmp(e, enc, enc_len) == 0);
  return EXIT_SUCCESS;
}

static int decryption(uint8_t *key, uint8_t counter, uint8_t *enc, size_t enc_len, uint8_t *dec, size_t dec_len) {
  uint8_t d[255] = {0};
  size_t d_len = sizeof(d);
  ykpiv_rc rc = aescbc_decrypt_data(key, counter, enc, enc_len, d, &d_len);

  ck_assert(rc == YKPIV_OK);
  ck_assert(d_len == dec_len);
  ck_assert(memcmp(d, dec, dec_len) == 0);
  return EXIT_SUCCESS;
}

static int mac(uint8_t *mac_key, uint8_t *mac_chain, uint8_t *data, size_t data_len, uint8_t *mac) {
  uint8_t m[255] = {0};
  ykpiv_rc rc = calculate_cmac(mac_key, mac_chain, data, data_len, m);

  ck_assert(rc == YKPIV_OK);
  ck_assert(memcmp(m, mac, 16) == 0);
  return EXIT_SUCCESS;
}

START_TEST(test_encryption) {
  int res = encryption(enc_data[_i].enc_key, enc_data[_i].counter, enc_data[_i].plain_text,
                       sizeof(enc_data[_i].plain_text), enc_data[_i].enc_text, sizeof(enc_data[_i].enc_text));
  ck_assert(res == EXIT_SUCCESS);
}

END_TEST

START_TEST(test_decryption) {
  int res = decryption(dec_data[_i].dec_key, dec_data[_i].counter, dec_data[_i].enc_text,
                       sizeof(dec_data[_i].enc_text), dec_data[_i].plain_text, sizeof(dec_data[_i].plain_text));
  ck_assert(res == EXIT_SUCCESS);
}

END_TEST

START_TEST(test_mac) {
  int res = mac(mac_data[_i].mac_key, mac_data[_i].mac_chain, mac_data[_i].input_text,
                sizeof(mac_data[_i].input_text), mac_data[_i].mac);
  ck_assert(res == EXIT_SUCCESS);
}

END_TEST

static Suite *aes_suite(void) {
  Suite *s;
  TCase *tc;

  s = suite_create("libykpiv aes");
  tc = tcase_create("aes");
  tcase_add_loop_test(tc, test_encryption, 0, sizeof(enc_data) / sizeof(struct enc_test_data));
  tcase_add_loop_test(tc, test_decryption, 0, sizeof(dec_data) / sizeof(struct dec_test_data));
  tcase_add_loop_test(tc, test_mac, 0, sizeof(mac_data) / sizeof(struct mac_test_data));
  suite_add_tcase(s, tc);

  return s;
}


int main(void) {
  int number_failed;
  Suite *s;
  SRunner *sr;

  s = aes_suite();
  sr = srunner_create(s);
  srunner_run_all(sr, CK_NORMAL);
  number_failed = srunner_ntests_failed(sr);
  srunner_free(sr);
  return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
