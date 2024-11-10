/*
 * Copyright (c) 2014-2020 Yubico AB
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
#include "util.h"
#include "../aes_cmac/aes.h"
#include "../../common/openssl-compat.h"
#include "test-config.h"

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <check.h>

#ifdef _WIN32
#define dprintf(fd, ...) fprintf(stdout, __VA_ARGS__)
#endif

// only defined in libcheck 0.11+ (linux distros still shipping 0.10)
#ifndef ck_assert_ptr_nonnull
#define ck_assert_ptr_nonnull(a) ck_assert((a) != NULL)
#endif
#ifndef ck_assert_mem_eq
#define ck_assert_mem_eq(a,b,n) ck_assert(memcmp((a), (b), (n)) == 0)
#endif
// only defined in libcheck 0.10+ (RHEL7 is still shipping 0.9)
#ifndef ck_assert_ptr_eq
#define ck_assert_ptr_eq(a,b) ck_assert((void *)(a) == (void *)(b))
#endif

ykpiv_state *g_state;
const uint8_t g_cert[] = {
  "0123456789ABCDEFGHIK0123456789ABCDEFGHIK0123456789ABCDEFGHIK0123456789ABCDEFGHIK"
  "0123456789ABCDEFGHIK0123456789ABCDEFGHIK0123456789ABCDEFGHIK0123456789ABCDEFGHIK"
  "0123456789ABCDEFGHIK0123456789ABCDEFGHIK0123456789ABCDEFGHIK0123456789ABCDEFGHIK"
  "0123456789ABCDEFGHIK0123456789ABCDEFGHIK0123456789ABCDEFGHIK0123456789ABCDEFGHIK"
  "0123456789ABCDEFGHIK0123456789ABCDEFGHIK0123456789ABCDEFGHIK0123456789ABCDEFGHIK"
};

#if HW_TESTS

static int destruction_confirmed(void) {
  char *confirmed = getenv("YKPIV_ENV_HWTESTS_CONFIRMED");
  if (confirmed && confirmed[0] == '1') {
#ifdef _WIN32
    return 1;
#else
    return system("../../../tools/confirm.sh") == 0;
#endif
  }
  // Use dprintf() to write directly to stdout, since cmake eats the standard stdout/stderr pointers.
  dprintf(0, "\n***\n*** Hardware tests skipped.\n***\n\n");
  return 0;
}

static void setup(void) {
  ykpiv_rc res;

  // Require user confirmation to continue, since this test suite will clear
  // any data stored on connected keys.
  if (!destruction_confirmed())
    exit(77); // exit code 77 == skipped tests

  res = ykpiv_init(&g_state, true);
  ck_assert_int_eq(res, YKPIV_OK);
  ck_assert_ptr_nonnull(g_state);

  res = ykpiv_connect(g_state, NULL);
  ck_assert_int_eq(res, YKPIV_OK);
}

static void teardown(void) {
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
  ykpiv_rc res;
  ykpiv_devmodel model;
  char version[256] = {0};
  char reader_buf[2048] = {0};
  size_t num_readers = sizeof(reader_buf);

  res = ykpiv_get_version(g_state, version, sizeof(version));
  ck_assert_int_eq(res, YKPIV_OK);
  fprintf(stderr, "Version: %s\n", version);
  model = ykpiv_util_devicemodel(g_state);
  fprintf(stdout, "Model: %x\n", model);
  ck_assert(model == DEVTYPE_YK5 || model == DEVTYPE_YK4 || model == DEVTYPE_NEOr3);

  res = ykpiv_list_readers(g_state, reader_buf, &num_readers);
  ck_assert_int_eq(res, YKPIV_OK);
  ck_assert_int_gt(num_readers, 0);
  ck_assert_int_eq(strncmp(reader_buf, "Yubico", 6), 0);
  if (model == DEVTYPE_YK5) {
    ck_assert(version[0] == '5'); // Verify app version 5.x
    ck_assert(version[1] == '.');
  }
  else if (model == DEVTYPE_YK4) {
    ck_assert(version[0] == '4'); // Verify app version 4.x
    ck_assert(version[1] == '.');
  }
  else {
    ck_assert(version[0] == '1'); // Verify app version 1.x
    ck_assert(version[1] == '.');
  }
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
  char reader_buf[2048] = {0};
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
    res = ykpiv_util_write_cert(g_state, YKPIV_KEY_AUTHENTICATION, (uint8_t*)g_cert, sizeof(g_cert), YKPIV_CERTINFO_UNCOMPRESSED);
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
    ck_assert_int_eq(res, YKPIV_INVALID_OBJECT);

    res = ykpiv_util_free(g_state, read_cert);
    ck_assert_int_eq(res, YKPIV_OK);
  }
}
END_TEST

#include <openssl/des.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/rand.h>

// RSA2048 private key, generated with: `openssl genrsa 2048 -out private.pem`
static const char *private_key_pem =
    "-----BEGIN RSA PRIVATE KEY-----\n"
    "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\n"
    "-----END RSA PRIVATE KEY-----\n";

// Certificate signed with key above:
// `openssl req -x509 -key private.pem -out cert.pem -subj "/CN=bar/OU=test/O=example.com/" -new`
static const char *certificate_pem =
    "-----BEGIN CERTIFICATE-----\n"
    "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\n"
    "CuRM0YVggUE4so4=\n"
    "-----END CERTIFICATE-----\n";


static void import_key(unsigned char slot, unsigned char pin_policy) {
  ykpiv_rc res;
  {
    unsigned char pp = pin_policy;
    unsigned char tp = YKPIV_TOUCHPOLICY_DEFAULT;
    EVP_PKEY *private_key = NULL;
    BIO *bio = NULL;
    RSA *rsa_private_key = NULL;
    unsigned char e[3] = {0};
    unsigned char p[256] = {0};
    unsigned char q[256] = {0};
    unsigned char dmp1[256] = {0};
    unsigned char dmq1[256] = {0};
    unsigned char iqmp[256] = {0};
    int element_len = 256;
    const BIGNUM *bn_e, *bn_p, *bn_q, *bn_dmp1, *bn_dmq1, *bn_iqmp;
    int e_len, p_len, q_len, dmp1_len, dmq1_len, iqmp_len;

    bio = BIO_new_mem_buf(private_key_pem, strlen(private_key_pem));
    private_key = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    ck_assert_ptr_nonnull(private_key);
    BIO_free(bio);
    rsa_private_key = EVP_PKEY_get1_RSA(private_key);
    ck_assert_ptr_nonnull(rsa_private_key);
    RSA_get0_key(rsa_private_key, NULL, &bn_e, NULL);
    RSA_get0_factors(rsa_private_key, &bn_p, &bn_q);
    RSA_get0_crt_params(rsa_private_key, &bn_dmp1, &bn_dmq1, &bn_iqmp);
    e_len = sizeof(e);
    ck_assert(set_component(e, bn_e, &e_len));
    p_len = element_len;
    ck_assert(set_component(p, bn_p, &p_len));
    q_len = element_len;
    ck_assert(set_component(q, bn_q, &q_len));
    dmp1_len = element_len;
    ck_assert(set_component(dmp1, bn_dmp1, &dmp1_len));
    dmq1_len = element_len;
    ck_assert(set_component(dmq1, bn_dmq1, &dmq1_len));
    iqmp_len = element_len;
    ck_assert(set_component(iqmp, bn_iqmp, &iqmp_len));

    // Try wrong algorithm, fail.
    res = ykpiv_import_private_key(g_state,
                                   slot,
                                   YKPIV_ALGO_RSA1024,
                                   p, p_len,
                                   q, q_len,
                                   dmp1, dmp1_len,
                                   dmq1, dmq1_len,
                                   iqmp, iqmp_len,
                                   NULL, 0,
                                   pp, tp);
    ck_assert_int_eq(res, YKPIV_ALGORITHM_ERROR);

    // Try right algorithm
    res = ykpiv_import_private_key(g_state,
                                   slot,
                                   YKPIV_ALGO_RSA4096,
                                   p, p_len,
                                   q, q_len,
                                   dmp1, dmp1_len,
                                   dmq1, dmq1_len,
                                   iqmp, iqmp_len,
                                   NULL, 0,
                                   pp, tp);
    ck_assert_int_eq(res, YKPIV_OK);
    RSA_free(rsa_private_key);
    EVP_PKEY_free(private_key);
  }

  // Use imported key to decrypt a thing.  See that it works.
  {
    BIO *bio = NULL;
    X509 *cert = NULL;
    EVP_PKEY *pub_key = NULL;
    unsigned char secret[64] = {0};
    unsigned char secret2[64] = {0};
    unsigned char data[512] = {0};
    int len;
    size_t len2 = sizeof(data);
    RSA *rsa = NULL;
    bio = BIO_new_mem_buf(certificate_pem, strlen(certificate_pem));
    cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    ck_assert_ptr_nonnull(cert);
    BIO_free(bio);
    pub_key = X509_get_pubkey(cert);
    ck_assert_ptr_nonnull(pub_key);
    rsa = EVP_PKEY_get1_RSA(pub_key);
    ck_assert_ptr_nonnull(rsa);
    EVP_PKEY_free(pub_key);

    ck_assert_int_gt(RAND_bytes(secret, sizeof(secret)), 0);
    len = RSA_public_encrypt(sizeof(secret), secret, data, rsa, RSA_PKCS1_PADDING);
    ck_assert_int_ge(len, 0);
    res = ykpiv_verify(g_state, "123456", NULL);
    ck_assert_int_eq(res, YKPIV_OK);
    res = ykpiv_decipher_data(g_state, data, (size_t)len, data, &len2, YKPIV_ALGO_RSA4096, slot);
    ck_assert_int_eq(res, YKPIV_OK);
    len = RSA_padding_check_PKCS1_type_2(secret2, sizeof(secret2), data + 1, len2 - 1, RSA_size(rsa));
    ck_assert_int_eq(len, sizeof(secret));
    ck_assert_int_eq(memcmp(secret, secret2, sizeof(secret)), 0);
    RSA_free(rsa);
    X509_free(cert);
  }
}

START_TEST(test_import_key) {
  ykpiv_rc res;

  import_key(0x9a, YKPIV_PINPOLICY_DEFAULT);

  // Verify certificate
  {
    BIO *bio = NULL;
    X509 *cert = NULL;
    RSA *rsa = NULL;
    EVP_PKEY *pub_key = NULL;
    const EVP_MD *md = EVP_sha256();
    EVP_MD_CTX *mdctx;

    unsigned char signature[2048] = {0};
    unsigned char encoded[2048] = {0};
    unsigned char data[2048] = {0};
    unsigned char signinput[2048] = {0};
    unsigned char rand[128] = {0};

    size_t sig_len = sizeof(signature);
    size_t padlen = 512;
    unsigned int enc_len;
    unsigned int data_len;

    bio = BIO_new_mem_buf(certificate_pem, strlen(certificate_pem));
    cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    ck_assert_ptr_nonnull(cert);
    BIO_free(bio);
    pub_key = X509_get_pubkey(cert);
    ck_assert_ptr_nonnull(pub_key);
    rsa = EVP_PKEY_get1_RSA(pub_key);
    ck_assert_ptr_nonnull(rsa);
    EVP_PKEY_free(pub_key);

    ck_assert_int_gt(RAND_bytes(rand, sizeof(rand)), 0);
    mdctx = EVP_MD_CTX_create();
    EVP_DigestInit_ex(mdctx, md, NULL);
    EVP_DigestUpdate(mdctx, rand, 128);
    EVP_DigestFinal_ex(mdctx, data, &data_len);

    prepare_rsa_signature(data, data_len, encoded, &enc_len, EVP_MD_type(md));
    ck_assert_int_ne(RSA_padding_add_PKCS1_type_1(signinput, padlen, encoded, enc_len), 0);
    res = ykpiv_sign_data(g_state, signinput, padlen, signature, &sig_len, YKPIV_ALGO_RSA4096, 0x9a);
    ck_assert_int_eq(res, YKPIV_OK);

    ck_assert_int_eq(RSA_verify(EVP_MD_type(md), data, data_len, signature, sig_len, rsa), 1);

    RSA_free(rsa);
    X509_free(cert);
    EVP_MD_CTX_destroy(mdctx);
  }

  // Verify that imported key can not be attested
  {
    unsigned char attest[4096] = {0};
    size_t attest_len = sizeof(attest);
    ykpiv_devmodel model;
    model = ykpiv_util_devicemodel(g_state);
    res = ykpiv_attest(g_state, 0x9a, attest, &attest_len);
    if (model != DEVTYPE_NEOr3) {
      ck_assert_int_eq(res, YKPIV_ARGUMENT_ERROR);
    }
    else {
      ck_assert_int_eq(res, YKPIV_NOT_SUPPORTED);
    }
  }
}
END_TEST

START_TEST(test_pin_policy_always) {
  ykpiv_rc res;

  {
    ykpiv_devmodel model;
    model = ykpiv_util_devicemodel(g_state);
    // Only works with YK4.  NEO should skip.
    if (model == DEVTYPE_NEOr3) {
      fprintf(stderr, "WARNING: Not supported with Yubikey NEO.  Test skipped.\n");
      return;
    }
  }

  import_key(0x9e, YKPIV_PINPOLICY_ALWAYS);

  // Verify certificate
  {
    BIO *bio = NULL;
    X509 *cert = NULL;
    RSA *rsa = NULL;
    EVP_PKEY *pub_key = NULL;
    const EVP_MD *md = EVP_sha256();
    EVP_MD_CTX *mdctx;

    unsigned char signature[1024] = {0};
    unsigned char encoded[1024] = {0};
    unsigned char data[1024] = {0};
    unsigned char signinput[1024] = {0};
    unsigned char rand[128] = {0};

    size_t sig_len = sizeof(signature);
    size_t padlen = 256;
    unsigned int enc_len;
    unsigned int data_len;

    bio = BIO_new_mem_buf(certificate_pem, strlen(certificate_pem));
    cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    ck_assert_ptr_nonnull(cert);
    BIO_free(bio);
    pub_key = X509_get_pubkey(cert);
    ck_assert_ptr_nonnull(pub_key);
    rsa = EVP_PKEY_get1_RSA(pub_key);
    ck_assert_ptr_nonnull(rsa);
    EVP_PKEY_free(pub_key);

    ck_assert_int_gt(RAND_bytes(rand, sizeof(rand)), 0);
    mdctx = EVP_MD_CTX_create();
    EVP_DigestInit_ex(mdctx, md, NULL);
    EVP_DigestUpdate(mdctx, rand, 128);
    EVP_DigestFinal_ex(mdctx, data, &data_len);

    prepare_rsa_signature(data, data_len, encoded, &enc_len, EVP_MD_type(md));
    ck_assert_int_ne(RSA_padding_add_PKCS1_type_1(signinput, padlen, encoded, enc_len), 0);

    // Sign without verify: fail
    res = ykpiv_sign_data(g_state, signinput, padlen, signature, &sig_len, YKPIV_ALGO_RSA4096, 0x9e);
    ck_assert_int_eq(res, YKPIV_AUTHENTICATION_ERROR);

    // Sign with verify: pass
    res = ykpiv_verify(g_state, "123456", NULL);
    ck_assert_int_eq(res, YKPIV_OK);
    res = ykpiv_sign_data(g_state, signinput, padlen, signature, &sig_len, YKPIV_ALGO_RSA4096, 0x9e);
    ck_assert_int_eq(res, YKPIV_OK);

    // Sign again without verify: fail
    res = ykpiv_sign_data(g_state, signinput, padlen, signature, &sig_len, YKPIV_ALGO_RSA4096, 0x9e);
    ck_assert_int_eq(res, YKPIV_AUTHENTICATION_ERROR);

    // Sign again with verify: pass
    res = ykpiv_verify(g_state, "123456", NULL);
    ck_assert_int_eq(res, YKPIV_OK);
    res = ykpiv_sign_data(g_state, signinput, padlen, signature, &sig_len, YKPIV_ALGO_RSA4096, 0x9e);
    ck_assert_int_eq(res, YKPIV_OK);

    ck_assert_int_eq(RSA_verify(EVP_MD_type(md), data, data_len, signature, sig_len, rsa), 1);

    RSA_free(rsa);
    X509_free(cert);
    EVP_MD_CTX_destroy(mdctx);
  }
}
END_TEST

START_TEST(test_generate_key) {
  ykpiv_rc res;
  uint8_t *mod, *exp;
  size_t mod_len, exp_len;
  res = ykpiv_util_write_cert(g_state, YKPIV_KEY_AUTHENTICATION, (uint8_t*)g_cert, sizeof(g_cert), YKPIV_CERTINFO_UNCOMPRESSED);
  ck_assert_int_eq(res, YKPIV_OK);
  res = ykpiv_util_generate_key(g_state,
                                YKPIV_KEY_AUTHENTICATION,
                                YKPIV_ALGO_RSA2048,
                                YKPIV_PINPOLICY_DEFAULT,
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

  // Verify that imported key can be attested
  {
    ykpiv_devmodel model;
    unsigned char attest[2048] = {0};
    size_t attest_len = sizeof(attest);
    model = ykpiv_util_devicemodel(g_state);
    res = ykpiv_attest(g_state, YKPIV_KEY_AUTHENTICATION, attest, &attest_len);
    // Only works with YK4.  NEO should error.
    if (model != DEVTYPE_NEOr3) {
      ck_assert_int_eq(res, YKPIV_OK);
      ck_assert_int_gt(attest_len, 0);
    }
    else {
      ck_assert_int_eq(res, YKPIV_NOT_SUPPORTED);
    }
  }
}
END_TEST

static void test_authenticate_helper(bool full) {
  ykpiv_rc res;
  int crc;
  aes_context cipher = {0};
  const char *default_mgm_key = "010203040506070801020304050607080102030405060708";
  const char *mgm_key = "112233445566778811223344556677881122334455667788";
  const char *mgm_key_16 = "11223344556677881122334455667788";
  const char *mgm_key_32 = "1122334455667788112233445566778811223344556677881122334455667788";
  const char *weak_des_key = "FEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFE";
  unsigned char key[32] = {0};
  size_t key_len = sizeof(key);
  unsigned char data[256];
  size_t data_len = sizeof(data);

  // Try default key, succeed
  res = ykpiv_hex_decode(default_mgm_key, strlen(default_mgm_key), key, &key_len);
  ck_assert_int_eq(res, YKPIV_OK);
  res = ykpiv_authenticate(g_state, key);
  ck_assert_int_eq(res, YKPIV_OK);

  if(!full) {
    return;
  }

  // Try new key, fail.
  key_len = sizeof(key);
  res = ykpiv_hex_decode(mgm_key, strlen(mgm_key), key, &key_len);
  ck_assert_int_eq(res, YKPIV_OK);
  res = ykpiv_authenticate(g_state, key);
  ck_assert_int_eq(res, YKPIV_AUTHENTICATION_ERROR);

  // Verify same key works twice
  key_len = sizeof(key);
  res = ykpiv_hex_decode(default_mgm_key, strlen(default_mgm_key), key, &key_len);
  ck_assert_int_eq(res, YKPIV_OK);
  res = ykpiv_authenticate(g_state, key);
  ck_assert_int_eq(res, YKPIV_OK);

  // Change to new key
  key_len = sizeof(key);
  res = ykpiv_hex_decode(mgm_key, strlen(mgm_key), key, &key_len);
  ck_assert_int_eq(res, YKPIV_OK);
  res = ykpiv_set_mgmkey(g_state, key);
  ck_assert_int_eq(res, YKPIV_OK);

  // Try new key, succeed.
  key_len = sizeof(key);
  res = ykpiv_hex_decode(mgm_key, strlen(mgm_key), key, &key_len);
  ck_assert_int_eq(res, YKPIV_OK);
  res = ykpiv_authenticate(g_state, key);
  ck_assert_int_eq(res, YKPIV_OK);

  // Change back to default key
  key_len = sizeof(key);
  res = ykpiv_hex_decode(default_mgm_key, strlen(default_mgm_key), key, &key_len);
  ck_assert_int_eq(res, YKPIV_OK);
  res = ykpiv_set_mgmkey(g_state, key);
  ck_assert_int_eq(res, YKPIV_OK);

  // Try default key, succeed
  key_len = sizeof(key);
  res = ykpiv_hex_decode(default_mgm_key, strlen(default_mgm_key), key, &key_len);
  ck_assert_int_eq(res, YKPIV_OK);
  res = ykpiv_authenticate(g_state, key);
  ck_assert_int_eq(res, YKPIV_OK);

  // Try to set a weak key, fail
  key_len = sizeof(key);
  res = ykpiv_hex_decode(weak_des_key, strlen(weak_des_key), key, &key_len);
  ck_assert_int_eq(res, YKPIV_OK);
  res = ykpiv_set_mgmkey(g_state, key);
  ck_assert_int_eq(res, YKPIV_KEY_ERROR);

  // Try default key, succeed
  key_len = sizeof(key);
  res = ykpiv_hex_decode(default_mgm_key, strlen(default_mgm_key), key, &key_len);
  ck_assert_int_eq(res, YKPIV_OK);
  res = ykpiv_authenticate(g_state, key);
  ck_assert_int_eq(res, YKPIV_OK);

  // Test external auth
  data_len = sizeof(data);
  ykpiv_metadata metadata = {0};
  res = ykpiv_auth_getchallenge(g_state, &metadata, data, &data_len);
  ck_assert_int_eq(res, YKPIV_OK);

  crc = aes_set_key(key, key_len, YKPIV_ALGO_3DES, &cipher);
  ck_assert_int_eq(crc, 0);
  uint32_t cipher_len = (uint32_t)data_len;
  crc = aes_encrypt(data, cipher_len, data, &cipher_len, &cipher);
  data_len = cipher_len;
  ck_assert_int_eq(crc, 0);
  crc = aes_destroy(&cipher);
  ck_assert_int_eq(crc, 0);

  res = ykpiv_auth_verifyresponse(g_state, &metadata, data, data_len);
  ck_assert_int_eq(res, YKPIV_OK);

  // Metadata support implies AES support for YKPIV_KEY_CARDMGM
  data_len = sizeof(data);
  res = ykpiv_get_metadata(g_state, YKPIV_KEY_CARDMGM, data, &data_len);
  if(YKPIV_OK == res) {
    // AES 128 key
    key_len = sizeof(key);
    res = ykpiv_hex_decode(mgm_key_16, strlen(mgm_key_16), key, &key_len);
    ck_assert_int_eq(res, YKPIV_OK);
    res = ykpiv_set_mgmkey3(g_state, key, key_len, YKPIV_ALGO_AES128, YKPIV_TOUCHPOLICY_DEFAULT);
    ck_assert_int_eq(res, YKPIV_OK);
    res = ykpiv_authenticate2(g_state, key, key_len);
    ck_assert_int_eq(res, YKPIV_OK);

    // AES 192 key
    key_len = sizeof(key);
    res = ykpiv_hex_decode(mgm_key, strlen(mgm_key), key, &key_len);
    ck_assert_int_eq(res, YKPIV_OK);
    res = ykpiv_set_mgmkey3(g_state, key, key_len, YKPIV_ALGO_AES192, YKPIV_TOUCHPOLICY_DEFAULT);
    ck_assert_int_eq(res, YKPIV_OK);
    res = ykpiv_authenticate2(g_state, key, key_len);
    ck_assert_int_eq(res, YKPIV_OK);

    // AES 256 key
    key_len = sizeof(key);
    res = ykpiv_hex_decode(mgm_key_32, strlen(mgm_key_32), key, &key_len);
    ck_assert_int_eq(res, YKPIV_OK);
    res = ykpiv_set_mgmkey3(g_state, key, key_len, YKPIV_ALGO_AES256, YKPIV_TOUCHPOLICY_DEFAULT);
    ck_assert_int_eq(res, YKPIV_OK);
    res = ykpiv_authenticate2(g_state, key, key_len);
    ck_assert_int_eq(res, YKPIV_OK);

    // A weak DES key should work fine as an AES 192 key
    key_len = sizeof(key);
    res = ykpiv_hex_decode(weak_des_key, strlen(weak_des_key), key, &key_len);
    ck_assert_int_eq(res, YKPIV_OK);
    res = ykpiv_set_mgmkey3(g_state, key, key_len, YKPIV_ALGO_AES192, YKPIV_TOUCHPOLICY_DEFAULT);
    ck_assert_int_eq(res, YKPIV_OK);
    res = ykpiv_authenticate2(g_state, key, key_len);
    ck_assert_int_eq(res, YKPIV_OK);

    // Default mgm key should work fine as an AES 192 key
    key_len = sizeof(key);
    res = ykpiv_hex_decode(default_mgm_key, strlen(default_mgm_key), key, &key_len);
    ck_assert_int_eq(res, YKPIV_OK);
    res = ykpiv_set_mgmkey3(g_state, key, key_len, YKPIV_ALGO_AES192, YKPIV_TOUCHPOLICY_DEFAULT);
    ck_assert_int_eq(res, YKPIV_OK);
    res = ykpiv_authenticate2(g_state, key, key_len);
    ck_assert_int_eq(res, YKPIV_OK);

    // Restore default 3DES mgmt key
    key_len = sizeof(key);
    res = ykpiv_hex_decode(default_mgm_key, strlen(default_mgm_key), key, &key_len);
    ck_assert_int_eq(res, YKPIV_OK);
    res = ykpiv_set_mgmkey3(g_state, key, key_len, YKPIV_ALGO_3DES, YKPIV_TOUCHPOLICY_DEFAULT);
    ck_assert_int_eq(res, YKPIV_OK);
    res = ykpiv_authenticate2(g_state, key, key_len);
    ck_assert_int_eq(res, YKPIV_OK);
  } else {
    fprintf(stderr, "Device does not support metadata. AES MGMT key tests skipped.\n");
  }
}

START_TEST(test_authenticate) {
  test_authenticate_helper(true);
}
END_TEST

START_TEST(test_change_pin) {
  ykpiv_rc res;

  res = ykpiv_verify(g_state, "123456", NULL);
  ck_assert_int_eq(res, YKPIV_OK);

  res = ykpiv_change_pin(g_state, "123456", 6, "ABCDEF", 6, NULL);
  ck_assert_int_eq(res, YKPIV_OK);

  res = ykpiv_verify(g_state, "123456", NULL);
  ck_assert_int_eq(res, YKPIV_WRONG_PIN);

  res = ykpiv_verify(g_state, "ABCDEF", NULL);
  ck_assert_int_eq(res, YKPIV_OK);

  res = ykpiv_change_pin(g_state, "ABCDEF", 6, "123456", 6, NULL);
  ck_assert_int_eq(res, YKPIV_OK);

  res = ykpiv_verify(g_state, "ABCDEF", NULL);
  ck_assert_int_eq(res, YKPIV_WRONG_PIN);

  res = ykpiv_verify(g_state, "123456", NULL);
  ck_assert_int_eq(res, YKPIV_OK);
}
END_TEST

START_TEST(test_change_puk) {
  ykpiv_rc res;

  res = ykpiv_unblock_pin(g_state, "12345678", 8, "123456", 6, NULL);
  ck_assert_int_eq(res, YKPIV_OK);

  res = ykpiv_change_puk(g_state, "12345678", 8, "ABCDEFGH", 8, NULL);
  ck_assert_int_eq(res, YKPIV_OK);

  res = ykpiv_unblock_pin(g_state, "12345678", 8, "123456", 6, NULL);
  ck_assert_int_eq(res, YKPIV_WRONG_PIN);

  res = ykpiv_unblock_pin(g_state, "ABCDEFGH", 8, "123456", 6, NULL);
  ck_assert_int_eq(res, YKPIV_OK);

  res = ykpiv_change_puk(g_state, "ABCDEFGH", 8, "12345678", 8, NULL);
  ck_assert_int_eq(res, YKPIV_OK);

  res = ykpiv_unblock_pin(g_state, "ABCDEFGH", 8, "123456", 6, NULL);
  ck_assert_int_eq(res, YKPIV_WRONG_PIN);

  res = ykpiv_unblock_pin(g_state, "12345678", 8, "123456", 6, NULL);
  ck_assert_int_eq(res, YKPIV_OK);
}
END_TEST

static int block_and_reset() {
  ykpiv_rc res;
  int tries = 100;
  int tries_until_blocked;

  tries_until_blocked = 0;
  while (tries) {
    res = ykpiv_verify(g_state, "AAAAAA", &tries);
    tries_until_blocked++;
    if (res == YKPIV_PIN_LOCKED)
      break;
    ck_assert_int_eq(res, YKPIV_WRONG_PIN);
  }

  // Verify no PIN retries remaining
  tries = 100;
  res = ykpiv_get_pin_retries(g_state, &tries);
  ck_assert_int_eq(res, YKPIV_OK);
  ck_assert_int_eq(tries, 0);

  tries = 100;
  while (tries) {
    res = ykpiv_change_puk(g_state, "AAAAAAAA", 8, "AAAAAAAA", 8, &tries);
    if (res == YKPIV_PIN_LOCKED)
      break;
    ck_assert_int_eq(res, YKPIV_WRONG_PIN);
  }
  res = ykpiv_util_reset(g_state);
  ck_assert_int_eq(res, YKPIV_OK);
  return tries_until_blocked;
}

START_TEST(test_reset) {
  ykpiv_rc res;
  int tries = 100;
  int tries_until_blocked;
  ykpiv_devmodel model;
  model = ykpiv_util_devicemodel(g_state);

  // Block and reset, with default PIN retries
  tries_until_blocked = block_and_reset();
  ck_assert_int_eq(tries_until_blocked, 3);

  // Authenticate and increase PIN retries
  test_authenticate_helper(false);
  res = ykpiv_verify(g_state, "123456", &tries);
  ck_assert_int_eq(res, YKPIV_OK);
  ck_assert_int_eq(tries, -1);
  res = ykpiv_set_pin_retries(g_state, 8, 3);
  ck_assert_int_eq(res, YKPIV_OK);

  // Block and reset again, verifying increased PIN retries
  tries_until_blocked = block_and_reset();
  ck_assert_int_eq(tries_until_blocked, 8);
  // Note: defaults back to 3 retries after reset

  // Verify default (3) PIN retries remaining
  tries = 0;
  res = ykpiv_get_pin_retries(g_state, &tries);
  ck_assert_int_eq(res, YKPIV_OK);
  ck_assert_int_eq(tries, 3);

  // Verify still (3) PIN retries remaining
  tries = 0;
  res = ykpiv_get_pin_retries(g_state, &tries);
  ck_assert_int_eq(res, YKPIV_OK);
  ck_assert_int_eq(tries, 3);

  // Try wrong PIN
  res = ykpiv_verify(g_state, "AAAAAA", &tries);
  ck_assert_int_eq(res, YKPIV_WRONG_PIN);
  ck_assert_int_eq(tries, 2);

  // Verify 2 PIN retries remaining
  tries = 0;
  res = ykpiv_get_pin_retries(g_state, &tries);
  ck_assert_int_eq(res, YKPIV_OK);
  ck_assert_int_eq(tries, 2);

  // Verify correct PIN
  tries = 100;
  res = ykpiv_verify(g_state, "123456", &tries);
  ck_assert_int_eq(res, YKPIV_OK);
  ck_assert_int_eq(tries, -1);

  // Verify back to 3 PIN retries remaining
  tries = 0;
  res = ykpiv_get_pin_retries(g_state, &tries);
  ck_assert_int_eq(res, YKPIV_OK);
  if(model == DEVTYPE_NEO || model == DEVTYPE_NEOr3) {
    ck_assert_int_eq(tries, 0);
  } else {
    ck_assert_int_eq(tries, 3);
  }
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

static uint8_t *alloc_auth_cert() {
  ykpiv_rc res;
  uint8_t *read_cert = NULL;
  size_t read_cert_len = 0;

  res = ykpiv_util_write_cert(g_state, YKPIV_KEY_AUTHENTICATION, (uint8_t*)g_cert, sizeof(g_cert), YKPIV_CERTINFO_UNCOMPRESSED);
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
  test_authenticate_helper(false);
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

START_TEST(test_pin_cache) {
  ykpiv_rc res;
  ykpiv_state *local_state;
  unsigned char data[256] = {0};
  unsigned char data_in[256] = {0};
  int len = sizeof(data);
  size_t len2 = sizeof(data);

  import_key(0x9a, YKPIV_PINPOLICY_DEFAULT);

  // Disconnect and reconnect to device to guarantee it is not authed
  res = ykpiv_disconnect(g_state);
  ck_assert_int_eq(res, YKPIV_OK);
  res = ykpiv_done(g_state);
  ck_assert_int_eq(res, YKPIV_OK);
  res = ykpiv_init(&g_state, true);
  ck_assert_int_eq(res, YKPIV_OK);
  ck_assert_ptr_nonnull(g_state);
  res = ykpiv_connect(g_state, NULL);
  ck_assert_int_eq(res, YKPIV_OK);

  // Verify decryption does not work without auth
  res = ykpiv_decipher_data(g_state, data_in, (size_t)len, data, &len2, YKPIV_ALGO_RSA2048, 0x9a);
  ck_assert_int_eq(res, YKPIV_AUTHENTICATION_ERROR);

  // Verify decryption does work when authed
  res = ykpiv_verify_select(g_state, "123456", 6, NULL, true);
  ck_assert_int_eq(res, YKPIV_OK);
  res = ykpiv_decipher_data(g_state, data_in, (size_t)len, data, &len2, YKPIV_ALGO_RSA2048, 0x9a);
  ck_assert_int_eq(res, YKPIV_OK);

  // Verify PIN policy allows continuing to decrypt without re-verifying
  res = ykpiv_decipher_data(g_state, data_in, (size_t)len, data, &len2, YKPIV_ALGO_RSA2048, 0x9a);
  ck_assert_int_eq(res, YKPIV_OK);

  // Create a new ykpiv state, connect, and close it.
  // This forces a card reset from another context, so the original global
  // context will require a reconnect for its next transaction.
  res = ykpiv_init(&local_state, true);
  ck_assert_int_eq(res, YKPIV_OK);
  ck_assert_ptr_nonnull(local_state);
  res = ykpiv_connect(local_state, NULL);
  ck_assert_int_eq(res, YKPIV_OK);
  res = ykpiv_disconnect(local_state);
  ck_assert_int_eq(res, YKPIV_OK);
  res = ykpiv_done(local_state);
  ck_assert_int_eq(res, YKPIV_OK);

  // Verify we are still authenticated on the global context.  This will
  // require an automatic  reconnect and re-verify with the cached PIN.
  //
  // Note that you can verify that this fails by rebuilding with
  // DISABLE_PIN_CACHE set to 1.
  res = ykpiv_decipher_data(g_state, data_in, (size_t)len, data, &len2, YKPIV_ALGO_RSA2048, 0x9a);
  ck_assert_int_eq(res, YKPIV_OK);
}
END_TEST
#endif

static Suite *test_suite(void) {
  Suite *s;
  TCase *tc;

  s = suite_create("libykpiv api");
  tc = tcase_create("api");
#if HW_TESTS
  tcase_add_unchecked_fixture(tc, setup, teardown);

  // Must be first: Reset device.  Tests run serially, and depend on a clean slate.
  tcase_add_test(tc, test_reset);

  // Authenticate after reset.
  tcase_add_test(tc, test_authenticate);

  // Test API functionality
  tcase_add_test(tc, test_change_pin);
  tcase_add_test(tc, test_change_puk);
  tcase_add_test(tc, test_devicemodel);
  tcase_add_test(tc, test_get_set_cardid);
  tcase_add_test(tc, test_list_readers);
  tcase_add_test(tc, test_read_write_list_delete_cert);
  tcase_add_test(tc, test_import_key);
  tcase_add_test(tc, test_pin_policy_always);
  tcase_add_test(tc, test_generate_key);
  tcase_add_test(tc, test_pin_cache);

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
