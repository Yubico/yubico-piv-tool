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
#include "../../tool/openssl-compat.h"

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <check.h>

#ifdef __MINGW32__
#define dprintf(fd, ...) fprintf(stdout, __VA_ARGS__)
#endif

int destruction_confirmed(void);

// only defined in libcheck 0.11+ (linux distros still shipping 0.10)
#ifndef ck_assert_ptr_nonnull
#define ck_assert_ptr_nonnull(a) ck_assert((a) != NULL)
#endif
#ifndef ck_assert_mem_eq
#define ck_assert_mem_eq(a,b,n) ck_assert(memcmp((a), (b), (n)) == 0)
#endif

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
  if (!destruction_confirmed())
    exit(77); // exit code 77 == skipped tests

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
  ykpiv_rc res;
  ykpiv_devmodel model;
  char version[256];
  char reader_buf[2048];
  size_t num_readers = sizeof(reader_buf);

  res = ykpiv_get_version(g_state, version, sizeof(version));
  ck_assert_int_eq(res, YKPIV_OK);
  fprintf(stderr, "Version: %s\n", version);
  model = ykpiv_util_devicemodel(g_state);
  fprintf(stdout, "Model: %u\n", model);
  ck_assert(model == DEVTYPE_YK4 || model == DEVTYPE_NEOr3);

  res = ykpiv_list_readers(g_state, reader_buf, &num_readers);
  ck_assert_int_eq(res, YKPIV_OK);
  ck_assert_int_gt(num_readers, 0);
  if (model == DEVTYPE_YK4) {
    ck_assert_ptr_nonnull(strstr(reader_buf, "Yubikey 4"));
    ck_assert(version[0] == '4'); // Verify app version 4.x
    ck_assert(version[1] == '.');
  }
  else {
    ck_assert_ptr_nonnull(strstr(reader_buf, "Yubikey NEO"));
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
    ck_assert_int_eq(res, YKPIV_GENERIC_ERROR);

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
  "MIIEpAIBAAKCAQEAwVUwmVbc+ffOy2+RivxBpgleTVN6bUa0q7jNYB+AseFQYaYq\n"
  "EGfa+VGdxSGo+8DV1KT9+fNEd5243gXn/tcjtMItKeB+oAQc64s9lIFlYuR8bpq1\n"
  "ibr33iW2elnnv9mpecqohdCVwM2McWveoPyb7MwlwVuhqexOzJO29bqJcazLbtkf\n"
  "ZETK0oBx53/ylA4Y6nE9Pa46jW2qhj+KShf1iBg+gAyt3eI+wI2Wmub1WxLLH8D2\n"
  "w+kow8QhQOa8dHCkRRw771JxVO5+d+Y/Y+x9B1HgF4q0q9xUlhWLK2TR4ChBFzXe\n"
  "47sAHsSqi/pl5JbwYrHPOE/VEBLukmjL8NFCSQIDAQABAoIBADmEyOK2DyRnb6Ti\n"
  "2qBJEJb/boj+7wuX36S/ZIrWlIlXiXyj3RvoaiOG/rNpokbURknvlIhKsfIMgLW9\n"
  "eBo/k6Xxp1IwMjwVPS1uzbFjFfDoHYUijiQd9iSnf7TDDsnrThqoCp9VQViNTt1n\n"
  "xGKNBS7cRddTFbPiVEdVIzfUeZPR2oRrc4maBCRCrQgg8WNknawmc8zhkf2NiPj3\n"
  "tWLQHMy1/MgW2W1LM9sgzllEtS5CZUnyGy2HbbhS2tbZ6j9kPzOp0pPxxTTzJmmV\n"
  "fi1vkJcVW4+MdXjWmhALcPA4dO7Y2Ljiu6VxIxQORRO1DyiCjAs1AVMQxgPAAY41\n"
  "YR4Q2EkCgYEA4zE0oytg97aVaBY9CKi7/PqR+NI/uEvfoQCnT+ddaJgp/qsspuXo\n"
  "tJt94p13ANd8O7suqQTVNvbZq1rX10xQjJZ9nvlqQa6iHkN6Epq31XBK3Z+acjIV\n"
  "A2rAgKBByjz9/CpKHqnOsrTWU1Y7x416IG4BZt42hHdrxRH98/wiDH8CgYEA2djj\n"
  "AjwgK+MwDnshwT1NNgCSP/2ZHatBAykZ5BCs9BJ6MNYqqXVGYoqs5Z5kSkow+Db3\n"
  "pipkEieo5w2Rd5zkolTThaVCvRkSe5wRiBpZhaeY+b0UFwavGCb6zU/MmJIMDPiI\n"
  "2iRGeCXgQDvIS/icIqzbTtp6dZaoMgG7LdSR7TcCgYBtxGhaLas8A8tL7vKuLFgn\n"
  "cij0vyBqOr5hW596y54l2t7vXGTGfm5gVIAN7WaB0ZsEgPuaTet2Eu44DDwcmZKR\n"
  "WmR3Wqor8eQCGzfvpTEMvqRtT5+fbPMaI4m+m68ttyo/m28UQZbMYPLscM2RLJnE\n"
  "8WFcAiD0/33iST8ZksggoQKBgQDE/7Yhsj+hkHxHzB+1QPtOp2uaBHnvc4uCESwB\n"
  "qvbMbN0kxrejsJLqz98UcozdBYSNIiAHmvQN2uGJuCJhGXdEORNjGxRkLoUhVPwh\n"
  "qTplfC8BQHQncnrqi21oNw6ctg3BuQsAwaccRZwqWiWCVhrT3J8iCr6NEaWeOySK\n"
  "iF1CNwKBgQCRpkkZArlccwS0kMvkK+tQ1rG2xWm7c05G34gP/g6dHFRy0gPNMyvi\n"
  "SkiLTJmQIEZSAEiq0FFgcVwM6o556ftvQZuwDp5rHUbwqnHCpMJKpD9aJpStvfPi\n"
  "4p9JbYdaGqnq4eoNKemmGnbUof0dR9Zr0lGmcMTwwzBib+4E1d7soA==\n"
  "-----END RSA PRIVATE KEY-----\n";

// Certificate signed with key above:
// `openssl req -x509 -key private.pem -out cert.pem -subj "/CN=bar/OU=test/O=example.com/" -new`
static const char *certificate_pem =
  "-----BEGIN CERTIFICATE-----\n"
  "MIIC5zCCAc+gAwIBAgIJAOq8A/cmpxF5MA0GCSqGSIb3DQEBCwUAMDMxDDAKBgNV\n"
  "BAMMA2JhcjENMAsGA1UECwwEdGVzdDEUMBIGA1UECgwLZXhhbXBsZS5jb20wHhcN\n"
  "MTcwODAzMTE1MDI2WhcNMTgwODAzMTE1MDI2WjAzMQwwCgYDVQQDDANiYXIxDTAL\n"
  "BgNVBAsMBHRlc3QxFDASBgNVBAoMC2V4YW1wbGUuY29tMIIBIjANBgkqhkiG9w0B\n"
  "AQEFAAOCAQ8AMIIBCgKCAQEAwVUwmVbc+ffOy2+RivxBpgleTVN6bUa0q7jNYB+A\n"
  "seFQYaYqEGfa+VGdxSGo+8DV1KT9+fNEd5243gXn/tcjtMItKeB+oAQc64s9lIFl\n"
  "YuR8bpq1ibr33iW2elnnv9mpecqohdCVwM2McWveoPyb7MwlwVuhqexOzJO29bqJ\n"
  "cazLbtkfZETK0oBx53/ylA4Y6nE9Pa46jW2qhj+KShf1iBg+gAyt3eI+wI2Wmub1\n"
  "WxLLH8D2w+kow8QhQOa8dHCkRRw771JxVO5+d+Y/Y+x9B1HgF4q0q9xUlhWLK2TR\n"
  "4ChBFzXe47sAHsSqi/pl5JbwYrHPOE/VEBLukmjL8NFCSQIDAQABMA0GCSqGSIb3\n"
  "DQEBCwUAA4IBAQCamrwdEhNmY2GCQWq6U90Q3XQT6w0HHW/JmtuGeF+BTpVr12gN\n"
  "/UvEXTo9geWbGcCTjaMMURTa7mUjVUIttIWEVHZMKqBuvsUM1RcuOEX/vitaJJ8K\n"
  "Sw4upjCNa3ZxUXmSA1FBixZgDzFqjEeSiaJjMU0yX5W2p1T4iNYtF3YqzMF5AWSI\n"
  "qCO7gP5ezPyg5kDnrO3V7DBgnDiqawq7Pyn9DynKNULX/hc1yls/R+ebb2u8Z+h5\n"
  "W4YXbzGZb8qdT27qIZaHD638tL6liLkI6UE4KCXH8X8e3fqdbmqvwrq403nOGmsP\n"
  "cbJb2PEXibNEQG234riKxm7x7vNDLL79Jwtc\n"
  "-----END CERTIFICATE-----\n";

static bool set_component(unsigned char *in_ptr, const BIGNUM *bn, int element_len) {
  int real_len = BN_num_bytes(bn);

  if(real_len > element_len) {
    return false;
  }
  memset(in_ptr, 0, (size_t)(element_len - real_len));
  in_ptr += element_len - real_len;
  BN_bn2bin(bn, in_ptr);

  return true;
}

static bool prepare_rsa_signature(const unsigned char *in, unsigned int in_len, unsigned char *out, unsigned int *out_len, int nid) {
  X509_SIG *digestInfo;
  X509_ALGOR *algor;
  ASN1_TYPE parameter;
  ASN1_OCTET_STRING *digest;
  unsigned char data[1024];

  memcpy(data, in, in_len);

  digestInfo = X509_SIG_new();
  X509_SIG_getm(digestInfo, &algor, &digest);
  algor->algorithm = OBJ_nid2obj(nid);
  X509_ALGOR_set0(algor, OBJ_nid2obj(nid), V_ASN1_NULL, NULL);
  ASN1_STRING_set(digest, data, in_len);
  *out_len = (unsigned int)i2d_X509_SIG(digestInfo, &out);
  X509_SIG_free(digestInfo);
  return true;
}

static void import_key(unsigned char slot, unsigned char pin_policy) {
  ykpiv_rc res;
  {
    unsigned char pp = pin_policy;
    unsigned char tp = YKPIV_TOUCHPOLICY_DEFAULT;
    EVP_PKEY *private_key = NULL;
    BIO *bio = NULL;
    RSA *rsa_private_key = NULL;
    unsigned char e[4];
    unsigned char p[128];
    unsigned char q[128];
    unsigned char dmp1[128];
    unsigned char dmq1[128];
    unsigned char iqmp[128];
    int element_len = 128;
    const BIGNUM *bn_e, *bn_p, *bn_q, *bn_dmp1, *bn_dmq1, *bn_iqmp;

    bio = BIO_new_mem_buf(private_key_pem, strlen(private_key_pem));
    private_key = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    ck_assert_ptr_nonnull(private_key);
    BIO_free(bio);
    rsa_private_key = EVP_PKEY_get1_RSA(private_key);
    ck_assert_ptr_nonnull(rsa_private_key);
    RSA_get0_key(rsa_private_key, NULL, &bn_e, NULL);
    RSA_get0_factors(rsa_private_key, &bn_p, &bn_q);
    RSA_get0_crt_params(rsa_private_key, &bn_dmp1, &bn_dmq1, &bn_iqmp);
    ck_assert(set_component(e, bn_e, 3));
    ck_assert(set_component(p, bn_p, element_len));
    ck_assert(set_component(q, bn_q, element_len));
    ck_assert(set_component(dmp1, bn_dmp1, element_len));
    ck_assert(set_component(dmq1, bn_dmq1, element_len));
    ck_assert(set_component(iqmp, bn_iqmp, element_len));

    // Try wrong algorithm, fail.
    res = ykpiv_import_private_key(g_state,
                                   slot,
                                   YKPIV_ALGO_RSA1024,
                                   p, element_len,
                                   q, element_len,
                                   dmp1, element_len,
                                   dmq1, element_len,
                                   iqmp, element_len,
                                   NULL, 0,
                                   pp, tp);
    ck_assert_int_eq(res, YKPIV_ALGORITHM_ERROR);

    // Try right algorithm
    res = ykpiv_import_private_key(g_state,
                                   slot,
                                   YKPIV_ALGO_RSA2048,
                                   p, element_len,
                                   q, element_len,
                                   dmp1, element_len,
                                   dmq1, element_len,
                                   iqmp, element_len,
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
    unsigned char secret[32];
    unsigned char secret2[32];
    unsigned char data[256];
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
    res = ykpiv_decipher_data(g_state, data, (size_t)len, data, &len2, YKPIV_ALGO_RSA2048, slot);
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

    unsigned char signature[1024];
    unsigned char encoded[1024];
    unsigned char data[1024];
    unsigned char signinput[1024];
    unsigned char rand[128];

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

    ck_assert_int_gt(RAND_bytes(rand, 128), 0);
    mdctx = EVP_MD_CTX_create();
    EVP_DigestInit_ex(mdctx, md, NULL);
    EVP_DigestUpdate(mdctx, rand, 128);
    EVP_DigestFinal_ex(mdctx, data, &data_len);

    prepare_rsa_signature(data, data_len, encoded, &enc_len, EVP_MD_type(md));
    ck_assert_int_ne(RSA_padding_add_PKCS1_type_1(signinput, padlen, encoded, enc_len), 0);
    res = ykpiv_sign_data(g_state, signinput, padlen, signature, &sig_len, YKPIV_ALGO_RSA2048, 0x9a);
    ck_assert_int_eq(res, YKPIV_OK);

    ck_assert_int_eq(RSA_verify(EVP_MD_type(md), data, data_len, signature, sig_len, rsa), 1);

    RSA_free(rsa);
    X509_free(cert);
    EVP_MD_CTX_destroy(mdctx);
  }

  // Verify that imported key can not be attested
  {
    unsigned char attest[2048];
    size_t attest_len = sizeof(attest);
    ykpiv_devmodel model;
    model = ykpiv_util_devicemodel(g_state);
    res = ykpiv_attest(g_state, 0x9a, attest, &attest_len);
    if (model == DEVTYPE_YK4) {
      ck_assert_int_eq(res, YKPIV_GENERIC_ERROR);
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
    if (model != DEVTYPE_YK4) {
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

    unsigned char signature[1024];
    unsigned char encoded[1024];
    unsigned char data[1024];
    unsigned char signinput[1024];
    unsigned char rand[128];

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

    ck_assert_int_gt(RAND_bytes(rand, 128), 0);
    mdctx = EVP_MD_CTX_create();
    EVP_DigestInit_ex(mdctx, md, NULL);
    EVP_DigestUpdate(mdctx, rand, 128);
    EVP_DigestFinal_ex(mdctx, data, &data_len);

    prepare_rsa_signature(data, data_len, encoded, &enc_len, EVP_MD_type(md));
    ck_assert_int_ne(RSA_padding_add_PKCS1_type_1(signinput, padlen, encoded, enc_len), 0);

    // Sign without verify: fail
    res = ykpiv_sign_data(g_state, signinput, padlen, signature, &sig_len, YKPIV_ALGO_RSA2048, 0x9e);
    ck_assert_int_eq(res, YKPIV_AUTHENTICATION_ERROR);

    // Sign with verify: pass
    res = ykpiv_verify(g_state, "123456", NULL);
    ck_assert_int_eq(res, YKPIV_OK);
    res = ykpiv_sign_data(g_state, signinput, padlen, signature, &sig_len, YKPIV_ALGO_RSA2048, 0x9e);
    ck_assert_int_eq(res, YKPIV_OK);

    // Sign again without verify: fail
    res = ykpiv_sign_data(g_state, signinput, padlen, signature, &sig_len, YKPIV_ALGO_RSA2048, 0x9e);
    ck_assert_int_eq(res, YKPIV_AUTHENTICATION_ERROR);

    // Sign again with verify: pass
    res = ykpiv_verify(g_state, "123456", NULL);
    ck_assert_int_eq(res, YKPIV_OK);
    res = ykpiv_sign_data(g_state, signinput, padlen, signature, &sig_len, YKPIV_ALGO_RSA2048, 0x9e);
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
    unsigned char attest[2048];
    size_t attest_len = sizeof(attest);
    model = ykpiv_util_devicemodel(g_state);
    res = ykpiv_attest(g_state, YKPIV_KEY_AUTHENTICATION, attest, &attest_len);
    // Only works with YK4.  NEO should error.
    if (model == DEVTYPE_YK4) {
      ck_assert_int_eq(res, YKPIV_OK);
      ck_assert_int_gt(attest_len, 0);
    }
    else {
      ck_assert_int_eq(res, YKPIV_NOT_SUPPORTED);
    }
  }
}
END_TEST

START_TEST(test_authenticate) {
  ykpiv_rc res;
  const char *default_mgm_key = "010203040506070801020304050607080102030405060708";
  const char *mgm_key = "112233445566778811223344556677881122334455667788";
  const char *weak_mgm_key = "FEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFE";
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

  // Verify same key works twice
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

  // Try to set a weak key, fail
  res = ykpiv_hex_decode(weak_mgm_key, strlen(weak_mgm_key), key, &key_len);
  ck_assert_int_eq(res, YKPIV_OK);
  res = ykpiv_set_mgmkey(g_state, key);
  ck_assert_int_eq(res, YKPIV_KEY_ERROR);

  // Try default key, succeed
  res = ykpiv_hex_decode(default_mgm_key, strlen(default_mgm_key), key, &key_len);
  ck_assert_int_eq(res, YKPIV_OK);
  res = ykpiv_authenticate(g_state, key);
  ck_assert_int_eq(res, YKPIV_OK);
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
    if (res == YKPIV_PIN_LOCKED)
      break;
    ck_assert_int_eq(res, YKPIV_WRONG_PIN);
    tries_until_blocked++;
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

  // Block and reset, with default PIN retries
  tries_until_blocked = block_and_reset();
  ck_assert_int_eq(tries_until_blocked, 3);

  // Authenticate and increase PIN retries
  test_authenticate(0);
  res = ykpiv_verify(g_state, "123456", NULL);
  ck_assert_int_eq(res, YKPIV_OK);
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

  // Verify 2 PIN retries remaining
  tries = 0;
  res = ykpiv_get_pin_retries(g_state, &tries);
  ck_assert_int_eq(res, YKPIV_OK);
  ck_assert_int_eq(tries, 2);

  // Verify correct PIN
  tries = 100;
  res = ykpiv_verify(g_state, "123456", &tries);
  ck_assert_int_eq(res, YKPIV_OK);

  // Verify back to 3 PIN retries remaining
  tries = 0;
  res = ykpiv_get_pin_retries(g_state, &tries);
  ck_assert_int_eq(res, YKPIV_OK);
  ck_assert_int_eq(tries, 3);
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

START_TEST(test_pin_cache) {
  ykpiv_rc res;
  ykpiv_state *local_state;
  unsigned char data[256];
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

int destruction_confirmed(void) {
  char *confirmed = getenv("YKPIV_ENV_HWTESTS_CONFIRMED");
  if (confirmed && confirmed[0] == '1')
    return 1;
  // Use dprintf() to write directly to stdout, since automake eats the standard stdout/stderr pointers.
  dprintf(0, "\n***\n*** Hardware tests skipped.  Run \"make hwcheck\".\n***\n\n");
  return 0;
}

Suite *test_suite(void) {
  Suite *s;
  TCase *tc;

  s = suite_create("libykpiv api");
  tc = tcase_create("api");
#ifdef HW_TESTS
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
