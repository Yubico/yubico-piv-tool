/*
 * Copyright (c) 2015-2016 Yubico AB
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

#include "../../tool/openssl-compat.h"
#include <ykcs11.h>
#include <ykcs11-version.h>

#include <string.h>

#include <openssl/rsa.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/x509.h>
#include <openssl/rand.h>

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wpointer-sign"

#ifdef __MINGW32__
#define dprintf(fd, ...) fprintf(stdout, __VA_ARGS__)
#endif

void dump_hex(const unsigned char *buf, unsigned int len, FILE *output, int space) {
  unsigned int i;
  for (i = 0; i < len; i++) {
    fprintf(output, "%02x%s", buf[i], space == 1 ? " " : "");
  }
  fprintf(output, "\n");
}

CK_FUNCTION_LIST_PTR funcs;

#define asrt(c, e, m) _asrt(__LINE__, c, e, m);

static void _asrt(int line, CK_ULONG check, CK_ULONG expected, CK_CHAR_PTR msg) {

  if (check == expected)
    return;

  fprintf(stderr, "<%s>:%d check failed with value %lu (0x%lx), expected %lu (0x%lx)\n",
          msg, line, check, check, expected, expected);

  exit(EXIT_FAILURE);

}

static void get_functions(CK_FUNCTION_LIST_PTR_PTR funcs) {

  if (C_GetFunctionList(funcs) != CKR_OK) {
    fprintf(stderr, "Get function list failed\n");
    exit(EXIT_FAILURE);
  }

}

static void test_lib_info() {

  const CK_CHAR_PTR MANUFACTURER_ID    = "Yubico (www.yubico.com)";
  const CK_CHAR_PTR YKCS11_DESCRIPTION = "PKCS#11 PIV Library (SP-800-73)";
  const CK_ULONG CRYPTOKI_VERSION_MAJ  = 2;
  const CK_ULONG CRYPTOKI_VERSION_MIN  = 40;


  CK_INFO info;

  asrt(funcs->C_GetInfo(&info), CKR_OK, "GET_INFO");

  asrt(strcmp(info.manufacturerID, MANUFACTURER_ID), 0, "MANUFACTURER");

  asrt(info.cryptokiVersion.major, CRYPTOKI_VERSION_MAJ, "CK_MAJ");
  asrt(info.cryptokiVersion.minor, CRYPTOKI_VERSION_MIN, "CK_MIN");

  asrt(info.libraryVersion.major, YKCS11_VERSION_MAJOR, "LIB_MAJ");
  asrt(info.libraryVersion.minor, ((YKCS11_VERSION_MINOR * 10) + YKCS11_VERSION_PATCH ), "LIB_MIN");

  asrt(strcmp(info.libraryDescription, YKCS11_DESCRIPTION), 0, "LIB_DESC");
}

#ifdef HW_TESTS
static void test_initalize() {

  asrt(funcs->C_Initialize(NULL), CKR_OK, "INITIALIZE");

  asrt(funcs->C_Finalize(NULL), CKR_OK, "FINALIZE");

}

static int test_token_info() {

  const CK_CHAR_PTR TOKEN_LABEL  = "YubiKey PIV";
  const CK_CHAR_PTR TOKEN_MODEL  = "YubiKey ";  // Skip last 3 characters (version dependent)
  const CK_CHAR_PTR TOKEN_MODEL_YK4  = "YubiKey YK4";
  const CK_CHAR_PTR TOKEN_SERIAL = "1234";
  const CK_FLAGS TOKEN_FLAGS = CKF_RNG | CKF_LOGIN_REQUIRED | CKF_USER_PIN_INITIALIZED | CKF_TOKEN_INITIALIZED;
  const CK_VERSION HW = {0, 0};
  const CK_CHAR_PTR TOKEN_TIME   = "                ";
  CK_TOKEN_INFO info;

  asrt(funcs->C_Initialize(NULL), CKR_OK, "INITIALIZE");

  asrt(funcs->C_GetTokenInfo(0, &info), CKR_OK, "GetTokeninfo");
  asrt(strncmp(info.label, TOKEN_LABEL, strlen(TOKEN_LABEL)), 0, "TOKEN_LABEL");
  // Skip manufacturer id (not used)
  asrt(strncmp(info.model, TOKEN_MODEL, strlen(TOKEN_MODEL)), 0, "TOKEN_MODEL");
  asrt(strncmp(info.serialNumber, TOKEN_SERIAL, strlen(TOKEN_SERIAL)), 0, "SERIAL_NUMBER");
  asrt(info.flags, TOKEN_FLAGS, "TOKEN_FLAGS");
  asrt(info.ulMaxSessionCount, CK_UNAVAILABLE_INFORMATION, "MAX_SESSION_COUNT");
  asrt(info.ulSessionCount, CK_UNAVAILABLE_INFORMATION, "SESSION_COUNT");
  asrt(info.ulMaxRwSessionCount, CK_UNAVAILABLE_INFORMATION, "MAX_RW_SESSION_COUNT");
  asrt(info.ulRwSessionCount, CK_UNAVAILABLE_INFORMATION, "RW_SESSION_COUNT");
  asrt(info.ulMaxPinLen, 8, "MAX_PIN_LEN");
  asrt(info.ulMinPinLen, 6, "MIN_PIN_LEN");
  asrt(info.ulTotalPublicMemory, CK_UNAVAILABLE_INFORMATION, "TOTAL_PUB_MEM");
  asrt(info.ulFreePublicMemory, CK_UNAVAILABLE_INFORMATION, "FREE_PUB_MEM");
  asrt(info.ulTotalPrivateMemory, CK_UNAVAILABLE_INFORMATION, "TOTAL_PVT_MEM");
  asrt(info.ulFreePrivateMemory, CK_UNAVAILABLE_INFORMATION, "FREE_PVT_MEM");

  if (strncmp(info.model, TOKEN_MODEL_YK4, strlen(TOKEN_MODEL_YK4)) != 0) {
    dprintf(0, "\n\n** WARNING: Only YK4 supported.  Skipping remaining tests.\n\n");
    return -1;
  }

  asrt(info.hardwareVersion.major, HW.major, "HW_MAJ");
  asrt(info.hardwareVersion.minor, HW.minor, "HW_MIN");

  if (info.firmwareVersion.major != 4 && info.firmwareVersion.major != 0)
    asrt(info.firmwareVersion.major, 4, "FW_MAJ");

  asrt(strncmp(info.utcTime, TOKEN_TIME, sizeof(info.utcTime)), 0, "TOKEN_TIME");

  asrt(funcs->C_Finalize(NULL), CKR_OK, "FINALIZE");
  return 0;
}

static void test_mechanism_list_and_info() {

  CK_MECHANISM_TYPE_PTR mechs;
  CK_ULONG              n_mechs;
  CK_MECHANISM_INFO     info;
  CK_ULONG              i;

  static const CK_MECHANISM_TYPE token_mechanisms[] = {
    CKM_RSA_PKCS_KEY_PAIR_GEN,
    CKM_RSA_PKCS,
    CKM_RSA_PKCS_PSS,
    CKM_RSA_X_509,
    CKM_SHA1_RSA_PKCS,
    CKM_SHA256_RSA_PKCS,
    CKM_SHA384_RSA_PKCS,
    CKM_SHA512_RSA_PKCS,
    CKM_SHA1_RSA_PKCS_PSS,
    CKM_SHA256_RSA_PKCS_PSS,
    CKM_SHA384_RSA_PKCS_PSS,
    CKM_SHA512_RSA_PKCS_PSS,
    CKM_EC_KEY_PAIR_GEN,
    CKM_ECDSA,
    CKM_ECDSA_SHA1,
    CKM_ECDSA_SHA256,
    CKM_SHA_1,
    CKM_SHA256,
    CKM_SHA384,
    CKM_SHA512
  };

  static const CK_MECHANISM_INFO token_mechanism_infos[] = { // KEEP ALIGNED WITH token_mechanisms
    {1024, 2048, CKF_HW | CKF_GENERATE_KEY_PAIR},
    {1024, 2048, CKF_HW | CKF_DECRYPT | CKF_SIGN},
    {1024, 2048, CKF_HW | CKF_SIGN},
    {1024, 2048, CKF_HW | CKF_DECRYPT | CKF_SIGN},
    {1024, 2048, CKF_HW | CKF_SIGN},
    {1024, 2048, CKF_HW | CKF_SIGN},
    {1024, 2048, CKF_HW | CKF_SIGN},
    {1024, 2048, CKF_HW | CKF_SIGN},
    {1024, 2048, CKF_HW | CKF_SIGN},
    {1024, 2048, CKF_HW | CKF_SIGN},
    {1024, 2048, CKF_HW | CKF_SIGN},
    {1024, 2048, CKF_HW | CKF_SIGN},
    {256, 384, CKF_HW | CKF_GENERATE_KEY_PAIR},
    {256, 384, CKF_HW | CKF_SIGN},
    {256, 384, CKF_HW | CKF_SIGN},
    {256, 384, CKF_HW | CKF_SIGN},
    {0, 0, CKF_DIGEST},
    {0, 0, CKF_DIGEST},
    {0, 0, CKF_DIGEST},
    {0, 0, CKF_DIGEST}
};

  asrt(funcs->C_Initialize(NULL), CKR_OK, "INITIALIZE");

  asrt(funcs->C_GetMechanismList(0, NULL, &n_mechs), CKR_OK, "GetMechanismList");

  mechs = malloc(n_mechs * sizeof(CK_MECHANISM_TYPE));
  asrt(funcs->C_GetMechanismList(0, mechs, &n_mechs), CKR_OK, "GetMechanismList");

  asrt(memcmp(token_mechanisms, mechs, sizeof(token_mechanisms)), 0, "CHECK MECHS");

  for (i = 0; i < n_mechs; i++) {
    asrt(funcs->C_GetMechanismInfo(0, mechs[i], &info), CKR_OK, "GET MECH INFO");
    asrt(memcmp(token_mechanism_infos + i, &info, sizeof(CK_MECHANISM_INFO)), 0, "CHECK MECH INFO");
  }

  asrt(funcs->C_Finalize(NULL), CKR_OK, "FINALIZE");
}

static void test_session() {

  CK_SESSION_HANDLE session;
  CK_SESSION_INFO   info;

  asrt(funcs->C_Initialize(NULL), CKR_OK, "INITIALIZE");

  asrt(funcs->C_OpenSession(0, CKF_SERIAL_SESSION, NULL, NULL, &session), CKR_OK, "OpenSession1");
  asrt(funcs->C_CloseSession(session), CKR_OK, "CloseSession");

  asrt(funcs->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &session), CKR_OK, "OpenSession2");
  asrt(funcs->C_GetSessionInfo(session, &info), CKR_OK, "GetSessionInfo");
  asrt(info.state, CKS_RW_PUBLIC_SESSION, "CHECK STATE");
  asrt(info.flags, CKF_SERIAL_SESSION | CKF_RW_SESSION, "CHECK FLAGS");
  asrt(info.ulDeviceError, 0, "CHECK DEVICE ERROR");
  asrt(funcs->C_CloseSession(session), CKR_OK, "CloseSession");

  asrt(funcs->C_OpenSession(0, CKF_SERIAL_SESSION, NULL, NULL, &session), CKR_OK, "OpenSession3");
  asrt(funcs->C_CloseAllSessions(0), CKR_OK, "CloseAllSessions");

  asrt(funcs->C_Finalize(NULL), CKR_OK, "FINALIZE");

}

static void test_login() {

  CK_SESSION_HANDLE session;
  CK_SESSION_INFO   info;

  asrt(funcs->C_Initialize(NULL), CKR_OK, "INITIALIZE");

  asrt(funcs->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &session), CKR_OK, "OpenSession1");

  asrt(funcs->C_Login(session, CKU_USER, "123456", 6), CKR_OK, "Login USER");
  asrt(funcs->C_Logout(session), CKR_OK, "Logout USER");

  asrt(funcs->C_Login(session, CKU_SO, "010203040506070801020304050607080102030405060708", 48), CKR_OK, "Login SO");
  asrt(funcs->C_Logout(session), CKR_OK, "Logout SO");

  asrt(funcs->C_CloseSession(session), CKR_OK, "CloseSession");

  asrt(funcs->C_Finalize(NULL), CKR_OK, "FINALIZE");

}

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
static int bogus_sign(int dtype, const unsigned char *m, unsigned int m_length,
               unsigned char *sigret, unsigned int *siglen, const RSA *rsa) {
  sigret = malloc(1);
  sigret = "";
  *siglen = 1;
  return 0;
}

static void bogus_sign_cert(X509 *cert) {
  EVP_PKEY *pkey = EVP_PKEY_new();
  RSA *rsa = RSA_new();
  RSA_METHOD *meth = RSA_meth_dup(RSA_get_default_method());
  BIGNUM *e = BN_new();

  BN_set_word(e, 65537);
  RSA_generate_key_ex(rsa, 1024, e, NULL);
  RSA_meth_set_sign(meth, bogus_sign);
  RSA_set_method(rsa, meth);
  EVP_PKEY_set1_RSA(pkey, rsa);
  X509_sign(cert, pkey, EVP_md5());
  EVP_PKEY_free(pkey);
}
#endif


// Import a newly generated P256 pvt key and a certificate
// to every slot and use the key to sign some data
static void test_import_and_sign_all_10() {

  EVP_PKEY       *evp;
  EC_KEY         *eck;
  const EC_POINT *ecp;
  const BIGNUM   *bn;
  char           pvt[32];
  X509           *cert;
  ASN1_TIME      *tm;
  CK_BYTE        i, j;
  CK_BYTE        some_data[32];

  CK_ULONG    class_k = CKO_PRIVATE_KEY;
  CK_ULONG    class_c = CKO_CERTIFICATE;
  CK_ULONG    kt = CKK_ECDSA;
  CK_BYTE     id = 0;
  CK_BYTE     params[] = {0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07};
  CK_BYTE     sig[64];
  CK_ULONG    recv_len;
  CK_BYTE     value_c[3100];
  CK_ULONG    cert_len;
  CK_BYTE     der_encoded[80];
  CK_BYTE_PTR der_ptr;
  CK_BYTE_PTR r_ptr;
  CK_BYTE_PTR s_ptr;
  CK_ULONG    r_len;
  CK_ULONG    s_len;

  unsigned char  *p;

  CK_ATTRIBUTE privateKeyTemplate[] = {
    {CKA_CLASS, &class_k, sizeof(class_k)},
    {CKA_KEY_TYPE, &kt, sizeof(kt)},
    {CKA_ID, &id, sizeof(id)},
    {CKA_EC_PARAMS, &params, sizeof(params)},
    {CKA_VALUE, pvt, sizeof(pvt)}
  };

  CK_ATTRIBUTE publicKeyTemplate[] = {
    {CKA_CLASS, &class_c, sizeof(class_c)},
    {CKA_ID, &id, sizeof(id)},
    {CKA_VALUE, value_c, sizeof(value_c)}
  };

  CK_OBJECT_HANDLE obj[24];
  CK_SESSION_HANDLE session;
  CK_MECHANISM mech = {CKM_ECDSA, NULL};

  evp = EVP_PKEY_new();

  if (evp == NULL)
    exit(EXIT_FAILURE);

  eck = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);

  if (eck == NULL)
    exit(EXIT_FAILURE);

  asrt(EC_KEY_generate_key(eck), 1, "GENERATE ECK");

  bn = EC_KEY_get0_private_key(eck);

  asrt(BN_bn2bin(bn, pvt), 32, "EXTRACT PVT");

  if (EVP_PKEY_set1_EC_KEY(evp, eck) == 0)
    exit(EXIT_FAILURE);

  cert = X509_new();

  if (cert == NULL)
    exit(EXIT_FAILURE);

  if (X509_set_pubkey(cert, evp) == 0)
    exit(EXIT_FAILURE);

  tm = ASN1_TIME_new();
  if (tm == NULL)
    exit(EXIT_FAILURE);

  ASN1_TIME_set_string(tm, "000001010000Z");
  X509_set_notBefore(cert, tm);
  X509_set_notAfter(cert, tm);

#if OPENSSL_VERSION_NUMBER < 0x10100000L
  cert->sig_alg->algorithm = OBJ_nid2obj(8);
  cert->cert_info->signature->algorithm = OBJ_nid2obj(8);

  ASN1_BIT_STRING_set_bit(cert->signature, 8, 1);
  ASN1_BIT_STRING_set(cert->signature, "\x00", 1);
#else
  bogus_sign_cert(cert);
#endif

  p = value_c;
  if ((cert_len = (CK_ULONG) i2d_X509(cert, &p)) == 0 || cert_len > sizeof(value_c))
    exit(EXIT_FAILURE);

  publicKeyTemplate[2].ulValueLen = cert_len;

  asrt(funcs->C_Initialize(NULL), CKR_OK, "INITIALIZE");
  asrt(funcs->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &session), CKR_OK, "OpenSession1");
  asrt(funcs->C_Login(session, CKU_SO, "010203040506070801020304050607080102030405060708", 48), CKR_OK, "Login SO");

  for (i = 0; i < 24; i++) {
    id = i;
    asrt(funcs->C_CreateObject(session, publicKeyTemplate, 3, obj + i), CKR_OK, "IMPORT CERT");
    asrt(funcs->C_CreateObject(session, privateKeyTemplate, 5, obj + i), CKR_OK, "IMPORT KEY");
  }

  asrt(funcs->C_Logout(session), CKR_OK, "Logout SO");

  for (i = 0; i < 24; i++) {
    for (j = 0; j < 10; j++) {

      if(RAND_bytes(some_data, sizeof(some_data)) == -1)
        exit(EXIT_FAILURE);

      asrt(funcs->C_Login(session, CKU_USER, "123456", 6), CKR_OK, "Login USER");
      asrt(funcs->C_SignInit(session, &mech, obj[i]), CKR_OK, "SignInit");

      recv_len = sizeof(sig);
      asrt(funcs->C_Sign(session, some_data, sizeof(some_data), sig, &recv_len), CKR_OK, "Sign");

      r_len = 32;
      s_len = 32;

      der_ptr = der_encoded;
      *der_ptr++ = 0x30;
      *der_ptr++ = 0xff; // placeholder, fix below

      r_ptr = sig;

      *der_ptr++ = 0x02;
      *der_ptr++ = r_len;
      if (*r_ptr >= 0x80) {
        *(der_ptr - 1) = *(der_ptr - 1) + 1;
        *der_ptr++ = 0x00;
      }
      else if (*r_ptr == 0x00 && *(r_ptr + 1) < 0x80) {
        r_len--;
        *(der_ptr - 1) = *(der_ptr - 1) - 1;
        r_ptr++;
      }
      memcpy(der_ptr, r_ptr, r_len);
      der_ptr+= r_len;

      s_ptr = sig + 32;

      *der_ptr++ = 0x02;
      *der_ptr++ = s_len;
      if (*s_ptr >= 0x80) {
        *(der_ptr - 1) = *(der_ptr - 1) + 1;
        *der_ptr++ = 0x00;
      }
      else if (*s_ptr == 0x00 && *(s_ptr + 1) < 0x80) {
        s_len--;
        *(der_ptr - 1) = *(der_ptr - 1) - 1;
        s_ptr++;
      }
      memcpy(der_ptr, s_ptr, s_len);
      der_ptr+= s_len;

      der_encoded[1] = der_ptr - der_encoded - 2;

      dump_hex(der_encoded, der_encoded[1] + 2, stderr, 1);

      asrt(ECDSA_verify(0, some_data, sizeof(some_data), der_encoded, der_encoded[1] + 2, eck), 1, "ECDSA VERIFICATION");

      }
  }

  asrt(funcs->C_Logout(session), CKR_OK, "Logout USER");

  asrt(funcs->C_CloseSession(session), CKR_OK, "CloseSession");
  asrt(funcs->C_Finalize(NULL), CKR_OK, "FINALIZE");

}

// Import a newly generated RSA1024 pvt key and a certificate
// to every slot and use the key to sign some data
static void test_import_and_sign_all_10_RSA() {

  EVP_PKEY    *evp;
  RSA         *rsak;
  X509        *cert;
  ASN1_TIME   *tm;
  CK_BYTE     i, j;
  CK_BYTE     some_data[32];
  CK_BYTE     e[] = {0x01, 0x00, 0x01};
  CK_BYTE     p[64];
  CK_BYTE     q[64];
  CK_BYTE     dp[64];
  CK_BYTE     dq[64];
  CK_BYTE     qinv[64];
  BIGNUM      *e_bn;
  CK_ULONG    class_k = CKO_PRIVATE_KEY;
  CK_ULONG    class_c = CKO_CERTIFICATE;
  CK_ULONG    kt = CKK_RSA;
  CK_BYTE     id = 0;
  CK_BYTE     sig[64];
  CK_ULONG    recv_len;
  CK_BYTE     value_c[3100];
  CK_ULONG    cert_len;
  CK_BYTE     der_encoded[80];
  CK_BYTE_PTR der_ptr;
  CK_BYTE_PTR r_ptr;
  CK_BYTE_PTR s_ptr;
  CK_ULONG    r_len;
  CK_ULONG    s_len;
  const BIGNUM *bp, *bq, *biqmp, *bdmp1, *bdmq1;

  unsigned char  *px;

  CK_ATTRIBUTE privateKeyTemplate[] = {
    {CKA_CLASS, &class_k, sizeof(class_k)},
    {CKA_KEY_TYPE, &kt, sizeof(kt)},
    {CKA_ID, &id, sizeof(id)},
    {CKA_PUBLIC_EXPONENT, e, sizeof(e)},
    {CKA_PRIME_1, p, sizeof(p)},
    {CKA_PRIME_2, q, sizeof(q)},
    {CKA_EXPONENT_1, dp, sizeof(dp)},
    {CKA_EXPONENT_2, dq, sizeof(dq)},
    {CKA_COEFFICIENT, qinv, sizeof(qinv)}
  };

  CK_ATTRIBUTE publicKeyTemplate[] = {
    {CKA_CLASS, &class_c, sizeof(class_c)},
    {CKA_ID, &id, sizeof(id)},
    {CKA_VALUE, value_c, sizeof(value_c)}
  };

  CK_OBJECT_HANDLE obj[24];
  CK_SESSION_HANDLE session;
  CK_MECHANISM mech = {CKM_RSA_PKCS, NULL};

  evp = EVP_PKEY_new();

  if (evp == NULL)
    exit(EXIT_FAILURE);

  rsak = RSA_new();

  if (rsak == NULL)
    exit(EXIT_FAILURE);

  e_bn = BN_bin2bn(e, 3, NULL);

  if (e_bn == NULL)
    exit(EXIT_FAILURE);

  asrt(RSA_generate_key_ex(rsak, 1024, e_bn, NULL), 1, "GENERATE RSAK");

  RSA_get0_factors(rsak, &bp, &bq);
  RSA_get0_crt_params(rsak, &bdmp1, &bdmq1, &biqmp);
  asrt(BN_bn2bin(bp, p), 64, "GET P");
  asrt(BN_bn2bin(bq, q), 64, "GET Q");
  asrt(BN_bn2bin(bdmp1, dp), 64, "GET DP");
  asrt(BN_bn2bin(bdmq1, dp), 64, "GET DQ");
  asrt(BN_bn2bin(biqmp, qinv), 64, "GET QINV");



  if (EVP_PKEY_set1_RSA(evp, rsak) == 0)
    exit(EXIT_FAILURE);

  cert = X509_new();

  if (cert == NULL)
    exit(EXIT_FAILURE);

  if (X509_set_pubkey(cert, evp) == 0)
    exit(EXIT_FAILURE);

  tm = ASN1_TIME_new();
  if (tm == NULL)
    exit(EXIT_FAILURE);

  ASN1_TIME_set_string(tm, "000001010000Z");
  X509_set_notBefore(cert, tm);
  X509_set_notAfter(cert, tm);

#if OPENSSL_VERSION_NUMBER < 0x10100000L
  /* putting bogus data to signature to make some checks happy */
  cert->sig_alg->algorithm = OBJ_nid2obj(8);
  cert->cert_info->signature->algorithm = OBJ_nid2obj(8);

  ASN1_BIT_STRING_set_bit(cert->signature, 8, 1);
  ASN1_BIT_STRING_set(cert->signature, "\x00", 1);
#else
  bogus_sign_cert(cert);
#endif

  px = value_c;
  if ((cert_len = (CK_ULONG) i2d_X509(cert, &px)) == 0 || cert_len > sizeof(value_c))
    exit(EXIT_FAILURE);

  publicKeyTemplate[2].ulValueLen = cert_len;

  asrt(funcs->C_Initialize(NULL), CKR_OK, "INITIALIZE");
  asrt(funcs->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &session), CKR_OK, "OpenSession1");
  asrt(funcs->C_Login(session, CKU_SO, "010203040506070801020304050607080102030405060708", 48), CKR_OK, "Login SO");

  for (i = 0; i < 24; i++) {
    id = i;
    asrt(funcs->C_CreateObject(session, publicKeyTemplate, 3, obj + i), CKR_OK, "IMPORT CERT");
    asrt(funcs->C_CreateObject(session, privateKeyTemplate, 9, obj + i), CKR_OK, "IMPORT KEY");
  }

  asrt(funcs->C_Logout(session), CKR_OK, "Logout SO");

  for (i = 0; i < 24; i++) {
    for (j = 0; j < 10; j++) {

      if(RAND_bytes(some_data, sizeof(some_data)) == -1)
        exit(EXIT_FAILURE);

      asrt(funcs->C_Login(session, CKU_USER, "123456", 6), CKR_OK, "Login USER");
      asrt(funcs->C_SignInit(session, &mech, obj[i]), CKR_OK, "SignInit");

      recv_len = sizeof(sig);
      asrt(funcs->C_Sign(session, some_data, sizeof(some_data), sig, &recv_len), CKR_OK, "Sign");

      /* r_len = 32; */
      /* s_len = 32; */

      /* der_ptr = der_encoded; */
      /* *der_ptr++ = 0x30; */
      /* *der_ptr++ = 0xff; // placeholder, fix below */

      /* r_ptr = sig; */

      /* *der_ptr++ = 0x02; */
      /* *der_ptr++ = r_len; */
      /* if (*r_ptr >= 0x80) { */
      /*   *(der_ptr - 1) = *(der_ptr - 1) + 1; */
      /*   *der_ptr++ = 0x00; */
      /* } */
      /* else if (*r_ptr == 0x00 && *(r_ptr + 1) < 0x80) { */
      /*   r_len--; */
      /*   *(der_ptr - 1) = *(der_ptr - 1) - 1; */
      /*   r_ptr++; */
      /* } */
      /* memcpy(der_ptr, r_ptr, r_len); */
      /* der_ptr+= r_len; */

      /* s_ptr = sig + 32; */

      /* *der_ptr++ = 0x02; */
      /* *der_ptr++ = s_len; */
      /* if (*s_ptr >= 0x80) { */
      /*   *(der_ptr - 1) = *(der_ptr - 1) + 1; */
      /*   *der_ptr++ = 0x00; */
      /* } */
      /* else if (*s_ptr == 0x00 && *(s_ptr + 1) < 0x80) { */
      /*   s_len--; */
      /*   *(der_ptr - 1) = *(der_ptr - 1) - 1; */
      /*   s_ptr++; */
      /* } */
      /* memcpy(der_ptr, s_ptr, s_len); */
      /* der_ptr+= s_len; */

      /* der_encoded[1] = der_ptr - der_encoded - 2; */

      /* dump_hex(der_encoded, der_encoded[1] + 2, stderr, 1); */

      /* asrt(ECDSA_verify(0, some_data, sizeof(some_data), der_encoded, der_encoded[1] + 2, eck), 1, "ECDSA VERIFICATION"); */

      }
  }

  asrt(funcs->C_Logout(session), CKR_OK, "Logout USER");

  asrt(funcs->C_CloseSession(session), CKR_OK, "CloseSession");
  asrt(funcs->C_Finalize(NULL), CKR_OK, "FINALIZE");

}
#endif

int destruction_confirmed(void) {
  char *confirmed = getenv("YKPIV_ENV_HWTESTS_CONFIRMED");
  if (confirmed && confirmed[0] == '1')
    return 1;
  // Use dprintf() to write directly to stdout, since automake eats the standard stdout/stderr pointers.
  dprintf(0, "\n***\n*** Hardware tests skipped.  Run \"make hwcheck\".\n***\n\n");
  return 0;
}

int main(void) {

  get_functions(&funcs);

  test_lib_info();

#ifdef HW_TESTS
  // Require user confirmation to continue, since this test suite will clear
  // any data stored on connected keys.
  if (!destruction_confirmed())
    exit(77); // exit code 77 == skipped tests

  test_initalize();
  // Require YK4 to continue.  Skip if different model found.
  if (test_token_info() != 0)
    exit(77);
  test_mechanism_list_and_info();
  test_session();
  test_login();
  test_import_and_sign_all_10();
  test_import_and_sign_all_10_RSA();
#else
  fprintf(stderr, "HARDWARE TESTS DISABLED!, skipping...\n");
#endif

  return EXIT_SUCCESS;

}

#pragma clang diagnostic pop
