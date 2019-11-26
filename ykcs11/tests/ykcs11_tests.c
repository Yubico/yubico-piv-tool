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

static void init_connection() {
  asrt(funcs->C_Initialize(NULL), CKR_OK, "INITIALIZE");
  CK_SLOT_ID pSlotList;
  CK_ULONG pulCount = 16;
  asrt(funcs->C_GetSlotList(true, &pSlotList, &pulCount), CKR_OK, "GETSLOTLIST");
}

static void test_lib_info() {
  dprintf(0, "TEST START: test_lib_info()\n");

  const CK_CHAR_PTR MANUFACTURER_ID = "Yubico (www.yubico.com)";
  const CK_CHAR_PTR YKCS11_DESCRIPTION = "PKCS#11 PIV Library (SP-800-73)";
  const CK_ULONG CRYPTOKI_VERSION_MAJ = 2;
  const CK_ULONG CRYPTOKI_VERSION_MIN = 40;


  CK_INFO info;

  asrt(funcs->C_GetInfo(&info), CKR_OK, "GET_INFO");

  asrt(strncmp(info.manufacturerID, MANUFACTURER_ID, strlen(MANUFACTURER_ID)), 0, "MANUFACTURER");

  asrt(info.cryptokiVersion.major, CRYPTOKI_VERSION_MAJ, "CK_MAJ");
  asrt(info.cryptokiVersion.minor, CRYPTOKI_VERSION_MIN, "CK_MIN");

  asrt(info.libraryVersion.major, YKCS11_VERSION_MAJOR, "LIB_MAJ");
  asrt(info.libraryVersion.minor, ((YKCS11_VERSION_MINOR * 10) + YKCS11_VERSION_PATCH), "LIB_MIN");

  asrt(strncmp(info.libraryDescription, YKCS11_DESCRIPTION, strlen(YKCS11_DESCRIPTION)), 0, "LIB_DESC");

  dprintf(0, "TEST END: test_lib_info()\n");
}

#if HW_TESTS
static void test_initalize() {
  dprintf(0, "TEST START: test_initalize()\n");
  asrt(funcs->C_Initialize(NULL), CKR_OK, "INITIALIZE");
  asrt(funcs->C_Finalize(NULL), CKR_OK, "FINALIZE");
  dprintf(0, "TEST END: test_initalize()\n");
}

static int test_token_info() {
  dprintf(0, "TEST START: test_token_info()\n");

  const CK_CHAR_PTR TOKEN_LABEL  = "YubiKey PIV";
  const CK_CHAR_PTR TOKEN_MODEL  = "YubiKey ";  // Skip last 3 characters (version dependent)
  const CK_CHAR_PTR TOKEN_MODEL_YK4  = "YubiKey YK4";
  const CK_CHAR_PTR TOKEN_MODEL_YK5  = "YubiKey YK5";
  //const CK_CHAR_PTR TOKEN_SERIAL = "1234";
  const CK_FLAGS TOKEN_FLAGS = CKF_RNG | CKF_LOGIN_REQUIRED | CKF_USER_PIN_INITIALIZED | CKF_TOKEN_INITIALIZED;
  const CK_VERSION HW = {1, 0};
  const CK_CHAR_PTR TOKEN_TIME   = "                ";
  CK_TOKEN_INFO info;

  init_connection();
  asrt(funcs->C_GetTokenInfo(0, &info), CKR_OK, "GetTokeninfo");
  asrt(strncmp(info.label, TOKEN_LABEL, strlen(TOKEN_LABEL)), 0, "TOKEN_LABEL");
  // Skip manufacturer id (not used)
  asrt(strncmp(info.model, TOKEN_MODEL, strlen(TOKEN_MODEL)), 0, "TOKEN_MODEL");
  //asrt(strncmp(info.serialNumber, TOKEN_SERIAL, strlen(TOKEN_SERIAL)), 0, "SERIAL_NUMBER");
  asrt(info.flags, TOKEN_FLAGS, "TOKEN_FLAGS");
  asrt(info.ulMaxSessionCount, 16, "MAX_SESSION_COUNT");
  asrt(info.ulSessionCount, 0, "SESSION_COUNT");
  asrt(info.ulMaxRwSessionCount, 16, "MAX_RW_SESSION_COUNT");
  asrt(info.ulRwSessionCount, 0, "RW_SESSION_COUNT");
  asrt(info.ulMaxPinLen, 8, "MAX_PIN_LEN");
  asrt(info.ulMinPinLen, 6, "MIN_PIN_LEN");
  asrt(info.ulTotalPublicMemory, -1, "TOTAL_PUB_MEM");
  asrt(info.ulFreePublicMemory, -1, "FREE_PUB_MEM");
  asrt(info.ulTotalPrivateMemory, -1, "TOTAL_PVT_MEM");
  asrt(info.ulFreePrivateMemory, -1, "FREE_PVT_MEM");

  if (strncmp(info.model, TOKEN_MODEL_YK4, strlen(TOKEN_MODEL_YK4)) != 0 &&
      strncmp(info.model, TOKEN_MODEL_YK5, strlen(TOKEN_MODEL_YK5)) != 0) {
    dprintf(0, "\n\n** WARNING: Only YK04 and YK05 supported. Skipping remaining tests.\n\n");
    return -1;
  }

  asrt(info.hardwareVersion.major, HW.major, "HW_MAJ");
  asrt(info.hardwareVersion.minor, HW.minor, "HW_MIN");

  if (info.firmwareVersion.major != 4 && info.firmwareVersion.major != 5)
    asrt(info.firmwareVersion.major, 4, "FW_MAJ");

  asrt(strncmp(info.utcTime, TOKEN_TIME, sizeof(info.utcTime)), 0, "TOKEN_TIME");

  asrt(funcs->C_Finalize(NULL), CKR_OK, "FINALIZE");
  dprintf(0, "TEST END: test_token_info()\n");
  return 0;
}

static void test_mechanism_list_and_info() {
  dprintf(0, "TEST START: test_mechanism_list_and_info()\n");

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
    CKM_ECDSA_SHA384,
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
    {256, 384, CKF_HW | CKF_SIGN},
    {0, 0, CKF_DIGEST},
    {0, 0, CKF_DIGEST},
    {0, 0, CKF_DIGEST},
    {0, 0, CKF_DIGEST}
};

  init_connection();
  asrt(funcs->C_GetMechanismList(0, NULL, &n_mechs), CKR_OK, "GetMechanismList");

  mechs = malloc(n_mechs * sizeof(CK_MECHANISM_TYPE));
  asrt(funcs->C_GetMechanismList(0, mechs, &n_mechs), CKR_OK, "GetMechanismList");

  asrt(memcmp(token_mechanisms, mechs, sizeof(token_mechanisms)), 0, "CHECK MECHS");

  for (i = 0; i < n_mechs; i++) {
    asrt(funcs->C_GetMechanismInfo(0, mechs[i], &info), CKR_OK, "GET MECH INFO");
    asrt(memcmp(token_mechanism_infos + i, &info, sizeof(CK_MECHANISM_INFO)), 0, "CHECK MECH INFO");
  }

  asrt(funcs->C_Finalize(NULL), CKR_OK, "FINALIZE");
  dprintf(0, "TEST END: test_mechanism_list_and_info()\n");
}

static void test_session() {
  dprintf(0, "TEST START: test_session()\n");

  CK_SESSION_HANDLE session;
  CK_SESSION_INFO   info;

  init_connection();
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
  dprintf(0, "TEST END: test_session()\n");
}

static void test_login() {
  dprintf(0, "TEST START: test_login()\n");
  CK_SESSION_HANDLE session;

  init_connection();
  asrt(funcs->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &session), CKR_OK, "OpenSession1");

  asrt(funcs->C_Login(session, CKU_USER, "123456", 6), CKR_OK, "Login USER");
  asrt(funcs->C_Login(session, CKU_SO, "010203040506070801020304050607080102030405060708", 48), CKR_USER_ANOTHER_ALREADY_LOGGED_IN, "Login SO");
  asrt(funcs->C_Logout(session), CKR_OK, "Logout USER");

  asrt(funcs->C_Login(session, CKU_SO, "010203040506070801020304050607080102030405060708", 48), CKR_OK, "Login SO");
  asrt(funcs->C_Login(session, CKU_USER, "123456", 6), CKR_USER_ANOTHER_ALREADY_LOGGED_IN, "Login USER");
  asrt(funcs->C_Logout(session), CKR_OK, "Logout SO");

  asrt(funcs->C_CloseSession(session), CKR_OK, "CloseSession");

  asrt(funcs->C_Finalize(NULL), CKR_OK, "FINALIZE");
  dprintf(0, "TEST END: test_login()\n");
}

static void test_multiple_sessions() {
  dprintf(0, "TEST START: test_multiple_sessions()\n");
  CK_SESSION_INFO info;
  CK_SESSION_HANDLE session1, session2, session3, session4;
  
  init_connection();

  // Open first session as a public session (no logging in)
  asrt(funcs->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &session1), CKR_OK, "MultipleSessions_OpenSession1");
  asrt(session1, 1, "MultipleSessions_session1Handle");
  asrt(funcs->C_GetSessionInfo(session1, &info), CKR_OK, "MultipleSessions_session1Info");
  asrt(info.state, CKS_RW_PUBLIC_SESSION, "MultipleSession_session1State");

  // Open the second session and log in as user. Both sessions should then be logged in as user
  asrt(funcs->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &session2), CKR_OK, "MultipleSessions_OpenSession2");
  asrt(session2, 2, "MultipleSessions_session2Handle");
  asrt(funcs->C_Login(session2, CKU_USER, "123456", 6), CKR_OK, "MultipleSession_Login USER");
  asrt(funcs->C_GetSessionInfo(session2, &info), CKR_OK, "MultipleSessions_session2Info");
  asrt(info.state, CKS_RW_USER_FUNCTIONS, "MultipleSession_session2State");
  asrt(funcs->C_GetSessionInfo(session1, &info), CKR_OK, "MultipleSessions_session1Info");
  asrt(info.state, CKS_RW_USER_FUNCTIONS, "MultipleSession_session1State");
  // Log out from the second session. Both sessions should then be loged out
  asrt(funcs->C_Logout(session2), CKR_OK, "Logout USER");
  asrt(funcs->C_GetSessionInfo(session2, &info), CKR_OK, "MultipleSessions_session2Info");
  asrt(info.state, CKS_RW_PUBLIC_SESSION, "MultipleSession_session2State");
  asrt(funcs->C_GetSessionInfo(session1, &info), CKR_OK, "MultipleSessions_session1Info");
  asrt(info.state, CKS_RW_PUBLIC_SESSION, "MultipleSession_session1State");

  // Open the third session and log in as so user
  asrt(funcs->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &session3), CKR_OK, "MultipleSessions_OpenSession3");
  asrt(session3, 3, "MultipleSessions_session3Handle");
  asrt(funcs->C_Login(session3, CKU_SO, "010203040506070801020304050607080102030405060708", 48), CKR_OK, "MultipleSessions_Login SO");
  asrt(funcs->C_GetSessionInfo(session3, &info), CKR_OK, "MultipleSessions_session3Info");
  asrt(info.state, CKS_RW_SO_FUNCTIONS, "MultipleSession_session3State");
  asrt(funcs->C_GetSessionInfo(session2, &info), CKR_OK, "MultipleSessions_session2Info");
  asrt(info.state, CKS_RW_SO_FUNCTIONS, "MultipleSession_session2State");
  asrt(funcs->C_GetSessionInfo(session1, &info), CKR_OK, "MultipleSessions_session1Info");
  asrt(info.state, CKS_RW_SO_FUNCTIONS, "MultipleSession_session1State");

  // Close the second session
  asrt(funcs->C_CloseSession(session2), CKR_OK, "MultipleSessions_CloseSession2");
  asrt(funcs->C_GetSessionInfo(session2, &info), CKR_SESSION_HANDLE_INVALID, "MultipleSessions_closedSession2Info");
  
  // Open a fourth session; should get the same handle as the previously closed session and it should be an SO session
  asrt(funcs->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &session4), CKR_OK, "MultipleSessions_OpenSession4");
  asrt(session4, session2, "MultipleSessions_session4Handle");
  asrt(funcs->C_GetSessionInfo(session4, &info), CKR_OK, "MultipleSessions_session4Info");
  asrt(info.state, CKS_RW_SO_FUNCTIONS, "MultipleSession_session4State");

  asrt(funcs->C_Login(session2, CKU_USER, "123456", 6), CKR_USER_ANOTHER_ALREADY_LOGGED_IN, "MultipleSession_Login USER");
  asrt(funcs->C_GetSessionInfo(session4, &info), CKR_OK, "MultipleSessions_session4Info");
  asrt(info.state, CKS_RW_SO_FUNCTIONS, "MultipleSession_session4State");

  // Close all session and end test
  asrt(funcs->C_CloseAllSessions(0), CKR_OK, "MultipleSessions_CloseAllSessions");
  asrt(funcs->C_Finalize(NULL), CKR_OK, "FINALIZE");
  dprintf(0, "TEST END: test_multiple_sessions()\n");
}

static void test_max_multiple_sessions() {
  dprintf(0, "TEST START: test_max_multiple_sessions()\n");
  init_connection();
  CK_SESSION_HANDLE session;
  for(int i=1; i<=16; i++) {
    asrt(funcs->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &session), CKR_OK, "MaxMultipleSession_OpenSession");
    asrt(session, i, "MaxMultipleSession_sessionHandle");
  }
  
  asrt(funcs->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &session), CKR_SESSION_COUNT, "MaxMultipleSession_OpenSession_TooMany");
  
  CK_SESSION_INFO pInfo;
  asrt(funcs->C_CloseAllSessions(0), CKR_OK, "MaxMultipleSessions_CloseAllSessions");
  for(int i=1; i<=17; i++) {
    asrt(funcs->C_GetSessionInfo(i, &pInfo), CKR_SESSION_HANDLE_INVALID, "MaxMultipleSessions_closedSessionsInfo");
  }

  asrt(funcs->C_Finalize(NULL), CKR_OK, "FINALIZE");
  dprintf(0, "TEST END: test_max_multiple_sessions()\n");
}

#if !((OPENSSL_VERSION_NUMBER < 0x10100000L) || defined(LIBRESSL_VERSION_NUMBER))
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

static void test_generate_ec() {
  dprintf(0, "TEST START: test_generate_ec()\n");

  CK_BYTE     i, j;
  CK_BYTE     some_data[30];
  CK_BYTE     params[] = {0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07};
  CK_ULONG    class_k = CKO_PRIVATE_KEY;
  CK_ULONG    class_c = CKO_PUBLIC_KEY;
  CK_ULONG    kt = CKK_ECDSA;
  CK_BYTE     id = 0;
  CK_BYTE     sig[64];
  CK_ULONG    recv_len;

  CK_ATTRIBUTE privateKeyTemplate[] = {
    {CKA_CLASS, &class_k, sizeof(class_k)},
    {CKA_KEY_TYPE, &kt, sizeof(kt)},
    {CKA_ID, &id, sizeof(id)}
  };

  CK_ATTRIBUTE publicKeyTemplate[] = {
    {CKA_CLASS, &class_c, sizeof(class_c)},
    {CKA_ID, &id, sizeof(id)},
    {CKA_EC_PARAMS, &params, sizeof(params)}
  };

  CK_MECHANISM keygen_mech = {CKM_EC_KEY_PAIR_GEN, NULL};
  CK_MECHANISM sign_mech = {CKM_ECDSA, NULL};

  CK_OBJECT_HANDLE privkey[24], pubkey[24];

  CK_SESSION_HANDLE session;
  init_connection();
  asrt(funcs->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &session), CKR_OK, "OpenSession1");
  asrt(funcs->C_Login(session, CKU_SO, "010203040506070801020304050607080102030405060708", 48), CKR_OK, "Login SO");

  for (i = 0; i < 24; i++) {
    id = i+1;
    asrt(funcs->C_GenerateKeyPair(session, &keygen_mech, publicKeyTemplate, 3, privateKeyTemplate, 3, pubkey+i, privkey+i), CKR_OK, "GEN RSA KEYPAIR");
  }
  asrt(funcs->C_Logout(session), CKR_OK, "Logout SO");

  for (i = 0; i < 24; i++) {
    for (j = 0; j < 10; j++) {
      if(RAND_bytes(some_data, sizeof(some_data)) == -1) {
        exit(EXIT_FAILURE);
      }

      asrt(funcs->C_Login(session, CKU_USER, "123456", 6), CKR_OK, "Login USER");
      asrt(funcs->C_SignInit(session, &sign_mech, privkey[i]), CKR_OK, "SignInit");
      recv_len = sizeof(sig);
      asrt(funcs->C_Sign(session, some_data, sizeof(some_data), sig, &recv_len), CKR_OK, "Sign");
      asrt(funcs->C_VerifyInit(session, &sign_mech, pubkey[i]), CKR_OK, "VerifyInit");
      asrt(funcs->C_Verify(session, some_data, sizeof(some_data), sig, recv_len), CKR_OK, "Verify");

      asrt(funcs->C_VerifyInit(session, &sign_mech, pubkey[i]), CKR_OK, "VerifyInit");
      asrt(funcs->C_VerifyUpdate(session, some_data, 15), CKR_OK, "VerifyUpdate 1");
      asrt(funcs->C_VerifyUpdate(session, some_data+15, 15), CKR_OK, "VerifyUpdate 2");
      asrt(funcs->C_VerifyFinal(session, sig, recv_len), CKR_OK, "VerifyFinal");
    }
  }

  asrt(funcs->C_Logout(session), CKR_OK, "Logout USER");


  CK_OBJECT_HANDLE cert_handle;
  CK_ULONG n_cert_handle;
  CK_BYTE ckaid = 0;
  CK_ULONG class_cert = CKO_CERTIFICATE;
  CK_ATTRIBUTE idTemplate[] = {
    {CKA_ID, &ckaid, sizeof(ckaid)}
  };
  CK_ATTRIBUTE idClassTemplate[] = {
    {CKA_ID, &ckaid, sizeof(ckaid)},
    {CKA_CLASS, &class_cert, sizeof(class_cert)}
  };

  asrt(funcs->C_Login(session, CKU_SO, "010203040506070801020304050607080102030405060708", 48), CKR_OK, "Login SO");
  for(i=0; i<24; i++) {
    asrt(funcs->C_GetAttributeValue(session, privkey[i], idTemplate, 1), CKR_OK, "GET CKA_ID");
    asrt(funcs->C_FindObjectsInit(session, idClassTemplate, 2), CKR_OK, "FIND INIT");
    asrt(funcs->C_FindObjects(session, &cert_handle, 1, &n_cert_handle), CKR_OK, "FIND");
    asrt(funcs->C_FindObjectsFinal(session), CKR_OK, "FIND FINAL");

    asrt(funcs->C_DestroyObject(session, cert_handle), CKR_OK, "Destroy Object");
  }
  asrt(funcs->C_Logout(session), CKR_OK, "Logout SO");

  asrt(funcs->C_CloseSession(session), CKR_OK, "CloseSession");
  asrt(funcs->C_Finalize(NULL), CKR_OK, "FINALIZE");
  dprintf(0, "TEST END: test_generate_ec()\n");
}

static void test_generate_ec_P384() {
  dprintf(0, "TEST START: test_generate_ec_P384()\n");

  CK_BYTE     i, j;
  CK_BYTE     some_data[32];
  CK_BYTE     params[] = {0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22};
  CK_ULONG    class_k = CKO_PRIVATE_KEY;
  CK_ULONG    class_c = CKO_PUBLIC_KEY;
  CK_ULONG    kt = CKK_ECDSA;
  CK_BYTE     id = 0;
  CK_BYTE     sig[96];
  CK_ULONG    recv_len;

  CK_ATTRIBUTE privateKeyTemplate[] = {
    {CKA_CLASS, &class_k, sizeof(class_k)},
    {CKA_KEY_TYPE, &kt, sizeof(kt)},
    {CKA_ID, &id, sizeof(id)}
  };

  CK_ATTRIBUTE publicKeyTemplate[] = {
    {CKA_CLASS, &class_c, sizeof(class_c)},
    {CKA_ID, &id, sizeof(id)},
    {CKA_EC_PARAMS, &params, sizeof(params)}
  };

  CK_MECHANISM keygen_mech = {CKM_EC_KEY_PAIR_GEN, NULL};
  CK_MECHANISM sign_mech = {CKM_ECDSA, NULL};

  CK_OBJECT_HANDLE privkey[24], pubkey[24];

  CK_SESSION_HANDLE session;
  init_connection();
  asrt(funcs->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &session), CKR_OK, "OpenSession1");
  asrt(funcs->C_Login(session, CKU_SO, "010203040506070801020304050607080102030405060708", 48), CKR_OK, "Login SO");

  for (i = 0; i < 24; i++) {
    id = i+1;
    asrt(funcs->C_GenerateKeyPair(session, &keygen_mech, publicKeyTemplate, 3, privateKeyTemplate, 3, pubkey+i, privkey+i), CKR_OK, "GEN RSA KEYPAIR");
  }
  asrt(funcs->C_Logout(session), CKR_OK, "Logout SO");

  for (i = 0; i < 24; i++) {
    for (j = 0; j < 10; j++) {
      if(RAND_bytes(some_data, sizeof(some_data)) == -1)
        exit(EXIT_FAILURE);

      asrt(funcs->C_Login(session, CKU_USER, "123456", 6), CKR_OK, "Login USER");
      asrt(funcs->C_SignInit(session, &sign_mech, privkey[i]), CKR_OK, "SignInit");
      recv_len = sizeof(sig);
      asrt(funcs->C_Sign(session, some_data, sizeof(some_data), sig, &recv_len), CKR_OK, "Sign");
      
      asrt(funcs->C_VerifyInit(session, &sign_mech, pubkey[i]), CKR_OK, "VerifyInit");
      asrt(funcs->C_Verify(session, some_data, sizeof(some_data), sig, recv_len), CKR_OK, "Verify");

      asrt(funcs->C_VerifyInit(session, &sign_mech, pubkey[i]), CKR_OK, "VerifyInit");
      asrt(funcs->C_VerifyUpdate(session, some_data, 16), CKR_OK, "VerifyUpdate 1");
      asrt(funcs->C_VerifyUpdate(session, some_data+16, 16), CKR_OK, "VerifyUpdate 2");
      asrt(funcs->C_VerifyFinal(session, sig, recv_len), CKR_OK, "VerifyFinal");
    }
  }

  asrt(funcs->C_Logout(session), CKR_OK, "Logout USER");


  CK_OBJECT_HANDLE cert_handle;
  CK_ULONG n_cert_handle;
  CK_BYTE ckaid = 0;
  CK_ULONG class_cert = CKO_CERTIFICATE;
  CK_ATTRIBUTE idTemplate[] = {
    {CKA_ID, &ckaid, sizeof(ckaid)}
  };
  CK_ATTRIBUTE idClassTemplate[] = {
    {CKA_ID, &ckaid, sizeof(ckaid)},
    {CKA_CLASS, &class_cert, sizeof(class_cert)}
  };

  asrt(funcs->C_Login(session, CKU_SO, "010203040506070801020304050607080102030405060708", 48), CKR_OK, "Login SO");
  for(i=0; i<24; i++) {
    asrt(funcs->C_GetAttributeValue(session, privkey[i], idTemplate, 1), CKR_OK, "GET CKA_ID");
    asrt(funcs->C_FindObjectsInit(session, idClassTemplate, 2), CKR_OK, "FIND INIT");
    asrt(funcs->C_FindObjects(session, &cert_handle, 1, &n_cert_handle), CKR_OK, "FIND");
    asrt(funcs->C_FindObjectsFinal(session), CKR_OK, "FIND FINAL");

    asrt(funcs->C_DestroyObject(session, cert_handle), CKR_OK, "Destroy Object");
  }
  asrt(funcs->C_Logout(session), CKR_OK, "Logout SO");

  asrt(funcs->C_CloseSession(session), CKR_OK, "CloseSession");
  asrt(funcs->C_Finalize(NULL), CKR_OK, "FINALIZE");
  dprintf(0, "TEST END: test_generate_ec_P384()\n");
}

static void test_generate_rsa() {
  dprintf(0, "TEST START: test_generate_rsa()\n");

  CK_BYTE     i, j;
  CK_BYTE     some_data[32];
  CK_BYTE     e[] = {0x01, 0x00, 0x01};
  CK_ULONG    class_k = CKO_PRIVATE_KEY;
  CK_ULONG    class_c = CKO_PUBLIC_KEY;
  CK_ULONG    kt = CKK_RSA;
  CK_ULONG    key_size = 1024;
  CK_BYTE     id = 0;
  CK_BYTE     sig[2048];
  CK_ULONG    recv_len;

  CK_ATTRIBUTE privateKeyTemplate[] = {
    {CKA_CLASS, &class_k, sizeof(class_k)},
    {CKA_KEY_TYPE, &kt, sizeof(kt)},
    {CKA_ID, &id, sizeof(id)}
  };

  CK_ATTRIBUTE publicKeyTemplate[] = {
    {CKA_CLASS, &class_c, sizeof(class_c)},
    {CKA_ID, &id, sizeof(id)},
    {CKA_MODULUS_BITS, &key_size, sizeof(key_size)},
    {CKA_PUBLIC_EXPONENT, e, sizeof(e)}
  };

  CK_MECHANISM keygen_mech = {CKM_RSA_PKCS_KEY_PAIR_GEN, NULL};
  CK_MECHANISM sign_mech = {CKM_RSA_PKCS, NULL};

  CK_OBJECT_HANDLE privkey[24], pubkey[24];

  CK_SESSION_HANDLE session;
  init_connection();
  asrt(funcs->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &session), CKR_OK, "OpenSession1");
  asrt(funcs->C_Login(session, CKU_SO, "010203040506070801020304050607080102030405060708", 48), CKR_OK, "Login SO");

  for (i = 0; i < 24; i++) {
    id = i+1;
    asrt(funcs->C_GenerateKeyPair(session, &keygen_mech, publicKeyTemplate, 4, privateKeyTemplate, 3, pubkey+i, privkey+i), CKR_OK, "GEN RSA KEYPAIR");
  }
  asrt(funcs->C_Logout(session), CKR_OK, "Logout SO");

  for (i = 0; i < 24; i++) {
    for (j = 0; j < 10; j++) {
      if(RAND_bytes(some_data, sizeof(some_data)) == -1)
        exit(EXIT_FAILURE);

      asrt(funcs->C_Login(session, CKU_USER, "123456", 6), CKR_OK, "Login USER");
      asrt(funcs->C_SignInit(session, &sign_mech, privkey[i]), CKR_OK, "SignInit");
      recv_len = sizeof(sig);
      asrt(funcs->C_Sign(session, some_data, sizeof(some_data), sig, &recv_len), CKR_OK, "Sign");
      
      asrt(funcs->C_VerifyInit(session, &sign_mech, pubkey[i]), CKR_OK, "VerifyInit");
      asrt(funcs->C_Verify(session, some_data, sizeof(some_data), sig, recv_len), CKR_OK, "Verify");

      asrt(funcs->C_VerifyInit(session, &sign_mech, pubkey[i]), CKR_OK, "VerifyInit");
      asrt(funcs->C_VerifyUpdate(session, some_data, 10), CKR_OK, "VerifyUpdate 1");
      asrt(funcs->C_VerifyUpdate(session, some_data+10, 22), CKR_OK, "VerifyUpdate 2");
      asrt(funcs->C_VerifyFinal(session, sig, recv_len), CKR_OK, "VerifyFinal");
    }
  }

  asrt(funcs->C_Logout(session), CKR_OK, "Logout USER");


  CK_OBJECT_HANDLE cert_handle;
  CK_ULONG n_cert_handle;
  CK_BYTE ckaid = 0;
  CK_ULONG class_cert = CKO_CERTIFICATE;
  CK_ATTRIBUTE idTemplate[] = {
    {CKA_ID, &ckaid, sizeof(ckaid)}
  };
  CK_ATTRIBUTE idClassTemplate[] = {
    {CKA_ID, &ckaid, sizeof(ckaid)},
    {CKA_CLASS, &class_cert, sizeof(class_cert)}
  };

  asrt(funcs->C_Login(session, CKU_SO, "010203040506070801020304050607080102030405060708", 48), CKR_OK, "Login SO");
  for(i=0; i<24; i++) {
    asrt(funcs->C_GetAttributeValue(session, privkey[i], idTemplate, 1), CKR_OK, "GET CKA_ID");
    asrt(funcs->C_FindObjectsInit(session, idClassTemplate, 2), CKR_OK, "FIND INIT");
    asrt(funcs->C_FindObjects(session, &cert_handle, 1, &n_cert_handle), CKR_OK, "FIND");
    asrt(funcs->C_FindObjectsFinal(session), CKR_OK, "FIND FINAL");

    asrt(funcs->C_DestroyObject(session, cert_handle), CKR_OK, "Destroy Object");
  }
  asrt(funcs->C_Logout(session), CKR_OK, "Logout SO");

  asrt(funcs->C_CloseSession(session), CKR_OK, "CloseSession");
  asrt(funcs->C_Finalize(NULL), CKR_OK, "FINALIZE");
  dprintf(0, "TEST END: test_generate_rsa()\n");
}

static void test_sign_update_RSA() {
  dprintf(0, "TEST START: test_sign_update()\n");

  CK_BYTE     i, j;
  CK_BYTE     some_data[32];
  CK_BYTE     sig_full[128];
  CK_BYTE     sig_update[128];
  CK_ULONG    recv_len_full;
  CK_ULONG    recv_len_update;
  CK_BYTE     e[] = {0x01, 0x00, 0x01};
  CK_ULONG    class_k = CKO_PRIVATE_KEY;
  CK_ULONG    class_c = CKO_PUBLIC_KEY;
  CK_ULONG    kt = CKK_RSA;
  CK_ULONG    key_size = 1024;
  CK_BYTE     id = 0;

  CK_ATTRIBUTE privateKeyTemplate[] = {
    {CKA_CLASS, &class_k, sizeof(class_k)},
    {CKA_KEY_TYPE, &kt, sizeof(kt)},
    {CKA_ID, &id, sizeof(id)}
  };

  CK_ATTRIBUTE publicKeyTemplate[] = {
    {CKA_CLASS, &class_c, sizeof(class_c)},
    {CKA_ID, &id, sizeof(id)},
    {CKA_MODULUS_BITS, &key_size, sizeof(key_size)},
    {CKA_PUBLIC_EXPONENT, e, sizeof(e)}
  };

  CK_MECHANISM keygen_mech = {CKM_RSA_PKCS_KEY_PAIR_GEN, NULL};
  CK_MECHANISM sign_mech_PKCS = {CKM_RSA_PKCS, NULL};
  CK_MECHANISM sign_mech_X509 = {CKM_RSA_X_509, NULL};
  CK_MECHANISM sign_mech_SHA1 = {CKM_SHA1_RSA_PKCS, NULL};
  CK_MECHANISM sign_mech_SHA256 = {CKM_SHA256_RSA_PKCS, NULL};
  CK_MECHANISM sign_mech_SHA384 = {CKM_SHA384_RSA_PKCS, NULL};
  CK_MECHANISM sign_mech_SHA512 = {CKM_SHA512_RSA_PKCS, NULL};



  CK_OBJECT_HANDLE privkey[24], pubkey[24];

  CK_SESSION_HANDLE session;
  init_connection();
  asrt(funcs->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &session), CKR_OK, "OpenSession1");
  asrt(funcs->C_Login(session, CKU_SO, "010203040506070801020304050607080102030405060708", 48), CKR_OK, "Login SO");

  for (i = 0; i < 24; i++) {
    id = i+1;
    asrt(funcs->C_GenerateKeyPair(session, &keygen_mech, publicKeyTemplate, 4, privateKeyTemplate, 3, pubkey+i, privkey+i), CKR_OK, "GEN RSA KEYPAIR");
  }
  asrt(funcs->C_Logout(session), CKR_OK, "Logout SO");

  for (i = 0; i < 24; i++) {
    for (j = 0; j < 10; j++) {
      if(RAND_bytes(some_data, sizeof(some_data)) == -1)
        exit(EXIT_FAILURE);
      asrt(funcs->C_Login(session, CKU_USER, "123456", 6), CKR_OK, "Login USER");

      // CKM_RSA_PKCS
      // C_Sign
      asrt(funcs->C_SignInit(session, &sign_mech_PKCS, privkey[i]), CKR_OK, "SignInit CKM_RSA_PKCS");
      recv_len_full = sizeof(sig_full);
      asrt(funcs->C_Sign(session, some_data, sizeof(some_data), sig_full, &recv_len_full), CKR_OK, "Sign CKM_RSA_PKCS");
      asrt(recv_len_full, 128, "Signature Length");
      //C_SignUpdate
      asrt(funcs->C_SignInit(session, &sign_mech_PKCS, privkey[i]), CKR_OK, "SignInit CKM_RSA_PKCS");
      recv_len_update = sizeof(sig_update);
      asrt(funcs->C_SignUpdate(session, some_data, 16), CKR_OK, "SignUpdate 1 CKM_RSA_PKCS");
      asrt(funcs->C_SignUpdate(session, some_data + 16, 10), CKR_OK, "SignUpdate 2 CKM_RSA_PKCS");
      asrt(funcs->C_SignUpdate(session, some_data + 26, 6), CKR_OK, "SignUpdate 3 CKM_RSA_PKCS");
      asrt(funcs->C_SignFinal(session, sig_update, &recv_len_update), CKR_OK, "SignFinal CKM_RSA_PKCS");
      asrt(recv_len_update, 128, "Signature Length CKM_RSA_PKCS");
      // Compare signatures
      asrt(memcmp(sig_full, sig_update, recv_len_full), 0, "Signature Compare CKM_RSA_PKCS");
      
      // CKM_RSA_X_509
      // C_Sign
      asrt(funcs->C_SignInit(session, &sign_mech_X509, privkey[i]), CKR_OK, "SignInit CKM_RSA_X_509");
      recv_len_full = sizeof(sig_full);
      asrt(funcs->C_Sign(session, some_data, sizeof(some_data), sig_full, &recv_len_full), CKR_OK, "Sign CKM_RSA_X_509");
      asrt(recv_len_full, 128, "Signature Length CKM_RSA_X_509");
      //C_SignUpdate
      asrt(funcs->C_SignInit(session, &sign_mech_X509, privkey[i]), CKR_OK, "SignInit CKM_RSA_X_509");
      recv_len_update = sizeof(sig_update);
      asrt(funcs->C_SignUpdate(session, some_data, 16), CKR_OK, "SignUpdate 1 CKM_RSA_X_509");
      asrt(funcs->C_SignUpdate(session, some_data + 16, 10), CKR_OK, "SignUpdate 2 CKM_RSA_X_509");
      asrt(funcs->C_SignUpdate(session, some_data + 26, 6), CKR_OK, "SignUpdate 3 CKM_RSA_X_509");
      asrt(funcs->C_SignFinal(session, sig_update, &recv_len_update), CKR_OK, "SignFinal CKM_RSA_X_509");
      asrt(recv_len_update, 128, "Signature Length CKM_RSA_X_509");
      // Compare signatures
      asrt(memcmp(sig_full, sig_update, recv_len_full), 0, "Signature Compare CKM_RSA_X_509");

      // CKM_SHA1_RSA_PKCS
      // C_Sign
      asrt(funcs->C_SignInit(session, &sign_mech_SHA1, privkey[i]), CKR_OK, "SignInit CKM_SHA1_RSA_PKCS");
      recv_len_full = sizeof(sig_full);
      asrt(funcs->C_Sign(session, some_data, sizeof(some_data), sig_full, &recv_len_full), CKR_OK, "Sign CKM_SHA1_RSA_PKCS");
      asrt(recv_len_full, 128, "Signature Length CKM_SHA1_RSA_PKCS");
      //C_SignUpdate
      asrt(funcs->C_SignInit(session, &sign_mech_SHA1, privkey[i]), CKR_OK, "SignInit CKM_SHA1_RSA_PKCS");
      recv_len_update = sizeof(sig_update);
      asrt(funcs->C_SignUpdate(session, some_data, 16), CKR_OK, "SignUpdate 1 CKM_SHA1_RSA_PKCS");
      asrt(funcs->C_SignUpdate(session, some_data + 16, 10), CKR_OK, "SignUpdate 2 CKM_SHA1_RSA_PKCS");
      asrt(funcs->C_SignUpdate(session, some_data + 26, 6), CKR_OK, "SignUpdate 3 CKM_SHA1_RSA_PKCS");
      asrt(funcs->C_SignFinal(session, sig_update, &recv_len_update), CKR_OK, "SignFinal CKM_SHA1_RSA_PKCS");
      asrt(recv_len_update, 128, "Signature Length CKM_SHA1_RSA_PKCS");
      // Compare signatures
      asrt(memcmp(sig_full, sig_update, recv_len_full), 0, "Signature Compare CKM_SHA1_RSA_PKCS");

      // CKM_SHA256_RSA_PKCS
      // C_Sign
      asrt(funcs->C_SignInit(session, &sign_mech_SHA256, privkey[i]), CKR_OK, "SignInit CKM_SHA256_RSA_PKCS");
      recv_len_full = sizeof(sig_full);
      asrt(funcs->C_Sign(session, some_data, sizeof(some_data), sig_full, &recv_len_full), CKR_OK, "Sign CKM_SHA256_RSA_PKCS");
      asrt(recv_len_full, 128, "Signature Length CKM_SHA256_RSA_PKCS");
      //C_SignUpdate
      asrt(funcs->C_SignInit(session, &sign_mech_SHA256, privkey[i]), CKR_OK, "SignInit CKM_SHA256_RSA_PKCS");
      recv_len_update = sizeof(sig_update);
      asrt(funcs->C_SignUpdate(session, some_data, 16), CKR_OK, "SignUpdate 1 CKM_SHA256_RSA_PKCS");
      asrt(funcs->C_SignUpdate(session, some_data + 16, 10), CKR_OK, "SignUpdate 2 CKM_SHA256_RSA_PKCS");
      asrt(funcs->C_SignUpdate(session, some_data + 26, 6), CKR_OK, "SignUpdate 3 CKM_SHA256_RSA_PKCS");
      asrt(funcs->C_SignFinal(session, sig_update, &recv_len_update), CKR_OK, "SignFinal CKM_SHA256_RSA_PKCS");
      asrt(recv_len_update, 128, "Signature Length CKM_SHA256_RSA_PKCS");
      // Compare signatures
      asrt(memcmp(sig_full, sig_update, recv_len_full), 0, "Signature Compare CKM_SHA256_RSA_PKCS");

      // CKM_SHA384_RSA_PKCS
      // C_Sign
      asrt(funcs->C_SignInit(session, &sign_mech_SHA384, privkey[i]), CKR_OK, "SignInit CKM_SHA384_RSA_PKCS");
      recv_len_full = sizeof(sig_full);
      asrt(funcs->C_Sign(session, some_data, sizeof(some_data), sig_full, &recv_len_full), CKR_OK, "Sign CKM_SHA384_RSA_PKCS");
      asrt(recv_len_full, 128, "Signature Length CKM_SHA384_RSA_PKCS");
      //C_SignUpdate
      asrt(funcs->C_SignInit(session, &sign_mech_SHA384, privkey[i]), CKR_OK, "SignInit CKM_SHA384_RSA_PKCS");
      recv_len_update = sizeof(sig_update);
      asrt(funcs->C_SignUpdate(session, some_data, 16), CKR_OK, "SignUpdate 1 CKM_SHA384_RSA_PKCS");
      asrt(funcs->C_SignUpdate(session, some_data + 16, 10), CKR_OK, "SignUpdate 2 CKM_SHA384_RSA_PKCS");
      asrt(funcs->C_SignUpdate(session, some_data + 26, 6), CKR_OK, "SignUpdate 3 CKM_SHA384_RSA_PKCS");
      asrt(funcs->C_SignFinal(session, sig_update, &recv_len_update), CKR_OK, "SignFinal CKM_SHA384_RSA_PKCS");
      asrt(recv_len_update, 128, "Signature Length CKM_SHA384_RSA_PKCS");
      // Compare signatures
      asrt(memcmp(sig_full, sig_update, recv_len_full), 0, "Signature Compare CKM_SHA384_RSA_PKCS");

      // CKM_SHA512_RSA_PKCS
      // C_Sign
      asrt(funcs->C_SignInit(session, &sign_mech_SHA512, privkey[i]), CKR_OK, "SignInit CKM_SHA512_RSA_PKCS");
      recv_len_full = sizeof(sig_full);
      asrt(funcs->C_Sign(session, some_data, sizeof(some_data), sig_full, &recv_len_full), CKR_OK, "Sign CKM_SHA512_RSA_PKCS");
      asrt(recv_len_full, 128, "Signature Length CKM_SHA512_RSA_PKCS");
      //C_SignUpdate
      asrt(funcs->C_SignInit(session, &sign_mech_SHA512, privkey[i]), CKR_OK, "SignInit CKM_SHA512_RSA_PKCS");
      recv_len_update = sizeof(sig_update);
      asrt(funcs->C_SignUpdate(session, some_data, 16), CKR_OK, "SignUpdate 1 CKM_SHA512_RSA_PKCS");
      asrt(funcs->C_SignUpdate(session, some_data + 16, 10), CKR_OK, "SignUpdate 2 CKM_SHA512_RSA_PKCS");
      asrt(funcs->C_SignUpdate(session, some_data + 26, 6), CKR_OK, "SignUpdate 3 CKM_SHA512_RSA_PKCS");
      asrt(funcs->C_SignFinal(session, sig_update, &recv_len_update), CKR_OK, "SignFinal CKM_SHA512_RSA_PKCS");
      asrt(recv_len_update, 128, "Signature Length CKM_SHA512_RSA_PKCS");
      // Compare signatures
      asrt(memcmp(sig_full, sig_update, recv_len_full), 0, "Signature Compare CKM_SHA512_RSA_PKCS");
    }
  }

  asrt(funcs->C_Logout(session), CKR_OK, "Logout USER");


  CK_OBJECT_HANDLE cert_handle;
  CK_ULONG n_cert_handle;
  CK_BYTE ckaid = 0;
  CK_ULONG class_cert = CKO_CERTIFICATE;
  CK_ATTRIBUTE idTemplate[] = {
    {CKA_ID, &ckaid, sizeof(ckaid)}
  };
  CK_ATTRIBUTE idClassTemplate[] = {
    {CKA_ID, &ckaid, sizeof(ckaid)},
    {CKA_CLASS, &class_cert, sizeof(class_cert)}
  };

  asrt(funcs->C_Login(session, CKU_SO, "010203040506070801020304050607080102030405060708", 48), CKR_OK, "Login SO");
  for(i=0; i<24; i++) {
    asrt(funcs->C_GetAttributeValue(session, privkey[i], idTemplate, 1), CKR_OK, "GET CKA_ID");
    asrt(funcs->C_FindObjectsInit(session, idClassTemplate, 2), CKR_OK, "FIND INIT");
    asrt(funcs->C_FindObjects(session, &cert_handle, 1, &n_cert_handle), CKR_OK, "FIND");
    asrt(funcs->C_FindObjectsFinal(session), CKR_OK, "FIND FINAL");

    asrt(funcs->C_DestroyObject(session, cert_handle), CKR_OK, "Destroy Object");
  }
  asrt(funcs->C_Logout(session), CKR_OK, "Logout SO");

  asrt(funcs->C_CloseSession(session), CKR_OK, "CloseSession");
  asrt(funcs->C_Finalize(NULL), CKR_OK, "FINALIZE");
  dprintf(0, "TEST END: test_sign_update()\n");
}

static void test_find_objects() {
  dprintf(0, "TEST START: test_find_objects()\n");

  CK_BYTE     i;
  CK_BYTE     some_data[32];
  CK_BYTE     e[] = {0x01, 0x00, 0x01};
  CK_ULONG    class_priv = CKO_PRIVATE_KEY;
  CK_ULONG    class_pub = CKO_PUBLIC_KEY;
  CK_ULONG    class_cert = CKO_CERTIFICATE;
  CK_ULONG    class_data = CKO_DATA;
  CK_ULONG    kt = CKK_RSA;
  CK_ULONG    key_size = 1024;
  CK_BYTE     id = 1;
  CK_BYTE     sig[2048];
  CK_ULONG    recv_len;

  CK_ATTRIBUTE privateKeyTemplate[] = {
    {CKA_CLASS, &class_priv, sizeof(class_priv)},
    {CKA_KEY_TYPE, &kt, sizeof(kt)},
    {CKA_ID, &id, sizeof(id)}
  };

  CK_ATTRIBUTE publicKeyTemplate[] = {
    {CKA_CLASS, &class_pub, sizeof(class_pub)},
    {CKA_ID, &id, sizeof(id)},
    {CKA_MODULUS_BITS, &key_size, sizeof(key_size)},
    {CKA_PUBLIC_EXPONENT, e, sizeof(e)}
  };

  CK_MECHANISM keygen_mech = {CKM_RSA_PKCS_KEY_PAIR_GEN, NULL};
  CK_MECHANISM sign_mech = {CKM_RSA_PKCS, NULL};

  CK_OBJECT_HANDLE privkey, pubkey;
  CK_SESSION_HANDLE session;

  init_connection();
  asrt(funcs->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &session), CKR_OK, "OpenSession1");
  asrt(funcs->C_Login(session, CKU_SO, "010203040506070801020304050607080102030405060708", 48), CKR_OK, "Login SO");
  asrt(funcs->C_GenerateKeyPair(session, &keygen_mech, publicKeyTemplate, 4, privateKeyTemplate, 3, &pubkey, &privkey), CKR_OK, "GEN RSA KEYPAIR");
  asrt(funcs->C_Logout(session), CKR_OK, "Logout SO");

  if(RAND_bytes(some_data, sizeof(some_data)) == -1) {
    exit(EXIT_FAILURE);
  }

  asrt(funcs->C_Login(session, CKU_USER, "123456", 6), CKR_OK, "Login USER");
  asrt(funcs->C_SignInit(session, &sign_mech, privkey), CKR_OK, "SignInit");
  recv_len = sizeof(sig);
  asrt(funcs->C_Sign(session, some_data, sizeof(some_data), sig, &recv_len), CKR_OK, "Sign");


  CK_OBJECT_HANDLE found_obj[10];
  CK_ULONG n_found_obj = 0;
  CK_ULONG object_class;
  CK_BYTE ckaid = 0;
  CK_BBOOL private_key = CK_FALSE;
  CK_BBOOL public_key  = CK_FALSE;
  CK_BBOOL cert = CK_FALSE;
  CK_BBOOL data = CK_FALSE;

  CK_ATTRIBUTE idTemplate[] = {
    {CKA_ID, &ckaid, sizeof(ckaid)}
  };
  CK_ATTRIBUTE classTemplate[] = {
    {CKA_CLASS, &object_class, sizeof(CK_ULONG)}
  };
  CK_ATTRIBUTE idClassTemplate[] = {
    {CKA_ID, &ckaid, sizeof(ckaid)},
    {CKA_CLASS, &object_class, sizeof(CK_ULONG)}
  };


  asrt(funcs->C_GetAttributeValue(session, privkey, idTemplate, 1), CKR_OK, "GET CKA_ID");
  asrt(funcs->C_FindObjectsInit(session, idTemplate, 1), CKR_OK, "FIND INIT");
  asrt(funcs->C_FindObjects(session, found_obj, 10, &n_found_obj), CKR_OK, "FIND");
  asrt(n_found_obj, 4, "N FOUND OBJS");
  asrt(funcs->C_FindObjectsFinal(session), CKR_OK, "FIND FINAL");

  for(i=0; i<4; i++) {
    asrt(funcs->C_GetAttributeValue(session, found_obj[i], classTemplate, 1), CKR_OK, "GET CKA_CLASS");
    if(object_class == CKO_PRIVATE_KEY) {
      private_key = CK_TRUE;
    } else if(object_class == CKO_PUBLIC_KEY) {
      public_key = CK_TRUE;
    }  else if(object_class == CKO_CERTIFICATE) {
      cert = CK_TRUE;
    } else if(object_class == CKO_DATA) {
      data = CK_TRUE;
    }
  }
  asrt(private_key, CK_TRUE, "NO PRIVATE KEY");
  asrt(public_key, CK_TRUE, "NO PUBLIC KEY");
  asrt(cert, CK_TRUE, "NO CERTIFICATE");
  asrt(data, CK_TRUE, "NO DATA");

  object_class = CKO_PRIVATE_KEY;
  asrt(funcs->C_FindObjectsInit(session, idClassTemplate, 2), CKR_OK, "FIND INIT");
  asrt(funcs->C_FindObjects(session, found_obj, 10, &n_found_obj), CKR_OK, "FIND");
  asrt(n_found_obj, 1, "N FOUND OBJS");
  asrt(funcs->C_FindObjectsFinal(session), CKR_OK, "FIND FINAL");

  asrt(funcs->C_SignInit(session, &sign_mech, found_obj[0]), CKR_OK, "SignInit");
  recv_len = sizeof(sig);
  asrt(funcs->C_Sign(session, some_data, sizeof(some_data), sig, &recv_len), CKR_OK, "Sign");

  object_class = CKO_PUBLIC_KEY;
  asrt(funcs->C_FindObjectsInit(session, idClassTemplate, 2), CKR_OK, "FIND INIT");
  asrt(funcs->C_FindObjects(session, found_obj, 10, &n_found_obj), CKR_OK, "FIND");
  asrt(n_found_obj, 1, "N FOUND OBJS");
  asrt(funcs->C_FindObjectsFinal(session), CKR_OK, "FIND FINAL");

  object_class = CKO_DATA;
  asrt(funcs->C_FindObjectsInit(session, idClassTemplate, 2), CKR_OK, "FIND INIT");
  asrt(funcs->C_FindObjects(session, found_obj, 10, &n_found_obj), CKR_OK, "FIND");
  asrt(n_found_obj, 1, "N FOUND OBJS");
  asrt(funcs->C_FindObjectsFinal(session), CKR_OK, "FIND FINAL");

  object_class = CKO_CERTIFICATE;
  asrt(funcs->C_FindObjectsInit(session, idClassTemplate, 2), CKR_OK, "FIND INIT");
  asrt(funcs->C_FindObjects(session, found_obj, 10, &n_found_obj), CKR_OK, "FIND");
  asrt(n_found_obj, 1, "N FOUND OBJS");
  asrt(funcs->C_FindObjectsFinal(session), CKR_OK, "FIND FINAL");

  asrt(funcs->C_Logout(session), CKR_OK, "Logout USER");

  asrt(funcs->C_Login(session, CKU_SO, "010203040506070801020304050607080102030405060708", 48), CKR_OK, "Login SO");
  asrt(funcs->C_DestroyObject(session, found_obj[0]), CKR_OK, "Destroy Object");
  asrt(funcs->C_Logout(session), CKR_OK, "Logout SO");

  asrt(funcs->C_CloseSession(session), CKR_OK, "CloseSession");
  asrt(funcs->C_Finalize(NULL), CKR_OK, "FINALIZE");
  dprintf(0, "TEST END: test_find_objects()\n");
}

static CK_OBJECT_HANDLE get_public_key_handle(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE privkey) {
  CK_OBJECT_HANDLE found_obj[10];
  CK_ULONG n_found_obj = 0;
  CK_ULONG class_pub = CKO_PUBLIC_KEY;
  CK_BYTE ckaid = 0;

  CK_ATTRIBUTE idTemplate[] = {
    {CKA_ID, &ckaid, sizeof(ckaid)}
  };
  CK_ATTRIBUTE idClassTemplate[] = {
    {CKA_ID, &ckaid, sizeof(ckaid)},
    {CKA_CLASS, &class_pub, sizeof(class_pub)}
  };

  asrt(funcs->C_GetAttributeValue(session, privkey, idTemplate, 1), CKR_OK, "GET CKA_ID");
  asrt(funcs->C_FindObjectsInit(session, idClassTemplate, 2), CKR_OK, "FIND INIT");
  asrt(funcs->C_FindObjects(session, found_obj, 10, &n_found_obj), CKR_OK, "FIND");
  asrt(n_found_obj, 1, "N FOUND OBJS");
  asrt(funcs->C_FindObjectsFinal(session), CKR_OK, "FIND FINAL");
  return found_obj[0];
}

// Import a newly generated P256 pvt key and a certificate
// to every slot and use the key to sign some data
static void test_import_and_sign_all_10() {
  dprintf(0, "TEST START: test_import_and_sign_all_10()\n");

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

  CK_OBJECT_HANDLE obj_cert[24], obj_pvtkey[24];
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

#if (OPENSSL_VERSION_NUMBER < 0x10100000L) || defined(LIBRESSL_VERSION_NUMBER)
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

  init_connection();
  asrt(funcs->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &session), CKR_OK, "OpenSession1");
  asrt(funcs->C_Login(session, CKU_SO, "010203040506070801020304050607080102030405060708", 48), CKR_OK, "Login SO");

  for (i = 0; i < 24; i++) {
    id = i+1;
    asrt(funcs->C_CreateObject(session, publicKeyTemplate, 3, obj_cert + i), CKR_OK, "IMPORT CERT");
    asrt(funcs->C_CreateObject(session, privateKeyTemplate, 5, obj_pvtkey + i), CKR_OK, "IMPORT KEY");
  }

  asrt(funcs->C_Logout(session), CKR_OK, "Logout SO");

  for (i = 0; i < 24; i++) {
    for (j = 0; j < 10; j++) {

      if(RAND_bytes(some_data, sizeof(some_data)) == -1)
        exit(EXIT_FAILURE);

      asrt(funcs->C_Login(session, CKU_USER, "123456", 6), CKR_OK, "Login USER");
      asrt(funcs->C_SignInit(session, &mech, obj_pvtkey[i]), CKR_OK, "SignInit");

      recv_len = sizeof(sig);
      asrt(funcs->C_Sign(session, some_data, sizeof(some_data), sig, &recv_len), CKR_OK, "Sign");

      // Internal verification
      asrt(funcs->C_VerifyInit(session, &mech, get_public_key_handle(session, obj_pvtkey[i])), CKR_OK, "VerifyInit");
      asrt(funcs->C_Verify(session, some_data, sizeof(some_data), sig, recv_len), CKR_OK, "Verify");


      // External verification
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

  asrt(funcs->C_Login(session, CKU_SO, "010203040506070801020304050607080102030405060708", 48), CKR_OK, "Login SO");
  for(i=0; i<24; i++) {
    asrt(funcs->C_DestroyObject(session, obj_cert[i]), CKR_OK, "Destroy Object");
  }
  asrt(funcs->C_Logout(session), CKR_OK, "Logout SO");

  asrt(funcs->C_CloseSession(session), CKR_OK, "CloseSession");
  asrt(funcs->C_Finalize(NULL), CKR_OK, "FINALIZE");

  dprintf(0, "TEST END: test_import_and_sign_all_10()\n");
}

// Import a newly generated P384 pvt key and a certificate
// to every slot and use the key to sign some data
static void test_import_and_sign_all_10_P384() {
  dprintf(0, "TEST START: test_import_and_sign_all_10_P384()\n");
  EVP_PKEY       *evp;
  EC_KEY         *eck;
  const EC_POINT *ecp;
  const BIGNUM   *bn;
  char           pvt[48];
  X509           *cert;
  ASN1_TIME      *tm;
  CK_BYTE        i, j;
  CK_BYTE        some_data[16];

  CK_ULONG    class_k = CKO_PRIVATE_KEY;
  CK_ULONG    class_c = CKO_CERTIFICATE;
  CK_ULONG    kt = CKK_ECDSA;
  CK_BYTE     id = 0;
  CK_BYTE     params[] = {0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22};
  CK_BYTE     sig[96];
  CK_ULONG    recv_len;
  CK_BYTE     value_c[3100];
  CK_ULONG    cert_len;
  CK_BYTE     der_encoded[110];
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

  CK_OBJECT_HANDLE obj_cert[24], obj_pvtkey[24];
  CK_SESSION_HANDLE session;
  CK_MECHANISM mech = {CKM_ECDSA_SHA384, NULL};

  evp = EVP_PKEY_new();

  if (evp == NULL)
    exit(EXIT_FAILURE);

  eck = EC_KEY_new_by_curve_name(NID_secp384r1);

  if (eck == NULL)
    exit(EXIT_FAILURE);

  asrt(EC_KEY_generate_key(eck), 1, "GENERATE ECK");

  bn = EC_KEY_get0_private_key(eck);

  asrt(BN_bn2bin(bn, pvt), 48, "EXTRACT PVT");

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

#if (OPENSSL_VERSION_NUMBER < 0x10100000L) || defined(LIBRESSL_VERSION_NUMBER)
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

  init_connection();
  asrt(funcs->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &session), CKR_OK, "OpenSession1");
  asrt(funcs->C_Login(session, CKU_SO, "010203040506070801020304050607080102030405060708", 48), CKR_OK, "Login SO");

  for (i = 0; i < 24; i++) {
    id = i+1;
    asrt(funcs->C_CreateObject(session, publicKeyTemplate, 3, obj_cert + i), CKR_OK, "IMPORT CERT384");
    asrt(funcs->C_CreateObject(session, privateKeyTemplate, 5, obj_pvtkey + i), CKR_OK, "IMPORT KEY384");
  }

  asrt(funcs->C_Logout(session), CKR_OK, "Logout SO");

  for (i = 0; i < 24; i++) {
    for (j = 0; j < 10; j++) {

      if(RAND_bytes(some_data, sizeof(some_data)) == -1)
        exit(EXIT_FAILURE);

      asrt(funcs->C_Login(session, CKU_USER, "123456", 6), CKR_OK, "Login USER");
      asrt(funcs->C_SignInit(session, &mech, obj_pvtkey[i]), CKR_OK, "SignInit");

      recv_len = sizeof(sig);
      asrt(funcs->C_Sign(session, some_data, sizeof(some_data), sig, &recv_len), CKR_OK, "Sign");

      // Internal verification
      asrt(funcs->C_VerifyInit(session, &mech, get_public_key_handle(session, obj_pvtkey[i])), CKR_OK, "VerifyInit");
      asrt(funcs->C_Verify(session, some_data, sizeof(some_data), sig, recv_len), CKR_OK, "Verify");

      // External verification
      r_len = 48;
      s_len = 48;

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

      s_ptr = sig + 48;

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

      CK_BYTE some_data_hashed[48];
      SHA384(some_data, sizeof(some_data), some_data_hashed);
      asrt(ECDSA_verify(0, some_data_hashed, sizeof(some_data_hashed), der_encoded, der_encoded[1] + 2, eck), 1, "ECDSA-SHA384 VERIFICATION");
    }
  }

  asrt(funcs->C_Logout(session), CKR_OK, "Logout USER");

  asrt(funcs->C_Login(session, CKU_SO, "010203040506070801020304050607080102030405060708", 48), CKR_OK, "Login SO");
  for(i=0; i<24; i++) {
    asrt(funcs->C_DestroyObject(session, obj_cert[i]), CKR_OK, "Destroy Object");
  }
  asrt(funcs->C_Logout(session), CKR_OK, "Logout SO");

  asrt(funcs->C_CloseSession(session), CKR_OK, "CloseSession");
  asrt(funcs->C_Finalize(NULL), CKR_OK, "FINALIZE");
  dprintf(0, "TEST END: test_import_and_sign_all_10_P384()\n");
}

// Import a newly generated RSA1024 pvt key and a certificate
// to every slot and use the key to sign some data and verify the signature
static void test_import_and_sign_all_10_RSA() {
  dprintf(0, "TEST START: test_import_and_sign_all_10_RSA()\n");

  EVP_PKEY_CTX *ctx = NULL;
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
  CK_BYTE     sig[2048];
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

  CK_OBJECT_HANDLE obj_cert[24], obj_pvtkey[24];
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

#if (OPENSSL_VERSION_NUMBER < 0x10100000L) || defined(LIBRESSL_VERSION_NUMBER)
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

  init_connection();
  asrt(funcs->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &session), CKR_OK, "OpenSession1");
  asrt(funcs->C_Login(session, CKU_SO, "010203040506070801020304050607080102030405060708", 48), CKR_OK, "Login SO");

  for (i = 0; i < 24; i++) {
    id = i+1;
    asrt(funcs->C_CreateObject(session, publicKeyTemplate, 3, obj_cert + i), CKR_OK, "IMPORT CERT");
    asrt(funcs->C_CreateObject(session, privateKeyTemplate, 9, obj_pvtkey + i), CKR_OK, "IMPORT KEY");
  }

  asrt(funcs->C_Logout(session), CKR_OK, "Logout SO");

  evp = X509_get_pubkey(cert);

  for (i = 0; i < 24; i++) {
    for (j = 0; j < 10; j++) {

      if(RAND_bytes(some_data, sizeof(some_data)) == -1)
        exit(EXIT_FAILURE);

      asrt(funcs->C_Login(session, CKU_USER, "123456", 6), CKR_OK, "Login USER");
      asrt(funcs->C_SignInit(session, &mech, obj_pvtkey[i]), CKR_OK, "SignInit");

      recv_len = sizeof(sig);
      asrt(funcs->C_Sign(session, some_data, sizeof(some_data), sig, &recv_len), CKR_OK, "Sign");
      
      // Internal verification
      asrt(funcs->C_VerifyInit(session, &mech, get_public_key_handle(session, obj_pvtkey[i])), CKR_OK, "VerifyInit");
      asrt(funcs->C_Verify(session, some_data, sizeof(some_data), sig, recv_len), CKR_OK, "Verify");

      // External verification
      ctx = EVP_PKEY_CTX_new(evp, NULL);
      asrt(ctx != NULL, true, "EVP_KEY_CTX_new");
      asrt(EVP_PKEY_verify_init(ctx) > 0, true, "EVP_KEY_verify_init");
      asrt(EVP_PKEY_CTX_set_signature_md(ctx, NULL) > 0, true, "EVP_PKEY_CTX_set_signature_md");
      asrt(EVP_PKEY_verify(ctx, sig, recv_len, some_data, sizeof(some_data)), 1, "EVP_PKEY_verify");
    }
  }

  asrt(funcs->C_Logout(session), CKR_OK, "Logout USER");

  asrt(funcs->C_Login(session, CKU_SO, "010203040506070801020304050607080102030405060708", 48), CKR_OK, "Login SO");
  for(i=0; i<24; i++) {
    asrt(funcs->C_DestroyObject(session, obj_cert[i]), CKR_OK, "Destroy Object");
  }
  asrt(funcs->C_Logout(session), CKR_OK, "Logout SO");

  asrt(funcs->C_CloseSession(session), CKR_OK, "CloseSession");
  asrt(funcs->C_Finalize(NULL), CKR_OK, "FINALIZE");
  dprintf(0, "TEST END: test_import_and_sign_all_10_RSA()\n");
}

// Import a newly generated RSA1024 pvt key and a certificate
// to every slot and use the key to sign some data and verify the signature
static void test_import_and_sign_RSA_SHA256() {
  dprintf(0, "TEST START: test_import_and_sign_RSA_SHA256()\n");

  EVP_PKEY_CTX *ctx = NULL;
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
  CK_BYTE     sig[2048];
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
  CK_BYTE     digest_info[] = {0x30, 0x31, 0x30, 0x0D, 0x06, 
                               0x09, 0x60, 0x86, 0x48, 0x01,
                               0x65, 0x03, 0x04, 0x02, 0x01,
                               0x05, 0x00, 0x04, 0x20};
  CK_BYTE     some_data_hashed[32 + sizeof(digest_info)];

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

  CK_OBJECT_HANDLE obj_cert[24], obj_pvtkey[24];
  CK_SESSION_HANDLE session;
  CK_MECHANISM mech = {CKM_SHA256_RSA_PKCS, NULL};

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

#if (OPENSSL_VERSION_NUMBER < 0x10100000L) || defined(LIBRESSL_VERSION_NUMBER)
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

  init_connection();
  asrt(funcs->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &session), CKR_OK, "OpenSession1");
  asrt(funcs->C_Login(session, CKU_SO, "010203040506070801020304050607080102030405060708", 48), CKR_OK, "Login SO");

  for (i = 0; i < 24; i++) {
    id = i+1;
    asrt(funcs->C_CreateObject(session, publicKeyTemplate, 3, obj_cert + i), CKR_OK, "IMPORT CERT");
    asrt(funcs->C_CreateObject(session, privateKeyTemplate, 9, obj_pvtkey + i), CKR_OK, "IMPORT KEY");
  }

  asrt(funcs->C_Logout(session), CKR_OK, "Logout SO");

  evp = X509_get_pubkey(cert);

  for (i = 0; i < 24; i++) {
    for (j = 0; j < 10; j++) {

      if(RAND_bytes(some_data, sizeof(some_data)) == -1)
        exit(EXIT_FAILURE);

      asrt(funcs->C_Login(session, CKU_USER, "123456", 6), CKR_OK, "Login USER");
      asrt(funcs->C_SignInit(session, &mech, obj_pvtkey[i]), CKR_OK, "SignInit");

      recv_len = sizeof(sig);
      asrt(funcs->C_Sign(session, some_data, sizeof(some_data), sig, &recv_len), CKR_OK, "Sign");
      
      // Internal verification
      asrt(funcs->C_VerifyInit(session, &mech, get_public_key_handle(session, obj_pvtkey[i])), CKR_OK, "VerifyInit");
      asrt(funcs->C_Verify(session, some_data, sizeof(some_data), sig, recv_len), CKR_OK, "Verify");

      // External verification
      memcpy(some_data_hashed, digest_info, sizeof(digest_info));
      SHA256(some_data, sizeof(some_data), some_data_hashed + sizeof(digest_info));
      dump_hex(some_data_hashed, some_data_hashed[1] + 2, stderr, 1);

      ctx = EVP_PKEY_CTX_new(evp, NULL);
      asrt(ctx != NULL, true, "EVP_KEY_CTX_new");
      asrt(EVP_PKEY_verify_init(ctx) > 0, true, "EVP_KEY_verify_init");
      asrt(EVP_PKEY_CTX_set_signature_md(ctx, NULL) > 0, true, "EVP_PKEY_CTX_set_signature_md");
      asrt(EVP_PKEY_verify(ctx, sig, recv_len, some_data_hashed, sizeof(some_data_hashed)), 1, "EVP_PKEY_verify");
    }
  }

  asrt(funcs->C_Logout(session), CKR_OK, "Logout USER");

  asrt(funcs->C_Login(session, CKU_SO, "010203040506070801020304050607080102030405060708", 48), CKR_OK, "Login SO");
  for(i=0; i<24; i++) {
    asrt(funcs->C_DestroyObject(session, obj_cert[i]), CKR_OK, "Destroy Object");
  }
  asrt(funcs->C_Logout(session), CKR_OK, "Logout SO");

  asrt(funcs->C_CloseSession(session), CKR_OK, "CloseSession");
  asrt(funcs->C_Finalize(NULL), CKR_OK, "FINALIZE");
  dprintf(0, "TEST END: test_import_and_sign_RSA_SHA256()\n");
}

static void test_decrypt_RSA() {
  dprintf(0, "TEST START: test_decrypt_RSA()\n");

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
  CK_BYTE     sig[2048];
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

  CK_OBJECT_HANDLE obj_cert[24], obj_pvtkey[24];
  CK_SESSION_HANDLE session;
  CK_MECHANISM mech_PKCS = {CKM_RSA_PKCS, NULL};
  CK_MECHANISM mech_X509 = {CKM_RSA_X_509, NULL};

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

#if (OPENSSL_VERSION_NUMBER < 0x10100000L) || defined(LIBRESSL_VERSION_NUMBER)
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

  init_connection();
  asrt(funcs->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &session), CKR_OK, "OpenSession1");
  asrt(funcs->C_Login(session, CKU_SO, "010203040506070801020304050607080102030405060708", 48), CKR_OK, "Login SO");

  for (i = 0; i < 24; i++) {
    id = i+1;
    asrt(funcs->C_CreateObject(session, publicKeyTemplate, 3, obj_cert + i), CKR_OK, "IMPORT CERT");
    asrt(funcs->C_CreateObject(session, privateKeyTemplate, 9, obj_pvtkey + i), CKR_OK, "IMPORT KEY");
  }


  asrt(funcs->C_Logout(session), CKR_OK, "Logout SO");

  CK_BYTE   enc[512];
  CK_ULONG  enc_len;
  CK_BYTE   dec[512];
  CK_ULONG  dec_len;

  for (i = 0; i < 24; i++) {
    for (j = 0; j < 10; j++) {
    
      if(RAND_bytes(some_data, sizeof(some_data)) == -1)
        exit(EXIT_FAILURE);

      asrt(funcs->C_Login(session, CKU_USER, "123456", 6), CKR_OK, "Login USER");

      enc_len = RSA_public_encrypt(32, some_data, enc, rsak, RSA_PKCS1_PADDING);

      // Decryption using CKM_RSA_PKCS
      asrt(funcs->C_DecryptInit(session, &mech_PKCS, obj_pvtkey[i]), CKR_OK, "DECRYPT INIT CKM_RSA_PKCS");
      asrt(funcs->C_Decrypt(session, enc, enc_len, dec, &dec_len), CKR_OK, "DECRYPT CKM_RSA_PKCS");
      asrt(dec_len, 32, "DECRYPTED DATA LEN CKM_RSA_PKCS");
      asrt(memcmp(some_data, dec, dec_len), 0, "DECRYPTED DATA CKM_RSA_PKCS");

      asrt(funcs->C_DecryptInit(session, &mech_PKCS, obj_pvtkey[i]), CKR_OK, "DECRYPT INIT CKM_RSA_PKCS");
      asrt(funcs->C_DecryptUpdate(session, enc, 100, NULL, NULL), CKR_OK, "DECRYPT UPDATE CKM_RSA_PKCS");
      asrt(funcs->C_DecryptUpdate(session, enc+100, 8, NULL, NULL), CKR_OK, "DECRYPT UPDATE CKM_RSA_PKCS");
      asrt(funcs->C_DecryptUpdate(session, enc+108, 20, NULL, NULL), CKR_OK, "DECRYPT UPDATE CKM_RSA_PKCS");
      asrt(funcs->C_DecryptFinal(session, dec, &dec_len), CKR_OK, "DECRYPT FINAL CKM_RSA_PKCS");
      asrt(dec_len, 32, "DECRYPTED DATA LEN CKM_RSA_PKCS");
      asrt(memcmp(some_data, dec, dec_len), 0, "DECRYPTED DATA CKM_RSA_PKCS");

      // Decryption using CKM_RSA_X_509
      asrt(funcs->C_DecryptInit(session, &mech_X509, obj_pvtkey[i]), CKR_OK, "DECRYPT INIT CKM_RSA_X_509");
      asrt(funcs->C_Decrypt(session, enc, enc_len, dec, &dec_len), CKR_OK, "DECRYPT CKM_RSA_X_509");
      asrt(dec_len, 128, "DECRYPTED DATA LEN CKM_RSA_X_509");
      asrt(memcmp(some_data, dec+128-32, 32), 0, "DECRYPTED DATA CKM_RSA_X_509");

      asrt(funcs->C_DecryptInit(session, &mech_X509, obj_pvtkey[i]), CKR_OK, "DECRYPT INIT CKM_RSA_X_509");
      asrt(funcs->C_DecryptUpdate(session, enc, 8, NULL, NULL), CKR_OK, "DECRYPT UPDATE CKM_RSA_X_509");
      asrt(funcs->C_DecryptUpdate(session, enc+8, 20, NULL, NULL), CKR_OK, "DECRYPT UPDATE CKM_RSA_X_509");
      asrt(funcs->C_DecryptUpdate(session, enc+28, 100, NULL, NULL), CKR_OK, "DECRYPT UPDATE CKM_RSA_X_509");
      asrt(funcs->C_DecryptFinal(session, dec, &dec_len), CKR_OK, "DECRYPT FINAL CKM_RSA_X_509");
      asrt(dec_len, 128, "DECRYPTED DATA LEN CKM_RSA_X_509");
      asrt(memcmp(some_data, dec+128-32, 32), 0, "DECRYPTED DATA CKM_RSA_X_509");
    }
  }

  asrt(funcs->C_Logout(session), CKR_OK, "Logout USER");

  asrt(funcs->C_Login(session, CKU_SO, "010203040506070801020304050607080102030405060708", 48), CKR_OK, "Login SO");
  for(i=0; i<24; i++) {
    asrt(funcs->C_DestroyObject(session, obj_cert[i]), CKR_OK, "Destroy Object");
  }
  asrt(funcs->C_Logout(session), CKR_OK, "Logout SO");

  asrt(funcs->C_CloseSession(session), CKR_OK, "CloseSession");
  asrt(funcs->C_Finalize(NULL), CKR_OK, "FINALIZE");
  dprintf(0, "TEST END: test_decrypt_RSA()\n");
}

static void test_digest() {
  dprintf(0, "TEST START: test_digest()\n");
  CK_BYTE     i;
  CK_BYTE     some_data[32];
  CK_BYTE     digest_data[128];
  CK_BYTE     digest_data_update[128];
  CK_ULONG    digest_len;
  CK_ULONG    digest_len_update;
  CK_BYTE     hashed_data[128];
  CK_ULONG    sha1_len = 20;
  CK_ULONG    sha256_len = 32;
  CK_ULONG    sha384_len = 48;
  CK_ULONG    sha512_len = 64;

  CK_MECHANISM mech_sha1 = {CKM_SHA_1, NULL};
  CK_MECHANISM mech_sha256 = {CKM_SHA256, NULL};
  CK_MECHANISM mech_sha384 = {CKM_SHA384, NULL};
  CK_MECHANISM mech_sha512 = {CKM_SHA512, NULL};

  CK_SESSION_HANDLE session;
  init_connection();
  asrt(funcs->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &session), CKR_OK, "OpenSession");

  for(i=0; i<10; i++) {
    if(RAND_bytes(some_data, sizeof(some_data)) == -1)
        exit(EXIT_FAILURE);

    // SHA1
    SHA1(some_data, sizeof(some_data), hashed_data);
    asrt(funcs->C_DigestInit(session, &mech_sha1), CKR_OK, "DIGEST INIT SHA1");  
    digest_len = sizeof(digest_data);
    asrt(funcs->C_Digest(session, some_data, sizeof(some_data), digest_data, &digest_len), CKR_OK, "DIGEST SHA1");
    asrt(digest_len, sha1_len, "SHA1 LEN");
    asrt(memcmp(hashed_data, digest_data, digest_len), 0, "SHA1");
    digest_len_update = sizeof(digest_data_update);
    asrt(funcs->C_DigestInit(session, &mech_sha1), CKR_OK, "DIGEST INIT SHA1");
    asrt(funcs->C_DigestUpdate(session, some_data, 10), CKR_OK, "DIGEST UPDATE SHA1");
    asrt(funcs->C_DigestUpdate(session, some_data+10, 22), CKR_OK, "DIGEST UPDATE SHA1");
    asrt(funcs->C_DigestFinal(session, digest_data_update, &digest_len_update), CKR_OK, "DIGEST FINAL SHA1");
    asrt(digest_len_update, sha1_len, "SHA1 LEN");
    asrt(memcmp(hashed_data, digest_data_update, digest_len_update), 0, "SHA1");

    // SHA256
    SHA256(some_data, sizeof(some_data), hashed_data);
    asrt(funcs->C_DigestInit(session, &mech_sha256), CKR_OK, "DIGEST INIT SHA256");  
    digest_len = 128;
    asrt(funcs->C_Digest(session, some_data, 32, digest_data, &digest_len), CKR_OK, "DIGEST SHA256");
    asrt(digest_len, sha256_len, "SHA256 LEN");
    asrt(memcmp(hashed_data, digest_data, digest_len), 0, "SHA256");
    digest_len_update = sizeof(digest_data_update);
    asrt(funcs->C_DigestInit(session, &mech_sha256), CKR_OK, "DIGEST INIT SHA256");
    asrt(funcs->C_DigestUpdate(session, some_data, 10), CKR_OK, "DIGEST UPDATE SHA256");
    asrt(funcs->C_DigestUpdate(session, some_data+10, 22), CKR_OK, "DIGEST UPDATE SHA256");
    asrt(funcs->C_DigestFinal(session, digest_data_update, &digest_len_update), CKR_OK, "DIGEST FINAL SHA256");
    asrt(digest_len_update, sha256_len, "SHA256 LEN");
    asrt(memcmp(hashed_data, digest_data_update, digest_len_update), 0, "SHA256");

    // SHA384
    SHA384(some_data, sizeof(some_data), hashed_data);
    asrt(funcs->C_DigestInit(session, &mech_sha384), CKR_OK, "DIGEST INIT SHA384");  
    digest_len = 128;
    asrt(funcs->C_Digest(session, some_data, 32, digest_data, &digest_len), CKR_OK, "DIGEST SHA384");
    asrt(digest_len, sha384_len, "SHA384 LEN");
    asrt(memcmp(hashed_data, digest_data, digest_len), 0, "SHA384");
    digest_len_update = sizeof(digest_data_update);
    asrt(funcs->C_DigestInit(session, &mech_sha384), CKR_OK, "DIGEST INIT SHA384");
    asrt(funcs->C_DigestUpdate(session, some_data, 10), CKR_OK, "DIGEST UPDATE SHA384");
    asrt(funcs->C_DigestUpdate(session, some_data+10, 22), CKR_OK, "DIGEST UPDATE SHA384");
    asrt(funcs->C_DigestFinal(session, digest_data_update, &digest_len_update), CKR_OK, "DIGEST FINAL SHA384");
    asrt(digest_len_update, sha384_len, "SHA384 LEN");
    asrt(memcmp(hashed_data, digest_data_update, digest_len_update), 0, "SHA384");


    // SHA512
    SHA512(some_data, sizeof(some_data), hashed_data);
    asrt(funcs->C_DigestInit(session, &mech_sha512), CKR_OK, "DIGEST INIT SHA512");  
    digest_len = 128;
    asrt(funcs->C_Digest(session, some_data, 32, digest_data, &digest_len), CKR_OK, "DIGEST SHA512");
    asrt(digest_len, sha512_len, "SHA512 LEN");
    asrt(memcmp(hashed_data, digest_data, digest_len), 0, "SHA512");
    digest_len_update = sizeof(digest_data_update);
    asrt(funcs->C_DigestInit(session, &mech_sha512), CKR_OK, "DIGEST INIT SHA512");
    asrt(funcs->C_DigestUpdate(session, some_data, 10), CKR_OK, "DIGEST UPDATE SHA512");
    asrt(funcs->C_DigestUpdate(session, some_data+10, 22), CKR_OK, "DIGEST UPDATE SHA512");
    asrt(funcs->C_DigestFinal(session, digest_data_update, &digest_len_update), CKR_OK, "DIGEST FINAL SHA512");
    asrt(digest_len_update, sha512_len, "SHA512 LEN");
    asrt(memcmp(hashed_data, digest_data_update, digest_len_update), 0, "SHA512");
  }

  asrt(funcs->C_CloseSession(session), CKR_OK, "CloseSession");
  asrt(funcs->C_Finalize(NULL), CKR_OK, "FINALIZE");
  dprintf(0, "TEST END: test_digest()\n");
}

static void test_login_order() {
  dprintf(0, "TEST START: test_login_order()\n");

  CK_BYTE     i, j;
  CK_BYTE     some_data[32];
  CK_BYTE     params[] = {0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07};
  CK_ULONG    class_k = CKO_PRIVATE_KEY;
  CK_ULONG    class_c = CKO_PUBLIC_KEY;
  CK_ULONG    kt = CKK_ECDSA;
  CK_BYTE     id = 1;
  CK_BYTE     sig[64];
  CK_ULONG    recv_len = sizeof(sig);

  CK_ATTRIBUTE privateKeyTemplate[] = {
    {CKA_CLASS, &class_k, sizeof(class_k)},
    {CKA_KEY_TYPE, &kt, sizeof(kt)},
    {CKA_ID, &id, sizeof(id)}
  };

  CK_ATTRIBUTE publicKeyTemplate[] = {
    {CKA_CLASS, &class_c, sizeof(class_c)},
    {CKA_ID, &id, sizeof(id)},
    {CKA_EC_PARAMS, &params, sizeof(params)}
  };

  CK_MECHANISM keygen_mech = {CKM_EC_KEY_PAIR_GEN, NULL};
  CK_MECHANISM sign_mech = {CKM_ECDSA, NULL};

  CK_OBJECT_HANDLE privkey, pubkey, cert;
  CK_SESSION_HANDLE session, session2;

  init_connection();
  asrt(funcs->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &session), CKR_OK, "OpenSession1");
  asrt(funcs->C_Login(session, CKU_SO, "010203040506070801020304050607080102030405060708", 48), CKR_OK, "Login SO");

  asrt(funcs->C_GenerateKeyPair(session, &keygen_mech, publicKeyTemplate, 3, privateKeyTemplate, 3, &pubkey, &privkey), CKR_OK, "GEN EC KEYPAIR");
  asrt(funcs->C_Logout(session), CKR_OK, "Logout SO");

  
  asrt(funcs->C_Login(session, CKU_USER, "123456", 6), CKR_OK, "Login USER");
  asrt(funcs->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &session2), CKR_OK, "OpenSession2");

  asrt(funcs->C_SignInit(session, &sign_mech, privkey), CKR_OK, "SignInit");
  asrt(funcs->C_Sign(session, some_data, sizeof(some_data), sig, &recv_len), CKR_OK, "Sign");
  asrt(funcs->C_Logout(session), CKR_OK, "Logout USER");

  CK_ULONG n_cert;
  CK_BYTE ckaid = 0;
  CK_ULONG class_cert = CKO_CERTIFICATE;
  CK_ATTRIBUTE idTemplate[] = {
    {CKA_ID, &ckaid, sizeof(ckaid)}
  };
  CK_ATTRIBUTE idClassTemplate[] = {
    {CKA_ID, &ckaid, sizeof(ckaid)},
    {CKA_CLASS, &class_cert, sizeof(class_cert)}
  };

  asrt(funcs->C_Login(session, CKU_SO, "010203040506070801020304050607080102030405060708", 48), CKR_OK, "Login SO");
  asrt(funcs->C_GetAttributeValue(session, privkey, idTemplate, 1), CKR_OK, "GET CKA_ID");
  asrt(funcs->C_FindObjectsInit(session, idClassTemplate, 2), CKR_OK, "FIND INIT");
  asrt(funcs->C_FindObjects(session, &cert, 1, &n_cert), CKR_OK, "FIND");
  asrt(n_cert, 1, "FIND NR OBJECTS");
  asrt(funcs->C_FindObjectsFinal(session), CKR_OK, "FIND FINAL");

  asrt(funcs->C_DestroyObject(session, cert), CKR_OK, "Destroy Object");
  asrt(funcs->C_Logout(session), CKR_OK, "Logout SO");
  asrt(funcs->C_CloseSession(session), CKR_OK, "CloseSession");
  asrt(funcs->C_Finalize(NULL), CKR_OK, "FINALIZE");
  dprintf(0, "TEST END: test_login_order()\n");
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

#if HW_TESTS
  // Require user confirmation to continue, since this test suite will clear
  // any data stored on connected keys.
  if (!destruction_confirmed())
    exit(77); // exit code 77 == skipped tests

  test_initalize();
  // Require YK4 to continue.  Skip if different model found.
  if (test_token_info() != 0) {
    exit(77);
  }
  test_mechanism_list_and_info();
  test_session();
  test_login();
  test_multiple_sessions();
  test_max_multiple_sessions();
  test_digest();
  test_find_objects();
  test_generate_rsa();
  test_generate_ec();
  test_generate_ec_P384();
  test_import_and_sign_all_10();
  test_import_and_sign_all_10_P384();
  test_import_and_sign_all_10_RSA();
  test_import_and_sign_RSA_SHA256();
  test_decrypt_RSA();
  test_login_order();
  test_sign_update_RSA();
#else
  fprintf(stderr, "HARDWARE TESTS DISABLED!, skipping...\n");
#endif

  return EXIT_SUCCESS;

}

#pragma clang diagnostic pop