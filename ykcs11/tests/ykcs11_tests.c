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

#include "ykcs11_tests_util.h"

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wpointer-sign"

#ifdef __MINGW32__
#define dprintf(fd, ...) fprintf(stdout, __VA_ARGS__)
#endif

CK_FUNCTION_LIST_PTR funcs;

#define asrt(c, e, m) _asrt(__FILE__, __LINE__, c, e, m);

static void _asrt(const char *file, int line, CK_ULONG check, CK_ULONG expected, const char *msg) {

  if (check == expected)
    return;

  fprintf(stderr, "%s.%d: <%s> check failed with value %lu (0x%lx), expected %lu (0x%lx)\n",
          file, line, msg, check, check, expected, expected);

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
  asrt(info.ulMaxPinLen, 48, "MAX_PIN_LEN");
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
    CKM_RSA_PKCS_OAEP,
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
    CKM_ECDSA_SHA224,
    CKM_ECDSA_SHA256,
    CKM_ECDSA_SHA384,
    CKM_SHA_1,
    CKM_SHA256,
    CKM_SHA384,
    CKM_SHA512
  };

  static const CK_MECHANISM_INFO token_mechanism_infos[] = { // KEEP ALIGNED WITH token_mechanisms
    {1024, 2048, CKF_HW | CKF_GENERATE_KEY_PAIR},
    {1024, 2048, CKF_HW | CKF_ENCRYPT | CKF_DECRYPT | CKF_SIGN | CKF_VERIFY},
    {1024, 2048, CKF_HW | CKF_SIGN | CKF_VERIFY},
    {1024, 2048, CKF_HW | CKF_ENCRYPT | CKF_DECRYPT},
    {1024, 2048, CKF_HW | CKF_ENCRYPT | CKF_DECRYPT | CKF_SIGN | CKF_VERIFY},
    {1024, 2048, CKF_HW | CKF_SIGN | CKF_VERIFY},
    {1024, 2048, CKF_HW | CKF_SIGN | CKF_VERIFY},
    {1024, 2048, CKF_HW | CKF_SIGN | CKF_VERIFY},
    {1024, 2048, CKF_HW | CKF_SIGN | CKF_VERIFY},
    {1024, 2048, CKF_HW | CKF_SIGN | CKF_VERIFY},
    {1024, 2048, CKF_HW | CKF_SIGN | CKF_VERIFY},
    {1024, 2048, CKF_HW | CKF_SIGN | CKF_VERIFY},
    {1024, 2048, CKF_HW | CKF_SIGN | CKF_VERIFY},
    {256, 384, CKF_HW | CKF_GENERATE_KEY_PAIR},
    {256, 384, CKF_HW | CKF_SIGN | CKF_VERIFY},
    {256, 384, CKF_HW | CKF_SIGN | CKF_VERIFY},
    {256, 384, CKF_HW | CKF_SIGN | CKF_VERIFY},
    {256, 384, CKF_HW | CKF_SIGN | CKF_VERIFY},
    {256, 384, CKF_HW | CKF_SIGN | CKF_VERIFY},
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
  free(mechs);
  asrt(funcs->C_Finalize(NULL), CKR_OK, "FINALIZE");
  dprintf(0, "TEST END: test_mechanism_list_and_info()\n");
}

static void test_session() {
  dprintf(0, "TEST START: test_session()\n");

  CK_SESSION_HANDLE session1, session2;
  CK_SESSION_INFO   info;

  init_connection();
  asrt(funcs->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &session1), CKR_OK, "OpenSession2");
  asrt(funcs->C_GetSessionInfo(session1, &info), CKR_OK, "GetSessionInfo");
  asrt(info.state, CKS_RW_PUBLIC_SESSION, "CHECK STATE");
  asrt(info.flags, CKF_SERIAL_SESSION | CKF_RW_SESSION, "CHECK FLAGS");
  asrt(info.ulDeviceError, 0, "CHECK DEVICE ERROR");
  asrt(funcs->C_CloseSession(session1), CKR_OK, "CloseSession");
  asrt(funcs->C_GetSessionInfo(session1, &info), CKR_SESSION_HANDLE_INVALID, "GetSessionInfo");

  asrt(funcs->C_OpenSession(0, CKF_SERIAL_SESSION, NULL, NULL, &session1), CKR_OK, "OpenSession3");
  asrt(funcs->C_OpenSession(0, CKF_SERIAL_SESSION, NULL, NULL, &session2), CKR_OK, "OpenSession3");
  asrt(funcs->C_GetSessionInfo(session1, &info), CKR_OK, "GetSessionInfo");
  asrt(funcs->C_GetSessionInfo(session2, &info), CKR_OK, "GetSessionInfo");
  asrt(funcs->C_CloseAllSessions(0), CKR_OK, "CloseAllSessions");
  asrt(funcs->C_GetSessionInfo(session1, &info), CKR_SESSION_HANDLE_INVALID, "GetSessionInfo");
  asrt(funcs->C_GetSessionInfo(session2, &info), CKR_SESSION_HANDLE_INVALID, "GetSessionInfo");

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
  CK_BYTE i;
  CK_SESSION_HANDLE session;
  CK_SESSION_INFO info;

  init_connection();

  for(i=1; i<=16; i++) {
    asrt(funcs->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &session), CKR_OK, "MaxMultipleSession_OpenSession");
    asrt(session, i, "MaxMultipleSession_sessionHandle");
    asrt(funcs->C_GetSessionInfo(i, &info), CKR_OK, "MaxMultipleSessions_closedSessionsInfo");
  }

  asrt(funcs->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &session), CKR_SESSION_COUNT, "MaxMultipleSession_OpenSession_TooMany");

  asrt(funcs->C_CloseAllSessions(0), CKR_OK, "MaxMultipleSessions_CloseAllSessions");
  for(int i=1; i<=17; i++) {
    asrt(funcs->C_GetSessionInfo(i, &info), CKR_SESSION_HANDLE_INVALID, "MaxMultipleSessions_closedSessionsInfo");
  }

  asrt(funcs->C_Finalize(NULL), CKR_OK, "FINALIZE");
  dprintf(0, "TEST END: test_max_multiple_sessions()\n");
}

static void test_generate_eccp256() {
  dprintf(0, "TEST START: test_generate_eccp256()\n");
  CK_BYTE     params[] = {0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07};
  CK_OBJECT_HANDLE obj_pvtkey[24], obj_pubkey[24];
  CK_SESSION_HANDLE session;

  init_connection();
  asrt(funcs->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &session), CKR_OK, "OpenSession1");

  generate_ec_keys(funcs, session, 24, params, sizeof(params), obj_pubkey, obj_pvtkey);

  test_ec_sign(funcs, session, obj_pvtkey, NULL, CKM_ECDSA, 32);
  test_ec_sign(funcs, session, obj_pvtkey, NULL, CKM_ECDSA_SHA1, 32);
  test_ec_sign(funcs, session, obj_pvtkey, NULL, CKM_ECDSA_SHA256, 32);

  destroy_test_objects(funcs, session, obj_pvtkey, 24);
  asrt(funcs->C_CloseSession(session), CKR_OK, "CloseSession");
  asrt(funcs->C_Finalize(NULL), CKR_OK, "FINALIZE");
  dprintf(0, "TEST END: test_generate_eccp256()\n");
}

static void test_generate_eccp384() {
  dprintf(0, "TEST START: test_generate_eccp384()\n");
  CK_BYTE     params[] = {0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22};
  CK_OBJECT_HANDLE obj_pvtkey[24], obj_pubkey[24];
  CK_SESSION_HANDLE session;

  init_connection();
  asrt(funcs->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &session), CKR_OK, "OpenSession1");

  generate_ec_keys(funcs, session, 24, params, sizeof(params), obj_pubkey, obj_pvtkey);

  test_ec_sign(funcs, session, obj_pvtkey, NULL, CKM_ECDSA, 48);
  test_ec_sign(funcs, session, obj_pvtkey, NULL, CKM_ECDSA_SHA1, 48);
  test_ec_sign(funcs, session, obj_pvtkey, NULL, CKM_ECDSA_SHA256, 48);
  test_ec_sign(funcs, session, obj_pvtkey, NULL, CKM_ECDSA_SHA384, 48);

  destroy_test_objects(funcs, session, obj_pvtkey, 24);
  asrt(funcs->C_CloseSession(session), CKR_OK, "CloseSession");
  asrt(funcs->C_Finalize(NULL), CKR_OK, "FINALIZE");
  dprintf(0, "TEST END: test_generate_eccp384()\n");
}

static void test_generate_rsa1024() {
  dprintf(0, "TEST START: test_generate_rsa1024()\n");
  CK_OBJECT_HANDLE obj_pvtkey[24], obj_pubkey[24];
  CK_SESSION_HANDLE session;

  init_connection();
  asrt(funcs->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &session), CKR_OK, "OpenSession1");

  generate_rsa_keys(funcs, session, 24, obj_pubkey, obj_pvtkey);

  test_rsa_sign(funcs, session, obj_pvtkey, NULL, CKM_RSA_PKCS);
  test_rsa_sign(funcs, session, obj_pvtkey, NULL, CKM_SHA1_RSA_PKCS);
  test_rsa_sign(funcs, session, obj_pvtkey, NULL, CKM_SHA256_RSA_PKCS);
  test_rsa_sign(funcs, session, obj_pvtkey, NULL, CKM_SHA384_RSA_PKCS);
  test_rsa_sign(funcs, session, obj_pvtkey, NULL, CKM_SHA512_RSA_PKCS);

  test_rsa_sign_pss(funcs, session, obj_pvtkey, NULL, CKM_RSA_PKCS_PSS);
  test_rsa_sign_pss(funcs, session, obj_pvtkey, NULL, CKM_SHA1_RSA_PKCS_PSS);
  test_rsa_sign_pss(funcs, session, obj_pvtkey, NULL, CKM_SHA256_RSA_PKCS_PSS);
  test_rsa_sign_pss(funcs, session, obj_pvtkey, NULL, CKM_SHA384_RSA_PKCS_PSS);

  destroy_test_objects(funcs, session, obj_pvtkey, 24);
  asrt(funcs->C_CloseSession(session), CKR_OK, "CloseSession");
  asrt(funcs->C_Finalize(NULL), CKR_OK, "FINALIZE");
  dprintf(0, "TEST END: test_generate_rsa1024()\n");
}

static void test_key_attributes() {
  dprintf(0, "TEST START: test_key_attributes()\n");
  CK_BYTE     e[] = {0x01, 0x00, 0x01};
  CK_BYTE     params_eccp256[] = {0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07};
  CK_BYTE     params_eccp384[] = {0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22};
  CK_OBJECT_HANDLE privkey, pubkey;
  CK_SESSION_HANDLE session;

  init_connection();
  asrt(funcs->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &session), CKR_OK, "OpenSession1");

  generate_ec_keys(funcs, session, 1, params_eccp256, sizeof(params_eccp256), &pubkey, &privkey);
  test_pubkey_attributes_ec(funcs, session, pubkey, 256, "Public key for PIV Authentication", 67, params_eccp256, sizeof(params_eccp256));
  test_privkey_attributes_ec(funcs, session, privkey, 256, "Private key for PIV Authentication", 67, params_eccp256, sizeof(params_eccp256), CK_FALSE);

  generate_ec_keys(funcs, session, 1, params_eccp384, sizeof(params_eccp384), &pubkey, &privkey);
  test_pubkey_attributes_ec(funcs, session, pubkey, 384, "Public key for PIV Authentication", 99, params_eccp384, sizeof(params_eccp384));
  test_privkey_attributes_ec(funcs, session, privkey, 384, "Private key for PIV Authentication", 99, params_eccp384, sizeof(params_eccp384), CK_FALSE);

  generate_rsa_keys(funcs, session, 1, &pubkey, &privkey);
  test_pubkey_attributes_rsa(funcs, session, pubkey, 1024, "Public key for PIV Authentication", 128, e, sizeof(e));
  test_privkey_attributes_rsa(funcs, session, privkey, 1024, "Private key for PIV Authentication", 128, e, sizeof(e), CK_FALSE);

  destroy_test_objects(funcs, session, &privkey, 1);
  asrt(funcs->C_CloseSession(session), CKR_OK, "CloseSession");
  asrt(funcs->C_Finalize(NULL), CKR_OK, "FINALIZE");

  dprintf(0, "TEST END: test_key_attributes()\n");
}

static void test_find_objects() {
  dprintf(0, "TEST START: test_find_objects()\n");

  CK_BYTE     i;
  CK_OBJECT_HANDLE privkey, pubkey;
  CK_SESSION_HANDLE session;

  init_connection();
  asrt(funcs->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &session), CKR_OK, "OpenSession1");
  generate_rsa_keys(funcs, session, 1, &pubkey, &privkey);

  asrt(funcs->C_Login(session, CKU_USER, "123456", 6), CKR_OK, "LOGIN USER");

  CK_OBJECT_HANDLE found_obj[10];
  CK_ULONG n_found_obj = 0;
  CK_ULONG object_class;
  CK_BYTE ckaid = 0;
  CK_BYTE n_privkey_obj = 0;
  CK_BYTE n_pubkey_obj  = 0;
  CK_BYTE n_cert_obj = 0;
  CK_BYTE n_data_obj = 0;

  CK_ATTRIBUTE idTemplate[] = {
    {CKA_ID, &ckaid, sizeof(ckaid)}
  };
  CK_ATTRIBUTE classTemplate[] = {
    {CKA_CLASS, &object_class, sizeof(CK_ULONG)}
  };

  asrt(funcs->C_GetAttributeValue(session, privkey, idTemplate, 1), CKR_OK, "GET CKA_ID");
  asrt(funcs->C_FindObjectsInit(session, idTemplate, 1), CKR_OK, "FIND INIT");
  asrt(funcs->C_FindObjects(session, found_obj, 10, &n_found_obj), CKR_OK, "FIND");
  asrt(n_found_obj, 5, "N FOUND OBJS");
  asrt(funcs->C_FindObjectsFinal(session), CKR_OK, "FIND FINAL");

  for(i=0; i<5; i++) {
    asrt(funcs->C_GetAttributeValue(session, found_obj[i], classTemplate, 1), CKR_OK, "GET CKA_CLASS");
    if(object_class == CKO_PRIVATE_KEY) {
      n_privkey_obj++;
      asrt(found_obj[i], privkey, "Wrong private key");
    } else if(object_class == CKO_PUBLIC_KEY) {
      n_pubkey_obj++;
      asrt(found_obj[i], pubkey, "Wrong public key");
    }  else if(object_class == CKO_CERTIFICATE) {
      n_cert_obj++;
    } else if(object_class == CKO_DATA) {
      n_data_obj++;
    }
  }
  asrt(n_privkey_obj, 1, "NO PRIVATE KEY");
  asrt(n_pubkey_obj, 1, "NO PUBLIC KEY");
  asrt(n_cert_obj, 2, "NUMBER OF CERTIFICATES");
  asrt(n_data_obj, 1, "NO DATA");

  test_find_objects_by_class(funcs, session, CKO_PRIVATE_KEY, ckaid, 1, 86);
  test_find_objects_by_class(funcs, session, CKO_PUBLIC_KEY, ckaid, 1, 111);
  test_find_objects_by_class(funcs, session, CKO_DATA, ckaid, 1, 0);
  test_find_objects_by_class(funcs, session, CKO_CERTIFICATE, ckaid, 2, 37);
  test_find_objects_by_class(funcs, session, CKO_CERTIFICATE, ckaid, 2, 62);

  asrt(funcs->C_Logout(session), CKR_OK, "Logout USER");

  destroy_test_objects(funcs, session, &privkey, 1);
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

static void test_import_eccp256() {
  dprintf(0, "TEST START: test_import_eccp256()\n");
  CK_BYTE           params[] = {0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07};
  EC_KEY            *eck;
  CK_OBJECT_HANDLE  obj_cert[24], obj_pvtkey[24];
  CK_SESSION_HANDLE session;

  init_connection();
  asrt(funcs->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &session), CKR_OK, "OpenSession1");

  eck = import_ec_key(funcs, session, NID_X9_62_prime256v1, 32, params, sizeof(params), obj_cert, obj_pvtkey);
  if (eck == NULL)
  exit(EXIT_FAILURE);

  test_ec_sign(funcs, session, obj_pvtkey, eck, CKM_ECDSA, 32);
  test_ec_sign(funcs, session, obj_pvtkey, eck, CKM_ECDSA_SHA1, 32);
  test_ec_sign(funcs, session, obj_pvtkey, eck, CKM_ECDSA_SHA256, 32);

  destroy_test_objects(funcs, session, obj_cert, 24);

  asrt(funcs->C_CloseSession(session), CKR_OK, "CloseSession");
  asrt(funcs->C_Finalize(NULL), CKR_OK, "FINALIZE");
  dprintf(0, "TEST END: test_import_eccp256()\n");
}

static void test_import_eccp384() {
  dprintf(0, "TEST START: test_import_eccp384()\n");
  CK_BYTE           params[] = {0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22};
  EC_KEY            *eck = NULL;
  CK_OBJECT_HANDLE  obj_cert[24], obj_pvtkey[24];
  CK_SESSION_HANDLE session;

  init_connection();
  asrt(funcs->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &session), CKR_OK, "OpenSession1");
  eck = import_ec_key(funcs, session, NID_secp384r1, 48, params, sizeof(params), obj_cert, obj_pvtkey);

  if (eck == NULL)
  exit(EXIT_FAILURE);

  test_ec_sign(funcs, session, obj_pvtkey, eck, CKM_ECDSA, 48);
  test_ec_sign(funcs, session, obj_pvtkey, eck, CKM_ECDSA_SHA1, 48);
  test_ec_sign(funcs, session, obj_pvtkey, eck, CKM_ECDSA_SHA256, 48);
  test_ec_sign(funcs, session, obj_pvtkey, eck, CKM_ECDSA_SHA384, 48);

  destroy_test_objects(funcs, session, obj_cert, 24);

  asrt(funcs->C_CloseSession(session), CKR_OK, "CloseSession");
  asrt(funcs->C_Finalize(NULL), CKR_OK, "FINALIZE");
  dprintf(0, "TEST END: test_import_eccp384()\n");
}

static void test_import_rsa1024() {
  dprintf(0, "TEST START: test_import_rsa1024()\n");
  EVP_PKEY    *evp = EVP_PKEY_new();
  RSA         *rsak = RSA_new();
  CK_OBJECT_HANDLE obj_cert[24], obj_pvtkey[24];
  CK_SESSION_HANDLE session;

  init_connection();
  asrt(funcs->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &session), CKR_OK, "OpenSession1");

  import_rsa_key(funcs, session, 1024, evp, rsak, obj_cert, obj_pvtkey);
  if (evp == NULL || rsak == NULL)
    exit(EXIT_FAILURE);

  test_rsa_sign(funcs, session, obj_pvtkey, evp, CKM_RSA_PKCS);
  test_rsa_sign(funcs, session, obj_pvtkey, evp, CKM_SHA1_RSA_PKCS);
  test_rsa_sign(funcs, session, obj_pvtkey, evp, CKM_SHA256_RSA_PKCS);
  test_rsa_sign(funcs, session, obj_pvtkey, evp, CKM_SHA384_RSA_PKCS);

  test_rsa_sign_pss(funcs, session, obj_pvtkey, rsak, CKM_RSA_PKCS_PSS);
  test_rsa_sign_pss(funcs, session, obj_pvtkey, rsak, CKM_SHA1_RSA_PKCS_PSS);
  test_rsa_sign_pss(funcs, session, obj_pvtkey, rsak, CKM_SHA256_RSA_PKCS_PSS);
  test_rsa_sign_pss(funcs, session, obj_pvtkey, rsak, CKM_SHA384_RSA_PKCS_PSS);

  destroy_test_objects(funcs, session, obj_cert, 24);
  asrt(funcs->C_CloseSession(session), CKR_OK, "CloseSession");
  asrt(funcs->C_Finalize(NULL), CKR_OK, "FINALIZE");
  dprintf(0, "TEST END: test_import_rsa1024()\n");
}

static void test_import_rsa2048() {
  dprintf(0, "TEST START: test_import_rsa2048()\n");
  EVP_PKEY    *evp = EVP_PKEY_new();
  RSA         *rsak = RSA_new();
  CK_OBJECT_HANDLE obj_cert[24], obj_pvtkey[24];
  CK_SESSION_HANDLE session;

  init_connection();
  asrt(funcs->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &session), CKR_OK, "OpenSession1");

  import_rsa_key(funcs, session, 2048, evp, rsak, obj_cert, obj_pvtkey);
  if (evp == NULL || rsak == NULL)
    exit(EXIT_FAILURE);

  test_rsa_sign(funcs, session, obj_pvtkey, evp, CKM_RSA_PKCS);
  test_rsa_sign(funcs, session, obj_pvtkey, evp, CKM_SHA1_RSA_PKCS);
  test_rsa_sign(funcs, session, obj_pvtkey, evp, CKM_SHA256_RSA_PKCS);
  test_rsa_sign(funcs, session, obj_pvtkey, evp, CKM_SHA384_RSA_PKCS);

  test_rsa_sign_pss(funcs, session, obj_pvtkey, rsak, CKM_RSA_PKCS_PSS);
  test_rsa_sign_pss(funcs, session, obj_pvtkey, rsak, CKM_SHA1_RSA_PKCS_PSS);
  test_rsa_sign_pss(funcs, session, obj_pvtkey, rsak, CKM_SHA256_RSA_PKCS_PSS);
  test_rsa_sign_pss(funcs, session, obj_pvtkey, rsak, CKM_SHA384_RSA_PKCS_PSS);

  destroy_test_objects(funcs, session, obj_cert, 24);
  asrt(funcs->C_CloseSession(session), CKR_OK, "CloseSession");
  asrt(funcs->C_Finalize(NULL), CKR_OK, "FINALIZE");
  dprintf(0, "TEST END: test_import_rsa2048()\n");
}

static void test_decrypt_RSA() {
  dprintf(0, "TEST START: test_decrypt_RSA()\n");
  EVP_PKEY    *evp = EVP_PKEY_new();
  RSA         *rsak = RSA_new();
  CK_OBJECT_HANDLE obj_cert[24], obj_pvtkey[24];
  CK_SESSION_HANDLE session;

  init_connection();
  asrt(funcs->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &session), CKR_OK, "OpenSession1");

  import_rsa_key(funcs, session, 1024, evp, rsak, obj_cert, obj_pvtkey);
  if (evp == NULL ||  rsak == NULL)
    exit(EXIT_FAILURE);

  test_rsa_decrypt(funcs, session, obj_pvtkey, rsak, CKM_RSA_PKCS, RSA_PKCS1_PADDING);
  test_rsa_decrypt(funcs, session, obj_pvtkey, rsak, CKM_RSA_X_509, RSA_NO_PADDING);
  test_rsa_decrypt(funcs, session, obj_pvtkey, rsak, CKM_RSA_PKCS_OAEP, RSA_PKCS1_OAEP_PADDING);

  destroy_test_objects(funcs, session, obj_cert, 24);

  asrt(funcs->C_CloseSession(session), CKR_OK, "CloseSession");
  asrt(funcs->C_Finalize(NULL), CKR_OK, "FINALIZE");
  dprintf(0, "TEST END: test_decrypt_RSA()\n");
}

static void test_encrypt_RSA() {
  dprintf(0, "TEST START: test_encrypt_RSA()\n");
  EVP_PKEY    *evp = EVP_PKEY_new();
  RSA         *rsak = RSA_new();
  CK_OBJECT_HANDLE obj_cert[24], obj_pvtkey[24];
  CK_SESSION_HANDLE session;

  init_connection();
  asrt(funcs->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &session), CKR_OK, "OpenSession1");

  import_rsa_key(funcs, session, 1024, evp, rsak, obj_cert, obj_pvtkey);
  if (evp == NULL ||  rsak == NULL)
    exit(EXIT_FAILURE);

  test_rsa_encrypt(funcs, session, obj_pvtkey, rsak, CKM_RSA_PKCS, RSA_PKCS1_PADDING);
  test_rsa_encrypt(funcs, session, obj_pvtkey, rsak, CKM_RSA_X_509, RSA_NO_PADDING);
  test_rsa_encrypt(funcs, session, obj_pvtkey, rsak, CKM_RSA_PKCS_OAEP, RSA_PKCS1_OAEP_PADDING);

  destroy_test_objects(funcs, session, obj_cert, 24);
  asrt(funcs->C_CloseSession(session), CKR_OK, "CloseSession");
  asrt(funcs->C_Finalize(NULL), CKR_OK, "FINALIZE");
  dprintf(0, "TEST END: test_encrypt_RSA()\n");
}

static void test_digest() {
  dprintf(0, "TEST START: test_digest()\n");
  CK_SESSION_HANDLE session;
  init_connection();
  asrt(funcs->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &session), CKR_OK, "OpenSession");

  test_digest_func(funcs, session, CKM_SHA_1);
  test_digest_func(funcs, session, CKM_SHA256);
  test_digest_func(funcs, session, CKM_SHA384);
  test_digest_func(funcs, session, CKM_SHA512);

  asrt(funcs->C_CloseSession(session), CKR_OK, "CloseSession");
  asrt(funcs->C_Finalize(NULL), CKR_OK, "FINALIZE");
  dprintf(0, "TEST END: test_digest()\n");
}

static void test_login_order() {
  dprintf(0, "TEST START: test_login_order()\n");
  CK_BYTE     params[] = {0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07};
  CK_BYTE     data[32];
  CK_BYTE     sig[128];
  CK_ULONG    recv_len = sizeof(sig);
  CK_OBJECT_HANDLE privkey, pubkey, cert;
  CK_SESSION_HANDLE session1, session2;

  CK_MECHANISM sign_mech = {CKM_ECDSA, NULL, 0};

  init_connection();
  asrt(funcs->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &session1), CKR_OK, "OpenSession1");

  generate_ec_keys(funcs, session1, 1, params, sizeof(params), &pubkey, &privkey);

  asrt(funcs->C_Login(session1, CKU_USER, "123456", 6), CKR_OK, "Login USER");
  asrt(funcs->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &session2), CKR_OK, "OpenSession2");

  asrt(funcs->C_SignInit(session1, &sign_mech, privkey), CKR_OK, "SignInit");
  asrt(funcs->C_Sign(session1, data, sizeof(data), sig, &recv_len), CKR_OK, "Sign");
  asrt(funcs->C_Logout(session1), CKR_OK, "Logout USER");

  destroy_test_objects(funcs, session1, &privkey, 1);

  asrt(funcs->C_CloseSession(session1), CKR_OK, "CloseSession");
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
  test_login_order();
  test_digest();
  test_generate_eccp256();
  test_generate_eccp384();
  test_generate_rsa1024();
  test_import_eccp256();
  test_import_eccp384();
  test_import_rsa1024();
  test_import_rsa2048();
  test_decrypt_RSA();
  test_encrypt_RSA();
  test_key_attributes();
  test_find_objects();
#else
  fprintf(stderr, "HARDWARE TESTS DISABLED!, skipping...\n");
#endif

  return EXIT_SUCCESS;
}

#pragma clang diagnostic pop