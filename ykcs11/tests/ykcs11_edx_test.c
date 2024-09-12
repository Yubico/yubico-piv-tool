/*
 * Copyright (c) 2015-2017,2019-2020 Yubico AB
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

#include "../../common/openssl-compat.h"
#include "../ykcs11.h"
#include "../ykcs11-config.h"

#include <string.h>

#include <openssl/bn.h>
#include <openssl/x509.h>
#include <openssl/rand.h>

#include "ykcs11_tests_util.h"

#ifdef _WIN32
#define dprintf(fd, ...) fprintf(stdout, __VA_ARGS__)
#endif

CK_FUNCTION_LIST_3_0_PTR funcs;

#define asrt(c, e, m) _asrt(__FILE__, __LINE__, c, e, m);

static void _asrt(const char *file, int line, CK_ULONG check, CK_ULONG expected, const char *msg) {

  if (check == expected)
    return;

  fprintf(stderr, "%s.%d: <%s> check failed with value %lu (0x%lx), expected %lu (0x%lx)\n",
          file, line, msg, check, check, expected, expected);

  exit(EXIT_FAILURE);

}

static void get_functions() {
  CK_INTERFACE_PTR interface;
  asrt(C_GetInterface(NULL,NULL,&interface,0), CKR_OK, "C_GetInterface default");
  funcs = interface->pFunctionList;
}

#if HW_TESTS
static void init_connection() {
  asrt(funcs->C_Initialize(NULL), CKR_OK, "INITIALIZE");
  CK_SLOT_ID pSlotList[16];
  CK_ULONG pulCount = 16;
  asrt(funcs->C_GetSlotList(true, pSlotList, &pulCount), CKR_OK, "GETSLOTLIST");
}

static bool has_hardware_support() {
  const CK_VERSION HW = {5, 70};
  CK_TOKEN_INFO info;
  bool ret = false;

  init_connection();
  asrt(funcs->C_GetTokenInfo(0, &info), CKR_OK, "GetTokeninfo");

  if(info.firmwareVersion.major > HW.major || (info.firmwareVersion.major == HW.major && info.firmwareVersion.minor >= HW.minor)) {
    ret = true;
  }
  asrt(funcs->C_Finalize(NULL), CKR_OK, "FINALIZE");
  return ret;
}

static void test_mechanism_list_and_info() {
  dprintf(0, "TEST START: test_mechanism_list_and_info()\n");

  CK_MECHANISM_TYPE_PTR mechs;
  CK_ULONG              n_mechs;
  CK_MECHANISM_INFO     info;
  CK_ULONG              i;

  init_connection();
  asrt(funcs->C_GetMechanismList(0, NULL, &n_mechs), CKR_OK, "GetMechanismList");

  mechs = malloc(n_mechs * sizeof(CK_MECHANISM_TYPE));
  asrt(funcs->C_GetMechanismList(0, mechs, &n_mechs), CKR_OK, "GetMechanismList");

  CK_MECHANISM_INFO mech_info = {255, 255, CKF_HW | CKF_GENERATE_KEY_PAIR | CKF_EC_F_P | CKF_EC_NAMEDCURVE | CKF_EC_UNCOMPRESS};
  CK_BOOL ed_mech_found = CK_FALSE, ex_mech_found = CK_FALSE;
  for (i = 0; i < n_mechs; i++) {
    if(mechs[i] == CKM_EC_EDWARDS_KEY_PAIR_GEN) {
      ed_mech_found = CK_TRUE;
      asrt(funcs->C_GetMechanismInfo(0, CKM_EC_EDWARDS_KEY_PAIR_GEN, &info), CKR_OK, "GET MECH INFO");
      asrt(memcmp(&mech_info, &info, sizeof(CK_MECHANISM_INFO)), 0, "CHECK MECH INFO");
    }

    if(mechs[i] == CKM_EC_MONTGOMERY_KEY_PAIR_GEN) {
      ex_mech_found = CK_TRUE;
      asrt(funcs->C_GetMechanismInfo(0, CKM_EC_MONTGOMERY_KEY_PAIR_GEN, &info), CKR_OK, "GET MECH INFO");
      asrt(memcmp(&mech_info, &info, sizeof(CK_MECHANISM_INFO)), 0, "CHECK MECH INFO");
    }
  }
  free(mechs);

  if(!ed_mech_found || !ex_mech_found) {
    asrt(CK_TRUE, CK_FALSE, "ED and EC generation mechanism are not supported");
  }

  asrt(funcs->C_Finalize(NULL), CKR_OK, "FINALIZE");
  dprintf(0, "TEST END: test_mechanism_list_and_info()\n");
}

static void get_attr(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE privkey, CK_ULONG privkey_type) {
  CK_ULONG type;
  CK_ATTRIBUTE template[] = {
      {CKA_KEY_TYPE, &type, sizeof(type)}
  };
  asrt(funcs->C_GetAttributeValue(session, privkey, template, 1), CKR_OK, "GET CKA_ID");
  asrt(type, privkey_type, "GET CKA_KEY_TYPE");
}

static void find_object(CK_SESSION_HANDLE session, CK_ULONG privkey_type) {
  CK_OBJECT_HANDLE objects[10] = {0};
  CK_ULONG objects_len = 0;

  CK_ULONG type = privkey_type;
  CK_ATTRIBUTE template[] = {
      {CKA_KEY_TYPE, &type, sizeof(type)}
  };
  asrt(funcs->C_FindObjectsInit(session, template, 1), CKR_OK, "FIND INIT");
  asrt(funcs->C_FindObjects(session, objects, 10, &objects_len), CKR_OK, "FIND");
  asrt(funcs->C_FindObjectsFinal(session), CKR_OK, "FIND FINAL");
  asrt(objects_len, 1, "NUMBER OF FOUND OBJECTS");
}

static void test_generate_ed() {
  dprintf(0, "TEST START: test_generate_ed25519()\n");
  CK_OBJECT_HANDLE pvtkey = 0, pubkey = 0;
  CK_SESSION_HANDLE session;

  init_connection();
  asrt(funcs->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &session), CKR_OK, "OpenSession1");

  generate_ed_key(funcs, session, &pubkey, &pvtkey);
  get_attr(session, pvtkey, CKK_EC_EDWARDS);
  find_object(session, CKK_EC_EDWARDS);

  destroy_test_objects(funcs, session, &pvtkey, 1);
  asrt(funcs->C_CloseSession(session), CKR_OK, "CloseSession");
  asrt(funcs->C_Finalize(NULL), CKR_OK, "FINALIZE");
  dprintf(0, "TEST END: test_generate_ed25519()\n");
}

static void test_generate_ex() {
  dprintf(0, "TEST START: test_generate_ex25519()\n");
  CK_OBJECT_HANDLE pvtkey = 0, pubkey = 0;
  CK_SESSION_HANDLE session;

  init_connection();
  asrt(funcs->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &session), CKR_OK, "OpenSession1");

  generate_ex_key(funcs, session, &pubkey, &pvtkey);
  get_attr(session, pvtkey, CKK_EC_MONTGOMERY);
  find_object(session, CKK_EC_MONTGOMERY);

  destroy_test_objects(funcs, session, &pvtkey, 1);
  asrt(funcs->C_CloseSession(session), CKR_OK, "CloseSession");
  asrt(funcs->C_Finalize(NULL), CKR_OK, "FINALIZE");
  dprintf(0, "TEST END: test_generate_ex25519()\n");
}

static void test_sign_edkey() {
  dprintf(0, "TEST START: test_sign_edkey()\n");
  EVP_PKEY     *edkey;
  CK_OBJECT_HANDLE pvtkey=0, cert=0;
  CK_SESSION_HANDLE session;

  init_connection();
  asrt(funcs->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &session), CKR_OK, "OpenSession1");

  edkey = import_edkey(funcs, session, &cert, &pvtkey);
  if (edkey == NULL)
    exit(EXIT_FAILURE);


  test_ed_sign_simple(funcs, session, pvtkey);

  EVP_PKEY_free(edkey);
  destroy_test_objects(funcs, session, &pvtkey, 1);
  asrt(funcs->C_CloseSession(session), CKR_OK, "CloseSession");
  asrt(funcs->C_Finalize(NULL), CKR_OK, "FINALIZE");
  dprintf(0, "TEST END: test_sign_edkey()\n");
}

static void test_edkey_attributes() {
  dprintf(0, "TEST START: test_edkey_attributes()\n");

  CK_OBJECT_HANDLE privkey, pubkey;
  CK_SESSION_HANDLE session;

  CK_ULONG obj_class;
  CK_BBOOL obj_token;
  CK_BBOOL obj_private;
  CK_ULONG obj_key_type;

  CK_ATTRIBUTE template[] = {
      {CKA_CLASS,    &obj_class,    sizeof(CK_ULONG)},
      {CKA_TOKEN,    &obj_token,    sizeof(CK_BBOOL)},
      {CKA_PRIVATE,  &obj_private,  sizeof(CK_BBOOL)},
      {CKA_KEY_TYPE, &obj_key_type, sizeof(CK_ULONG)},
  };

  init_connection();
  asrt(funcs->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &session), CKR_OK, "OpenSession1");

  generate_ed_key(funcs, session, &pubkey, &privkey);
  asrt(funcs->C_GetAttributeValue(session, pubkey, template, 4), CKR_OK, "GET BASIC ATTRIBUTES");
  asrt(obj_class, CKO_PUBLIC_KEY, "CLASS");
  asrt(obj_token, CK_TRUE, "TOKEN");
  asrt(obj_private, CK_FALSE, "PRIVATE");
  asrt(obj_key_type, CKK_EC_EDWARDS, "KEY_TYPE");

  asrt(funcs->C_GetAttributeValue(session, privkey, template, 4), CKR_OK, "GET BASIC ATTRIBUTES");
  asrt(obj_class, CKO_PRIVATE_KEY, "CLASS");
  asrt(obj_token, CK_TRUE, "TOKEN");
  asrt(obj_private, CK_TRUE, "PRIVATE");
  asrt(obj_key_type, CKK_EC_EDWARDS, "KEY_TYPE");

  destroy_test_objects(funcs, session, &privkey, 1);
  asrt(funcs->C_CloseSession(session), CKR_OK, "CloseSession");
  asrt(funcs->C_Finalize(NULL), CKR_OK, "FINALIZE");

  dprintf(0, "TEST END: test_edkey_attributes()\n");
}

static void test_xkey_attributes() {
  dprintf(0, "TEST START: test_xkey_attributes()\n");

  CK_OBJECT_HANDLE privkey, pubkey;
  CK_SESSION_HANDLE session;

  CK_ULONG obj_class;
  CK_BBOOL obj_token;
  CK_BBOOL obj_private;
  CK_ULONG obj_key_type;
  CK_BYTE obj_point[64] = {0};

  CK_ATTRIBUTE template[] = {
      {CKA_CLASS,    &obj_class,    sizeof(CK_ULONG)},
      {CKA_TOKEN,    &obj_token,    sizeof(CK_BBOOL)},
      {CKA_PRIVATE,  &obj_private,  sizeof(CK_BBOOL)},
      {CKA_KEY_TYPE, &obj_key_type, sizeof(CK_ULONG)},
      {CKA_EC_POINT, obj_point, sizeof(obj_point)}
  };

  init_connection();
  asrt(funcs->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &session), CKR_OK, "OpenSession1");

  generate_ex_key(funcs, session, &pubkey, &privkey);

  asrt(funcs->C_GetAttributeValue(session, pubkey, template, 5), CKR_OK, "GET BASIC ATTRIBUTES");
  asrt(obj_class, CKO_PUBLIC_KEY, "CLASS");
  asrt(obj_token, CK_TRUE, "TOKEN");
  asrt(obj_private, CK_FALSE, "PRIVATE");
  asrt(obj_key_type, CKK_EC_MONTGOMERY, "KEY_TYPE");
  asrt(template[4].ulValueLen, 34, "EC_POINT LEN");

  asrt(funcs->C_GetAttributeValue(session, privkey, template, 5), CKR_OK, "GET BASIC ATTRIBUTES");
  asrt(obj_class, CKO_PRIVATE_KEY, "CLASS");
  asrt(obj_token, CK_TRUE, "TOKEN");
  asrt(obj_private, CK_TRUE, "PRIVATE");
  asrt(obj_key_type, CKK_EC_MONTGOMERY, "KEY_TYPE");
  asrt(template[4].ulValueLen, 34, "EC_POINT LEN");

  destroy_test_objects(funcs, session, &privkey, 1);
  asrt(funcs->C_CloseSession(session), CKR_OK, "CloseSession");
  asrt(funcs->C_Finalize(NULL), CKR_OK, "FINALIZE");

  dprintf(0, "TEST END: test_xkey_attributes()\n");
}

static void test_find_objects() {
  dprintf(0, "TEST START: test_find_objects()\n");

  CK_BYTE     i;
  CK_OBJECT_HANDLE privkey, pubkey;
  CK_SESSION_HANDLE session;

  init_connection();
  asrt(funcs->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &session), CKR_OK, "OpenSession1");
  generate_ed_key(funcs, session, &pubkey, &privkey);

  asrt(funcs->C_Login(session, CKU_USER, "123456", 6), CKR_OK, "LOGIN USER");

  CK_OBJECT_HANDLE found_obj[10] = {0};
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

  for(i=0; i<n_found_obj; i++) {
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
  asrt(n_data_obj, 1, "NO DATA");
  asrt(n_cert_obj, 2, "NUMBER OF CERTIFICATES");

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

static EVP_PKEY* test_import_edkey() {
  dprintf(0, "TEST START: test_import_edkey()\n");

  EVP_PKEY *edkey;
  CK_OBJECT_HANDLE cert = 0, pvtkey = 0;
  CK_SESSION_HANDLE session;

  init_connection();
  asrt(funcs->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &session), CKR_OK, "OpenSession1");

  edkey = import_edkey(funcs, session, &cert, &pvtkey);

  destroy_test_objects(funcs, session, &cert, 1);
  asrt(funcs->C_CloseSession(session), CKR_OK, "CloseSession");
  asrt(funcs->C_Finalize(NULL), CKR_OK, "FINALIZE");
  dprintf(0, "TEST END: test_import_edkey()\n");

  return edkey;
}

static void test_import_x25519key() {
  dprintf(0, "TEST START: test_import_x25519key()\n");

  CK_OBJECT_HANDLE  cert = 0, pvtkey = 0;
  CK_SESSION_HANDLE session;

  init_connection();
  asrt(funcs->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &session), CKR_OK, "OpenSession1");

  import_x25519key(funcs, session, &cert, &pvtkey);

  destroy_test_objects(funcs, session, &pvtkey, 1);
  asrt(funcs->C_CloseSession(session), CKR_OK, "CloseSession");
  asrt(funcs->C_Finalize(NULL), CKR_OK, "FINALIZE");
  dprintf(0, "TEST END: test_import_x25519key()\n");
}

#endif

#if HW_TESTS
static int destruction_confirmed(void) {
#ifdef _WIN32
  return 1;
#else
  return system("../../../tools/confirm.sh") == 0;
#endif
}
#endif

int main(void) {

  get_functions();

#if HW_TESTS

//  test_initalize();
  // Require firmware version 5.7 or higher. Skip if earlier.
  if (!has_hardware_support()) {
    fprintf(stdout, "Firmware version too old to support ED25519 and EX25519 keys. Skipping tests.\n");
    exit(77);
  }

  // Require user confirmation to continue, since this test suite will clear
  // any data stored on connected keys.
  if (!destruction_confirmed()) {
    dprintf(0, "\n***\n*** Hardware tests skipped.\n***\n\n");
    exit(77); // exit code 77 == skipped tests
  }

  test_mechanism_list_and_info();
  test_generate_ed();
  test_generate_ex();
  test_import_edkey();
  test_import_x25519key();
  test_sign_edkey();
  test_edkey_attributes();
  test_xkey_attributes();
  test_find_objects();
#else
  fprintf(stderr, "HARDWARE TESTS DISABLED!, skipping...\n");
#endif

  return EXIT_SUCCESS;
}

//#pragma clang diagnostic pop