/*
 * Copyright (c) 2024 Yubico AB
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

#include "../ykcs11.h"
#include "../ykcs11-config.h"

#include <string.h>

//#pragma clang diagnostic push
//#pragma clang diagnostic ignored "-Wpointer-sign"

#ifdef _WIN32
#define dprintf(fd, ...) fprintf(stdout, __VA_ARGS__)
#endif

CK_VOID_PTR funcs;

#define asrt(c, e, m) _asrt(__FILE__, __LINE__, c, e, m);

CK_BBOOL is_neo = CK_FALSE;

static void _asrt(const char *file, int line, CK_ULONG check, CK_ULONG expected, const char *msg) {

  if (check == expected)
    return;

  fprintf(stderr, "%s.%d: <%s> check failed with value %lu (0x%lx), expected %lu (0x%lx)\n",
          file, line, msg, check, check, expected, expected);

  exit(EXIT_FAILURE);

}

static void get_default_functions() {
  CK_INTERFACE_PTR interface;
  asrt(C_GetInterface(NULL,NULL,&interface,0), CKR_OK, "C_GetInterface default");
  funcs = interface->pFunctionList;
}

static void get_named_functions(CK_UTF8CHAR_PTR name) {
  CK_INTERFACE_PTR interface;
  asrt(C_GetInterface((CK_UTF8CHAR_PTR)"PKCS 11",NULL,&interface,0), CKR_OK, "C_GetInterface named");
  funcs = interface->pFunctionList;
}

static void get_versioned_functions(CK_BYTE major, CK_BYTE minor) {
  CK_INTERFACE_PTR interface;
  CK_VERSION version;
  version.major=major;
  version.minor=minor;
  asrt(C_GetInterface(NULL,&version,&interface,0), CKR_OK, "C_GetInterface versioned");
  funcs = interface->pFunctionList;
}

static void test_lib_info(CK_ULONG vmajor, CK_ULONG vminor) {
  dprintf(0, "TEST START: test_lib_info()\n");

  const CK_CHAR_PTR MANUFACTURER_ID = (const CK_CHAR_PTR)"Yubico (www.yubico.com)";
  const CK_CHAR_PTR YKCS11_DESCRIPTION = (const CK_CHAR_PTR)"PKCS#11 PIV Library (SP-800-73)";
  const CK_ULONG CRYPTOKI_VERSION_MAJ = vmajor;
  const CK_ULONG CRYPTOKI_VERSION_MIN = vminor;

  CK_INFO info;
  asrt(((CK_FUNCTION_LIST_3_0*)funcs)->C_Initialize(NULL), CKR_OK, "INITIALIZE");
  asrt(((CK_FUNCTION_LIST_3_0*)funcs)->C_GetInfo(&info), CKR_OK, "GET_INFO");
  asrt(strncmp((const char*)info.manufacturerID, (const char*)MANUFACTURER_ID, strlen((const char*)MANUFACTURER_ID)), 0, "MANUFACTURER");

  asrt(info.cryptokiVersion.major, CRYPTOKI_VERSION_MAJ, "CK_MAJ");
  asrt(info.cryptokiVersion.minor, CRYPTOKI_VERSION_MIN, "CK_MIN");
  asrt(info.libraryVersion.major, YKCS11_VERSION_MAJOR, "LIB_MAJ");
  asrt(info.libraryVersion.minor, ((YKCS11_VERSION_MINOR * 10) + YKCS11_VERSION_PATCH), "LIB_MIN");
  asrt(strncmp((const char*)info.libraryDescription, (const char*)YKCS11_DESCRIPTION, strlen((const char*)YKCS11_DESCRIPTION)), 0, "LIB_DESC");
  asrt(((CK_FUNCTION_LIST_3_0*)funcs)->C_Finalize(NULL), CKR_OK, "FINALIZE");
  dprintf(0, "TEST END: test_lib_info()\n");
}


int main(void) {
  get_default_functions();
  test_lib_info(CRYPTOKI_VERSION_MAJOR, CRYPTOKI_VERSION_MINOR);
  asrt(((CK_FUNCTION_LIST_3_0*)funcs)->C_SignMessage(0, NULL, 0, NULL, 0, NULL, NULL), CKR_FUNCTION_NOT_SUPPORTED, "C_SignMessage");

  get_versioned_functions(CRYPTOKI_LEGACY_VERSION_MAJOR, CRYPTOKI_LEGACY_VERSION_MINOR);
  test_lib_info(CRYPTOKI_LEGACY_VERSION_MAJOR, CRYPTOKI_LEGACY_VERSION_MINOR);

  get_versioned_functions(CRYPTOKI_VERSION_MAJOR, CRYPTOKI_VERSION_MINOR);
  test_lib_info(CRYPTOKI_VERSION_MAJOR, CRYPTOKI_VERSION_MINOR);

  get_named_functions("PKCS 11");
  test_lib_info(CRYPTOKI_VERSION_MAJOR, CRYPTOKI_VERSION_MINOR);

  return EXIT_SUCCESS;
}

//#pragma clang diagnostic pop