#include <ykcs11.h>
#include <ykcs11-version.h>

#include <string.h>

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
  asrt(info.libraryVersion.minor, ((YKCS11_VERSION_MINOR * 100) + YKCS11_VERSION_PATCH ), "LIB_MIN");

  asrt(strcmp(info.libraryDescription, YKCS11_DESCRIPTION), 0, "LIB_DESC");
}

static void test_initalize() {

  asrt(funcs->C_Initialize(NULL), CKR_OK, "INITIALIZE");

  asrt(funcs->C_Finalize(NULL), CKR_OK, "FINALIZE");

}

static void test_token_info() {

  const CK_CHAR_PTR TOKEN_LABEL  = "YubiKey PIV";
  const CK_CHAR_PTR TOKEN_MODEL  = "YubiKey ";  // Skip last 3 characters (version dependent)
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
  asrt(info.hardwareVersion.major, HW.major, "HW_MAJ");
  asrt(info.hardwareVersion.minor, HW.minor, "HW_MIN");

  if (info.firmwareVersion.major != 4 && info.firmwareVersion.major != 0)
    asrt(info.firmwareVersion.major, 4, "FW_MAJ");

  asrt(strcmp(info.utcTime, TOKEN_TIME), 0, "TOKEN_TIME");

  asrt(funcs->C_Finalize(NULL), CKR_OK, "FINALIZE");

}

int main(void) {

  get_functions(&funcs);

  test_lib_info();

#ifdef HW_TESTS
  test_initalize();
  test_token_info();
#endif

  return EXIT_SUCCESS;

}
