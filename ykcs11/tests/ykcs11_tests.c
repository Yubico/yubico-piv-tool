#include <ykcs11.h>
#include <ykcs11-version.h>

#include <string.h>
#include <assert.h>

#define MANUFACTURER_ID      "Yubico (www.yubico.com)"
#define YKCS11_DESCRIPTION   "PKCS#11 PIV Library (SP-800-73)"
#define CRYPTOKI_VERSION_MAJ 2
#define CRYPTOKI_VERSION_MIN 40

CK_FUNCTION_LIST_PTR funcs;

static void get_functions(CK_FUNCTION_LIST_PTR_PTR funcs) {

  if (C_GetFunctionList(funcs) != CKR_OK) {
    fprintf(stderr, "Get function list failed\n");
    exit(EXIT_FAILURE);
  }

}

static void test_lib_info() {

  CK_INFO info;

  if (funcs->C_GetInfo(&info) != CKR_OK) {
    fprintf(stderr, "GetInfo failed\n");
    exit(EXIT_FAILURE);
  }

  if (strcmp(info.manufacturerID, MANUFACTURER_ID) != 0) {
    fprintf(stderr, "Unexpected manufacturer ID %s\n", info.manufacturerID);
    exit(EXIT_FAILURE);
  }

  if (info.cryptokiVersion.major != CRYPTOKI_VERSION_MAJ ||
      info.cryptokiVersion.minor != CRYPTOKI_VERSION_MIN ) {
    fprintf(stderr, "Unexpected Cryptoki version %d.%d\n", info.cryptokiVersion.major, info.cryptokiVersion.minor);
    exit(EXIT_FAILURE);
  }

  if (info.libraryVersion.major != YKCS11_VERSION_MAJOR ||
      info.libraryVersion.minor != ((YKCS11_VERSION_MINOR * 100) + YKCS11_VERSION_PATCH )) {
    fprintf(stderr, "Unexpected YKCS11 version %d.%d\n", info.libraryVersion.major, info.libraryVersion.minor);
    exit(EXIT_FAILURE);
  }

  if (strcmp(info.libraryDescription, YKCS11_DESCRIPTION) != 0) {
    fprintf(stderr, "Unexpected description %s\n", info.libraryDescription);
    exit(EXIT_FAILURE);
  }

}

static void test_initalize() {

  if (funcs->C_Initialize(NULL) != CKR_OK) {
    fprintf(stderr, "Unable to initialize YKCS11\n");
    exit(EXIT_FAILURE);
  }

  if (funcs->C_Finalize(NULL) != CKR_OK) {
    fprintf(stderr, "Unable to finalize YKCS11\n");
    exit(EXIT_FAILURE);
  }

}

static void test_token_info() {

  CK_TOKEN_INFO info;

  assert(funcs->C_GetTokenInfo(0, &info) == CKR_OK);
  /*fprintf
  }*/

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
