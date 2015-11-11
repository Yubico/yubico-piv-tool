#include <ykcs11.h>
#include <ykcs11-version.h>

#include <string.h>

#define MANUFACTURER_ID      "Yubico (www.yubico.com)"
#define YKCS11_DESCRIPTION   "PKCS#11 PIV Library (SP-800-73)"
#define CRYPTOKI_VERSION_MAJ 2
#define CRYPTOKI_VERSION_MIN 40


static void lib_info() {

  CK_INFO info;
  CK_FUNCTION_LIST_PTR funcs;

  if (C_GetFunctionList(&funcs) != CKR_OK) {
    fprintf(stderr, "Get function list failed\n");
    exit(EXIT_FAILURE);
  }

  if (funcs->C_Initialize(NULL) != CKR_OK) {
    fprintf(stderr, "Initialize failed\n");
    exit(EXIT_FAILURE);
  }

  if (funcs->C_GetInfo(&info) != CKR_OK) {
    fprintf(stderr, "GetInfo failed\n");
    exit(EXIT_FAILURE);
  }

  if (strcmp(info.manufacturerID, MANUFACTURER_ID) != 0) {
    fprintf(stderr, "unexpected manufacturer ID %s\n", info.manufacturerID);
    exit(EXIT_FAILURE);
  }

  if (info.cryptokiVersion.major != CRYPTOKI_VERSION_MAJ ||
      info.cryptokiVersion.minor != CRYPTOKI_VERSION_MIN ) {
    fprintf(stderr, "unexpected Cryptoki version %d.%d\n", info.cryptokiVersion.major, info.cryptokiVersion.minor);
    exit(EXIT_FAILURE);
  }

  if (info.libraryVersion.major != YKCS11_VERSION_MAJOR ||
      info.libraryVersion.minor != ((YKCS11_VERSION_MINOR * 100) + YKCS11_VERSION_PATCH )) {
    fprintf(stderr, "unexpected YKCS11 version %d.%d\n", info.libraryVersion.major, info.libraryVersion.minor);
    exit(EXIT_FAILURE);
  }

  if (strcmp(info.libraryDescription, YKCS11_DESCRIPTION) != 0) {
    fprintf(stderr, "unexpected description %s\n", info.libraryDescription);
    exit(EXIT_FAILURE);
  }

  if (funcs->C_Finalize(NULL) != CKR_OK) {
    fprintf(stderr, "Finalize failed\n");
    exit(EXIT_FAILURE);
  }

}

int main(void) {

  lib_info();

  return EXIT_SUCCESS;

}
