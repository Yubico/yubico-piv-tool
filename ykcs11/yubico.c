#include "yubico.h"
#include "pkcs11.h"

CK_VERSION YUBICO_get_version(char *version, int len) {

  CK_VERSION v = {0, 0};
  int i = 0;

  while (i < len && version[i] != '.') {
    v.major *= 10;
    v.major += version[i++] - '0';
  }

  i++;

  while (i < len && version[i] != '.') {
    v.minor *= 10;
    v.minor += version[i++] - '0';
  }

  i++;

  while (i < len && version[i] != '.') {
    v.minor *= 10;
    v.minor += version[i++] - '0';
  }

  return v;
}
