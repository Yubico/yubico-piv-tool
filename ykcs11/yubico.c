#include "yubico.h"
#include "pkcs11.h"

CK_VERSION YUBICO_get_version(CK_UTF8CHAR_PTR version, CK_ULONG len) {

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

CK_UTF8CHAR_PTR YUBICO_get_label(void) {

  return "YubiKey";

}

CK_UTF8CHAR_PTR YUBICO_get_manufacturer(void) {

  return "Yubico";

}

CK_UTF8CHAR_PTR YUBICO_get_model(void) {

  return "PRO";

}

CK_FLAGS YUBICO_get_flags(void) {

  return CKF_RNG | CKF_LOGIN_REQUIRED | CKF_USER_PIN_INITIALIZED | CKF_TOKEN_INITIALIZED;

}
