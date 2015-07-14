#include "yubico.h"
#include "pkcs11.h"


CK_UTF8CHAR_PTR YUBICO_get_slot_description(void) {
  
  return "YubiKey Virtual Reader";
  
}

CK_UTF8CHAR_PTR YUBICO_get_slot_manufacturer(void) {

  return "Yubico";

}

CK_FLAGS YUBICO_get_slot_flags(void) {

  return CKF_TOKEN_PRESENT | CKF_HW_SLOT;

}

CK_VERSION YUBICO_get_slot_version(CK_UTF8CHAR_PTR version, CK_ULONG len) {

  CK_VERSION v = {1.0}; // Dummy value

  return v;

}

CK_UTF8CHAR_PTR YUBICO_get_token_label(void) {

  return "YubiKey PIV";

}

CK_UTF8CHAR_PTR YUBICO_get_token_manufacturer(void) {

  return "Yubico";

}

CK_UTF8CHAR_PTR YUBICO_get_token_model(void) {

  return "PRO";

}

CK_FLAGS YUBICO_get_token_flags(void) {

  return CKF_RNG | CKF_LOGIN_REQUIRED | CKF_USER_PIN_INITIALIZED | CKF_TOKEN_INITIALIZED;

}

CK_VERSION YUBICO_get_token_version(CK_UTF8CHAR_PTR version, CK_ULONG len) {

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

CK_BYTE_PTR YUBICO_get_token_serial(void) {

  return "1234";

}
