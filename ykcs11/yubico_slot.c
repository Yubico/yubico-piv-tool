#include "yubico_slot.h"
#include "pkcs11.h"
#include <string.h>

static const CK_UTF8CHAR_PTR slot_description = "YubiKey Virtual Reader";
static const CK_UTF8CHAR_PTR slot_manufacturer = "Yubico";
static const CK_FLAGS slot_flags = CKF_TOKEN_PRESENT | CKF_HW_SLOT;
static const CK_VERSION slot_version = {1, 0};

CK_RV YUBICO_get_slot_description(CK_UTF8CHAR_PTR str, CK_ULONG len) {

  if (strlen(slot_description) > len)
    return CKR_BUFFER_TOO_SMALL;

  memcpy(str, slot_description, strlen(slot_description));
  return CKR_OK;

}

CK_RV YUBICO_get_slot_manufacturer(CK_UTF8CHAR_PTR str, CK_ULONG len) {

  if (strlen(slot_manufacturer) > len)
    return CKR_BUFFER_TOO_SMALL;

  memcpy(str, slot_manufacturer, strlen(slot_manufacturer));
  return CKR_OK;

}

CK_RV YUBICO_get_slot_flags(CK_FLAGS_PTR flags) {

  *flags = slot_flags;
  return CKR_OK;

}

CK_RV YUBICO_get_slot_version(CK_VERSION_PTR version) {

  version->major = slot_version.major;
  version->minor = slot_version.minor;

  return CKR_OK;

}
