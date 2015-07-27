#include "mechanisms.h"

// Supported mechanisms for signature
static const CK_MECHANISM_TYPE sign[] = {
  CKM_RSA_PKCS,
  CKM_RSA_PKCS_PSS,
  CKM_RSA_X_509,
  CKM_SHA1_RSA_PKCS,
  CKM_SHA256_RSA_PKCS,
  CKM_SHA384_RSA_PKCS,
  CKM_SHA512_RSA_PKCS,
  CKM_SHA1_RSA_PKCS_PSS,
  CKM_SHA256_RSA_PKCS_PSS,
  CKM_SHA384_RSA_PKCS_PSS,
  CKM_SHA512_RSA_PKCS_PSS,
  CKM_ECDSA,
  CKM_ECDSA_SHA1
};

CK_RV check_sign_mechanism(const ykcs11_session_t *s, const CK_MECHANISM_PTR m, const CK_OBJECT_HANDLE k) {

  CK_ULONG i;
  CK_BBOOL supported = CK_FALSE;

  /* Check if mechanism is supported by the module */
  for (i = 0; i < sizeof(sign) / sizeof(CK_MECHANISM_TYPE); i++) {
    if (m->mechanism == sign[i]) {
      supported = CK_TRUE;
      break;
    }
  }
  if (supported == CK_FALSE)
    return CKR_MECHANISM_INVALID;

  /* Check if mechanism is supported by the token */
  
  
  CK_OK;
    
}
