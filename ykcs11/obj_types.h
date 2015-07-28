#ifndef OBJ_TYPES_H
#define OBJ_TYPES_H

#include "pkcs11t.h"

#include <openssl/x509.h>

// TODO: this is mostly from OpenSC, how to give credit?
typedef enum {
  PIV_DATA_OBJ_X509_PIV_AUTH = 0, // PIV authentication
  PIV_DATA_OBJ_X509_CARD_AUTH,    // Certificate for card authentication
  PIV_DATA_OBJ_X509_DS,           // Certificate for digital signature
  PIV_DATA_OBJ_X509_KM,           // Certificate for key management
  PIV_DATA_OBJ_CCC,               // Card capability container
  PIV_DATA_OBJ_CHUI,              // Cardholder unique id
  PIV_DATA_OBJ_CHF,               // Cardholder fingerprints
  PIV_DATA_OBJ_SEC_OBJ,           // Security object
  PIV_DATA_OBJ_CHFI,              // Cardholder facial images
  PIV_DATA_OBJ_PI,                // Cardholder printed information
  PIV_DATA_OBJ_DISCOVERY,         // Discovery object
  PIV_DATA_OBJ_HISTORY,           // History object
  PIV_DATA_OBJ_RETIRED_X509_1,    // Retired certificate for KM 1
  PIV_DATA_OBJ_RETIRED_X509_2,    // Retired certificate for KM 2
  PIV_DATA_OBJ_RETIRED_X509_3,    // Retired certificate for KM 3
  PIV_DATA_OBJ_RETIRED_X509_4,    // Retired certificate for KM 4
  PIV_DATA_OBJ_RETIRED_X509_5,    // Retired certificate for KM 5
  PIV_DATA_OBJ_RETIRED_X509_6,    // Retired certificate for KM 6
  PIV_DATA_OBJ_RETIRED_X509_7,    // Retired certificate for KM 7
  PIV_DATA_OBJ_RETIRED_X509_8,    // Retired certificate for KM 8
  PIV_DATA_OBJ_RETIRED_X509_9,    // Retired certificate for KM 9
  PIV_DATA_OBJ_RETIRED_X509_10,   // Retired certificate for KM 10
  PIV_DATA_OBJ_RETIRED_X509_11,   // Retired certificate for KM 11
  PIV_DATA_OBJ_RETIRED_X509_12,   // Retired certificate for KM 12
  PIV_DATA_OBJ_RETIRED_X509_13,   // Retired certificate for KM 13
  PIV_DATA_OBJ_RETIRED_X509_14,   // Retired certificate for KM 14
  PIV_DATA_OBJ_RETIRED_X509_15,   // Retired certificate for KM 15
  PIV_DATA_OBJ_RETIRED_X509_16,   // Retired certificate for KM 16
  PIV_DATA_OBJ_RETIRED_X509_17,   // Retired certificate for KM 17
  PIV_DATA_OBJ_RETIRED_X509_18,   // Retired certificate for KM 18
  PIV_DATA_OBJ_RETIRED_X509_19,   // Retired certificate for KM 19
  PIV_DATA_OBJ_RETIRED_X509_20,   // Retired certificate for KM 20
  PIV_DATA_OBJ_IRIS_IMAGE,        // Cardholder iris images
  PIV_DATA_OBJ_BITGT,             // Biometric information templates group template
  PIV_DATA_OBJ_SM_SIGNER,         // Secure messaging signer
  PIV_DATA_OBJ_PC_REF_DATA,       // Pairing code reference data
/*  PIV_DATA_OBJ_9B03,            // NON-STANDARD TODO: remove?
  PIV_DATA_OBJ_9A06,              // NON-STANDARD
  PIV_DATA_OBJ_9C06,              // NON-STANDARD
  PIV_DATA_OBJ_9D06,              // NON-STANDARD
  PIV_DATA_OBJ_9E06,              // NON-STANDARD
  PIV_DATA_OBJ_8206,              // NON-STANDARD
  PIV_DATA_OBJ_8306,              // NON-STANDARD
  PIV_DATA_OBJ_8406,              // NON-STANDARD
  PIV_DATA_OBJ_8506,              // NON-STANDARD
  PIV_DATA_OBJ_8606,              // NON-STANDARD
  PIV_DATA_OBJ_8706,              // NON-STANDARD
  PIV_DATA_OBJ_8806,              // NON-STANDARD
  PIV_DATA_OBJ_8906,              // NON-STANDARD
  PIV_DATA_OBJ_8A06,              // NON-STANDARD
  PIV_DATA_OBJ_8B06,              // NON-STANDARD
  PIV_DATA_OBJ_8C06,              // NON-STANDARD
  PIV_DATA_OBJ_8D06,              // NON-STANDARD
  PIV_DATA_OBJ_8E06,              // NON-STANDARD
  PIV_DATA_OBJ_8F06,              // NON-STANDARD
  PIV_DATA_OBJ_9006,              // NON-STANDARD
  PIV_DATA_OBJ_9106,              // NON-STANDARD
  PIV_DATA_OBJ_9206,              // NON-STANDARD
  PIV_DATA_OBJ_9306,              // NON-STANDARD
  PIV_DATA_OBJ_9406,              // NON-STANDARD
  PIV_DATA_OBJ_9506,              // NON-STANDARD*/
  PIV_DATA_OBJ_LAST,

  PIV_CERT_OBJ_X509_PIV_AUTH,     // PIV authentication
  PIV_CERT_OBJ_X509_CARD_AUTH,    // Certificate for card authentication
  PIV_CERT_OBJ_X509_DS,           // Certificate for digital signature
  PIV_CERT_OBJ_X509_KM,           // Certificate for key management
  PIV_CERT_OBJ_LAST,

  PIV_PVTK_OBJ_PIV_AUTH,          // Private key for PIV authentication
  PIV_PVTK_OBJ_CARD_AUTH,         // Private Key for card authentication
  PIV_PVTK_OBJ_DS,                // Private Key for digital signature
  PIV_PVTK_OBJ_KM,                // Private Key for key management
  PIV_PVTK_OBJ_LAST,

  PIV_PUBK_OBJ_PIV_AUTH,          // Public key for PIV authentication
  PIV_PUBK_OBJ_CARD_AUTH,         // Public Key for card authentication
  PIV_PUBK_OBJ_DS,                // Public Key for digital signature
  PIV_PUBK_OBJ_KM,                // Public Key for key management
  PIV_PUBK_OBJ_LAST

} piv_obj_id_t;

typedef CK_RV (*get_attr_f)(CK_OBJECT_HANDLE, CK_ATTRIBUTE_PTR);

typedef struct {
  const char   *oid;
  CK_BYTE      tag_len;
  CK_BYTE      tag_value[3];   // TODO: needed?
  CK_BYTE      containerid[2]; /* will use as relative paths for simulation */ // TODO: needed?
} piv_data_obj_t;

typedef struct {
  X509 *data;
} piv_cert_obj_t;

typedef struct {
  CK_BBOOL todo;
} piv_pvtk_obj_t;

typedef struct {
  CK_BBOOL todo;
} piv_pubk_obj_t;

typedef struct {
  piv_obj_id_t piv_id; // TODO: technically redundant
  CK_BBOOL     token; // TODO: not used yet
  CK_BBOOL     private;
  CK_BBOOL     modifiable;
  char        *label;
  CK_BBOOL     copyable; // TODO: Optional, not used so far (default TRUE)
  CK_BBOOL     destroyable; // TODO: Optional, not used so far (default TRUE)
  get_attr_f   get_attribute;
  CK_ULONG     sub_id; // Sub-object id
} piv_obj_t;

#endif
