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
  PIV_DATA_OBJ_X509_RETIRED_1,    // Certificate for retired key 1
  PIV_DATA_OBJ_X509_RETIRED_2,    // Certificate for retired key 2
  PIV_DATA_OBJ_X509_RETIRED_3,    // Certificate for retired key 3
  PIV_DATA_OBJ_X509_RETIRED_4,    // Certificate for retired key 4
  PIV_DATA_OBJ_X509_RETIRED_5,    // Certificate for retired key 5
  PIV_DATA_OBJ_X509_RETIRED_6,    // Certificate for retired key 6
  PIV_DATA_OBJ_X509_RETIRED_7,    // Certificate for retired key 7
  PIV_DATA_OBJ_X509_RETIRED_8,    // Certificate for retired key 8
  PIV_DATA_OBJ_X509_RETIRED_9,    // Certificate for retired key 9
  PIV_DATA_OBJ_X509_RETIRED_10,   // Certificate for retired key 10
  PIV_DATA_OBJ_X509_RETIRED_11,   // Certificate for retired key 11
  PIV_DATA_OBJ_X509_RETIRED_12,   // Certificate for retired key 12
  PIV_DATA_OBJ_X509_RETIRED_13,   // Certificate for retired key 13
  PIV_DATA_OBJ_X509_RETIRED_14,   // Certificate for retired key 14
  PIV_DATA_OBJ_X509_RETIRED_15,   // Certificate for retired key 15
  PIV_DATA_OBJ_X509_RETIRED_16,   // Certificate for retired key 16
  PIV_DATA_OBJ_X509_RETIRED_17,   // Certificate for retired key 17
  PIV_DATA_OBJ_X509_RETIRED_18,   // Certificate for retired key 18
  PIV_DATA_OBJ_X509_RETIRED_19,   // Certificate for retired key 19
  PIV_DATA_OBJ_X509_RETIRED_20,   // Certificate for retired key 20
  PIV_DATA_OBJ_CCC,               // Card capability container
  PIV_DATA_OBJ_CHUI,              // Cardholder unique id
  PIV_DATA_OBJ_CHF,               // Cardholder fingerprints
  PIV_DATA_OBJ_SEC_OBJ,           // Security object
  PIV_DATA_OBJ_CHFI,              // Cardholder facial images
  PIV_DATA_OBJ_PI,                // Cardholder printed information
  PIV_DATA_OBJ_DISCOVERY,         // Discovery object
  PIV_DATA_OBJ_HISTORY,           // History object
  PIV_DATA_OBJ_IRIS_IMAGE,        // Cardholder iris images
  PIV_DATA_OBJ_BITGT,             // Biometric information templates group template
  PIV_DATA_OBJ_SM_SIGNER,         // Secure messaging signer
  PIV_DATA_OBJ_PC_REF_DATA,       // Pairing code reference data
  PIV_DATA_OBJ_LAST,

  PIV_CERT_OBJ_X509_PIV_AUTH,     // PIV authentication
  PIV_CERT_OBJ_X509_CARD_AUTH,    // Certificate for card authentication
  PIV_CERT_OBJ_X509_DS,           // Certificate for digital signature
  PIV_CERT_OBJ_X509_KM,           // Certificate for key management
  PIV_CERT_OBJ_X509_RETIRED_1,    // Certificate for retired key 1
  PIV_CERT_OBJ_X509_RETIRED_2,    // Certificate for retired key 2
  PIV_CERT_OBJ_X509_RETIRED_3,    // Certificate for retired key 3
  PIV_CERT_OBJ_X509_RETIRED_4,    // Certificate for retired key 4
  PIV_CERT_OBJ_X509_RETIRED_5,    // Certificate for retired key 5
  PIV_CERT_OBJ_X509_RETIRED_6,    // Certificate for retired key 6
  PIV_CERT_OBJ_X509_RETIRED_7,    // Certificate for retired key 7
  PIV_CERT_OBJ_X509_RETIRED_8,    // Certificate for retired key 8
  PIV_CERT_OBJ_X509_RETIRED_9,    // Certificate for retired key 9
  PIV_CERT_OBJ_X509_RETIRED_10,   // Certificate for retired key 10
  PIV_CERT_OBJ_X509_RETIRED_11,   // Certificate for retired key 11
  PIV_CERT_OBJ_X509_RETIRED_12,   // Certificate for retired key 12
  PIV_CERT_OBJ_X509_RETIRED_13,   // Certificate for retired key 13
  PIV_CERT_OBJ_X509_RETIRED_14,   // Certificate for retired key 14
  PIV_CERT_OBJ_X509_RETIRED_15,   // Certificate for retired key 15
  PIV_CERT_OBJ_X509_RETIRED_16,   // Certificate for retired key 16
  PIV_CERT_OBJ_X509_RETIRED_17,   // Certificate for retired key 17
  PIV_CERT_OBJ_X509_RETIRED_18,   // Certificate for retired key 18
  PIV_CERT_OBJ_X509_RETIRED_19,   // Certificate for retired key 19
  PIV_CERT_OBJ_X509_RETIRED_20,   // Certificate for retired key 20
  PIV_CERT_OBJ_LAST,

  PIV_PVTK_OBJ_PIV_AUTH,          // Private key for PIV authentication
  PIV_PVTK_OBJ_CARD_AUTH,         // Private key for card authentication
  PIV_PVTK_OBJ_DS,                // Private key for digital signature
  PIV_PVTK_OBJ_KM,                // Private key for key management
  PIV_PVTK_OBJ_RETIRED_1,         // Private key for retired key 1
  PIV_PVTK_OBJ_RETIRED_2,         // Private key for retired key 2
  PIV_PVTK_OBJ_RETIRED_3,         // Private key for retired key 3
  PIV_PVTK_OBJ_RETIRED_4,         // Private key for retired key 4
  PIV_PVTK_OBJ_RETIRED_5,         // Private key for retired key 5
  PIV_PVTK_OBJ_RETIRED_6,         // Private key for retired key 6
  PIV_PVTK_OBJ_RETIRED_7,         // Private key for retired key 7
  PIV_PVTK_OBJ_RETIRED_8,         // Private key for retired key 8
  PIV_PVTK_OBJ_RETIRED_9,         // Private key for retired key 9
  PIV_PVTK_OBJ_RETIRED_10,        // Private key for retired key 10
  PIV_PVTK_OBJ_RETIRED_11,        // Private key for retired key 11
  PIV_PVTK_OBJ_RETIRED_12,        // Private key for retired key 12
  PIV_PVTK_OBJ_RETIRED_13,        // Private key for retired key 13
  PIV_PVTK_OBJ_RETIRED_14,        // Private key for retired key 14
  PIV_PVTK_OBJ_RETIRED_15,        // Private key for retired key 15
  PIV_PVTK_OBJ_RETIRED_16,        // Private key for retired key 16
  PIV_PVTK_OBJ_RETIRED_17,        // Private key for retired key 17
  PIV_PVTK_OBJ_RETIRED_18,        // Private key for retired key 18
  PIV_PVTK_OBJ_RETIRED_19,        // Private key for retired key 19
  PIV_PVTK_OBJ_RETIRED_20,        // Private key for retired key 20
  PIV_PVTK_OBJ_LAST,

  PIV_PUBK_OBJ_PIV_AUTH,          // Public key for PIV authentication
  PIV_PUBK_OBJ_CARD_AUTH,         // Public key for card authentication
  PIV_PUBK_OBJ_DS,                // Public key for digital signature
  PIV_PUBK_OBJ_KM,                // Public key for key management
  PIV_PUBK_OBJ_RETIRED_1,         // Public key for retired key 1
  PIV_PUBK_OBJ_RETIRED_2,         // Public key for retired key 2
  PIV_PUBK_OBJ_RETIRED_3,         // Public key for retired key 3
  PIV_PUBK_OBJ_RETIRED_4,         // Public key for retired key 4
  PIV_PUBK_OBJ_RETIRED_5,         // Public key for retired key 5
  PIV_PUBK_OBJ_RETIRED_6,         // Public key for retired key 6
  PIV_PUBK_OBJ_RETIRED_7,         // Public key for retired key 7
  PIV_PUBK_OBJ_RETIRED_8,         // Public key for retired key 8
  PIV_PUBK_OBJ_RETIRED_9,         // Public key for retired key 9
  PIV_PUBK_OBJ_RETIRED_10,        // Public key for retired key 10
  PIV_PUBK_OBJ_RETIRED_11,        // Public key for retired key 11
  PIV_PUBK_OBJ_RETIRED_12,        // Public key for retired key 12
  PIV_PUBK_OBJ_RETIRED_13,        // Public key for retired key 13
  PIV_PUBK_OBJ_RETIRED_14,        // Public key for retired key 14
  PIV_PUBK_OBJ_RETIRED_15,        // Public key for retired key 15
  PIV_PUBK_OBJ_RETIRED_16,        // Public key for retired key 16
  PIV_PUBK_OBJ_RETIRED_17,        // Public key for retired key 17
  PIV_PUBK_OBJ_RETIRED_18,        // Public key for retired key 18
  PIV_PUBK_OBJ_RETIRED_19,        // Public key for retired key 19
  PIV_PUBK_OBJ_RETIRED_20,        // Public key for retired key 20
  PIV_PUBK_OBJ_LAST

} piv_obj_id_t;

#define OBJECT_INVALID            (PIV_PUBK_OBJ_LAST + 1)

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

typedef struct { // TODO: enough to use the public key for the parameters?
  CK_BBOOL decrypt;
  CK_BBOOL sign;
  CK_BBOOL unwrap;
  CK_BBOOL derive;
  CK_BBOOL always_auth;
} piv_pvtk_obj_t;

typedef struct {
  EVP_PKEY *data; // TODO: make custom type for this and X509
  CK_BBOOL encrypt;
  CK_BBOOL verify;
  CK_BBOOL wrap;
  CK_BBOOL derive;
} piv_pubk_obj_t;

typedef struct {
  piv_obj_id_t piv_id; // TODO: technically redundant
  CK_BBOOL     token; // TODO: not used yet
  CK_BBOOL     private;
  CK_BBOOL     modifiable;
  const char   *label;
  CK_BBOOL     copyable; // TODO: Optional, not used so far (default TRUE)
  CK_BBOOL     destroyable; // TODO: Optional, not used so far (default TRUE)
  get_attr_f   get_attribute;
  CK_BYTE      sub_id; // Sub-object id
} piv_obj_t;

#endif
