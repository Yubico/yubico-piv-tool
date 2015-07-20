#ifndef OBJ_TYPES_H
#define OBJ_TYPES_H

#include "pkcs11t.h"

// TODO: this is mostly from OpenSC, how to give credit?
typedef enum {
  PIV_OBJ_CCC = 0,         // Card capability container
  PIV_OBJ_CHUI,            // Cardholder unique id
  /*  PIV_OBJ_UCHUI is not in new with 800-73-2 */
  PIV_OBJ_X509_PIV_AUTH,   // PIV authentication
  PIV_OBJ_CHF,             // Cardholder fingerprints
  PIV_OBJ_SEC_OBJ,         // Security object
  PIV_OBJ_CHFI,            // Cardholder facial images
  PIV_OBJ_X509_CARD_AUTH,  // Certificate for card authentication
  PIV_OBJ_X509_DS,         // Certificate for digital signature
  PIV_OBJ_X509_KM,         // Certificate for key management
  PIV_OBJ_PI,              // Cardholder printed information
  PIV_OBJ_DISCOVERY,       // Discovery object
  PIV_OBJ_HISTORY,         // History object
  PIV_OBJ_RETIRED_X509_1,  // Retired certificate for KM 1
  PIV_OBJ_RETIRED_X509_2,  // Retired certificate for KM 2
  PIV_OBJ_RETIRED_X509_3,  // Retired certificate for KM 3
  PIV_OBJ_RETIRED_X509_4,  // Retired certificate for KM 4
  PIV_OBJ_RETIRED_X509_5,  // Retired certificate for KM 5
  PIV_OBJ_RETIRED_X509_6,  // Retired certificate for KM 6
  PIV_OBJ_RETIRED_X509_7,  // Retired certificate for KM 7
  PIV_OBJ_RETIRED_X509_8,  // Retired certificate for KM 8
  PIV_OBJ_RETIRED_X509_9,  // Retired certificate for KM 9
  PIV_OBJ_RETIRED_X509_10, // Retired certificate for KM 10
  PIV_OBJ_RETIRED_X509_11, // Retired certificate for KM 11
  PIV_OBJ_RETIRED_X509_12, // Retired certificate for KM 12
  PIV_OBJ_RETIRED_X509_13, // Retired certificate for KM 13
  PIV_OBJ_RETIRED_X509_14, // Retired certificate for KM 14
  PIV_OBJ_RETIRED_X509_15, // Retired certificate for KM 15
  PIV_OBJ_RETIRED_X509_16, // Retired certificate for KM 16
  PIV_OBJ_RETIRED_X509_17, // Retired certificate for KM 17
  PIV_OBJ_RETIRED_X509_18, // Retired certificate for KM 18
  PIV_OBJ_RETIRED_X509_19, // Retired certificate for KM 19
  PIV_OBJ_RETIRED_X509_20, // Retired certificate for KM 20
  PIV_OBJ_IRIS_IMAGE,      // Cardholder iris images
  PIV_OBJ_BITGT,           // Biometric information templates group template
  PIV_OBJ_SM_SIGNER,       // Secure messaging signer
  PIV_OBJ_PC_REF_DATA,      // Pairing code reference data
  PIV_OBJ_9B03,            // NON-STANDARD TODO: remove?
  PIV_OBJ_9A06,            // NON-STANDARD
  PIV_OBJ_9C06,            // NON-STANDARD
  PIV_OBJ_9D06,            // NON-STANDARD
  PIV_OBJ_9E06,            // NON-STANDARD
  PIV_OBJ_8206,            // NON-STANDARD
  PIV_OBJ_8306,            // NON-STANDARD
  PIV_OBJ_8406,            // NON-STANDARD
  PIV_OBJ_8506,            // NON-STANDARD
  PIV_OBJ_8606,            // NON-STANDARD
  PIV_OBJ_8706,            // NON-STANDARD
  PIV_OBJ_8806,            // NON-STANDARD
  PIV_OBJ_8906,            // NON-STANDARD
  PIV_OBJ_8A06,            // NON-STANDARD
  PIV_OBJ_8B06,            // NON-STANDARD
  PIV_OBJ_8C06,            // NON-STANDARD
  PIV_OBJ_8D06,            // NON-STANDARD
  PIV_OBJ_8E06,            // NON-STANDARD
  PIV_OBJ_8F06,            // NON-STANDARD
  PIV_OBJ_9006,            // NON-STANDARD
  PIV_OBJ_9106,            // NON-STANDARD
  PIV_OBJ_9206,            // NON-STANDARD
  PIV_OBJ_9306,            // NON-STANDARD
  PIV_OBJ_9406,            // NON-STANDARD
  PIV_OBJ_9506,            // NON-STANDARD
  PIV_OBJ_LAST_ENUM
} piv_obj_id_t;

#define PIV_OBJECT_TYPE_CERT   1
#define PIV_OBJECT_TYPE_PUBKEY 2
#define PIV_OBJECT_NOT_PRESENT 4

typedef struct {
  //const CK_OBJECT_CLASS class;
  piv_obj_id_t      type;
  const CK_CHAR_PTR name; // TODO: or utf8
  const CK_CHAR_PTR oid;
  CK_BYTE           tag_len; // TODO: or ulong?
	CK_BYTE           tag_value[3];
	CK_BYTE           containerid[2];	/* will use as relative paths for simulation */ // TODO: needed?
	CK_ULONG          flags;          /* object has some internal object like a cert */
} piv_obj_t;

#endif
