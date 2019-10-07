/*
 * Copyright (c) 2015-2016 Yubico AB
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *
 *   * Redistributions in binary form must reproduce the above
 *     copyright notice, this list of conditions and the following
 *     disclaimer in the documentation and/or other materials provided
 *     with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#ifndef OBJ_TYPES_H
#define OBJ_TYPES_H

#include "pkcs11y.h"

#include <openssl/x509.h>

// TODO: this is mostly from OpenSC, how to give credit?
typedef enum {
  PIV_DATA_OBJ_X509_PIV_AUTH = 0, // PIV authentication
  PIV_DATA_OBJ_X509_DS,           // Digital signature
  PIV_DATA_OBJ_X509_KM,           // Key management
  PIV_DATA_OBJ_X509_CARD_AUTH,    // Card authentication
  PIV_DATA_OBJ_X509_RETIRED1,     // Retired key 1
  PIV_DATA_OBJ_X509_RETIRED2,     // Retired key 2
  PIV_DATA_OBJ_X509_RETIRED3,     // Retired key 3
  PIV_DATA_OBJ_X509_RETIRED4,     // Retired key 4
  PIV_DATA_OBJ_X509_RETIRED5,     // Retired key 5
  PIV_DATA_OBJ_X509_RETIRED6,     // Retired key 6
  PIV_DATA_OBJ_X509_RETIRED7,     // Retired key 7
  PIV_DATA_OBJ_X509_RETIRED8,     // Retired key 8
  PIV_DATA_OBJ_X509_RETIRED9,     // Retired key 9
  PIV_DATA_OBJ_X509_RETIRED10,    // Retired key 10
  PIV_DATA_OBJ_X509_RETIRED11,    // Retired key 11
  PIV_DATA_OBJ_X509_RETIRED12,    // Retired key 12
  PIV_DATA_OBJ_X509_RETIRED13,    // Retired key 13
  PIV_DATA_OBJ_X509_RETIRED14,    // Retired key 14
  PIV_DATA_OBJ_X509_RETIRED15,    // Retired key 15
  PIV_DATA_OBJ_X509_RETIRED16,    // Retired key 16
  PIV_DATA_OBJ_X509_RETIRED17,    // Retired key 17
  PIV_DATA_OBJ_X509_RETIRED18,    // Retired key 18
  PIV_DATA_OBJ_X509_RETIRED19,    // Retired key 19
  PIV_DATA_OBJ_X509_RETIRED20,    // Retired key 20
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

  PIV_CERT_OBJ_X509_PIV_AUTH,     // Certificate for PIV authentication
  PIV_CERT_OBJ_X509_DS,           // Certificate for digital signature
  PIV_CERT_OBJ_X509_KM,           // Certificate for key management
  PIV_CERT_OBJ_X509_CARD_AUTH,    // Certificate for card authentication
  PIV_CERT_OBJ_X509_RETIRED1,     // Certificate for retired key 1
  PIV_CERT_OBJ_X509_RETIRED2,     // Certificate for retired key 2
  PIV_CERT_OBJ_X509_RETIRED3,     // Certificate for retired key 3
  PIV_CERT_OBJ_X509_RETIRED4,     // Certificate for retired key 4
  PIV_CERT_OBJ_X509_RETIRED5,     // Certificate for retired key 5
  PIV_CERT_OBJ_X509_RETIRED6,     // Certificate for retired key 6
  PIV_CERT_OBJ_X509_RETIRED7,     // Certificate for retired key 7
  PIV_CERT_OBJ_X509_RETIRED8,     // Certificate for retired key 8
  PIV_CERT_OBJ_X509_RETIRED9,     // Certificate for retired key 9
  PIV_CERT_OBJ_X509_RETIRED10,    // Certificate for retired key 10
  PIV_CERT_OBJ_X509_RETIRED11,    // Certificate for retired key 11
  PIV_CERT_OBJ_X509_RETIRED12,    // Certificate for retired key 12
  PIV_CERT_OBJ_X509_RETIRED13,    // Certificate for retired key 13
  PIV_CERT_OBJ_X509_RETIRED14,    // Certificate for retired key 14
  PIV_CERT_OBJ_X509_RETIRED15,    // Certificate for retired key 15
  PIV_CERT_OBJ_X509_RETIRED16,    // Certificate for retired key 16
  PIV_CERT_OBJ_X509_RETIRED17,    // Certificate for retired key 17
  PIV_CERT_OBJ_X509_RETIRED18,    // Certificate for retired key 18
  PIV_CERT_OBJ_X509_RETIRED19,    // Certificate for retired key 19
  PIV_CERT_OBJ_X509_RETIRED20,    // Certificate for retired key 20
  PIV_CERT_OBJ_LAST,

  PIV_PVTK_OBJ_PIV_AUTH,          // Private key for PIV authentication
  PIV_PVTK_OBJ_DS,                // Private key for digital signature
  PIV_PVTK_OBJ_KM,                // Private key for key management
  PIV_PVTK_OBJ_CARD_AUTH,         // Private key for card authentication
  PIV_PVTK_OBJ_RETIRED1,          // Private key for retired key 1
  PIV_PVTK_OBJ_RETIRED2,          // Private key for retired key 2
  PIV_PVTK_OBJ_RETIRED3,          // Private key for retired key 3
  PIV_PVTK_OBJ_RETIRED4,          // Private key for retired key 4
  PIV_PVTK_OBJ_RETIRED5,          // Private key for retired key 5
  PIV_PVTK_OBJ_RETIRED6,          // Private key for retired key 6
  PIV_PVTK_OBJ_RETIRED7,          // Private key for retired key 7
  PIV_PVTK_OBJ_RETIRED8,          // Private key for retired key 8
  PIV_PVTK_OBJ_RETIRED9,          // Private key for retired key 9
  PIV_PVTK_OBJ_RETIRED10,         // Private key for retired key 10
  PIV_PVTK_OBJ_RETIRED11,         // Private key for retired key 11
  PIV_PVTK_OBJ_RETIRED12,         // Private key for retired key 12
  PIV_PVTK_OBJ_RETIRED13,         // Private key for retired key 13
  PIV_PVTK_OBJ_RETIRED14,         // Private key for retired key 14
  PIV_PVTK_OBJ_RETIRED15,         // Private key for retired key 15
  PIV_PVTK_OBJ_RETIRED16,         // Private key for retired key 16
  PIV_PVTK_OBJ_RETIRED17,         // Private key for retired key 17
  PIV_PVTK_OBJ_RETIRED18,         // Private key for retired key 18
  PIV_PVTK_OBJ_RETIRED19,         // Private key for retired key 19
  PIV_PVTK_OBJ_RETIRED20,         // Private key for retired key 20
  PIV_PVTK_OBJ_LAST,

  PIV_PUBK_OBJ_PIV_AUTH,          // Public key for PIV authentication
  PIV_PUBK_OBJ_DS,                // Public key for digital signature
  PIV_PUBK_OBJ_KM,                // Public key for key management
  PIV_PUBK_OBJ_CARD_AUTH,         // Public key for card authentication
  PIV_PUBK_OBJ_RETIRED1,          // Public key for retired key 1
  PIV_PUBK_OBJ_RETIRED2,          // Public key for retired key 2
  PIV_PUBK_OBJ_RETIRED3,          // Public key for retired key 3
  PIV_PUBK_OBJ_RETIRED4,          // Public key for retired key 4
  PIV_PUBK_OBJ_RETIRED5,          // Public key for retired key 5
  PIV_PUBK_OBJ_RETIRED6,          // Public key for retired key 6
  PIV_PUBK_OBJ_RETIRED7,          // Public key for retired key 7
  PIV_PUBK_OBJ_RETIRED8,          // Public key for retired key 8
  PIV_PUBK_OBJ_RETIRED9,          // Public key for retired key 9
  PIV_PUBK_OBJ_RETIRED10,         // Public key for retired key 10
  PIV_PUBK_OBJ_RETIRED11,         // Public key for retired key 11
  PIV_PUBK_OBJ_RETIRED12,         // Public key for retired key 12
  PIV_PUBK_OBJ_RETIRED13,         // Public key for retired key 13
  PIV_PUBK_OBJ_RETIRED14,         // Public key for retired key 14
  PIV_PUBK_OBJ_RETIRED15,         // Public key for retired key 15
  PIV_PUBK_OBJ_RETIRED16,         // Public key for retired key 16
  PIV_PUBK_OBJ_RETIRED17,         // Public key for retired key 17
  PIV_PUBK_OBJ_RETIRED18,         // Public key for retired key 18
  PIV_PUBK_OBJ_RETIRED19,         // Public key for retired key 19
  PIV_PUBK_OBJ_RETIRED20,         // Public key for retired key 20
  PIV_PUBK_OBJ_LAST

} piv_obj_id_t;

#define OBJECT_INVALID            (PIV_PUBK_OBJ_LAST + 1)

typedef struct {
  const char   *oid;
  CK_BYTE      tag_len;
  CK_BYTE      tag_value[3];   // TODO: needed?
  CK_BYTE      containerid[2]; /* will use as relative paths for simulation */ // TODO: needed?
} piv_data_obj_t;

typedef struct { // TODO: enough to use the public key for the parameters?
  CK_BBOOL decrypt;
  CK_BBOOL sign;
  CK_BBOOL unwrap;
  CK_BBOOL derive;
  CK_BBOOL always_auth;
} piv_pvtk_obj_t;

typedef struct {
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
  CK_RV        (*get_attribute)();
  CK_BYTE      sub_id; // Sub-object id
} piv_obj_t;

#endif
