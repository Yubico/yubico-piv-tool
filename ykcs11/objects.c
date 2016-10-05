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

#include "obj_types.h"
#include "objects.h"
#include <ykpiv.h>
#include <string.h>
#include <stdlib.h>
#include "openssl_utils.h"
#include "utils.h"
#include "debug.h"

#define IS_CERT(x) (((x) >= PIV_CERT_OBJ_X509_PIV_AUTH && (x) <  PIV_CERT_OBJ_LAST) ? CK_TRUE : CK_FALSE)

#define F4 "\x01\x00\x01" // TODO: already define in mechanisms.c. Move
#define PRIME256V1 "\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07" // TODO: already define in mechanisms.c. Move

CK_RV get_doa(CK_OBJECT_HANDLE obj, CK_ATTRIBUTE_PTR template); // TODO: static?
CK_RV get_coa(CK_OBJECT_HANDLE obj, CK_ATTRIBUTE_PTR template);
CK_RV get_proa(CK_OBJECT_HANDLE obj, CK_ATTRIBUTE_PTR template);
CK_RV get_puoa(CK_OBJECT_HANDLE obj, CK_ATTRIBUTE_PTR template);

//TODO: this is mostly a snippet from OpenSC how to give credit?     Less and less so now
/* Must be in order, and one per enumerated PIV_OBJ */
static piv_obj_t piv_objects[] = {
  {PIV_DATA_OBJ_X509_PIV_AUTH, 1, 0, 0, "X.509 Certificate for PIV Authentication", 0, 0, get_doa, 0},
  {PIV_DATA_OBJ_X509_CARD_AUTH, 1, 0, 0, "X.509 Certificate for Card Authentication", 0, 0, get_doa, 1},
  {PIV_DATA_OBJ_X509_DS, 1, 0, 0, "X.509 Certificate for Digital Signature", 0, 0, get_doa, 2},
  {PIV_DATA_OBJ_X509_KM, 1, 0, 0, "X.509 Certificate for Key Management", 0, 0, get_doa, 3},
  {PIV_DATA_OBJ_X509_RETIRED1, 1, 0, 0, "X.509 Certificate for Retired Key 1", 0, 0, get_doa, 4},
  {PIV_DATA_OBJ_X509_RETIRED2, 1, 0, 0, "X.509 Certificate for Retired Key 2", 0, 0, get_doa, 5},
  {PIV_DATA_OBJ_X509_RETIRED3, 1, 0, 0, "X.509 Certificate for Retired Key 3", 0, 0, get_doa, 6},
  {PIV_DATA_OBJ_X509_RETIRED4, 1, 0, 0, "X.509 Certificate for Retired Key 4", 0, 0, get_doa, 7},
  {PIV_DATA_OBJ_X509_RETIRED5, 1, 0, 0, "X.509 Certificate for Retired Key 5", 0, 0, get_doa, 8},
  {PIV_DATA_OBJ_X509_RETIRED6, 1, 0, 0, "X.509 Certificate for Retired Key 6", 0, 0, get_doa, 9},
  {PIV_DATA_OBJ_X509_RETIRED7, 1, 0, 0, "X.509 Certificate for Retired Key 7", 0, 0, get_doa, 10},
  {PIV_DATA_OBJ_X509_RETIRED8, 1, 0, 0, "X.509 Certificate for Retired Key 8", 0, 0, get_doa, 11},
  {PIV_DATA_OBJ_X509_RETIRED9, 1, 0, 0, "X.509 Certificate for Retired Key 9", 0, 0, get_doa, 12},
  {PIV_DATA_OBJ_X509_RETIRED10, 1, 0, 0, "X.509 Certificate for Retired Key 10", 0, 0, get_doa, 13},
  {PIV_DATA_OBJ_X509_RETIRED11, 1, 0, 0, "X.509 Certificate for Retired Key 11", 0, 0, get_doa, 14},
  {PIV_DATA_OBJ_X509_RETIRED12, 1, 0, 0, "X.509 Certificate for Retired Key 12", 0, 0, get_doa, 15},
  {PIV_DATA_OBJ_X509_RETIRED13, 1, 0, 0, "X.509 Certificate for Retired Key 13", 0, 0, get_doa, 16},
  {PIV_DATA_OBJ_X509_RETIRED14, 1, 0, 0, "X.509 Certificate for Retired Key 14", 0, 0, get_doa, 17},
  {PIV_DATA_OBJ_X509_RETIRED15, 1, 0, 0, "X.509 Certificate for Retired Key 15", 0, 0, get_doa, 18},
  {PIV_DATA_OBJ_X509_RETIRED16, 1, 0, 0, "X.509 Certificate for Retired Key 16", 0, 0, get_doa, 19},
  {PIV_DATA_OBJ_X509_RETIRED17, 1, 0, 0, "X.509 Certificate for Retired Key 17", 0, 0, get_doa, 20},
  {PIV_DATA_OBJ_X509_RETIRED18, 1, 0, 0, "X.509 Certificate for Retired Key 18", 0, 0, get_doa, 21},
  {PIV_DATA_OBJ_X509_RETIRED19, 1, 0, 0, "X.509 Certificate for Retired Key 19", 0, 0, get_doa, 22},
  {PIV_DATA_OBJ_X509_RETIRED20, 1, 0, 0, "X.509 Certificate for Retired Key 20", 0, 0, get_doa, 23},
  {PIV_DATA_OBJ_CCC, 1, 0, 0, "Card Capability Container", 0, 0, get_doa, 24},
  {PIV_DATA_OBJ_CHUI, 1, 0, 0, "Card Holder Unique Identifier", 0, 0, get_doa, 25},
  {PIV_DATA_OBJ_CHF, 1, 1, 0, "Card Holder Fingerprints", 0, 0, get_doa, 26},
  {PIV_DATA_OBJ_SEC_OBJ, 1, 0, 0, "Security Object", 0, 0, get_doa, 27},
  {PIV_DATA_OBJ_CHFI, 1, 1, 0, "Cardholder Facial Images", 0, 0, get_doa, 28},
  {PIV_DATA_OBJ_PI, 1, 1, 0, "Printed Information", 0, 0, get_doa, 29},
  {PIV_DATA_OBJ_DISCOVERY, 1, 0, 0, "Discovery Object", 0, 0, get_doa, 30},
  {PIV_DATA_OBJ_HISTORY, 1, 0, 0, "Key History Object", 0, 0, get_doa, 31},
  {PIV_DATA_OBJ_IRIS_IMAGE, 1, 1, 0, "Cardholder Iris Images", 0, 0, get_doa, 32},
  {PIV_DATA_OBJ_BITGT, 1, 0, 0, "Biometric Information Templates Group Template", 0, 0, get_doa, 33},
  {PIV_DATA_OBJ_SM_SIGNER, 1, 0, 0, "Secure Messaging Certificate Signer", 0, 0, get_doa, 34},
  {PIV_DATA_OBJ_PC_REF_DATA, 1, 1, 0, "Pairing Code Reference Data Container", 0, 0, get_doa, 35},
  {PIV_DATA_OBJ_LAST, 1, 0, 0, "", 0, 0, NULL, 36},

  {PIV_CERT_OBJ_X509_PIV_AUTH, 1, 0, 0, "X.509 Certificate for PIV Authentication", 0, 0, get_coa, 0},
  {PIV_CERT_OBJ_X509_CARD_AUTH, 1, 0, 0, "X.509 Certificate for Card Authentication", 0, 0, get_coa, 1},
  {PIV_CERT_OBJ_X509_DS, 1, 0, 0, "X.509 Certificate for Digital Signature", 0, 0, get_coa, 2},
  {PIV_CERT_OBJ_X509_KM, 1, 0, 0, "X.509 Certificate for Key Management", 0, 0, get_coa, 3},
  {PIV_CERT_OBJ_X509_RETIRED1, 1, 0, 0, "X.509 Certificate for Retired Key 1", 0, 0, get_coa, 4},
  {PIV_CERT_OBJ_X509_RETIRED2, 1, 0, 0, "X.509 Certificate for Retired Key 2", 0, 0, get_coa, 5},
  {PIV_CERT_OBJ_X509_RETIRED3, 1, 0, 0, "X.509 Certificate for Retired Key 3", 0, 0, get_coa, 6},
  {PIV_CERT_OBJ_X509_RETIRED4, 1, 0, 0, "X.509 Certificate for Retired Key 4", 0, 0, get_coa, 7},
  {PIV_CERT_OBJ_X509_RETIRED5, 1, 0, 0, "X.509 Certificate for Retired Key 5", 0, 0, get_coa, 8},
  {PIV_CERT_OBJ_X509_RETIRED6, 1, 0, 0, "X.509 Certificate for Retired Key 6", 0, 0, get_coa, 9},
  {PIV_CERT_OBJ_X509_RETIRED7, 1, 0, 0, "X.509 Certificate for Retired Key 7", 0, 0, get_coa, 10},
  {PIV_CERT_OBJ_X509_RETIRED8, 1, 0, 0, "X.509 Certificate for Retired Key 8", 0, 0, get_coa, 11},
  {PIV_CERT_OBJ_X509_RETIRED9, 1, 0, 0, "X.509 Certificate for Retired Key 9", 0, 0, get_coa, 12},
  {PIV_CERT_OBJ_X509_RETIRED10, 1, 0, 0, "X.509 Certificate for Retired Key 10", 0, 0, get_coa, 13},
  {PIV_CERT_OBJ_X509_RETIRED11, 1, 0, 0, "X.509 Certificate for Retired Key 11", 0, 0, get_coa, 14},
  {PIV_CERT_OBJ_X509_RETIRED12, 1, 0, 0, "X.509 Certificate for Retired Key 12", 0, 0, get_coa, 15},
  {PIV_CERT_OBJ_X509_RETIRED13, 1, 0, 0, "X.509 Certificate for Retired Key 13", 0, 0, get_coa, 16},
  {PIV_CERT_OBJ_X509_RETIRED14, 1, 0, 0, "X.509 Certificate for Retired Key 14", 0, 0, get_coa, 17},
  {PIV_CERT_OBJ_X509_RETIRED15, 1, 0, 0, "X.509 Certificate for Retired Key 15", 0, 0, get_coa, 18},
  {PIV_CERT_OBJ_X509_RETIRED16, 1, 0, 0, "X.509 Certificate for Retired Key 16", 0, 0, get_coa, 19},
  {PIV_CERT_OBJ_X509_RETIRED17, 1, 0, 0, "X.509 Certificate for Retired Key 17", 0, 0, get_coa, 20},
  {PIV_CERT_OBJ_X509_RETIRED18, 1, 0, 0, "X.509 Certificate for Retired Key 18", 0, 0, get_coa, 21},
  {PIV_CERT_OBJ_X509_RETIRED19, 1, 0, 0, "X.509 Certificate for Retired Key 19", 0, 0, get_coa, 22},
  {PIV_CERT_OBJ_X509_RETIRED20, 1, 0, 0, "X.509 Certificate for Retired Key 20", 0, 0, get_coa, 23},
  {PIV_CERT_OBJ_LAST, 1, 0, 0, "", 0, 0, NULL, 24},

  {PIV_PVTK_OBJ_PIV_AUTH, 1, 1, 0, "Private key for PIV Authentication", 0, 0, get_proa, 0},   // 9a
  {PIV_PVTK_OBJ_CARD_AUTH, 1, 0, 0, "Private key for Card Authentication", 0, 0, get_proa, 1}, // 9e
  {PIV_PVTK_OBJ_DS, 1, 1, 0, "Private key for Digital Signature", 0, 0, get_proa, 2},          // 9c
  {PIV_PVTK_OBJ_KM, 1, 1, 0, "Private key for Key Management", 0, 0, get_proa, 3},             // 9d
  {PIV_PVTK_OBJ_RETIRED1, 1, 1, 0, "Private key for Retired Key 1", 0, 0, get_proa, 4},
  {PIV_PVTK_OBJ_RETIRED2, 1, 1, 0, "Private key for Retired Key 2", 0, 0, get_proa, 5},
  {PIV_PVTK_OBJ_RETIRED3, 1, 1, 0, "Private key for Retired Key 3", 0, 0, get_proa, 6},
  {PIV_PVTK_OBJ_RETIRED4, 1, 1, 0, "Private key for Retired Key 4", 0, 0, get_proa, 7},
  {PIV_PVTK_OBJ_RETIRED5, 1, 1, 0, "Private key for Retired Key 5", 0, 0, get_proa, 8},
  {PIV_PVTK_OBJ_RETIRED6, 1, 1, 0, "Private key for Retired Key 6", 0, 0, get_proa, 9},
  {PIV_PVTK_OBJ_RETIRED7, 1, 1, 0, "Private key for Retired Key 7", 0, 0, get_proa, 10},
  {PIV_PVTK_OBJ_RETIRED8, 1, 1, 0, "Private key for Retired Key 8", 0, 0, get_proa, 11},
  {PIV_PVTK_OBJ_RETIRED9, 1, 1, 0, "Private key for Retired Key 9", 0, 0, get_proa, 12},
  {PIV_PVTK_OBJ_RETIRED10, 1, 1, 0, "Private key forRretired Key 10", 0, 0, get_proa, 13},
  {PIV_PVTK_OBJ_RETIRED11, 1, 1, 0, "Private key forRretired Key 11", 0, 0, get_proa, 14},
  {PIV_PVTK_OBJ_RETIRED12, 1, 1, 0, "Private key forRretired Key 12", 0, 0, get_proa, 15},
  {PIV_PVTK_OBJ_RETIRED13, 1, 1, 0, "Private key forRretired Key 13", 0, 0, get_proa, 16},
  {PIV_PVTK_OBJ_RETIRED14, 1, 1, 0, "Private key forRretired Key 14", 0, 0, get_proa, 17},
  {PIV_PVTK_OBJ_RETIRED15, 1, 1, 0, "Private key forRretired Key 15", 0, 0, get_proa, 18},
  {PIV_PVTK_OBJ_RETIRED16, 1, 1, 0, "Private key forRretired Key 16", 0, 0, get_proa, 19},
  {PIV_PVTK_OBJ_RETIRED17, 1, 1, 0, "Private key forRretired Key 17", 0, 0, get_proa, 20},
  {PIV_PVTK_OBJ_RETIRED18, 1, 1, 0, "Private key forRretired Key 18", 0, 0, get_proa, 21},
  {PIV_PVTK_OBJ_RETIRED19, 1, 1, 0, "Private key forRretired Key 19", 0, 0, get_proa, 22},
  {PIV_PVTK_OBJ_RETIRED20, 1, 1, 0, "Private key forRretired Key 20", 0, 0, get_proa, 23},
  {PIV_PVTK_OBJ_LAST, 1, 0, 0, "", 0, 0, NULL, 24},

  {PIV_PUBK_OBJ_PIV_AUTH, 1, 0, 0, "Public key for PIV Authentication", 0, 0, get_puoa, 0},
  {PIV_PUBK_OBJ_CARD_AUTH, 1, 0, 0, "Public key for Card Authentication", 0, 0, get_puoa, 1},
  {PIV_PUBK_OBJ_DS, 1, 0, 0, "Public key for Digital Signature", 0, 0, get_puoa, 2},
  {PIV_PUBK_OBJ_KM, 1, 0, 0, "Public key for Key Management", 0, 0, get_puoa, 3},
  {PIV_PUBK_OBJ_RETIRED1, 1, 0, 0, "Public key for Retired Key 1", 0, 0, get_puoa, 4},
  {PIV_PUBK_OBJ_RETIRED2, 1, 0, 0, "Public key for Retired Key 2", 0, 0, get_puoa, 5},
  {PIV_PUBK_OBJ_RETIRED3, 1, 0, 0, "Public key for Retired Key 3", 0, 0, get_puoa, 6},
  {PIV_PUBK_OBJ_RETIRED4, 1, 0, 0, "Public key for Retired Key 4", 0, 0, get_puoa, 7},
  {PIV_PUBK_OBJ_RETIRED5, 1, 0, 0, "Public key for Retired Key 5", 0, 0, get_puoa, 8},
  {PIV_PUBK_OBJ_RETIRED6, 1, 0, 0, "Public key for Retired Key 6", 0, 0, get_puoa, 9},
  {PIV_PUBK_OBJ_RETIRED7, 1, 0, 0, "Public key for Retired Key 7", 0, 0, get_puoa, 10},
  {PIV_PUBK_OBJ_RETIRED8, 1, 0, 0, "Public key for Retired Key 8", 0, 0, get_puoa, 11},
  {PIV_PUBK_OBJ_RETIRED9, 1, 0, 0, "Public key for Retired Key 9", 0, 0, get_puoa, 12},
  {PIV_PUBK_OBJ_RETIRED10, 1, 0, 0, "Public key for Retired Key 10", 0, 0, get_puoa, 13},
  {PIV_PUBK_OBJ_RETIRED11, 1, 0, 0, "Public key for Retired Key 11", 0, 0, get_puoa, 14},
  {PIV_PUBK_OBJ_RETIRED12, 1, 0, 0, "Public key for Retired Key 12", 0, 0, get_puoa, 15},
  {PIV_PUBK_OBJ_RETIRED13, 1, 0, 0, "Public key for Retired Key 13", 0, 0, get_puoa, 16},
  {PIV_PUBK_OBJ_RETIRED14, 1, 0, 0, "Public key for Retired Key 14", 0, 0, get_puoa, 17},
  {PIV_PUBK_OBJ_RETIRED15, 1, 0, 0, "Public key for Retired Key 15", 0, 0, get_puoa, 18},
  {PIV_PUBK_OBJ_RETIRED16, 1, 0, 0, "Public key for Retired Key 16", 0, 0, get_puoa, 19},
  {PIV_PUBK_OBJ_RETIRED17, 1, 0, 0, "Public key for Retired Key 17", 0, 0, get_puoa, 20},
  {PIV_PUBK_OBJ_RETIRED18, 1, 0, 0, "Public key for Retired Key 18", 0, 0, get_puoa, 21},
  {PIV_PUBK_OBJ_RETIRED19, 1, 0, 0, "Public key for Retired Key 19", 0, 0, get_puoa, 22},
  {PIV_PUBK_OBJ_RETIRED20, 1, 0, 0, "Public key for Retired Key 20", 0, 0, get_puoa, 23},
  {PIV_PUBK_OBJ_LAST, 1, 0, 0, "", 0, 0, NULL, 24}
};

static piv_data_obj_t data_objects[] = {
  {"2.16.840.1.101.3.7.2.1.1",   3, "\x5F\xC1\x05", "\x01\x01"}, // PIV Authentication
  {"2.16.840.1.101.3.7.2.5.0",   3, "\x5F\xC1\x01", "\x05\x00"}, // Card Authentication
  {"2.16.840.1.101.3.7.2.1.0",   3, "\x5F\xC1\x0A", "\x01\x00"}, // Digital Signature
  {"2.16.840.1.101.3.7.2.1.2",   3, "\x5F\xC1\x0B", "\x01\x02"}, // Key Management
  {"2.16.840.1.101.3.7.2.16.1",  3, "\x5F\xC1\x0D", "\x10\x01"}, // Retired Key 1
  {"2.16.840.1.101.3.7.2.16.2",  3, "\x5F\xC1\x0E", "\x10\x02"}, // Retired Key 2
  {"2.16.840.1.101.3.7.2.16.3",  3, "\x5F\xC1\x0F", "\x10\x03"}, // Retired Key 3
  {"2.16.840.1.101.3.7.2.16.4",  3, "\x5F\xC1\x10", "\x10\x04"}, // Retired Key 4
  {"2.16.840.1.101.3.7.2.16.5",  3, "\x5F\xC1\x11", "\x10\x05"}, // Retired Key 5
  {"2.16.840.1.101.3.7.2.16.6",  3, "\x5F\xC1\x12", "\x10\x06"}, // Retired Key 6
  {"2.16.840.1.101.3.7.2.16.7",  3, "\x5F\xC1\x13", "\x10\x07"}, // Retired Key 7
  {"2.16.840.1.101.3.7.2.16.8",  3, "\x5F\xC1\x14", "\x10\x08"}, // Retired Key 8
  {"2.16.840.1.101.3.7.2.16.9",  3, "\x5F\xC1\x15", "\x10\x09"}, // Retired Key 9
  {"2.16.840.1.101.3.7.2.16.10", 3, "\x5F\xC1\x16", "\x10\x0A"}, // Retired Key 10
  {"2.16.840.1.101.3.7.2.16.11", 3, "\x5F\xC1\x17", "\x10\x0B"}, // Retired Key 11
  {"2.16.840.1.101.3.7.2.16.12", 3, "\x5F\xC1\x18", "\x10\x0C"}, // Retired Key 12
  {"2.16.840.1.101.3.7.2.16.13", 3, "\x5F\xC1\x19", "\x10\x0D"}, // Retired Key 13
  {"2.16.840.1.101.3.7.2.16.14", 3, "\x5F\xC1\x1A", "\x10\x0E"}, // Retired Key 14
  {"2.16.840.1.101.3.7.2.16.15", 3, "\x5F\xC1\x1B", "\x10\x0F"}, // Retired Key 15
  {"2.16.840.1.101.3.7.2.16.16", 3, "\x5F\xC1\x1C", "\x10\x10"}, // Retired Key 16
  {"2.16.840.1.101.3.7.2.16.17", 3, "\x5F\xC1\x1D", "\x10\x11"}, // Retired Key 17
  {"2.16.840.1.101.3.7.2.16.18", 3, "\x5F\xC1\x1E", "\x10\x12"}, // Retired Key 18
  {"2.16.840.1.101.3.7.2.16.19", 3, "\x5F\xC1\x1F", "\x10\x13"}, // Retired Key 19
  {"2.16.840.1.101.3.7.2.16.20", 3, "\x5F\xC1\x20", "\x10\x14"}, // Retired Key 20
  {"2.16.840.1.101.3.7.1.219.0", 3, "\x5F\xC1\x07", "\xDB\x00"}, // CCC
  {"2.16.840.1.101.3.7.2.48.0",  3, "\x5F\xC1\x02", "\x30\x00"}, // CHUID
  {"2.16.840.1.101.3.7.2.96.16", 3, "\x5F\xC1\x03", "\x60\x10"}, // CHFP
  {"2.16.840.1.101.3.7.2.144.0", 3, "\x5F\xC1\x06", "\x90\x00"}, // Security Object
  {"2.16.840.1.101.3.7.2.96.48", 3, "\x5F\xC1\x08", "\x60\x30"}, // CHFI
  {"2.16.840.1.101.3.7.2.48.1",  3, "\x5F\xC1\x09", "\x30\x01"}, // Printed Information
  {"2.16.840.1.101.3.7.2.96.80", 1, "\x7E",         "\x60\x50"}, // Discovery Object
  {"2.16.840.1.101.3.7.2.96.96", 3, "\x5F\xC1\x0C", "\x60\x60"}, // Key History Object
  {"2.16.840.1.101.3.7.2.16.21", 3, "\x5F\xC1\x21", "\x10\x15"}, // CHII
  {"2.16.840.1.101.3.7.2.16.22", 2, "\x7F\x61",     "\x10\x16"}, // Biometric Information
  {"2.16.840.1.101.3.7.2.16.23", 3, "\x5F\xC1\x22", "\x10\x17"}, // Secure Messaging Certificate Signer
  {"2.16.840.1.101.3.7.2.16.24", 3, "\x5F\xC1\x23", "\x10\x18"}, // Pairing Code Reference Data Container
  {"", 0, "", ""}
};

static piv_cert_obj_t cert_objects[] = {
  {NULL},
  {NULL},
  {NULL},
  {NULL},
  {NULL},
  {NULL},
  {NULL},
  {NULL},
  {NULL},
  {NULL},
  {NULL},
  {NULL},
  {NULL},
  {NULL},
  {NULL},
  {NULL},
  {NULL},
  {NULL},
  {NULL},
  {NULL},
  {NULL},
  {NULL},
  {NULL},
  {NULL},
  {NULL}
};

static piv_pvtk_obj_t pvtkey_objects[] = {
  {1, 1, 0, 0, 0},
  {1, 1, 0, 0, 0},
  {1, 1, 0, 0, 0},
  {1, 1, 0, 0, 1},
  {1, 1, 0, 0, 0},
  {1, 1, 0, 0, 0},
  {1, 1, 0, 0, 0},
  {1, 1, 0, 0, 0},
  {1, 1, 0, 0, 0},
  {1, 1, 0, 0, 0},
  {1, 1, 0, 0, 0},
  {1, 1, 0, 0, 0},
  {1, 1, 0, 0, 0},
  {1, 1, 0, 0, 0},
  {1, 1, 0, 0, 0},
  {1, 1, 0, 0, 0},
  {1, 1, 0, 0, 0},
  {1, 1, 0, 0, 0},
  {1, 1, 0, 0, 0},
  {1, 1, 0, 0, 0},
  {1, 1, 0, 0, 0},
  {1, 1, 0, 0, 0},
  {1, 1, 0, 0, 0},
  {1, 1, 0, 0, 0},
  {1, 1, 0, 0, 0}
};

static piv_pubk_obj_t pubkey_objects[] = {
  {NULL, 1, 1, 0, 0},
  {NULL, 1, 1, 0, 0},
  {NULL, 1, 1, 0, 0},
  {NULL, 1, 1, 0, 0},
  {NULL, 1, 1, 0, 0},
  {NULL, 1, 1, 0, 0},
  {NULL, 1, 1, 0, 0},
  {NULL, 1, 1, 0, 0},
  {NULL, 1, 1, 0, 0},
  {NULL, 1, 1, 0, 0},
  {NULL, 1, 1, 0, 0},
  {NULL, 1, 1, 0, 0},
  {NULL, 1, 1, 0, 0},
  {NULL, 1, 1, 0, 0},
  {NULL, 1, 1, 0, 0},
  {NULL, 1, 1, 0, 0},
  {NULL, 1, 1, 0, 0},
  {NULL, 1, 1, 0, 0},
  {NULL, 1, 1, 0, 0},
  {NULL, 1, 1, 0, 0},
  {NULL, 1, 1, 0, 0},
  {NULL, 1, 1, 0, 0},
  {NULL, 1, 1, 0, 0},
  {NULL, 1, 1, 0, 0},
  {NULL, 1, 1, 0, 0}
};

// Next two functions based off the code at
// https://github.com/m9aertner/oidConverter/blob/master/oid.c
// TODO: how to give credit? OR JUST STORE THE OID ALREADY ENCODED?
static void make_base128(unsigned long l, int first, CK_BYTE_PTR buf, CK_ULONG_PTR n) {
  if (l > 127)
    make_base128(l / 128, 0, buf, n);

  l %= 128;

  if (first)
    buf[(*n)++] = (CK_BYTE)l;
  else
    buf[(*n)++] = 0x80 | (CK_BYTE)l;
}

static void asn1_encode_oid(CK_CHAR_PTR oid, CK_BYTE_PTR asn1_oid, CK_ULONG_PTR len) {
  CK_CHAR_PTR tmp = (CK_BYTE_PTR) strdup((char *)oid);
  CK_CHAR_PTR p = tmp;
  CK_BYTE_PTR q = NULL;
  CK_ULONG    n = 0;
  CK_BYTE     b = 0;
  CK_ULONG    l = 0;
  CK_ULONG    nodes;

  q = p;
  *len = 0;
  nodes = 1;
  while (*p != 0) {
    if (*p == '.')
      nodes++;
    p++;
  }

  n = 0;
  b = 0;
  p = q;
  while (n < nodes) {
    q = p;
    while (*p != 0) {
      if (*p == '.')
        break;
      p++;
    }

    if (*p == '.') {
      *p = 0;
      l = (CK_ULONG) atoi((char *)q);
      q = p + 1;
      p = q;
    }
    else {
      l = (CK_ULONG) atoi((char *)q);
      //      q = p;
    }

    /* Digit is in l. */
    if (n == 0)
      b = 40 * ((CK_BYTE)l);
    else if (n == 1) {
      b += (CK_BYTE) l;
      asn1_oid[(*len)++] = b;
    }
    else {
      make_base128(l, 1, asn1_oid, len);
    }
    n++;
  }

  free(tmp);
}

static CK_KEY_TYPE get_key_type(EVP_PKEY *key) {
  return do_get_key_type(key);
}

static CK_ULONG get_modulus_bits(EVP_PKEY *key) {
  return do_get_rsa_modulus_length(key);
}

static CK_RV get_public_exponent(EVP_PKEY *key, CK_BYTE_PTR data, CK_ULONG_PTR len) {
  return do_get_public_exponent(key, data, len);
}

static CK_RV get_modulus(EVP_PKEY *key, CK_BYTE_PTR data, CK_ULONG_PTR len) {
  return do_get_modulus(key, data, len);
}

static CK_RV get_public_key(EVP_PKEY *key, CK_BYTE_PTR data, CK_ULONG_PTR len) {
  return do_get_public_key(key, data, len);
}

static CK_RV get_curve_parameters(EVP_PKEY *key, CK_BYTE_PTR data, CK_ULONG_PTR len) {
  return do_get_curve_parameters(key, data, len);
}

static CK_RV get_raw_cert(X509 *cert, CK_BYTE_PTR data, CK_ULONG_PTR len) {
  return do_get_raw_cert(cert, data, len);
}

/* Get data object attribute */
CK_RV get_doa(CK_OBJECT_HANDLE obj, CK_ATTRIBUTE_PTR template) {
  CK_BYTE_PTR data;
  CK_BYTE     tmp[64];
  CK_ULONG    len = 0;
  DBG("For data object %lu, get ", obj);

  switch (template->type) {
  case CKA_CLASS:
    DBG("CLASS");
    len = 1;
    tmp[0] = CKO_DATA;
    data = tmp;
    break;

  case CKA_TOKEN:
    // Technically all these objects are token objects
    DBG("TOKEN");
    len = 1;
    tmp[0] = piv_objects[obj].token;
    data = tmp;
    break;

  case CKA_PRIVATE:
    DBG("PRIVATE");
    len = 1;
    tmp[0] = piv_objects[obj].private;
    data = tmp;
    break;

  case CKA_LABEL:
    DBG("LABEL");
    len = strlen(piv_objects[obj].label) + 1;
    data = (CK_BYTE_PTR) piv_objects[obj].label;
    break;

  case CKA_APPLICATION:
    DBG("APPLICATION");
    len = strlen(piv_objects[obj].label) + 1;
    data = (CK_BYTE_PTR) piv_objects[obj].label;
    break;

  case CKA_VALUE: // TODO: this can be done with -r and -d|-a
    DBG("VALUE TODO!!!");
    return CKR_FUNCTION_FAILED;

  case CKA_OBJECT_ID: // TODO: how about just storing the OID in DER ?
    DBG("OID");
    memcpy((char *)tmp, data_objects[piv_objects[obj].sub_id].oid, sizeof(tmp));
    asn1_encode_oid(tmp, tmp, &len);
    data = tmp;
    break;

  case CKA_MODIFIABLE:
    DBG("MODIFIABLE");
    len = 1;
    tmp[0] = piv_objects[obj].modifiable;
    data = tmp;
    break;

  default:
    DBG("UNKNOWN ATTRIBUTE %lx", template[0].type);
    template->ulValueLen = CK_UNAVAILABLE_INFORMATION;
    return CKR_ATTRIBUTE_TYPE_INVALID;
  }

  /* Just get the length */
  if (template->pValue == NULL_PTR) {
    template->ulValueLen = len;
    return CKR_OK;
  }

  /* Actually get the attribute */
  if (template->ulValueLen < len)
    return CKR_BUFFER_TOO_SMALL;

  template->ulValueLen = len;
  memcpy(template->pValue, data, len);

  return CKR_OK;

}

/* Get certificate object attribute */
CK_RV get_coa(CK_OBJECT_HANDLE obj, CK_ATTRIBUTE_PTR template) {
  CK_BYTE_PTR data;
  CK_BYTE     b_tmp[1024];
  CK_ULONG    ul_tmp;
  CK_ULONG    len = 0;
  DBG("For certificate object %lu, get ", obj);

  switch (template->type) {
  case CKA_CLASS:
    DBG("CLASS");
    len = sizeof(CK_ULONG);
    ul_tmp = CKO_CERTIFICATE;
    data = (CK_BYTE_PTR) &ul_tmp;
    break;

  case CKA_TOKEN:
    // Technically all these objects are token objects
    DBG("TOKEN");
    len = sizeof(CK_BBOOL);
    b_tmp[0] = piv_objects[obj].token;
    data = b_tmp;
    break;

  case CKA_PRIVATE:
    DBG("PRIVATE");
    len = sizeof(CK_BBOOL);
    b_tmp[0] = piv_objects[obj].private;
    data = b_tmp;
    break;

  case CKA_LABEL:
    DBG("LABEL");
    len = strlen(piv_objects[obj].label) + 1;
    data = (CK_BYTE_PTR) piv_objects[obj].label;
    break;

  case CKA_VALUE:
    DBG("VALUE");
    len = sizeof(b_tmp);
    if (get_raw_cert(cert_objects[piv_objects[obj].sub_id].data, b_tmp, &len) != CKR_OK)
      return CKR_FUNCTION_FAILED;
    data = b_tmp;
    break;

  case CKA_CERTIFICATE_TYPE:
    DBG("CERTIFICATE TYPE");
    len = sizeof(CK_ULONG);
    ul_tmp = CKC_X_509; // Support only X.509 certs
    data = (CK_BYTE_PTR) &ul_tmp;
    break;

  case CKA_ISSUER:
    DBG("ISSUER TODO"); // Default empty
    return CKR_ATTRIBUTE_TYPE_INVALID;

  case CKA_SERIAL_NUMBER:
    DBG("SERIAL NUMBER TODO"); // Default empty
    return CKR_ATTRIBUTE_TYPE_INVALID;

  case CKA_SUBJECT:
    DBG("SUBJECT TODO"); // Required
    return CKR_ATTRIBUTE_TYPE_INVALID;

  case CKA_ID:
    DBG("ID");
    len = sizeof(CK_BYTE);
    b_tmp[0] = piv_objects[obj].sub_id;
    data = b_tmp;
    break;

  case CKA_START_DATE:
    DBG("START DATE TODO"); // Default empty
    return CKR_ATTRIBUTE_TYPE_INVALID;

  case CKA_END_DATE:
    DBG("END DATE TODO"); // Default empty
    return CKR_ATTRIBUTE_TYPE_INVALID;

  case CKA_MODIFIABLE:
    DBG("MODIFIABLE");
    len = sizeof(CK_BBOOL);
    b_tmp[0] = piv_objects[obj].modifiable;
    data = b_tmp;
    break;

  default: // TODO: there are other attributes for a (x509) certificate
    DBG("UNKNOWN ATTRIBUTE %lx", template[0].type);
    template->ulValueLen = CK_UNAVAILABLE_INFORMATION;
    return CKR_ATTRIBUTE_TYPE_INVALID;
  }

  /* Just get the length */
  if (template->pValue == NULL_PTR) {
    template->ulValueLen = len;
    return CKR_OK;
  }

  /* Actually get the attribute */
  if (template->ulValueLen < len)
    return CKR_BUFFER_TOO_SMALL;

  template->ulValueLen = len;
  memcpy(template->pValue, data, len);

  return CKR_OK;

}

/* Get private key object attribute */
CK_RV get_proa(CK_OBJECT_HANDLE obj, CK_ATTRIBUTE_PTR template) {
  CK_BYTE_PTR data;
  CK_BYTE     b_tmp[1024];
  CK_ULONG    ul_tmp; // TODO: fix elsewhere too
  CK_ULONG    len = 0;
  DBG("For private key object %lu, get ", obj);

  switch (template->type) {
  case CKA_CLASS:
    DBG("CLASS");
    len = sizeof(CK_ULONG);
    ul_tmp = CKO_PRIVATE_KEY;
    data = (CK_BYTE_PTR) &ul_tmp;
    break;

  case CKA_TOKEN:
    // Technically all these objects are token objects
    DBG("TOKEN");
    len = sizeof(CK_BBOOL);
    b_tmp[0] = piv_objects[obj].token;
    data = b_tmp;
    break;

  case CKA_PRIVATE:
    DBG("PRIVATE");
    len = sizeof(CK_BBOOL);
    b_tmp[0] = piv_objects[obj].private;
    data = b_tmp;
    break;

  case CKA_LABEL:
    DBG("LABEL");
    len = strlen(piv_objects[obj].label) + 1;
    data = (CK_BYTE_PTR) piv_objects[obj].label;
    break;

  case CKA_KEY_TYPE:
    DBG("KEY TYPE");
    len = sizeof(CK_ULONG);
    ul_tmp = get_key_type(pubkey_objects[piv_objects[obj].sub_id].data); // Getting the info from the pubk
    if (ul_tmp == CKK_VENDOR_DEFINED)
      return CKR_FUNCTION_FAILED;
    data = (CK_BYTE_PTR) &ul_tmp;
    break;

  case CKA_SUBJECT:
    DBG("SUBJECT TODO"); // Default empty
    return CKR_ATTRIBUTE_TYPE_INVALID;

  case CKA_ID:
    DBG("ID");
    len = sizeof(CK_BYTE);
    ul_tmp = piv_objects[obj].sub_id;
    data = (CK_BYTE_PTR) &ul_tmp;
    break;

  case CKA_SENSITIVE:
    DBG("SENSITIVE TODO"); // Default empty
    return CKR_ATTRIBUTE_TYPE_INVALID;

  case CKA_DECRYPT:
    DBG("DECRYPT"); // Default empy
    len = sizeof(CK_BBOOL);
    b_tmp[0] = pvtkey_objects[piv_objects[obj].sub_id].decrypt;
    data = b_tmp;
    break;

  case CKA_UNWRAP:
    DBG("UNWRAP"); // Default empty
    len = sizeof(CK_BBOOL);
    b_tmp[0] = pvtkey_objects[piv_objects[obj].sub_id].unwrap;
    data = b_tmp;
    break;

  case CKA_SIGN:
    DBG("SIGN"); // Default empty
    len = sizeof(CK_BBOOL);
    b_tmp[0] = pvtkey_objects[piv_objects[obj].sub_id].sign;
    data = b_tmp;
    break;

  case CKA_SIGN_RECOVER:
    DBG("SIGN RECOVER TODO"); // Default empty
    return CKR_ATTRIBUTE_TYPE_INVALID;

  case CKA_DERIVE:
    DBG("DERIVE"); // Default false
    len = sizeof(CK_BBOOL);
    b_tmp[0] = pvtkey_objects[piv_objects[obj].sub_id].derive;
    data = b_tmp;
    break;

  case CKA_START_DATE:
    DBG("START DATE TODO"); // Default empty
    return CKR_ATTRIBUTE_TYPE_INVALID;

  case CKA_END_DATE:
    DBG("END DATE TODO"); // Default empty
    return CKR_ATTRIBUTE_TYPE_INVALID;

  case CKA_MODULUS:
    DBG("MODULUS");
    len = sizeof(b_tmp);

    // Make sure that this is an RSA key
    ul_tmp = get_key_type(pubkey_objects[piv_objects[obj].sub_id].data); // Getting the info from the pubk
    if (ul_tmp == CKK_VENDOR_DEFINED)
      return CKR_FUNCTION_FAILED;
    if (ul_tmp != CKK_RSA)
      return CKR_ATTRIBUTE_VALUE_INVALID;

    if (get_modulus(pubkey_objects[piv_objects[obj].sub_id].data, b_tmp, &len) != CKR_OK)
      return CKR_FUNCTION_FAILED;
    data = b_tmp;
    break;

  case CKA_EC_POINT:
    DBG("EC_POINT");
    len = sizeof(b_tmp);

    // Make sure that this is an EC key
    ul_tmp = get_key_type(pubkey_objects[piv_objects[obj].sub_id].data); // Getting the info from the pubk
    if (ul_tmp == CKK_VENDOR_DEFINED)
      return CKR_FUNCTION_FAILED;
    if (ul_tmp != CKK_ECDSA)
      return CKR_ATTRIBUTE_VALUE_INVALID;

    if (get_public_key(pubkey_objects[piv_objects[obj].sub_id].data, b_tmp, &len) != CKR_OK)
      return CKR_FUNCTION_FAILED;
    data = b_tmp;
    break;

    case CKA_EC_PARAMS:
    // Here we want the curve parameters (DER encoded OID)
    DBG("EC_PARAMS");
    len = sizeof(b_tmp);

    // Make sure that this is an EC key
    ul_tmp = get_key_type(pubkey_objects[piv_objects[obj].sub_id].data); // Getting the info from the pubk
    if (ul_tmp == CKK_VENDOR_DEFINED)
      return CKR_FUNCTION_FAILED;
    if (ul_tmp != CKK_ECDSA)
      return CKR_ATTRIBUTE_VALUE_INVALID;

    if (get_curve_parameters(pubkey_objects[piv_objects[obj].sub_id].data, b_tmp, &len) != CKR_OK)
      return CKR_FUNCTION_FAILED;

    data = b_tmp;
    break;

  case CKA_MODULUS_BITS:
    DBG("MODULUS BITS");
    len = sizeof(CK_ULONG);

    // Make sure that this is an RSA key
    ul_tmp = get_key_type(pubkey_objects[piv_objects[obj].sub_id].data); // Getting the info from the pubk
    if (ul_tmp == CKK_VENDOR_DEFINED)
      return CKR_FUNCTION_FAILED;
    if (ul_tmp != CKK_RSA)
      return CKR_ATTRIBUTE_VALUE_INVALID;

    ul_tmp = get_modulus_bits(pubkey_objects[piv_objects[obj].sub_id].data); // Getting the info from the pubk
    if (ul_tmp == 0)
      return CKR_FUNCTION_FAILED;
    data = (CK_BYTE_PTR) &ul_tmp;
    break;

  case CKA_PUBLIC_EXPONENT:
    DBG("PUBLIC EXPONENT");
    len = sizeof(CK_ULONG);

    // Make sure that this is an RSA key
    ul_tmp = get_key_type(pubkey_objects[piv_objects[obj].sub_id].data); // Getting the info from the pubk
    if (ul_tmp == CKK_VENDOR_DEFINED)
      return CKR_FUNCTION_FAILED;
    if (ul_tmp != CKK_RSA)
      return CKR_ATTRIBUTE_VALUE_INVALID;

    if (get_public_exponent(pubkey_objects[piv_objects[obj].sub_id].data, b_tmp, &len) != CKR_OK)
      return CKR_FUNCTION_FAILED;
    data = b_tmp;
    break;

  /* case CKA_PRIVATE_EXPONENT: */
  /* case CKA_PRIME_1: */
  /* case CKA_PRIME_2: */
  /* case CKA_EXPONENT_1: */
  /* case CKA_EXPONENT_2: */
  /* case CKA_COEFFICIENT: */
  /* case CKA_PRIME: */
  /* case CKA_SUBPRIME: */
  /* case CKA_BASE: */
  /* case CKA_VALUE_BITS: */
  /* case CKA_VALUE_LEN: */
  /* case CKA_EXTRACTABLE: */
  case CKA_LOCAL:
    DBG("LOCAL TODO"); // Required
    return CKR_ATTRIBUTE_TYPE_INVALID;

  /* case CKA_NEVER_EXTRACTABLE: */
  /*case CKA_ALWAYS_SENSITIVE:*/

  case CKA_ALWAYS_AUTHENTICATE:
    DBG("ALWAYS AUTHENTICATE");
    len = sizeof(CK_BBOOL);
    b_tmp[0] = pvtkey_objects[piv_objects[obj].sub_id].always_auth;
    data = b_tmp;
    break;

  case CKA_MODIFIABLE:
    DBG("MODIFIABLE");
    len = sizeof(CK_BBOOL);
    b_tmp[0] = piv_objects[obj].modifiable;
    data = b_tmp;
    break;

    /*case CKA_VENDOR_DEFINED:*/
  default:
    DBG("UNKNOWN ATTRIBUTE %lx", template[0].type); // TODO: there are other parameters for public keys, plus there is more if the key is RSA
    template->ulValueLen = CK_UNAVAILABLE_INFORMATION;
    return CKR_ATTRIBUTE_TYPE_INVALID;
  }

  /* Just get the length */
  if (template->pValue == NULL_PTR) {
    template->ulValueLen = len;
    return CKR_OK;
  }

  /* Actually get the attribute */
  if (template->ulValueLen < len)
    return CKR_BUFFER_TOO_SMALL;

  template->ulValueLen = len;
  memcpy(template->pValue, data, len);

  return CKR_OK;

}

/* Get public key object attribute */
CK_RV get_puoa(CK_OBJECT_HANDLE obj, CK_ATTRIBUTE_PTR template) {
  CK_BYTE_PTR data;
  CK_BYTE     b_tmp[1024];
  CK_ULONG    ul_tmp;
  CK_ULONG    len = 0;
  DBG("For public key object %lu, get ", obj);

  switch (template->type) {
  case CKA_CLASS:
    DBG("CLASS");
    len = sizeof(CK_ULONG);
    ul_tmp = CKO_PUBLIC_KEY;
    data = (CK_BYTE_PTR) &ul_tmp;
    break;

  case CKA_TOKEN:
    // Technically all these objects are token objects
    DBG("TOKEN");
    len = sizeof(CK_BBOOL);
    b_tmp[0] = piv_objects[obj].token;
    data = b_tmp;
    break;

  case CKA_PRIVATE:
    DBG("PRIVATE");
    len = sizeof(CK_BBOOL);
    b_tmp[0] = piv_objects[obj].private;
    data = b_tmp;
    break;

  case CKA_LABEL:
    DBG("LABEL");
    len = strlen(piv_objects[obj].label) + 1;
    data = (CK_BYTE_PTR) piv_objects[obj].label;
    break;

  case CKA_KEY_TYPE:
    DBG("KEY TYPE");
    len = sizeof(CK_ULONG);
    ul_tmp = get_key_type(pubkey_objects[piv_objects[obj].sub_id].data);
    if (ul_tmp == CKK_VENDOR_DEFINED) // This value is used as an error here
      return CKR_FUNCTION_FAILED;
    data = (CK_BYTE_PTR) &ul_tmp;
    break;

  case CKA_SUBJECT:
    DBG("SUBJECT TODO"); // Default empty
    return CKR_ATTRIBUTE_TYPE_INVALID;

  case CKA_ID:
    DBG("ID");
    len = sizeof(CK_BYTE);
    b_tmp[0] = piv_objects[obj].sub_id;
    data = b_tmp;
    break;

  case CKA_ENCRYPT:
    DBG("ENCRYPT");
    len = sizeof(CK_BBOOL);
    b_tmp[0] = pubkey_objects[piv_objects[obj].sub_id].encrypt;
    data = b_tmp;
    break;

  case CKA_VERIFY: // TODO: what about verify recover ?
    DBG("VERIFY");
    len = sizeof(CK_BBOOL);
    b_tmp[0] = pubkey_objects[piv_objects[obj].sub_id].verify;
    data = b_tmp;
    break;

  case CKA_WRAP:
    DBG("WRAP");
    len = sizeof(CK_BBOOL);
    b_tmp[0] = pubkey_objects[piv_objects[obj].sub_id].wrap;
    data = b_tmp;
    break;

  case CKA_DERIVE:
    DBG("DERIVE");
    len = sizeof(CK_BBOOL);
    b_tmp[0] = pubkey_objects[piv_objects[obj].sub_id].derive;
    data = b_tmp;
    break;

  case CKA_START_DATE:
    DBG("START DATE TODO"); // Default empty
    return CKR_ATTRIBUTE_TYPE_INVALID;

  case CKA_END_DATE:
    DBG("END DATE TODO"); // Default empty
    return CKR_ATTRIBUTE_TYPE_INVALID;

  case CKA_EC_POINT:
    DBG("EC_POINT");
    len = sizeof(b_tmp);

    // Make sure that this is an EC key
    ul_tmp = get_key_type(pubkey_objects[piv_objects[obj].sub_id].data); // Getting the info from the pubk
    if (ul_tmp == CKK_VENDOR_DEFINED)
      return CKR_FUNCTION_FAILED;
    if (ul_tmp != CKK_ECDSA)
      return CKR_ATTRIBUTE_VALUE_INVALID;

    if (get_public_key(pubkey_objects[piv_objects[obj].sub_id].data, b_tmp, &len) != CKR_OK)
      return CKR_FUNCTION_FAILED;
    data = b_tmp;
    break;

  case CKA_EC_PARAMS:
    // Here we want the curve parameters (DER encoded OID)
    DBG("EC_PARAMS");
    len = sizeof(b_tmp);

    // Make sure that this is an EC key
    ul_tmp = get_key_type(pubkey_objects[piv_objects[obj].sub_id].data); // Getting the info from the pubk
    if (ul_tmp == CKK_VENDOR_DEFINED)
      return CKR_FUNCTION_FAILED;
    if (ul_tmp != CKK_ECDSA)
      return CKR_ATTRIBUTE_VALUE_INVALID;

    if (get_curve_parameters(pubkey_objects[piv_objects[obj].sub_id].data, b_tmp, &len) != CKR_OK)
      return CKR_FUNCTION_FAILED;

    data = b_tmp;
    break;

  case CKA_MODULUS:
    DBG("MODULUS");
    len = sizeof(b_tmp);

    // Make sure that this is an RSA key
    ul_tmp = get_key_type(pubkey_objects[piv_objects[obj].sub_id].data); // Getting the info from the pubk
    if (ul_tmp == CKK_VENDOR_DEFINED)
      return CKR_FUNCTION_FAILED;
    if (ul_tmp != CKK_RSA)
      return CKR_ATTRIBUTE_VALUE_INVALID;

    if (get_modulus(pubkey_objects[piv_objects[obj].sub_id].data, b_tmp, &len) != CKR_OK)
      return CKR_FUNCTION_FAILED;
    data = b_tmp;
    break;

  case CKA_MODULUS_BITS:
    DBG("MODULUS BITS");
    len = sizeof(CK_ULONG);

    // Make sure that this is an RSA key
    ul_tmp = get_key_type(pubkey_objects[piv_objects[obj].sub_id].data); // Getting the info from the pubk
    if (ul_tmp == CKK_VENDOR_DEFINED)
      return CKR_FUNCTION_FAILED;
    if (ul_tmp != CKK_RSA)
      return CKR_ATTRIBUTE_VALUE_INVALID;

    ul_tmp = get_modulus_bits(pubkey_objects[piv_objects[obj].sub_id].data); // Getting the info from the pubk
    if (ul_tmp == 0)
      return CKR_FUNCTION_FAILED;
    data = (CK_BYTE_PTR) &ul_tmp;
    break;

  case CKA_PUBLIC_EXPONENT:
    DBG("PUBLIC EXPONENT");
    len = sizeof(CK_ULONG);

    // Make sure that this is an RSA key
    ul_tmp = get_key_type(pubkey_objects[piv_objects[obj].sub_id].data); // Getting the info from the pubk
    if (ul_tmp == CKK_VENDOR_DEFINED)
      return CKR_FUNCTION_FAILED;
    if (ul_tmp != CKK_RSA)
      return CKR_ATTRIBUTE_VALUE_INVALID;

    if (get_public_exponent(pubkey_objects[piv_objects[obj].sub_id].data, b_tmp, &len) != CKR_OK)
      return CKR_FUNCTION_FAILED;
    data = b_tmp;
    break;

  case CKA_LOCAL:
    DBG("LOCAL TODO"); // Required
    return CKR_ATTRIBUTE_TYPE_INVALID;

  case CKA_MODIFIABLE:
    DBG("MODIFIABLE");
    len = sizeof(CK_BBOOL);
    b_tmp[0] = piv_objects[obj].modifiable;
    data = b_tmp;
    break;

  default:
    DBG("UNKNOWN ATTRIBUTE %lx", template[0].type); // TODO: there are other parameters for public keys
    template->ulValueLen = CK_UNAVAILABLE_INFORMATION;
    return CKR_ATTRIBUTE_TYPE_INVALID;
  }

  /* Just get the length */
  if (template->pValue == NULL_PTR) {
    template->ulValueLen = len;
    return CKR_OK;
  }

  /* Actually get the attribute */
  if (template->ulValueLen < len)
    return CKR_BUFFER_TOO_SMALL;

  template->ulValueLen = len;
  memcpy(template->pValue, data, len);

  return CKR_OK;

}

CK_ULONG piv_2_ykpiv(piv_obj_id_t id) {
  switch(id) {
  case PIV_CERT_OBJ_X509_PIV_AUTH:
    return YKPIV_OBJ_AUTHENTICATION;

  case PIV_CERT_OBJ_X509_CARD_AUTH:
    return YKPIV_OBJ_CARD_AUTH;

  case PIV_CERT_OBJ_X509_DS:
    return YKPIV_OBJ_SIGNATURE;

  case PIV_CERT_OBJ_X509_KM:
    return YKPIV_OBJ_KEY_MANAGEMENT;

  case PIV_CERT_OBJ_X509_RETIRED1:
    return YKPIV_OBJ_RETIRED1;

  case PIV_CERT_OBJ_X509_RETIRED2:
    return YKPIV_OBJ_RETIRED2;

  case PIV_CERT_OBJ_X509_RETIRED3:
    return YKPIV_OBJ_RETIRED3;

  case PIV_CERT_OBJ_X509_RETIRED4:
    return YKPIV_OBJ_RETIRED4;

  case PIV_CERT_OBJ_X509_RETIRED5:
    return YKPIV_OBJ_RETIRED5;

  case PIV_CERT_OBJ_X509_RETIRED6:
    return YKPIV_OBJ_RETIRED6;

  case PIV_CERT_OBJ_X509_RETIRED7:
    return YKPIV_OBJ_RETIRED7;

  case PIV_CERT_OBJ_X509_RETIRED8:
    return YKPIV_OBJ_RETIRED8;

  case PIV_CERT_OBJ_X509_RETIRED9:
    return YKPIV_OBJ_RETIRED9;

  case PIV_CERT_OBJ_X509_RETIRED10:
    return YKPIV_OBJ_RETIRED10;

  case PIV_CERT_OBJ_X509_RETIRED11:
    return YKPIV_OBJ_RETIRED11;

  case PIV_CERT_OBJ_X509_RETIRED12:
    return YKPIV_OBJ_RETIRED12;

  case PIV_CERT_OBJ_X509_RETIRED13:
    return YKPIV_OBJ_RETIRED13;

  case PIV_CERT_OBJ_X509_RETIRED14:
    return YKPIV_OBJ_RETIRED14;

  case PIV_CERT_OBJ_X509_RETIRED15:
    return YKPIV_OBJ_RETIRED15;

  case PIV_CERT_OBJ_X509_RETIRED16:
    return YKPIV_OBJ_RETIRED16;

  case PIV_CERT_OBJ_X509_RETIRED17:
    return YKPIV_OBJ_RETIRED17;

  case PIV_CERT_OBJ_X509_RETIRED18:
    return YKPIV_OBJ_RETIRED18;

  case PIV_CERT_OBJ_X509_RETIRED19:
    return YKPIV_OBJ_RETIRED19;

  case PIV_CERT_OBJ_X509_RETIRED20:
    return YKPIV_OBJ_RETIRED20;

  case PIV_PVTK_OBJ_PIV_AUTH:
    return YKPIV_KEY_AUTHENTICATION;

  case PIV_PVTK_OBJ_CARD_AUTH:
    return YKPIV_KEY_CARDAUTH;

  case PIV_PVTK_OBJ_DS:
    return YKPIV_KEY_SIGNATURE;

  case PIV_PVTK_OBJ_KM:
    return YKPIV_KEY_KEYMGM;

  case PIV_PVTK_OBJ_RETIRED1:
    return YKPIV_KEY_RETIRED1;

  case PIV_PVTK_OBJ_RETIRED2:
    return YKPIV_KEY_RETIRED2;

  case PIV_PVTK_OBJ_RETIRED3:
    return YKPIV_KEY_RETIRED3;

  case PIV_PVTK_OBJ_RETIRED4:
    return YKPIV_KEY_RETIRED4;

  case PIV_PVTK_OBJ_RETIRED5:
    return YKPIV_KEY_RETIRED5;

  case PIV_PVTK_OBJ_RETIRED6:
    return YKPIV_KEY_RETIRED6;

  case PIV_PVTK_OBJ_RETIRED7:
    return YKPIV_KEY_RETIRED7;

  case PIV_PVTK_OBJ_RETIRED8:
    return YKPIV_KEY_RETIRED8;

  case PIV_PVTK_OBJ_RETIRED9:
    return YKPIV_KEY_RETIRED9;

  case PIV_PVTK_OBJ_RETIRED10:
    return YKPIV_KEY_RETIRED10;

  case PIV_PVTK_OBJ_RETIRED11:
    return YKPIV_KEY_RETIRED11;

  case PIV_PVTK_OBJ_RETIRED12:
    return YKPIV_KEY_RETIRED12;

  case PIV_PVTK_OBJ_RETIRED13:
    return YKPIV_KEY_RETIRED13;

  case PIV_PVTK_OBJ_RETIRED14:
    return YKPIV_KEY_RETIRED14;

  case PIV_PVTK_OBJ_RETIRED15:
    return YKPIV_KEY_RETIRED15;

  case PIV_PVTK_OBJ_RETIRED16:
    return YKPIV_KEY_RETIRED16;

  case PIV_PVTK_OBJ_RETIRED17:
    return YKPIV_KEY_RETIRED17;

  case PIV_PVTK_OBJ_RETIRED18:
    return YKPIV_KEY_RETIRED18;

  case PIV_PVTK_OBJ_RETIRED19:
    return YKPIV_KEY_RETIRED19;

  case PIV_PVTK_OBJ_RETIRED20:
    return YKPIV_KEY_RETIRED20;

  default:
    return 0ul;
  }
}

CK_RV get_attribute(ykcs11_session_t *s, CK_OBJECT_HANDLE obj, CK_ATTRIBUTE_PTR template) {
  CK_ULONG i;

  for (i = 0; i < s->slot->token->n_objects; i++)
    if (s->slot->token->objects[i] == obj) {
      return piv_objects[obj].get_attribute(obj, template);
    }

  return CKR_OBJECT_HANDLE_INVALID;
}

CK_BBOOL attribute_match(ykcs11_session_t *s, CK_OBJECT_HANDLE obj, CK_ATTRIBUTE_PTR attribute) {

  CK_ATTRIBUTE to_match;
  CK_BYTE_PTR data;

  // Get the size first
  to_match.type = attribute->type;
  to_match.pValue = NULL;
  to_match.ulValueLen = 0;

  if (get_attribute(s, obj, &to_match) != CKR_OK)
    return CK_FALSE;

  if (to_match.ulValueLen != attribute->ulValueLen)
    return CK_FALSE;

  // Allocate space for the attribute
  data = malloc(to_match.ulValueLen);
  if (data == NULL)
    return CK_FALSE;

  // Retrieve the attribute
  to_match.pValue = data;
  if (get_attribute(s, obj, &to_match) != CKR_OK) {
    free(data);
    data = NULL;
    return CK_FALSE;
  }

  // Compare the attributes
  if (memcmp(attribute->pValue, to_match.pValue, to_match.ulValueLen) != 0) {
    free(data);
    data = NULL;
    return CK_FALSE;
  }

  free(data);
  data = NULL;

  return CK_TRUE;
}

CK_BBOOL is_private_object(ykcs11_session_t *s, CK_OBJECT_HANDLE obj) {

  CK_ATTRIBUTE attr;
  CK_BYTE      private;

  attr.type = CKA_PRIVATE;
  attr.pValue = &private;
  attr.ulValueLen = sizeof(private);

  if (get_attribute(s, obj, &attr) != CKR_OK)
    return CK_FALSE;

  return private == CK_FALSE ? CK_FALSE : CK_TRUE;
}

CK_RV get_available_certificate_ids(ykcs11_session_t *s, piv_obj_id_t *cert_ids, CK_ULONG n_certs) {
  CK_ULONG i, j;

  if (n_certs > s->slot->token->n_objects)
    return CKR_BUFFER_TOO_SMALL;

  j = 0;
  for (i = 0; i < s->slot->token->n_objects; i++)
    if (IS_CERT(s->slot->token->objects[i]) == CK_TRUE)
      cert_ids[j++] = s->slot->token->objects[i];

  return CKR_OK;
}

CK_RV store_cert(piv_obj_id_t cert_id, CK_BYTE_PTR data, CK_ULONG len) {

  CK_RV rv;

  // Store the certificate as an object
  rv = do_store_cert(data, len, &cert_objects[piv_objects[cert_id].sub_id].data);
  if (rv != CKR_OK)
    return rv;

  // Extract and store the public key as an object
  rv = do_store_pubk(cert_objects[piv_objects[cert_id].sub_id].data, &pubkey_objects[piv_objects[cert_id].sub_id].data);
  if (rv != CKR_OK)
    return rv;

  return CKR_OK;
}

CK_RV delete_cert(piv_obj_id_t cert_id) {
  CK_RV rv;

  // Clear the object containing the certificate
  rv = do_delete_cert(&cert_objects[piv_objects[cert_id].sub_id].data);
  if (rv != CKR_OK)
    return rv;

  // Clear the object containing the public key
  rv = do_delete_pubk(&pubkey_objects[piv_objects[cert_id].sub_id].data);
  if (rv != CKR_OK)
    return rv;

  return CKR_OK;
}

CK_RV check_create_cert(CK_ATTRIBUTE_PTR templ, CK_ULONG n,
                        CK_BYTE_PTR id, CK_BYTE_PTR *value, CK_ULONG_PTR cert_len) {

  CK_ULONG    i;
  CK_BBOOL    has_id = CK_FALSE;
  CK_BBOOL    has_value = CK_FALSE;

  for (i = 0; i < n; i++) {
    switch (templ[i].type) {
    case CKA_CLASS:
      // Technically redundant check
      if (*((CK_ULONG_PTR)templ[i].pValue) != CKO_CERTIFICATE)
        return CKR_ATTRIBUTE_VALUE_INVALID;

      break;

    case CKA_ID:
      has_id = CK_TRUE;
      if (is_valid_key_id(*((CK_BYTE_PTR)templ[i].pValue)) == CK_FALSE)
        return CKR_ATTRIBUTE_VALUE_INVALID;

      *id = *((CK_BYTE_PTR)templ[i].pValue);
      break;

    case CKA_VALUE:
      has_value = CK_TRUE;
      *value = (CK_BYTE_PTR)templ[i].pValue;

      *cert_len = templ[i].ulValueLen;
      break;

    case CKA_TOKEN:
    case CKA_LABEL:
    case CKA_SUBJECT:
    case CKA_ISSUER:
    case CKA_CERTIFICATE_TYPE:
      // Ignore other attributes
      break;

    default:
      DBG("Invalid %lx", templ[i].type);
      return CKR_ATTRIBUTE_TYPE_INVALID;
    }
  }

  if (has_id == CK_FALSE ||
      has_value == CK_FALSE)
    return CKR_TEMPLATE_INCOMPLETE;

  return CKR_OK;
}

CK_RV check_create_ec_key(CK_ATTRIBUTE_PTR templ, CK_ULONG n, CK_BYTE_PTR id,
                          CK_BYTE_PTR *value, CK_ULONG_PTR value_len, CK_ULONG_PTR vendor_defined) {

  CK_ULONG i;
  CK_BBOOL has_id = CK_FALSE;
  CK_BBOOL has_value = CK_FALSE;
  CK_BBOOL has_params = CK_FALSE;

  CK_BYTE_PTR ec_params = NULL;
  CK_ULONG    ec_params_len = 0;

  *vendor_defined = 0;

  for (i = 0; i < n; i++) {
    switch (templ[i].type) {
    case CKA_CLASS:
      if (*((CK_ULONG_PTR)templ[i].pValue) != CKO_PRIVATE_KEY)
        return CKR_ATTRIBUTE_VALUE_INVALID;

      break;

    case CKA_KEY_TYPE:
      if (*((CK_ULONG_PTR)templ[i].pValue) != CKK_ECDSA)
        return CKR_ATTRIBUTE_VALUE_INVALID;

      break;

    case CKA_ID:
      has_id = CK_TRUE;
      if (is_valid_key_id(*((CK_BYTE_PTR)templ[i].pValue)) == CK_FALSE)
        return CKR_ATTRIBUTE_VALUE_INVALID;

      *id = *((CK_BYTE_PTR)templ[i].pValue);
      break;

    case CKA_VALUE:
      has_value = CK_TRUE;
      *value = (CK_BYTE_PTR)templ[i].pValue;
      *value_len = templ[i].ulValueLen;
      break;

    case CKA_EC_PARAMS:
      has_params = CK_TRUE;
      ec_params = (CK_BYTE_PTR)templ[i].pValue;
      ec_params_len = templ[i].ulValueLen;

      break;

    case CKA_VENDOR_DEFINED:
      *vendor_defined = *((CK_ULONG_PTR)templ[i].pValue);
      break;

    case CKA_TOKEN:
    case CKA_LABEL:
    case CKA_SUBJECT:
    case CKA_SENSITIVE:
    case CKA_DERIVE:
      // Ignore other attributes
      break;

    default:
      DBG("Invalid %lx", templ[i].type);
      return CKR_ATTRIBUTE_TYPE_INVALID;
    }
  }

  if (has_id == CK_FALSE ||
      has_value == CK_FALSE ||
      has_params == CK_FALSE)
    return CKR_TEMPLATE_INCOMPLETE;

  if (*value_len == 32 || *value_len == 31) {
    if (ec_params_len != 10 || memcmp(ec_params, PRIME256V1, ec_params_len) != 0)
      return CKR_ATTRIBUTE_VALUE_INVALID;
  }
  else /*if () TODO: P384*/
    return CKR_ATTRIBUTE_VALUE_INVALID;

  return CKR_OK;
}

CK_RV check_create_rsa_key(CK_ATTRIBUTE_PTR templ, CK_ULONG n, CK_BYTE_PTR id,
                           CK_BYTE_PTR *p, CK_ULONG_PTR p_len,
                           CK_BYTE_PTR *q, CK_ULONG_PTR q_len,
                           CK_BYTE_PTR *dp, CK_ULONG_PTR dp_len,
                           CK_BYTE_PTR *dq, CK_ULONG_PTR dq_len,
                           CK_BYTE_PTR *qinv, CK_ULONG_PTR qinv_len,
                           CK_ULONG_PTR vendor_defined) {

  CK_ULONG i;
  CK_BBOOL has_id = CK_FALSE;
  CK_BBOOL has_e = CK_FALSE;
  CK_BBOOL has_p = CK_FALSE;
  CK_BBOOL has_q = CK_FALSE;
  CK_BBOOL has_dp = CK_FALSE;
  CK_BBOOL has_dq = CK_FALSE;
  CK_BBOOL has_qinv = CK_FALSE;

  *vendor_defined = 0;

  for (i = 0; i < n; i++) {
    switch (templ[i].type) {
    case CKA_CLASS:
      if (*((CK_ULONG_PTR)templ[i].pValue) != CKO_PRIVATE_KEY)
        return CKR_ATTRIBUTE_VALUE_INVALID;

      break;

    case CKA_ID:
      has_id = CK_TRUE;
      if (is_valid_key_id(*((CK_BYTE_PTR)templ[i].pValue)) == CK_FALSE)
        return CKR_ATTRIBUTE_VALUE_INVALID;

      *id = *((CK_BYTE_PTR)templ[i].pValue);
      break;

    case CKA_KEY_TYPE:
      if (*((CK_ULONG_PTR)templ[i].pValue) != CKK_RSA)
        return CKR_ATTRIBUTE_VALUE_INVALID;

      break;

    case CKA_PUBLIC_EXPONENT:
      has_e = CK_TRUE;
      if (templ[i].ulValueLen != 3 || memcmp((CK_BYTE_PTR)templ[i].pValue, F4, 3) != 0)
        return CKR_ATTRIBUTE_VALUE_INVALID;
      break;

    case CKA_PRIME_1:
      has_p = CK_TRUE;
      *p = (CK_BYTE_PTR)templ[i].pValue;
      *p_len = templ[i].ulValueLen;

      break;

    case CKA_PRIME_2:
      has_q = CK_TRUE;
      *q = (CK_BYTE_PTR)templ[i].pValue;
      *q_len = templ[i].ulValueLen;

      break;

    case CKA_EXPONENT_1:
      has_dp = CK_TRUE;
      *dp = (CK_BYTE_PTR)templ[i].pValue;
      *dp_len = templ[i].ulValueLen;

      break;

    case CKA_EXPONENT_2:
      has_dq = CK_TRUE;
      *dq = (CK_BYTE_PTR)templ[i].pValue;
      *dq_len = templ[i].ulValueLen;

      break;

    case CKA_COEFFICIENT:
      has_qinv = CK_TRUE;
      *qinv = (CK_BYTE_PTR)templ[i].pValue;
      *qinv_len = templ[i].ulValueLen;

      break;

    case CKA_VENDOR_DEFINED:
      *vendor_defined = *((CK_ULONG_PTR)templ[i].pValue);
      break;

    case CKA_TOKEN:
    case CKA_LABEL:
    case CKA_SUBJECT:
    case CKA_SENSITIVE:
    case CKA_DERIVE:
      // Ignore other attributes
      break;

    default:
      DBG("Invalid %lx", templ[i].type);
      return CKR_ATTRIBUTE_TYPE_INVALID;
    }
  }

  if (has_id == CK_FALSE ||
      has_e == CK_FALSE ||
      has_p == CK_FALSE ||
      has_q == CK_FALSE ||
      has_dp == CK_FALSE ||
      has_dq == CK_FALSE ||
      has_qinv == CK_FALSE)
    return CKR_TEMPLATE_INCOMPLETE;

  if (*p_len != 64 && *p_len != 128)
    return CKR_ATTRIBUTE_VALUE_INVALID;


  if (*q_len != *p_len || *dp_len > *p_len ||
      *dq_len > *p_len || *qinv_len > *p_len)
    return CKR_ATTRIBUTE_VALUE_INVALID;

  return CKR_OK;
}

CK_RV check_delete_cert(CK_OBJECT_HANDLE hObject, CK_BYTE_PTR id) {

  if (hObject < PIV_CERT_OBJ_X509_PIV_AUTH || hObject >= PIV_CERT_OBJ_LAST)
    return CKR_FUNCTION_FAILED;

  *id = hObject - PIV_CERT_OBJ_X509_PIV_AUTH;

  return CKR_OK;
}
