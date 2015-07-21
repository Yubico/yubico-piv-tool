#include "objects.h"
#include <ykpiv.h>
#include <string.h>
#include <stdlib.h>

//TODO: this is mostly a snippet from OpenSC how to give credit?
/* Must be in order, and one per enumerated PIV_OBJ */
static piv_obj_t objects[] = {
  {PIV_OBJ_CCC, "Card Capability Container",
   "2.16.840.1.101.3.7.1.219.0", 3, "\x5F\xC1\x07", "\xDB\x00", 0},
  {PIV_OBJ_CHUI, "Card Holder Unique Identifier",
   "2.16.840.1.101.3.7.2.48.0", 3, "\x5F\xC1\x02", "\x30\x00", 0},
  {PIV_OBJ_X509_PIV_AUTH, "X.509 Certificate for PIV Authentication",
   "2.16.840.1.101.3.7.2.1.1", 3, "\x5F\xC1\x05", "\x01\x01", PIV_OBJECT_TYPE_CERT},
  {PIV_OBJ_CHF, "Card Holder Fingerprints",
   "2.16.840.1.101.3.7.2.96.16", 3, "\x5F\xC1\x03", "\x60\x10", 0},
  {PIV_OBJ_SEC_OBJ, "Security Object",
   "2.16.840.1.101.3.7.2.144.0", 3, "\x5F\xC1\x06", "\x90\x00", 0},
  {PIV_OBJ_CHFI, "Cardholder Facial Images",
   "2.16.840.1.101.3.7.2.96.48", 3, "\x5F\xC1\x08", "\x60\x30", 0},
  {PIV_OBJ_X509_CARD_AUTH, "X.509 Certificate for Card Authentication",
   "2.16.840.1.101.3.7.2.5.0", 3, "\x5F\xC1\x01", "\x05\x00", PIV_OBJECT_TYPE_CERT},
  {PIV_OBJ_X509_DS, "X.509 Certificate for Digital Signature",
   "2.16.840.1.101.3.7.2.1.0", 3, "\x5F\xC1\x0A", "\x01\x00", PIV_OBJECT_TYPE_CERT},
  {PIV_OBJ_X509_KM, "X.509 Certificate for Key Management",
   "2.16.840.1.101.3.7.2.1.2", 3, "\x5F\xC1\x0B", "\x01\x02", PIV_OBJECT_TYPE_CERT},
  {PIV_OBJ_PI, "Printed Information",
   "2.16.840.1.101.3.7.2.48.1", 3, "\x5F\xC1\x09", "\x30\x01", 0},
  {PIV_OBJ_DISCOVERY, "Discovery Object",
   "2.16.840.1.101.3.7.2.96.80", 1, "\x7E", "\x60\x50", 0},
  {PIV_OBJ_HISTORY, "Key History Object",
   "2.16.840.1.101.3.7.2.96.96", 3, "\x5F\xC1\x0C", "\x60\x60", 0},

/* 800-73-3, 21 new objects, 20 history certificates */
  {PIV_OBJ_RETIRED_X509_1, "Retired X.509 Certificate for Key Management 1",
   "2.16.840.1.101.3.7.2.16.1", 3, "\x5F\xC1\x0D", "\x10\x01",
   PIV_OBJECT_NOT_PRESENT|PIV_OBJECT_TYPE_CERT},
  {PIV_OBJ_RETIRED_X509_2, "Retired X.509 Certificate for Key Management 2",
   "2.16.840.1.101.3.7.2.16.2", 3, "\x5F\xC1\x0E", "\x10\x02",
   PIV_OBJECT_NOT_PRESENT|PIV_OBJECT_TYPE_CERT},
  {PIV_OBJ_RETIRED_X509_3, "Retired X.509 Certificate for Key Management 3",
   "2.16.840.1.101.3.7.2.16.3", 3, "\x5F\xC1\x0F", "\x10\x03",
   PIV_OBJECT_NOT_PRESENT|PIV_OBJECT_TYPE_CERT},
  {PIV_OBJ_RETIRED_X509_4, "Retired X.509 Certificate for Key Management 4",
   "2.16.840.1.101.3.7.2.16.4", 3, "\x5F\xC1\x10", "\x10\x04",
   PIV_OBJECT_NOT_PRESENT|PIV_OBJECT_TYPE_CERT},
  {PIV_OBJ_RETIRED_X509_5, "Retired X.509 Certificate for Key Management 5",
   "2.16.840.1.101.3.7.2.16.5", 3, "\x5F\xC1\x11", "\x10\x05",
   PIV_OBJECT_NOT_PRESENT|PIV_OBJECT_TYPE_CERT},
  {PIV_OBJ_RETIRED_X509_6, "Retired X.509 Certificate for Key Management 6",
   "2.16.840.1.101.3.7.2.16.6", 3, "\x5F\xC1\x12", "\x10\x06",
   PIV_OBJECT_NOT_PRESENT|PIV_OBJECT_TYPE_CERT},
  {PIV_OBJ_RETIRED_X509_7, "Retired X.509 Certificate for Key Management 7",
   "2.16.840.1.101.3.7.2.16.7", 3, "\x5F\xC1\x13", "\x10\x07",
   PIV_OBJECT_NOT_PRESENT|PIV_OBJECT_TYPE_CERT},
  {PIV_OBJ_RETIRED_X509_8, "Retired X.509 Certificate for Key Management 8",
   "2.16.840.1.101.3.7.2.16.8", 3, "\x5F\xC1\x14", "\x10\x08",
   PIV_OBJECT_NOT_PRESENT|PIV_OBJECT_TYPE_CERT},
  {PIV_OBJ_RETIRED_X509_9, "Retired X.509 Certificate for Key Management 9",
   "2.16.840.1.101.3.7.2.16.9", 3, "\x5F\xC1\x15", "\x10\x09",
   PIV_OBJECT_NOT_PRESENT|PIV_OBJECT_TYPE_CERT},
  {PIV_OBJ_RETIRED_X509_10, "Retired X.509 Certificate for Key Management 10",
   "2.16.840.1.101.3.7.2.16.10", 3, "\x5F\xC1\x16", "\x10\x0A",
   PIV_OBJECT_NOT_PRESENT|PIV_OBJECT_TYPE_CERT},
  {PIV_OBJ_RETIRED_X509_11, "Retired X.509 Certificate for Key Management 11",
   "2.16.840.1.101.3.7.2.16.11", 3, "\x5F\xC1\x17", "\x10\x0B",
   PIV_OBJECT_NOT_PRESENT|PIV_OBJECT_TYPE_CERT},
  {PIV_OBJ_RETIRED_X509_12, "Retired X.509 Certificate for Key Management 12",
   "2.16.840.1.101.3.7.2.16.12", 3, "\x5F\xC1\x18", "\x10\x0C",
   PIV_OBJECT_NOT_PRESENT|PIV_OBJECT_TYPE_CERT},
  {PIV_OBJ_RETIRED_X509_13, "Retired X.509 Certificate for Key Management 13",
   "2.16.840.1.101.3.7.2.16.13", 3, "\x5F\xC1\x19", "\x10\x0D",
   PIV_OBJECT_NOT_PRESENT|PIV_OBJECT_TYPE_CERT},
  {PIV_OBJ_RETIRED_X509_14, "Retired X.509 Certificate for Key Management 14",
   "2.16.840.1.101.3.7.2.16.14", 3, "\x5F\xC1\x1A", "\x10\x0E",
   PIV_OBJECT_NOT_PRESENT|PIV_OBJECT_TYPE_CERT},
  {PIV_OBJ_RETIRED_X509_15, "Retired X.509 Certificate for Key Management 15",
   "2.16.840.1.101.3.7.2.16.15", 3, "\x5F\xC1\x1B", "\x10\x0F",
   PIV_OBJECT_NOT_PRESENT|PIV_OBJECT_TYPE_CERT},
  {PIV_OBJ_RETIRED_X509_16, "Retired X.509 Certificate for Key Management 16",
   "2.16.840.1.101.3.7.2.16.16", 3, "\x5F\xC1\x1C", "\x10\x10",
   PIV_OBJECT_NOT_PRESENT|PIV_OBJECT_TYPE_CERT},
  {PIV_OBJ_RETIRED_X509_17, "Retired X.509 Certificate for Key Management 17",
   "2.16.840.1.101.3.7.2.16.17", 3, "\x5F\xC1\x1D", "\x10\x11",
   PIV_OBJECT_NOT_PRESENT|PIV_OBJECT_TYPE_CERT},
  {PIV_OBJ_RETIRED_X509_18, "Retired X.509 Certificate for Key Management 18",
   "2.16.840.1.101.3.7.2.16.18", 3, "\x5F\xC1\x1E", "\x10\x12",
   PIV_OBJECT_NOT_PRESENT|PIV_OBJECT_TYPE_CERT},
  {PIV_OBJ_RETIRED_X509_19, "Retired X.509 Certificate for Key Management 19",
   "2.16.840.1.101.3.7.2.16.19", 3, "\x5F\xC1\x1F", "\x10\x13",
   PIV_OBJECT_NOT_PRESENT|PIV_OBJECT_TYPE_CERT},
  {PIV_OBJ_RETIRED_X509_20, "Retired X.509 Certificate for Key Management 20",
   "2.16.840.1.101.3.7.2.16.20", 3, "\x5F\xC1\x20", "\x10\x14",
   PIV_OBJECT_NOT_PRESENT|PIV_OBJECT_TYPE_CERT},

  {PIV_OBJ_IRIS_IMAGE, "Cardholder Iris Images",
   "2.16.840.1.101.3.7.2.16.21", 3, "\x5F\xC1\x21", "\x10\x15", 0},
  {PIV_OBJ_BITGT, "Biometric Information Templates Group Template",
   "2.16.840.1.101.3.7.2.16.22", 2, "\x7F\x61", "\x10\x16", 0},
  {PIV_OBJ_SM_SIGNER, "Secure Messaging Certificate Signer",
   "2.16.840.1.101.3.7.2.16.23", 3, "\x5F\xC1\x22", "\x10\x17", 0},
  {PIV_OBJ_PC_REF_DATA, "Pairing Code Reference Data Container",
   "2.16.840.1.101.3.7.2.16.24", 3, "\x5F\xC1\x23", "\x10\x18", 0},

/* following not standard , to be used by piv-tool only for testing */
  {PIV_OBJ_9B03, "3DES-ECB ADM",
   "2.16.840.1.101.3.7.2.9999.3", 2, "\x9B\x03", "\x9B\x03", 0},
  /* Only used when signing a cert req, usually from engine
   * after piv-tool generated the key and saved the pub key
   * to a file. Note RSA key can be 1024, 2048 or 3072
   * but still use the "9x06" name.
   */
  {PIV_OBJ_9A06, "RSA 9A Pub key from last genkey",
   "2.16.840.1.101.3.7.2.9999.20", 2, "\x9A\x06", "\x9A\x06", PIV_OBJECT_TYPE_PUBKEY},
  {PIV_OBJ_9C06, "Pub 9C key from last genkey",
   "2.16.840.1.101.3.7.2.9999.21", 2, "\x9C\x06", "\x9C\x06", PIV_OBJECT_TYPE_PUBKEY},
  {PIV_OBJ_9D06, "Pub 9D key from last genkey",
   "2.16.840.1.101.3.7.2.9999.22", 2, "\x9D\x06", "\x9D\x06", PIV_OBJECT_TYPE_PUBKEY},
  {PIV_OBJ_9E06, "Pub 9E key from last genkey",
   "2.16.840.1.101.3.7.2.9999.23", 2, "\x9E\x06", "\x9E\x06", PIV_OBJECT_TYPE_PUBKEY},

  {PIV_OBJ_8206, "Pub 82 key ",
   "2.16.840.1.101.3.7.2.9999.101", 2, "\x82\x06", "\x82\x06", PIV_OBJECT_TYPE_PUBKEY},
  {PIV_OBJ_8306, "Pub 83 key ",
   "2.16.840.1.101.3.7.2.9999.102", 2, "\x83\x06", "\x83\x06", PIV_OBJECT_TYPE_PUBKEY},
  {PIV_OBJ_8406, "Pub 84 key ",
   "2.16.840.1.101.3.7.2.9999.103", 2, "\x84\x06", "\x84\x06", PIV_OBJECT_TYPE_PUBKEY},
  {PIV_OBJ_8506, "Pub 85 key ",
   "2.16.840.1.101.3.7.2.9999.104", 2, "\x85\x06", "\x85\x06", PIV_OBJECT_TYPE_PUBKEY},
  {PIV_OBJ_8606, "Pub 86 key ",
   "2.16.840.1.101.3.7.2.9999.105", 2, "\x86\x06", "\x86\x06", PIV_OBJECT_TYPE_PUBKEY},
  {PIV_OBJ_8706, "Pub 87 key ",
   "2.16.840.1.101.3.7.2.9999.106", 2, "\x87\x06", "\x87\x06", PIV_OBJECT_TYPE_PUBKEY},
  {PIV_OBJ_8806, "Pub 88 key ",
   "2.16.840.1.101.3.7.2.9999.107", 2, "\x88\x06", "\x88\x06", PIV_OBJECT_TYPE_PUBKEY},
  {PIV_OBJ_8906, "Pub 89 key ",
   "2.16.840.1.101.3.7.2.9999.108", 2, "\x89\x06", "\x89\x06", PIV_OBJECT_TYPE_PUBKEY},
  {PIV_OBJ_8A06, "Pub 8A key ",
   "2.16.840.1.101.3.7.2.9999.109", 2, "\x8A\x06", "\x8A\x06", PIV_OBJECT_TYPE_PUBKEY},
  {PIV_OBJ_8B06, "Pub 8B key ",
   "2.16.840.1.101.3.7.2.9999.110", 2, "\x8B\x06", "\x8B\x06", PIV_OBJECT_TYPE_PUBKEY},
  {PIV_OBJ_8C06, "Pub 8C key ",
   "2.16.840.1.101.3.7.2.9999.111", 2, "\x8C\x06", "\x8C\x06", PIV_OBJECT_TYPE_PUBKEY},
  {PIV_OBJ_8D06, "Pub 8D key ",
   "2.16.840.1.101.3.7.2.9999.112", 2, "\x8D\x06", "\x8D\x06", PIV_OBJECT_TYPE_PUBKEY},
  {PIV_OBJ_8E06, "Pub 8E key ",
   "2.16.840.1.101.3.7.2.9999.113", 2, "\x8E\x06", "\x8E\x06", PIV_OBJECT_TYPE_PUBKEY},
  {PIV_OBJ_8F06, "Pub 8F key ",
   "2.16.840.1.101.3.7.2.9999.114", 2, "\x8F\x06", "\x8F\x06", PIV_OBJECT_TYPE_PUBKEY},
  {PIV_OBJ_9006, "Pub 90 key ",
   "2.16.840.1.101.3.7.2.9999.115", 2, "\x90\x06", "\x90\x06", PIV_OBJECT_TYPE_PUBKEY},
  {PIV_OBJ_9106, "Pub 91 key ",
   "2.16.840.1.101.3.7.2.9999.116", 2, "\x91\x06", "\x91\x06", PIV_OBJECT_TYPE_PUBKEY},
  {PIV_OBJ_9206, "Pub 92 key ",
   "2.16.840.1.101.3.7.2.9999.117", 2, "\x92\x06", "\x92\x06", PIV_OBJECT_TYPE_PUBKEY},
  {PIV_OBJ_9306, "Pub 93 key ",
   "2.16.840.1.101.3.7.2.9999.118", 2, "\x93\x06", "\x93\x06", PIV_OBJECT_TYPE_PUBKEY},
  {PIV_OBJ_9406, "Pub 94 key ",
   "2.16.840.1.101.3.7.2.9999.119", 2, "\x94\x06", "\x94\x06", PIV_OBJECT_TYPE_PUBKEY},
  {PIV_OBJ_9506, "Pub 95 key ",
   "2.16.840.1.101.3.7.2.9999.120", 2, "\x95\x06", "\x95\x06", PIV_OBJECT_TYPE_PUBKEY},
  {PIV_OBJ_LAST_ENUM, "", "", 0, "", "", 0}
};

static const CK_ULONG n_objects = sizeof(objects) / sizeof(piv_obj_t);

static void get_object_class(CK_OBJECT_HANDLE obj, CK_OBJECT_CLASS_PTR class) {
  if ((objects[obj].flags & PIV_OBJECT_TYPE_PUBKEY))
    *class = CKO_PUBLIC_KEY;
  else if ((objects[obj].flags & PIV_OBJECT_TYPE_CERT))
    *class = CKO_CERTIFICATE;
  else
    *class = CKO_DATA; // TODO: other possibilities?
}

static void get_object_label(CK_OBJECT_HANDLE obj, CK_UTF8CHAR_PTR label) {
  strcpy((char *)label, objects[obj].name);
}

// Next two functions based off the code at
// https://github.com/m9aertner/oidConverter/blob/master/oid.c
// TODO: how to give credit?
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
  CK_CHAR_PTR tmp = strdup((char *)oid);
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

    l = 0;
    if (*p == '.') {
      *p = 0;
      l = (CK_ULONG) atoi((char *)q);
      q = p + 1;
      p = q;
    }
    else {
      l = (CK_ULONG) atoi((char *)q);
      q = p;
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

static void get_object_oid(CK_OBJECT_HANDLE obj, CK_UTF8CHAR_PTR oid) {
  strcpy((char *)oid, objects[obj].oid);
}

static void get_object_certificate_type(CK_OBJECT_HANDLE obj, CK_CERTIFICATE_TYPE_PTR type) {
  if ((objects[obj].flags & PIV_OBJECT_TYPE_CERT))
      *type = CKC_X_509;
}

static void get_object_key_id(CK_OBJECT_HANDLE obj, CK_UTF8CHAR_PTR key_id) {
  memcpy((char *)key_id, objects[obj].containerid, 2);
}

CK_RV get_attribute(CK_OBJECT_HANDLE obj, CK_ATTRIBUTE_PTR template) {
  fprintf(stderr, "FOR OBJECT %lu, I WANT ", obj);

  switch (template->type) {
  case CKA_CLASS:
    fprintf(stderr, "CLASS\n");
    if (template->pValue == NULL_PTR) // TODO: just don't use functions, break and check return later?
      template->ulValueLen = 1;
    else
      get_object_class(obj, template->pValue);

    return CKR_OK;

//  case CKA_TOKEN:
  case CKA_PRIVATE:
    fprintf(stderr, "PRIVATE\n"); // TODO: check more
    template->ulValueLen = CK_UNAVAILABLE_INFORMATION;
    return CKR_OK;

  case CKA_LABEL:
    fprintf(stderr, "LABEL\n");
    if (template->pValue == NULL_PTR)
      template->ulValueLen = strlen(objects[obj].name);
    else
      strcpy((char *)template->pValue, objects[obj].name);
    return CKR_OK;

  case CKA_APPLICATION:
    fprintf(stderr, "APPLICATION\n");
    if (template->pValue == NULL_PTR)
      template->ulValueLen = strlen(objects[obj].name);
    else
      strcpy((char *)template->pValue, objects[obj].name);
    return CKR_OK;

//  case CKA_VALUE:
  case CKA_OBJECT_ID: // TODO: how about just storing the OID in DER ?
    fprintf(stderr, "OID\n");
    if (template->pValue == NULL_PTR)
      template->ulValueLen = strlen(objects[obj].oid) * 2; // Slightly oversized
    else {
      strcpy((char *)template->pValue, objects[obj].oid);
      asn1_encode_oid(template->pValue, template->pValue, &template->ulValueLen);
    }
    return CKR_OK;

  case CKA_CERTIFICATE_TYPE:
    fprintf(stderr, "CERTIFICATE TYPE\n");
    if (template->pValue == NULL_PTR)
      template->ulValueLen = 1;
    else
      *((CK_ULONG_PTR)template->pValue) = CKC_X_509; // Support only X.509 certs
    return CKR_OK;
//  case CKA_ISSUER:
//  case CKA_SERIAL_NUMBER:
  case CKA_KEY_TYPE:
    fprintf(stderr, "Return the key type TODO!!!\n");
    return CKR_OK;

  /* case CKA_SUBJECT: */
  case CKA_ID:
    fprintf(stderr, "KEY ID\n");
    if (template->pValue == NULL_PTR)
      template->ulValueLen = 2;
    else
      memcpy((char *)template->pValue, objects[obj].containerid, 2);
    return CKR_OK;
  /* case CKA_SENSITIVE: */
  /* case CKA_ENCRYPT: */
  /* case CKA_DECRYPT: */
  /* case CKA_WRAP: */
  /* case CKA_UNWRAP: */
  /* case CKA_SIGN: */
  /* case CKA_SIGN_RECOVER: */
  /* case CKA_VERIFY: */
  /* case CKA_VERIFY_RECOVER: */
  /* case CKA_DERIVE: */
  /* case CKA_START_DATE: */
  /* case CKA_END_DATE: */
  /* case CKA_MODULUS: */
  /* case CKA_MODULUS_BITS: */
  /* case CKA_PUBLIC_EXPONENT: */
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
  /* case CKA_LOCAL: */
  /* case CKA_NEVER_EXTRACTABLE: */
  /* case CKA_ALWAYS_SENSITIVE: */
  case CKA_MODIFIABLE:
    fprintf(stderr, "MODIFIABLE\n");
    if (template->pValue == NULL_PTR)
      template->ulValueLen = 1;
    else
    *((CK_ULONG_PTR)template->pValue) = CK_FALSE;
    return CKR_OK;

  case CKA_VENDOR_DEFINED:
  default:
    fprintf(stderr, "UNKNOWN ATTRIBUTE!!!!! %lx\n", template[0].type);
    template->ulValueLen = CK_UNAVAILABLE_INFORMATION;
    return CKR_FUNCTION_FAILED;
  }

  // Never reached
  return CKR_FUNCTION_FAILED;

}
