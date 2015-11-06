#include "yubico_token.h"
#include "pkcs11.h"
#include <string.h>
#include "debug.h"
#include "objects.h"

#define MIN_RSA_KEY_SIZE 1024
#define MAX_RSA_KEY_SIZE 2048
#define MIN_ECC_KEY_SIZE 256
#define MAX_ECC_KEY_SIZE 384

static const char *token_label = "YubiKey PIV";
static const char *token_manufacturer = "Yubico";
static const char *token_model = "YubiKey XXX";
static const CK_FLAGS token_flags = CKF_RNG | CKF_LOGIN_REQUIRED | CKF_USER_PIN_INITIALIZED | CKF_TOKEN_INITIALIZED;
static const char *token_serial = "1234";
static const CK_MECHANISM_TYPE token_mechanisms[] = { // KEEP ALIGNED WITH token_mechanism_infos
  CKM_RSA_PKCS_KEY_PAIR_GEN,
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
  CKM_EC_KEY_PAIR_GEN,
  //CKM_ECDSA_KEY_PAIR_GEN, Same as CKM_EC_KEY_PAIR_GEN, deprecated in 2.11
  CKM_ECDSA,
  CKM_ECDSA_SHA1,
  CKM_ECDSA_SHA256,
  CKM_SHA_1,
  CKM_SHA256,
  CKM_SHA384,
  CKM_SHA512
  // SUPPORT FOR OATH?
};
static const CK_ULONG token_mechanisms_num = sizeof(token_mechanisms) / sizeof(CK_MECHANISM_TYPE);

static const CK_MECHANISM_INFO token_mechanism_infos[] = { // KEEP ALIGNED WITH token_mechanisms
  {MIN_RSA_KEY_SIZE, MAX_RSA_KEY_SIZE, CKF_HW | CKF_GENERATE_KEY_PAIR}, // CKM_RSA_PKCS_KEY_PAIR_GEN
  {MIN_RSA_KEY_SIZE, MAX_RSA_KEY_SIZE, CKF_HW | CKF_DECRYPT | CKF_SIGN}, // CKM_RSA_PKCS
  {MIN_RSA_KEY_SIZE, MAX_RSA_KEY_SIZE, CKF_HW | CKF_SIGN}, // CKM_RSA_PKCS_PSS
  {MIN_RSA_KEY_SIZE, MAX_RSA_KEY_SIZE, CKF_HW | CKF_DECRYPT | CKF_SIGN}, // CKM_RSA_X_509
  {MIN_RSA_KEY_SIZE, MAX_RSA_KEY_SIZE, CKF_HW | CKF_SIGN}, // CKM_SHA1_RSA_PKCS
  {MIN_RSA_KEY_SIZE, MAX_RSA_KEY_SIZE, CKF_HW | CKF_SIGN}, // CKM_SHA256_RSA_PKCS
  {MIN_RSA_KEY_SIZE, MAX_RSA_KEY_SIZE, CKF_HW | CKF_SIGN}, // CKM_SHA384_RSA_PKCS
  {MIN_RSA_KEY_SIZE, MAX_RSA_KEY_SIZE, CKF_HW | CKF_SIGN}, // CKM_SHA512_RSA_PKCS
  {MIN_RSA_KEY_SIZE, MAX_RSA_KEY_SIZE, CKF_HW | CKF_SIGN}, // CKM_SHA1_RSA_PKCS_PSS
  {MIN_RSA_KEY_SIZE, MAX_RSA_KEY_SIZE, CKF_HW | CKF_SIGN}, // CKM_SHA256_RSA_PKCS_PSS
  {MIN_RSA_KEY_SIZE, MAX_RSA_KEY_SIZE, CKF_HW | CKF_SIGN}, // CKM_SHA384_RSA_PKCS_PSS
  {MIN_RSA_KEY_SIZE, MAX_RSA_KEY_SIZE, CKF_HW | CKF_SIGN}, // CKM_SHA512_RSA_PKCS_PSS
  {MIN_ECC_KEY_SIZE, MAX_ECC_KEY_SIZE, CKF_HW | CKF_GENERATE_KEY_PAIR}, // CKM_EC_KEY_PAIR_GEN
  //{, , }, // CKM_ECDSA_KEY_PAIR_GEN Same as CKM_EC_KEY_PAIR_GEN deprecated in 2.11
  {MIN_ECC_KEY_SIZE, MAX_ECC_KEY_SIZE, CKF_HW | CKF_SIGN}, // CKM_ECDSA
  {MIN_ECC_KEY_SIZE, MAX_ECC_KEY_SIZE, CKF_HW | CKF_SIGN}, // CKM_ECDSA_SHA1
  {MIN_ECC_KEY_SIZE, MAX_ECC_KEY_SIZE, CKF_HW | CKF_SIGN}, // CKM_ECDSA_SHA256
  {0, 0, CKF_DIGEST}, // CKM_SHA_1
  {0, 0, CKF_DIGEST}, // CKM_SHA256
  {0, 0, CKF_DIGEST}, // CKM_SHA384
  {0, 0, CKF_DIGEST}  // CKM_SHA512
};

static const piv_obj_id_t token_objects[] = { // TODO: is there a way to get this from the token?
  PIV_DATA_OBJ_X509_PIV_AUTH,   // PIV authentication
  PIV_DATA_OBJ_X509_CARD_AUTH,  // Certificate for card authentication
  PIV_DATA_OBJ_X509_DS,         // Certificate for digital signature
  PIV_DATA_OBJ_X509_KM,         // Certificate for key management
  PIV_DATA_OBJ_CCC,             // Card capability container
  PIV_DATA_OBJ_CHUI,            // Cardholder unique id
  PIV_DATA_OBJ_CHF,             // Cardholder fingerprints
  PIV_DATA_OBJ_SEC_OBJ,         // Security object
  PIV_DATA_OBJ_CHFI,            // Cardholder facial images
  //PIV_DATA_OBJ_PI,              // Cardholder printed information
  //PIV_DATA_OBJ_DISCOVERY,       // Discovery object
  //PIV_DATA_OBJ_HISTORY,         // History object
/*  PIV_DATA_OBJ_RETIRED_X509_1,  // Retired certificate for KM 1
  PIV_DATA_OBJ_RETIRED_X509_2,  // Retired certificate for KM 2
  PIV_DATA_OBJ_RETIRED_X509_3,  // Retired certificate for KM 3
  PIV_DATA_OBJ_RETIRED_X509_4,  // Retired certificate for KM 4
  PIV_DATA_OBJ_RETIRED_X509_5,  // Retired certificate for KM 5
  PIV_DATA_OBJ_RETIRED_X509_6,  // Retired certificate for KM 6
  PIV_DATA_OBJ_RETIRED_X509_7,  // Retired certificate for KM 7
  PIV_DATA_OBJ_RETIRED_X509_8,  // Retired certificate for KM 8
  PIV_DATA_OBJ_RETIRED_X509_9,  // Retired certificate for KM 9
  PIV_DATA_OBJ_RETIRED_X509_10, // Retired certificate for KM 10
  PIV_DATA_OBJ_RETIRED_X509_11, // Retired certificate for KM 11
  PIV_DATA_OBJ_RETIRED_X509_12, // Retired certificate for KM 12
  PIV_DATA_OBJ_RETIRED_X509_13, // Retired certificate for KM 13
  PIV_DATA_OBJ_RETIRED_X509_14, // Retired certificate for KM 14
  PIV_DATA_OBJ_RETIRED_X509_15, // Retired certificate for KM 15
  PIV_DATA_OBJ_RETIRED_X509_16, // Retired certificate for KM 16
  PIV_DATA_OBJ_RETIRED_X509_17, // Retired certificate for KM 17
  PIV_DATA_OBJ_RETIRED_X509_18, // Retired certificate for KM 18
  PIV_DATA_OBJ_RETIRED_X509_19, // Retired certificate for KM 19
  PIV_DATA_OBJ_RETIRED_X509_20, // Retired certificate for KM 20*/
  //PIV_DATA_OBJ_IRIS_IMAGE,      // Cardholder iris images
  //PIV_DATA_OBJ_BITGT,           // Biometric information templates group template
  //PIV_DATA_OBJ_SM_SIGNER,       // Secure messaging signer
  //PIV_DATA_OBJ_PC_REF_DATA,      // Pairing code reference data
};
static const CK_ULONG token_objects_num = sizeof(token_objects) / sizeof(piv_obj_id_t);

CK_RV YUBICO_get_token_label(CK_UTF8CHAR_PTR str, CK_ULONG len) {

  if (strlen(token_label) > len)
    return CKR_BUFFER_TOO_SMALL;

  memcpy(str, token_label, strlen(token_label));
  return CKR_OK;

}

CK_RV YUBICO_get_token_manufacturer(CK_UTF8CHAR_PTR str, CK_ULONG len) {

  if (strlen(token_manufacturer) > len)
    return CKR_BUFFER_TOO_SMALL;

  memcpy(str, token_manufacturer, strlen(token_manufacturer));
  return CKR_OK;

}
#include "debug.h"
CK_RV YUBICO_get_token_model(ykpiv_state *state, CK_UTF8CHAR_PTR str, CK_ULONG len) {

  char buf[16];

  if (strlen(token_model) > len)
    return CKR_BUFFER_TOO_SMALL;

  if (ykpiv_get_version(state, buf, sizeof(buf)) != YKPIV_OK)
    return CKR_FUNCTION_FAILED;

  memcpy(str, token_model, strlen(token_model));

  if (buf[0] >= '4')
    memcpy(str + strlen(token_model) - 3, "YK4", 3);
  else
    memcpy(str + strlen(token_model) - 3, "NEO", 3);

  return CKR_OK;

}

CK_RV YUBICO_get_token_flags(CK_FLAGS_PTR flags) {

  *flags = token_flags;
  return CKR_OK;

}

CK_RV YUBICO_get_token_version(CK_UTF8CHAR_PTR v_str, CK_ULONG len, CK_VERSION_PTR version) {

  CK_VERSION v = {0, 0};
  unsigned int i = 0;

  while (i < len && v_str[i] != '.') {
    v.major *= 10;
    v.major += v_str[i++] - '0';
  }

  i++;

  while (i < len && v_str[i] != '.') {
    v.minor *= 10;
    v.minor += v_str[i++] - '0';
  }

  i++;

  while (i < len && v_str[i] != '.') {
    v.minor *= 10;
    v.minor += v_str[i++] - '0';
  }

  version->major = v.major;
  version->minor = v.minor;

  return CKR_OK;
}

CK_RV YUBICO_get_token_serial(CK_CHAR_PTR str, CK_ULONG len) {

  if (strlen(token_serial) > len)
    return CKR_BUFFER_TOO_SMALL;

  memcpy(str, token_serial, strlen(token_serial));
  return CKR_OK;

}

CK_RV YUBICO_get_token_mechanisms_num(CK_ULONG_PTR num) {

  *num = token_mechanisms_num;
  return CKR_OK;

}

CK_RV YUBICO_get_token_mechanism_list(CK_MECHANISM_TYPE_PTR mec, CK_ULONG num) {

  if (token_mechanisms_num > num)
    return CKR_BUFFER_TOO_SMALL;

  memcpy(mec, token_mechanisms, token_mechanisms_num * sizeof(CK_MECHANISM_TYPE));
  return CKR_OK;

}

CK_RV YUBICO_get_token_mechanism_info(CK_MECHANISM_TYPE mec, CK_MECHANISM_INFO_PTR info) {

  CK_ULONG i;

  for (i = 0; i < token_mechanisms_num; i++)
    if (token_mechanisms[i] == mec) {
      memcpy((CK_BYTE_PTR) info, (CK_BYTE_PTR) (token_mechanism_infos + i), sizeof(CK_MECHANISM_INFO));
      return CKR_OK;
    }

  return CKR_MECHANISM_INVALID;

}

static CK_RV get_objects(ykpiv_state *state, CK_BBOOL num_only,
                         piv_obj_id_t *obj, CK_ULONG_PTR len, CK_ULONG_PTR num_certs) {
  CK_BYTE buf[2048];
  CK_ULONG buf_len;

  piv_obj_id_t certs[4]; // TODO: this can be > 4 if there are retired keys
  piv_obj_id_t pvtkeys[4];
  piv_obj_id_t pubkeys[4];
  CK_ULONG n_cert = 0;

  if (state == NULL || len == NULL_PTR)
    return CKR_ARGUMENTS_BAD;

  if (num_only == CK_FALSE && obj == NULL)
    return CKR_ARGUMENTS_BAD;

  buf_len = sizeof(buf);
  if (ykpiv_fetch_object(state, YKPIV_OBJ_AUTHENTICATION, buf, &buf_len) == YKPIV_OK) {
    certs[n_cert] = PIV_CERT_OBJ_X509_PIV_AUTH;
    pvtkeys[n_cert] = PIV_PVTK_OBJ_PIV_AUTH;
    pubkeys[n_cert] = PIV_PUBK_OBJ_PIV_AUTH;
    n_cert++;
    DBG("Found AUTH cert (9a)");
  }

  buf_len = sizeof(buf);
  if (ykpiv_fetch_object(state, YKPIV_OBJ_CARD_AUTH, buf, &buf_len) == YKPIV_OK) {
    certs[n_cert] = PIV_CERT_OBJ_X509_CARD_AUTH;
    pvtkeys[n_cert] = PIV_PVTK_OBJ_CARD_AUTH;
    pubkeys[n_cert] = PIV_PUBK_OBJ_CARD_AUTH;
    n_cert++;
    DBG("Found CARD AUTH cert (9e)");
  }

  buf_len = sizeof(buf);
  if (ykpiv_fetch_object(state, YKPIV_OBJ_SIGNATURE, buf, &buf_len) == YKPIV_OK) {
    certs[n_cert] = PIV_CERT_OBJ_X509_DS;
    pvtkeys[n_cert] = PIV_PVTK_OBJ_DS;
    pubkeys[n_cert] = PIV_PUBK_OBJ_DS;
    n_cert++;
    DBG("Found SIGNATURE cert (9c)");
  }

  buf_len = sizeof(buf);
  if (ykpiv_fetch_object(state, YKPIV_OBJ_KEY_MANAGEMENT, buf, &buf_len) == YKPIV_OK) {
    certs[n_cert] = PIV_CERT_OBJ_X509_KM;
    pvtkeys[n_cert] = PIV_PVTK_OBJ_KM;
    pubkeys[n_cert] = PIV_PUBK_OBJ_KM;
    n_cert++;
    DBG("Found KMK cert (9d)");
  }

  DBG("The total number of objects for this token is %lu", (n_cert * 3) + token_objects_num);

  if (num_only == CK_TRUE) {
    // We just want the number of objects
    // Each cert object counts for 3: cert, pub key, pvt key
    *len = (n_cert * 3) + token_objects_num;
    if (num_certs != NULL)
      *num_certs = n_cert;
    return CKR_OK;
  }

  if (*len < (n_cert * 3) + token_objects_num)
    return CKR_BUFFER_TOO_SMALL;

  // Copy mandatory data objects
  memcpy(obj, token_objects, token_objects_num * sizeof(piv_obj_id_t));

  // Copy certificates
  if (n_cert > 0) {
    memcpy(obj + token_objects_num, certs, n_cert * sizeof(piv_obj_id_t));
    memcpy(obj + token_objects_num + n_cert, pvtkeys, n_cert * sizeof(piv_obj_id_t));
    memcpy(obj + token_objects_num + (2 * n_cert), pubkeys, n_cert * sizeof(piv_obj_id_t));
  }

  return CKR_OK;
}

CK_RV YUBICO_get_token_objects_num(ykpiv_state *state, CK_ULONG_PTR num, CK_ULONG_PTR num_certs) {
  return get_objects(state, CK_TRUE, NULL, num, num_certs);
}

CK_RV YUBICO_get_token_object_list(ykpiv_state *state, piv_obj_id_t *obj, CK_ULONG num) {
  return get_objects(state, CK_FALSE, obj, &num, NULL);
}

CK_RV YUBICO_get_token_raw_certificate(ykpiv_state *state, piv_obj_id_t obj, CK_BYTE_PTR data, CK_ULONG_PTR len) {

  if (ykpiv_fetch_object(state, piv_2_ykpiv(obj), data, len) != YKPIV_OK)
    return CKR_FUNCTION_FAILED;

  return CKR_OK;
}
