#include "../../tool/openssl-compat.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <openssl/rsa.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/x509.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include "pkcs11y.h"
#include "ykcs11_tests_util.h"

static CK_BYTE SHA1_DIGEST[] = {0x30, 0x21, 0x30, 0x09, 0x06,
                                0x05, 0x2B, 0x0E, 0x03, 0x02,
                                0x1A, 0x05, 0x00, 0x04, 0x14};

static CK_BYTE SHA256_DIGEST[] = {0x30, 0x31, 0x30, 0x0D, 0x06,
                                  0x09, 0x60, 0x86, 0x48, 0x01,
                                  0x65, 0x03, 0x04, 0x02, 0x01,
                                  0x05, 0x00, 0x04, 0x20};

static CK_BYTE SHA384_DIGEST[] = {0x30, 0x41, 0x30, 0x0D, 0x06,
                                  0x09, 0x60, 0x86, 0x48, 0x01,
                                  0x65, 0x03, 0x04, 0x02, 0x02,
                                  0x05, 0x00, 0x04, 0x30};

static CK_BYTE SHA512_DIGEST[] = {0x30, 0x51, 0x30, 0x0D, 0x06,
                                  0x09, 0x60, 0x86, 0x48, 0x01,
                                  0x65, 0x03, 0x04, 0x02, 0x03,
                                  0x05, 0x00, 0x04, 0x40};

#define asrt(c, e, m) _asrt(__FILE__, __LINE__, c, e, m);

static void _asrt(const char *file, int line, CK_ULONG check, CK_ULONG expected, const char *msg) {

  if (check == expected)
    return;

  fprintf(stderr, "%s.%d: <%s> check failed with value %lu (0x%lx), expected %lu (0x%lx)\n",
          file, line, msg, check, check, expected, expected);

  exit(EXIT_FAILURE);

}

void dump_hex(const unsigned char *buf, unsigned int len, FILE *output, int space) {
  unsigned int i;
  for (i = 0; i < len; i++) {
    fprintf(output, "%02x%s", buf[i], space == 1 ? " " : "");
  }
  fprintf(output, "\n");
}

static CK_OBJECT_HANDLE get_public_key_handle(CK_FUNCTION_LIST_PTR funcs, CK_SESSION_HANDLE session, 
                        CK_OBJECT_HANDLE privkey) {
  CK_OBJECT_HANDLE found_obj[10];
  CK_ULONG n_found_obj = 0;
  CK_ULONG class_pub = CKO_PUBLIC_KEY;
  CK_BYTE ckaid = 0;

  CK_ATTRIBUTE idTemplate[] = {
    {CKA_ID, &ckaid, sizeof(ckaid)}
  };
  CK_ATTRIBUTE idClassTemplate[] = {
    {CKA_ID, &ckaid, sizeof(ckaid)},
    {CKA_CLASS, &class_pub, sizeof(class_pub)}
  };

  asrt(funcs->C_GetAttributeValue(session, privkey, idTemplate, 1), CKR_OK, "GET CKA_ID");
  asrt(funcs->C_FindObjectsInit(session, idClassTemplate, 2), CKR_OK, "FIND INIT");
  asrt(funcs->C_FindObjects(session, found_obj, 10, &n_found_obj), CKR_OK, "FIND");
  asrt(n_found_obj, 1, "N FOUND OBJS");
  asrt(funcs->C_FindObjectsFinal(session), CKR_OK, "FIND FINAL");
  return found_obj[0];
}

void destroy_test_objects(CK_FUNCTION_LIST_PTR funcs, CK_SESSION_HANDLE session, CK_OBJECT_HANDLE_PTR obj_cert, CK_ULONG n) {
  CK_ULONG i;
  asrt(funcs->C_Login(session, CKU_SO, (CK_CHAR_PTR)"010203040506070801020304050607080102030405060708", 48), CKR_OK, "Login SO");
  for(i=0; i<n; i++) {
    asrt(funcs->C_DestroyObject(session, obj_cert[i]), CKR_OK, "Destroy Object");
  }
  asrt(funcs->C_Logout(session), CKR_OK, "Logout SO");
}

static CK_RV get_hash(CK_MECHANISM_TYPE mech, 
                    CK_BYTE* data, CK_ULONG data_len, 
                    CK_BYTE* hdata, CK_ULONG* hdata_len) {
  if(data == NULL || hdata == NULL || hdata_len == NULL) {
    return CKR_FUNCTION_FAILED;
  }

  CK_BYTE hashed_data[512];
  switch(mech) {
    case CKM_SHA_1:
    case CKM_RSA_PKCS_PSS:
    case CKM_SHA1_RSA_PKCS_PSS:
      SHA1(data, data_len, hashed_data);
      memcpy(hdata, hashed_data, 20);
      *hdata_len = 20;
      break;
    case CKM_SHA256:
    case CKM_SHA256_RSA_PKCS_PSS:
      SHA256(data, data_len, hashed_data);
      memcpy(hdata, hashed_data, 32);
      *hdata_len = 32;
      break;
    case CKM_SHA384:
    case CKM_SHA384_RSA_PKCS_PSS:
      SHA384(data, data_len, hashed_data);
      memcpy(hdata, hashed_data, 48);
      *hdata_len = 48;
      break;
    case CKM_SHA512:
    case CKM_SHA512_RSA_PKCS_PSS:
      SHA512(data, data_len, hashed_data);
      memcpy(hdata, hashed_data, 64);
      *hdata_len = 64;
      break;
    default:
      break;
  }
  return CKR_OK;
}

static CK_RV get_digest(CK_MECHANISM_TYPE mech, 
                       CK_BYTE* data, CK_ULONG data_len, 
                       CK_BYTE* hdata, CK_ULONG* hdata_len) {
  if(data == NULL || hdata == NULL || hdata_len == NULL) {
    return CKR_FUNCTION_FAILED;
  }

  CK_BYTE hashed_data[512];
  switch(mech) {
    case CKM_ECDSA:
    case CKM_RSA_PKCS:
      memcpy(hdata, data, data_len);
      *hdata_len = data_len;
      break;
    case CKM_ECDSA_SHA1:
    case CKM_SHA1_RSA_PKCS:
    case CKM_SHA1_RSA_PKCS_PSS:
      SHA1(data, data_len, hashed_data);
      memcpy(hdata, SHA1_DIGEST, sizeof(SHA1_DIGEST));
      memcpy(hdata + sizeof(SHA1_DIGEST), hashed_data, 20);
      *hdata_len = sizeof(SHA1_DIGEST) + 20;
      break;
    case CKM_ECDSA_SHA256:
    case CKM_SHA256_RSA_PKCS:
    case CKM_SHA256_RSA_PKCS_PSS:
      SHA256(data, data_len, hashed_data);
      memcpy(hdata, SHA256_DIGEST, sizeof(SHA256_DIGEST));
      memcpy(hdata + sizeof(SHA256_DIGEST), hashed_data, 32);
      *hdata_len = sizeof(SHA256_DIGEST) + 32;
      break;
    case CKM_ECDSA_SHA384:
    case CKM_SHA384_RSA_PKCS:
    case CKM_SHA384_RSA_PKCS_PSS:
      SHA384(data, data_len, hashed_data);
      memcpy(hdata, SHA384_DIGEST, sizeof(SHA384_DIGEST));
      memcpy(hdata + sizeof(SHA384_DIGEST), hashed_data, 48);
      *hdata_len = sizeof(SHA384_DIGEST) + 48;
      break;
    case CKM_ECDSA_SHA512:
    case CKM_SHA512_RSA_PKCS:
    case CKM_SHA512_RSA_PKCS_PSS:
      SHA512(data, data_len, hashed_data);
      memcpy(hdata, SHA512_DIGEST, sizeof(SHA512_DIGEST));
      memcpy(hdata + sizeof(SHA512_DIGEST), hashed_data, 64);
      *hdata_len = sizeof(SHA512_DIGEST) + 64;
      break;
    default:
      break;
  }
  return CKR_OK;
}

static const EVP_MD* get_md_type(CK_MECHANISM_TYPE mech) {
  switch(mech) {
    case CKM_SHA_1:
    case CKM_SHA1_RSA_PKCS:
    case CKM_SHA1_RSA_PKCS_PSS:
    case CKM_ECDSA_SHA1:
    case CKG_MGF1_SHA1:
      return EVP_sha1();
    case CKM_ECDSA_SHA224:
    case CKG_MGF1_SHA224:
      return EVP_sha224();
    case CKM_SHA256:
    case CKM_SHA256_RSA_PKCS:
    case CKM_SHA256_RSA_PKCS_PSS:
    case CKM_ECDSA_SHA256:
    case CKG_MGF1_SHA256:
      return EVP_sha256();
    case CKM_SHA384:
    case CKM_SHA384_RSA_PKCS:
    case CKM_SHA384_RSA_PKCS_PSS:
    case CKM_ECDSA_SHA384:
    case CKG_MGF1_SHA384:
      return EVP_sha384();
    case CKM_SHA512:
    case CKM_SHA512_RSA_PKCS:
    case CKM_SHA512_RSA_PKCS_PSS:
    case CKM_ECDSA_SHA512:
    case CKG_MGF1_SHA512:
      return EVP_sha512();
    default:
      return NULL;
  }
}

static CK_MECHANISM_TYPE get_md_of(CK_MECHANISM_TYPE mech) {
  switch(mech) {
    case CKM_SHA_1:
    case CKM_SHA1_RSA_PKCS:
    case CKM_SHA1_RSA_PKCS_PSS:
    case CKM_ECDSA_SHA1:
    case CKG_MGF1_SHA1:
      return CKM_SHA_1;
    case CKM_SHA256:
    case CKM_SHA256_RSA_PKCS:
    case CKM_SHA256_RSA_PKCS_PSS:
    case CKM_ECDSA_SHA256:
    case CKG_MGF1_SHA256:
      return CKM_SHA256;
    case CKM_SHA384:
    case CKM_SHA384_RSA_PKCS:
    case CKM_SHA384_RSA_PKCS_PSS:
    case CKM_ECDSA_SHA384:
    case CKG_MGF1_SHA384:
      return CKM_SHA384;
    case CKM_SHA512:
    case CKM_SHA512_RSA_PKCS:
    case CKM_SHA512_RSA_PKCS_PSS:
    case CKM_ECDSA_SHA512:
    case CKG_MGF1_SHA512:
      return CKM_SHA512;
    default:
      return CKM_SHA256;
  }
}

void test_digest_func(CK_FUNCTION_LIST_PTR funcs, CK_SESSION_HANDLE session, CK_MECHANISM_TYPE mech_type) {
  CK_BYTE     i;
  CK_BYTE     data[32];
  CK_ULONG    data_len = sizeof(data);
  CK_BYTE     digest[128];
  CK_ULONG    digest_len;
  CK_BYTE     digest_update[128];
  CK_ULONG    digest_update_len;
  CK_BYTE     hdata[128];
  CK_ULONG    hdata_len;

  CK_MECHANISM mech = {mech_type, NULL, 0};

  for(i=0; i<10; i++) {
    if(RAND_bytes(data, data_len) <= 0)
        exit(EXIT_FAILURE);

    asrt(get_hash(mech_type, data, data_len, hdata, &hdata_len), CKR_OK, "GET HASH");

    asrt(funcs->C_DigestInit(session, &mech), CKR_OK, "DIGEST INIT");  
    digest_len = sizeof(digest);
    asrt(funcs->C_Digest(session, data, data_len, digest, &digest_len), CKR_OK, "DIGEST");
    asrt(digest_len, hdata_len, "DIGEST LEN");
    asrt(memcmp(hdata, digest, digest_len), 0, "DIGEST VALUE");

    digest_update_len = sizeof(digest_update);
    asrt(funcs->C_DigestInit(session, &mech), CKR_OK, "DIGEST INIT");
    asrt(funcs->C_DigestUpdate(session, data, 10), CKR_OK, "DIGEST UPDATE");
    asrt(funcs->C_DigestUpdate(session, data+10, 22), CKR_OK, "DIGEST UPDATE");
    asrt(funcs->C_DigestFinal(session, digest_update, &digest_update_len), CKR_OK, "DIGEST FINAL");
    asrt(digest_update_len, hdata_len, "DIGEST LEN");
    asrt(memcmp(hdata, digest_update, digest_update_len), 0, "DIGEST VALUE");
  }
}

EC_KEY* import_ec_key(CK_FUNCTION_LIST_PTR funcs, CK_SESSION_HANDLE session, CK_BYTE n_keys, int curve, CK_ULONG key_len, 
                      CK_BYTE* ec_params, CK_ULONG ec_params_len, CK_OBJECT_HANDLE_PTR obj_cert, CK_OBJECT_HANDLE_PTR obj_pvtkey) {
  EVP_PKEY       *evp;
  EC_KEY         *eck;
  const BIGNUM   *bn;
  CK_CHAR        pvt[key_len];
  X509           *cert;
  ASN1_TIME      *tm;
  CK_BYTE        i, j;

  CK_ULONG    class_k = CKO_PRIVATE_KEY;
  CK_ULONG    class_c = CKO_CERTIFICATE;
  CK_ULONG    kt = CKK_ECDSA;
  CK_BYTE     id = 0;
  CK_BYTE     value_c[3100];
  CK_ULONG    cert_len;

  unsigned char  *p;

  CK_ATTRIBUTE privateKeyTemplate[] = {
    {CKA_CLASS, &class_k, sizeof(class_k)},
    {CKA_KEY_TYPE, &kt, sizeof(kt)},
    {CKA_ID, &id, sizeof(id)},
    {CKA_EC_PARAMS, ec_params, ec_params_len},
    {CKA_VALUE, pvt, sizeof(pvt)}
  };

  CK_ATTRIBUTE publicKeyTemplate[] = {
    {CKA_CLASS, &class_c, sizeof(class_c)},
    {CKA_ID, &id, sizeof(id)},
    {CKA_VALUE, value_c, sizeof(value_c)}
  };

  evp = EVP_PKEY_new();

  if (evp == NULL)
    exit(EXIT_FAILURE);

  eck = EC_KEY_new_by_curve_name(curve);

  if (eck == NULL)
    exit(EXIT_FAILURE);

  asrt(EC_KEY_generate_key(eck), 1, "GENERATE ECK");

  bn = EC_KEY_get0_private_key(eck);

  asrt(BN_bn2bin(bn, pvt), key_len, "EXTRACT PVT");

  if (EVP_PKEY_set1_EC_KEY(evp, eck) == 0)
    exit(EXIT_FAILURE);

  cert = X509_new();

  if (cert == NULL)
    exit(EXIT_FAILURE);

  X509_set_version(cert, 2); // Version 3
  X509_NAME_add_entry_by_txt(X509_get_issuer_name(cert), "CN", MBSTRING_ASC, (unsigned char*)"Test Issuer", -1, -1, 0);
  X509_NAME_add_entry_by_txt(X509_get_subject_name(cert), "CN", MBSTRING_ASC, (unsigned char*)"Test Subject", -1, -1, 0);
  ASN1_INTEGER_set(X509_get_serialNumber(cert), 0);
  X509_gmtime_adj(X509_get_notBefore(cert), 0);
  X509_gmtime_adj(X509_get_notAfter(cert), 0);

  if (X509_set_pubkey(cert, evp) == 0)
    exit(EXIT_FAILURE);

  if (X509_sign(cert, evp, EVP_sha1()) == 0)
    exit(EXIT_FAILURE);

  p = value_c;
  if ((cert_len = (CK_ULONG) i2d_X509(cert, &p)) == 0 || cert_len > sizeof(value_c))
    exit(EXIT_FAILURE);

  publicKeyTemplate[2].ulValueLen = cert_len;

  asrt(funcs->C_Login(session, CKU_SO, (CK_CHAR_PTR)"010203040506070801020304050607080102030405060708", 48), CKR_OK, "Login SO");

  for (i = 0; i < n_keys; i++) {
    id = i+1;
    asrt(funcs->C_CreateObject(session, publicKeyTemplate, 3, obj_cert + i), CKR_OK, "IMPORT CERT");
    asrt(obj_cert[i], 37+i, "CERTIFICATE HANDLE");
    asrt(funcs->C_CreateObject(session, privateKeyTemplate, 5, obj_pvtkey + i), CKR_OK, "IMPORT KEY");
    asrt(obj_pvtkey[i], 86+i, "PRIVATE KEY HANDLE");
  }

  asrt(funcs->C_Logout(session), CKR_OK, "Logout SO");

  return eck;
}

void import_rsa_key(CK_FUNCTION_LIST_PTR funcs, CK_SESSION_HANDLE session, int keylen, EVP_PKEY* evp, RSA* rsak,
                    CK_BYTE n_keys, CK_OBJECT_HANDLE_PTR obj_cert, CK_OBJECT_HANDLE_PTR obj_pvtkey) {
  X509        *cert;
  ASN1_TIME   *tm;
  CK_BYTE     i, j;
  CK_BYTE     e[] = {0x01, 0x00, 0x01};
  CK_BYTE     p[keylen / 16];
  CK_BYTE     q[keylen / 16];
  CK_BYTE     dp[keylen / 16];
  CK_BYTE     dq[keylen / 16];
  CK_BYTE     qinv[keylen / 16];
  BIGNUM      *e_bn;
  CK_ULONG    class_k = CKO_PRIVATE_KEY;
  CK_ULONG    class_c = CKO_CERTIFICATE;
  CK_ULONG    kt = CKK_RSA;
  CK_BYTE     id = 0;
  CK_BYTE     value_c[3100];
  CK_ULONG    cert_len;
  const BIGNUM *bp, *bq, *biqmp, *bdmp1, *bdmq1;

  unsigned char  *px;
  int p_len, q_len, dp_len, dq_len, qinv_len;
  int len = keylen/16;

  CK_ATTRIBUTE privateKeyTemplate[] = {
    {CKA_CLASS, &class_k, sizeof(class_k)},
    {CKA_KEY_TYPE, &kt, sizeof(kt)},
    {CKA_ID, &id, sizeof(id)},
    {CKA_PUBLIC_EXPONENT, e, sizeof(e)},
    {CKA_PRIME_1, p, sizeof(p)},
    {CKA_PRIME_2, q, sizeof(q)},
    {CKA_EXPONENT_1, dp, sizeof(dp)},
    {CKA_EXPONENT_2, dq, sizeof(dq)},
    {CKA_COEFFICIENT, qinv, sizeof(qinv)}
  };

  CK_ATTRIBUTE publicKeyTemplate[] = {
    {CKA_CLASS, &class_c, sizeof(class_c)},
    {CKA_ID, &id, sizeof(id)},
    {CKA_VALUE, value_c, sizeof(value_c)}
  };

  int len_correct = 0;

  e_bn = BN_bin2bn(e, 3, NULL);
  if (e_bn == NULL)
    exit(EXIT_FAILURE);

  do {
    asrt(RSA_generate_key_ex(rsak, keylen, e_bn, NULL), 1, "GENERATE RSAK");

    RSA_get0_factors(rsak, &bp, &bq);
    RSA_get0_crt_params(rsak, &bdmp1, &bdmq1, &biqmp);
    p_len = BN_bn2bin(bp, p);
    q_len = BN_bn2bin(bq, q);
    dp_len = BN_bn2bin(bdmp1, dp);
    dq_len = BN_bn2bin(bdmq1, dq);
    qinv_len = BN_bn2bin(biqmp, qinv);
    len_correct = p_len == len && q_len == len && dp_len == len && dq_len == len && qinv_len == len; 
  } while(!len_correct);


  if (EVP_PKEY_set1_RSA(evp, rsak) == 0)
    exit(EXIT_FAILURE);

  cert = X509_new();

  if (cert == NULL)
    exit(EXIT_FAILURE);

  X509_set_version(cert, 2); // Version 3
  X509_NAME_add_entry_by_txt(X509_get_issuer_name(cert), "CN", MBSTRING_ASC, (unsigned char*)"Test Issuer", -1, -1, 0);
  X509_NAME_add_entry_by_txt(X509_get_subject_name(cert), "CN", MBSTRING_ASC, (unsigned char*)"Test Subject", -1, -1, 0);
  ASN1_INTEGER_set(X509_get_serialNumber(cert), 0);
  X509_gmtime_adj(X509_get_notBefore(cert), 0);
  X509_gmtime_adj(X509_get_notAfter(cert), 0);

  if (X509_set_pubkey(cert, evp) == 0)
    exit(EXIT_FAILURE);

  if (X509_sign(cert, evp, EVP_sha1()) == 0)
    exit(EXIT_FAILURE);

  px = value_c;
  if ((cert_len = (CK_ULONG) i2d_X509(cert, &px)) == 0 || cert_len > sizeof(value_c))
    exit(EXIT_FAILURE);

  publicKeyTemplate[2].ulValueLen = cert_len;

  asrt(funcs->C_Login(session, CKU_SO, (CK_CHAR_PTR)"010203040506070801020304050607080102030405060708", 48), CKR_OK, "Login SO");

  for (i = 0; i < n_keys; i++) {
    id = i+1;
    asrt(funcs->C_CreateObject(session, publicKeyTemplate, 3, obj_cert + i), CKR_OK, "IMPORT CERT");
    asrt(obj_cert[i], 37+i, "CERTIFICATE HANDLE");
    asrt(funcs->C_CreateObject(session, privateKeyTemplate, 9, obj_pvtkey + i), CKR_OK, "IMPORT KEY");
    asrt(obj_pvtkey[i], 86+i, "PRIVATE KEY HANDLE");
  }

  asrt(funcs->C_Logout(session), CKR_OK, "Logout SO");

  evp = X509_get_pubkey(cert);
}

void generate_ec_keys(CK_FUNCTION_LIST_PTR funcs, CK_SESSION_HANDLE session, CK_BYTE n_keys,
                      CK_BYTE* ec_params, CK_ULONG ec_params_len, 
                      CK_OBJECT_HANDLE_PTR obj_pubkey, CK_OBJECT_HANDLE_PTR obj_pvtkey) {
  CK_BYTE     i;
  CK_ULONG    class_k = CKO_PRIVATE_KEY;
  CK_ULONG    class_c = CKO_PUBLIC_KEY;
  CK_ULONG    kt = CKK_ECDSA;
  CK_BYTE     id = 0;

  CK_ATTRIBUTE privateKeyTemplate[] = {
    {CKA_CLASS, &class_k, sizeof(class_k)},
    {CKA_KEY_TYPE, &kt, sizeof(kt)},
    {CKA_ID, &id, sizeof(id)}
  };

  CK_ATTRIBUTE publicKeyTemplate[] = {
    {CKA_CLASS, &class_c, sizeof(class_c)},
    {CKA_ID, &id, sizeof(id)},
    {CKA_EC_PARAMS, ec_params, ec_params_len}
  };

  CK_MECHANISM mech = {CKM_EC_KEY_PAIR_GEN, NULL, 0};

  asrt(funcs->C_Login(session, CKU_SO, (CK_CHAR_PTR)"010203040506070801020304050607080102030405060708", 48), CKR_OK, "Login SO");

  for (i = 0; i < n_keys; i++) {
    id = i+1;
    asrt(funcs->C_GenerateKeyPair(session, &mech, publicKeyTemplate, 3, privateKeyTemplate, 3, obj_pubkey+i, obj_pvtkey+i), CKR_OK, "GEN RSA KEYPAIR");
    asrt(obj_pubkey[i], 111+i, "PUBLIC KEY HANDLE");
    asrt(obj_pvtkey[i], 86+i, "PRIVATE KEY HANDLE");
  }
  asrt(funcs->C_Logout(session), CKR_OK, "Logout SO");
}

void generate_rsa_keys(CK_FUNCTION_LIST_PTR funcs, CK_SESSION_HANDLE session, CK_ULONG key_size, CK_BYTE n_keys,
                      CK_OBJECT_HANDLE_PTR obj_pubkey, CK_OBJECT_HANDLE_PTR obj_pvtkey) {
  CK_BYTE     i, j;
  CK_BYTE     e[] = {0x01, 0x00, 0x01};
  CK_ULONG    class_k = CKO_PRIVATE_KEY;
  CK_ULONG    class_c = CKO_PUBLIC_KEY;
  CK_ULONG    kt = CKK_RSA;
  CK_BYTE     id = 0;

  CK_ATTRIBUTE privateKeyTemplate[] = {
    {CKA_CLASS, &class_k, sizeof(class_k)},
    {CKA_KEY_TYPE, &kt, sizeof(kt)},
    {CKA_ID, &id, sizeof(id)}
  };

  CK_ATTRIBUTE publicKeyTemplate[] = {
    {CKA_CLASS, &class_c, sizeof(class_c)},
    {CKA_ID, &id, sizeof(id)},
    {CKA_MODULUS_BITS, &key_size, sizeof(key_size)},
    {CKA_PUBLIC_EXPONENT, e, sizeof(e)}
  };

  CK_MECHANISM mech = {CKM_RSA_PKCS_KEY_PAIR_GEN, NULL, 0};

  asrt(funcs->C_Login(session, CKU_SO, (CK_CHAR_PTR)"010203040506070801020304050607080102030405060708", 48), CKR_OK, "Login SO");
  for (i = 0; i < n_keys; i++) {
    id = i+1;
    asrt(funcs->C_GenerateKeyPair(session, &mech, publicKeyTemplate, 4, privateKeyTemplate, 3, obj_pubkey+i, obj_pvtkey+i), CKR_OK, "GEN RSA KEYPAIR");
    asrt(obj_pubkey[i], 111+i, "PUBLIC KEY HANDLE");
    asrt(obj_pvtkey[i], 86+i, "PRIVATE KEY HANDLE");
  }
  asrt(funcs->C_Logout(session), CKR_OK, "Logout SO");
}

static void construct_der_encoded_sig(CK_BYTE sig[], CK_BYTE_PTR der_encoded, CK_ULONG key_len) {
    CK_ULONG    der_encoded_len;
    CK_BYTE_PTR der_ptr;
    CK_BYTE_PTR r_ptr;
    CK_BYTE_PTR s_ptr;
    CK_ULONG    r_len;
    CK_ULONG    s_len;
    const EVP_MD *md;
    EVP_MD_CTX *mdctx;

      r_len = key_len;
      s_len = key_len;

      der_ptr = der_encoded;
      *der_ptr++ = 0x30;
      *der_ptr++ = 0xff; // placeholder, fix below

      r_ptr = sig;

      *der_ptr++ = 0x02;
      *der_ptr++ = r_len;
      if (*r_ptr >= 0x80) {
        *(der_ptr - 1) = *(der_ptr - 1) + 1;
        *der_ptr++ = 0x00;
      }
      else if (*r_ptr == 0x00 && *(r_ptr + 1) < 0x80) {
        r_len--;
        *(der_ptr - 1) = *(der_ptr - 1) - 1;
        r_ptr++;
      }
      memcpy(der_ptr, r_ptr, r_len);
      der_ptr+= r_len;

      s_ptr = sig + key_len;

      *der_ptr++ = 0x02;
      *der_ptr++ = s_len;
      if (*s_ptr >= 0x80) {
        *(der_ptr - 1) = *(der_ptr - 1) + 1;
        *der_ptr++ = 0x00;
      }
      else if (*s_ptr == 0x00 && *(s_ptr + 1) < 0x80) {
        s_len--;
        *(der_ptr - 1) = *(der_ptr - 1) - 1;
        s_ptr++;
      }
      memcpy(der_ptr, s_ptr, s_len);
      der_ptr+= s_len;

      der_encoded[1] = der_ptr - der_encoded - 2;
}

void test_ec_sign_simple(CK_FUNCTION_LIST_PTR funcs, CK_SESSION_HANDLE session, CK_OBJECT_HANDLE_PTR obj_pvtkey, 
                         CK_BYTE n_keys, EC_KEY *eck, CK_ULONG key_len) {
                    
  CK_BYTE     i;
  CK_BYTE     data[32];
  CK_ULONG    data_len;
  CK_BYTE     sig[256];
  CK_ULONG    recv_len;

  CK_BYTE     der_encoded[116];

  CK_MECHANISM mech = {CKM_ECDSA, NULL, 0};

  asrt(funcs->C_Login(session, CKU_USER, (CK_CHAR_PTR)"123456", 6), CKR_OK, "Login USER");

  data_len = sizeof(data);
  for (i = 0; i < n_keys; i++) {
    if(RAND_bytes(data, data_len) <= 0)
      exit(EXIT_FAILURE);

    asrt(funcs->C_SignInit(session, &mech, obj_pvtkey[i]), CKR_OK, "SignInit");
    asrt(funcs->C_Login(session, CKU_CONTEXT_SPECIFIC, (CK_CHAR_PTR)"123456", 6), CKR_OK, "Re-Login USER");
    recv_len = sizeof(sig);
    asrt(funcs->C_Sign(session, data, sizeof(data), sig, &recv_len), CKR_OK, "Sign");

    if(eck != NULL) {
      // External verification
      construct_der_encoded_sig(sig, der_encoded, key_len);
      asrt(ECDSA_verify(0, data, data_len, der_encoded, der_encoded[1] + 2, eck), 1, "ECDSA VERIFICATION");
    } else {
      // Internal verification
      asrt(funcs->C_VerifyInit(session, &mech, get_public_key_handle(funcs, session, obj_pvtkey[i])), CKR_OK, "VerifyInit");
      asrt(funcs->C_Verify(session, data, sizeof(data), sig, recv_len), CKR_OK, "Verify");
    }
  }
  asrt(funcs->C_Logout(session), CKR_OK, "Logout USER");  
}

void test_ec_sign_thorough(CK_FUNCTION_LIST_PTR funcs, CK_SESSION_HANDLE session, CK_OBJECT_HANDLE_PTR obj_pvtkey, 
                           CK_MECHANISM_TYPE mech_type, EC_KEY *eck, CK_ULONG key_len) {
                    
  CK_BYTE     i, j;
  CK_BYTE     data[32];
  CK_ULONG    data_len;
  CK_BYTE     hdata[64];
  unsigned int    hdata_len;  
  CK_BYTE     sig[256];
  CK_ULONG    sig_len;
  CK_BYTE     sig_update[256];
  CK_ULONG    sig_update_len;

  CK_BYTE     der_encoded[116];
  const EVP_MD *md;
  EVP_MD_CTX *mdctx;

  CK_OBJECT_HANDLE obj_pubkey;
  CK_MECHANISM mech = {mech_type, NULL, 0};

  asrt(funcs->C_Login(session, CKU_USER, (CK_CHAR_PTR)"123456", 6), CKR_OK, "Login USER");

  for (i = 0; i < 4; i++) {
    obj_pubkey = get_public_key_handle(funcs, session, obj_pvtkey[i]);
    for (j = 0; j < 4; j++) {
      if(RAND_bytes(data, sizeof(data)) <= 0)
        exit(EXIT_FAILURE);
      data_len = sizeof(data);

      // Sign
      asrt(funcs->C_SignInit(session, &mech, obj_pvtkey[i]), CKR_OK, "SignInit");
      asrt(funcs->C_Login(session, CKU_CONTEXT_SPECIFIC, (CK_CHAR_PTR)"123456", 6), CKR_OK, "Re-Login USER");
      sig_len = sizeof(sig);
      asrt(funcs->C_Sign(session, data, sizeof(data), sig, &sig_len), CKR_OK, "Sign");
      //Verify
      asrt(funcs->C_VerifyInit(session, &mech, obj_pubkey), CKR_OK, "VerifyInit");
      asrt(funcs->C_Verify(session, data, sizeof(data), sig, sig_len), CKR_OK, "Verify");

      // External verification
      if(eck != NULL) {
        if(mech_type == CKM_ECDSA) {
          memcpy(hdata, data, data_len);
          hdata_len = data_len;
        } else if(mech_type == CKM_ECDSA_SHA384) {
          SHA384(data, data_len, hdata);
          hdata_len = 48;
        } else {
          md = get_md_type(mech_type);
          mdctx = EVP_MD_CTX_create();
          EVP_DigestInit_ex(mdctx, md, NULL);
          EVP_DigestUpdate(mdctx, data, data_len);
          EVP_DigestFinal_ex(mdctx, hdata, &hdata_len);
        }

        construct_der_encoded_sig(sig, der_encoded, key_len);

        asrt(ECDSA_verify(0, hdata, hdata_len, der_encoded, der_encoded[1] + 2, eck), 1, "ECDSA VERIFICATION");
      }
    }
  }
  asrt(funcs->C_Logout(session), CKR_OK, "Logout USER");  
}

void test_rsa_sign_simple(CK_FUNCTION_LIST_PTR funcs, CK_SESSION_HANDLE session, CK_OBJECT_HANDLE_PTR obj_pvtkey, 
                          CK_BYTE n_keys, EVP_PKEY* evp) {
  CK_BYTE     i, j;
  CK_BYTE     data[32];
  CK_BYTE     sig[256];
  CK_BYTE     sig_update[256];
  CK_ULONG    sig_len;
  CK_ULONG    sig_update_len;
  EVP_PKEY_CTX *ctx = NULL;

  CK_BYTE     hdata[512];
  CK_ULONG    hdata_len;

  CK_OBJECT_HANDLE obj_pubkey;
  CK_MECHANISM mech = {CKM_RSA_PKCS, NULL, 0};

  asrt(funcs->C_Login(session, CKU_USER, (CK_CHAR_PTR)"123456", 6), CKR_OK, "LOGIN USER");

  for (i = 0; i < n_keys; i++) {
    obj_pubkey = get_public_key_handle(funcs, session, obj_pvtkey[i]);    
    
    if(RAND_bytes(data, sizeof(data)) <= 0)
      exit(EXIT_FAILURE);

    // Sign
    asrt(funcs->C_SignInit(session, &mech, obj_pvtkey[i]), CKR_OK, "SIGN INIT");
    asrt(funcs->C_Login(session, CKU_CONTEXT_SPECIFIC, (CK_CHAR_PTR)"123456", 6), CKR_OK, "Re-Login USER");
    sig_len = sizeof(sig);
    asrt(funcs->C_Sign(session, data, sizeof(data), sig, &sig_len), CKR_OK, "SIGN");

    if(evp != NULL) {
      // External verification
      ctx = EVP_PKEY_CTX_new(evp, NULL);
      asrt(ctx != NULL, 1, "EVP_KEY_CTX_new");
      asrt(EVP_PKEY_verify_init(ctx) > 0, 1, "EVP_KEY_verify_init");
      asrt(EVP_PKEY_CTX_set_signature_md(ctx, NULL) > 0, 1, "EVP_PKEY_CTX_set_signature_md");
      asrt(EVP_PKEY_verify(ctx, sig, sig_len, data, 32), 1, "EVP_PKEY_verify");
    } else {
      // Internal verification: Verify
      asrt(funcs->C_VerifyInit(session, &mech, obj_pubkey), CKR_OK, "VERIFY INIT");
      asrt(funcs->C_Verify(session, data, sizeof(data), sig, sig_len), CKR_OK, "VERIFY"); 
    }
  }

  asrt(funcs->C_Logout(session), CKR_OK, "Logout USER");
}

void test_rsa_sign_thorough(CK_FUNCTION_LIST_PTR funcs, CK_SESSION_HANDLE session, CK_OBJECT_HANDLE_PTR obj_pvtkey, 
                            CK_BYTE n_keys, EVP_PKEY* evp, CK_MECHANISM_TYPE mech_type) {
  CK_BYTE     i, j;
  CK_BYTE     data[32];
  CK_BYTE     sig[256];
  CK_BYTE     sig_update[256];
  CK_ULONG    sig_len;
  CK_ULONG    sig_update_len;
  EVP_PKEY_CTX *ctx = NULL;

  CK_BYTE     hdata[512];
  CK_ULONG    hdata_len;

  CK_OBJECT_HANDLE obj_pubkey;
  CK_MECHANISM mech = {mech_type, NULL, 0};

  asrt(funcs->C_Login(session, CKU_USER, (CK_CHAR_PTR)"123456", 6), CKR_OK, "LOGIN USER");

  for (i = 0; i < n_keys; i++) {
    obj_pubkey = get_public_key_handle(funcs, session, obj_pvtkey[i]);    
    for (j = 0; j < 4; j++) {

      if(RAND_bytes(data, sizeof(data)) <= 0)
        exit(EXIT_FAILURE);

      // Sign
      asrt(funcs->C_SignInit(session, &mech, obj_pvtkey[i]), CKR_OK, "SIGN INIT");
      asrt(funcs->C_Login(session, CKU_CONTEXT_SPECIFIC, (CK_CHAR_PTR)"123456", 6), CKR_OK, "Re-Login USER");
      sig_len = sizeof(sig);
      asrt(funcs->C_Sign(session, data, sizeof(data), sig, &sig_len), CKR_OK, "SIGN");

      // External verification
      if(evp != NULL) {
        asrt(get_digest(mech_type, data, sizeof(data), hdata, &hdata_len), CKR_OK, "GET DIGEST");
        ctx = EVP_PKEY_CTX_new(evp, NULL);
        asrt(ctx != NULL, 1, "EVP_KEY_CTX_new");
        asrt(EVP_PKEY_verify_init(ctx) > 0, 1, "EVP_KEY_verify_init");
        asrt(EVP_PKEY_CTX_set_signature_md(ctx, NULL) > 0, 1, "EVP_PKEY_CTX_set_signature_md");
        asrt(EVP_PKEY_verify(ctx, sig, sig_len, hdata, hdata_len), 1, "EVP_PKEY_verify");
      }
      
      // Internal verification: Verify
      asrt(funcs->C_VerifyInit(session, &mech, obj_pubkey), CKR_OK, "VERIFY INIT");
      asrt(funcs->C_Verify(session, data, sizeof(data), sig, sig_len), CKR_OK, "VERIFY");

      // Sign Update
      asrt(funcs->C_SignInit(session, &mech, obj_pvtkey[i]), CKR_OK, "SIGN INIT");
      asrt(funcs->C_Login(session, CKU_CONTEXT_SPECIFIC, (CK_CHAR_PTR)"123456", 6), CKR_OK, "Re-Login USER");
      sig_update_len = sizeof(sig_update);
      asrt(funcs->C_SignUpdate(session, data, 16), CKR_OK, "SIGN UPDATE 1");
      asrt(funcs->C_SignUpdate(session, data + 16, 10), CKR_OK, "SIGN UPDATE 2");
      asrt(funcs->C_SignUpdate(session, data + 26, 6), CKR_OK, "SIGN UPDATE 3");
      asrt(funcs->C_SignFinal(session, sig_update, &sig_update_len), CKR_OK, "SIGN FINAL");
      asrt(sig_update_len, sig_len, "SIGNATURE LENGTH");
      // Compare signatures
      asrt(memcmp(sig, sig_update, sig_len), 0, "SIGNATURE");

      // Internal verification: Verify Update
      asrt(funcs->C_VerifyInit(session, &mech, obj_pubkey), CKR_OK, "VERIFY INIT");
      asrt(funcs->C_VerifyUpdate(session, data, 10), CKR_OK, "VERIFY UPDATE 1");
      asrt(funcs->C_VerifyUpdate(session, data+10, 22), CKR_OK, "VERIFY UPDATE 2");
      asrt(funcs->C_VerifyFinal(session, sig_update, sig_update_len), CKR_OK, "VERIFY FINAL");     
    }
  }

  asrt(funcs->C_Logout(session), CKR_OK, "Logout USER");
}

void test_rsa_sign_pss(CK_FUNCTION_LIST_PTR funcs, CK_SESSION_HANDLE session, CK_OBJECT_HANDLE_PTR obj_pvtkey, 
                       CK_BYTE n_keys, RSA* rsak, CK_MECHANISM_TYPE mech_type) {
  CK_BYTE     i, j;
  CK_BYTE*    data;
  CK_BYTE     sig[256];
  CK_BYTE     sig_update[256];
  CK_ULONG    sig_len;
  CK_ULONG    sig_update_len;

  CK_BYTE*     pss_buf;
  CK_BYTE      digest_data[256];
  unsigned int digest_data_len = sizeof(digest_data);
  EVP_MD_CTX   *md_ctx;

  CK_OBJECT_HANDLE obj_pubkey;

  CK_RSA_PKCS_PSS_PARAMS pss_params = {get_md_of(mech_type), get_md_of(mech_type), EVP_MD_size(get_md_type(get_md_of(mech_type)))};
  CK_MECHANISM mech = {mech_type, &pss_params, sizeof(pss_params)};

  data = malloc(pss_params.sLen);

  asrt(funcs->C_Login(session, CKU_USER, (CK_CHAR_PTR)"123456", 6), CKR_OK, "LOGIN USER");

  for (i = 0; i < n_keys; i++) {
    obj_pubkey = get_public_key_handle(funcs, session, obj_pvtkey[i]);    
    for (j = 0; j < 4; j++) {

      if(RAND_bytes(data, pss_params.sLen) <= 0)
        exit(EXIT_FAILURE);

      // Sign
      asrt(funcs->C_SignInit(session, &mech, obj_pvtkey[i]), CKR_OK, "SIGN INIT");
      asrt(funcs->C_Login(session, CKU_CONTEXT_SPECIFIC, (CK_CHAR_PTR)"123456", 6), CKR_OK, "Re-Login USER");
      sig_len = sizeof(sig);
      asrt(funcs->C_Sign(session, data, pss_params.sLen, sig, &sig_len), CKR_OK, "SIGN");

      // External verification
      if(rsak != NULL) {
        pss_buf = malloc(sig_len);
        asrt(RSA_public_decrypt(sig_len, sig, pss_buf, rsak, RSA_NO_PADDING), sig_len, "DECRYPT PSS SIGNATURE");

        if(mech_type == CKM_RSA_PKCS_PSS) {
          asrt(RSA_verify_PKCS1_PSS_mgf1(rsak, data, get_md_type(pss_params.hashAlg), get_md_type(pss_params.mgf), pss_buf, pss_params.sLen), 1, "VERIFY PSS SIGNATURE");  
        } else {
          md_ctx = EVP_MD_CTX_create();
          asrt(EVP_DigestInit_ex(md_ctx, get_md_type(mech_type), NULL), 1, "DIGEST INIT");
          asrt(EVP_DigestUpdate(md_ctx, data, pss_params.sLen), 1, "DIGEST UPDATE");
          asrt(EVP_DigestFinal_ex(md_ctx, digest_data, &digest_data_len), 1, "DIGEST FINAL");

          asrt(RSA_verify_PKCS1_PSS_mgf1(rsak, digest_data, get_md_type(pss_params.hashAlg), get_md_type(pss_params.mgf), pss_buf, pss_params.sLen), 1, "VERIFY PSS SIGNATURE");
        }
        free(pss_buf);
      }
      
      // Internal verification: Verify
      asrt(funcs->C_VerifyInit(session, &mech, obj_pubkey), CKR_OK, "VERIFY INIT");
      asrt(funcs->C_Verify(session, data, pss_params.sLen, sig, sig_len), CKR_OK, "VERIFY");

      // Sign Update
      asrt(funcs->C_SignInit(session, &mech, obj_pvtkey[i]), CKR_OK, "SIGN INIT");
      asrt(funcs->C_Login(session, CKU_CONTEXT_SPECIFIC, (CK_CHAR_PTR)"123456", 6), CKR_OK, "Re-Login USER");
      sig_update_len = sizeof(sig_update);
      asrt(funcs->C_SignUpdate(session, data, 10), CKR_OK, "SIGN UPDATE 1");
      asrt(funcs->C_SignUpdate(session, data + 10, pss_params.sLen - 10), CKR_OK, "SIGN UPDATE 2");
      asrt(funcs->C_SignFinal(session, sig_update, &sig_update_len), CKR_OK, "SIGN FINAL");
      asrt(sig_update_len, sig_len, "SIGNATURE LENGTH");


      // External verification
      if(rsak != NULL) {
        pss_buf = malloc(sig_update_len);
        asrt(RSA_public_decrypt(sig_update_len, sig_update, pss_buf, rsak, RSA_NO_PADDING), sig_update_len, "DECRYPT PSS SIGNATURE");

        if(mech_type == CKM_RSA_PKCS_PSS) {
          asrt(RSA_verify_PKCS1_PSS_mgf1(rsak, data, get_md_type(pss_params.hashAlg), get_md_type(pss_params.mgf), pss_buf, pss_params.sLen), 1, "VERIFY PSS SIGNATURE");  
        } else {
          md_ctx = EVP_MD_CTX_create();
          asrt(EVP_DigestInit_ex(md_ctx, get_md_type(mech_type), NULL), 1, "DIGEST INIT");
          asrt(EVP_DigestUpdate(md_ctx, data, pss_params.sLen), 1, "DIGEST UPDATE");
          asrt(EVP_DigestFinal_ex(md_ctx, digest_data, &digest_data_len), 1, "DIGEST FINAL");

          asrt(RSA_verify_PKCS1_PSS_mgf1(rsak, digest_data, get_md_type(pss_params.hashAlg), get_md_type(pss_params.mgf), pss_buf, pss_params.sLen), 1, "VERIFY PSS SIGNATURE");
        }
        free(pss_buf);
      }

      // Internal verification: Verify Update
      asrt(funcs->C_VerifyInit(session, &mech, obj_pubkey), CKR_OK, "VERIFY INIT");
      asrt(funcs->C_VerifyUpdate(session, data, 5), CKR_OK, "VERIFY UPDATE 1");
      asrt(funcs->C_VerifyUpdate(session, data+5, pss_params.sLen-5), CKR_OK, "VERIFY UPDATE 2");
      asrt(funcs->C_VerifyFinal(session, sig_update, sig_update_len), CKR_OK, "VERIFY FINAL");     
    
    }
  }
  free(data);
  asrt(funcs->C_Logout(session), CKR_OK, "Logout USER");
}

static int is_data_too_large(int enc_ret) {
  if(enc_ret != -1) {
    return 0;
  }

  unsigned long err;
  ERR_load_crypto_strings();
  err = ERR_get_error();
  //char err_str[128];  
  //ERR_error_string_n(err, err_str, 128);
  //printf("%ld    %s\n", err, err_str);
  if(err == 67534980) { // Error code for "data too large for modulus"
    return 1;
  }
  return 0;
}

void test_rsa_decrypt(CK_FUNCTION_LIST_PTR funcs, CK_SESSION_HANDLE session, CK_OBJECT_HANDLE_PTR obj_pvtkey, 
                      CK_BYTE n_keys, RSA* rsak, CK_MECHANISM_TYPE mech_type, CK_ULONG padding) {
  CK_ULONG  i, j;
  int       data_len, enc_len;
  CK_BYTE*  data;
  CK_BYTE   enc[512];
  CK_BYTE   dec[512];
  CK_ULONG  dec_len;

  if(padding == RSA_NO_PADDING) {
    data_len = RSA_size(rsak);
  } else {
    data_len = 32;
  }
  data = malloc(data_len);

  CK_RSA_PKCS_OAEP_PARAMS params = {0};
  CK_MECHANISM mech = {mech_type, &params, sizeof(params)};
  asrt(funcs->C_Login(session, CKU_USER, (CK_CHAR_PTR)"123456", 6), CKR_OK, "Login USER");

  for (i = 0; i < n_keys; i++) {
    for (j = 0; j < 4; j++) {
      // This is because the numerical value of the clear data cannot be larger than the numerical value of the RSA key modulus
      // Adding a padding takes care of this, but with RSA_NO_PADDING, we need to deal with that manually
      do {
        if(RAND_bytes(data, data_len) <= 0)
          exit(EXIT_FAILURE);

        enc_len = RSA_public_encrypt(data_len, data, enc, rsak, padding);
      } while(is_data_too_large(enc_len) == 1);

      // Decrypt
      asrt(funcs->C_DecryptInit(session, &mech, obj_pvtkey[i]), CKR_OK, "DECRYPT INIT");
      asrt(funcs->C_Login(session, CKU_CONTEXT_SPECIFIC, (CK_CHAR_PTR)"123456", 6), CKR_OK, "Re-Login USER");
      dec_len = sizeof(dec);
      asrt(funcs->C_Decrypt(session, enc, enc_len, dec, &dec_len), CKR_OK, "DECRYPT");
      asrt(dec_len, data_len, "DECRYPTED DATA LEN");
      asrt(memcmp(data, dec, dec_len), 0, "DECRYPTED DATA");

      // Decrypt Update
      asrt(funcs->C_DecryptInit(session, &mech, obj_pvtkey[i]), CKR_OK, "DECRYPT INIT");
      asrt(funcs->C_Login(session, CKU_CONTEXT_SPECIFIC, (CK_CHAR_PTR)"123456", 6), CKR_OK, "Re-Login USER");
      dec_len = sizeof(dec);
      asrt(funcs->C_DecryptUpdate(session, enc, 100, dec, &dec_len), CKR_OK, "DECRYPT UPDATE");
      dec_len = sizeof(dec);
      asrt(funcs->C_DecryptUpdate(session, enc+100, 8, dec, &dec_len), CKR_OK, "DECRYPT UPDATE");
      dec_len = sizeof(dec);
      asrt(funcs->C_DecryptUpdate(session, enc+108, 20, dec, &dec_len), CKR_OK, "DECRYPT UPDATE");
      dec_len = sizeof(dec);
      asrt(funcs->C_DecryptFinal(session, dec, &dec_len), CKR_OK, "DECRYPT FINAL");
      asrt(dec_len, data_len, "DECRYPTED DATA LEN");
      asrt(memcmp(data, dec, dec_len), 0, "DECRYPTED DATA");
    }
  }
  free(data);
  asrt(funcs->C_Logout(session), CKR_OK, "Logout USER");
}

void test_rsa_decrypt_oaep(CK_FUNCTION_LIST_PTR funcs, CK_SESSION_HANDLE session, CK_OBJECT_HANDLE_PTR obj_pvtkey, 
                           CK_BYTE n_keys, CK_MECHANISM_TYPE mdhash,  RSA* rsak) {
  CK_ULONG  i, j;
  int       data_len;
  CK_BYTE   data[32];
  CK_BYTE   padded_data[512];
  CK_BYTE   padded_data_len;
  CK_BYTE   enc[512];
  CK_BYTE   dec[512];
  CK_ULONG  dec_len;
  size_t    enc_len;
  const EVP_MD *md;

  CK_RSA_PKCS_OAEP_PARAMS params = {mdhash, mdhash, 0, NULL, 0};
  CK_MECHANISM mech = {CKM_RSA_PKCS_OAEP, &params, sizeof(params)};

  data_len = sizeof(data);
  padded_data_len = RSA_size(rsak);
  md = get_md_type(mdhash);

  asrt(funcs->C_Login(session, CKU_USER, (CK_CHAR_PTR)"123456", 6), CKR_OK, "Login USER");


  for (i = 0; i < n_keys; i++) {
    for (j = 0; j < 4; j++) {

      if(RAND_bytes(data, data_len) <= 0)
        exit(EXIT_FAILURE);

      RSA_padding_add_PKCS1_OAEP_mgf1(padded_data, padded_data_len, data, data_len, 
					                            NULL, 0, md, md);
       enc_len = RSA_public_encrypt(padded_data_len, padded_data, enc, rsak, RSA_NO_PADDING);
      
      // Decrypt
      asrt(funcs->C_DecryptInit(session, &mech, obj_pvtkey[i]), CKR_OK, "DECRYPT INIT");
      asrt(funcs->C_Login(session, CKU_CONTEXT_SPECIFIC, (CK_CHAR_PTR)"123456", 6), CKR_OK, "Re-Login USER");
      dec_len = sizeof(dec);
      asrt(funcs->C_Decrypt(session, enc, enc_len, dec, &dec_len), CKR_OK, "DECRYPT");
      asrt(dec_len, data_len, "DECRYPTED DATA LEN");
      asrt(memcmp(data, dec, dec_len), 0, "DECRYPTED DATA");

      // Decrypt Update
      asrt(funcs->C_DecryptInit(session, &mech, obj_pvtkey[i]), CKR_OK, "DECRYPT INIT");
      asrt(funcs->C_Login(session, CKU_CONTEXT_SPECIFIC, (CK_CHAR_PTR)"123456", 6), CKR_OK, "Re-Login USER");
      dec_len = sizeof(dec);
      asrt(funcs->C_DecryptUpdate(session, enc, 100, dec, &dec_len), CKR_OK, "DECRYPT UPDATE");
      dec_len = sizeof(dec);
      asrt(funcs->C_DecryptUpdate(session, enc+100, 8, dec, &dec_len), CKR_OK, "DECRYPT UPDATE");
      dec_len = sizeof(dec);
      asrt(funcs->C_DecryptUpdate(session, enc+108, 20, dec, &dec_len), CKR_OK, "DECRYPT UPDATE");
      dec_len = sizeof(dec);
      asrt(funcs->C_DecryptFinal(session, dec, &dec_len), CKR_OK, "DECRYPT FINAL");
      asrt(dec_len, data_len, "DECRYPTED DATA LEN");
      asrt(memcmp(data, dec, dec_len), 0, "DECRYPTED DATA");
    }
  }
  asrt(funcs->C_Logout(session), CKR_OK, "Logout USER");
}

void test_rsa_encrypt(CK_FUNCTION_LIST_PTR funcs, CK_SESSION_HANDLE session, CK_OBJECT_HANDLE_PTR obj_pvtkey, 
                      CK_BYTE n_keys, RSA* rsak, CK_MECHANISM_TYPE mech_type, CK_ULONG padding) {
  CK_ULONG  i,j;
  CK_BYTE   data[32];
  CK_ULONG  data_len = sizeof(data);
  CK_BYTE   enc[512];
  CK_ULONG  enc_len;
  CK_BYTE   dec[512];
  CK_ULONG  dec_len;

  CK_RSA_PKCS_OAEP_PARAMS params = {0};
  CK_MECHANISM mech = {mech_type, &params, sizeof(params)};
  CK_OBJECT_HANDLE pubkey;

  asrt(funcs->C_Login(session, CKU_USER, (CK_CHAR_PTR)"123456", 6), CKR_OK, "Login USER");

  for (i = 0; i < n_keys; i++) {
    pubkey = get_public_key_handle(funcs, session, obj_pvtkey[i]);
    for (j = 0; j < 4; j++) {
    
      if(RAND_bytes(data, data_len) <= 0)
        exit(EXIT_FAILURE);

      // Encrypt
      asrt(funcs->C_EncryptInit(session, &mech, pubkey), CKR_OK, "ENCRYPT INIT CKM_RSA_PKCS");
      enc_len = sizeof(enc);
      asrt(funcs->C_Encrypt(session, data, data_len, enc, &enc_len), CKR_OK, "ENCRYPT CKM_RSA_PKCS");
      asrt(enc_len, 128, "ENCRYPTED DATA LEN");

      dec_len = RSA_private_decrypt(enc_len, enc, dec, rsak, padding);
      if(padding == RSA_NO_PADDING) {
        asrt(dec_len, 128, "DECRYPTED DATA LEN CKM_RSA_X_509");
        asrt(memcmp(data, dec+128-data_len, data_len), 0, "DECRYPTED DATA CKM_RSA_X_509");
      } else {
        asrt(dec_len, data_len, "DECRYPTED DATA LEN CKM_RSA_PKCS");
        asrt(memcmp(data, dec, dec_len), 0, "DECRYPTED DATA CKM_RSA_PKCS");
      }

      // Encrypt Update
      asrt(funcs->C_EncryptInit(session, &mech, pubkey), CKR_OK, "ENCRYPT INIT CKM_RSA_PKCS");
      enc_len = sizeof(enc);
      asrt(funcs->C_EncryptUpdate(session, data, 10, enc, &enc_len), CKR_OK, "ENCRYPT UPDATE CKM_RSA_PKCS");
      enc_len = sizeof(enc);
      asrt(funcs->C_EncryptUpdate(session, data+10, 22, enc, &enc_len), CKR_OK, "ENCRYPT UPDATE CKM_RSA_PKCS");
      enc_len = sizeof(enc);
      asrt(funcs->C_EncryptFinal(session, enc, &enc_len), CKR_OK, "ENCRYPT FINAL CKM_RSA_PKCS");
      asrt(enc_len, 128, "ENCRYPTED DATA LEN");

      dec_len = RSA_private_decrypt(enc_len, enc, dec, rsak, padding);
      if(padding == RSA_NO_PADDING) {
        asrt(dec_len, 128, "DECRYPTED DATA LEN CKM_RSA_X_509");
        asrt(memcmp(data, dec+128-data_len, data_len), 0, "DECRYPTED DATA CKM_RSA_X_509");
      } else {
        asrt(dec_len, data_len, "DECRYPTED DATA LEN CKM_RSA_PKCS");
        asrt(memcmp(data, dec, dec_len), 0, "DECRYPTED DATA CKM_RSA_PKCS");
      }
    }
  }
  asrt(funcs->C_Logout(session), CKR_OK, "Logout USER");
}

static void test_pubkey_basic_attributes(CK_FUNCTION_LIST_PTR funcs, CK_SESSION_HANDLE session, 
                                         CK_OBJECT_HANDLE pubkey, CK_ULONG key_type, CK_ULONG key_size,
                                         const unsigned char* label) {
  CK_ULONG obj_class;
  CK_BBOOL obj_token;
  CK_BBOOL obj_private;
  CK_ULONG obj_key_type;
  CK_BBOOL obj_trusted;
  CK_BBOOL obj_local;
  CK_BBOOL obj_encrypt;
  CK_BBOOL obj_verify;
  CK_BBOOL obj_wrap;
  CK_BBOOL obj_derive;
  CK_ULONG obj_modulus_bits;
  CK_BBOOL obj_modifiable;
  char obj_label[1024];
  CK_ULONG obj_label_len;

  CK_ATTRIBUTE template[] = {
    {CKA_CLASS, &obj_class, sizeof(CK_ULONG)},
    {CKA_TOKEN, &obj_token, sizeof(CK_BBOOL)},
    {CKA_PRIVATE, &obj_private, sizeof(CK_BBOOL)},
    {CKA_KEY_TYPE, &obj_key_type, sizeof(CK_ULONG)},
    {CKA_TRUSTED, &obj_trusted, sizeof(CK_BBOOL)},
    {CKA_LOCAL, &obj_local, sizeof(CK_BBOOL)},
    {CKA_ENCRYPT, &obj_encrypt, sizeof(CK_BBOOL)},
    {CKA_VERIFY, &obj_verify, sizeof(CK_BBOOL)},
    {CKA_WRAP, &obj_wrap, sizeof(CK_BBOOL)},
    {CKA_DERIVE, &obj_derive, sizeof(CK_BBOOL)},
    {CKA_MODULUS_BITS, &obj_modulus_bits, sizeof(CK_ULONG)},
    {CKA_MODIFIABLE, &obj_modifiable, sizeof(CK_BBOOL)},
  };

  CK_ATTRIBUTE template_label[] = {
    {CKA_LABEL, obj_label, sizeof(obj_label)}
  };

  asrt(funcs->C_GetAttributeValue(session, pubkey, template, 12), CKR_OK, "GET BASIC ATTRIBUTES");
  asrt(obj_class, CKO_PUBLIC_KEY, "CLASS");
  asrt(obj_token, CK_TRUE, "TOKEN");
  asrt(obj_private, CK_FALSE, "PRIVATE");
  asrt(obj_key_type, key_type, "KEY_TYPE");
  asrt(obj_trusted, CK_FALSE, "TRUSTED");
  asrt(obj_local, CK_TRUE, "LOCAL");
  asrt(obj_encrypt, CK_TRUE, "ENCRYPT");
  asrt(obj_verify, CK_TRUE, "VERIFY");
  asrt(obj_wrap, CK_FALSE, "WRAP");
  asrt(obj_derive, CK_FALSE, "DERIVE");
  asrt(obj_modulus_bits, key_size, "MODULUS BITS");
  asrt(obj_modifiable, CK_FALSE, "MODIFIABLE");
  asrt(obj_trusted, CK_FALSE, "TRUSTED");

  asrt(funcs->C_GetAttributeValue(session, pubkey, template_label, 1), CKR_OK, "GET LABEL");
  obj_label_len = template_label[0].ulValueLen;
  asrt(obj_label_len, strlen((char*)label), "LABEL LEN");
  asrt(strncmp(obj_label, (char*)label, obj_label_len), 0, "LABEL");
}

void test_pubkey_attributes_rsa(CK_FUNCTION_LIST_PTR funcs, CK_SESSION_HANDLE session, 
                                CK_OBJECT_HANDLE pubkey, CK_ULONG key_size, 
                                const unsigned char* label, CK_ULONG modulus_len,
                                CK_BYTE_PTR pubexp, CK_ULONG pubexp_len) {

  CK_BYTE obj_pubexp[1024];
  CK_BYTE obj_modulus[1024];

  CK_ATTRIBUTE template[] = {
    {CKA_MODULUS, obj_modulus, sizeof(obj_modulus)},
    {CKA_PUBLIC_EXPONENT, &obj_pubexp, sizeof(obj_pubexp)},
  };

  test_pubkey_basic_attributes(funcs, session, pubkey, CKK_RSA, key_size, label);

  asrt(funcs->C_GetAttributeValue(session, pubkey, template, 2), CKR_OK, "GET RSA ATTRIBUTES");
  asrt(template[0].ulValueLen, modulus_len, "MODULUS LEN");
  asrt(template[1].ulValueLen, pubexp_len, "PUBLIC EXPONEN LEN");
  asrt(memcmp(obj_pubexp, pubexp, pubexp_len), 0, "PUBLIC EXPONENT");
}

void test_pubkey_attributes_ec(CK_FUNCTION_LIST_PTR funcs, CK_SESSION_HANDLE session, 
                                CK_OBJECT_HANDLE pubkey, CK_ULONG key_size, 
                                const unsigned char* label, CK_ULONG ec_point_len,
                                CK_BYTE_PTR ec_params, CK_ULONG ec_params_len) {
  CK_BYTE obj_ec_point[1024];
  CK_BYTE obj_ec_param[1024];

  CK_ATTRIBUTE template[] = {
    {CKA_EC_POINT, obj_ec_point, sizeof(obj_ec_point)},
    {CKA_EC_PARAMS, obj_ec_param, sizeof(obj_ec_param)}
  };

  test_pubkey_basic_attributes(funcs, session, pubkey, CKK_EC, key_size, label);

  asrt(funcs->C_GetAttributeValue(session, pubkey, template, 2), CKR_OK, "GET EC ATTRIBUTES");
  asrt(template[0].ulValueLen, ec_point_len, "EC POINT LEN");
  asrt(template[1].ulValueLen, ec_params_len, "EC PARAMS LEN");
  asrt(memcmp(obj_ec_param, ec_params, ec_params_len), 0, "EC PARAMS");
}

static void test_privkey_basic_attributes(CK_FUNCTION_LIST_PTR funcs, CK_SESSION_HANDLE session, 
                                          CK_OBJECT_HANDLE privkey, CK_ULONG key_type, CK_ULONG key_size,
                                         const unsigned char* label, CK_BBOOL always_authenticate) {
  CK_ULONG obj_class;
  CK_BBOOL obj_token;
  CK_BBOOL obj_private;
  CK_ULONG obj_key_type;
  CK_BBOOL obj_sensitive;
  CK_BBOOL obj_always_sensitive;
  CK_BBOOL obj_extractable;
  CK_BBOOL obj_never_extractable;
  CK_BBOOL obj_local;
  CK_BBOOL obj_decrypt;
  CK_BBOOL obj_unwrap;
  CK_BBOOL obj_sign;
  CK_BBOOL obj_derive;
  CK_ULONG obj_modulus_bits;
  CK_BBOOL obj_always_authenticate;
  CK_BBOOL obj_modifiable;
  char obj_label[1024];
  CK_ULONG obj_label_len;

  CK_ATTRIBUTE template[] = {
    {CKA_CLASS, &obj_class, sizeof(CK_ULONG)},
    {CKA_TOKEN, &obj_token, sizeof(CK_BBOOL)},
    {CKA_PRIVATE, &obj_private, sizeof(CK_BBOOL)},
    {CKA_KEY_TYPE, &obj_key_type, sizeof(CK_ULONG)},
    {CKA_SENSITIVE, &obj_sensitive, sizeof(CK_BBOOL)},
    {CKA_ALWAYS_SENSITIVE, &obj_always_sensitive, sizeof(CK_BBOOL)},
    {CKA_EXTRACTABLE, &obj_extractable, sizeof(CK_BBOOL)},
    {CKA_NEVER_EXTRACTABLE, &obj_never_extractable, sizeof(CK_BBOOL)},
    {CKA_LOCAL, &obj_local, sizeof(CK_BBOOL)},
    {CKA_DECRYPT, &obj_decrypt, sizeof(CK_BBOOL)},
    {CKA_UNWRAP, &obj_unwrap, sizeof(CK_BBOOL)},
    {CKA_SIGN, &obj_sign, sizeof(CK_BBOOL)},
    {CKA_DERIVE, &obj_derive, sizeof(CK_BBOOL)},
    {CKA_MODULUS_BITS, &obj_modulus_bits, sizeof(CK_ULONG)},
    {CKA_ALWAYS_AUTHENTICATE, &obj_always_authenticate, sizeof(CK_BBOOL)},
    {CKA_MODIFIABLE, &obj_modifiable, sizeof(CK_BBOOL)}
  };

  CK_ATTRIBUTE template_label[] = {
    {CKA_LABEL, obj_label, sizeof(obj_label)}
  };

  asrt(funcs->C_GetAttributeValue(session, privkey, template, 16), CKR_OK, "GET BASIC ATTRIBUTES");
  asrt(obj_class, CKO_PRIVATE_KEY, "CLASS");
  asrt(obj_token, CK_TRUE, "TOKEN");
  asrt(obj_private, CK_TRUE, "PRIVATE");
  asrt(obj_key_type, key_type, "KEY_TYPE");
  asrt(obj_sensitive, CK_TRUE, "SENSITIVE");
  asrt(obj_always_sensitive, CK_TRUE, "ALWAYS_SENSITIVE");
  asrt(obj_extractable, CK_FALSE, "EXTRACTABLE");
  asrt(obj_never_extractable, CK_TRUE, "NEVER_EXTRACTABLE");
  asrt(obj_local, CK_TRUE, "LOCAL");
  asrt(obj_decrypt, CK_TRUE, "DECRYPT");
  asrt(obj_unwrap, CK_FALSE, "UNWRAP");
  asrt(obj_sign, CK_TRUE, "SIGN");
  asrt(obj_derive, CK_FALSE, "DERIVE");
  asrt(obj_modulus_bits, key_size, "MODULUS BITS");
  asrt(obj_always_authenticate, always_authenticate, "ALWAYS AUTHENTICATE");
  asrt(obj_modifiable, CK_FALSE, "MODIFIABLE");

  asrt(funcs->C_GetAttributeValue(session, privkey, template_label, 1), CKR_OK, "GET LABEL");
  obj_label_len = template_label[0].ulValueLen;
  asrt(obj_label_len, strlen((char*)label), "LABEL LEN");
  asrt(strncmp(obj_label, (char*)label, obj_label_len), 0, "LABEL");
}

void test_privkey_attributes_rsa(CK_FUNCTION_LIST_PTR funcs, CK_SESSION_HANDLE session, 
                                CK_OBJECT_HANDLE pubkey, CK_ULONG key_size, 
                                const unsigned char* label, CK_ULONG modulus_len,
                                CK_BYTE_PTR pubexp, CK_ULONG pubexp_len, 
                                CK_BBOOL always_authenticate) {

  CK_BYTE obj_pubexp[1024];
  CK_BYTE obj_modulus[1024];

  CK_ATTRIBUTE template[] = {
    {CKA_MODULUS, obj_modulus, sizeof(obj_modulus)},
    {CKA_PUBLIC_EXPONENT, &obj_pubexp, sizeof(obj_pubexp)},
  };

  test_privkey_basic_attributes(funcs, session, pubkey, CKK_RSA, key_size, label, always_authenticate);

  asrt(funcs->C_GetAttributeValue(session, pubkey, template, 2), CKR_OK, "GET RSA ATTRIBUTES");
  asrt(template[0].ulValueLen, modulus_len, "MODULUS LEN");
  asrt(template[1].ulValueLen, pubexp_len, "PUBLIC EXPONEN LEN");
  asrt(memcmp(obj_pubexp, pubexp, pubexp_len), 0, "PUBLIC EXPONENT");
}

void test_privkey_attributes_ec(CK_FUNCTION_LIST_PTR funcs, CK_SESSION_HANDLE session, 
                                CK_OBJECT_HANDLE pubkey, CK_ULONG key_size, 
                                const unsigned char* label, CK_ULONG ec_point_len,
                                CK_BYTE_PTR ec_params, CK_ULONG ec_params_len, 
                                CK_BBOOL always_authenticate) {
  CK_BYTE obj_ec_point[1024];
  CK_BYTE obj_ec_param[1024];

  CK_ATTRIBUTE template[] = {
    {CKA_EC_POINT, obj_ec_point, sizeof(obj_ec_point)},
    {CKA_EC_PARAMS, obj_ec_param, sizeof(obj_ec_param)}
  };

  test_privkey_basic_attributes(funcs, session, pubkey, CKK_EC, key_size, label, always_authenticate);

  asrt(funcs->C_GetAttributeValue(session, pubkey, template, 2), CKR_OK, "GET EC ATTRIBUTES");
  asrt(template[0].ulValueLen, ec_point_len, "EC POINT LEN");
  asrt(template[1].ulValueLen, ec_params_len, "EC PARAMS LEN");
  asrt(memcmp(obj_ec_param, ec_params, ec_params_len), 0, "EC PARAMS");
}

void test_find_objects_by_class(CK_FUNCTION_LIST_PTR funcs, CK_SESSION_HANDLE session, 
                                CK_ULONG class, CK_BYTE ckaid,
                                CK_ULONG n_expected, CK_OBJECT_HANDLE obj_expected) {
  CK_BYTE i;
  CK_OBJECT_HANDLE obj[10];
  CK_ULONG n = 0;
  CK_BBOOL found = CK_FALSE;

  CK_ATTRIBUTE idClassTemplate[] = {
    {CKA_ID, &ckaid, sizeof(ckaid)},
    {CKA_CLASS, &class, sizeof(CK_ULONG)}
  };

  asrt(funcs->C_FindObjectsInit(session, idClassTemplate, 2), CKR_OK, "FIND INIT");
  asrt(funcs->C_FindObjects(session, obj, 10, &n), CKR_OK, "FIND");
  asrt(n, n_expected, "N FOUND OBJS");
  asrt(funcs->C_FindObjectsFinal(session), CKR_OK, "FIND FINAL");
  for(i=0; i<n; i++) {
    if(obj[i] == obj_expected) {
      found = CK_TRUE;
    }
  }
  asrt(found, CK_TRUE, "EXPECTED OBJECT FOUND");
}