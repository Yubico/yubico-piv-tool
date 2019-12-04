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

#include "mechanisms.h"
#include "objects.h"
#include "token.h"
#include "openssl_utils.h"
#include "utils.h"
#include "debug.h"
#include <string.h>

#define F4 "\x01\x00\x01"
#define PRIME256V1 "\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07"
#define SECP384R1 "\x06\x05\x2b\x81\x04\x00\x22"

// Supported mechanisms for RSA decryption
static const CK_MECHANISM_TYPE decrypt_rsa_mechanisms[] = {
  CKM_RSA_PKCS,
  CKM_RSA_X_509
};

// Supported mechanisms for key pair generation
static const CK_MECHANISM_TYPE generation_mechanisms[] = {
  CKM_RSA_PKCS_KEY_PAIR_GEN,
  //CKM_ECDSA_KEY_PAIR_GEN, Deperecated
  CKM_EC_KEY_PAIR_GEN
};

CK_BBOOL is_RSA_mechanism(CK_MECHANISM_TYPE m) {

  switch (m) {
  case CKM_RSA_PKCS_KEY_PAIR_GEN:
  case CKM_RSA_PKCS:
  case CKM_RSA_9796:
  case CKM_RSA_X_509:
  case CKM_SHA1_RSA_PKCS:
//  case CKM_SHA224_RSA_PKCS:
  case CKM_SHA256_RSA_PKCS:
  case CKM_SHA384_RSA_PKCS:
  case CKM_SHA512_RSA_PKCS:
//  case CKM_RIPEMD128_RSA_PKCS:
//  case CKM_RIPEMD160_RSA_PKCS:
//  case CKM_RSA_PKCS_OAEP:
//  case CKM_RSA_X9_31_KEY_PAIR_GEN:
//  case CKM_RSA_X9_31:
//  case CKM_SHA1_RSA_X9_31:
  case CKM_RSA_PKCS_PSS:
  case CKM_SHA1_RSA_PKCS_PSS:
//  case CKM_SHA224_RSA_PKCS_PSS:
  case CKM_SHA256_RSA_PKCS_PSS:
  case CKM_SHA512_RSA_PKCS_PSS:
  case CKM_SHA384_RSA_PKCS_PSS:
//  case CKM_RSA_PKCS_TPM_1_1:
//  case CKM_RSA_PKCS_OAEP_TPM_1_1:
//  case CKM_RSA_AES_KEY_WRAP:
    return CK_TRUE;

  default:
    return CK_FALSE;
  }

  // Not reached
  return CK_FALSE;
}

CK_BBOOL is_EC_sign_mechanism(CK_MECHANISM_TYPE m) {
  switch (m) {
    case CKM_ECDSA:
    case CKM_ECDSA_SHA1:
    case CKM_ECDSA_SHA256:
    case CKM_ECDSA_SHA384:
    case CKM_ECDSA_SHA512:
      return CK_TRUE;
    default:
      return CK_FALSE;
  }

  // Not reached
  return CK_FALSE;
}

static int rsa_priv_enc(int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding) {
  const RSA_METHOD *meth = RSA_get_method(rsa);
  ykcs11_session_t *session = RSA_meth_get0_app_data(meth);
  size_t siglen = session->op_info.op.sign.sig_len;
  CK_BYTE buf[siglen];
  int ret;

  DBG("RSA sign %d bytes with padding %d", flen, padding);

  switch(padding) {
    case RSA_PKCS1_PADDING:
      ret = RSA_padding_add_PKCS1_type_1(buf, siglen, from, flen);
      break;
    case RSA_NO_PADDING:
      ret = RSA_padding_add_none(buf, siglen, from, flen);
      break;
    default:
      DBG("Unknown padding type %d", padding);
      return -1;
  }
  if(ret <= 0) {
    DBG("Failed to apply padding type %d", padding);
    return -1;
  }
  ykpiv_rc rc = ykpiv_sign_data(session->slot->piv_state, buf, siglen, to, &siglen, session->op_info.op.sign.algorithm, session->op_info.op.sign.key);
  if(rc == YKPIV_OK) {
    DBG("ykpiv_sign_data with key %x returned %lu bytes", session->op_info.op.sign.key, siglen);    
    return siglen;
  } else {
    DBG("ykpiv_sign_data with key %x failed: %s", session->op_info.op.sign.key, ykpiv_strerror(rc));
    return -1;
  }
}

static int ec_key_ex_data_idx = -1;

static int ec_sign(int type, const unsigned char *m, int m_len, unsigned char *sig, unsigned int *sig_len, const BIGNUM *kinv, const BIGNUM *r, EC_KEY *ec) {
  ykcs11_session_t *session = EC_KEY_get_ex_data(ec, ec_key_ex_data_idx);
  size_t siglen = session->op_info.op.sign.sig_len;

  DBG("ECDSA sign %d bytes", m_len);

  ykpiv_rc rc = ykpiv_sign_data(session->slot->piv_state, m, m_len, sig, &siglen, session->op_info.op.sign.algorithm, session->op_info.op.sign.key);
  if(rc == YKPIV_OK) {
    DBG("ykpiv_sign_data with key %x returned %lu bytes data", session->op_info.op.sign.key, siglen);
    *sig_len = siglen;
    return 1;
  } else {
    DBG("ykpiv_sign_data with key %x failed: %s", session->op_info.op.sign.key, ykpiv_strerror(rc));
    return 0;
  }
}

CK_RV sign_mechanism_init(ykcs11_session_t *session, ykcs11_pkey_t *key) {

  const EVP_MD *md = NULL;

  session->op_info.op.sign.md_ctx = NULL;
  session->op_info.op.sign.pkey_ctx = NULL;

  switch (session->op_info.mechanism) {
    case CKM_RSA_X_509:
    case CKM_RSA_PKCS:
    case CKM_RSA_PKCS_PSS:
    case CKM_ECDSA:
      // No hash required for these mechanisms
      break;

    case CKM_MD5_RSA_PKCS:
      md = EVP_md5();
      break;

    case CKM_RIPEMD160_RSA_PKCS:
      md = EVP_ripemd160();
      break;

    case CKM_SHA1_RSA_PKCS:
    case CKM_SHA1_RSA_PKCS_PSS:
    case CKM_ECDSA_SHA1:
      md = EVP_sha1();
      break;

    case CKM_SHA256_RSA_PKCS:
    case CKM_SHA256_RSA_PKCS_PSS:
    case CKM_ECDSA_SHA256:
      md = EVP_sha256();
      break;

    case CKM_SHA384_RSA_PKCS:
    case CKM_SHA384_RSA_PKCS_PSS:
    case CKM_ECDSA_SHA384:
      md = EVP_sha384();
      break;

    case CKM_SHA512_RSA_PKCS:
    case CKM_SHA512_RSA_PKCS_PSS:
    case CKM_ECDSA_SHA512:
      md = EVP_sha512();
      break;

    default:
      DBG("Mechanism %lu not supported by the module", session->op_info.mechanism.mechanism);
      return CKR_MECHANISM_INVALID;
  }

  session->op_info.op.sign.algorithm = do_get_key_algorithm(key);
  CK_KEY_TYPE key_type = do_get_key_type(key);
  CK_ULONG padding = 0;

  switch (session->op_info.mechanism) {
    case CKM_RSA_X_509:
      if(key_type != CKK_RSA) {
        DBG("Mechanism %lu requires an RSA key", session->op_info.mechanism.mechanism);
        return CKR_KEY_TYPE_INCONSISTENT;
      }
      padding = RSA_NO_PADDING;
    break;

    case CKM_RSA_PKCS:
    case CKM_MD5_RSA_PKCS:
    case CKM_SHA1_RSA_PKCS:
    case CKM_RIPEMD160_RSA_PKCS:
    case CKM_SHA256_RSA_PKCS:
    case CKM_SHA384_RSA_PKCS:
    case CKM_SHA512_RSA_PKCS:
      if(key_type != CKK_RSA) {
        DBG("Mechanism %lu requires an RSA key", session->op_info.mechanism.mechanism);
        return CKR_KEY_TYPE_INCONSISTENT;
      }
      padding = RSA_PKCS1_PADDING;
    break;

    case CKM_RSA_PKCS_PSS:
    case CKM_SHA1_RSA_PKCS_PSS:
    case CKM_SHA256_RSA_PKCS_PSS:
    case CKM_SHA384_RSA_PKCS_PSS:
    case CKM_SHA512_RSA_PKCS_PSS:
      if(key_type != CKK_RSA) {
        DBG("Mechanism %lu requires an RSA key", session->op_info.mechanism.mechanism);
        return CKR_KEY_TYPE_INCONSISTENT;
      }
      padding = RSA_PKCS1_PSS_PADDING;
      break;

    default:
      if(key_type != CKK_ECDSA) {
        DBG("Mechanism %lu requires an ECDSA key", session->op_info.mechanism.mechanism);
        return CKR_KEY_TYPE_INCONSISTENT;
      }
      break;
  }

  if(md) {
    session->op_info.op.sign.md_ctx = EVP_MD_CTX_create();
    if (session->op_info.op.sign.md_ctx == NULL) {
      return CKR_FUNCTION_FAILED;
    }
    if (EVP_DigestSignInit(session->op_info.op.sign.md_ctx, &session->op_info.op.sign.pkey_ctx, md, NULL, key) <= 0) {
      DBG("EVP_DigestSignInit failed");
      return CKR_FUNCTION_FAILED;
    }
  } else {
    session->op_info.op.sign.md_ctx = NULL;
    session->op_info.op.sign.pkey_ctx = EVP_PKEY_CTX_new(key, NULL);
    if (session->op_info.op.sign.pkey_ctx == NULL) {
      DBG("EVP_PKEY_CTX_new failed");
      return CKR_FUNCTION_FAILED;
    }
    if(EVP_PKEY_sign_init(session->op_info.op.sign.pkey_ctx) <= 0) {
      DBG("EVP_PKEY_sign_init failed");
      return CKR_FUNCTION_FAILED;
    }
  }

  if (padding) {
    if (EVP_PKEY_CTX_set_rsa_padding(session->op_info.op.sign.pkey_ctx, padding) <= 0) {
      DBG("EVP_PKEY_CTX_set_rsa_padding failed");
      return CKR_FUNCTION_FAILED;
    }
    RSA *rsa = EVP_PKEY_get0_RSA(key);
    RSA_METHOD *meth = RSA_meth_dup(RSA_get_default_method());
    RSA_meth_set0_app_data(meth, session);
    RSA_meth_set_priv_enc(meth, rsa_priv_enc);
    RSA_set_method(rsa, meth);
    session->op_info.op.sign.sig_len = RSA_size(rsa);
  } else {
    EC_KEY *ec = EVP_PKEY_get0_EC_KEY(key);
    EC_KEY_METHOD *meth = EC_KEY_METHOD_new(EC_KEY_get_method(ec));
    if (ec_key_ex_data_idx == -1)
      ec_key_ex_data_idx = EC_KEY_get_ex_new_index(0, NULL, NULL, NULL, 0);
    EC_KEY_set_ex_data(ec, ec_key_ex_data_idx, session);
    EC_KEY_METHOD_set_sign(meth, ec_sign, NULL, NULL);
    EC_KEY_set_method(ec, meth);
    session->op_info.op.sign.sig_len = ECDSA_size(ec);
  }

  session->op_info.buf_len = 0;

  return CKR_OK;
}

CK_RV sign_mechanism_update(ykcs11_session_t *session, CK_BYTE_PTR in, CK_ULONG in_len) {

  if(session->op_info.op.sign.md_ctx) {
    if (EVP_DigestSignUpdate(session->op_info.op.sign.md_ctx, in, in_len) <= 0) {
      DBG("EVP_DigestSignUpdate failed");
      return CKR_FUNCTION_FAILED;
    }
  } else {
    if(session->op_info.buf_len + in_len > sizeof(session->op_info.buf)) {
      return CKR_DATA_LEN_RANGE;
    }
    memcpy(session->op_info.buf + session->op_info.buf_len, in, in_len);
    session->op_info.buf_len += in_len;
  }

  return CKR_OK;
}

CK_RV sign_mechanism_final(ykcs11_session_t *session, CK_BYTE_PTR sig, CK_ULONG_PTR sig_len) {

  int rc;

  if(session->op_info.op.sign.md_ctx) {
    rc = EVP_DigestSignFinal(session->op_info.op.sign.md_ctx, sig, sig_len);
  } else {
    rc = EVP_PKEY_sign(session->op_info.op.sign.pkey_ctx, sig, sig_len, session->op_info.buf, session->op_info.buf_len);
  }

  if(rc <= 0) {
    return CKR_DATA_LEN_RANGE;
  }
  
  switch(session->op_info.op.sign.algorithm) {
    case YKPIV_ALGO_ECCP256:
      do_strip_DER_encoding_from_ECSIG(sig, sig_len, 64);
      break;
    case YKPIV_ALGO_ECCP384:
      do_strip_DER_encoding_from_ECSIG(sig, sig_len, 96);
      break;
  }

  return CKR_OK;
}

CK_RV sign_mechanism_cleanup(ykcs11_session_t *session) {

  if (session->op_info.op.sign.md_ctx != NULL) {
    EVP_MD_CTX_destroy(session->op_info.op.sign.md_ctx);
    session->op_info.op.sign.md_ctx = NULL;
  } else if(session->op_info.op.sign.pkey_ctx != NULL) {
    EVP_PKEY_CTX_free(session->op_info.op.sign.pkey_ctx);
  }
  session->op_info.op.sign.pkey_ctx = NULL;
  session->op_info.buf_len = 0;
  return CKR_OK;
}

CK_RV verify_mechanism_cleanup(ykcs11_session_t *session) {

  if (session->op_info.op.verify.md_ctx != NULL) {
    EVP_MD_CTX_destroy(session->op_info.op.verify.md_ctx);
    session->op_info.op.verify.md_ctx = NULL;
  } else if(session->op_info.op.verify.pkey_ctx != NULL) {
    EVP_PKEY_CTX_free(session->op_info.op.verify.pkey_ctx);
  }
  session->op_info.op.verify.pkey_ctx = NULL;
  session->op_info.buf_len = 0;
  return CKR_OK;
}

CK_RV verify_mechanism_init(ykcs11_session_t *session, ykcs11_pkey_t *key) {

  const EVP_MD *md = NULL;

  session->op_info.op.verify.md_ctx = NULL;
  session->op_info.op.verify.pkey_ctx = NULL;

  switch (session->op_info.mechanism) {
    case CKM_RSA_X_509:
    case CKM_RSA_PKCS:
    case CKM_RSA_PKCS_PSS:
    case CKM_ECDSA:
      // No hash required for these mechanisms
      break;

    case CKM_MD5_RSA_PKCS:
      md = EVP_md5();
      break;

    case CKM_RIPEMD160_RSA_PKCS:
      md = EVP_ripemd160();
      break;

    case CKM_SHA1_RSA_PKCS:
    case CKM_SHA1_RSA_PKCS_PSS:
    case CKM_ECDSA_SHA1:
      md = EVP_sha1();
      break;

    case CKM_SHA256_RSA_PKCS:
    case CKM_SHA256_RSA_PKCS_PSS:
    case CKM_ECDSA_SHA256:
      md = EVP_sha256();
      break;

    case CKM_SHA384_RSA_PKCS:
    case CKM_SHA384_RSA_PKCS_PSS:
    case CKM_ECDSA_SHA384:
      md = EVP_sha384();
      break;

    case CKM_SHA512_RSA_PKCS:
    case CKM_SHA512_RSA_PKCS_PSS:
    case CKM_ECDSA_SHA512:
      md = EVP_sha512();
      break;

    default:
      DBG("Mechanism %lu not supported by the module", op_info->mechanism.mechanism);
      return CKR_MECHANISM_INVALID;
  }

  CK_KEY_TYPE key_type = do_get_key_type(key);
  CK_ULONG padding = 0;

  switch (session->op_info.mechanism) {
    case CKM_RSA_X_509:
      if(key_type != CKK_RSA) {
        DBG("Mechanism %lu requires an RSA key", op_info->mechanism.mechanism);
        return CKR_KEY_TYPE_INCONSISTENT;
      }
      padding = RSA_NO_PADDING;
    break;

    case CKM_RSA_PKCS:
    case CKM_MD5_RSA_PKCS:
    case CKM_SHA1_RSA_PKCS:
    case CKM_RIPEMD160_RSA_PKCS:
    case CKM_SHA256_RSA_PKCS:
    case CKM_SHA384_RSA_PKCS:
    case CKM_SHA512_RSA_PKCS:
      if(key_type != CKK_RSA) {
        DBG("Mechanism %lu requires an RSA key", session->op_info.mechanism.mechanism);
        return CKR_KEY_TYPE_INCONSISTENT;
      }
      padding = RSA_PKCS1_PADDING;
    break;

    case CKM_RSA_PKCS_PSS:
    case CKM_SHA1_RSA_PKCS_PSS:
    case CKM_SHA256_RSA_PKCS_PSS:
    case CKM_SHA384_RSA_PKCS_PSS:
    case CKM_SHA512_RSA_PKCS_PSS:
      if(key_type != CKK_RSA) {
        DBG("Mechanism %lu requires an RSA key", session->op_info.mechanism.mechanism);
        return CKR_KEY_TYPE_INCONSISTENT;
      }
      padding = RSA_PKCS1_PSS_PADDING;
      break;

    default:
      if(key_type != CKK_ECDSA) {
        DBG("Mechanism %lu requires an ECDSA key", session->op_info.mechanism.mechanism);
        return CKR_KEY_TYPE_INCONSISTENT;
      }
  }

  if(md) {
    session->op_info.op.verify.md_ctx = EVP_MD_CTX_create();
    if (session->op_info.op.verify.md_ctx == NULL) {
      return CKR_FUNCTION_FAILED;
    }
    if (EVP_DigestVerifyInit(session->op_info.op.verify.md_ctx, &session->op_info.op.verify.pkey_ctx, md, NULL, key) <= 0) {
      DBG("EVP_DigestVerifyInit failed");
      return CKR_FUNCTION_FAILED;
    }
  } else {
    session->op_info.op.verify.md_ctx = NULL;
    session->op_info.op.verify.pkey_ctx = EVP_PKEY_CTX_new(key, NULL);
    if (session->op_info.op.verify.pkey_ctx == NULL) {
      DBG("EVP_PKEY_CTX_new failed");
      return CKR_FUNCTION_FAILED;
    }
    if(EVP_PKEY_verify_init(session->op_info.op.verify.pkey_ctx) <= 0) {
      DBG("EVP_PKEY_verify_init failed");
      return CKR_FUNCTION_FAILED;
    }
  }

  if (padding) {
    if (EVP_PKEY_CTX_set_rsa_padding(session->op_info.op.verify.pkey_ctx, padding) <= 0) {
      DBG("EVP_PKEY_CTX_set_rsa_padding failed");
      return CKR_FUNCTION_FAILED;
    }
  }

  session->op_info.buf_len = 0;

  return CKR_OK;
}

CK_RV verify_mechanism_update(ykcs11_session_t *session, CK_BYTE_PTR in, CK_ULONG in_len) {

  if(session->op_info.op.verify.md_ctx) {
    if (EVP_DigestVerifyUpdate(session->op_info.op.verify.md_ctx, in, in_len) <= 0) {
      return CKR_FUNCTION_FAILED;
    }
  } else {
    if(session->op_info.buf_len + in_len > sizeof(session->op_info.buf)) {
      return CKR_DATA_LEN_RANGE;
    }
    memcpy(session->op_info.buf + session->op_info.buf_len, in, in_len);
    session->op_info.buf_len += in_len;
  }

  return CKR_OK;
}

CK_RV verify_mechanism_final(ykcs11_session_t *session, CK_BYTE_PTR sig, CK_ULONG sig_len) {

  int rc;

  CK_BYTE der[sig_len + 32]; // Add some space for the DER encoding
  if(is_EC_sign_mechanism(session->op_info.mechanism)) {
    memcpy(der, sig, sig_len);
    sig = der;
    do_apply_DER_encoding_to_ECSIG(sig, &sig_len);
  }

  if(session->op_info.op.verify.md_ctx) {
    rc = EVP_DigestVerifyFinal(session->op_info.op.verify.md_ctx, sig, sig_len);
  } else {
    rc = EVP_PKEY_verify(session->op_info.op.verify.pkey_ctx, sig, sig_len, session->op_info.buf, session->op_info.buf_len);
  }

  if(rc <= 0)
    return CKR_SIGNATURE_INVALID;

  return CKR_OK;
}

CK_RV check_generation_mechanism(CK_MECHANISM_PTR m) {

  CK_ULONG          i;
  CK_BBOOL          supported = CK_FALSE;
  CK_MECHANISM_INFO info;

  // Check if the mechanism is supported by the module
  for (i = 0; i < sizeof(generation_mechanisms) / sizeof(CK_MECHANISM_TYPE); i++) {
    if (m->mechanism == generation_mechanisms[i]) {
      supported = CK_TRUE;
      break;
    }
  }
  if (supported == CK_FALSE)
    return CKR_MECHANISM_INVALID;

  // Check if the mechanism is supported by the token
  if (get_token_mechanism_info(m->mechanism, &info) != CKR_OK)
    return CKR_MECHANISM_INVALID;

  // TODO: also check that parametes make sense if any? And key size is in [min max]

  return CKR_OK;

}

CK_RV check_pubkey_template(gen_info_t *gen, CK_MECHANISM_PTR mechanism, CK_ATTRIBUTE_PTR templ, CK_ULONG n) {

  CK_ULONG i;

  gen->rsa = is_RSA_mechanism(mechanism->mechanism);

  for (i = 0; i < n; i++) {
    switch (templ[i].type) {
    case CKA_CLASS:
      if (*((CK_ULONG_PTR) templ[i].pValue) != CKO_PUBLIC_KEY)
        return CKR_TEMPLATE_INCONSISTENT;

      break;

    case CKA_KEY_TYPE:
      if ((gen->rsa == CK_TRUE  && (*((CK_KEY_TYPE *)templ[i].pValue)) != CKK_RSA) ||
          (gen->rsa == CK_FALSE && (*((CK_KEY_TYPE *)templ[i].pValue)) != CKK_ECDSA))
        return CKR_TEMPLATE_INCONSISTENT;

      break;

    case CKA_PUBLIC_EXPONENT:
      if (gen->rsa == CK_FALSE)
        return CKR_ATTRIBUTE_VALUE_INVALID;

      // Only support F4
      if (templ[i].ulValueLen != 3 || memcmp((CK_BYTE_PTR)templ[i].pValue, F4, 3) != 0) {
        DBG("Unsupported public exponent");
        return CKR_ATTRIBUTE_VALUE_INVALID;
      }

      break;

    case CKA_MODULUS_BITS:
      if (gen->rsa == CK_FALSE)
        return CKR_ATTRIBUTE_VALUE_INVALID;

      if (*((CK_ULONG_PTR) templ[i].pValue) != 1024 &&
          *((CK_ULONG_PTR) templ[i].pValue) != 2048) { // TODO: make define?
        DBG("Unsupported MODULUS_BITS (key length)");
        return CKR_ATTRIBUTE_VALUE_INVALID;
      }

      gen->key_len = *((CK_ULONG_PTR) templ[i].pValue);
      break;

    case CKA_EC_PARAMS:
      // Support PRIME256V1 and SECP384R1
      if (templ[i].ulValueLen == 10 && memcmp((CK_BYTE_PTR)templ[i].pValue, PRIME256V1, 10) == 0)
        gen->key_len = 256;
      else if(templ[i].ulValueLen == 7 && memcmp((CK_BYTE_PTR)templ[i].pValue, SECP384R1, 7) == 0)
        gen->key_len = 384;
      else
        return CKR_FUNCTION_FAILED;
      break;

    case CKA_ID:
      if (find_pubk_object(*((CK_BYTE_PTR)templ[i].pValue)) == (piv_obj_id_t)-1)
        return CKR_ATTRIBUTE_VALUE_INVALID;

      gen->key_id = *((CK_BYTE_PTR)templ[i].pValue);
      break;

    case CKA_TOKEN:
    case CKA_ENCRYPT:
    case CKA_VERIFY:
    case CKA_WRAP:
    case CKA_DERIVE:
    case CKA_PRIVATE:
    case CKA_LABEL:
      // Ignore these attributes for now
      break;

    default:
      DBG("Invalid attribute %lx in public key template", templ[i].type);
      return CKR_ATTRIBUTE_TYPE_INVALID;
    }
  }

  return CKR_OK;

}

CK_RV check_pvtkey_template(gen_info_t *gen, CK_MECHANISM_PTR mechanism, CK_ATTRIBUTE_PTR templ, CK_ULONG n) {

  CK_ULONG i;

  gen->rsa = is_RSA_mechanism(mechanism->mechanism);

  for (i = 0; i < n; i++) {
    switch (templ[i].type) {
    case CKA_CLASS:
      if (*((CK_ULONG_PTR)templ[i].pValue) != CKO_PRIVATE_KEY)
        return CKR_TEMPLATE_INCONSISTENT;

      break;

    case CKA_KEY_TYPE:
      if ((gen->rsa == CK_TRUE  && (*((CK_KEY_TYPE *)templ[i].pValue)) != CKK_RSA) ||
          (gen->rsa == CK_FALSE && (*((CK_KEY_TYPE *)templ[i].pValue)) != CKK_ECDSA))
        return CKR_TEMPLATE_INCONSISTENT;

      break;

/*    case CKA_MODULUS_BITS:
      if (op_info->op.gen.rsa == CK_FALSE)
        return CKR_MECHANISM_PARAM_INVALID;
      if (*((CK_ULONG_PTR)templ[i].pValue) != 1024 &&
          *((CK_ULONG_PTR) templ[i].pValue) != 2048) // TODO: make define?
        return CKR_MECHANISM_PARAM_INVALID;
      op_info->op.gen.key_len = *((CK_ULONG_PTR) templ[i].pValue); // TODO: check length?
      break;*/

    case CKA_ID:
      if (find_pvtk_object(*((CK_BYTE_PTR)templ[i].pValue)) == (piv_obj_id_t)-1)
        return CKR_ATTRIBUTE_VALUE_INVALID;

      // Check if ID was already specified in the public key template
      // In that case it has to match
      if (gen->key_id != 0 &&
          gen->key_id != *((CK_BYTE_PTR)templ[i].pValue))
        return CKR_TEMPLATE_INCONSISTENT;

      gen->key_id = *((CK_BYTE_PTR)templ[i].pValue);
      break;

    case CKA_SENSITIVE:
    case CKA_DECRYPT:
    case CKA_UNWRAP:
    case CKA_SIGN:
    case CKA_PRIVATE:
    case CKA_TOKEN:
    case CKA_DERIVE:
    case CKA_LABEL:
      // Ignore these attributes for now
      break;

    default:
      DBG("Invalid attribute %lx in private key template", templ[i].type);
      return CKR_ATTRIBUTE_TYPE_INVALID;
    }
  }

  return CKR_OK;

}

CK_RV hash_mechanism_init(ykcs11_session_t *session) {

  const EVP_MD *md = NULL;

  switch (session->op_info.mechanism) {
    case CKM_SHA_1:
      md = EVP_sha1();
      break;

    case CKM_SHA256:
      md = EVP_sha256();
      break;

    case CKM_SHA384:
      md = EVP_sha384();
      break;

    case CKM_SHA512:
      md = EVP_sha512();
      break;

    default:
      DBG("Mechanism %lu not supported", op_info->mechanism.mechanism);
      return CKR_MECHANISM_INVALID;
  }

  session->op_info.op.digest.length = EVP_MD_size(md);
  session->op_info.op.digest.md_ctx = EVP_MD_CTX_create();

  if (EVP_DigestInit_ex(session->op_info.op.digest.md_ctx, md, NULL) <= 0) {
    EVP_MD_CTX_destroy(session->op_info.op.digest.md_ctx);
    session->op_info.op.digest.md_ctx = NULL;
    return CKR_FUNCTION_FAILED;
  }

  DBG("Initialized %s digest of length %lu", EVP_MD_name(md), op_info->op.digest.length);
  return CKR_OK;
}

CK_RV hash_mechanism_update(ykcs11_session_t *session, CK_BYTE_PTR in, CK_ULONG in_len) {

  if (EVP_DigestUpdate(session->op_info.op.digest.md_ctx, in, in_len) <= 0) {
    EVP_MD_CTX_destroy(session->op_info.op.digest.md_ctx);
    session->op_info.op.digest.md_ctx = NULL;
    return CKR_FUNCTION_FAILED;
  }

  DBG("Updated digest with %lu bytes of data", in_len);
  return CKR_OK;
}

CK_RV hash_mechanism_final(ykcs11_session_t *session, CK_BYTE_PTR pDigest, CK_ULONG_PTR pDigestLength) {

  unsigned int cbLength = *pDigestLength;
  int ret = EVP_DigestFinal_ex(session->op_info.op.digest.md_ctx, pDigest, &cbLength);

  EVP_MD_CTX_destroy(session->op_info.op.digest.md_ctx);
  session->op_info.op.digest.md_ctx = NULL;

  if (ret <= 0) {
    return CKR_FUNCTION_FAILED;
  }

  DBG("Finalized digest with %u bytes of data", cbLength);
  *pDigestLength = cbLength;
  return CKR_OK;
}

CK_RV check_rsa_decrypt_mechanism(ykcs11_session_t *s, CK_MECHANISM_PTR m) {

  CK_ULONG          i;
  CK_BBOOL          supported = CK_FALSE;
  CK_MECHANISM_INFO info;

  // Check if the mechanism is supported by the module
  for (i = 0; i < sizeof(decrypt_rsa_mechanisms) / sizeof(CK_MECHANISM_TYPE); i++) {
    if (m->mechanism == decrypt_rsa_mechanisms[i]) {
      supported = CK_TRUE;
      break;
    }
  }
  if (supported == CK_FALSE)
    return CKR_MECHANISM_INVALID;

  // Check if the mechanism is supported by the token
  if (get_token_mechanism_info(m->mechanism, &info) != CKR_OK)
    return CKR_MECHANISM_INVALID;

  // TODO: also check that parametes make sense if any? And key size is in [min max]

  return CKR_OK;
}