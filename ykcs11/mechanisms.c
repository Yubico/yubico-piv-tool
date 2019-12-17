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

#include <string.h>
#include "mechanisms.h"
#include "objects.h"
#include "../tool/openssl-compat.h" // TODO: share this better?
#include "../tool/util.h" // TODO: share this better?
#include "openssl_utils.h"
#include "utils.h"
#include "debug.h"

#define F4 "\x01\x00\x01"
#define PRIME256V1 "\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07"
#define SECP384R1 "\x06\x05\x2b\x81\x04\x00\x22"

// Supported mechanisms for RSA decryption
static const CK_MECHANISM_TYPE decrypt_rsa_mechanisms[] = {
  CKM_RSA_PKCS,
  //CKM_RSA_PKCS_OAEP,
  CKM_RSA_X_509
};

// Supported mechanisms for key pair generation
static const CK_MECHANISM_TYPE generation_mechanisms[] = {
  CKM_RSA_PKCS_KEY_PAIR_GEN,
  //CKM_ECDSA_KEY_PAIR_GEN, Deperecated
  CKM_EC_KEY_PAIR_GEN
};

static CK_BBOOL is_RSA_mechanism(CK_MECHANISM_TYPE m) {

  switch (m) {
  case CKM_RSA_PKCS_KEY_PAIR_GEN:
  case CKM_RSA_PKCS:
//  case CKM_RSA_9796:
  case CKM_RSA_X_509:
  case CKM_MD5_RSA_PKCS:
  case CKM_SHA1_RSA_PKCS:
  case CKM_SHA256_RSA_PKCS:
  case CKM_SHA384_RSA_PKCS:
  case CKM_SHA512_RSA_PKCS:
//  case CKM_RIPEMD128_RSA_PKCS:
  case CKM_RIPEMD160_RSA_PKCS:
//  case CKM_RSA_PKCS_OAEP:
//  case CKM_RSA_X9_31_KEY_PAIR_GEN:
//  case CKM_RSA_X9_31:
//  case CKM_SHA1_RSA_X9_31:
  case CKM_RSA_PKCS_PSS:
  case CKM_SHA1_RSA_PKCS_PSS:
  case CKM_SHA256_RSA_PKCS_PSS:
  case CKM_SHA512_RSA_PKCS_PSS:
  case CKM_SHA384_RSA_PKCS_PSS:
    return CK_TRUE;

  default:
    return CK_FALSE;
  }

  // Not reached
  return CK_FALSE;
}

static const EVP_MD* EVP_MD_by_mechanism(CK_MECHANISM_TYPE m) {
  switch (m) {
  case CKM_MD5:
    return EVP_md5();
  case CKM_SHA_1:
  case CKG_MGF1_SHA1:
    return EVP_sha1();
  case CKM_RIPEMD160:
    return EVP_ripemd160();
  case CKG_MGF1_SHA224:
    return EVP_sha224();
  case CKM_SHA256:
  case CKG_MGF1_SHA256:
    return EVP_sha256();
  case CKM_SHA384:
  case CKG_MGF1_SHA384:
    return EVP_sha384();
  case CKM_SHA512:
  case CKG_MGF1_SHA512:
    return EVP_sha512();
  default:
    return NULL;
  }
}

CK_RV sign_mechanism_init(ykcs11_session_t *session, ykcs11_pkey_t *key, CK_RSA_PKCS_PSS_PARAMS_PTR pss) {

  const EVP_MD *md = NULL;

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

    case CKM_ECDSA_SHA224:
      md = EVP_sha224();
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
//    case CKM_ECDSA_SHA512:
      md = EVP_sha512();
      break;

    default:
      DBG("Mechanism %lu not supported", session->op_info.mechanism);
      return CKR_MECHANISM_INVALID;
  }

  session->op_info.out_len = EVP_PKEY_size(key);
  session->op_info.op.sign.rsa = EVP_PKEY_get0_RSA(key);
  session->op_info.op.sign.algorithm = do_get_key_algorithm(key);

  switch (session->op_info.mechanism) {
    case CKM_RSA_X_509:
      if(!session->op_info.op.sign.rsa) {
        DBG("Mechanism %lu requires an RSA key", session->op_info.mechanism);
        return CKR_KEY_TYPE_INCONSISTENT;
      }
      session->op_info.op.sign.padding = RSA_NO_PADDING;
    break;

    case CKM_RSA_PKCS:
    case CKM_MD5_RSA_PKCS:
    case CKM_SHA1_RSA_PKCS:
    case CKM_RIPEMD160_RSA_PKCS:
    case CKM_SHA256_RSA_PKCS:
    case CKM_SHA384_RSA_PKCS:
    case CKM_SHA512_RSA_PKCS:
      if(!session->op_info.op.sign.rsa) {
        DBG("Mechanism %lu requires an RSA key", session->op_info.mechanism);
        return CKR_KEY_TYPE_INCONSISTENT;
      }
      session->op_info.op.sign.padding = RSA_PKCS1_PADDING;
    break;

    case CKM_RSA_PKCS_PSS:
    case CKM_SHA1_RSA_PKCS_PSS:
    case CKM_SHA256_RSA_PKCS_PSS:
    case CKM_SHA384_RSA_PKCS_PSS:
    case CKM_SHA512_RSA_PKCS_PSS:
      if(!session->op_info.op.sign.rsa) {
        DBG("Mechanism %lu requires an RSA key", session->op_info.mechanism);
        return CKR_KEY_TYPE_INCONSISTENT;
      }
      if(!pss) {
        DBG("Mechanism %lu requires PSS parameters", session->op_info.mechanism);
        return CKR_ARGUMENTS_BAD;
      }
      session->op_info.op.sign.padding = RSA_PKCS1_PSS_PADDING;
      session->op_info.op.sign.pss_md = EVP_MD_by_mechanism(pss->hashAlg);
      session->op_info.op.sign.mgf1_md = EVP_MD_by_mechanism(pss->mgf);
      session->op_info.op.sign.pss_slen = pss->sLen;
      if(!session->op_info.op.sign.pss_md) {
        DBG("Invalid PSS parameters: hashAlg mechanism %lu unknown", pss->hashAlg);
        return CKR_ARGUMENTS_BAD;
      }
      if(!session->op_info.op.sign.mgf1_md) {
        DBG("Invalid PSS parameters: mgf mechanism %lu unknown", pss->mgf);
        return CKR_ARGUMENTS_BAD;
      }
      if(md && md != session->op_info.op.sign.pss_md) {
        DBG("Mechanism %lu requires PSS parameters to specify hashAlg %s", session->op_info.mechanism, EVP_MD_name(md));
        return CKR_ARGUMENTS_BAD;
      }
      break;

    default:
      if(session->op_info.op.sign.rsa) {
        DBG("Mechanism %lu requires an ECDSA key", session->op_info.mechanism);
        return CKR_KEY_TYPE_INCONSISTENT;
      }
      session->op_info.op.sign.padding = 0;
      break;
  }

  if(md) {
    session->op_info.md_ctx = EVP_MD_CTX_create();
    if (session->op_info.md_ctx == NULL) {
      DBG("EVP_MD_CTX_create failed");
      return CKR_FUNCTION_FAILED;
    }
    if (EVP_DigestInit_ex(session->op_info.md_ctx, md, NULL) <= 0) {
      DBG("EVP_DigestInit_ex failed");
      return CKR_FUNCTION_FAILED;
    }
  } else {
    session->op_info.md_ctx = NULL;
  }

  session->op_info.buf_len = 0;

  return CKR_OK;
}

CK_RV sign_mechanism_final(ykcs11_session_t *session, CK_BYTE_PTR sig, CK_ULONG_PTR sig_len) {

  if(session->op_info.md_ctx) {
    // Compute the digest
    unsigned int cbLength;
    if(EVP_DigestFinal_ex(session->op_info.md_ctx, session->op_info.buf, &cbLength) <= 0) {
      DBG("EVP_DigestFinal_ex failed");
      return CKR_FUNCTION_FAILED;
    }
    if(session->op_info.op.sign.padding == RSA_PKCS1_PADDING) {
      // Wrap in an X509_SIG
      prepare_rsa_signature(session->op_info.buf, cbLength, session->op_info.buf, &cbLength,
                            EVP_MD_type(EVP_MD_CTX_md(session->op_info.md_ctx)));
    }
    session->op_info.buf_len = cbLength;
  }

  int padlen = session->op_info.out_len;
  CK_BYTE buf[padlen];

  // Apply padding
  switch(session->op_info.op.sign.padding) {
    case RSA_PKCS1_PADDING:
      if(RSA_padding_add_PKCS1_type_1(buf, padlen, session->op_info.buf, session->op_info.buf_len) <= 0) {
        DBG("RSA_padding_add_PKCS1_type_1 failed");
        return CKR_FUNCTION_FAILED;
      }
      memcpy(session->op_info.buf, buf, padlen);
      session->op_info.buf_len = padlen;
      break;
    case RSA_PKCS1_PSS_PADDING:
      if(RSA_padding_add_PKCS1_PSS_mgf1(session->op_info.op.sign.rsa, buf, session->op_info.buf, session->op_info.op.sign.pss_md,
                                        session->op_info.op.sign.mgf1_md, session->op_info.op.sign.pss_slen) <= 0) {
        DBG("RSA_padding_add_PKCS1_PSS_mgf1 failed");
        return CKR_FUNCTION_FAILED;
      }
      memcpy(session->op_info.buf, buf, padlen);
      session->op_info.buf_len = padlen;
      break;
    case RSA_NO_PADDING:
      if(RSA_padding_add_none(buf, padlen, session->op_info.buf, session->op_info.buf_len) <= 0) {
        DBG("RSA_padding_add_none failed");
        return CKR_FUNCTION_FAILED;
      }
      memcpy(session->op_info.buf, buf, padlen);
      session->op_info.buf_len = padlen;
      break;
  }

  // Sign with PIV
  size_t siglen = *sig_len;
  ykpiv_rc rcc = ykpiv_sign_data(session->slot->piv_state, session->op_info.buf, session->op_info.buf_len, sig, &siglen, session->op_info.op.sign.algorithm, session->op_info.op.sign.piv_key);
  if(rcc == YKPIV_OK) {
    DBG("ykpiv_sign_data %lu bytes with key %x returned %lu bytes data", session->op_info.buf_len, session->op_info.op.sign.piv_key, siglen);
    *sig_len = siglen;
  } else {
    DBG("ykpiv_sign_data with key %x failed: %s", session->op_info.op.sign.piv_key, ykpiv_strerror(rcc));
    return CKR_FUNCTION_FAILED;
  }

  CK_RV rv = CKR_OK;
  
  // Strip DER encoding on EC signatures
  switch(session->op_info.op.sign.algorithm) {
    case YKPIV_ALGO_ECCP256:
      DBG("Stripping DER encoding from %lu bytes, returning 64", *sig_len);
      rv = do_strip_DER_encoding_from_ECSIG(sig, sig_len, 64);
      break;
    case YKPIV_ALGO_ECCP384:
      DBG("Stripping DER encoding from %lu bytes, returning 96", *sig_len);
      rv = do_strip_DER_encoding_from_ECSIG(sig, sig_len, 96);
      break;
  }

  return rv;
}

CK_RV sign_mechanism_cleanup(ykcs11_session_t *session) {

  if (session->op_info.md_ctx != NULL) {
    EVP_MD_CTX_destroy(session->op_info.md_ctx);
    session->op_info.md_ctx = NULL;
  }
  session->op_info.buf_len = 0;
  return CKR_OK;
}

CK_RV verify_mechanism_cleanup(ykcs11_session_t *session) {

  if (session->op_info.md_ctx != NULL) {
    EVP_MD_CTX_destroy(session->op_info.md_ctx);
    session->op_info.md_ctx = NULL;
  } else if(session->op_info.op.verify.pkey_ctx != NULL) {
    EVP_PKEY_CTX_free(session->op_info.op.verify.pkey_ctx);
  }
  session->op_info.op.verify.pkey_ctx = NULL;
  session->op_info.buf_len = 0;
  return CKR_OK;
}

CK_RV verify_mechanism_init(ykcs11_session_t *session, ykcs11_pkey_t *key, CK_RSA_PKCS_PSS_PARAMS_PTR pss) {

  const EVP_MD *md = NULL;

  session->op_info.md_ctx = NULL;
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

    case CKM_ECDSA_SHA224:
      md = EVP_sha224();
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
      DBG("Mechanism %lu not supported", session->op_info.mechanism);
      return CKR_MECHANISM_INVALID;
  }

  CK_KEY_TYPE key_type = session->op_info.op.verify.key_type = do_get_key_type(key);
  CK_ULONG padding;

  switch (session->op_info.mechanism) {
    case CKM_RSA_X_509:
      if(key_type != CKK_RSA) {
        DBG("Mechanism %lu requires an RSA key", session->op_info.mechanism);
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
        DBG("Mechanism %lu requires an RSA key", session->op_info.mechanism);
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
        DBG("Mechanism %lu requires an RSA key", session->op_info.mechanism);
        return CKR_KEY_TYPE_INCONSISTENT;
      }
      if(!pss) {
        DBG("Mechanism %lu requires PSS parameters", session->op_info.mechanism);
        return CKR_ARGUMENTS_BAD;
      }
      padding = RSA_PKCS1_PSS_PADDING;
      break;

    default:
      if(key_type != CKK_ECDSA) {
        DBG("Mechanism %lu requires an ECDSA key", session->op_info.mechanism);
        return CKR_KEY_TYPE_INCONSISTENT;
      }
      padding = 0;
  }

  if(md) {
    session->op_info.md_ctx = EVP_MD_CTX_create();
    if (session->op_info.md_ctx == NULL) {
      return CKR_FUNCTION_FAILED;
    }
    if (EVP_DigestVerifyInit(session->op_info.md_ctx, &session->op_info.op.verify.pkey_ctx, md, NULL, key) <= 0) {
      DBG("EVP_DigestVerifyInit failed");
      return CKR_FUNCTION_FAILED;
    }
  } else {
    session->op_info.md_ctx = NULL;
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
    if (padding == RSA_PKCS1_PSS_PADDING) {
      if(!EVP_MD_by_mechanism(pss->hashAlg)) {
        DBG("Invalid PSS parameters: hashAlg mechanism %lu unknown", pss->hashAlg);
        return CKR_ARGUMENTS_BAD;
      }
      if(!EVP_MD_by_mechanism(pss->mgf)) {
        DBG("Invalid PSS parameters: mgf mechanism %lu unknown", pss->mgf);
        return CKR_ARGUMENTS_BAD;
      }
      if(md && md != EVP_MD_by_mechanism(pss->hashAlg)) {
        DBG("Mechanism %lu requires PSS parameters to specify hashAlg %s", session->op_info.mechanism, EVP_MD_name(md));
        return CKR_ARGUMENTS_BAD;
      }
      EVP_PKEY_CTX_set_signature_md(session->op_info.op.verify.pkey_ctx, EVP_MD_by_mechanism(pss->hashAlg));
      EVP_PKEY_CTX_set_rsa_mgf1_md(session->op_info.op.verify.pkey_ctx, EVP_MD_by_mechanism(pss->mgf));
      EVP_PKEY_CTX_set_rsa_pss_saltlen(session->op_info.op.verify.pkey_ctx, pss->sLen);
    }
  }

  session->op_info.out_len = 0;
  session->op_info.buf_len = 0;

  return CKR_OK;
}

CK_RV verify_mechanism_final(ykcs11_session_t *session, CK_BYTE_PTR sig, CK_ULONG sig_len) {

  int rc;

  CK_BYTE der[sig_len + 32]; // Add some space for the DER encoding
  if(session->op_info.op.verify.key_type == CKK_ECDSA) {
    memcpy(der, sig, sig_len);
    sig = der;
    DBG("Applying DER encoding to signature of %lu bytes", sig_len);
    CK_RV rv = do_apply_DER_encoding_to_ECSIG(sig, &sig_len);
    if(rv != CKR_OK) {
      DBG("do_apply_DER_encoding_to_ECSIG failed");
      return CKR_FUNCTION_FAILED;
    }
  }

  if(session->op_info.md_ctx) {
    rc = EVP_DigestVerifyFinal(session->op_info.md_ctx, sig, sig_len);
    if(rc <= 0) {
      DBG("EVP_DigestVerifyFinal failed");
      return rc < 0 ? CKR_FUNCTION_FAILED : CKR_SIGNATURE_INVALID;
    }
  } else {
    rc = EVP_PKEY_verify(session->op_info.op.verify.pkey_ctx, sig, sig_len, session->op_info.buf, session->op_info.buf_len);
    if(rc <= 0) {
      DBG("EVP_PKEY_verify failed");
      return rc < 0 ? CKR_FUNCTION_FAILED : CKR_SIGNATURE_INVALID;
    }
  }

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

  CK_BBOOL rsa = is_RSA_mechanism(mechanism->mechanism);

  for (CK_ULONG i = 0; i < n; i++) {
    switch (templ[i].type) {
    case CKA_CLASS:
      if (*((CK_ULONG_PTR) templ[i].pValue) != CKO_PUBLIC_KEY)
        return CKR_TEMPLATE_INCONSISTENT;

      break;

    case CKA_KEY_TYPE:
      if ((rsa == CK_TRUE  && (*((CK_KEY_TYPE *)templ[i].pValue)) != CKK_RSA) ||
          (rsa == CK_FALSE && (*((CK_KEY_TYPE *)templ[i].pValue)) != CKK_ECDSA))
        return CKR_TEMPLATE_INCONSISTENT;

      break;

    case CKA_PUBLIC_EXPONENT:
      if (rsa == CK_FALSE)
        return CKR_ATTRIBUTE_VALUE_INVALID;

      // Only support F4
      if (templ[i].ulValueLen != 3 || memcmp((CK_BYTE_PTR)templ[i].pValue, F4, 3) != 0) {
        DBG("Unsupported public exponent");
        return CKR_ATTRIBUTE_VALUE_INVALID;
      }

      break;

    case CKA_MODULUS_BITS:
      if (rsa == CK_FALSE)
        return CKR_ATTRIBUTE_VALUE_INVALID;

      switch(*(CK_ULONG_PTR)templ[i].pValue) {
        case 1024:
          gen->algorithm = YKPIV_ALGO_RSA1024;
          break;
        case 2048:
          gen->algorithm = YKPIV_ALGO_RSA2048; 
          break;
        default:
          DBG("Unsupported MODULUS_BITS (key length)");
          return CKR_ATTRIBUTE_VALUE_INVALID;
      }
      break;

    case CKA_EC_PARAMS:
      // Support PRIME256V1 and SECP384R1
      if (templ[i].ulValueLen == 10 && memcmp((CK_BYTE_PTR)templ[i].pValue, PRIME256V1, 10) == 0)
        gen->algorithm = YKPIV_ALGO_ECCP256;
      else if(templ[i].ulValueLen == 7 && memcmp((CK_BYTE_PTR)templ[i].pValue, SECP384R1, 7) == 0)
        gen->algorithm = YKPIV_ALGO_ECCP384;
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

  CK_BBOOL rsa = is_RSA_mechanism(mechanism->mechanism);

  for (CK_ULONG i = 0; i < n; i++) {
    switch (templ[i].type) {
    case CKA_CLASS:
      if (*((CK_ULONG_PTR)templ[i].pValue) != CKO_PRIVATE_KEY)
        return CKR_TEMPLATE_INCONSISTENT;

      break;

    case CKA_KEY_TYPE:
      if ((rsa == CK_TRUE  && (*((CK_KEY_TYPE *)templ[i].pValue)) != CKK_RSA) ||
          (rsa == CK_FALSE && (*((CK_KEY_TYPE *)templ[i].pValue)) != CKK_ECDSA))
        return CKR_TEMPLATE_INCONSISTENT;

      break;

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

CK_RV digest_mechanism_init(ykcs11_session_t *session) {

  const EVP_MD *md = NULL;

  switch (session->op_info.mechanism) {
    case CKM_MD5:
      md = EVP_md5();
      break;

    case CKM_RIPEMD160:
      md = EVP_ripemd160();
      break;

    case CKM_SHA_1:
      md = EVP_sha1();
      break;

    case CKM_ECDSA_SHA224:
      md = EVP_sha224();
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
      DBG("Mechanism %lu not supported", session->op_info.mechanism);
      return CKR_MECHANISM_INVALID;
  }

  session->op_info.md_ctx = EVP_MD_CTX_create();
  if (session->op_info.md_ctx == NULL) {
    DBG("EVP_MD_CTX_create failed");
    return CKR_FUNCTION_FAILED;
  }

  if (EVP_DigestInit_ex(session->op_info.md_ctx, md, NULL) <= 0) {
    DBG("EVP_DigestInit_ex failed");
    EVP_MD_CTX_destroy(session->op_info.md_ctx);
    session->op_info.md_ctx = NULL;
    return CKR_FUNCTION_FAILED;
  }

  session->op_info.out_len = EVP_MD_size(md);
  session->op_info.buf_len = 0;

  DBG("Initialized %s digest of length %lu", EVP_MD_name(md), session->op_info.out_len);
  return CKR_OK;
}

CK_RV digest_mechanism_update(ykcs11_session_t *session, CK_BYTE_PTR in, CK_ULONG in_len) {

  if(session->op_info.md_ctx) {
    if (EVP_DigestUpdate(session->op_info.md_ctx, in, in_len) <= 0) {
      DBG("EVP_DigestUpdate failed");
      return CKR_FUNCTION_FAILED;
    }
  } else {
    if(session->op_info.buf_len + in_len > sizeof(session->op_info.buf)) {
      DBG("Too much data added to operation buffer, max is %lu bytes", sizeof(session->op_info.buf));
      return CKR_DATA_LEN_RANGE;
    }
    memcpy(session->op_info.buf + session->op_info.buf_len, in, in_len);
    session->op_info.buf_len += in_len;
  }
  return CKR_OK;
}

CK_RV digest_mechanism_final(ykcs11_session_t *session, CK_BYTE_PTR pDigest, CK_ULONG_PTR pDigestLength) {

  unsigned int cbLength = *pDigestLength;
  int ret = EVP_DigestFinal_ex(session->op_info.md_ctx, pDigest, &cbLength);

  DBG("EVP_MD_CTX_destroy");
  EVP_MD_CTX_destroy(session->op_info.md_ctx);
  session->op_info.md_ctx = NULL;

  if (ret <= 0) {
    DBG("EVP_DigestFinal_ex with %lu bytes of data at %p failed", *pDigestLength, pDigest);
    return CKR_FUNCTION_FAILED;
  }

  DBG("EVP_DigestFinal_ex returned %u bytes of data", cbLength);
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