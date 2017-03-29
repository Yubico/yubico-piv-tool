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
#include "openssl_utils.h"
#include "utils.h"
#include "debug.h"
#include <string.h>

#define F4 "\x01\x00\x01"
#define PRIME256V1 "\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07"

// Supported mechanisms for signature
static const CK_MECHANISM_TYPE sign_mechanisms[] = {
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
  CKM_ECDSA,
  CKM_ECDSA_SHA1,
  CKM_ECDSA_SHA256
};

// Supported mechanisms for key pair generation
static const CK_MECHANISM_TYPE generation_mechanisms[] = {
  CKM_RSA_PKCS_KEY_PAIR_GEN,
  //CKM_ECDSA_KEY_PAIR_GEN, Deperecated
  CKM_EC_KEY_PAIR_GEN
};

// Supported mechanisms for hashing
static const CK_MECHANISM_TYPE hash_mechanisms[] = {
  CKM_SHA_1,
  CKM_SHA256,
  CKM_SHA384,
  CKM_SHA512
};

CK_RV check_sign_mechanism(const ykcs11_session_t *s, const CK_MECHANISM_PTR m) {

  CK_ULONG          i;
  CK_BBOOL          supported = CK_FALSE;
  token_vendor_t    token;
  CK_MECHANISM_INFO info;

  // Check if the mechanism is supported by the module
  for (i = 0; i < sizeof(sign_mechanisms) / sizeof(CK_MECHANISM_TYPE); i++) {
    if (m->mechanism == sign_mechanisms[i]) {
      supported = CK_TRUE;
      break;
    }
  }
  if (supported == CK_FALSE)
    return CKR_MECHANISM_INVALID;

  // Check if the mechanism is supported by the token
  token = get_token_vendor(s->slot->token->vid);

  if (token.get_token_mechanism_info(m->mechanism, &info) != CKR_OK)
    return CKR_MECHANISM_INVALID;

  // TODO: also check that parametes make sense if any? And key size is in [min max]

  return CKR_OK;

}

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

CK_BBOOL is_PSS_mechanism(CK_MECHANISM_TYPE m) {

  switch (m) {
  case CKM_RSA_PKCS_PSS:
  case CKM_SHA1_RSA_PKCS_PSS:
//  case CKM_SHA224_RSA_PKCS_PSS:
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

CK_BBOOL is_hashed_mechanism(CK_MECHANISM_TYPE m) {

  switch (m) {
  case CKM_SHA1_RSA_PKCS:
  case CKM_SHA256_RSA_PKCS:
  case CKM_SHA384_RSA_PKCS:
  case CKM_SHA512_RSA_PKCS:
  case CKM_SHA1_RSA_PKCS_PSS:
  case CKM_SHA256_RSA_PKCS_PSS:
  case CKM_SHA384_RSA_PKCS_PSS:
  case CKM_SHA512_RSA_PKCS_PSS:
  case CKM_ECDSA_SHA1:
  case CKM_ECDSA_SHA256:
  case CKM_SHA_1:
  case CKM_SHA256:
  case CKM_SHA384:
  case CKM_SHA512:
    return CK_TRUE;

  default:
    return CK_FALSE;
  }

  // Not reached
  return CK_FALSE;
}

CK_RV apply_sign_mechanism_init(op_info_t *op_info) {

    if (op_info->type != YKCS11_SIGN)
      return CKR_FUNCTION_FAILED;

    switch (op_info->mechanism.mechanism) {
    case CKM_RSA_PKCS:
    case CKM_RSA_PKCS_PSS:
    case CKM_RSA_X_509:
    case CKM_ECDSA:
      // No hash required for this mechanism
      op_info->op.sign.md_ctx = NULL;
      return CKR_OK;

    case CKM_SHA1_RSA_PKCS:
    case CKM_SHA1_RSA_PKCS_PSS:
    case CKM_ECDSA_SHA1:
      return do_md_init(YKCS11_SHA1, &op_info->op.sign.md_ctx);

    case CKM_SHA256_RSA_PKCS:
    case CKM_SHA256_RSA_PKCS_PSS:
    case CKM_ECDSA_SHA256:
      return do_md_init(YKCS11_SHA256, &op_info->op.sign.md_ctx);

    case CKM_SHA384_RSA_PKCS:
    case CKM_SHA384_RSA_PKCS_PSS:
      return do_md_init(YKCS11_SHA384, &op_info->op.sign.md_ctx);

    case CKM_SHA512_RSA_PKCS:
    case CKM_SHA512_RSA_PKCS_PSS:
      return do_md_init(YKCS11_SHA512, &op_info->op.sign.md_ctx);

    default:
      return CKR_FUNCTION_FAILED;
  }

    // Never reached
    return CKR_FUNCTION_FAILED;
}

CK_RV apply_sign_mechanism_update(op_info_t *op_info, CK_BYTE_PTR in, CK_ULONG in_len) {
  CK_RV rv;

  if (op_info->type != YKCS11_SIGN)
    return CKR_FUNCTION_FAILED;

  switch (op_info->mechanism.mechanism) {
  case CKM_RSA_PKCS:
  case CKM_RSA_PKCS_PSS:
  case CKM_ECDSA:
  case CKM_RSA_X_509:
    // Mechanism not suitable for multipart signatures
    return CKR_FUNCTION_FAILED;

  case CKM_SHA1_RSA_PKCS:
  case CKM_SHA256_RSA_PKCS:
  case CKM_SHA384_RSA_PKCS:
  case CKM_SHA512_RSA_PKCS:
  case CKM_SHA1_RSA_PKCS_PSS:
  case CKM_SHA256_RSA_PKCS_PSS:
  case CKM_SHA384_RSA_PKCS_PSS:
  case CKM_SHA512_RSA_PKCS_PSS:
  case CKM_ECDSA_SHA1:
  case CKM_ECDSA_SHA256:
    rv = do_md_update(op_info->op.sign.md_ctx, in, in_len);
    if (rv != CKR_OK)
      return CKR_FUNCTION_FAILED;

    return CKR_OK;

  default:
    return CKR_FUNCTION_FAILED;
  }

}

CK_RV apply_sign_mechanism_finalize(op_info_t *op_info) {

  CK_RV    rv;
  int      nid = NID_undef;
  CK_ULONG len;

  if (op_info->type != YKCS11_SIGN)
    return CKR_FUNCTION_FAILED;

  switch (op_info->mechanism.mechanism) {
  case CKM_SHA1_RSA_PKCS_PSS:
  case CKM_SHA256_RSA_PKCS_PSS:
  case CKM_SHA384_RSA_PKCS_PSS:
  case CKM_SHA512_RSA_PKCS_PSS:
    // Finalize the hash
    rv = do_md_finalize(op_info->op.sign.md_ctx, op_info->buf, &op_info->buf_len, &nid);
    op_info->op.sign.md_ctx = NULL;
    if (rv != CKR_OK)
      return CKR_FUNCTION_FAILED;

  case CKM_RSA_PKCS_PSS:
    // Compute padding for all PSS variants
    // TODO: digestinfo/paraminfo ?
    rv = do_pkcs_pss(op_info->op.sign.key, op_info->buf, op_info->buf_len, nid, op_info->buf, &op_info->buf_len);
    do_free_rsa_public_key(op_info->op.sign.key);

    return rv;

  case CKM_RSA_X_509:
    // Padding in this case consists of prepending zeroes
    len = (op_info->op.sign.key_len / 8) - op_info->buf_len;
    memmove(op_info->buf + len, op_info->buf, op_info->buf_len);
    memset(op_info->buf, 0, len);
    op_info->buf_len = op_info->op.sign.key_len / 8;
    return CKR_OK;

  case CKM_SHA1_RSA_PKCS:
  case CKM_SHA256_RSA_PKCS:
  case CKM_SHA384_RSA_PKCS:
  case CKM_SHA512_RSA_PKCS:
    // Finalize the hash add digest info
    rv = do_md_finalize(op_info->op.sign.md_ctx, op_info->buf, &op_info->buf_len, &nid);
    op_info->op.sign.md_ctx = NULL;
    if (rv != CKR_OK)
      return CKR_FUNCTION_FAILED;

  case CKM_RSA_PKCS:
    // Add digest info if needed
    if (nid != NID_undef) {
      rv = do_pkcs_1_digest_info(op_info->buf, op_info->buf_len, nid, op_info->buf, &op_info->buf_len);
      if (rv != CKR_OK)
        return CKR_FUNCTION_FAILED;
    }

    // Compute padding for all PKCS1 variants
    len = op_info->buf_len;
    op_info->buf_len = sizeof(op_info->buf);
    return do_pkcs_1_t1(op_info->buf, len, op_info->buf, &op_info->buf_len, op_info->op.sign.key_len);

  case CKM_ECDSA_SHA1:
  case CKM_ECDSA_SHA256:
    // Finalize the hash
    rv = do_md_finalize(op_info->op.sign.md_ctx, op_info->buf, &op_info->buf_len, &nid);
    op_info->op.sign.md_ctx = NULL;
    if (rv != CKR_OK)
      return CKR_FUNCTION_FAILED;

  case CKM_ECDSA:
    return CKR_OK;

  default:
    return CKR_FUNCTION_FAILED;
  }
}

CK_RV sign_mechanism_cleanup(op_info_t *op_info) {

  if (op_info->op.sign.md_ctx != NULL) {
    do_md_cleanup(op_info->op.sign.md_ctx);
    op_info->op.sign.md_ctx = NULL;
  }

  return CKR_OK;
}

CK_RV check_generation_mechanism(const ykcs11_session_t *s, CK_MECHANISM_PTR m) {

  CK_ULONG          i;
  CK_BBOOL          supported = CK_FALSE;
  token_vendor_t    token;
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
  token = get_token_vendor(s->slot->token->vid);

  if (token.get_token_mechanism_info(m->mechanism, &info) != CKR_OK)
    return CKR_MECHANISM_INVALID;

  // TODO: also check that parametes make sense if any? And key size is in [min max]

  return CKR_OK;

}

CK_RV check_pubkey_template(op_info_t *op_info, CK_ATTRIBUTE_PTR templ, CK_ULONG n) {

  CK_ULONG i;

  op_info->op.gen.rsa = is_RSA_mechanism(op_info->mechanism.mechanism);

  for (i = 0; i < n; i++) {
    switch (templ[i].type) {
    case CKA_CLASS:
      if (*((CK_ULONG_PTR) templ[i].pValue) != CKO_PUBLIC_KEY)
        return CKR_TEMPLATE_INCONSISTENT;

      break;

    case CKA_KEY_TYPE:
      if ((op_info->op.gen.rsa == CK_TRUE  && (*((CK_KEY_TYPE *)templ[i].pValue)) != CKK_RSA) ||
          (op_info->op.gen.rsa == CK_FALSE && (*((CK_KEY_TYPE *)templ[i].pValue)) != CKK_ECDSA))
        return CKR_TEMPLATE_INCONSISTENT;

      break;

    case CKA_PUBLIC_EXPONENT:
      if (op_info->op.gen.rsa == CK_FALSE)
        return CKR_ATTRIBUTE_VALUE_INVALID;

      // Only support F4
      if (templ[i].ulValueLen != 3 || memcmp((CK_BYTE_PTR)templ[i].pValue, F4, 3) != 0) {
        DBG("Unsupported public exponent");
        return CKR_ATTRIBUTE_VALUE_INVALID;
      }

      break;

    case CKA_MODULUS_BITS:
      if (op_info->op.gen.rsa == CK_FALSE)
        return CKR_ATTRIBUTE_VALUE_INVALID;

      if (*((CK_ULONG_PTR) templ[i].pValue) != 1024 &&
          *((CK_ULONG_PTR) templ[i].pValue) != 2048) { // TODO: make define?
        DBG("Unsupported MODULUS_BITS (key length)");
        return CKR_ATTRIBUTE_VALUE_INVALID;
      }

      op_info->op.gen.key_len = *((CK_ULONG_PTR) templ[i].pValue);
      break;

    case CKA_EC_PARAMS:
      // Only support PRIME256V1
      if (templ[i].ulValueLen != 10 || memcmp((CK_BYTE_PTR)templ[i].pValue, PRIME256V1, 10) != 0)
        return CKR_FUNCTION_FAILED;

      op_info->op.gen.key_len = 256;
      break;

    case CKA_ID:
      if (is_valid_key_id(*((CK_BYTE_PTR)templ[i].pValue)) == CK_FALSE)
        return CKR_ATTRIBUTE_VALUE_INVALID;

      op_info->op.gen.key_id = PIV_PVTK_OBJ_PIV_AUTH + *((CK_BYTE_PTR)templ[i].pValue);
      break;

    case CKA_TOKEN:
    case CKA_ENCRYPT:
    case CKA_VERIFY:
    case CKA_WRAP:
    case CKA_DERIVE:
      // Ignore these attributes for now
      break;

    default:
      DBG("Invalid attribute %lx in public key template", templ[i].type);
      return CKR_ATTRIBUTE_TYPE_INVALID;
    }
  }

  return CKR_OK;

}

CK_RV check_pvtkey_template(op_info_t *op_info, CK_ATTRIBUTE_PTR templ, CK_ULONG n) {

  CK_ULONG i;

  op_info->op.gen.rsa = is_RSA_mechanism(op_info->mechanism.mechanism);
  op_info->op.gen.vendor_defined = 0;

  for (i = 0; i < n; i++) {
    switch (templ[i].type) {
    case CKA_CLASS:
      if (*((CK_ULONG_PTR)templ[i].pValue) != CKO_PRIVATE_KEY)
        return CKR_TEMPLATE_INCONSISTENT;

      break;

    case CKA_KEY_TYPE:
      if ((op_info->op.gen.rsa == CK_TRUE  && (*((CK_KEY_TYPE *)templ[i].pValue)) != CKK_RSA) ||
          (op_info->op.gen.rsa == CK_FALSE && (*((CK_KEY_TYPE *)templ[i].pValue)) != CKK_ECDSA))
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
      if (is_valid_key_id(*((CK_BYTE_PTR)templ[i].pValue)) == CK_FALSE)
        return CKR_ATTRIBUTE_VALUE_INVALID;

      // Check if ID was already specified in the public key template
      // In that case it has to match
      if (op_info->op.gen.key_id != 0 &&
          op_info->op.gen.key_id != (*((CK_BYTE_PTR)templ[i].pValue) + PIV_PVTK_OBJ_PIV_AUTH))
        return CKR_TEMPLATE_INCONSISTENT;

      op_info->op.gen.key_id = PIV_PVTK_OBJ_PIV_AUTH + *((CK_BYTE_PTR)templ[i].pValue);
      break;

    case CKA_VENDOR_DEFINED:
      op_info->op.gen.vendor_defined = (*((CK_ULONG_PTR)templ[i].pValue));

    case CKA_SENSITIVE:
    case CKA_DECRYPT:
    case CKA_UNWRAP:
    case CKA_SIGN:
    case CKA_PRIVATE:
    case CKA_TOKEN:
    case CKA_DERIVE:
      // Ignore these attributes for now
      break;

    default:
      DBG("Invalid attribute %lx in private key template", templ[i].type);
      return CKR_ATTRIBUTE_TYPE_INVALID;
    }
  }

  return CKR_OK;

}

CK_RV check_hash_mechanism(const ykcs11_session_t *s, CK_MECHANISM_PTR m) {

  CK_ULONG          i;
  CK_BBOOL          supported = CK_FALSE;
  token_vendor_t    token;
  CK_MECHANISM_INFO info;

  // Check if the mechanism is supported by the module
  for (i = 0; i < sizeof(hash_mechanisms) / sizeof(CK_MECHANISM_TYPE); i++) {
    if (m->mechanism == hash_mechanisms[i]) {
      supported = CK_TRUE;
      break;
    }
  }
  if (supported == CK_FALSE)
    return CKR_MECHANISM_INVALID;

  // Check if the mechanism is supported by the token
  token = get_token_vendor(s->slot->token->vid);

  if (token.get_token_mechanism_info(m->mechanism, &info) != CKR_OK)
    return CKR_MECHANISM_INVALID;

  // TODO: also check that parametes make sense if any? And key size is in [min max]

  return CKR_OK;

}
