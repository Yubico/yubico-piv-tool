#include "mechanisms.h"

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
  CKM_ECDSA_SHA1
};

// Supported mechanisms for key pair generation
static const CK_MECHANISM_TYPE generation_mechanisms[] = {
  CKM_RSA_PKCS_KEY_PAIR_GEN,
  //CKM_ECDSA_KEY_PAIR_GEN, Deperecated
  CKM_EC_KEY_PAIR_GEN
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
      // No hash required for this mechanism
      return CKR_OK;

    case CKM_RSA_PKCS_PSS:
      // No hash required for this mechanism
      return CKR_OK;

    case CKM_RSA_X_509:
      // No hash required for this mechanism
      return CKR_OK;

    case CKM_SHA1_RSA_PKCS:
    case CKM_SHA1_RSA_PKCS_PSS:
    case CKM_ECDSA_SHA1:
      return do_md_init(YKCS11_SHA1, &op_info->op.sign.md_ctx);

    case CKM_SHA256_RSA_PKCS:
    case CKM_SHA256_RSA_PKCS_PSS:
      return do_md_init(YKCS11_SHA256, &op_info->op.sign.md_ctx);

    case CKM_SHA384_RSA_PKCS:
    case CKM_SHA384_RSA_PKCS_PSS:
      return do_md_init(YKCS11_SHA384, &op_info->op.sign.md_ctx);

    case CKM_SHA512_RSA_PKCS:
    case CKM_SHA512_RSA_PKCS_PSS:
      return do_md_init(YKCS11_SHA512, &op_info->op.sign.md_ctx);

    case CKM_ECDSA:
      // No hash required for this mechanism
      return CKR_OK;

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
    // Mechanism not suitable for multipart signatures
    return CKR_FUNCTION_FAILED;

  case CKM_RSA_X_509:
    return CKR_OK;

  case CKM_SHA1_RSA_PKCS:
  case CKM_SHA256_RSA_PKCS:
  case CKM_SHA384_RSA_PKCS:
  case CKM_SHA512_RSA_PKCS:
  case CKM_SHA1_RSA_PKCS_PSS:
  case CKM_SHA256_RSA_PKCS_PSS:
  case CKM_SHA384_RSA_PKCS_PSS:
  case CKM_SHA512_RSA_PKCS_PSS:
  case CKM_ECDSA_SHA1:
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
  RSA      *rsa;
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
    if (rv != CKR_OK)
      return CKR_FUNCTION_FAILED;

  case CKM_RSA_PKCS_PSS:
    // Compute padding for all PSS variants
    // TODO: digestinfo/paraminfo ?

    rv = do_encode_rsa_public_key(op_info->op.sign.key, op_info->op.sign.key_len, &rsa);
    if (rv != CKR_OK)
      return CKR_FUNCTION_FAILED;
    
    rv = do_pkcs_pss(rsa, op_info->buf, op_info->buf_len, nid, op_info->buf, &op_info->buf_len);

    // TODO: does rsa have to be free'd ?
    
    return rv;

  case CKM_RSA_X_509:
    return CKR_OK;

  case CKM_SHA1_RSA_PKCS:
  case CKM_SHA256_RSA_PKCS:
  case CKM_SHA384_RSA_PKCS:
  case CKM_SHA512_RSA_PKCS:
    // Finalize the hash add digest info
    rv = do_md_finalize(op_info->op.sign.md_ctx, op_info->buf, &op_info->buf_len, &nid);
    if (rv != CKR_OK)
      return CKR_FUNCTION_FAILED;
    DBG(("The hashed value is %lu long and looks like\n", op_info->buf_len));
    dump_hex(op_info->buf, op_info->buf_len, stderr, CK_TRUE);

  case CKM_RSA_PKCS:
    // Add digest info if needed
    if (nid != NID_undef) {
      rv = do_pkcs_1_digest_info(op_info->buf, op_info->buf_len, nid, op_info->buf, &op_info->buf_len);
      if (rv != CKR_OK)
        return CKR_FUNCTION_FAILED;

      DBG(("After adding digestinfo is %lu long and looks like\n", op_info->buf_len));
      dump_hex(op_info->buf, op_info->buf_len, stderr, CK_TRUE);
    }
    
    // Compute padding for all PKCS1 variants
    len = op_info->buf_len;
    op_info->buf_len = sizeof(op_info->buf);
    return do_pkcs_1_t1(op_info->buf, len, op_info->buf, &op_info->buf_len, op_info->op.sign.key_len);

  case CKM_ECDSA_SHA1:
    // Finalize the hash
    rv = do_md_finalize(op_info->op.sign.md_ctx, op_info->buf, &op_info->buf_len, &nid);
    if (rv != CKR_OK)
      return CKR_FUNCTION_FAILED;

  case CKM_ECDSA:
    return CKR_OK;

  default:
    return CKR_FUNCTION_FAILED;
  }
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
  CK_BBOOL rsa_mechanism;

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
        return CKR_MECHANISM_PARAM_INVALID;

      // Only support F4
      if (templ[i].ulValueLen != 3 || memcmp((CK_BYTE_PTR)templ[i].pValue, "\x01\x00\x01", 3) != 0)
        return CKR_MECHANISM_PARAM_INVALID;

      break;

    case CKA_MODULUS_BITS:
      if (op_info->op.gen.rsa == CK_FALSE)
        return CKR_MECHANISM_PARAM_INVALID;

      if (*((CK_ULONG_PTR)templ[i].pValue) != 1024 &&
          *((CK_ULONG_PTR) templ[i].pValue) != 2048) // TODO: make define?
        return CKR_MECHANISM_PARAM_INVALID;

      op_info->op.gen.key_len = *((CK_ULONG_PTR) templ[i].pValue); // TODO: check length?
      break;

    case CKA_ID:
      // TODO: get pvt key with attributed id and store it's id into op_info

    case CKA_TOKEN:
    case CKA_ENCRYPT:
    case CKA_VERIFY:
    case CKA_WRAP:
      // Ignore these attributes for now
      break;

    default:
      return CKR_MECHANISM_PARAM_INVALID;
    }
  }

  return CKR_OK;
  
}

CK_RV check_pvtkey_template(op_info_t *op_info, CK_ATTRIBUTE_PTR templ, CK_ULONG n) {

  CK_ULONG i;
  CK_BBOOL rsa_mechanism;

  op_info->op.gen.rsa = is_RSA_mechanism(op_info->mechanism.mechanism);

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

    case CKA_PUBLIC_EXPONENT:
      if (op_info->op.gen.rsa == CK_FALSE)
        return CKR_MECHANISM_PARAM_INVALID;

      // Only support F4
      if (templ[i].ulValueLen != 3 || memcmp((CK_BYTE_PTR)templ[i].pValue, "\x01\x00\x01", 3) != 0)
        return CKR_MECHANISM_PARAM_INVALID;

      break;

    case CKA_MODULUS_BITS:
      if (op_info->op.gen.rsa == CK_FALSE)
        return CKR_MECHANISM_PARAM_INVALID;

      if (*((CK_ULONG_PTR)templ[i].pValue) != 1024 &&
          *((CK_ULONG_PTR) templ[i].pValue) != 2048) // TODO: make define?
        return CKR_MECHANISM_PARAM_INVALID;

      op_info->op.gen.key_len = *((CK_ULONG_PTR) templ[i].pValue); // TODO: check length?
      break;

    case CKA_SENSITIVE:
    case CKA_DECRYPT:
    case CKA_UNWRAP:
    case CKA_SIGN:
    case CKA_PRIVATE:
    case CKA_TOKEN:
      // Ignore these attributes for now
      break;

    default:
        return CKR_MECHANISM_PARAM_INVALID;
    }
  }

  return CKR_OK;
  
}
