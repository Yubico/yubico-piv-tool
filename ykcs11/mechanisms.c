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

  // TODO: also check that parametes make sense if any?

  CKR_OK;

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
      return CKR_FUNCTION_FAILED; // TODO: but no hash needed

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

  case CKM_ECDSA:
    return CKR_FUNCTION_FAILED;

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
    fprintf(stderr, "The hashed value is %lu long and looks like\n", op_info->buf_len);
    dump_hex(op_info->buf, op_info->buf_len, stderr, CK_TRUE);

  case CKM_RSA_PKCS:
    // Add digest info if needed
    if (nid != NID_undef) {
      rv = do_pkcs_1_digest_info(op_info->buf, op_info->buf_len, nid, op_info->buf, &op_info->buf_len);
      if (rv != CKR_OK)
        return CKR_FUNCTION_FAILED;

      fprintf(stderr, "After adding digestinfo is %lu long and looks like\n", op_info->buf_len);
      dump_hex(op_info->buf, op_info->buf_len, stderr, CK_TRUE);
    }
    
    // Compute padding for all PKCS1 variants
    len = op_info->buf_len;
    op_info->buf_len = sizeof(op_info->buf);
    return do_pkcs_1_t1(op_info->buf, len, op_info->buf, &op_info->buf_len, op_info->op.sign.key_len);

  case CKM_ECDSA_SHA1: // TODO:
  case CKM_ECDSA:
    return CKR_FUNCTION_FAILED;

  default:
    return CKR_FUNCTION_FAILED;
  }
}
