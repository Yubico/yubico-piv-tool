#ifndef OPENSSL_TYPES_H
#define OPENSSL_TYPES_H

#include <openssl/x509.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/ec.h>

typedef enum {
  YKCS11_NO_HASH,
  YKCS11_SHA1,
  //YKCS11_SHA224,
  YKCS11_SHA256,
  YKCS11_SHA384,
  YKCS11_SHA512,
  //YKCS11_RIPEMD128_RSA_PKCS,
  //YKCS11_RIPEMD160
} hash_t;

typedef EVP_MD_CTX ykcs11_md_ctx_t;

#endif
