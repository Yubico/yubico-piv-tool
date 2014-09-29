 /*
 * Copyright (c) 2014 Yubico AB
 * All rights reserved.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 * Additional permission under GNU GPL version 3 section 7
 *
 * If you modify this program, or any covered work, by linking or
 * combining it with the OpenSSL project's OpenSSL library (or a
 * modified version of that library), containing parts covered by the
 * terms of the OpenSSL or SSLeay licenses, We grant you additional 
 * permission to convey the resulting work. Corresponding Source for a
 * non-source form of such a combination shall include the source code
 * for the parts of OpenSSL used as well as that of the covered work.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>

#include "ykpiv.h"

#ifdef _WIN32
#include <windows.h>
#endif

#include "cmdline-signer.h"
#include "util.h"

static bool verify_pin(ykpiv_state *state, const char *pin) {
  int tries = -1;
  ykpiv_rc res;
  int len = strlen(pin);

  if(len > 8) {
    fprintf(stderr, "Maximum 8 digits of PIN supported.\n");
  }

  res = ykpiv_verify(state, pin, &tries);
  if(res == YKPIV_OK) {
    return true;
  } else if(res == YKPIV_WRONG_PIN) {
    if(tries > 0) {
      fprintf(stderr, "Pin verification failed, %d tries left before pin is blocked.\n", tries);
    } else {
      fprintf(stderr, "Pin code blocked.\n");
    }
  } else {
    fprintf(stderr, "Pin code verification failed: '%s'\n", ykpiv_strerror(res));
  }
  return false;
}

static bool sign_file(ykpiv_state *state, const char *input, const char *output,
    const char *slot, enum enum_algorithm algorithm, enum enum_hash hash,
    int verbosity) {
  FILE *input_file = NULL;
  FILE *output_file = NULL;
  int key;
  unsigned int hash_len;
  unsigned char hashed[EVP_MAX_MD_SIZE];
  bool ret = false;
  int algo;
  int nid;

  sscanf(slot, "%x", &key);

  input_file = open_file(input, INPUT);
  if(!input_file) {
    return false;
  }

  output_file = open_file(output, OUTPUT);
  if(!output_file) {
    return false;
  }

  switch(algorithm) {
    case algorithm_arg_RSA2048:
      algo = YKPIV_ALGO_RSA2048;
      break;
    case algorithm_arg_RSA1024:
      algo = YKPIV_ALGO_RSA1024;
      break;
    case algorithm_arg_ECCP256:
      algo = YKPIV_ALGO_ECCP256;
      break;
    case algorithm__NULL:
    default:
      goto out;
  }

  {
    const EVP_MD *md;
    EVP_MD_CTX *mdctx;

    switch(hash) {
      case hash_arg_SHA1:
        md = EVP_sha1();
        nid = NID_sha1;
        break;
      case hash_arg_SHA256:
        md = EVP_sha256();
        nid = NID_sha256;
        break;
      case hash_arg_SHA512:
        md = EVP_sha512();
        nid = NID_sha512;
        break;
      case hash__NULL:
      default:
        goto out;
    }

    mdctx = EVP_MD_CTX_create();
    EVP_DigestInit_ex(mdctx, md, NULL);
    while(!feof(input_file)) {
      char buf[1024];
      size_t len = fread(buf, 1, 1024, input_file);
      EVP_DigestUpdate(mdctx, buf, len);
    }
    EVP_DigestFinal_ex(mdctx, hashed, &hash_len);

    if(verbosity) {
      fprintf(stderr, "file hashed as: ");
      dump_hex(hashed, hash_len);
      fprintf(stderr, "\n");
    }
    EVP_MD_CTX_destroy(mdctx);
  }

  if(algo == YKPIV_ALGO_RSA1024 || algo == YKPIV_ALGO_RSA2048) {
    X509_SIG digestInfo;
    X509_ALGOR algor;
    ASN1_TYPE parameter;
    ASN1_OCTET_STRING digest;
    unsigned char buf[1024];
    unsigned char *ptr = hashed;

    memcpy(buf, hashed, hash_len);

    digestInfo.algor = &algor;
    digestInfo.algor->algorithm = OBJ_nid2obj(nid);
    digestInfo.algor->parameter = &parameter;
    digestInfo.algor->parameter->type = V_ASN1_NULL;
    digestInfo.algor->parameter->value.ptr = NULL;
    digestInfo.digest = &digest;
    digestInfo.digest->data = buf;
    digestInfo.digest->length = (int)hash_len;
    hash_len = (unsigned int)i2d_X509_SIG(&digestInfo, &ptr);
  }

  {
    unsigned char buf[1024];
    size_t len = sizeof(buf);
    if(ykpiv_sign_data(state, hashed, hash_len, buf, &len, algo, key) != YKPIV_OK) {
      fprintf(stderr, "failed signing file\n");
      goto out;
    }

    if(verbosity) {
      fprintf(stderr, "file signed as: ");
      dump_hex(buf, len);
      fprintf(stderr, "\n");
    }
    fwrite(buf, 1, len, output_file);
    ret = true;
  }

out:
  if(input_file && input_file != stdin) {
    fclose(input_file);
  }

  if(output_file && output_file != stdout) {
    fclose(output_file);
  }

  return ret;
}

int main(int argc, char *argv[]) {
  struct gengetopt_args_info args_info;
  ykpiv_state *state;
  int verbosity;
  int ret = EXIT_SUCCESS;
  bool rc;

  if(cmdline_parser(argc, argv, &args_info) != 0) {
    return EXIT_FAILURE;
  }

  verbosity = args_info.verbose_arg + (int)args_info.verbose_given;

  if(ykpiv_init(&state, verbosity) != YKPIV_OK) {
    fprintf(stderr, "Failed initializing library.\n");
    return EXIT_FAILURE;
  }

  if(ykpiv_connect(state, args_info.reader_arg) != YKPIV_OK) {
    fprintf(stderr, "Failed to connect to reader.\n");
    return EXIT_FAILURE;
  }

  if(verify_pin(state, args_info.pin_arg)) {
    if(verbosity) {
      fprintf(stderr, "Successfully verified PIN.\n");
    }
  } else {
    return EXIT_FAILURE;
  }

  /* openssl setup.. */
  OpenSSL_add_all_algorithms();

  rc = sign_file(state, args_info.input_arg, args_info.output_arg,
      args_info.slot_orig, args_info.algorithm_arg, args_info.hash_arg,
      verbosity);

  if(rc == false) {
    fprintf(stderr, "Failed signing!\n");
    ret = EXIT_FAILURE;
  } else {
    fprintf(stderr, "Signature successful!\n");
  }

  ykpiv_done(state);
  EVP_cleanup();
  return ret;
}
