 /*
 * Copyright (c) 2014-2015 Yubico AB
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

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "ykpiv.h"

#ifdef _WIN32
#include <windows.h>
#endif

#include <openssl/des.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include "cmdline.h"
#include "util.h"

/* FASC-N containing S9999F9999F999999F0F1F0000000000300001E encoded in
 * 4-bit BCD with 1 bit parity. run through the tools/fasc.pl script to get
 * bytes. */
/* this CHUID has an expiry of 2030-01-01, maybe that should be variable.. */
unsigned const char chuid_tmpl[] = {
  0x30, 0x19, 0xd4, 0xe7, 0x39, 0xda, 0x73, 0x9c, 0xed, 0x39, 0xce, 0x73, 0x9d,
  0x83, 0x68, 0x58, 0x21, 0x08, 0x42, 0x10, 0x84, 0x21, 0x38, 0x42, 0x10, 0xc3,
  0xf5, 0x34, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x35, 0x08, 0x32, 0x30, 0x33, 0x30, 0x30,
  0x31, 0x30, 0x31, 0x3e, 0x00, 0xfe, 0x00,
};
#define CHUID_GUID_OFFS 29

unsigned const char sha1oid[] = {
  0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2B, 0x0E, 0x03, 0x02, 0x1A, 0x05, 0x00,
  0x04, 0x14
};

unsigned const char sha256oid[] = {
  0x30, 0x31, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04,
  0x02, 0x01, 0x05, 0x00, 0x04, 0x20
};

unsigned const char sha512oid[] = {
  0x30, 0x51, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04,
  0x02, 0x03, 0x05, 0x00, 0x04, 0x40
};

#define KEY_LEN 24
#define SALT_LEN 16

static void print_version(ykpiv_state *state, const char *output_file_name) {
  char version[7];
  FILE *output_file = open_file(output_file_name, OUTPUT);
  if(!output_file) {
    fprintf(stderr, "Failed opening output_file_name\n");
  }

  if(ykpiv_get_version(state, version, sizeof(version)) == YKPIV_OK) {
    fprintf(output_file, "Applet version %s found.\n", version);
  } else {
    fprintf(stderr, "Failed to retrieve applet version.\n");
  }

  if(output_file != stdout) {
    fclose(output_file);
  }
}

/**
 * Reads the YKPIV_OBJ_PIVMAN_DATA area from the token.
 *
 * @brief read_pivman_data
 * @param state
 * @param data a pointer to where to put the data
 * @param data_len
 * @param verbosity logging level indicator
 * @return YKPIV_OK (0) if success
 */
static ykpiv_rc read_pivman_data(ykpiv_state* state,
                                 unsigned char* data,
                                 size_t* data_len,
                                 const int verbosity) {
  unsigned char raw_data[*data_len];
  ykpiv_rc ret = ykpiv_fetch_object(state, YKPIV_OBJ_PIVMAN_DATA, raw_data, data_len);

  if (ret == YKPIV_OK) {

    if (verbosity >= 2) {
      fprintf(stderr, "pivman data: ");
      dump_hex(raw_data, *data_len, stderr, false);
    }

    if (parse_value_from_tlv(YKPIV_TAG_PIVMAN_DATA, raw_data, data_len)) {
      memcpy(data, raw_data, *data_len);
    } else {
      return YKPIV_PARSE_ERROR;
    }
  } else {
    if (verbosity > 2) {
      fprintf(stderr, "No pivman data found, error: %d\n", ret);
    }
  }
  return ret;
}

/**
 * Checks if there is a salt tagged in the YKPIV_OBJ_PIVMAN_DATA area.
 *
 * @brief has_salt
 * @param state
 * @param current_salt pointer to where to store the existing salt.
 * @param current_salt_len
 * @param verbosity logging level indicator
 * @return true on success, otherwise false.
 */
static bool has_salt(ykpiv_state* state,
                     unsigned char* current_salt,
                     size_t* current_salt_len,
                     const int verbosity) {
  unsigned char data[256];
  memset (data, 0x00, 256);
  size_t data_len = 256;
  ykpiv_rc ret = read_pivman_data(state, data, &data_len, verbosity);

  if (ret == YKPIV_OK) {
    unsigned char* salt_ptr = memchr(data, YKPIV_TAG_SALT, data_len);
    if (salt_ptr != NULL) {
      int length = 0;
      int offset = get_length(++salt_ptr, &length);
      salt_ptr = salt_ptr + offset;

      if (salt_ptr != NULL && length == SALT_LEN) {

        if (current_salt && *current_salt_len >= SALT_LEN) {
          memcpy(current_salt, salt_ptr, SALT_LEN);
          *current_salt_len = SALT_LEN;

          if (verbosity >= 2) {
            fprintf(stderr, "Salt found: ");
            dump_hex(current_salt, *current_salt_len, stderr, false);
          }
        }
        return true;
      } else {
        fprintf(stderr, "Read salt data is null or of wrong length.");
        return false;
      }
    }

  } else {
    if(verbosity > 2) {
      fprintf(stderr, "Failed to read salt data. %#x\n", ret);
    }
    return false;
  }
}

/**
 * Updates the salt entry, or writes a new entry, in YKPIV_OBJ_PIVMAN_DATA.
 *
 * @brief update_salt
 * @param state
 * @param new_salt the new salt to write, if NULL the salt will be removed.
 * @param new_salt_len the new salt length, if 0 the salt will be removed.
 * @param verbosity logging level indicator
 * @return true on success
 */
static bool update_salt(ykpiv_state* state,
                        const unsigned char* new_salt,
                        const size_t new_salt_len,
                        const int verbosity) {

  ykpiv_rc ret = YKPIV_GENERIC_ERROR;
  unsigned char pivman_data[256];
  memset(pivman_data, 0x00, 256);
  size_t data_len = 256;
  ret = read_pivman_data(state, pivman_data, &data_len, verbosity);
  if (ret == YKPIV_OK) {

    if (verbosity >= 2) {
      fprintf(stderr, "Current pivman data: ");
      dump_hex(pivman_data, data_len, stderr, false);
    }

    unsigned char* salt_ptr = memchr(pivman_data, YKPIV_TAG_SALT, data_len);
    if (salt_ptr != NULL) {
      int length = 0;
      int offset = get_length(salt_ptr + 1, &length);

      // If salt is null and legth is 0 we want to remove the existing salt from PIVMAN_DATA
      if (new_salt == NULL || new_salt_len == 0) {
        size_t salt_tlv_size = 1 + offset + length;
        memset(salt_ptr, 0x00, salt_tlv_size);
        memmove(salt_ptr, salt_ptr + salt_tlv_size, data_len - salt_tlv_size - (salt_ptr - pivman_data));
        data_len = data_len - salt_tlv_size;
      } else {
        salt_ptr = salt_ptr + 1 + offset;
        memcpy(salt_ptr, new_salt, new_salt_len);
      }

    } else {
      // No salt tag found to update, add new one.
      pivman_data[data_len] = 0x82;
      int offset = set_length(pivman_data + data_len + 1, new_salt_len);
      memcpy(pivman_data + data_len + 1 + offset, new_salt, new_salt_len);
      data_len = data_len + 1 + offset + new_salt_len;
    }

    if (verbosity >= 2) {
      fprintf(stderr, "New pivman data: ");
      dump_hex(pivman_data, data_len, stderr, false);
    }

    // Add PIVMAN_DATA tag and length and append the new data.
    unsigned char data_to_write[256];
    memset(data_to_write, 0x00, 256);
    data_to_write[0] = 0x80;
    unsigned char* length_ptr = data_to_write + 1;
    int offset = set_length(length_ptr, data_len);
    memcpy(length_ptr + offset, pivman_data, data_len);

    ret = ykpiv_save_object(state, YKPIV_OBJ_PIVMAN_DATA, data_to_write, strlen(data_to_write));
    if (ret == YKPIV_OK) {
      printf("PIV Data written.\n");
      return true;
    }
  }
  fprintf(stderr, "Could not update salt. %d\n", ret);
  return false;
}

static bool derive_key(const unsigned char* pin,
                       const unsigned char* salt,
                       const size_t salt_len,
                       unsigned char* out,
                       size_t* out_len,
                       int verbosity) {

  size_t pin_len = 0;

  if(pin) {
    pin_len = strlen(pin);
  } else {
    return false;
  }

  if(!salt && salt_len != SALT_LEN) {
    fprintf(stderr, "Salt is not of right length. Actual: %zu. Expected: %d", salt_len, SALT_LEN);
    return false;
  }

  if (*out_len >= KEY_LEN) {
    unsigned char key[KEY_LEN];
    memset(out, 0x00, KEY_LEN);
    memset(key, 0x00, KEY_LEN);
    *out_len = KEY_LEN;
    PKCS5_PBKDF2_HMAC_SHA1(pin, pin_len, salt, salt_len, 10000, KEY_LEN, out);

    if (verbosity >= 2) {
      fprintf(stderr, "Derived key: ");
      dump_hex(out, *out_len, stderr, false);
    }

    return true;
  } else {
    return false;
  }
}

static bool generate_key(ykpiv_state *state,
                         const char *slot,
                         enum enum_algorithm algorithm,
                         const char *output_file_name,
                         enum enum_key_format key_format) {
  unsigned char in_data[5];
  unsigned char data[1024];
  unsigned char templ[] = {0, YKPIV_INS_GENERATE_ASYMMERTRIC, 0, 0};
  unsigned long recv_len = sizeof(data);
  int sw;
  int key = 0;
  FILE *output_file = NULL;
  bool ret = false;
  EVP_PKEY *public_key = NULL;
  RSA *rsa = NULL;
  BIGNUM *bignum_n = NULL;
  BIGNUM *bignum_e = NULL;
  EC_KEY *eckey = NULL;
  EC_POINT *point = NULL;

  sscanf(slot, "%2x", &key);
  templ[3] = key;

  output_file = open_file(output_file_name, OUTPUT);
  if(!output_file) {
    return false;
  }

  in_data[0] = 0xac;
  in_data[1] = 3;
  in_data[2] = 0x80;
  in_data[3] = 1;
  switch(algorithm) {
    case algorithm_arg_RSA2048:
      in_data[4] = YKPIV_ALGO_RSA2048;
      break;
    case algorithm_arg_RSA1024:
      in_data[4] = YKPIV_ALGO_RSA1024;
      break;
    case algorithm_arg_ECCP256:
      in_data[4] = YKPIV_ALGO_ECCP256;
      break;
    case algorithm__NULL:
    default:
      fprintf(stderr, "Unexepcted algorithm.\n");
      goto generate_out;
  }
  if(ykpiv_transfer_data(state, templ, in_data, sizeof(in_data), data,
        &recv_len, &sw) != YKPIV_OK) {
    fprintf(stderr, "Failed to communicate.\n");
    goto generate_out;
  } else if(sw != 0x9000) {
    fprintf(stderr, "Failed to generate new key.\n");
    goto generate_out;
  }

  if(key_format == key_format_arg_PEM) {
    public_key = EVP_PKEY_new();
    if(algorithm == algorithm_arg_RSA1024 || algorithm == algorithm_arg_RSA2048) {
      unsigned char *data_ptr = data + 5;
      int len = 0;
      rsa = RSA_new();

      if(*data_ptr != 0x81) {
        fprintf(stderr, "Failed to parse public key structure.\n");
        goto generate_out;
      }
      data_ptr++;
      data_ptr += get_length(data_ptr, &len);
      bignum_n = BN_bin2bn(data_ptr, len, NULL);
      if(bignum_n == NULL) {
        fprintf(stderr, "Failed to parse public key modulus.\n");
        goto generate_out;
      }
      data_ptr += len;

      if(*data_ptr != 0x82) {
        fprintf(stderr, "Failed to parse public key structure (2).\n");
        goto generate_out;
      }
      data_ptr++;
      data_ptr += get_length(data_ptr, &len);
      bignum_e = BN_bin2bn(data_ptr, len, NULL);
      if(bignum_e == NULL) {
        fprintf(stderr, "Failed to parse public key exponent.\n");
        goto generate_out;
      }

      rsa->n = bignum_n;
      rsa->e = bignum_e;
      EVP_PKEY_set1_RSA(public_key, rsa);
    } else if(algorithm == algorithm_arg_ECCP256) {
      EC_GROUP *group;
      unsigned char *data_ptr = data + 3;

      eckey = EC_KEY_new();
      group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
      EC_GROUP_set_asn1_flag(group, NID_X9_62_prime256v1);
      EC_KEY_set_group(eckey, group);
      point = EC_POINT_new(group);
      if(*data_ptr++ != 0x86) {
        fprintf(stderr, "Failed to parse public key structure.\n");
        goto generate_out;
      }
      if(*data_ptr++ != 65) { /* the curve point should always be 65 bytes */
        fprintf(stderr, "Unexpected length.\n");
        goto generate_out;
      }
      if(!EC_POINT_oct2point(group, point, data_ptr, 65, NULL)) {
        fprintf(stderr, "Failed to load public point.\n");
        goto generate_out;
      }
      if(!EC_KEY_set_public_key(eckey, point)) {
        fprintf(stderr, "Failed to set the public key.\n");
        goto generate_out;
      }
      EVP_PKEY_set1_EC_KEY(public_key, eckey);
    } else {
      fprintf(stderr, "Wrong algorithm.\n");
      goto generate_out;
    }
    PEM_write_PUBKEY(output_file, public_key);
    ret = true;
  } else {
    fprintf(stderr, "Only PEM is supported as public_key output.\n");
    goto generate_out;
  }

generate_out:
  if(output_file != stdout) {
    fclose(output_file);
  }
  if(point) {
    EC_POINT_free(point);
  }
  if(eckey) {
    EC_KEY_free(eckey);
  }
  if(rsa) {
    RSA_free(rsa);
  }
  if(public_key) {
    EVP_PKEY_free(public_key);
  }

  return ret;
}

static bool reset(ykpiv_state *state) {
  unsigned char templ[] = {0, YKPIV_INS_RESET, 0, 0};
  unsigned char data[0xff];
  unsigned long recv_len = sizeof(data);
  int sw;

  /* note: the reset function is only available when both pins are blocked. */
  if(ykpiv_transfer_data(state, templ, NULL, 0, data, &recv_len, &sw) != YKPIV_OK) {
    return false;
  } else if(sw == 0x9000) {
    return true;
  }
  return false;
}

static bool set_pin_retries(ykpiv_state *state, int pin_retries, int puk_retries, int verbose) {
  unsigned char templ[] = {0, YKPIV_INS_SET_PIN_RETRIES, pin_retries, puk_retries};
  unsigned char data[0xff];
  unsigned long recv_len = sizeof(data);
  int sw;

  if(pin_retries > 0xff || puk_retries > 0xff || pin_retries < 1 || puk_retries < 1) {
    fprintf(stderr, "pin and puk retries must be between 1 and 255.\n");
    return false;
  }

  if(verbose) {
    fprintf(stderr, "Setting pin retries to %d and puk retries to %d.\n", pin_retries, puk_retries);
  }

  if(ykpiv_transfer_data(state, templ, NULL, 0, data, &recv_len, &sw) != YKPIV_OK) {
    return false;
  } else if(sw == 0x9000) {
    return true;
  }
  return false;
}

static bool import_key(ykpiv_state *state, enum enum_key_format key_format,
    const char *input_file_name, const char *slot, char *password) {
  int key = 0;
  FILE *input_file = NULL;
  EVP_PKEY *private_key = NULL;
  PKCS12 *p12 = NULL;
  X509 *cert = NULL;
  bool ret = false;

  sscanf(slot, "%2x", &key);

  input_file = open_file(input_file_name, INPUT);
  if(!input_file) {
    return false;
  }

  if(isatty(fileno(input_file))) {
    fprintf(stderr, "Please paste the private key...\n");
  }

  if(key_format == key_format_arg_PEM) {
    private_key = PEM_read_PrivateKey(input_file, NULL, NULL, password);
    if(!private_key) {
      fprintf(stderr, "Failed loading private key for import.\n");
      goto import_out;
    }
  } else if(key_format == key_format_arg_PKCS12) {
    p12 = d2i_PKCS12_fp(input_file, NULL);
    if(!p12) {
      fprintf(stderr, "Failed to load PKCS12 from file.\n");
      goto import_out;
    }
    if(PKCS12_parse(p12, password, &private_key, &cert, NULL) == 0) {
      fprintf(stderr, "Failed to parse PKCS12 structure. (wrong password?)\n");
      goto import_out;
    }
  } else {
    /* TODO: more formats go here */
    fprintf(stderr, "Unknown key format.\n");
    goto import_out;
  }

  {
    unsigned char algorithm = get_algorithm(private_key);
    if(algorithm == 0) {
      goto import_out;
    }
    {
      unsigned char data[0xff];
      unsigned long recv_len = sizeof(data);
      unsigned char in_data[1024];
      unsigned char *in_ptr = in_data;
      unsigned char templ[] = {0, YKPIV_INS_IMPORT_KEY, algorithm, key};
      int sw;
      if(algorithm == YKPIV_ALGO_RSA1024 || algorithm == YKPIV_ALGO_RSA2048) {
        RSA *rsa_private_key = EVP_PKEY_get1_RSA(private_key);
        unsigned char e[4];
        unsigned char *e_ptr = e;
        int element_len = 128;
        if(algorithm == YKPIV_ALGO_RSA1024) {
          element_len = 64;
        }

        if((set_component_with_len(&e_ptr, rsa_private_key->e, 3) == false) ||
            !(e[1] == 0x01 && e[2] == 0x00 && e[3] == 0x01)) {
          fprintf(stderr, "Invalid public exponent for import (only 0x10001 supported)\n");
          goto import_out;
        }

        *in_ptr++ = 0x01;
        if(set_component_with_len(&in_ptr, rsa_private_key->p, element_len) == false) {
          fprintf(stderr, "Failed setting p component.\n");
          goto import_out;
        }

        *in_ptr++ = 0x02;
        if(set_component_with_len(&in_ptr, rsa_private_key->q, element_len) == false) {
          fprintf(stderr, "Failed setting q component.\n");
          goto import_out;
        }

        *in_ptr++ = 0x03;
        if(set_component_with_len(&in_ptr, rsa_private_key->dmp1, element_len) == false) {
          fprintf(stderr, "Failed setting dmp1 component.\n");
          goto import_out;
        }

        *in_ptr++ = 0x04;
        if(set_component_with_len(&in_ptr, rsa_private_key->dmq1, element_len) == false) {
          fprintf(stderr, "Failed setting dmq1 component.\n");
          goto import_out;
        }

        *in_ptr++ = 0x05;
        if(set_component_with_len(&in_ptr, rsa_private_key->iqmp, element_len) == false) {
          fprintf(stderr, "Failed setting iqmp component.\n");
          goto import_out;
        }
      } else if(algorithm == YKPIV_ALGO_ECCP256) {
        EC_KEY *ec = EVP_PKEY_get1_EC_KEY(private_key);
        const BIGNUM *s = EC_KEY_get0_private_key(ec);

        *in_ptr++ = 0x06;
        if(set_component_with_len(&in_ptr, s, 32) == false) {
          fprintf(stderr, "Failed setting ec private key.\n");
          goto import_out;
        }
      }

      if(ykpiv_transfer_data(state, templ, in_data, in_ptr - in_data, data,
            &recv_len, &sw) != YKPIV_OK) {
        return false;
      } else if(sw != 0x9000) {
        fprintf(stderr, "Failed import command with code %x.\n", sw);
      } else {
        ret = true;
      }
    }
  }
import_out:
  if(private_key) {
    EVP_PKEY_free(private_key);
  }
  if(p12) {
    PKCS12_free(p12);
  }
  if(cert) {
    X509_free(cert);
  }
  if(input_file != stdin) {
    fclose(input_file);
  }
  return ret;
}

static bool import_cert(ykpiv_state *state, enum enum_key_format cert_format,
    const char *input_file_name, enum enum_slot slot, char *password) {
  bool ret = false;
  FILE *input_file = NULL;
  X509 *cert = NULL;
  PKCS12 *p12 = NULL;
  EVP_PKEY *private_key = NULL;
  int compress = 0;
  int cert_len = -1;

  input_file = open_file(input_file_name, INPUT);
  if(!input_file) {
    return false;
  }

  if(isatty(fileno(input_file))) {
    fprintf(stderr, "Please paste the certificate...\n");
  }

  if(cert_format == key_format_arg_PEM) {
    cert = PEM_read_X509(input_file, NULL, NULL, password);
    if(!cert) {
      fprintf(stderr, "Failed loading certificate for import.\n");
      goto import_cert_out;
    }
  } else if(cert_format == key_format_arg_DER) {
    cert = d2i_X509_fp(input_file, NULL);
    if(!cert) {
      fprintf(stderr, "Failed loading certificate for import.\n");
      goto import_cert_out;
    }
  } else if(cert_format == key_format_arg_PKCS12) {
    p12 = d2i_PKCS12_fp(input_file, NULL);
    if(!p12) {
      fprintf(stderr, "Failed to load PKCS12 from file.\n");
      goto import_cert_out;
    }
    if(!PKCS12_parse(p12, password, &private_key, &cert, NULL)) {
      fprintf(stderr, "Failed to parse PKCS12 structure.\n");
      goto import_cert_out;
    }
  } else if (cert_format == key_format_arg_GZIP) {
    struct stat st;

    if(fstat(fileno(input_file), &st) == -1) {
      fprintf(stderr, "Failed checking input GZIP file.\n");
      goto import_cert_out;
    }
    cert_len = st.st_size;
    compress = 0x01;
  } else {
    /* TODO: more formats go here */
    fprintf(stderr, "Unknown key format.\n");
    goto import_cert_out;
  }
  if(cert_len == -1) {
    cert_len = i2d_X509(cert, NULL);
  }

  {
    unsigned char certdata[2100];
    unsigned char *certptr = certdata;
    int object = get_object_id(slot);
    ykpiv_rc res;

    if(cert_len > 2048) {
      fprintf(stderr, "Certificate to large, maximum 2048 bytes (was %d bytes).\n", cert_len);
      goto import_cert_out;
    }
    *certptr++ = 0x70;
    certptr += set_length(certptr, cert_len);
    if (compress) {
      if (fread(certptr, 1, (size_t)cert_len, input_file) != (size_t)cert_len) {
        fprintf(stderr, "Failed to read compressed certificate\n");
        goto import_cert_out;
      }
      certptr += cert_len;
    } else {
      /* i2d_X509 increments certptr here.. */
      i2d_X509(cert, &certptr);
    }
    *certptr++ = 0x71;
    *certptr++ = 1;
    *certptr++ = compress; /* certinfo (gzip etc) */
    *certptr++ = 0xfe; /* LRC */
    *certptr++ = 0;

    if((res = ykpiv_save_object(state, object, certdata, (size_t)(certptr - certdata))) != YKPIV_OK) {
      fprintf(stderr, "Failed commands with device: %s\n", ykpiv_strerror(res));
    } else {
      ret = true;
    }
  }

import_cert_out:
  if(cert) {
    X509_free(cert);
  }
  if(input_file != stdin) {
    fclose(input_file);
  }
  if(p12) {
    PKCS12_free(p12);
  }
  if(private_key) {
    EVP_PKEY_free(private_key);
  }

  return ret;
}

static bool set_chuid(ykpiv_state *state, int verbose) {
  unsigned char chuid[sizeof(chuid_tmpl)];
  ykpiv_rc res;

  memcpy(chuid, chuid_tmpl, sizeof(chuid));
  if(RAND_pseudo_bytes(chuid + CHUID_GUID_OFFS, 0x10) == -1) {
    fprintf(stderr, "error: no randomness.\n");
    return false;
  }
  if(verbose) {
    fprintf(stderr, "Setting the CHUID to: ");
    dump_hex(chuid, sizeof(chuid), stderr, true);
  }
  if((res = ykpiv_save_object(state, YKPIV_OBJ_CHUID, chuid, sizeof(chuid))) != YKPIV_OK) {
    fprintf(stderr, "Failed communicating with device: %s\n", ykpiv_strerror(res));
    return false;
  }

  return true;
}

static bool request_certificate(ykpiv_state *state, enum enum_key_format key_format,
    const char *input_file_name, const char *slot, char *subject, enum enum_hash hash,
    const char *output_file_name) {
  X509_REQ *req = NULL;
  X509_NAME *name = NULL;
  FILE *input_file = NULL;
  FILE *output_file = NULL;
  EVP_PKEY *public_key = NULL;
  const EVP_MD *md;
  bool ret = false;
  unsigned char digest[EVP_MAX_MD_SIZE + sizeof(sha512oid)]; // maximum..
  unsigned int digest_len;
  unsigned int md_len;
  unsigned char algorithm;
  int key = 0;
  unsigned char *signinput;
  size_t len = 0;
  size_t oid_len;
  const unsigned char *oid;
  int nid;

  sscanf(slot, "%2x", &key);

  input_file = open_file(input_file_name, INPUT);
  output_file = open_file(output_file_name, OUTPUT);
  if(!input_file || !output_file) {
    goto request_out;
  }

  if(isatty(fileno(input_file))) {
    fprintf(stderr, "Please paste the public key...\n");
  }

  if(key_format == key_format_arg_PEM) {
    public_key = PEM_read_PUBKEY(input_file, NULL, NULL, NULL);
    if(!public_key) {
      fprintf(stderr, "Failed loading public key for request.\n");
      goto request_out;
    }
  } else {
    fprintf(stderr, "Only PEM supported for public key input.\n");
    goto request_out;
  }
  algorithm = get_algorithm(public_key);
  if(algorithm == 0) {
    goto request_out;
  }

  switch(hash) {
    case hash_arg_SHA1:
      md = EVP_sha1();
      oid = sha1oid;
      oid_len = sizeof(sha1oid);
      break;
    case hash_arg_SHA256:
      md = EVP_sha256();
      oid = sha256oid;
      oid_len = sizeof(sha256oid);
      break;
    case hash_arg_SHA512:
      md = EVP_sha512();
      oid = sha512oid;
      oid_len = sizeof(sha512oid);
      break;
    case hash__NULL:
    default:
      goto request_out;
  }

  md_len = (unsigned int)EVP_MD_size(md);
  digest_len = sizeof(digest) - md_len;

  req = X509_REQ_new();
  if(!req) {
    fprintf(stderr, "Failed to allocate request structure.\n");
    goto request_out;
  }
  if(!X509_REQ_set_pubkey(req, public_key)) {
    fprintf(stderr, "Failed setting the request public key.\n");
    goto request_out;
  }

  X509_REQ_set_version(req, 0);

  name = parse_name(subject);
  if(!name) {
    fprintf(stderr, "Failed encoding subject as name.\n");
    goto request_out;
  }
  if(!X509_REQ_set_subject_name(req, name)) {
    fprintf(stderr, "Failed setting the request subject.\n");
    goto request_out;
  }

  memcpy(digest, oid, oid_len);
  /* XXX: this should probably use X509_REQ_digest() but that's buggy */
  if(!ASN1_item_digest(ASN1_ITEM_rptr(X509_REQ_INFO), md, req->req_info,
			  digest + oid_len, &digest_len)) {
    fprintf(stderr, "Failed doing digest of request.\n");
    goto request_out;
  }

  switch(algorithm) {
    case YKPIV_ALGO_RSA1024:
    case YKPIV_ALGO_RSA2048:
      signinput = digest;
      len = oid_len + digest_len;
      switch(hash) {
        case hash_arg_SHA1:
          nid = NID_sha1WithRSAEncryption;
          break;
        case hash_arg_SHA256:
          nid = NID_sha256WithRSAEncryption;
          break;
        case hash_arg_SHA512:
          nid = NID_sha512WithRSAEncryption;
          break;
        case hash__NULL:
        default:
          goto request_out;
      }
      break;
    case YKPIV_ALGO_ECCP256:
      signinput = digest + oid_len;
      len = digest_len;
      switch(hash) {
        case hash_arg_SHA1:
          nid = NID_ecdsa_with_SHA1;
          break;
        case hash_arg_SHA256:
          nid = NID_ecdsa_with_SHA256;
          break;
        case hash_arg_SHA512:
          nid = NID_ecdsa_with_SHA512;
          break;
        case hash__NULL:
        default:
          goto request_out;
      }
      break;
    default:
      fprintf(stderr, "Unsupported algorithm %x.\n", algorithm);
      goto request_out;
  }
  req->sig_alg->algorithm = OBJ_nid2obj(nid);
  {
    unsigned char signature[1024];
    size_t sig_len = sizeof(signature);
    if(ykpiv_sign_data(state, signinput, len, signature, &sig_len, algorithm, key)
        != YKPIV_OK) {
      fprintf(stderr, "Failed signing request.\n");
      goto request_out;
    }
    M_ASN1_BIT_STRING_set(req->signature, signature, sig_len);
    /* mark that all bits should be used. */
    req->signature->flags = ASN1_STRING_FLAG_BITS_LEFT;
  }

  if(key_format == key_format_arg_PEM) {
    PEM_write_X509_REQ(output_file, req);
    ret = true;
  } else {
    fprintf(stderr, "Only PEM support available for certificate requests.\n");
  }

request_out:
  if(input_file && input_file != stdin) {
    fclose(input_file);
  }
  if(output_file && output_file != stdout) {
    fclose(output_file);
  }
  if(public_key) {
    EVP_PKEY_free(public_key);
  }
  if(req) {
    X509_REQ_free(req);
  }
  if(name) {
    X509_NAME_free(name);
  }
  return ret;
}

static bool selfsign_certificate(ykpiv_state *state, enum enum_key_format key_format,
    const char *input_file_name, const char *slot, char *subject, enum enum_hash hash,
    const char *output_file_name) {
  FILE *input_file = NULL;
  FILE *output_file = NULL;
  bool ret = false;
  EVP_PKEY *public_key = NULL;
  X509 *x509 = NULL;
  X509_NAME *name = NULL;
  const EVP_MD *md;
  unsigned char digest[EVP_MAX_MD_SIZE + sizeof(sha512oid)];
  unsigned int digest_len;
  unsigned char algorithm;
  int key = 0;
  unsigned char *signinput;
  size_t len = 0;
  size_t oid_len;
  const unsigned char *oid;
  int nid;
  unsigned int md_len;

  sscanf(slot, "%2x", &key);

  input_file = open_file(input_file_name, INPUT);
  output_file = open_file(output_file_name, OUTPUT);
  if(!input_file || !output_file) {
    goto selfsign_out;
  }

  if(isatty(fileno(input_file))) {
    fprintf(stderr, "Please paste the public key...\n");
  }

  if(key_format == key_format_arg_PEM) {
    public_key = PEM_read_PUBKEY(input_file, NULL, NULL, NULL);
    if(!public_key) {
      fprintf(stderr, "Failed loading public key for certificate.\n");
      goto selfsign_out;
    }
  } else {
    fprintf(stderr, "Only PEM supported for public key input.\n");
    goto selfsign_out;
  }
  algorithm = get_algorithm(public_key);
  if(algorithm == 0) {
    goto selfsign_out;
  }

  switch(hash) {
    case hash_arg_SHA1:
      md = EVP_sha1();
      oid = sha1oid;
      oid_len = sizeof(sha1oid);
      break;
    case hash_arg_SHA256:
      md = EVP_sha256();
      oid = sha256oid;
      oid_len = sizeof(sha256oid);
      break;
    case hash_arg_SHA512:
      md = EVP_sha512();
      oid = sha512oid;
      oid_len = sizeof(sha512oid);
      break;
    case hash__NULL:
    default:
      goto selfsign_out;
  }

  md_len = (unsigned int)EVP_MD_size(md);
  digest_len = sizeof(digest) - md_len;

  x509 = X509_new();
  if(!x509) {
    fprintf(stderr, "Failed to allocate certificate structure.\n");
    goto selfsign_out;
  }
  if(!X509_set_version(x509, 2)) {
    fprintf(stderr, "Failed to set certificate version.\n");
    goto selfsign_out;
  }
  if(!X509_set_pubkey(x509, public_key)) {
    fprintf(stderr, "Failed to set the certificate public key.\n");
    goto selfsign_out;
  }
  if(!ASN1_INTEGER_set(X509_get_serialNumber(x509), 1)) {
    fprintf(stderr, "Failed to set certificate serial.\n");
    goto selfsign_out;
  }
  if(!X509_gmtime_adj(X509_get_notBefore(x509), 0)) {
    fprintf(stderr, "Failed to set certificate notBefore.\n");
    goto selfsign_out;
  }
  if(!X509_gmtime_adj(X509_get_notAfter(x509), 31536000L)) {
    fprintf(stderr, "Failed to set certificate notAfter.\n");
    goto selfsign_out;
  }
  name = parse_name(subject);
  if(!name) {
    fprintf(stderr, "Failed encoding subject as name.\n");
    goto selfsign_out;
  }
  if(!X509_set_subject_name(x509, name)) {
    fprintf(stderr, "Failed setting certificate subject.\n");
    goto selfsign_out;
  }
  if(!X509_set_issuer_name(x509, name)) {
    fprintf(stderr, "Failed setting certificate issuer.\n");
    goto selfsign_out;
  }
  switch(algorithm) {
    case YKPIV_ALGO_RSA1024:
    case YKPIV_ALGO_RSA2048:
      signinput = digest;
      len = oid_len + md_len;
      switch(hash) {
        case hash_arg_SHA1:
          nid = NID_sha1WithRSAEncryption;
          break;
        case hash_arg_SHA256:
          nid = NID_sha256WithRSAEncryption;
          break;
        case hash_arg_SHA512:
          nid = NID_sha512WithRSAEncryption;
          break;
        case hash__NULL:
        default:
          goto selfsign_out;
      }
      break;
    case YKPIV_ALGO_ECCP256:
      signinput = digest + oid_len;
      len = md_len;
      switch(hash) {
        case hash_arg_SHA1:
          nid = NID_ecdsa_with_SHA1;
          break;
        case hash_arg_SHA256:
          nid = NID_ecdsa_with_SHA256;
          break;
        case hash_arg_SHA512:
          nid = NID_ecdsa_with_SHA512;
          break;
        case hash__NULL:
        default:
          goto selfsign_out;
      }
      break;
    default:
      fprintf(stderr, "Unsupported algorithm %x.\n", algorithm);
      goto selfsign_out;
  }
  x509->sig_alg->algorithm = OBJ_nid2obj(nid);
  x509->cert_info->signature->algorithm = x509->sig_alg->algorithm;
  memcpy(digest, oid, oid_len);
  /* XXX: this should probably use X509_digest() but that looks buggy */
  if(!ASN1_item_digest(ASN1_ITEM_rptr(X509_CINF), md, x509->cert_info,
			  digest + oid_len, &digest_len)) {
    fprintf(stderr, "Failed doing digest of certificate.\n");
    goto selfsign_out;
  }
  {
    unsigned char signature[1024];
    size_t sig_len = sizeof(signature);
    if(ykpiv_sign_data(state, signinput, len, signature, &sig_len, algorithm, key)
        != YKPIV_OK) {
      fprintf(stderr, "Failed signing certificate.\n");
      goto selfsign_out;
    }
    M_ASN1_BIT_STRING_set(x509->signature, signature, sig_len);
    /* setting flags to ASN1_STRING_FLAG_BITS_LEFT here marks that no bits
     * should be subtracted from the bit string, thus making sure that the
     * certificate can be validated. */
    x509->signature->flags = ASN1_STRING_FLAG_BITS_LEFT;
  }

  if(key_format == key_format_arg_PEM) {
    PEM_write_X509(output_file, x509);
    ret = true;
  } else {
    fprintf(stderr, "Only PEM support available for certificate requests.\n");
  }

selfsign_out:
  if(input_file && input_file != stdin) {
    fclose(input_file);
  }
  if(output_file && output_file != stdout) {
    fclose(output_file);
  }
  if(x509) {
    X509_free(x509);
  }
  if(public_key) {
    EVP_PKEY_free(public_key);
  }
  if(name) {
    X509_NAME_free(name);
  }
  return ret;
}

static bool verify_pin(ykpiv_state *state, const char *pin) {
  int tries = -1;
  ykpiv_rc res;
  int len;
  char pinbuf[9] = {0};
  if(!pin) {
    if (!read_pw("PIN", pinbuf, sizeof(pinbuf), false)) {
      return false;
    }
    pin = pinbuf;
  }
  len = strlen(pin);

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
      fprintf(stderr, "Pin code blocked, use unblock-pin action to unblock.\n");
    }
  } else {
    fprintf(stderr, "Pin code verification failed: '%s'\n", ykpiv_strerror(res));
  }
  return false;
}

/* this function is called for all three of change-pin, change-puk and unblock pin
 * since they're very similar in what data they use. */
static bool change_pin(ykpiv_state *state,
                       enum enum_action action,
                       const char *pin,
                       const char *new_pin) {
  unsigned char templ[] = {0, YKPIV_INS_CHANGE_REFERENCE, 0, 0x80};
  unsigned char indata[0x10];
  unsigned char data[0xff];
  unsigned long recv_len = sizeof(data);
  char pinbuf[9] = {0};
  char new_pinbuf[9] = {0};
  const char *name = action == action_arg_changeMINUS_pin ? "pin" : "puk";
  const char *new_name = action == action_arg_changeMINUS_pin ? "new pin" : "new puk";
  int sw;
  size_t pin_len;
  size_t new_len;

  if(!pin) {
    if (!read_pw(name, pinbuf, sizeof(pinbuf), false)) {
      return false;
    }
    pin = pinbuf;
  }
  if(!new_pin) {
    if (!read_pw(new_name, new_pinbuf, sizeof(new_pinbuf), true)) {
      return false;
    }
    new_pin = new_pinbuf;
  }
  pin_len = strlen(pin);
  new_len = strlen(new_pin);

  if(pin_len > 8 || new_len > 8) {
    fprintf(stderr, "Maximum 8 digits of PIN supported.\n");
    return false;
  }

  if(action == action_arg_unblockMINUS_pin) {
    templ[1] = YKPIV_INS_RESET_RETRY;
  }
  else if(action == action_arg_changeMINUS_puk) {
    templ[3] = 0x81;
  }
  memcpy(indata, pin, pin_len);
  if(pin_len < 8) {
    memset(indata + pin_len, 0xff, 8 - pin_len);
  }
  memcpy(indata + 8, new_pin, new_len);
  if(new_len < 8) {
    memset(indata + 8 + new_len, 0xff, 16 - new_len);
  }
  if(ykpiv_transfer_data(state, templ, indata, sizeof(indata), data, &recv_len, &sw) != YKPIV_OK) {
    return false;
  } else if(sw != 0x9000) {
    if((sw >> 8) == 0x63) {
      int tries = sw & 0xf;
      fprintf(stderr, "Failed verifying %s code, now %d tries left before blocked.\n",
          name, tries);
    } else if(sw == 0x6983) {
      if(action == action_arg_changeMINUS_pin) {
        fprintf(stderr, "The pin code is blocked, use the unblock-pin action to unblock it.\n");
      } else {
        fprintf(stderr, "The puk code is blocked, you will have to reinitialize the applet.\n");
      }
    } else {
      fprintf(stderr, "Failed changing/unblocking code, error: %x\n", sw);
    }
    return false;
  }
  return true;
}

static bool set_puk_blocked(ykpiv_state* state) {
  unsigned char def_key[] = {
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08
  };

  ykpiv_authenticate(state, def_key);

  // Block the PUK
  int i;
  for (i = 0 ; i < 3 ; i++) {
    change_pin(state, action_arg_changeMINUS_puk, "00000000", "00000000");
  }

  unsigned char puk_blocked[] = {
    0x80, 0x03, 0x81, 0x01, 0x01
  };

  if (ykpiv_save_object(state, YKPIV_OBJ_PIVMAN_DATA, puk_blocked, 5) != YKPIV_OK) {
    fprintf(stderr, "Failed to set puk blocked in PIVMAN_DATA.");
    return false;
  }
  return true;
}

static bool delete_certificate(ykpiv_state *state, enum enum_slot slot) {
  int object = get_object_id(slot);

  if(ykpiv_save_object(state, object, NULL, 0) != YKPIV_OK) {
    fprintf(stderr, "Failed deleting object.\n");
    return false;
  } else {
    fprintf(stderr, "Certificate deleted.\n");
    return true;
  }
}

static bool read_certificate(ykpiv_state *state, enum enum_slot slot,
    enum enum_key_format key_format, const char *output_file_name) {
  FILE *output_file;
  int object = get_object_id(slot);
  unsigned char data[2048];
  const unsigned char *ptr = data;
  unsigned long len = sizeof(data);
  int cert_len;
  bool ret = false;
  X509 *x509 = NULL;

  if(key_format != key_format_arg_PEM && key_format != key_format_arg_DER) {
    fprintf(stderr, "Only PEM and DER format are supported for read-certificate.\n");
    return false;
  }

  output_file = open_file(output_file_name, OUTPUT);
  if(!output_file) {
    return false;
  }

  if(ykpiv_fetch_object(state, object, data, &len) != YKPIV_OK) {
    fprintf(stderr, "Failed fetching certificate.\n");
    goto read_cert_out;
  }

  if(*ptr++ == 0x70) {
    ptr += get_length(ptr, &cert_len);
    if(key_format == key_format_arg_PEM) {
      x509 = X509_new();
      if(!x509) {
        fprintf(stderr, "Failed allocating x509 structure.\n");
        goto read_cert_out;
      }
      x509 = d2i_X509(NULL, &ptr, cert_len);
      if(!x509) {
        fprintf(stderr, "Failed parsing x509 information.\n");
        goto read_cert_out;
      }
      PEM_write_X509(output_file, x509);
      ret = true;
    } else { /* key_format_arg_DER */
      /* XXX: This will just dump the raw data in tag 0x70.. */
      fwrite(ptr, (size_t)cert_len, 1, output_file);
      ret = true;
    }
  } else {
    fprintf(stderr, "Failed parsing data.\n");
  }

read_cert_out:
  if(output_file != stdout) {
    fclose(output_file);
  }
  if(x509) {
    X509_free(x509);
  }
  return ret;
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
  const EVP_MD *md;

  sscanf(slot, "%2x", &key);

  input_file = open_file(input, INPUT);
  if(!input_file) {
    return false;
  }

  if(isatty(fileno(input_file))) {
    fprintf(stderr, "Please paste the input...\n");
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
    EVP_MD_CTX *mdctx;

    switch(hash) {
      case hash_arg_SHA1:
        md = EVP_sha1();
        break;
      case hash_arg_SHA256:
        md = EVP_sha256();
        break;
      case hash_arg_SHA512:
        md = EVP_sha512();
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
      dump_hex(hashed, hash_len, stderr, true);
    }
    EVP_MD_CTX_destroy(mdctx);
  }

  if(algo == YKPIV_ALGO_RSA1024 || algo == YKPIV_ALGO_RSA2048) {
    prepare_rsa_signature(hashed, hash_len, hashed, &hash_len, EVP_MD_type(md));
  }

  {
    unsigned char buf[1024];
    size_t len = sizeof(buf);
    ykpiv_rc rc = ykpiv_sign_data(state, hashed, hash_len, buf, &len, algo, key);
    if(rc != YKPIV_OK) {
      fprintf(stderr, "failed signing file: %s\n", ykpiv_strerror(rc));
      goto out;
    }

    if(verbosity) {
      fprintf(stderr, "file signed as: ");
      dump_hex(buf, len, stderr, true);
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

static void print_cert_info(ykpiv_state *state, enum enum_slot slot, const EVP_MD *md,
    FILE *output) {
  int object = get_object_id(slot);
  unsigned char data[2048];
  const unsigned char *ptr = data;
  unsigned long len = sizeof(data);
  int cert_len;
  X509 *x509 = NULL;
  X509_NAME *subj;
  BIO *bio = NULL;

  if(ykpiv_fetch_object(state, object, data, &len) != YKPIV_OK) {
    fprintf(output, "No data available.\n");
    return;
  }

  if(*ptr++ == 0x70) {
    unsigned int md_len = sizeof(data);
    ASN1_TIME *not_before, *not_after;

    ptr += get_length(ptr, &cert_len);
    x509 = X509_new();
    if(!x509) {
      fprintf(output, "Allocation failure.\n");
      return;
    }
    x509 = d2i_X509(NULL, &ptr, cert_len);
    if(!x509) {
      fprintf(output, "Unknown data present.\n");
      goto cert_out;
    }
    {
      EVP_PKEY *key = X509_get_pubkey(x509);
      if(!key) {
        fprintf(output, "Parse error.\n");
        goto cert_out;
      }
      fprintf(output, "\n\tAlgorithm:\t");
      switch(get_algorithm(key)) {
        case YKPIV_ALGO_RSA1024:
          fprintf(output, "RSA1024\n");
          break;
        case YKPIV_ALGO_RSA2048:
          fprintf(output, "RSA2048\n");
          break;
        case YKPIV_ALGO_ECCP256:
          fprintf(output, "ECCP256\n");
          break;
        default:
          fprintf(output, "Unknown\n");
      }
    }
    subj = X509_get_subject_name(x509);
    if(!subj) {
      fprintf(output, "Parse error.\n");
      goto cert_out;
    }
    fprintf(output, "\tSubject DN:\t");
    X509_NAME_print_ex_fp(output, subj, 0, XN_FLAG_COMPAT);
    fprintf(output, "\n");
    subj = X509_get_issuer_name(x509);
    if(!subj) {
      fprintf(output, "Parse error.\n");
      goto cert_out;
    }
    fprintf(output, "\tIssuer DN:\t");
    X509_NAME_print_ex_fp(output, subj, 0, XN_FLAG_COMPAT);
    fprintf(output, "\n");
    X509_digest(x509, md, data, &md_len);
    fprintf(output, "\tFingerprint:\t");
    dump_hex(data, md_len, output, false);

    bio = BIO_new_fp(output, BIO_NOCLOSE | BIO_FP_TEXT);
    not_before = X509_get_notBefore(x509);
    if(not_before) {
      fprintf(output, "\tNot Before:\t");
      ASN1_TIME_print(bio, not_before);
      fprintf(output, "\n");
    }
    not_after = X509_get_notAfter(x509);
    if(not_after) {
      fprintf(output, "\tNot After:\t");
      ASN1_TIME_print(bio, not_after);
      fprintf(output, "\n");
    }
  } else {
    fprintf(output, "Parse error.\n");
    return;
  }
cert_out:
  if(x509) {
    X509_free(x509);
  }
  if(bio) {
    BIO_free(bio);
  }
}

static bool status(ykpiv_state *state, enum enum_hash hash,
  const char *output_file_name) {
  const EVP_MD *md;
  unsigned char chuid[2048];
  long unsigned len = sizeof(chuid);
  FILE *output_file = open_file(output_file_name, OUTPUT);
  if(!output_file) {
    return false;
  }

  switch(hash) {
    case hash_arg_SHA1:
      md = EVP_sha1();
      break;
    case hash_arg_SHA256:
      md = EVP_sha256();
      break;
    case hash_arg_SHA512:
      md = EVP_sha512();
      break;
    case hash__NULL:
    default:
      return false;
  }

  fprintf(output_file, "CHUID:\t");
  if(ykpiv_fetch_object(state, YKPIV_OBJ_CHUID, chuid, &len) != YKPIV_OK) {
    fprintf(output_file, "No data available\n");
  } else {
    dump_hex(chuid, len, output_file, false);
  }

  fprintf(output_file, "Slot 9a:\t");
  print_cert_info(state, slot_arg_9a, md, output_file);
  fprintf(output_file, "Slot 9c:\t");
  print_cert_info(state, slot_arg_9c, md, output_file);
  fprintf(output_file, "Slot 9d:\t");
  print_cert_info(state, slot_arg_9d, md, output_file);
  fprintf(output_file, "Slot 9e:\t");
  print_cert_info(state, slot_arg_9e, md, output_file);

  {
    int tries;
    ykpiv_verify(state, NULL, &tries);
    fprintf(output_file, "PIN tries left:\t%d\n", tries);
  }

  if(output_file != stdout) {
    fclose(output_file);
  }
  return true;
}

static bool test_signature(ykpiv_state *state, enum enum_slot slot,
    enum enum_hash hash, const char *input_file_name,
    enum enum_key_format cert_format, int verbose) {
  const EVP_MD *md;
  bool ret = false;
  unsigned char data[1024];
  unsigned int data_len;
  X509 *x509 = NULL;
  EVP_PKEY *pubkey;
  FILE *input_file = open_file(input_file_name, INPUT);

  if(!input_file) {
    fprintf(stderr, "Failed opening input file %s.\n", input_file_name);
    return false;
  }

  if(isatty(fileno(input_file))) {
    fprintf(stderr, "Please paste the certificate to verify against...\n");
  }

  if(cert_format == key_format_arg_PEM) {
    x509 = PEM_read_X509(input_file, NULL, NULL, NULL);
  } else if(cert_format == key_format_arg_DER) {
    x509 = d2i_X509_fp(input_file, NULL);
  } else {
    fprintf(stderr, "Only PEM or DER format is supported for test-signature.\n");
    goto test_out;
  }
  if(!x509) {
    fprintf(stderr, "Failed loading certificate for test-signature.\n");
    goto test_out;
  }

  switch(hash) {
    case hash_arg_SHA1:
      md = EVP_sha1();
      break;
    case hash_arg_SHA256:
      md = EVP_sha256();
      break;
    case hash_arg_SHA512:
      md = EVP_sha512();
      break;
    case hash__NULL:
    default:
      return false;
  }

  {
    unsigned char rand[128];
    EVP_MD_CTX *mdctx;
    if(RAND_pseudo_bytes(rand, 128) == -1) {
      fprintf(stderr, "error: no randomness.\n");
      return false;
    }

    mdctx = EVP_MD_CTX_create();
    EVP_DigestInit_ex(mdctx, md, NULL);
    EVP_DigestUpdate(mdctx, rand, 128);
    EVP_DigestFinal_ex(mdctx, data, &data_len);
    if(verbose) {
      fprintf(stderr, "Test data hashes as: ");
      dump_hex(data, data_len, stderr, true);
    }
  }

  {
    unsigned char signature[1024];
    unsigned char encoded[1024];
    unsigned char *ptr = data;
    unsigned int enc_len;
    size_t sig_len = sizeof(signature);
    int key = 0;
    unsigned char algorithm;

    pubkey = X509_get_pubkey(x509);
    if(!pubkey) {
      fprintf(stderr, "Parse error.\n");
      goto test_out;
    }
    algorithm = get_algorithm(pubkey);
    if(algorithm == 0) {
      goto test_out;
    }
    sscanf(cmdline_parser_slot_values[slot], "%2x", &key);
    if(algorithm == YKPIV_ALGO_RSA1024 || algorithm == YKPIV_ALGO_RSA2048) {
      prepare_rsa_signature(data, data_len, encoded, &enc_len, EVP_MD_type(md));
      ptr = encoded;
    } else {
      enc_len = data_len;
    }
    if(ykpiv_sign_data(state, ptr, enc_len, signature, &sig_len, algorithm, key)
      != YKPIV_OK) {
      fprintf(stderr, "Failed signing test data.\n");
      goto test_out;
    }

    switch(algorithm) {
      case YKPIV_ALGO_RSA1024:
      case YKPIV_ALGO_RSA2048:
        {
          RSA *rsa = EVP_PKEY_get1_RSA(pubkey);
          if(!rsa) {
            fprintf(stderr, "Failed getting RSA pubkey.\n");
            goto test_out;
          }

          if(RSA_verify(EVP_MD_type(md), data, data_len, signature, sig_len, rsa) == 1) {
            fprintf(stderr, "Successful RSA verification.\n");
            ret = true;
            goto test_out;
          } else {
            fprintf(stderr, "Failed RSA verification.\n");
            goto test_out;
          }
        }

        break;
      case YKPIV_ALGO_ECCP256:
        {
          EC_KEY *ec = EVP_PKEY_get1_EC_KEY(pubkey);
          if(ECDSA_verify(0, data, (int)data_len, signature, (int)sig_len, ec) == 1) {
            fprintf(stderr, "Successful ECDSA verification.\n");
            ret = true;
            goto test_out;
          } else {
            fprintf(stderr, "Failed ECDSA verification.\n");
            goto test_out;
          }
        }
        break;
      default:
        fprintf(stderr, "Unknown algorithm.\n");
        goto test_out;
    }
  }
test_out:
  if(x509) {
    X509_free(x509);
  }
  if(input_file != stdin) {
    fclose(input_file);
  }
  return ret;
}

static bool test_decipher(ykpiv_state *state, enum enum_slot slot,
    const char *input_file_name, enum enum_key_format cert_format, int verbose) {
  bool ret = false;
  X509 *x509 = NULL;
  EVP_PKEY *pubkey;
  EC_KEY *tmpkey = NULL;
  FILE *input_file = open_file(input_file_name, INPUT);

  if(!input_file) {
    fprintf(stderr, "Failed opening input file %s.\n", input_file_name);
    return false;
  }

  if(isatty(fileno(input_file))) {
    fprintf(stderr, "Please paste the certificate to encrypt for...\n");
  }

  if(cert_format == key_format_arg_PEM) {
    x509 = PEM_read_X509(input_file, NULL, NULL, NULL);
  } else if(cert_format == key_format_arg_DER) {
    x509 = d2i_X509_fp(input_file, NULL);
  } else {
    fprintf(stderr, "Only PEM or DER format is supported for test-decipher.\n");
    goto decipher_out;
  }
  if(!x509) {
    fprintf(stderr, "Failed loading certificate for test-decipher.\n");
    goto decipher_out;
  }

  {
    int key = 0;
    unsigned char algorithm;

    pubkey = X509_get_pubkey(x509);
    if(!pubkey) {
      fprintf(stderr, "Parse error.\n");
      goto decipher_out;
    }
    algorithm = get_algorithm(pubkey);
    if(algorithm == 0) {
      goto decipher_out;
    }
    sscanf(cmdline_parser_slot_values[slot], "%2x", &key);
    if(algorithm == YKPIV_ALGO_RSA1024 || algorithm == YKPIV_ALGO_RSA2048) {
      unsigned char secret[32];
      unsigned char secret2[32];
      unsigned char data[256];
      int len;
      size_t len2 = sizeof(data);
      RSA *rsa = EVP_PKEY_get1_RSA(pubkey);

      if(RAND_pseudo_bytes(secret, sizeof(secret)) == -1) {
        fprintf(stderr, "error: no randomness.\n");
        ret = false;
        goto decipher_out;
      }

      len = RSA_public_encrypt(sizeof(secret), secret, data, rsa, RSA_PKCS1_PADDING);
      if(len < 0) {
        fprintf(stderr, "Failed performing RSA encryption!\n");
        goto decipher_out;
      }
      if(ykpiv_decipher_data(state, data, (size_t)len, data, &len2, algorithm, key) != YKPIV_OK) {
        fprintf(stderr, "RSA decrypt failed!\n");
        goto decipher_out;
      }
      /* for some reason we have to give the padding check function data + 1 */
      len = RSA_padding_check_PKCS1_type_2(secret2, sizeof(secret2), data + 1, len2 - 1, RSA_size(rsa));
      if(len == sizeof(secret)) {
        if(verbose) {
          fprintf(stderr, "Generated nonce: ");
          dump_hex(secret, sizeof(secret), stderr, true);
          fprintf(stderr, "Decrypted nonce: ");
          dump_hex(secret2, sizeof(secret2), stderr, true);
        }
        if(memcmp(secret, secret2, sizeof(secret)) == 0) {
          fprintf(stderr, "Successfully performed RSA decryption!\n");
          ret = true;
        } else {
          fprintf(stderr, "Failed performing RSA decryption!\n");
        }
      } else {
        fprintf(stderr, "Failed unwrapping PKCS1 envelope.\n");
      }
    } else {
      unsigned char secret[32];
      unsigned char secret2[32];
      unsigned char public_key[65];
      unsigned char *ptr = public_key;
      size_t len = sizeof(secret);
      EC_KEY *ec = EVP_PKEY_get1_EC_KEY(pubkey);

      tmpkey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
      EC_KEY_generate_key(tmpkey);
      ECDH_compute_key(secret, len, EC_KEY_get0_public_key(ec), tmpkey, NULL);

      i2o_ECPublicKey(tmpkey, &ptr);
      if(ykpiv_decipher_data(state, public_key, sizeof(public_key), secret2, &len, algorithm, key) != YKPIV_OK) {
        fprintf(stderr, "Failed ECDH exchange!\n");
        goto decipher_out;
      }
      if(verbose) {
        fprintf(stderr, "ECDH host generated: ");
        dump_hex(secret, len, stderr, true);
        fprintf(stderr, "ECDH card generated: ");
        dump_hex(secret2, len, stderr, true);
      }
      if(memcmp(secret, secret2, 32) == 0) {
        fprintf(stderr, "Successfully performed ECDH exchange with card.\n");
        ret = true;
      } else {
        fprintf(stderr, "ECDH exchange with card failed!\n");
      }
    }
  }

decipher_out:
  if(tmpkey) {
    EC_KEY_free(tmpkey);
  }
  if(x509) {
    X509_free(x509);
  }
  if(input_file != stdin) {
    fclose(input_file);
  }
  return ret;
}

int main(int argc, char *argv[]) {
  bool salt_present = false;
  struct gengetopt_args_info args_info;
  ykpiv_state *state;
  int verbosity;
  enum enum_action action;
  unsigned int i;
  int ret = EXIT_SUCCESS;

  if(cmdline_parser(argc, argv, &args_info) != 0) {
    return EXIT_FAILURE;
  }

  verbosity = args_info.verbose_arg + (int)args_info.verbose_given;

  for(i = 0; i < args_info.action_given; i++) {
    action = *(args_info.action_arg + i);
    switch(action) {
      case action_arg_requestMINUS_certificate:
      case action_arg_selfsignMINUS_certificate:
        if(!args_info.subject_arg) {
          fprintf(stderr,
                  "The '%s' action needs a subject (-S) to operate on.\n",
                  cmdline_parser_action_values[action]);
          return EXIT_FAILURE;
        }
      case action_arg_generate:
      case action_arg_importMINUS_key:
      case action_arg_importMINUS_certificate:
      case action_arg_deleteMINUS_certificate:
      case action_arg_readMINUS_certificate:
      case action_arg_testMINUS_signature:
      case action_arg_testMINUS_decipher:
        if(args_info.slot_arg == slot__NULL) {
          fprintf(stderr,
                  "The '%s' action needs a slot (-s) to operate on.\n",
                  cmdline_parser_action_values[action]);
          return EXIT_FAILURE;
        }
        break;
      case action_arg_pinMINUS_retries:
        if(!args_info.pin_retries_arg || !args_info.puk_retries_arg) {
          fprintf(stderr,
                  "The '%s' action needs both --pin-retries and --puk-retries arguments.\n",
                  cmdline_parser_action_values[action]);
          return EXIT_FAILURE;
        }
        break;
      case action_arg_changeMINUS_pin:
      case action_arg_changeMINUS_puk:
      case action_arg_unblockMINUS_pin:
      case action_arg_verifyMINUS_pin:
      case action_arg_setMINUS_mgmMINUS_key:
      case action_arg_setMINUS_mgmMINUS_keyMINUS_withMINUS_pin:
      case action_arg_setMINUS_chuid:
      case action_arg_version:
      case action_arg_reset:
      case action_arg_status:
      case action__NULL:
      default:
        continue;
    }
  }

  if(ykpiv_init(&state, verbosity) != YKPIV_OK) {
    fprintf(stderr, "Failed initializing library.\n");
    return EXIT_FAILURE;
  }

  if(ykpiv_connect(state, args_info.reader_arg) != YKPIV_OK) {
    fprintf(stderr, "Failed to connect to reader.\n");
    return EXIT_FAILURE;
  }

  // Check if salt data is present
  unsigned char current_salt[0x20];
  size_t current_salt_len = 0x20;
  salt_present = has_salt(state, current_salt, &current_salt_len, verbosity);

  for(i = 0; i < args_info.action_given; i++) {
    bool needs_auth = false;
    action = *(args_info.action_arg + i);
    switch(action) {
      case action_arg_generate:
      case action_arg_setMINUS_mgmMINUS_key:
      case action_arg_setMINUS_mgmMINUS_keyMINUS_withMINUS_pin:
      case action_arg_pinMINUS_retries:
      case action_arg_importMINUS_key:
      case action_arg_importMINUS_certificate:
      case action_arg_setMINUS_chuid:
      case action_arg_deleteMINUS_certificate:
        if(verbosity) {
          fprintf(stderr,
                  "Authenticating since action '%s' needs that.\n",
                  cmdline_parser_action_values[action]);
        }
        needs_auth = true;
        break;
      case action_arg_changeMINUS_pin:
      case action_arg_unblockMINUS_pin:
        if (salt_present) {
          needs_auth = true;
          if(verbosity) {
            fprintf(stderr,
                    "Authenticating since action '%s' needs that.\n",
                    cmdline_parser_action_values[action]);
          }
        }
        break;
      case action_arg_version:
      case action_arg_reset:
      case action_arg_requestMINUS_certificate:
      case action_arg_verifyMINUS_pin:
      case action_arg_changeMINUS_puk:
      case action_arg_selfsignMINUS_certificate:
      case action_arg_readMINUS_certificate:
      case action_arg_status:
      case action_arg_testMINUS_signature:
      case action_arg_testMINUS_decipher:
      case action__NULL:
      default:
        if(verbosity) {
          fprintf(stderr, "Action '%s' does not need authentication.\n", cmdline_parser_action_values[action]);
        }
        continue;
    }

    if(needs_auth) {
      unsigned char key[KEY_LEN + 1] = {0};
      unsigned char pin[8] = {0};
      size_t key_len = sizeof(key);

      if (salt_present) {
        if (!args_info.pin_arg) {
          if (!read_pw("PIN", pin, sizeof(pin), false)) {
            fprintf(stderr, "Failed to read pin from stdin.\n");
            return EXIT_FAILURE;
          }
        } else {
          memcpy(pin, args_info.pin_arg, strlen(args_info.pin_arg));
        }

        dump_hex(pin, strlen(pin), stderr, false);

        if (!derive_key(pin, current_salt, current_salt_len, key, &key_len, verbosity)) {
          fprintf(stderr, "Failed to derive key from pin\n");
          return EXIT_FAILURE;
        }
      } else {
        if(ykpiv_hex_decode(args_info.key_arg, strlen(args_info.key_arg), key, &key_len) != YKPIV_OK) {
          fprintf(stderr, "Failed decoding key!\n");
          return EXIT_FAILURE;
        }
      }

      dump_hex(key, key_len, stderr, false);
      if(ykpiv_authenticate(state, key) != YKPIV_OK) {
        fprintf(stderr, "Failed authentication with the applet.\n");
        return EXIT_FAILURE;
      }

      if(verbosity) {
        fprintf(stderr, "Successful applet authentication.\n");
      }

      break;
    }
  }

  /* openssl setup.. */
  OpenSSL_add_all_algorithms();

  for(i = 0; i < args_info.action_given; i++) {
    char new_keybuf[KEY_LEN*2+1] = {0};
    char pin_buf[8] = {0};
    size_t new_keybuf_len = sizeof(new_keybuf) / sizeof(new_keybuf[0]);
    char *new_mgm_key = args_info.new_key_arg;
    action = *(args_info.action_arg + i);
    if(verbosity) {
      fprintf(stderr, "Now processing for action '%s'.\n",
          cmdline_parser_action_values[action]);
    }
    switch(action) {
      case action_arg_version:
        print_version(state, args_info.output_arg);
        break;
      case action_arg_generate:
        if(generate_key(state, args_info.slot_orig, args_info.algorithm_arg, args_info.output_arg, args_info.key_format_arg) == false) {
          ret = EXIT_FAILURE;
        } else {
          fprintf(stderr, "Successfully generated a new private key.\n");
        }
        break;
      case action_arg_setMINUS_mgmMINUS_key:
        if(!new_mgm_key) {
          if(!read_pw("Enter new management key", new_keybuf, sizeof(new_keybuf), true)) {
            fprintf(stderr, "Failed to read management key from stdin.\n");
            ret = EXIT_FAILURE;
            break;
          }
          new_mgm_key = new_keybuf;
        }
        if(strlen(new_mgm_key) == (KEY_LEN * 2)){
          unsigned char new_key[KEY_LEN];
          size_t new_key_len = sizeof(new_key);
          if(ykpiv_hex_decode(new_mgm_key, strlen(new_mgm_key), new_key, &new_key_len) != YKPIV_OK) {
            fprintf(stderr, "Failed decoding new key!\n");
            ret = EXIT_FAILURE;
          } else if(ykpiv_set_mgmkey(state, new_key) != YKPIV_OK) {
            fprintf(stderr, "Failed setting the new key!\n");
            ret = EXIT_FAILURE;
          } else {
            fprintf(stderr, "Successfully set new management key.\n");
            // Remove the salt
            if (salt_present) {
              if (update_salt(state, NULL, 0, verbosity) == false) {
                fprintf(stderr, "Failed to remove salt. You will have to reset the device.\n");
                ret = EXIT_FAILURE;
                break;
              }
            }
          }
        } else {
          fprintf(stderr, "The new management key has to be exactly %d character.\n", KEY_LEN * 2);
          ret = EXIT_FAILURE;
        }
        break;
      case action_arg_setMINUS_mgmMINUS_keyMINUS_withMINUS_pin:
        if (salt_present) {
          if (!args_info.new_pin_arg) {
            if (!read_pw("New PIN", pin_buf, sizeof(pin_buf),true)) {
              fprintf(stderr, "Failed to read new PIN from stdin.\n");
              ret = EXIT_FAILURE;
              break;
            }
          } else {
            if (strlen(args_info.new_pin_arg) > 8) {
              fprintf(stderr, "Maximum 8 digits of PIN supported.\n");
              ret = EXIT_FAILURE;
              break;
            }
            memcpy(pin_buf, args_info.new_pin_arg, strlen(args_info.new_pin_arg));
          }

        } else {
          if (!args_info.pin_arg) {
            if (!read_pw("PIN", pin_buf, sizeof(pin_buf),true)) {
              fprintf(stderr, "Failed to read new PIN from stdin.\n");
              ret = EXIT_FAILURE;
              break;
            }
          } else {
            if (strlen(args_info.pin_arg) > 8) {
              fprintf(stderr, "Maximum 8 digits of PIN supported.\n");
              ret = EXIT_FAILURE;
              break;
            }
            memcpy(pin_buf, args_info.pin_arg, strlen(args_info.pin_arg));
          }
          // Block puk and set flag in PIVMAN_DATA
          set_puk_blocked(state);
        }

        unsigned char salt[SALT_LEN] = {0};
        if (generate_salt(salt, SALT_LEN, verbosity) == false){
          fprintf(stderr, "Failed to generate salt.\n");
          ret = EXIT_FAILURE;
          break;
        }

        if (derive_key(pin_buf, salt, SALT_LEN, new_keybuf, &new_keybuf_len, verbosity) == false){
          fprintf(stderr, "Failed to derive key.\n");
          ret = EXIT_FAILURE;
          break;
        }

        if (ykpiv_set_mgmkey(state, new_keybuf) != YKPIV_OK) {
          fprintf(stderr, "Failed setting the new key.\n");
          ret = EXIT_FAILURE;
          break;
        }

        if (change_pin(state, action_arg_changeMINUS_pin, args_info.pin_arg, pin_buf) == false) {
          fprintf(stderr, "Failed to change pin.\n");
          ret = EXIT_FAILURE;
          break;
        }

        if (update_salt(state, salt, SALT_LEN, verbosity) == false){
          fprintf(stderr, "Failed to update salt.\n");
          ret = EXIT_FAILURE;
          break;
        }

        break;
      case action_arg_reset:
        if(reset(state) == false) {
          fprintf(stderr, "Reset failed, are pincodes blocked? If not, they have to be.\n");
          ret = EXIT_FAILURE;
        } else {
          fprintf(stderr, "Successfully reset the applet.\n");
        }
        break;
      case action_arg_pinMINUS_retries:
        if(set_pin_retries(state, args_info.pin_retries_arg, args_info.puk_retries_arg, verbosity) == false) {
          ret = EXIT_FAILURE;
        } else {
          fprintf(stderr, "Successfully changed pin retries to %d and puk retries to %d, both codes have been reset to default now.\n",
              args_info.pin_retries_arg, args_info.puk_retries_arg);
        }
        break;
      case action_arg_importMINUS_key:
        if(import_key(state, args_info.key_format_arg, args_info.input_arg, args_info.slot_orig, args_info.password_arg) == false) {
          ret = EXIT_FAILURE;
        } else {
          fprintf(stderr, "Successfully imported a new private key.\n");
        }
        break;
      case action_arg_importMINUS_certificate:
        if(import_cert(state, args_info.key_format_arg, args_info.input_arg, args_info.slot_arg, args_info.password_arg) == false) {
          ret = EXIT_FAILURE;
        } else {
          fprintf(stderr, "Successfully imported a new certificate.\n");
        }
        break;
      case action_arg_setMINUS_chuid:
        if(set_chuid(state, verbosity) == false) {
          ret = EXIT_FAILURE;
        } else {
          fprintf(stderr, "Successfully set new CHUID.\n");
        }
        break;
      case action_arg_requestMINUS_certificate:
        if(request_certificate(state, args_info.key_format_arg, args_info.input_arg,
              args_info.slot_orig, args_info.subject_arg, args_info.hash_arg,
              args_info.output_arg) == false) {
          ret = EXIT_FAILURE;
        } else {
          fprintf(stderr, "Successfully generated a certificate request.\n");
        }
        break;
      case action_arg_verifyMINUS_pin:
        if(verify_pin(state, args_info.pin_arg)) {
          fprintf(stderr, "Successfully verified PIN.\n");
        } else {
          ret = EXIT_FAILURE;
        }
        break;
      case action_arg_changeMINUS_pin:
      case action_arg_changeMINUS_puk:
      case action_arg_unblockMINUS_pin:
        // TODO: set new management key if SALT is set
        if (salt_present) {
          derive_key(args_info.new_pin_arg, current_salt, current_salt_len, new_keybuf, &new_keybuf_len, 2);
          ret = ykpiv_set_mgmkey(state, new_keybuf);
          if (ret != YKPIV_OK) {
            fprintf(stderr, "Failed to update mgmkey.\n");
          }
        } else {
          fprintf(stderr, "Failed to verify pin.");
        }

        if(change_pin(state, action, args_info.pin_arg, args_info.new_pin_arg)) {
          if(action == action_arg_unblockMINUS_pin) {
            fprintf(stderr, "Successfully unblocked the pin code.\n");
          } else {
            fprintf(stderr, "Successfully changed the %s code.\n",
                action == action_arg_changeMINUS_pin ? "pin" : "puk");
          }
        } else {
          ret = EXIT_FAILURE;
        }
        break;
      case action_arg_selfsignMINUS_certificate:
        if(selfsign_certificate(state, args_info.key_format_arg, args_info.input_arg,
              args_info.slot_orig, args_info.subject_arg, args_info.hash_arg,
              args_info.output_arg) == false) {
          ret = EXIT_FAILURE;
        } else {
          fprintf(stderr, "Successfully generated a new self signed certificate.\n");
        }
        break;
      case action_arg_deleteMINUS_certificate:
        if(delete_certificate(state, args_info.slot_arg) == false) {
          ret = EXIT_FAILURE;
        }
        break;
      case action_arg_readMINUS_certificate:
        if(read_certificate(state, args_info.slot_arg, args_info.key_format_arg,
              args_info.output_arg) == false) {
          ret = EXIT_FAILURE;
        }
        break;
      case action_arg_status:
        if(status(state, args_info.hash_arg, args_info.output_arg) == false) {
          ret = EXIT_FAILURE;
        }
        break;
      case action_arg_testMINUS_signature:
        if(test_signature(state, args_info.slot_arg, args_info.hash_arg,
              args_info.input_arg, args_info.key_format_arg, verbosity) == false) {
          ret = EXIT_FAILURE;
        }
        break;
      case action_arg_testMINUS_decipher:
        if(test_decipher(state, args_info.slot_arg, args_info.input_arg,
              args_info.key_format_arg, verbosity) == false) {
          ret = EXIT_FAILURE;
        }
        break;
      case action__NULL:
      default:
        fprintf(stderr, "Wrong action. %d.\n", action);
        ret = EXIT_FAILURE;
    }
    if(ret == EXIT_FAILURE) {
      break;
    }
  }

  if(ret == EXIT_SUCCESS && args_info.sign_flag) {
    if(args_info.slot_arg == slot__NULL) {
      fprintf(stderr, "The sign action needs a slot (-s) to operate on.\n");
      ret = EXIT_FAILURE;
    } else if(sign_file(state,
                        args_info.input_arg,
                        args_info.output_arg,
                        args_info.slot_orig,
                        args_info.algorithm_arg,
                        args_info.hash_arg,
                        verbosity)) {
      fprintf(stderr, "Signature successful!\n");
    } else {
      fprintf(stderr, "Failed signing!\n");
      ret = EXIT_FAILURE;
    }
  }

  ykpiv_done(state);
  EVP_cleanup();
  return ret;
}
