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

#include <openssl/des.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/rand.h>

#include "cmdline.h"

/* FASC-N containing S9999F9999F999999F0F1F0000000000300001E encoded in
 * 4-bit BCD with 1 bit parity. run through the tools/fasc.pl script to get
 * bytes. */
/* this CHUID has an expiry of 2030-01-01, maybe that should be variable.. */
unsigned const char chuid_tmpl[] = {
  0x5c, 0x03, 0x5f, 0xc1, 0x02, 0x53, 0x3b, 0x30, 0x19, 0xd4, 0xe7, 0x39, 0xda,
  0x73, 0x9c, 0xed, 0x39, 0xce, 0x73, 0x9d, 0x83, 0x68, 0x58, 0x21, 0x08, 0x42,
  0x10, 0x84, 0x21, 0x38, 0x42, 0x10, 0xc3, 0xf5, 0x34, 0x10, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x35, 0x08, 0x32, 0x30, 0x33, 0x30, 0x30, 0x31, 0x30, 0x31, 0x3e, 0x00, 0xfe,
  0x00,
};
#define CHUID_GUID_OFFS 36

unsigned const char sha256oid[] = {
  0x30, 0x31, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04,
  0x02, 0x01, 0x05, 0x00, 0x04, 0x20
};
#define DIGEST_LEN 32

#define KEY_LEN 24

#define INPUT 1
#define OUTPUT 2

union u_APDU {
  struct {
    unsigned char cla;
    unsigned char ins;
    unsigned char p1;
    unsigned char p2;
    unsigned char lc;
    unsigned char data[0xff];
  } st;
  unsigned char raw[0xff + 5];
};

typedef union u_APDU APDU;

static void dump_hex(unsigned const char*, unsigned int);
static int set_length(unsigned char*, int);
static int get_length(unsigned char*, int*);
static X509_NAME *parse_name(char*);
static unsigned char get_algorithm(EVP_PKEY*);
static FILE *open_file(const char*, int);
static bool sign_data(ykpiv_state*, unsigned char*, int, unsigned char, unsigned char,
    ASN1_BIT_STRING*);
static int get_object_id(enum enum_slot slot);

static void print_version(ykpiv_state *state) {
  APDU apdu;
  unsigned char data[0xff];
  unsigned long recv_len = sizeof(data);
  int sw;

  memset(apdu.raw, 0, sizeof(apdu));
  apdu.st.ins = 0xfd;
  if(ykpiv_send_data(state, apdu.raw, data, &recv_len, &sw) != YKPIV_OK) {
    printf("Failed to retreive apple version.\n");
  } else if(sw == 0x9000) {
    printf("Applet version %d.%d.%d found.\n", data[0], data[1], data[2]);
  } else {
    printf("Applet version not found. Status code: %x\n", sw);
  }
}

static bool generate_key(ykpiv_state *state, const char *slot,
    enum enum_algorithm algorithm, const char *output_file_name,
    enum enum_key_format key_format) {
  unsigned char in_data[5];
  unsigned char data[1024];
  unsigned char templ[] = {0, 0x47, 0, 0};
  unsigned long recv_len = sizeof(data);
  unsigned long received = 0;
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

  sscanf(slot, "%x", &key);
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
      in_data[4] = 0x07;
      break;
    case algorithm_arg_RSA1024:
      in_data[4] = 0x06;
      break;
    case algorithm_arg_ECCP256:
      in_data[4] = 0x11;
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
  /* to drop the 90 00 and the 7f 49 at the start */
  received += recv_len - 4;

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
  APDU apdu;
  unsigned char data[0xff];
  unsigned long recv_len = sizeof(data);
  int sw;

  memset(apdu.raw, 0, sizeof(apdu));
  /* note: the reset function is only available when both pins are blocked. */
  apdu.st.ins = 0xfb;
  if(ykpiv_send_data(state, apdu.raw, data, &recv_len, &sw) != YKPIV_OK) {
    return false;
  } else if(sw == 0x9000) {
    return true;
  }
  return false;
}

static bool set_pin_retries(ykpiv_state *state, int pin_retries, int puk_retries, int verbose) {
  APDU apdu;
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

  memset(apdu.raw, 0, sizeof(apdu));
  apdu.st.ins = 0xfa;
  apdu.st.p1 = pin_retries;
  apdu.st.p2 = puk_retries;
  if(ykpiv_send_data(state, apdu.raw, data, &recv_len, &sw) != YKPIV_OK) {
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

  sscanf(slot, "%x", &key);

  input_file = open_file(input_file_name, INPUT);
  if(!input_file) {
    return false;
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
      unsigned char templ[] = {0, 0xfe, algorithm, key};
      int sw;
      if(algorithm == 0x06 || algorithm == 0x07) {
        RSA *rsa_private_key = EVP_PKEY_get1_RSA(private_key);

        *in_ptr++ = 0x01;
        in_ptr += set_length(in_ptr, BN_num_bytes(rsa_private_key->p));
        in_ptr += BN_bn2bin(rsa_private_key->p, in_ptr);

        *in_ptr++ = 0x02;
        in_ptr += set_length(in_ptr, BN_num_bytes(rsa_private_key->q));
        in_ptr += BN_bn2bin(rsa_private_key->q, in_ptr);

        *in_ptr++ = 0x03;
        in_ptr += set_length(in_ptr, BN_num_bytes(rsa_private_key->dmp1));
        in_ptr += BN_bn2bin(rsa_private_key->dmp1, in_ptr);

        *in_ptr++ = 0x04;
        in_ptr += set_length(in_ptr, BN_num_bytes(rsa_private_key->dmq1));
        in_ptr += BN_bn2bin(rsa_private_key->dmq1, in_ptr);

        *in_ptr++ = 0x05;
        in_ptr += set_length(in_ptr, BN_num_bytes(rsa_private_key->iqmp));
        in_ptr += BN_bn2bin(rsa_private_key->iqmp, in_ptr);
      } else if(algorithm == 0x11) {
        EC_KEY *ec = EVP_PKEY_get1_EC_KEY(private_key);
        const BIGNUM *s = EC_KEY_get0_private_key(ec);

        *in_ptr++ = 0x06;
        in_ptr += set_length(in_ptr, BN_num_bytes(s));
        in_ptr += BN_bn2bin(s, in_ptr);
      }

      if(ykpiv_transfer_data(state, templ, in_data, in_ptr - in_data, data,
            &recv_len, &sw) != YKPIV_OK) {
        return false;
      } else if(sw != 0x9000) {
        fprintf(stderr, "Failed import command with code %x.", sw);
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
  int object = get_object_id(slot);

  input_file = open_file(input_file_name, INPUT);
  if(!input_file) {
    return false;
  }

  if(cert_format == key_format_arg_PEM) {
    cert = PEM_read_X509(input_file, NULL, NULL, password);
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
  } else {
    /* TODO: more formats go here */
    fprintf(stderr, "Unknown key format.\n");
    goto import_cert_out;
  }

  {
    unsigned char certdata[2100];
    unsigned char *certptr = certdata;
    unsigned char data[0xff];
    unsigned char templ[] = {0, 0xdb, 0x3f, 0xff};
    unsigned long recv_len = sizeof(data);
    int cert_len = i2d_X509(cert, NULL);
    int bytes;
    int sw;

    if(cert_len > 2048) {
      fprintf(stderr, "Certificate to large, maximum 2048 bytes (was %d bytes).\n", cert_len);
      goto import_cert_out;
    }
    *certptr++ = 0x5c;
    *certptr++ = 0x03;
    *certptr++ = (object >> 16) & 0xff;
    *certptr++ = (object >> 8) & 0xff;
    *certptr++ = object & 0xff;
    *certptr++ = 0x53;
    if(cert_len < 0x80) {
      bytes = 1;
    } else if(cert_len < 0xff) {
      bytes = 2;
    } else {
      bytes = 3;
    }
    certptr += set_length(certptr, cert_len + bytes + 6);
    *certptr++ = 0x70;
    certptr += set_length(certptr, cert_len);
    /* i2d_X509 increments certptr here.. */
    i2d_X509(cert, &certptr);
    *certptr++ = 0x71;
    *certptr++ = 1;
    *certptr++ = 0; /* certinfo (gzip etc) */
    *certptr++ = 0xfe; /* LRC */
    *certptr++ = 0;

    if(ykpiv_transfer_data(state, templ, certdata, certptr - certdata, data,
          &recv_len, &sw) != YKPIV_OK) {
      fprintf(stderr, "Failed commands with device.\n");
    } else if(sw != 0x9000) {
      fprintf(stderr, "Failed loading certificate to device with code %x.\n", sw);
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
  APDU apdu;
  unsigned char data[0xff];
  unsigned char *dataptr = apdu.st.data;
  unsigned long recv_len = sizeof(data);
  int sw;

  memset(apdu.raw, 0, sizeof(apdu));
  memcpy(apdu.st.data, chuid_tmpl, sizeof(chuid_tmpl));
  dataptr += CHUID_GUID_OFFS;
  if(RAND_pseudo_bytes(dataptr, 0x10) == -1) {
    fprintf(stderr, "error: no randomness.\n");
    return false;
  }
  if(verbose) {
    fprintf(stderr, "Setting the GUID to: ");
    dump_hex(dataptr, 0x10);
    fprintf(stderr, "\n");
  }
  apdu.st.ins = 0xdb;
  apdu.st.p1 = 0x3f;
  apdu.st.p2 = 0xff;
  apdu.st.lc = sizeof(chuid_tmpl);
  if(ykpiv_send_data(state, apdu.raw, data, &recv_len, &sw) != YKPIV_OK) {
    fprintf(stderr, "Failed communicating with device.\n");
    return false;
  } else if(sw != 0x9000) {
    fprintf(stderr, "Failed setting CHUID.\n");
    return false;
  }
  return true;
}

static bool request_certificate(ykpiv_state *state, enum enum_key_format key_format,
    const char *input_file_name, const char *slot, char *subject,
    const char *output_file_name) {
  X509_REQ *req = NULL;
  X509_NAME *name = NULL;
  FILE *input_file = NULL;
  FILE *output_file = NULL;
  EVP_PKEY *public_key = NULL;
  bool ret = false;
  unsigned char digest[DIGEST_LEN + sizeof(sha256oid)];
  unsigned int digest_len = DIGEST_LEN;
  unsigned char algorithm;
  int key = 0;
  unsigned char signinput[256];
  int len = 0;

  sscanf(slot, "%x", &key);

  input_file = open_file(input_file_name, INPUT);
  output_file = open_file(output_file_name, OUTPUT);
  if(!input_file || !output_file) {
    goto request_out;
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

  memset(digest, 0, sizeof(digest));
  memcpy(digest, sha256oid, sizeof(sha256oid));
  /* XXX: this should probably use X509_REQ_digest() but that's buggy */
  if(!ASN1_item_digest(ASN1_ITEM_rptr(X509_REQ_INFO), EVP_sha256(), req->req_info,
			  digest + sizeof(sha256oid), &digest_len)) {
    fprintf(stderr, "Failed doing digest of request.\n");
    goto request_out;
  }

  switch(algorithm) {
    case 0x6:
      len = 128;
    case 0x7:
      if(len == 0) {
        len = 256;
      }
      RSA_padding_add_PKCS1_type_1(signinput, len, digest, sizeof(digest));
      req->sig_alg->algorithm = OBJ_nid2obj(NID_sha256WithRSAEncryption);
      break;
    case 0x11:
      req->sig_alg->algorithm = OBJ_nid2obj(NID_ecdsa_with_SHA256);
      len = DIGEST_LEN;
      memcpy(signinput, digest + sizeof(sha256oid), DIGEST_LEN);
      break;
    default:
      fprintf(stderr, "Unsupported algorithm %x.\n", algorithm);
      goto request_out;
  }
  if(sign_data(state, signinput, len, algorithm, key, req->signature) == false) {
    goto request_out;
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
    const char *input_file_name, const char *slot, char *subject,
    const char *output_file_name) {
  FILE *input_file = NULL;
  FILE *output_file = NULL;
  bool ret = false;
  EVP_PKEY *public_key = NULL;
  X509 *x509 = NULL;
  X509_NAME *name = NULL;
  unsigned char digest[DIGEST_LEN + sizeof(sha256oid)];
  unsigned int digest_len = DIGEST_LEN;
  unsigned char algorithm;
  int key = 0;
  unsigned char signinput[256];
  int len = 0;

  sscanf(slot, "%x", &key);

  input_file = open_file(input_file_name, INPUT);
  output_file = open_file(output_file_name, OUTPUT);
  if(!input_file || !output_file) {
    goto selfsign_out;
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

  x509 = X509_new();
  if(!x509) {
    fprintf(stderr, "Failed to allocate certificate structure.\n");
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
  memset(digest, 0, sizeof(digest));
  memcpy(digest, sha256oid, sizeof(sha256oid));
  /* XXX: this should probably use X509_digest() but that looks buggy */
  if(!ASN1_item_digest(ASN1_ITEM_rptr(X509_CINF), EVP_sha256(), x509->cert_info,
			  digest + sizeof(sha256oid), &digest_len)) {
    fprintf(stderr, "Failed doing digest of certificate.\n");
    goto selfsign_out;
  }
  switch(algorithm) {
    case 0x6:
      len = 128;
    case 0x7:
      if(len == 0) {
        len = 256;
      }
      RSA_padding_add_PKCS1_type_1(signinput, len, digest, sizeof(digest));
      x509->sig_alg->algorithm = OBJ_nid2obj(NID_sha256WithRSAEncryption);
      break;
    case 0x11:
      x509->sig_alg->algorithm = OBJ_nid2obj(NID_ecdsa_with_SHA256);
      len = DIGEST_LEN;
      memcpy(signinput, digest + sizeof(sha256oid), DIGEST_LEN);
      break;
    default:
      fprintf(stderr, "Unsupported algorithm %x.\n", algorithm);
      goto selfsign_out;
  }
  if(sign_data(state, signinput, len, algorithm, key, x509->signature)) {
    goto selfsign_out;
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
  APDU apdu;
  unsigned char data[0xff];
  unsigned long recv_len = sizeof(data);
  int sw;
  size_t len = strlen(pin);

  if(len > 8) {
    fprintf(stderr, "Maximum 8 digits of PIN supported.\n");
    return false;
  }

  memset(apdu.raw, 0, sizeof(apdu.raw));
  apdu.st.ins = 0x20;
  apdu.st.p1 = 0x00;
  apdu.st.p2 = 0x80;
  apdu.st.lc = 0x08;
  memcpy(apdu.st.data, pin, len);
  if(len < 8) {
    memset(apdu.st.data + len, 0xff, 8 - len);
  }
  if(ykpiv_send_data(state, apdu.raw, data, &recv_len, &sw) != YKPIV_OK) {
    return false;
  } else if(sw == 0x9000) {
    return true;
  } else if((sw >> 8) == 0x63) {
    fprintf(stderr, "Pin verification failed, %d tries left before pin is blocked.\n", sw & 0xff);
  } else if(sw == 0x6983) {
    fprintf(stderr, "Pin code blocked, use unblock-pin action to unblock.\n");
  } else {
    fprintf(stderr, "Pin code verification failed with code %x.\n", sw);
  }
  return false;
}

/* this function is called for all three of change-pin, change-puk and unblock pin
 * since they're very similar in what data they use. */
static bool change_pin(ykpiv_state *state, enum enum_action action, const char *pin,
    const char *new_pin) {
  APDU apdu;
  unsigned char data[0xff];
  unsigned long recv_len = sizeof(data);
  int sw;
  size_t pin_len = strlen(pin);
  size_t new_len = strlen(new_pin);

  if(pin_len > 8 || new_len > 8) {
    fprintf(stderr, "Maximum 8 digits of PIN supported.\n");
    return false;
  }

  memset(apdu.raw, 0, sizeof(apdu.raw));
  apdu.st.ins = action == action_arg_unblockMINUS_pin ? 0x2c : 0x24;
  apdu.st.p2 = action == action_arg_changeMINUS_puk ? 0x81 : 0x80;
  apdu.st.lc = 0x10;
  memcpy(apdu.st.data, pin, pin_len);
  if(pin_len < 8) {
    memset(apdu.st.data + pin_len, 0xff, 8 - pin_len);
  }
  memcpy(apdu.st.data + 8, new_pin, new_len);
  if(new_len < 8) {
    memset(apdu.st.data + 8 + new_len, 0xff, 16 - new_len);
  }
  if(ykpiv_send_data(state, apdu.raw, data, &recv_len, &sw) != YKPIV_OK) {
    return false;
  } else if(sw != 0x9000) {
    if((sw >> 8) == 0x63) {
      int tries = sw & 0xff;
      fprintf(stderr, "Failed verifying %s code, now %d tries left before blocked.\n",
          action == action_arg_changeMINUS_pin ? "pin" : "puk", tries);
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

static bool delete_certificate(ykpiv_state *state, enum enum_slot slot) {
  APDU apdu;
  unsigned char objdata[7];
  unsigned char *ptr = objdata;
  unsigned char data[0xff];
  unsigned long recv_len = sizeof(data);
  unsigned char templ[] = {0, 0xdb, 0x3f, 0xff};
  int sw;
  bool ret = false;
  int object = get_object_id(slot);

  *ptr++ = 0x5c;
  *ptr++ = 0x03;
  *ptr++ = (object >> 16) & 0xff;
  *ptr++ = (object >> 8) & 0xff;
  *ptr++ = object & 0xff;
  *ptr++ = 0x53;
  *ptr++ = 0x00; /* length 0 means we'll delete the object */

  memset(apdu.raw, 0, sizeof(apdu.raw));
  apdu.st.ins = 0xdb;
  apdu.st.p1 = 0x3f;
  apdu.st.p2 = 0xff;

  if(ykpiv_transfer_data(state, templ, objdata, 7, data, &recv_len, &sw)
      != YKPIV_OK) {
    return false;
  } else if(sw != 0x9000) {
    fprintf(stderr, "Failed deleting certificate to device with code %x.\n", sw);
  } else {
    ret = true;
  }
  return ret;
}

static bool sign_data(ykpiv_state *state, unsigned char *signinput, int in_len,
    unsigned char algorithm, unsigned char key, ASN1_BIT_STRING *sig) {
  unsigned char indata[1024];
  unsigned char *dataptr = indata;
  unsigned char data[1024];
  unsigned char templ[] = {0, 0x87, algorithm, key};
  unsigned long recv_len = sizeof(data);
  int sw;
  int bytes;
  int len;

  if(in_len < 0x80) {
    bytes = 1;
  } else if(in_len < 0xff) {
    bytes = 2;
  } else {
    bytes = 3;
  }

  *dataptr++ = 0x7c;
  dataptr += set_length(dataptr, in_len + bytes + 3);
  *dataptr++ = 0x82;
  *dataptr++ = 0x00;
  *dataptr++ = 0x81;
  dataptr += set_length(dataptr, in_len);
  memcpy(dataptr, signinput, (size_t)in_len);
  dataptr += in_len;

  if(ykpiv_transfer_data(state, templ, indata, dataptr - indata, data,
        &recv_len, &sw) != YKPIV_OK) {
    fprintf(stderr, "Sign command failed to communicate.\n");
    return false;
  } else if(sw != 0x9000) {
    fprintf(stderr, "Failed sign command with code %x.\n", sw);
    return false;
  }
  /* skip the first 7c tag */
  if(data[0] != 0x7c) {
    fprintf(stderr, "Failed parsing signature reply.\n");
    return false;
  }
  dataptr = data + 1;
  dataptr += get_length(dataptr, &len);
  /* skip the 82 tag */
  if(*dataptr != 0x82) {
    fprintf(stderr, "Failed parsing signature reply.\n");
    return false;
  }
  dataptr++;
  dataptr += get_length(dataptr, &len);
  M_ASN1_BIT_STRING_set(sig, dataptr, len);
  return true;
}

static FILE *open_file(const char *file_name, int mode) {
  FILE *file;
  if(!strcmp(file_name, "-")) {
    file = mode == INPUT ? stdin : stdout;
  } else {
    file = fopen(file_name, mode == INPUT ? "r" : "w");
    if(!file) {
      fprintf(stderr, "Failed opening '%s'!\n", file_name);
      return NULL;
    }
  }
  return file;
}

static unsigned char get_algorithm(EVP_PKEY *key) {
  int type = EVP_PKEY_type(key->type);
  switch(type) {
    case EVP_PKEY_RSA:
      {
        RSA *rsa = EVP_PKEY_get1_RSA(key);
        int size = RSA_size(rsa);
        if(size == 256) {
          return 0x7;
        } else if(size == 128) {
          return 0x6;
        } else {
          fprintf(stderr, "Unuseable key of %d bits, only 1024 and 2048 is supported.\n", size * 8);
          return 0;
        }
      }
    case EVP_PKEY_EC:
      {
        EC_KEY *ec = EVP_PKEY_get1_EC_KEY(key);
        const EC_GROUP *group = EC_KEY_get0_group(ec);
        int curve = EC_GROUP_get_curve_name(group);
        if(curve == NID_X9_62_prime256v1) {
          return 0x11;
        } else {
          fprintf(stderr, "Unknown EC curve %d\n", curve);
          return 0;
        }
      }
    default:
      fprintf(stderr, "Unknown algorithm %d.\n", type);
      return 0;
  }
}

static X509_NAME *parse_name(char *name) {
  X509_NAME *parsed = NULL;
  char *ptr = name;
  char *part;
  if(*name != '/') {
    fprintf(stderr, "Name does not start with '/'!\n");
    return NULL;
  }
  parsed = X509_NAME_new();
  if(!parsed) {
    fprintf(stderr, "Failed to allocate memory\n");
    return NULL;
  }
  while((part = strtok(ptr, "/"))) {
    char *key;
    char *value;
    char *equals = strchr(part, '=');
    if(!equals) {
      fprintf(stderr, "The part '%s' doesn't seem to contain a =.\n", part);
      goto parse_err;
    }
    *equals++ = '\0';
    value = equals;
    key = part;

    ptr = NULL;
    if(!key) {
      fprintf(stderr, "Malformed name (%s)\n", part);
      goto parse_err;
    }
    if(!value) {
      fprintf(stderr, "Malformed name (%s)\n", part);
      goto parse_err;
    }
    if(!X509_NAME_add_entry_by_txt(parsed, key, MBSTRING_UTF8, (unsigned char*)value, -1, -1, 0)) {
      fprintf(stderr, "Failed adding %s=%s to name.\n", key, value);
      goto parse_err;
    }
  }
  return parsed;
parse_err:
  X509_NAME_free(parsed);
  return NULL;
}

static void dump_hex(const unsigned char *buf, unsigned int len) {
  unsigned int i;
  for (i = 0; i < len; i++) {
    fprintf(stderr, "%02x ", buf[i]);
  }
}

static int get_length(unsigned char *buffer, int *len) {
  if(buffer[0] < 0x81) {
    *len = buffer[0];
    return 1;
  } else if((*buffer & 0x7f) == 1) {
    *len = buffer[1];
    return 2;
  } else if((*buffer & 0x7f) == 2) {
    *len = (buffer[1] << 8) + buffer[2];
    return 3;
  }
  return 0;
}

static int set_length(unsigned char *buffer, int length) {
  if(length < 0x80) {
    *buffer++ = length;
    return 1;
  } else if(length < 0xff) {
    *buffer++ = 0x81;
    *buffer++ = length;
    return 2;
  } else {
    *buffer++ = 0x82;
    *buffer++ = (length >> 8) & 0xff;
    *buffer++ = length & 0xff;
    return 3;
  }
}

static int get_object_id(enum enum_slot slot) {
  int object;

  switch(slot) {
    case slot_arg_9a:
      object = 0x5fc105;
      break;
    case slot_arg_9c:
      object = 0x5fc10a;
      break;
    case slot_arg_9d:
      object = 0x5fc10b;
      break;
    case slot_arg_9e:
      object = 0x5fc101;
      break;
    case slot__NULL:
    default:
      object = 0;
  }
  return object;
}

int main(int argc, char *argv[]) {
  struct gengetopt_args_info args_info;
  ykpiv_state *state;
  unsigned char key[KEY_LEN];
  int verbosity;
  enum enum_action action;
  unsigned int i;
  int ret = EXIT_SUCCESS;

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

  if(ykpiv_parse_key(state, args_info.key_arg, key) != YKPIV_OK) {
    return EXIT_FAILURE;
  }

  if(ykpiv_authenticate(state, key) != YKPIV_OK) {
    fprintf(stderr, "Failed authentication with the applet.\n");
    return EXIT_FAILURE;
  }
  if(verbosity) {
    fprintf(stderr, "Successful applet authentication.\n");
  }

  /* openssl setup.. */
  OpenSSL_add_all_algorithms();

  for(i = 0; i < args_info.action_given; i++) {
    action = *args_info.action_arg++;
    if(verbosity) {
      fprintf(stderr, "Now processing for action %d.\n", action);
    }
    switch(action) {
      case action_arg_version:
        print_version(state);
        break;
      case action_arg_generate:
        if(args_info.slot_arg != slot__NULL) {
          if(generate_key(state, args_info.slot_orig, args_info.algorithm_arg, args_info.output_arg, args_info.key_format_arg) == false) {
            ret = EXIT_FAILURE;
          }
        } else {
          fprintf(stderr, "The generate action needs a slot (-s) to operate on.\n");
          ret = EXIT_FAILURE;
        }
        break;
      case action_arg_setMINUS_mgmMINUS_key:
        if(args_info.new_key_arg) {
          unsigned char new_key[KEY_LEN];
          if(ykpiv_parse_key(state, args_info.new_key_arg, new_key) != YKPIV_OK) {
            ret = EXIT_FAILURE;
          } else if(ykpiv_set_mgmkey(state, new_key) != YKPIV_OK) {
            ret = EXIT_FAILURE;
          } else {
            printf("Successfully set new management key.\n");
          }
        } else {
          fprintf(stderr, "The set-mgm-key action needs the new-key (-n) argument.\n");
          ret = EXIT_FAILURE;
        }
        break;
      case action_arg_reset:
        if(reset(state) == false) {
          ret = EXIT_FAILURE;
        } else {
          printf("Successfully reset the applet.\n");
        }
        break;
      case action_arg_pinMINUS_retries:
        if(args_info.pin_retries_arg && args_info.puk_retries_arg) {
          if(set_pin_retries(state, args_info.pin_retries_arg, args_info.puk_retries_arg, verbosity) == false) {
            ret = EXIT_FAILURE;
          } else {
            printf("Successfully changed pin retries to %d and puk retries to %d, both codes have been reset to default now.\n",
                args_info.pin_retries_arg, args_info.puk_retries_arg);
          }
        } else {
          fprintf(stderr, "The pin-retries action needs both --pin-retries and --puk-retries arguments.\n");
          ret = EXIT_FAILURE;
        }
        break;
      case action_arg_importMINUS_key:
        if(args_info.slot_arg != slot__NULL) {
          if(import_key(state, args_info.key_format_arg, args_info.input_arg, args_info.slot_orig, args_info.password_arg) == false) {
            ret = EXIT_FAILURE;
          } else {
            printf("Successfully imported a new private key.\n");
          }
        } else {
          fprintf(stderr, "The import action needs a slot (-s) to operate on.\n");
          ret = EXIT_FAILURE;
        }
        break;
      case action_arg_importMINUS_certificate:
        if(args_info.slot_arg != slot__NULL) {
          if(import_cert(state, args_info.key_format_arg, args_info.input_arg, args_info.slot_arg, args_info.password_arg) == false) {
            ret = EXIT_FAILURE;
          } else {
            printf("Successfully imported a new certificate.\n");
          }
        } else {
          fprintf(stderr, "The import action needs a slot (-s) to operate on.\n");
          ret = EXIT_FAILURE;
        }
        break;
      case action_arg_setMINUS_chuid:
        if(set_chuid(state, verbosity) == false) {
          ret = EXIT_FAILURE;
        } else {
          printf("Successfully set new CHUID.\n");
        }
        break;
      case action_arg_requestMINUS_certificate:
        if(args_info.slot_arg == slot__NULL) {
          fprintf(stderr, "The request-certificate action needs a slot (-s) to operate on.\n");
          ret = EXIT_FAILURE;
        } else if(!args_info.subject_arg) {
          fprintf(stderr, "The request-certificate action needs a subject (-S) to operate on.\n");
          ret = EXIT_FAILURE;
        } else {
          if(request_certificate(state, args_info.key_format_arg, args_info.input_arg,
                args_info.slot_orig, args_info.subject_arg, args_info.output_arg) == false) {
            ret = EXIT_FAILURE;
          }
        }
        break;
      case action_arg_verifyMINUS_pin:
        if(args_info.pin_arg) {
          if(verify_pin(state, args_info.pin_arg)) {
            printf("Successfully verified PIN.\n");
          } else {
            ret = EXIT_FAILURE;
          }
        } else {
          fprintf(stderr, "The verify-pin action needs a pin (-P).\n");
          ret = EXIT_FAILURE;
        }
        break;
      case action_arg_changeMINUS_pin:
      case action_arg_changeMINUS_puk:
      case action_arg_unblockMINUS_pin:
        if(args_info.pin_arg && args_info.new_pin_arg) {
          if(change_pin(state, action, args_info.pin_arg, args_info.new_pin_arg)) {
            if(action == action_arg_unblockMINUS_pin) {
              printf("Successfully unblocked the pin code.\n");
            } else {
              printf("Successfully changed the %s code.\n",
                  action == action_arg_changeMINUS_pin ? "pin" : "puk");
            }
          } else {
            ret = EXIT_FAILURE;
          }
        } else {
          fprintf(stderr, "The %s action needs a pin (-P) and a new-pin (-N).\n",
              action == action_arg_changeMINUS_pin ? "change-pin" :
              action == action_arg_changeMINUS_puk ? "change-puk" : "unblock-pin");
          ret = EXIT_FAILURE;
        }
        break;
      case action_arg_selfsignMINUS_certificate:
        if(args_info.slot_arg == slot__NULL) {
          fprintf(stderr, "The selfsign-certificate action needs a slot (-s) to operate on.\n");
          ret = EXIT_FAILURE;
        } else if(!args_info.subject_arg) {
          fprintf(stderr, "The selfsign-certificate action needs a subject (-S) to operate on.\n");
          ret = EXIT_FAILURE;
        } else {
          if(selfsign_certificate(state, args_info.key_format_arg, args_info.input_arg,
                args_info.slot_orig, args_info.subject_arg, args_info.output_arg) == false) {
            ret = EXIT_FAILURE;
          }
        }
        break;
      case action_arg_deleteMINUS_certificate:
	if(args_info.slot_arg == slot__NULL) {
	  fprintf(stderr, "The delete-certificate action needs a slot (-s) to operate on.\n");
	  ret = EXIT_FAILURE;
	} else {
	  if(delete_certificate(state, args_info.slot_arg) == false) {
	    ret = EXIT_FAILURE;
	  }
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

  ykpiv_done(state);
  EVP_cleanup();
  return ret;
}
