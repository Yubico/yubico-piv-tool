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

#include <openssl/des.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/rand.h>

#if BACKEND_PCSC
#if defined HAVE_PCSC_WINSCARD_H
# include <PCSC/wintypes.h>
# include <PCSC/winscard.h>
#else
# include <winscard.h>
#endif
#endif

#include "cmdline.h"

unsigned const char aid[] = {
  0xa0, 0x00, 0x00, 0x03, 0x08
};

/* FASC-N containing F9999F9999F999999F0F1F0000000000300001E encoded in
 * 4-bit BCD with 1 bit parity. run through the tools/fasc.pl script to get
 * bytes. */
/* this CHUID has an expiry of 2030-01-01, maybe that should be variable.. */
unsigned const char chuid_tmpl[] = {
  0x5c, 0x03, 0x5f, 0xc1, 0x02, 0x53, 0x3b, 0x30, 0x19, 0xd4, 0xe7, 0x39, 0xea,
  0x73, 0x9c, 0xf5, 0x39, 0xce, 0x73, 0x9e, 0x83, 0xa8, 0x68, 0x21, 0x08, 0x42,
  0x10, 0x84, 0x21, 0x38, 0x42, 0x10, 0xc3, 0xf9, 0x34, 0x10, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x35, 0x08, 0x32, 0x30, 0x33, 0x30, 0x30, 0x31, 0x30, 0x31, 0x3e, 0x00, 0xfe,
  0x00,
};
#define CHUID_GUID_OFFS 35

#define KEY_LEN 24

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
static int send_data(SCARDHANDLE*, APDU*, unsigned int, unsigned char*, unsigned long*, int);
static int set_length(unsigned char*, int);
static int get_length(unsigned char*, int *);

static bool connect_reader(SCARDHANDLE *card, SCARDCONTEXT *context, const char *wanted, int verbose) {
  unsigned long num_readers;
  unsigned long active_protocol;
  char reader_buf[1024];
  long rc;
  char *reader_ptr;

  rc = SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, context);
  if (rc != SCARD_S_SUCCESS) {
    fprintf (stderr, "error: SCardEstablishContext failed, rc=%08lx\n", rc);
    return false;
  }

  rc = SCardListReaders(*context, NULL, NULL, &num_readers);
  if (rc != SCARD_S_SUCCESS) {
    fprintf (stderr, "error: SCardListReaders failed, rc=%08lx\n", rc);
    SCardReleaseContext(*context);
    return false;
  }

  if (num_readers > sizeof(reader_buf)) {
    num_readers = sizeof(reader_buf);
  }

  rc = SCardListReaders(*context, NULL, reader_buf, &num_readers);
  if (rc != SCARD_S_SUCCESS)
  {
    fprintf (stderr, "error: SCardListReaders failed, rc=%08lx\n", rc);
    SCardReleaseContext(*context);
    return false;
  }

  reader_ptr = reader_buf;
  if(wanted) {
    while(*reader_ptr != '\0') {
      if(strstr(reader_ptr, wanted)) {
        if(verbose) {
          fprintf(stderr, "using reader '%s' matching '%s'.\n", reader_ptr, wanted);
        }
        break;
      } else {
        if(verbose) {
          fprintf(stderr, "skipping reader '%s' since it doesn't match.\n", reader_ptr);
        }
        reader_ptr += strlen(reader_ptr) + 1;
      }
    }
  }
  if(*reader_ptr == '\0') {
    fprintf(stderr, "error: no useable reader found.\n");
    SCardReleaseContext(*context);
    return false;
  }

  rc = SCardConnect(*context, reader_ptr, SCARD_SHARE_SHARED,
      SCARD_PROTOCOL_T1, card, &active_protocol);
  if(rc != SCARD_S_SUCCESS)
  {
    fprintf(stderr, "error: SCardConnect failed, rc=%08lx\n", rc);
    SCardReleaseContext(*context);
    return false;
  }

  return true;
}

static bool select_applet(SCARDHANDLE *card, int verbose) {
  APDU apdu;
  unsigned char data[0xff];
  unsigned long recv_len = sizeof(data);
  int sw;

  memset(apdu.raw, 0, sizeof(apdu));
  apdu.st.ins = 0xa4;
  apdu.st.p1 = 0x04;
  apdu.st.lc = sizeof(aid);
  memcpy(apdu.st.data, aid, sizeof(aid));

  sw = send_data(card, &apdu, sizeof(aid) + 5, data, &recv_len, verbose);
  if(sw == 0x9000) {
    return true;
  }

  return false;
}

static bool authenticate(SCARDHANDLE *card, unsigned const char *key, int verbose) {
  APDU apdu;
  unsigned char data[0xff];
  DES_cblock challenge;
  unsigned long recv_len = sizeof(data);
  int sw;

  DES_key_schedule ks1, ks2, ks3;

  {
    const_DES_cblock key_tmp;
    memcpy(key_tmp, key, 8);
    DES_set_key_unchecked(&key_tmp, &ks1);
    memcpy(key_tmp, key + 8, 8);
    DES_set_key_unchecked(&key_tmp, &ks2);
    memcpy(key_tmp, key + 16, 8);
    DES_set_key_unchecked(&key_tmp, &ks3);
  }

  {
    memset(apdu.raw, 0, sizeof(apdu));
    apdu.st.ins = 0x87;
    apdu.st.p1 = 0x03; /* triple des */
    apdu.st.p2 = 0x9b; /* management key */
    apdu.st.lc = 0x04;
    apdu.st.data[0] = 0x7c;
    apdu.st.data[1] = 0x02;
    apdu.st.data[2] = 0x80;
    sw = send_data(card, &apdu, 9, data, &recv_len, verbose);
    if(sw != 0x9000) {
      return false;
    }
    memcpy(challenge, data + 4, 8);
  }

  {
    DES_cblock response;
    DES_ecb3_encrypt(&challenge, &response, &ks1, &ks2, &ks3, 0);

    recv_len = 0xff;
    memset(apdu.raw, 0, sizeof(apdu));
    apdu.st.ins = 0x87;
    apdu.st.p1 = 0x03; /* triple des */
    apdu.st.p2 = 0x9b; /* management key */
    apdu.st.lc = 12;
    apdu.st.data[0] = 0x7c;
    apdu.st.data[1] = 10;
    apdu.st.data[2] = 0x80;
    apdu.st.data[3] = 8;
    memcpy(apdu.st.data + 4, response, 8);
    sw = send_data(card, &apdu, 17, data, &recv_len, verbose);
  }

  if(sw == 0x9000) {
    return true;
  }
  return false;
}

static void print_version(SCARDHANDLE *card, int verbose) {
  APDU apdu;
  unsigned char data[0xff];
  unsigned long recv_len = sizeof(data);
  int sw;

  memset(apdu.raw, 0, sizeof(apdu));
  apdu.st.ins = 0xfd;
  sw = send_data(card, &apdu, 4, data, &recv_len, verbose);
  if(sw == 0x9000) {
    printf("Applet version %d.%d.%d found.\n", data[0], data[1], data[2]);
  } else {
    printf("Applet version not found. Status code: %x\n", sw);
  }
}

static bool generate_key(SCARDHANDLE *card, const char *slot, enum enum_algorithm algorithm, const char *output_file_name, enum enum_key_format key_format, int verbose) {
  APDU apdu;
  unsigned char data[1024];
  unsigned long recv_len = 0xff;
  unsigned long received = 0;
  int sw;
  int key = 0;
  FILE *output_file;
  bool ret = true;
  EVP_PKEY *public_key = NULL;
  RSA *rsa = NULL;
  BIGNUM *bignum_n = NULL;
  BIGNUM *bignum_e = NULL;
  EC_KEY *eckey = NULL;
  EC_POINT *point = NULL;

  sscanf(slot, "%x", &key);

  if(!strcmp(output_file_name, "-")) {
    output_file = stdout;
  } else {
    output_file = fopen(output_file_name, "r");
    if(!output_file) {
      fprintf(stderr, "Failed opening '%s'!\n", output_file_name);
      return false;
    }
  }

  memset(apdu.raw, 0, sizeof(apdu));
  apdu.st.ins = 0x47;
  apdu.st.p2 = key;
  apdu.st.lc = 5;
  apdu.st.data[0] = 0xac;
  apdu.st.data[1] = 3;
  apdu.st.data[2] = 0x80;
  apdu.st.data[3] = 1;
  switch(algorithm) {
    case algorithm_arg_RSA2048:
      apdu.st.data[4] = 0x07;
      break;
    case algorithm_arg_RSA1024:
      apdu.st.data[4] = 0x06;
      break;
    case algorithm_arg_ECCP256:
      apdu.st.data[4] = 0x11;
      break;
    case algorithm__NULL:
    default:
      fprintf(stderr, "Unexepcted algorithm.\n");
      ret = false;
      goto generate_out;
  }
  sw = send_data(card, &apdu, 10, data, &recv_len, verbose);

  /* chained response */
  if((sw & 0x6100) == 0x6100) {
    received += recv_len - 2;
    recv_len = 0xff;
    memset(apdu.raw, 0, sizeof(apdu));
    apdu.st.ins = 0xc0;
    sw = send_data(card, &apdu, 4, data + received, &recv_len, verbose);
  }
  if(sw != 0x9000) {
    fprintf(stderr, "Failed to generate new key.\n");
    ret = false;
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
        ret = false;
        goto generate_out;
      }
      data_ptr++;
      data_ptr += get_length(data_ptr, &len);
      bignum_n = BN_bin2bn(data_ptr, len, NULL);
      if(bignum_n == NULL) {
        fprintf(stderr, "Failed to parse public key modulus.\n");
        ret = false;
        goto generate_out;
      }
      data_ptr += len;

      if(*data_ptr != 0x82) {
        fprintf(stderr, "Failed to parse public key structure (2).\n");
        ret = false;
        goto generate_out;
      }
      data_ptr++;
      data_ptr += get_length(data_ptr, &len);
      bignum_e = BN_bin2bn(data_ptr, len, NULL);
      if(bignum_e == NULL) {
        fprintf(stderr, "Failed to parse public key exponent.\n");
        ret = false;
        goto generate_out;
      }

      rsa->n = bignum_n;
      rsa->e = bignum_e;
      EVP_PKEY_set1_RSA(public_key, rsa);
    } else if(algorithm == algorithm_arg_ECCP256) {
      const EC_GROUP *group;
      unsigned char *data_ptr = data + 3;

      eckey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
      group = EC_KEY_get0_group(eckey);
      point = EC_POINT_new(group);
      if(*data_ptr++ != 0x86) {
        fprintf(stderr, "Failed to parse public key structure.\n");
        ret = false;
        goto generate_out;
      }
      if(*data_ptr++ != 65) { /* the curve point should always be 65 bytes */
        fprintf(stderr, "Unexpected length.\n");
        ret = false;
        goto generate_out;
      }
      if(!EC_POINT_oct2point(group, point, data_ptr, 65, NULL)) {
        fprintf(stderr, "Failed to load public point.\n");
        ret = false;
        goto generate_out;
      }
      if(!EC_KEY_set_public_key(eckey, point)) {
        fprintf(stderr, "Failed to set the public key.\n");
        ret = false;
        goto generate_out;
      }
      EVP_PKEY_set1_EC_KEY(public_key, eckey);
    } else {
      fprintf(stderr, "Wrong algorithm.\n");
      ret = false;
      goto generate_out;
    }
    PEM_write_PUBKEY(output_file, public_key);
  } else {
    fprintf(stderr, "Only PEM is supported as public_key output.\n");
    ret = false;
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

static bool set_mgm_key(SCARDHANDLE *card, unsigned const char *new_key, int verbose) {
  APDU apdu;
  unsigned char data[0xff];
  unsigned long recv_len = sizeof(data);
  int sw;

  /* TODO: check that it's a good key before setting. */
  memset(apdu.raw, 0, sizeof(apdu));
  apdu.st.ins = 0xff;
  apdu.st.p1 = 0xff;
  apdu.st.p2 = 0xff;
  apdu.st.lc = KEY_LEN + 3;
  apdu.st.data[0] = 0x03; /* 3-DES */
  apdu.st.data[1] = 0x9b;
  apdu.st.data[2] = KEY_LEN;
  memcpy(apdu.st.data + 3, new_key, KEY_LEN);
  sw = send_data(card, &apdu, KEY_LEN + 8, data, &recv_len, verbose);

  if(sw == 0x9000) {
    return true;
  }
  return false;
}

static bool reset(SCARDHANDLE *card, int verbose) {
  APDU apdu;
  unsigned char data[0xff];
  unsigned long recv_len = sizeof(data);
  int sw;

  memset(apdu.raw, 0, sizeof(apdu));
  /* note: the reset function is only available when both pins are blocked. */
  apdu.st.ins = 0xfb;
  sw = send_data(card, &apdu, 4, data, &recv_len, verbose);

  if(sw == 0x9000) {
    return true;
  }
  return false;
}

static bool set_pin_retries(SCARDHANDLE *card, int pin_retries, int puk_retries, int verbose) {
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
  sw = send_data(card, &apdu, 4, data, &recv_len, verbose);

  if(sw == 0x9000) {
    return true;
  }
  return false;
}

static bool import_key(SCARDHANDLE *card, enum enum_key_format key_format,
    const char *input_file_name, const char *slot, char *password, int verbose) {
  int key = 0;
  FILE *input_file;
  EVP_PKEY *private_key = NULL;
  PKCS12 *p12 = NULL;
  X509 *cert = NULL;
  bool ret = true;

  sscanf(slot, "%x", &key);

  if(!strcmp(input_file_name, "-")) {
    input_file = stdin;
  } else {
    input_file = fopen(input_file_name, "r");
    if(!input_file) {
      fprintf(stderr, "Failed opening '%s'!\n", input_file_name);
      return false;
    }
  }

  if(key_format == key_format_arg_PEM) {
    private_key = PEM_read_PrivateKey(input_file, NULL, NULL, password);
    if(!private_key) {
      fprintf(stderr, "Failed loading private key for import.\n");
      ret = false;
      goto import_out;
    }
  } else if(key_format == key_format_arg_PKCS12) {
    p12 = d2i_PKCS12_fp(input_file, NULL);
    if(!p12) {
      fprintf(stderr, "Failed to load PKCS12 from file.\n");
      ret = false;
      goto import_out;
    }
    if(PKCS12_parse(p12, password, &private_key, &cert, NULL) == 0) {
      fprintf(stderr, "Failed to parse PKCS12 structure. (password: %s)\n", password);
      ret = false;
      goto import_out;
    }
  } else {
    /* TODO: more formats go here */
    fprintf(stderr, "Unknown key format.\n");
    ret = false;
    goto import_out;
  }

  {
    int type = EVP_PKEY_type(private_key->type);
    if(type == EVP_PKEY_RSA) {
      int algorithm;
      RSA *rsa_private_key = EVP_PKEY_get1_RSA(private_key);
      int size = RSA_size(rsa_private_key);
      if(size == 256) {
        algorithm = 7;
      } else if(size == 128) {
        algorithm = 6;
      } else {
        fprintf(stderr, "Unuseable key of %d bits, only 1024 and 2048 is supported.\n", size * 8);
        ret = false;
        goto import_out;
      }
      {
        APDU apdu;
        unsigned char in_data[1024];
        unsigned char *in_ptr = in_data;
        int sw;
        int in_size;

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

        in_size = in_ptr - in_data;
        in_ptr = in_data;

        while(in_ptr < in_data + in_size) {
          unsigned char data[0xff];
          unsigned long recv_len = sizeof(data);
          size_t this_size = 0xff;
          memset(apdu.raw, 0, sizeof(apdu));
          if(in_ptr + 0xff < in_data + in_size) {
            apdu.st.cla = 0x10;
          } else {
            this_size = (size_t)((in_data + in_size) - in_ptr);
          }
          if(verbose) {
            fprintf(stderr, "going to send %zu bytes in this go.\n", this_size);
          }
          apdu.st.ins = 0xfe;
          apdu.st.p1 = algorithm;
          apdu.st.p2 = key;
          apdu.st.lc = this_size;
          memcpy(apdu.st.data, in_ptr, this_size);
          sw = send_data(card, &apdu, this_size + 5, data, &recv_len, verbose);
          if(sw != 0x9000) {
            fprintf(stderr, "Failed import command with code %x.", sw);
            ret = false;
            goto import_out;
          }
          in_ptr += this_size;
        }
      }

    } else {
      /* TODO: ECC */
      fprintf(stderr, "Unknown type: %d\n", type);
      ret = false;
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

static bool import_cert(SCARDHANDLE *card, enum enum_key_format cert_format,
    const char *input_file_name, enum enum_slot slot, char *password, int verbose) {
  int object;
  bool ret = true;
  FILE *input_file;
  X509 *cert = NULL;
  PKCS12 *p12 = NULL;
  EVP_PKEY *private_key = NULL;

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
      fprintf(stderr, "wrong slot argument.\n");
      return false;
  }

  if(!strcmp(input_file_name, "-")) {
    input_file = stdin;
  } else {
    input_file = fopen(input_file_name, "r");
    if(!input_file) {
      fprintf(stderr, "Failed opening '%s'!\n", input_file_name);
      return false;
    }
  }

  if(cert_format == key_format_arg_PEM) {
    cert = PEM_read_X509(input_file, NULL, NULL, password);
    if(!cert) {
      fprintf(stderr, "Failed loading certificate for import.\n");
      goto import_cert_out;
      ret = false;
    }
  } else if(cert_format == key_format_arg_PKCS12) {
    p12 = d2i_PKCS12_fp(input_file, NULL);
    if(!p12) {
      fprintf(stderr, "Failed to load PKCS12 from file.\n");
      goto import_cert_out;
      ret = false;
    }
    if(!PKCS12_parse(p12, password, &private_key, &cert, NULL)) {
      fprintf(stderr, "Failed to parse PKCS12 structure.\n");
      ret = false;
      goto import_cert_out;
    }
  } else {
    /* TODO: more formats go here */
    fprintf(stderr, "Unknown key format.\n");
    ret = false;
    goto import_cert_out;
  }

  {
    unsigned char certdata[2100];
    unsigned char *certptr = certdata;
    int cert_len = i2d_X509(cert, NULL);
    int bytes;
    int cert_size;
    int sw;

    if(cert_len > 2048) {
      fprintf(stderr, "Certificate to large, maximum 4096 bytes (was %d bytes).\n", cert_len);
      ret = false;
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

    cert_size = certptr - certdata;
    certptr = certdata;
    while(certptr < certdata + cert_size) {
      unsigned char data[0xff];
      unsigned long recv_len = sizeof(data);
      size_t this_size = 0xff;
      APDU apdu;

      memset(apdu.raw, 0, sizeof(apdu));
      if(certptr + 0xff < certdata + cert_size) {
        apdu.st.cla = 0x10;
      } else {
        this_size = (size_t)((certdata + cert_size) - certptr);
      }
      if(verbose) {
        fprintf(stderr, "going to send %zu bytes in this go.\n", this_size);
      }
      apdu.st.ins = 0xdb;
      apdu.st.p1 = 0x3f;
      apdu.st.p2 = 0xff;
      apdu.st.lc = this_size;
      memcpy(apdu.st.data, certptr, this_size);
      sw = send_data(card, &apdu, this_size + 5, data, &recv_len, verbose);
      if(sw != 0x9000) {
        fprintf(stderr, "Failed import command with code %x.", sw);
        ret = false;
        goto import_cert_out;
      }
      certptr += this_size;
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

static bool set_chuid(SCARDHANDLE *card, int verbose) {
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
  sw = send_data(card, &apdu, sizeof(chuid_tmpl) + 5, data, &recv_len, verbose);
  if(sw != 0x9000) {
    fprintf(stderr, "Failed setting CHUID.\n");
    return false;
  }
  return true;
}

static int send_data(SCARDHANDLE *card, APDU *apdu, unsigned int send_len,
    unsigned char *data, unsigned long *recv_len, int verbose) {
  long rc;
  int sw;

  if(verbose > 1) {
    fprintf(stderr, "> ");
    dump_hex(apdu->raw, send_len);
    fprintf(stderr, "\n");
  }
  rc = SCardTransmit(*card, SCARD_PCI_T1, apdu->raw, send_len, NULL, data, recv_len);
  if(rc != SCARD_S_SUCCESS) {
    fprintf (stderr, "error: SCardTransmit failed, rc=%08lx\n", rc);
    return 0;
  }

  if(verbose > 1) {
    fprintf(stderr, "< ");
    dump_hex(data, *recv_len);
    fprintf(stderr, "\n");
  }
  if(*recv_len >= 2) {
    sw = (data[*recv_len - 2] << 8) | data[*recv_len - 1];
  } else {
    sw = 0;
  }
  return sw;
}

static void dump_hex(const unsigned char *buf, unsigned int len) {
  unsigned int i;
  for (i = 0; i < len; i++) {
    fprintf(stderr, "%02x ", buf[i]);
  }
}

static bool parse_key(char *key_arg, unsigned char *key, int verbose) {
  int i;
  char key_part[4];
  int key_len = strlen(key_arg);

  if(key_len != KEY_LEN * 2) {
    fprintf(stderr, "Wrong key size, should be %d characters (was %d).\n", KEY_LEN * 2, key_len);
    return false;
  }
  for(i = 0; i < KEY_LEN; i++) {
    key_part[0] = *key_arg++;
    key_part[1] = *key_arg++;
    if(sscanf(key_part, "%hhx", &key[i]) != 1) {
      fprintf(stderr, "Failed parsing key at position %d.\n", i);
      return false;
    }
  }
  if(verbose > 1) {
    fprintf(stderr, "parsed key: ");
    dump_hex(key, KEY_LEN);
    fprintf(stderr, "\n");
  }
  return true;
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

int main(int argc, char *argv[]) {
  struct gengetopt_args_info args_info;
  SCARDHANDLE card;
  SCARDCONTEXT context;
  unsigned char key[KEY_LEN];
  int verbosity;
  enum enum_action action;
  unsigned int i;

  if(cmdline_parser(argc, argv, &args_info) != 0) {
    return EXIT_FAILURE;
  }

  verbosity = args_info.verbose_arg + (int)args_info.verbose_given;

  if(parse_key(args_info.key_arg, key, verbosity) == false) {
    return EXIT_FAILURE;
  }

  if(connect_reader(&card, &context, args_info.reader_arg, verbosity) == false) {
    fprintf(stderr, "Failed to connect to reader.\n");
    return EXIT_FAILURE;
  }

  if(select_applet(&card, verbosity) == false) {
    fprintf(stderr, "Failed to select applet.\n");
    return EXIT_FAILURE;
  }

  if(authenticate(&card, key, verbosity) == false) {
    fprintf(stderr, "Failed authentication with the applet.\n");
    return EXIT_FAILURE;
  }
  if(verbosity) {
    fprintf(stderr, "Successfull applet authentication.\n");
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
        print_version(&card, verbosity);
        break;
      case action_arg_generate:
        if(args_info.slot_arg != slot__NULL) {
          if(generate_key(&card, args_info.slot_orig, args_info.algorithm_arg, args_info.output_arg, args_info.key_format_arg, verbosity) == false) {
            return EXIT_FAILURE;
          }
        } else {
          fprintf(stderr, "The generate action needs a slot (-s) to operate on.\n");
          return EXIT_FAILURE;
        }
        break;
      case action_arg_setMINUS_mgmMINUS_key:
        if(args_info.new_key_arg) {
          unsigned char new_key[KEY_LEN];
          if(parse_key(args_info.new_key_arg, new_key, verbosity) == false) {
            return EXIT_FAILURE;
          }
          if(set_mgm_key(&card, new_key, verbosity) == false) {
            return EXIT_FAILURE;
          }
          printf("Successfully set new management key.\n");
        } else {
          fprintf(stderr, "The set-mgm-key action needs the new-key (-n) argument.\n");
          return EXIT_FAILURE;
        }
        break;
      case action_arg_reset:
        if(reset(&card, verbosity) == false) {
          return EXIT_FAILURE;
        }
        printf("Successfully reset the applet.\n");
        break;
      case action_arg_pinMINUS_retries:
        if(args_info.pin_retries_arg && args_info.puk_retries_arg) {
          if(set_pin_retries(&card, args_info.pin_retries_arg, args_info.puk_retries_arg, verbosity) == false) {
            return EXIT_FAILURE;
          }
          printf("Successfully changed pin retries to %d and puk retries to %d.\n", args_info.pin_retries_arg, args_info.puk_retries_arg);
        } else {
          fprintf(stderr, "The pin-retries action needs both --pin-retries and --puk-retries arguments.\n");
          return EXIT_FAILURE;
        }
        break;
      case action_arg_importMINUS_key:
        if(args_info.slot_arg != slot__NULL) {
          if(import_key(&card, args_info.key_format_arg, args_info.input_arg, args_info.slot_orig, args_info.password_arg, verbosity) == false) {
            return EXIT_FAILURE;
          }
          printf("Successfully imported a new private key.\n");
        } else {
          fprintf(stderr, "The import action needs a slot (-s) to operate on.\n");
          return EXIT_FAILURE;
        }
        break;
      case action_arg_importMINUS_certificate:
        if(args_info.slot_arg != slot__NULL) {
          if(import_cert(&card, args_info.key_format_arg, args_info.input_arg, args_info.slot_arg, args_info.password_arg, verbosity) == false) {
            return EXIT_FAILURE;
          }
          printf("Successfully imported a new certificate.\n");
        } else {
          fprintf(stderr, "The import action needs a slot (-s) to operate on.\n");
          return EXIT_FAILURE;
        }
        break;
      case action_arg_setMINUS_chuid:
        if(set_chuid(&card, verbosity) == false) {
          return EXIT_FAILURE;
        }
        printf("Successfully set new CHUID.\n");
        break;
      case action__NULL:
      default:
        fprintf(stderr, "Wrong action. %d.\n", action);
        return EXIT_FAILURE;
    }
  }

  return EXIT_SUCCESS;
}
