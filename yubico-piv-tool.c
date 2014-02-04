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

#ifdef __APPLE__
#include <PCSC/wintypes.h>
#else
#include <winscard.h>
#endif

#include "cmdline.h"

unsigned const char aid[] = {
  0xa0, 0x00, 0x00, 0x03, 0x08
};
#define AID_LEN 5

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

void dump_hex(unsigned const char*, unsigned int);
int send_data(SCARDHANDLE*, APDU, unsigned int, unsigned char*, unsigned long*, int);

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
  apdu.st.lc = AID_LEN;
  memcpy(apdu.st.data, aid, AID_LEN);

  sw = send_data(card, apdu, AID_LEN + 5, data, &recv_len, verbose);
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
    sw = send_data(card, apdu, 9, data, &recv_len, verbose);
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
    sw = send_data(card, apdu, 17, data, &recv_len, verbose);
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
  sw = send_data(card, apdu, 4, data, &recv_len, verbose);
  if(sw == 0x9000) {
    printf("Applet version %d.%d.%d found.\n", data[0], data[1], data[2]);
  } else {
    printf("Applet version not found. Status code: %x\n", sw);
  }
}

static bool generate_key(SCARDHANDLE *card, const char *slot, enum enum_algorithm algorithm, int verbose) {
  APDU apdu;
  unsigned char data[1024];
  unsigned long recv_len = 0xff;
  unsigned long received = 0;
  int sw;
  int key = 0;

  sscanf(slot, "%x", &key);

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
  }
  sw = send_data(card, apdu, 10, data, &recv_len, verbose);

  /* chained response */
  if((sw & 0x6100) == 0x6100) {
    received += recv_len - 2;
    recv_len = 0xff;
    memset(apdu.raw, 0, sizeof(apdu));
    apdu.st.ins = 0xc0;
    sw = send_data(card, apdu, 4, data + received, &recv_len, verbose);
    received += recv_len;
  }

  dump_hex(data, received);

  return true;
}

static bool set_mgm_key(SCARDHANDLE *card, unsigned const char *new_key, int verbose) {
  APDU apdu;
  unsigned char data[0xff];
  unsigned long recv_len = sizeof(data);
  int sw;

  memset(apdu.raw, 0, sizeof(apdu));
  apdu.st.ins = 0xff;
  apdu.st.p1 = 0xff;
  apdu.st.p2 = 0xff;
  apdu.st.lc = KEY_LEN + 3;
  apdu.st.data[0] = 0x03; // 3-DES
  apdu.st.data[1] = 0x9b;
  apdu.st.data[2] = KEY_LEN;
  memcpy(apdu.st.data + 3, new_key, KEY_LEN);
  sw = send_data(card, apdu, KEY_LEN + 8, data, &recv_len, verbose);

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
  sw = send_data(card, apdu, 4, data, &recv_len, verbose);

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
  sw = send_data(card, apdu, 4, data, &recv_len, verbose);

  if(sw == 0x9000) {
    return true;
  }
  return false;
}

int send_data(SCARDHANDLE *card, APDU apdu, unsigned int send_len, unsigned char *data, unsigned long *recv_len, int verbose) {
  long rc;
  int sw;

  if(verbose > 1) {
    fprintf(stderr, "> ");
    dump_hex(apdu.raw, send_len);
    fprintf(stderr, "\n");
  }
  rc = SCardTransmit(*card, SCARD_PCI_T1, apdu.raw, send_len, NULL, data, recv_len);
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

void dump_hex(const unsigned char *buf, unsigned int len) {
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
  if(verbose) {
    fprintf(stderr, "parsed key: ");
    dump_hex(key, KEY_LEN);
    fprintf(stderr, "\n");
  }
  return true;
}

int main(int argc, char *argv[]) {
  struct gengetopt_args_info args_info;
  SCARDHANDLE card;
  SCARDCONTEXT context;
  unsigned char key[KEY_LEN];
  int verbosity;

  if(cmdline_parser(argc, argv, &args_info) != 0) {
    return EXIT_FAILURE;
  }

  verbosity = args_info.verbose_arg + (int)args_info.verbose_given;

  if(parse_key(args_info.key_arg, key, verbosity) == false) {
    return EXIT_FAILURE;
  }

  if(connect_reader(&card, &context, args_info.reader_arg, verbosity) == false) {
    return EXIT_FAILURE;
  }

  if(select_applet(&card, verbosity) == false) {
    return EXIT_FAILURE;
  }

  if(authenticate(&card, key, verbosity) == false) {
    return EXIT_FAILURE;
  }

  if(args_info.action_arg == action_arg_version) {
    print_version(&card, verbosity);
  } else if(args_info.action_arg == action_arg_generate) {
    if(args_info.slot_arg != slot__NULL) {
      generate_key(&card, args_info.slot_orig, args_info.algorithm_arg, verbosity);
    } else {
      fprintf(stderr, "The generate action needs a slot (-s) to operate on.\n");
      return EXIT_FAILURE;
    }
  } else if(args_info.action_arg == action_arg_setMINUS_mgmMINUS_key) {
    if(args_info.new_key_arg) {
      unsigned char new_key[KEY_LEN];
      if(parse_key(args_info.new_key_arg, new_key, verbosity) == false) {
        return EXIT_FAILURE;
      }
      if(set_mgm_key(&card, new_key, verbosity) == false) {
        return EXIT_FAILURE;
      }
    } else {
      fprintf(stderr, "The set-mgm-key action needs the new-key (-n) argument.\n");
      return EXIT_FAILURE;
    }
  } else if(args_info.action_arg == action_arg_reset) {
    if(reset(&card, verbosity) == false) {
      return EXIT_FAILURE;
    }
  } else if(args_info.action_arg == action_arg_pinMINUS_retries) {
    if(args_info.pin_retries_arg && args_info.puk_retries_arg) {
      if(set_pin_retries(&card, args_info.pin_retries_arg, args_info.puk_retries_arg, verbosity) == false) {
        return EXIT_FAILURE;
      }
    } else {
      return EXIT_FAILURE;
    }
  }

  return EXIT_SUCCESS;
}
