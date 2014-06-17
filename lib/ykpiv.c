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

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>

#include <openssl/des.h>
#include <openssl/rand.h>

#include "internal.h"
#include "ykpiv.h"

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

static void dump_hex(const unsigned char *buf, unsigned int len) {
  unsigned int i;
  for (i = 0; i < len; i++) {
    fprintf(stderr, "%02x ", buf[i]);
  }
}

ykpiv_rc ykpiv_init(ykpiv_state **state, int verbose) {
  ykpiv_state *s = malloc(sizeof(ykpiv_state));
  if(s == NULL) {
    return YKPIV_MEMORY_ERROR;
  }
  memset(s, 0, sizeof(ykpiv_state));
  s->verbose = verbose;
  *state = s;
  return YKPIV_OK;
}

ykpiv_rc ykpiv_done(ykpiv_state *state) {
  free(state);
  return YKPIV_OK;
}

ykpiv_rc ykpiv_connect(ykpiv_state *state, const char *wanted) {
  unsigned long num_readers = 0;
  unsigned long active_protocol;
  char reader_buf[1024];
  long rc;
  char *reader_ptr;

  rc = SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, &state->context);
  if (rc != SCARD_S_SUCCESS) {
    if(state->verbose) {
      fprintf (stderr, "error: SCardEstablishContext failed, rc=%08lx\n", rc);
    }
    return YKPIV_PCSC_ERROR;
  }

  rc = SCardListReaders(state->context, NULL, NULL, &num_readers);
  if (rc != SCARD_S_SUCCESS) {
    if(state->verbose) {
      fprintf (stderr, "error: SCardListReaders failed, rc=%08lx\n", rc);
    }
    SCardReleaseContext(state->context);
    return YKPIV_PCSC_ERROR;
  }

  if (num_readers > sizeof(reader_buf)) {
    num_readers = sizeof(reader_buf);
  }

  rc = SCardListReaders(state->context, NULL, reader_buf, &num_readers);
  if (rc != SCARD_S_SUCCESS)
  {
    if(state->verbose) {
      fprintf (stderr, "error: SCardListReaders failed, rc=%08lx\n", rc);
    }
    SCardReleaseContext(state->context);
    return YKPIV_PCSC_ERROR;
  }

  reader_ptr = reader_buf;
  if(wanted) {
    while(*reader_ptr != '\0') {
      if(strstr(reader_ptr, wanted)) {
	if(state->verbose) {
	  fprintf(stderr, "using reader '%s' matching '%s'.\n", reader_ptr, wanted);
	}
	break;
      } else {
	if(state->verbose) {
	  fprintf(stderr, "skipping reader '%s' since it doesn't match.\n", reader_ptr);
	}
	reader_ptr += strlen(reader_ptr) + 1;
      }
    }
  }
  if(*reader_ptr == '\0') {
    if(state->verbose) {
      fprintf(stderr, "error: no useable reader found.\n");
    }
    SCardReleaseContext(state->context);
    return YKPIV_PCSC_ERROR;
  }

  rc = SCardConnect(state->context, reader_ptr, SCARD_SHARE_SHARED,
      SCARD_PROTOCOL_T1, &state->card, &active_protocol);
  if(rc != SCARD_S_SUCCESS)
  {
    if(state->verbose) {
      fprintf(stderr, "error: SCardConnect failed, rc=%08lx\n", rc);
    }
    SCardReleaseContext(state->context);
    return YKPIV_PCSC_ERROR;
  }

  {
    APDU apdu;
    unsigned char data[0xff];
    unsigned long recv_len = sizeof(data);
    int sw;
    ykpiv_rc res;

    memset(apdu.raw, 0, sizeof(apdu));
    apdu.st.ins = 0xa4;
    apdu.st.p1 = 0x04;
    apdu.st.lc = sizeof(aid);
    memcpy(apdu.st.data, aid, sizeof(aid));

    if((res = ykpiv_send_data(state, apdu.raw, data, &recv_len, &sw) != YKPIV_OK)) {
      return res;
    } else if(sw == 0x9000) {
      return YKPIV_OK;
    }

    return YKPIV_APPLET_ERROR;
  }

  return YKPIV_OK;
}

ykpiv_rc ykpiv_transfer_data(ykpiv_state *state, unsigned char *templ,
    unsigned char *in_data, long in_len,
    unsigned char *out_data, unsigned long *out_len, int *sw) {
  unsigned char *in_ptr = in_data;
  unsigned long max_out = *out_len;
  ykpiv_rc res;
  *out_len = 0;

  while(in_ptr < in_data + in_len) {
    size_t this_size = 0xff;
    unsigned long recv_len = 0xff;
    unsigned char data[0xff];
    APDU apdu;

    memset(apdu.raw, 0, sizeof(apdu.raw));
    memcpy(apdu.raw, templ, 4);
    if(in_ptr + 0xff < in_data + in_len) {
      apdu.st.cla = 0x10;
    } else {
      this_size = (size_t)((in_data + in_len) - in_ptr);
    }
    if(state->verbose > 2) {
      fprintf(stderr, "Going to send %lu bytes in this go.\n", (unsigned long)this_size);
    }
    apdu.st.lc = this_size;
    memcpy(apdu.st.data, in_ptr, this_size);
    res = ykpiv_send_data(state, apdu.raw, data, &recv_len, sw);
    if(res != YKPIV_OK) {
      return res;
    } else if(*sw != 0x9000 && *sw >> 8 != 0x61) {
      return YKPIV_OK;
    }
    if(*out_len + recv_len - 2 > max_out) {
      if(state->verbose) {
	fprintf(stderr, "Output buffer to small, wanted to write %lu, max was %lu.\n", *out_len + recv_len - 2, max_out);
      }
      return YKPIV_SIZE_ERROR;
    }
    memcpy(out_data, data, recv_len - 2);
    out_data += recv_len - 2;
    *out_len += recv_len - 2;
    in_ptr += this_size;
  }
  while(*sw >> 8 == 0x61) {
    APDU apdu;
    unsigned long recv_len = 0xff;
    unsigned char data[0xff];

    if(state->verbose > 2) {
      fprintf(stderr, "The card indicates there is %d bytes more data for us.\n", *sw & 0xff);
    }

    memset(apdu.raw, 0, sizeof(apdu.raw));
    apdu.st.ins = 0xc0;
    res = ykpiv_send_data(state, apdu.raw, data, &recv_len, sw);
    if(res != YKPIV_OK) {
      return res;
    } else if(*sw != 0x9000 && *sw >> 8 != 0x61) {
      return YKPIV_OK;
    }
    if(*out_len + recv_len - 2 > max_out) {
      fprintf(stderr, "Output buffer to small, wanted to write %lu, max was %lu.", *out_len + recv_len - 2, max_out);
    }
    memcpy(out_data, data, recv_len - 2);
    out_data += recv_len - 2;
    *out_len += recv_len - 2;
  }
  return YKPIV_OK;
}

ykpiv_rc ykpiv_send_data(ykpiv_state *state, unsigned char *apdu,
    unsigned char *data, unsigned long *recv_len, int *sw) {
  long rc;
  unsigned int send_len = (unsigned int)(apdu[4] + 5); /* magic numbers.. */

  if(state->verbose > 1) {
    fprintf(stderr, "> ");
    dump_hex(apdu, send_len);
    fprintf(stderr, "\n");
  }
  rc = SCardTransmit(state->card, SCARD_PCI_T1, apdu, send_len, NULL, data, recv_len);
  if(rc != SCARD_S_SUCCESS) {
    if(state->verbose) {
      fprintf (stderr, "error: SCardTransmit failed, rc=%08lx\n", rc);
    }
    return YKPIV_PCSC_ERROR;
  }

  if(state->verbose > 1) {
    fprintf(stderr, "< ");
    dump_hex(data, *recv_len);
    fprintf(stderr, "\n");
  }
  if(*recv_len >= 2) {
    *sw = (data[*recv_len - 2] << 8) | data[*recv_len - 1];
  } else {
    *sw = 0;
  }
  return YKPIV_OK;
}

ykpiv_rc ykpiv_authenticate(ykpiv_state *state, unsigned const char *key) {
  APDU apdu;
  unsigned char data[0xff];
  DES_cblock challenge;
  unsigned long recv_len = sizeof(data);
  int sw;
  ykpiv_rc res;

  DES_key_schedule ks1, ks2, ks3;

  /* set up our key */
  {
    const_DES_cblock key_tmp;
    memcpy(key_tmp, key, 8);
    DES_set_key_unchecked(&key_tmp, &ks1);
    memcpy(key_tmp, key + 8, 8);
    DES_set_key_unchecked(&key_tmp, &ks2);
    memcpy(key_tmp, key + 16, 8);
    DES_set_key_unchecked(&key_tmp, &ks3);
  }

  /* get a challenge from the card */
  {
    memset(apdu.raw, 0, sizeof(apdu));
    apdu.st.ins = 0x87;
    apdu.st.p1 = 0x03; /* triple des */
    apdu.st.p2 = 0x9b; /* management key */
    apdu.st.lc = 0x04;
    apdu.st.data[0] = 0x7c;
    apdu.st.data[1] = 0x02;
    apdu.st.data[2] = 0x80;
    if((res = ykpiv_send_data(state, apdu.raw, data, &recv_len, &sw)) != YKPIV_OK) {
      return res;
    } else if(sw != 0x9000) {
      return YKPIV_AUTHENTICATION_ERROR;
    }
    memcpy(challenge, data + 4, 8);
  }

  /* send a response to the cards challenge and a challenge of our own. */
  {
    unsigned char *dataptr = apdu.st.data;
    DES_cblock response;
    DES_ecb3_encrypt(&challenge, &response, &ks1, &ks2, &ks3, 0);

    recv_len = 0xff;
    memset(apdu.raw, 0, sizeof(apdu));
    apdu.st.ins = 0x87;
    apdu.st.p1 = 0x03; /* triple des */
    apdu.st.p2 = 0x9b; /* management key */
    *dataptr++ = 0x7c;
    *dataptr++ = 20; /* 2 + 8 + 2 +8 */
    *dataptr++ = 0x80;
    *dataptr++ = 8;
    memcpy(dataptr, response, 8);
    dataptr += 8;
    *dataptr++ = 0x81;
    *dataptr++ = 8;
    if(RAND_pseudo_bytes(dataptr, 8) == -1) {
      if(state->verbose) {
	fprintf(stderr, "Failed getting randomness for authentication.\n");
      }
      return YKPIV_RANDOMNESS_ERROR;
    }
    memcpy(challenge, dataptr, 8);
    dataptr += 8;
    apdu.st.lc = dataptr - apdu.st.data;
    if((res = ykpiv_send_data(state, apdu.raw, data, &recv_len, &sw)) != YKPIV_OK) {
      return res;
    } else if(sw != 0x9000) {
      return YKPIV_AUTHENTICATION_ERROR;
    }
  }

  /* compare the response from the card with our challenge */
  {
    DES_cblock response;
    DES_ecb3_encrypt(&challenge, &response, &ks1, &ks2, &ks3, 1);
    if(memcmp(response, data + 4, 8) == 0) {
      return YKPIV_OK;
    } else {
      return YKPIV_AUTHENTICATION_ERROR;
    }
  }
}
