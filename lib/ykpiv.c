 /*
 * Copyright (c) 2014-2016 Yubico AB
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

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <ctype.h>

#include <openssl/des.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>

#include "internal.h"
#include "ykpiv.h"

static ykpiv_rc send_data(ykpiv_state *state, APDU *apdu,
    unsigned char *data, unsigned long *recv_len, int *sw);

static void dump_hex(const unsigned char *buf, unsigned int len) {
  unsigned int i;
  for (i = 0; i < len; i++) {
    fprintf(stderr, "%02x ", buf[i]);
  }
}

static int set_length(unsigned char *buffer, size_t length) {
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

static int get_length(const unsigned char *buffer, size_t *len) {
  if(buffer[0] < 0x81) {
    *len = buffer[0];
    return 1;
  } else if((*buffer & 0x7f) == 1) {
    *len = buffer[1];
    return 2;
  } else if((*buffer & 0x7f) == 2) {
    size_t tmp = buffer[1];
    *len = (tmp << 8) + buffer[2];
    return 3;
  }
  return 0;
}

static unsigned char *set_object(int object_id, unsigned char *buffer) {
  *buffer++ = 0x5c;
  if(object_id == YKPIV_OBJ_DISCOVERY) {
    *buffer++ = 1;
    *buffer++ = YKPIV_OBJ_DISCOVERY;
  } else if(object_id > 0xffff && object_id <= 0xffffff) {
    *buffer++ = 3;
    *buffer++ = (object_id >> 16) & 0xff;
    *buffer++ = (object_id >> 8) & 0xff;
    *buffer++ = object_id & 0xff;
  }
  return buffer;
}

ykpiv_rc ykpiv_init(ykpiv_state **state, int verbose) {
  ykpiv_state *s = malloc(sizeof(ykpiv_state));
  if(s == NULL) {
    return YKPIV_MEMORY_ERROR;
  }
  memset(s, 0, sizeof(ykpiv_state));
  s->verbose = verbose;
  s->context = SCARD_E_INVALID_HANDLE;
  *state = s;
  return YKPIV_OK;
}

ykpiv_rc ykpiv_done(ykpiv_state *state) {
  ykpiv_disconnect(state);
  free(state);
  return YKPIV_OK;
}

ykpiv_rc ykpiv_disconnect(ykpiv_state *state) {
  if(state->card) {
    SCardDisconnect(state->card, SCARD_RESET_CARD);
    state->card = 0;
  }

  if(SCardIsValidContext(state->context) == SCARD_S_SUCCESS) {
    SCardReleaseContext(state->context);
    state->context = SCARD_E_INVALID_HANDLE;
  }

  return YKPIV_OK;
}

ykpiv_rc ykpiv_connect(ykpiv_state *state, const char *wanted) {
  unsigned long active_protocol;
  char reader_buf[2048];
  size_t num_readers = sizeof(reader_buf);
  long rc;
  char *reader_ptr;

  ykpiv_rc ret = ykpiv_list_readers(state, reader_buf, &num_readers);
  if(ret != YKPIV_OK) {
    return ret;
  }

  for(reader_ptr = reader_buf; *reader_ptr != '\0'; reader_ptr += strlen(reader_ptr) + 1) {
    if(wanted) {
      if(!strstr(reader_ptr, wanted)) {
        if(state->verbose) {
          fprintf(stderr, "skipping reader '%s' since it doesn't match '%s'.\n", reader_ptr, wanted);
        }
        continue;
      }
    }
    if(state->verbose) {
      fprintf(stderr, "trying to connect to reader '%s'.\n", reader_ptr);
    }
    rc = SCardConnect(state->context, reader_ptr, SCARD_SHARE_SHARED,
        SCARD_PROTOCOL_T1, &state->card, &active_protocol);
    if(rc != SCARD_S_SUCCESS)
    {
      if(state->verbose) {
        fprintf(stderr, "SCardConnect failed, rc=%08lx\n", rc);
      }
      continue;
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

      if((res = send_data(state, &apdu, data, &recv_len, &sw)) != YKPIV_OK) {
        if(state->verbose) {
          fprintf(stderr, "Failed communicating with card: '%s'\n", ykpiv_strerror(res));
        }
        continue;
      } else if(sw == SW_SUCCESS) {
        return YKPIV_OK;
      } else {
        if(state->verbose) {
          fprintf(stderr, "Failed selecting application: %04x\n", sw);
        }
      }
    }
  }

  if(*reader_ptr == '\0') {
    if(state->verbose) {
      fprintf(stderr, "error: no usable reader found.\n");
    }
    SCardReleaseContext(state->context);
    state->context = SCARD_E_INVALID_HANDLE;
    return YKPIV_PCSC_ERROR;
  }

  return YKPIV_GENERIC_ERROR;
}

ykpiv_rc ykpiv_list_readers(ykpiv_state *state, char *readers, size_t *len) {
  unsigned long num_readers = 0;
  long rc;

  if(SCardIsValidContext(state->context) != SCARD_S_SUCCESS) {
    rc = SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, &state->context);
    if (rc != SCARD_S_SUCCESS) {
      if(state->verbose) {
        fprintf (stderr, "error: SCardEstablishContext failed, rc=%08lx\n", rc);
      }
      return YKPIV_PCSC_ERROR;
    }
  }

  rc = SCardListReaders(state->context, NULL, NULL, &num_readers);
  if (rc != SCARD_S_SUCCESS) {
    if(state->verbose) {
      fprintf (stderr, "error: SCardListReaders failed, rc=%08lx\n", rc);
    }
    SCardReleaseContext(state->context);
    state->context = SCARD_E_INVALID_HANDLE;
    return YKPIV_PCSC_ERROR;
  }

  if (num_readers > *len) {
    num_readers = *len;
  }

  rc = SCardListReaders(state->context, NULL, readers, &num_readers);
  if (rc != SCARD_S_SUCCESS)
  {
    if(state->verbose) {
      fprintf (stderr, "error: SCardListReaders failed, rc=%08lx\n", rc);
    }
    SCardReleaseContext(state->context);
    state->context = SCARD_E_INVALID_HANDLE;
    return YKPIV_PCSC_ERROR;
  }

  *len = num_readers;

  return YKPIV_OK;
}

ykpiv_rc ykpiv_transfer_data(ykpiv_state *state, const unsigned char *templ,
    const unsigned char *in_data, long in_len,
    unsigned char *out_data, unsigned long *out_len, int *sw) {
  const unsigned char *in_ptr = in_data;
  unsigned long max_out = *out_len;
  ykpiv_rc res;
  long rc;
  *out_len = 0;

  rc = SCardBeginTransaction(state->card);
  if(rc != SCARD_S_SUCCESS) {
    if(state->verbose) {
      fprintf(stderr, "error: Failed to begin pcsc transaction, rc=%08lx\n", rc);
    }
    return YKPIV_PCSC_ERROR;
  }
  do {
    size_t this_size = 0xff;
    unsigned char data[261];
    unsigned long recv_len = sizeof(data);
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
    res = send_data(state, &apdu, data, &recv_len, sw);
    if(res != YKPIV_OK) {
      return res;
    } else if(*sw != SW_SUCCESS && *sw >> 8 != 0x61) {
      return YKPIV_OK;
    }
    if(*out_len + recv_len - 2 > max_out) {
      if(state->verbose) {
  fprintf(stderr, "Output buffer to small, wanted to write %lu, max was %lu.\n", *out_len + recv_len - 2, max_out);
      }
      return YKPIV_SIZE_ERROR;
    }
    if(out_data) {
      memcpy(out_data, data, recv_len - 2);
      out_data += recv_len - 2;
      *out_len += recv_len - 2;
    }
    in_ptr += this_size;
  } while(in_ptr < in_data + in_len);
  while(*sw >> 8 == 0x61) {
    APDU apdu;
    unsigned char data[261];
    unsigned long recv_len = sizeof(data);

    if(state->verbose > 2) {
      fprintf(stderr, "The card indicates there is %d bytes more data for us.\n", *sw & 0xff);
    }

    memset(apdu.raw, 0, sizeof(apdu.raw));
    apdu.st.ins = 0xc0;
    res = send_data(state, &apdu, data, &recv_len, sw);
    if(res != YKPIV_OK) {
      return res;
    } else if(*sw != SW_SUCCESS && *sw >> 8 != 0x61) {
      return YKPIV_OK;
    }
    if(*out_len + recv_len - 2 > max_out) {
      fprintf(stderr, "Output buffer to small, wanted to write %lu, max was %lu.", *out_len + recv_len - 2, max_out);
    }
    if(out_data) {
      memcpy(out_data, data, recv_len - 2);
      out_data += recv_len - 2;
      *out_len += recv_len - 2;
    }
  }
  rc = SCardEndTransaction(state->card, SCARD_LEAVE_CARD);
  if(rc != SCARD_S_SUCCESS) {
    if(state->verbose) {
      fprintf(stderr, "error: Failed to end pcsc transaction, rc=%08lx\n", rc);
    }
    return YKPIV_PCSC_ERROR;
  }
  return YKPIV_OK;
}

static ykpiv_rc send_data(ykpiv_state *state, APDU *apdu,
    unsigned char *data, unsigned long *recv_len, int *sw) {
  long rc;
  unsigned int send_len = (unsigned int)apdu->st.lc + 5;

  if(state->verbose > 1) {
    fprintf(stderr, "> ");
    dump_hex(apdu->raw, send_len);
    fprintf(stderr, "\n");
  }
  rc = SCardTransmit(state->card, SCARD_PCI_T1, apdu->raw, send_len, NULL, data, recv_len);
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
  unsigned char data[261];
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
    apdu.st.ins = YKPIV_INS_AUTHENTICATE;
    apdu.st.p1 = YKPIV_ALGO_3DES; /* triple des */
    apdu.st.p2 = YKPIV_KEY_CARDMGM; /* management key */
    apdu.st.lc = 0x04;
    apdu.st.data[0] = 0x7c;
    apdu.st.data[1] = 0x02;
    apdu.st.data[2] = 0x80;
    if((res = send_data(state, &apdu, data, &recv_len, &sw)) != YKPIV_OK) {
      return res;
    } else if(sw != SW_SUCCESS) {
      return YKPIV_AUTHENTICATION_ERROR;
    }
    memcpy(challenge, data + 4, 8);
  }

  /* send a response to the cards challenge and a challenge of our own. */
  {
    unsigned char *dataptr = apdu.st.data;
    DES_cblock response;
    DES_ecb3_encrypt(&challenge, &response, &ks1, &ks2, &ks3, 0);

    recv_len = sizeof(data);
    memset(apdu.raw, 0, sizeof(apdu));
    apdu.st.ins = YKPIV_INS_AUTHENTICATE;
    apdu.st.p1 = YKPIV_ALGO_3DES; /* triple des */
    apdu.st.p2 = YKPIV_KEY_CARDMGM; /* management key */
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
    if((res = send_data(state, &apdu, data, &recv_len, &sw)) != YKPIV_OK) {
      return res;
    } else if(sw != SW_SUCCESS) {
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

ykpiv_rc ykpiv_set_mgmkey(ykpiv_state *state, const unsigned char *new_key) {
  return ykpiv_set_mgmkey2(state, new_key, 0);
}

ykpiv_rc ykpiv_set_mgmkey2(ykpiv_state *state, const unsigned char *new_key, const unsigned char touch) {
  APDU apdu;
  unsigned char data[261];
  unsigned long recv_len = sizeof(data);
  int sw;
  size_t i;
  ykpiv_rc res;

  for(i = 0; i < 3; i++) {
    const_DES_cblock key_tmp;
    memcpy(key_tmp, new_key + i * 8, 8);
    DES_set_odd_parity(&key_tmp);
    if(DES_is_weak_key(&key_tmp) != 0) {
      if(state->verbose) {
  fprintf(stderr, "Won't set new key '");
  dump_hex(new_key + i * 8, 8);
  fprintf(stderr, "' since it's weak (with parity the key is: ");
  dump_hex(key_tmp, 8);
  fprintf(stderr, ").\n");
      }
      return YKPIV_GENERIC_ERROR;
    }
  }

  memset(apdu.raw, 0, sizeof(apdu));
  apdu.st.ins = YKPIV_INS_SET_MGMKEY;
  apdu.st.p1 = 0xff;
  if(touch == 0) {
    apdu.st.p2 = 0xff;
  } else if(touch == 1) {
    apdu.st.p2 = 0xfe;
  } else {
    return YKPIV_GENERIC_ERROR;
  }
  apdu.st.lc = DES_KEY_SZ * 3 + 3;
  apdu.st.data[0] = YKPIV_ALGO_3DES;
  apdu.st.data[1] = YKPIV_KEY_CARDMGM;
  apdu.st.data[2] = DES_KEY_SZ * 3;
  memcpy(apdu.st.data + 3, new_key, DES_KEY_SZ * 3);
  if((res = send_data(state, &apdu, data, &recv_len, &sw)) != YKPIV_OK) {
    return res;
  } else if(sw == SW_SUCCESS) {
    return YKPIV_OK;
  }
  return YKPIV_GENERIC_ERROR;
}

static char hex_translate[] = "0123456789abcdef";

ykpiv_rc ykpiv_hex_decode(const char *hex_in, size_t in_len,
    unsigned char *hex_out, size_t *out_len) {

  size_t i;
  bool first = true;
  if(*out_len < in_len / 2) {
    return YKPIV_SIZE_ERROR;
  } else if(in_len % 2 != 0) {
    return YKPIV_SIZE_ERROR;
  }
  *out_len = in_len / 2;
  for(i = 0; i < in_len; i++) {
    char *ind_ptr = strchr(hex_translate, tolower(*hex_in++));
    int index = 0;
    if(ind_ptr) {
      index = ind_ptr - hex_translate;
    } else {
      return YKPIV_PARSE_ERROR;
    }
    if(first) {
      *hex_out = index << 4;
    } else {
      *hex_out++ |= index;
    }
    first = !first;
  }
  return YKPIV_OK;
}

static ykpiv_rc _general_authenticate(ykpiv_state *state,
    const unsigned char *sign_in, size_t in_len,
    unsigned char *out, size_t *out_len,
    unsigned char algorithm, unsigned char key, bool decipher) {
  unsigned char indata[1024];
  unsigned char *dataptr = indata;
  unsigned char data[1024];
  unsigned char templ[] = {0, YKPIV_INS_AUTHENTICATE, algorithm, key};
  unsigned long recv_len = sizeof(data);
  size_t key_len = 0;
  int sw;
  size_t bytes;
  size_t len = 0;
  ykpiv_rc res;

  switch(algorithm) {
    case YKPIV_ALGO_RSA1024:
      key_len = 128;
    case YKPIV_ALGO_RSA2048:
      if(key_len == 0) {
	key_len = 256;
      }
      if(in_len != key_len) {
	return YKPIV_SIZE_ERROR;
      }
      break;
    case YKPIV_ALGO_ECCP256:
      key_len = 32;
    case YKPIV_ALGO_ECCP384:
      if(key_len == 0) {
	key_len = 48;
      }
      if(!decipher && in_len > key_len) {
	return YKPIV_SIZE_ERROR;
      } else if(decipher && in_len != (key_len * 2) + 1) {
	return YKPIV_SIZE_ERROR;
      }
      break;
    default:
      return YKPIV_ALGORITHM_ERROR;
  }

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
  *dataptr++ = YKPIV_IS_EC(algorithm) && decipher ? 0x85 : 0x81;
  dataptr += set_length(dataptr, in_len);
  memcpy(dataptr, sign_in, (size_t)in_len);
  dataptr += in_len;

  if((res = ykpiv_transfer_data(state, templ, indata, dataptr - indata, data,
        &recv_len, &sw)) != YKPIV_OK) {
    if(state->verbose) {
      fprintf(stderr, "Sign command failed to communicate.\n");
    }
    return res;
  } else if(sw != SW_SUCCESS) {
    if(state->verbose) {
      fprintf(stderr, "Failed sign command with code %x.\n", sw);
    }
    if (sw == SW_ERR_SECURITY_STATUS)
      return YKPIV_AUTHENTICATION_ERROR;
    else
      return YKPIV_GENERIC_ERROR;
  }
  /* skip the first 7c tag */
  if(data[0] != 0x7c) {
    if(state->verbose) {
      fprintf(stderr, "Failed parsing signature reply.\n");
    }
    return YKPIV_PARSE_ERROR;
  }
  dataptr = data + 1;
  dataptr += get_length(dataptr, &len);
  /* skip the 82 tag */
  if(*dataptr != 0x82) {
    if(state->verbose) {
      fprintf(stderr, "Failed parsing signature reply.\n");
    }
    return YKPIV_PARSE_ERROR;
  }
  dataptr++;
  dataptr += get_length(dataptr, &len);
  if(len > *out_len) {
    if(state->verbose) {
      fprintf(stderr, "Wrong size on output buffer.\n");
    }
    return YKPIV_SIZE_ERROR;
  }
  *out_len = len;
  memcpy(out, dataptr, len);
  return YKPIV_OK;
}

ykpiv_rc ykpiv_sign_data(ykpiv_state *state,
    const unsigned char *raw_in, size_t in_len,
    unsigned char *sign_out, size_t *out_len,
    unsigned char algorithm, unsigned char key) {

  return _general_authenticate(state, raw_in, in_len, sign_out, out_len,
                               algorithm, key, false);
}

ykpiv_rc ykpiv_decipher_data(ykpiv_state *state, const unsigned char *in,
    size_t in_len, unsigned char *out, size_t *out_len,
    unsigned char algorithm, unsigned char key) {
  return _general_authenticate(state, in, in_len, out, out_len,
                               algorithm, key, true);
}

ykpiv_rc ykpiv_get_version(ykpiv_state *state, char *version, size_t len) {
  APDU apdu;
  unsigned char data[261];
  unsigned long recv_len = sizeof(data);
  int sw;
  ykpiv_rc res;

  memset(apdu.raw, 0, sizeof(apdu));
  apdu.st.ins = YKPIV_INS_GET_VERSION;
  if((res = send_data(state, &apdu, data, &recv_len, &sw)) != YKPIV_OK) {
    return res;
  } else if(sw == SW_SUCCESS) {
    int result = snprintf(version, len, "%d.%d.%d", data[0], data[1], data[2]);
    if(result < 0) {
      return YKPIV_SIZE_ERROR;
    }
    return YKPIV_OK;
  } else {
    return YKPIV_GENERIC_ERROR;
  }
}

ykpiv_rc ykpiv_verify(ykpiv_state *state, const char *pin, int *tries) {
  APDU apdu;
  unsigned char data[261];
  unsigned long recv_len = sizeof(data);
  int sw;
  size_t len = 0;
  ykpiv_rc res;
  if(pin) {
    len = strlen(pin);
  }

  if(len > 8) {
    return YKPIV_SIZE_ERROR;
  }

  memset(apdu.raw, 0, sizeof(apdu.raw));
  apdu.st.ins = YKPIV_INS_VERIFY;
  apdu.st.p1 = 0x00;
  apdu.st.p2 = 0x80;
  apdu.st.lc = pin ? 0x08 : 0;
  if(pin) {
    memcpy(apdu.st.data, pin, len);
    if(len < 8) {
      memset(apdu.st.data + len, 0xff, 8 - len);
    }
  }
  if((res = send_data(state, &apdu, data, &recv_len, &sw)) != YKPIV_OK) {
    return res;
  } else if(sw == SW_SUCCESS) {
    return YKPIV_OK;
  } else if((sw >> 8) == 0x63) {
    *tries = (sw & 0xf);
    return YKPIV_WRONG_PIN;
  } else if(sw == SW_ERR_AUTH_BLOCKED) {
    *tries = 0;
    return YKPIV_WRONG_PIN;
  } else {
    return YKPIV_GENERIC_ERROR;
  }
}

#define CHREF_ACT_CHANGE_PIN 0
#define CHREF_ACT_UNBLOCK_PIN 1
#define CHREF_ACT_CHANGE_PUK 2

static ykpiv_rc _change_pin_internal(ykpiv_state *state, int action, const char * current_pin, size_t current_pin_len, const char * new_pin, size_t new_pin_len, int *tries) {
  int sw;
  unsigned char templ[] = {0, YKPIV_INS_CHANGE_REFERENCE, 0, 0x80};
  unsigned char indata[0x10];
  unsigned char data[0xff];
  unsigned long recv_len = sizeof(data);
  ykpiv_rc res;
  if (current_pin_len > 8) {
    return YKPIV_SIZE_ERROR;
  }
  if (new_pin_len > 8) {
    return YKPIV_SIZE_ERROR;
  }
  if(action == CHREF_ACT_UNBLOCK_PIN) {
    templ[1] = YKPIV_INS_RESET_RETRY;
  }
  else if(action == CHREF_ACT_CHANGE_PUK) {
    templ[3] = 0x81;
  }
  memcpy(indata, current_pin, current_pin_len);
  if(current_pin_len < 8) {
    memset(indata + current_pin_len, 0xff, 8 - current_pin_len);
  }
  memcpy(indata + 8, new_pin, new_pin_len);
  if(new_pin_len < 8) {
    memset(indata + 8 + new_pin_len, 0xff, 8 - new_pin_len);
  }
  res = ykpiv_transfer_data(state, templ, indata, sizeof(indata), data, &recv_len, &sw);
  if(res != YKPIV_OK) {
    return res;
  } else if(sw != SW_SUCCESS) {
    if((sw >> 8) == 0x63) {
      *tries = sw & 0xf;
      return YKPIV_WRONG_PIN;
    } else if(sw == SW_ERR_AUTH_BLOCKED) {
      return YKPIV_PIN_LOCKED;
    } else {
      if(state->verbose) {
        fprintf(stderr, "Failed changing pin, token response code: %x.\n", sw);
      }
      return YKPIV_GENERIC_ERROR;
    }
  }
  return YKPIV_OK;
}

ykpiv_rc ykpiv_change_pin(ykpiv_state *state, const char * current_pin, size_t current_pin_len, const char * new_pin, size_t new_pin_len, int *tries) {
  return _change_pin_internal(state, CHREF_ACT_CHANGE_PIN, current_pin, current_pin_len, new_pin, new_pin_len, tries);
}

ykpiv_rc ykpiv_change_puk(ykpiv_state *state, const char * current_puk, size_t current_puk_len, const char * new_puk, size_t new_puk_len, int *tries) {
  return _change_pin_internal(state, CHREF_ACT_CHANGE_PUK, current_puk, current_puk_len, new_puk, new_puk_len, tries);
}

ykpiv_rc ykpiv_unblock_pin(ykpiv_state *state, const char * puk, size_t puk_len, const char * new_pin, size_t new_pin_len, int *tries) {
  return _change_pin_internal(state, CHREF_ACT_UNBLOCK_PIN, puk, puk_len, new_pin, new_pin_len, tries);
}

ykpiv_rc ykpiv_fetch_object(ykpiv_state *state, int object_id,
    unsigned char *data, unsigned long *len) {
  int sw;
  unsigned char indata[5];
  unsigned char *inptr = indata;
  unsigned char templ[] = {0, YKPIV_INS_GET_DATA, 0x3f, 0xff};
  ykpiv_rc res;

  inptr = set_object(object_id, inptr);
  if(inptr == NULL) {
    return YKPIV_INVALID_OBJECT;
  }

  if((res = ykpiv_transfer_data(state, templ, indata, inptr - indata, data, len, &sw))
      != YKPIV_OK) {
    return res;
  }

  if(sw == SW_SUCCESS) {
    size_t outlen;
    int offs = get_length(data + 1, &outlen);
    if(offs == 0) {
      return YKPIV_SIZE_ERROR;
    }
    memmove(data, data + 1 + offs, outlen);
    *len = outlen;
    return YKPIV_OK;
  } else {
    return YKPIV_GENERIC_ERROR;
  }
}

ykpiv_rc ykpiv_save_object(ykpiv_state *state, int object_id,
    unsigned char *indata, size_t len) {

  unsigned char data[3072];
  unsigned char *dataptr = data;
  unsigned char templ[] = {0, YKPIV_INS_PUT_DATA, 0x3f, 0xff};
  int sw;
  ykpiv_rc res;
  unsigned long outlen = 0;

  if(len > sizeof(data) - 9) {
    return YKPIV_SIZE_ERROR;
  }
  dataptr = set_object(object_id, dataptr);
  if(dataptr == NULL) {
    return YKPIV_INVALID_OBJECT;
  }
  *dataptr++ = 0x53;
  dataptr += set_length(dataptr, len);
  memcpy(dataptr, indata, len);
  dataptr += len;

  if((res = ykpiv_transfer_data(state, templ, data, dataptr - data, NULL, &outlen,
    &sw)) != YKPIV_OK) {
    return res;
  }

  if(sw == SW_SUCCESS) {
    return YKPIV_OK;
  } else {
    return YKPIV_GENERIC_ERROR;
  }
}

ykpiv_rc ykpiv_import_private_key(ykpiv_state *state, const unsigned char key, unsigned char algorithm,
                                  const unsigned char *p, size_t p_len,
                                  const unsigned char *q, size_t q_len,
                                  const unsigned char *dp, size_t dp_len,
                                  const unsigned char *dq, size_t dq_len,
                                  const unsigned char *qinv, size_t qinv_len,
                                  const unsigned char *ec_data, unsigned char ec_data_len,
                                  const unsigned char pin_policy, const unsigned char touch_policy) {

  unsigned char key_data[1024];
  unsigned char *in_ptr = key_data;
  unsigned char templ[] = {0, YKPIV_INS_IMPORT_KEY, algorithm, key};
  unsigned char data[256];
  unsigned long recv_len = sizeof(data);
  unsigned elem_len;
  int sw;
  const unsigned char *params[5];
  size_t lens[5];
  size_t padding;
  unsigned char n_params;
  int i;
  int param_tag;

  if (state == NULL)
    return YKPIV_GENERIC_ERROR;

  if (key == YKPIV_KEY_CARDMGM ||
      key < YKPIV_KEY_RETIRED1 ||
      (key > YKPIV_KEY_RETIRED20 && key < YKPIV_KEY_AUTHENTICATION) ||
      (key > YKPIV_KEY_CARDAUTH && key != YKPIV_KEY_ATTESTATION)) {
    return YKPIV_KEY_ERROR;
  }

  if (pin_policy != YKPIV_PINPOLICY_DEFAULT &&
      pin_policy != YKPIV_PINPOLICY_NEVER &&
      pin_policy != YKPIV_PINPOLICY_ONCE &&
      pin_policy != YKPIV_PINPOLICY_ALWAYS)
    return YKPIV_GENERIC_ERROR;

  if (touch_policy != YKPIV_TOUCHPOLICY_DEFAULT &&
      touch_policy != YKPIV_TOUCHPOLICY_NEVER &&
      touch_policy != YKPIV_TOUCHPOLICY_ALWAYS &&
      touch_policy != YKPIV_TOUCHPOLICY_CACHED)
    return YKPIV_GENERIC_ERROR;

  if (algorithm == YKPIV_ALGO_RSA1024 || algorithm == YKPIV_ALGO_RSA2048) {

    if (algorithm == YKPIV_ALGO_RSA1024)
      elem_len = 64;
    if (algorithm == YKPIV_ALGO_RSA2048)
      elem_len = 128;

    if (p == NULL || q == NULL || dp == NULL ||
        dq == NULL || qinv == NULL)
      return YKPIV_GENERIC_ERROR;

    params[0] = p;
    lens[0] = p_len;
    params[1] = q;
    lens[1] = q_len;
    params[2] = dp;
    lens[2] = dp_len;
    params[3] = dq;
    lens[3] = dq_len;
    params[4] = qinv;
    lens[4] = qinv_len;
    param_tag = 0x01;

    n_params = 5;
  }
  else if (algorithm == YKPIV_ALGO_ECCP256 || algorithm == YKPIV_ALGO_ECCP384) {
    if (algorithm == YKPIV_ALGO_ECCP256)
      elem_len = 32;
    if (algorithm == YKPIV_ALGO_ECCP384)
      elem_len = 48;

    if (ec_data == NULL)
      return YKPIV_GENERIC_ERROR;

    params[0] = ec_data;
    lens[0] = ec_data_len;
    param_tag = 0x06;
    n_params = 1;
  }
  else
    return YKPIV_ALGORITHM_ERROR;

  for (i = 0; i < n_params; i++) {
    *in_ptr++ = param_tag + i;
    in_ptr += set_length(in_ptr, elem_len);
    padding = elem_len - lens[i];
    memset(in_ptr, 0, padding);
    in_ptr += padding;
    memcpy(in_ptr, params[i], lens[i]);
    in_ptr += lens[i];
  }

  if (pin_policy != YKPIV_PINPOLICY_DEFAULT) {
    *in_ptr++ = YKPIV_PINPOLICY_TAG;
    *in_ptr++ = 0x01;
    *in_ptr++ = pin_policy;
  }

  if (touch_policy != YKPIV_TOUCHPOLICY_DEFAULT) {
    *in_ptr++ = YKPIV_TOUCHPOLICY_TAG;
    *in_ptr++ = 0x01;
    *in_ptr++ = touch_policy;
  }

  if (ykpiv_transfer_data(state, templ, key_data, in_ptr - key_data, data, &recv_len, &sw) != YKPIV_OK)
    return YKPIV_GENERIC_ERROR;

  if (sw == SW_ERR_SECURITY_STATUS)
    return YKPIV_AUTHENTICATION_ERROR;

  if (sw != SW_SUCCESS)
    return YKPIV_GENERIC_ERROR;

  return YKPIV_OK;

}
