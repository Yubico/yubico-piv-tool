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
/** @file */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <ctype.h>

#include "internal.h"
#include "ykpiv.h"

/**
 * DISABLE_PIN_CACHE - disable in-RAM cache of PIN
 *
 * By default, the PIN is cached in RAM when provided to \p ykpiv_verify() or
 * changed with \p ykpiv_change_pin().  If the USB connection is lost between
 * calls, the device will be re-authenticated on the next call using the cached
 * PIN.  The PIN is cleared with a call to \p ykpiv_done().
 *
 * The PIN cache prevents problems with long-running applications losing their
 * authentication in some cases, such as when a laptop sleeps.
 *
 * The cache can be disabled by setting this define to 1 if it is not desired
 * to store the PIN in RAM.
 *
 */
#ifndef DISABLE_PIN_CACHE
#define DISABLE_PIN_CACHE 0
#endif

/**
 * ENABLE_APPLICATION_RESELECT - re-select application for all public API calls
 *
 * If this is enabled, every public call (prefixed with \r ykpiv_) will check
 * that the PIV application is currently selected, or re-select it if it is
 * not.
 *
 * Auto re-selection allows a long-running PIV application to cooperate on
 * a system that may simultaneously use the non-PIV applications of connected
 * devices.
 *
 * This is \b DANGEROUS - with this enabled, slots with the policy
 * \p YKPIV_PINPOLICY_ALWAYS will not be accessible.
 *
 */
#ifndef ENABLE_APPLICATION_RESELECTION
#define ENABLE_APPLICATION_RESELECTION 0
#endif

#define YKPIV_MGM_DEFAULT "\x01\x02\x03\x04\x05\x06\x07\x08\x01\x02\x03\x04\x05\x06\x07\x08\x01\x02\x03\x04\x05\x06\x07\x08"

static ykpiv_rc _cache_pin(ykpiv_state *state, const char *pin, size_t len);

static ykpiv_rc _send_data(ykpiv_state *state, APDU *apdu,
    unsigned char *data, uint32_t *recv_len, int *sw);

unsigned const char aid[] = {
	0xa0, 0x00, 0x00, 0x03, 0x08
};


static void* _default_alloc(void *data, size_t cb) {
  (void)data;
  return calloc(cb, 1);
}

static void * _default_realloc(void *data, void *p, size_t cb) {
  (void)data;
  return realloc(p, cb);
}

static void _default_free(void *data, void *p) {
  (void)data;
  free(p);
}

ykpiv_allocator _default_allocator = {
  .pfn_alloc = _default_alloc,
  .pfn_realloc = _default_realloc,
  .pfn_free = _default_free,
  .alloc_data = 0
};

/* Memory helper functions */

void* _ykpiv_alloc(ykpiv_state *state, size_t size) {
  if (!state || !(state->allocator.pfn_alloc)) return NULL;
  return state->allocator.pfn_alloc(state->allocator.alloc_data, size);
}

void* _ykpiv_realloc(ykpiv_state *state, void *address, size_t size) {
  if (!state || !(state->allocator.pfn_realloc)) return NULL;
  return state->allocator.pfn_realloc(state->allocator.alloc_data, address, size);
}

void _ykpiv_free(ykpiv_state *state, void *data) {
  if (!data || !state || (!(state->allocator.pfn_free))) return;
  state->allocator.pfn_free(state->allocator.alloc_data, data);
}

static void dump_hex(const unsigned char *buf, unsigned int len) {
  unsigned int i;
  for (i = 0; i < len; i++) {
    fprintf(stderr, "%02x ", buf[i]);
  }
}

int _ykpiv_set_length(unsigned char *buffer, size_t length) {
  if(length < 0x80) {
    *buffer++ = (unsigned char)length;
    return 1;
  } else if(length < 0xff) {
    *buffer++ = 0x81;
    *buffer++ = (unsigned char)length;
    return 2;
  } else {
    *buffer++ = 0x82;
    *buffer++ = (length >> 8) & 0xff;
    *buffer++ = (unsigned char)length & 0xff;
    return 3;
  }
}

int _ykpiv_get_length(const unsigned char *buffer, size_t *len) {
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

ykpiv_rc ykpiv_init_with_allocator(ykpiv_state **state, int verbose, const ykpiv_allocator *allocator) {
  ykpiv_state *s;
  if (NULL == state) {
    return YKPIV_GENERIC_ERROR;
  }
  if (NULL == allocator || !allocator->pfn_alloc || !allocator->pfn_realloc || !allocator->pfn_free) {
    return YKPIV_MEMORY_ERROR;
  }

  s = allocator->pfn_alloc(allocator->alloc_data, sizeof(ykpiv_state));
  if (NULL == s) {
    return YKPIV_MEMORY_ERROR;
  }

  memset(s, 0, sizeof(ykpiv_state));
  s->pin = NULL;
  s->allocator = *allocator;
  s->verbose = verbose;
  s->context = SCARD_E_INVALID_HANDLE;
  *state = s;
  return YKPIV_OK;
}

ykpiv_rc ykpiv_init(ykpiv_state **state, int verbose) {
  return ykpiv_init_with_allocator(state, verbose, &_default_allocator);
}

static ykpiv_rc _ykpiv_done(ykpiv_state *state, bool disconnect) {
  if (disconnect)
    ykpiv_disconnect(state);
  _cache_pin(state, NULL, 0);
  _ykpiv_free(state, state);
  return YKPIV_OK;
}

ykpiv_rc ykpiv_done_with_external_card(ykpiv_state *state) {
  return _ykpiv_done(state, false);
}

ykpiv_rc ykpiv_done(ykpiv_state *state) {
  return _ykpiv_done(state, true);
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

ykpiv_rc _ykpiv_select_application(ykpiv_state *state) {
  APDU apdu;
  unsigned char data[0xff];
  uint32_t recv_len = sizeof(data);
  int sw;
  ykpiv_rc res;

  memset(apdu.raw, 0, sizeof(apdu));
  apdu.st.ins = YKPIV_INS_SELECT_APPLICATION;
  apdu.st.p1 = 0x04;
  apdu.st.lc = sizeof(aid);
  memcpy(apdu.st.data, aid, sizeof(aid));

  if((res = _send_data(state, &apdu, data, &recv_len, &sw)) != YKPIV_OK) {
    if(state->verbose) {
      fprintf(stderr, "Failed communicating with card: '%s'\n", ykpiv_strerror(res));
    }
    return res;
  } else if(sw == SW_SUCCESS) {
    return YKPIV_OK;
  } else {
    if(state->verbose) {
      fprintf(stderr, "Failed selecting application: %04x\n", sw);
    }
    return YKPIV_GENERIC_ERROR;
  }
}

ykpiv_rc _ykpiv_ensure_application_selected(ykpiv_state *state) {
  ykpiv_rc res = YKPIV_OK;

#if ENABLE_APPLICATION_RESELECTION
  if (NULL == state) {
    return YKPIV_GENERIC_ERROR;
  }

  res = ykpiv_verify(state, NULL, 0);

  if ((YKPIV_OK != res) && (YKPIV_WRONG_PIN != res)) {
    res = _ykpiv_select_application(state);
  }
  else {
    res = YKPIV_OK;
  }

  return res;
#else
  return res;
#endif
}

static ykpiv_rc _ykpiv_connect(ykpiv_state *state, uintptr_t context, uintptr_t card) {
  ykpiv_rc res = YKPIV_OK;

  if (NULL == state) {
    return YKPIV_GENERIC_ERROR;
  }

  // if the context has changed, and the new context is not valid, return an error
  if ((context != state->context) && (SCARD_S_SUCCESS != SCardIsValidContext(context))) {
    return YKPIV_PCSC_ERROR;
  }

  // if card handle has changed, determine if handle is valid (less efficient, but complete)
  if ((card != state->card)) {
    char reader[CB_BUF_MAX];
    pcsc_word reader_len = sizeof(reader);
    uint8_t atr[CB_ATR_MAX];
    pcsc_word atr_len = sizeof(atr);

    // Cannot set the reader len to NULL.  Confirmed in OSX 10.10, so we have to retrieve it even though we don't need it.
    if (SCARD_S_SUCCESS != SCardStatus(card, reader, &reader_len, NULL, NULL, atr, &atr_len)) {
      return YKPIV_PCSC_ERROR;
    }

    state->isNEO = (((sizeof(YKPIV_ATR_NEO_R3) - 1) == atr_len) && (0 == memcmp(YKPIV_ATR_NEO_R3, atr, atr_len)));
  }

  state->context = context;
  state->card = card;

  /*
  ** Do not select the applet here, as we need to accommodate commands that are
  ** sensitive to re-select (custom apdu/auth). All commands that can handle explicit
  ** selection already check the applet state and select accordingly anyway.
  ** ykpiv_verify_select is supplied for those who want to select explicitly.
  **
  ** The applet _is_ selected by ykpiv_connect(), but is not selected when bypassing
  ** it with ykpiv_connect_with_external_card().
  */
  return res;
}

ykpiv_rc ykpiv_connect_with_external_card(ykpiv_state *state, uintptr_t context, uintptr_t card) {
  return _ykpiv_connect(state, context, card);
}

ykpiv_rc ykpiv_connect(ykpiv_state *state, const char *wanted) {
  pcsc_word active_protocol;
  char reader_buf[2048];
  size_t num_readers = sizeof(reader_buf);
  long rc;
  char *reader_ptr;
  SCARDHANDLE card = (SCARDHANDLE)-1;

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
		      SCARD_PROTOCOL_T1, &card, &active_protocol);
    if(rc != SCARD_S_SUCCESS)
    {
      if(state->verbose) {
        fprintf(stderr, "SCardConnect failed, rc=%08lx\n", rc);
      }
      continue;
    }

    // at this point, card should not equal state->card, to allow _ykpiv_connect() to determine device type
    if (YKPIV_OK == _ykpiv_connect(state, state->context, card)) {
      /*
       * Select applet.  This is done here instead of in _ykpiv_connect() because
       * you may not want to select the applet when connecting to a card handle that
       * was supplied by an external library.
       */
      if (YKPIV_OK != (ret = _ykpiv_begin_transaction(state))) return YKPIV_PCSC_ERROR;
#if ENABLE_APPLICATION_RESELECTION
      ret = _ykpiv_ensure_application_selected(state);
#else
      ret = _ykpiv_select_application(state);
#endif
      _ykpiv_end_transaction(state);
      return ret;
    }
  }

  if(*reader_ptr == '\0') {
    if(state->verbose) {
      fprintf(stderr, "error: no usable reader found.\n");
    }
    SCardReleaseContext(state->context);
    state->context = (SCARDCONTEXT)-1;
    return YKPIV_PCSC_ERROR;
  }

  return YKPIV_GENERIC_ERROR;
}

static ykpiv_rc reconnect(ykpiv_state *state) {
  pcsc_word active_protocol = 0;
  long rc;
  ykpiv_rc res;
  int tries;
  if(state->verbose) {
    fprintf(stderr, "trying to reconnect to current reader.\n");
  }
  rc = SCardReconnect(state->card, SCARD_SHARE_SHARED,
		      SCARD_PROTOCOL_T1, SCARD_RESET_CARD, &active_protocol);
  if(rc != SCARD_S_SUCCESS) {
    if(state->verbose) {
      fprintf(stderr, "SCardReconnect failed, rc=%08lx\n", rc);
    }
    return YKPIV_PCSC_ERROR;
  }
  if ((res = _ykpiv_select_application(state)) != YKPIV_OK) {
    return res;
  }
  if (state->pin) {
    return ykpiv_verify(state, state->pin, &tries);
  }
  return YKPIV_OK;
}

ykpiv_rc ykpiv_list_readers(ykpiv_state *state, char *readers, size_t *len) {
  pcsc_word num_readers = 0;
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

ykpiv_rc _ykpiv_begin_transaction(ykpiv_state *state) {
  long rc;
  ykpiv_rc res;

  rc = SCardBeginTransaction(state->card);
  if((rc & 0xFFFFFFFF) == SCARD_W_RESET_CARD) {
    if((res = reconnect(state)) != YKPIV_OK) {
      return res;
    }
    rc = SCardBeginTransaction(state->card);
  }
  if(rc != SCARD_S_SUCCESS) {
    if(state->verbose) {
      fprintf(stderr, "error: Failed to begin pcsc transaction, rc=%08lx\n", rc);
    }
    return YKPIV_PCSC_ERROR;
  }
  return YKPIV_OK;
}

ykpiv_rc _ykpiv_end_transaction(ykpiv_state *state) {
  long rc = SCardEndTransaction(state->card, SCARD_LEAVE_CARD);
  if(rc != SCARD_S_SUCCESS && state->verbose) {
    fprintf(stderr, "error: Failed to end pcsc transaction, rc=%08lx\n", rc);
    return YKPIV_PCSC_ERROR;
  }
  return YKPIV_OK;
}

ykpiv_rc ykpiv_transfer_data(ykpiv_state *state, const unsigned char *templ,
    const unsigned char *in_data, long in_len,
    unsigned char *out_data, unsigned long *out_len, int *sw) {
  const unsigned char *in_ptr = in_data;
  unsigned long max_out = *out_len;
  ykpiv_rc res;
  *out_len = 0;

  if (YKPIV_OK != (res = _ykpiv_begin_transaction(state))) return YKPIV_PCSC_ERROR;
  do {
    size_t this_size = 0xff;
    unsigned char data[261];
    uint32_t recv_len = sizeof(data);
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
    res = _send_data(state, &apdu, data, &recv_len, sw);
    if(res != YKPIV_OK) {
      goto Cleanup;
    } else if(*sw != SW_SUCCESS && *sw >> 8 != 0x61) {
      goto Cleanup;
    }
    if(*out_len + recv_len - 2 > max_out) {
      if(state->verbose) {
        fprintf(stderr, "Output buffer to small, wanted to write %lu, max was %lu.\n", *out_len + recv_len - 2, max_out);
      }
      res = YKPIV_SIZE_ERROR;
      goto Cleanup;
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
    uint32_t recv_len = sizeof(data);

    if(state->verbose > 2) {
      fprintf(stderr, "The card indicates there is %d bytes more data for us.\n", *sw & 0xff);
    }

    memset(apdu.raw, 0, sizeof(apdu.raw));
    apdu.st.ins = YKPIV_INS_GET_RESPONSE_APDU;
    res = _send_data(state, &apdu, data, &recv_len, sw);
    if(res != YKPIV_OK) {
      goto Cleanup;
    } else if(*sw != SW_SUCCESS && *sw >> 8 != 0x61) {
      goto Cleanup;
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
Cleanup:
  _ykpiv_end_transaction(state);
  return res;
}

static ykpiv_rc _send_data(ykpiv_state *state, APDU *apdu,
    unsigned char *data, uint32_t *recv_len, int *sw) {
  long rc;
  unsigned int send_len = (unsigned int)apdu->st.lc + 5;
  pcsc_word tmp_len = *recv_len;

  if(state->verbose > 1) {
    fprintf(stderr, "> ");
    dump_hex(apdu->raw, send_len);
    fprintf(stderr, "\n");
  }
  rc = SCardTransmit(state->card, SCARD_PCI_T1, apdu->raw, send_len, NULL, data, &tmp_len);
  if(rc != SCARD_S_SUCCESS) {
    if(state->verbose) {
      fprintf (stderr, "error: SCardTransmit failed, rc=%08lx\n", rc);
    }
    return YKPIV_PCSC_ERROR;
  }
  *recv_len = (uint32_t)tmp_len;

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
  unsigned char challenge[8];
  uint32_t recv_len = sizeof(data);
  int sw;
  ykpiv_rc res;
  des_key* mgm_key = NULL;
  size_t out_len = 0;

  if (NULL == state) return YKPIV_GENERIC_ERROR;

  if (YKPIV_OK != (res = _ykpiv_begin_transaction(state))) return YKPIV_PCSC_ERROR;
  if (YKPIV_OK != (res = _ykpiv_ensure_application_selected(state))) goto Cleanup;

  if (NULL == key) {
    /* use the derived mgm key to authenticate, if it hasn't been derived, use default */
    key = (unsigned const char*)YKPIV_MGM_DEFAULT;
  }

  /* set up our key */
  if (DES_OK != des_import_key(DES_TYPE_3DES, key, CB_MGM_KEY, &mgm_key)) {
    res = YKPIV_ALGORITHM_ERROR;
    goto Cleanup;
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
    if ((res = _send_data(state, &apdu, data, &recv_len, &sw)) != YKPIV_OK) {
      goto Cleanup;
    }
    else if (sw != SW_SUCCESS) {
      res = YKPIV_AUTHENTICATION_ERROR;
      goto Cleanup;
    }
    memcpy(challenge, data + 4, 8);
  }

  /* send a response to the cards challenge and a challenge of our own. */
  {
    unsigned char *dataptr = apdu.st.data;
    unsigned char response[8];
    out_len = sizeof(response);
    des_decrypt(mgm_key, challenge, sizeof(challenge), response, &out_len);

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
    if (PRNG_GENERAL_ERROR == _ykpiv_prng_generate(dataptr, 8)) {
      if (state->verbose) {
        fprintf(stderr, "Failed getting randomness for authentication.\n");
      }
      res = YKPIV_RANDOMNESS_ERROR;
      goto Cleanup;
    }
    memcpy(challenge, dataptr, 8);
    dataptr += 8;
    apdu.st.lc = (unsigned char)(dataptr - apdu.st.data);
    if ((res = _send_data(state, &apdu, data, &recv_len, &sw)) != YKPIV_OK) {
      goto Cleanup;
    }
    else if (sw != SW_SUCCESS) {
      res = YKPIV_AUTHENTICATION_ERROR;
      goto Cleanup;
    }
  }

  /* compare the response from the card with our challenge */
  {
    unsigned char response[8];
    out_len = sizeof(response);
    des_encrypt(mgm_key, challenge, sizeof(challenge), response, &out_len);
    if (memcmp(response, data + 4, 8) == 0) {
      res = YKPIV_OK;
    }
    else {
      res = YKPIV_AUTHENTICATION_ERROR;
    }
  }

Cleanup:

  if (mgm_key) {
    des_destroy_key(mgm_key);
  }

  _ykpiv_end_transaction(state);
  return res;
}

ykpiv_rc ykpiv_set_mgmkey(ykpiv_state *state, const unsigned char *new_key) {
  return ykpiv_set_mgmkey2(state, new_key, 0);
}

ykpiv_rc ykpiv_set_mgmkey2(ykpiv_state *state, const unsigned char *new_key, const unsigned char touch) {
  APDU apdu;
  unsigned char data[261];
  uint32_t recv_len = sizeof(data);
  int sw;
  ykpiv_rc res = YKPIV_OK;

  if (YKPIV_OK != (res = _ykpiv_begin_transaction(state))) return YKPIV_PCSC_ERROR;
  if (YKPIV_OK != (res = _ykpiv_ensure_application_selected(state))) goto Cleanup;

  if (yk_des_is_weak_key(new_key, DES_LEN_3DES)) {
    if (state->verbose) {
      fprintf(stderr, "Won't set new key '");
      dump_hex(new_key, DES_LEN_3DES);
      fprintf(stderr, "' since it's weak (with odd parity).\n");
    }
    res = YKPIV_KEY_ERROR;
    goto Cleanup;
  }

  memset(apdu.raw, 0, sizeof(apdu));
  apdu.st.ins = YKPIV_INS_SET_MGMKEY;
  apdu.st.p1 = 0xff;
  if (touch == 0) {
    apdu.st.p2 = 0xff;
  }
  else if (touch == 1) {
    apdu.st.p2 = 0xfe;
  }
  else {
    res = YKPIV_GENERIC_ERROR;
    goto Cleanup;
  }

  apdu.st.lc = DES_LEN_3DES + 3;
  apdu.st.data[0] = YKPIV_ALGO_3DES;
  apdu.st.data[1] = YKPIV_KEY_CARDMGM;
  apdu.st.data[2] = DES_LEN_3DES;
  memcpy(apdu.st.data + 3, new_key, DES_LEN_3DES);

  if ((res = _send_data(state, &apdu, data, &recv_len, &sw)) != YKPIV_OK) {
    goto Cleanup;
  }
  else if (sw == SW_SUCCESS) {
    goto Cleanup;
  }
  res = YKPIV_GENERIC_ERROR;

Cleanup:
  _ykpiv_end_transaction(state);
  return res;
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
  int sw = 0;
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
  dataptr += _ykpiv_set_length(dataptr, in_len + bytes + 3);
  *dataptr++ = 0x82;
  *dataptr++ = 0x00;
  *dataptr++ = YKPIV_IS_EC(algorithm) && decipher ? 0x85 : 0x81;
  dataptr += _ykpiv_set_length(dataptr, in_len);
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
  dataptr += _ykpiv_get_length(dataptr, &len);
  /* skip the 82 tag */
  if(*dataptr != 0x82) {
    if(state->verbose) {
      fprintf(stderr, "Failed parsing signature reply.\n");
    }
    return YKPIV_PARSE_ERROR;
  }
  dataptr++;
  dataptr += _ykpiv_get_length(dataptr, &len);
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
  ykpiv_rc res = YKPIV_OK;

  if (NULL == state) return YKPIV_GENERIC_ERROR;

  if (YKPIV_OK != (res = _ykpiv_begin_transaction(state))) return YKPIV_PCSC_ERROR;
  if (YKPIV_OK != (res = _ykpiv_ensure_application_selected(state))) goto Cleanup;

  res = _general_authenticate(state, raw_in, in_len, sign_out, out_len,
                              algorithm, key, false);
Cleanup:
  _ykpiv_end_transaction(state);
  return res;
}

ykpiv_rc ykpiv_decipher_data(ykpiv_state *state, const unsigned char *in,
    size_t in_len, unsigned char *out, size_t *out_len,
    unsigned char algorithm, unsigned char key) {
  ykpiv_rc res = YKPIV_OK;

  if (NULL == state) return YKPIV_GENERIC_ERROR;

  if (YKPIV_OK != (res = _ykpiv_begin_transaction(state))) return YKPIV_PCSC_ERROR;
  if (YKPIV_OK != (res = _ykpiv_ensure_application_selected(state))) goto Cleanup;


  res = _general_authenticate(state, in, in_len, out, out_len,
     algorithm, key, true);

Cleanup:

  _ykpiv_end_transaction(state);
  return res;
}

ykpiv_rc ykpiv_get_version(ykpiv_state *state, char *version, size_t len) {
  APDU apdu;
  unsigned char data[261];
  uint32_t recv_len = sizeof(data);
  int sw;
  ykpiv_rc res;

  if (YKPIV_OK != (res = _ykpiv_begin_transaction(state))) return YKPIV_PCSC_ERROR;
  if (YKPIV_OK != (res = _ykpiv_ensure_application_selected(state))) goto Cleanup;

  memset(apdu.raw, 0, sizeof(apdu));
  apdu.st.ins = YKPIV_INS_GET_VERSION;
  if((res = _send_data(state, &apdu, data, &recv_len, &sw)) != YKPIV_OK) {
    goto Cleanup;
  } else if(sw == SW_SUCCESS) {
    int result = snprintf(version, len, "%d.%d.%d", data[0], data[1], data[2]);
    if(result < 0) {
      res = YKPIV_SIZE_ERROR;
    }
    goto Cleanup;
  } else {
    res = YKPIV_GENERIC_ERROR;
    goto Cleanup;
  }

Cleanup:
  _ykpiv_end_transaction(state);
  return res;
}

static ykpiv_rc _cache_pin(ykpiv_state *state, const char *pin, size_t len) {
#if DISABLE_PIN_CACHE
  // Some embedded applications of this library may not want to keep the PIN
  // data in RAM for security reasons.
  return YKPIV_OK;
#else
  if (!state)
    return YKPIV_ARGUMENT_ERROR;
  if (pin && state->pin == pin) {
    return YKPIV_OK;
  }
  if (state->pin) {
    _ykpiv_free(state, state->pin);
    state->pin = NULL;
  }
  if (pin && len > 0) {
    state->pin = _ykpiv_alloc(state, len * sizeof(char) + 1);
    if (state->pin == NULL) {
      return YKPIV_MEMORY_ERROR;
    }
    memcpy(state->pin, pin, len);
    state->pin[len] = 0;
  }
  return YKPIV_OK;
#endif
}

static ykpiv_rc _verify(ykpiv_state *state, const char *pin, const size_t pin_len, int *tries) {
  APDU apdu;
  unsigned char data[261];
  uint32_t recv_len = sizeof(data);
  int sw;
  ykpiv_rc res;

  if (pin_len > 8) {
    return YKPIV_SIZE_ERROR;
  }

  memset(apdu.raw, 0, sizeof(apdu.raw));
  apdu.st.ins = YKPIV_INS_VERIFY;
  apdu.st.p1 = 0x00;
  apdu.st.p2 = 0x80;
  apdu.st.lc = pin ? 0x08 : 0;
  if (pin) {
    memcpy(apdu.st.data, pin, pin_len);
    if (pin_len < 8) {
      memset(apdu.st.data + pin_len, 0xff, 8 - pin_len);
    }
  }
  if ((res = _send_data(state, &apdu, data, &recv_len, &sw)) != YKPIV_OK) {
    return res;
  } else if (sw == SW_SUCCESS) {
    if (pin && pin_len) {
      // Intentionally ignore errors.  If the PIN fails to save, it will only
      // be a problem if a reconnect is attempted.  Failure deferred until then.
      _cache_pin(state, pin, pin_len);
    }
    if (tries) *tries = (sw & 0xf);
    return YKPIV_OK;
  } else if ((sw >> 8) == 0x63) {
    if (tries) *tries = (sw & 0xf);
    return YKPIV_WRONG_PIN;
  } else if (sw == SW_ERR_AUTH_BLOCKED) {
    if (tries) *tries = 0;
    return YKPIV_WRONG_PIN;
  } else {
    return YKPIV_GENERIC_ERROR;
  }
}

ykpiv_rc ykpiv_verify(ykpiv_state *state, const char *pin, int *tries) {
  return ykpiv_verify_select(state, pin, pin ? strlen(pin) : 0, tries, false);
}

ykpiv_rc ykpiv_verify_select(ykpiv_state *state, const char *pin, const size_t pin_len, int *tries, bool force_select) {
  ykpiv_rc res = YKPIV_OK;
  if (YKPIV_OK != (res = _ykpiv_begin_transaction(state))) goto Cleanup;
  if (force_select) {
    if (YKPIV_OK != (res = _ykpiv_ensure_application_selected(state))) goto Cleanup;
  }
  res = _verify(state, pin, pin_len, tries);
Cleanup:

  _ykpiv_end_transaction(state);
  return res;
}

ykpiv_rc ykpiv_get_pin_retries(ykpiv_state *state, int *tries) {
  ykpiv_rc res;
  ykpiv_rc ykrc;
  if (NULL == state || NULL == tries) {
    return YKPIV_ARGUMENT_ERROR;
  }
  // Force a re-select to unverify, because once verified the spec dictates that
  // subsequent verify calls will return a "verification not needed" instead of
  // the number of tries left...
  res = _ykpiv_select_application(state);
  if (res != YKPIV_OK) return res;
  ykrc = ykpiv_verify(state, NULL, tries);
  // WRONG_PIN is expected on successful query.
  return ykrc == YKPIV_WRONG_PIN ? YKPIV_OK : ykrc;
}


ykpiv_rc ykpiv_set_pin_retries(ykpiv_state *state, int pin_tries, int puk_tries) {
  ykpiv_rc res = YKPIV_OK;
  unsigned char templ[] = {0, YKPIV_INS_SET_PIN_RETRIES, 0, 0};
  unsigned char data[0xff];
  unsigned long recv_len = sizeof(data);
  int sw = 0;

  // Special case: if either retry count is 0, it's a successful no-op
  if (pin_tries == 0 || puk_tries == 0) {
    return YKPIV_OK;
  }

  if (pin_tries > 0xff || puk_tries > 0xff || pin_tries < 1 || puk_tries < 1) {
    return YKPIV_RANGE_ERROR;
  }

  templ[2] = (unsigned char)pin_tries;
  templ[3] = (unsigned char)puk_tries;

  if (YKPIV_OK != (res = _ykpiv_begin_transaction(state))) return YKPIV_PCSC_ERROR;
  if (YKPIV_OK != (res = _ykpiv_ensure_application_selected(state))) goto Cleanup;

  res = ykpiv_transfer_data(state, templ, NULL, 0, data, &recv_len, &sw);
  if (YKPIV_OK == res) {
    if (SW_SUCCESS == sw) {
      // success, fall through
    } else if (sw == SW_ERR_AUTH_BLOCKED) {
      res = YKPIV_AUTHENTICATION_ERROR;
    } else if (sw == SW_ERR_SECURITY_STATUS) {
      res = YKPIV_AUTHENTICATION_ERROR;
    } else {
      res = YKPIV_GENERIC_ERROR;
    }
  }

Cleanup:
  _ykpiv_end_transaction(state);
  return res;
}

static ykpiv_rc _ykpiv_change_pin(ykpiv_state *state, int action, const char * current_pin, size_t current_pin_len, const char * new_pin, size_t new_pin_len, int *tries) {
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
      if (tries) *tries = sw & 0xf;
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
  ykpiv_rc res = YKPIV_GENERIC_ERROR;

  if (YKPIV_OK != (res = _ykpiv_begin_transaction(state))) return YKPIV_PCSC_ERROR;
  if (YKPIV_OK != (res = _ykpiv_ensure_application_selected(state))) goto Cleanup;

  res = _ykpiv_change_pin(state, CHREF_ACT_CHANGE_PIN, current_pin, current_pin_len, new_pin, new_pin_len, tries);
  if (res == YKPIV_OK && new_pin != NULL) {
    // Intentionally ignore errors.  If the PIN fails to save, it will only
    // be a problem if a reconnect is attempted.  Failure deferred until then.
    _cache_pin(state, new_pin, new_pin_len);
  }

Cleanup:
  _ykpiv_end_transaction(state);
  return res;
}

ykpiv_rc ykpiv_change_puk(ykpiv_state *state, const char * current_puk, size_t current_puk_len, const char * new_puk, size_t new_puk_len, int *tries) {
  ykpiv_rc res = YKPIV_GENERIC_ERROR;

  if (YKPIV_OK != (res = _ykpiv_begin_transaction(state))) return YKPIV_PCSC_ERROR;
  if (YKPIV_OK != (res = _ykpiv_ensure_application_selected(state))) goto Cleanup;

  res = _ykpiv_change_pin(state, CHREF_ACT_CHANGE_PUK, current_puk, current_puk_len, new_puk, new_puk_len, tries);

Cleanup:
  _ykpiv_end_transaction(state);
  return res;
}

ykpiv_rc ykpiv_unblock_pin(ykpiv_state *state, const char * puk, size_t puk_len, const char * new_pin, size_t new_pin_len, int *tries) {
  ykpiv_rc res = YKPIV_GENERIC_ERROR;

  if (YKPIV_OK != (res = _ykpiv_begin_transaction(state))) return YKPIV_PCSC_ERROR;
  if (YKPIV_OK != (res = _ykpiv_ensure_application_selected(state))) goto Cleanup;

  res = _ykpiv_change_pin(state, CHREF_ACT_UNBLOCK_PIN, puk, puk_len, new_pin, new_pin_len, tries);

Cleanup:
  _ykpiv_end_transaction(state);
  return res;
}

ykpiv_rc ykpiv_fetch_object(ykpiv_state *state, int object_id,
    unsigned char *data, unsigned long *len) {
  ykpiv_rc res;

  if (YKPIV_OK != (res = _ykpiv_begin_transaction(state))) return YKPIV_PCSC_ERROR;
  if (YKPIV_OK != (res = _ykpiv_ensure_application_selected(state))) goto Cleanup;

  res = _ykpiv_fetch_object(state, object_id, data, len);

Cleanup:
  _ykpiv_end_transaction(state);
  return res;
}

ykpiv_rc _ykpiv_fetch_object(ykpiv_state *state, int object_id,
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
    int offs = _ykpiv_get_length(data + 1, &outlen);
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
  ykpiv_rc res;

  if (YKPIV_OK != (res = _ykpiv_begin_transaction(state))) return YKPIV_PCSC_ERROR;
  if (YKPIV_OK != (res = _ykpiv_ensure_application_selected(state))) goto Cleanup;

  res = _ykpiv_save_object(state, object_id, indata, len);

Cleanup:
  _ykpiv_end_transaction(state);
  return res;
}

ykpiv_rc _ykpiv_save_object(ykpiv_state *state, int object_id,
    unsigned char *indata, size_t len) {
  unsigned char data[CB_BUF_MAX];
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
  dataptr += _ykpiv_set_length(dataptr, len);
  memcpy(dataptr, indata, len);
  dataptr += len;

  if((res = ykpiv_transfer_data(state, templ, data, dataptr - data, NULL, &outlen,
    &sw)) != YKPIV_OK) {
    return res;
  }

  if(SW_SUCCESS == sw) {
    return YKPIV_OK;
  }
  else if (SW_ERR_SECURITY_STATUS == sw) {
    return YKPIV_AUTHENTICATION_ERROR;
  }
  else {
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
  ykpiv_rc res;

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

    if (p_len + q_len + dp_len + dq_len + qinv_len >= sizeof(key_data)) {
      return YKPIV_SIZE_ERROR;
    }

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

    if ((size_t)ec_data_len >= sizeof(key_data)) {
      // This can never be true, but check to be explicit.
      return YKPIV_SIZE_ERROR;
    }

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
    size_t remaining;
    *in_ptr++ = param_tag + i;
    in_ptr += _ykpiv_set_length(in_ptr, elem_len);
    padding = elem_len - lens[i];
    remaining = (uintptr_t)key_data + sizeof(key_data) - (uintptr_t)in_ptr;
    if (padding > remaining) {
      return YKPIV_ALGORITHM_ERROR;
    }
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

  if (YKPIV_OK != (res = _ykpiv_begin_transaction(state))) return YKPIV_PCSC_ERROR;
  if (YKPIV_OK != (res = _ykpiv_ensure_application_selected(state))) goto Cleanup;

  if ((res = ykpiv_transfer_data(state, templ, key_data, in_ptr - key_data, data, &recv_len, &sw)) != YKPIV_OK) {
    goto Cleanup;
  }
  if (SW_SUCCESS != sw) {
    res = YKPIV_GENERIC_ERROR;
    if (sw == SW_ERR_SECURITY_STATUS) {
      res = YKPIV_AUTHENTICATION_ERROR;
    }
    goto Cleanup;
  }

Cleanup:
  _ykpiv_end_transaction(state);
  return res;
}

ykpiv_rc ykpiv_attest(ykpiv_state *state, const unsigned char key, unsigned char *data, size_t *data_len) {
  ykpiv_rc res;
  bool ret = false;
  unsigned char templ[] = {0, YKPIV_INS_ATTEST, key, 0};
  int sw;

  if (state == NULL || data == NULL || data_len == NULL) {
    return YKPIV_ARGUMENT_ERROR;
  }

  if (YKPIV_OK != (res = _ykpiv_begin_transaction(state))) return YKPIV_PCSC_ERROR;
  if (YKPIV_OK != (res = _ykpiv_ensure_application_selected(state))) goto Cleanup;

  if ((res = ykpiv_transfer_data(state, templ, NULL, 0, data, data_len, &sw)) != YKPIV_OK) {
    goto Cleanup;
  }
  if (SW_SUCCESS != sw) {
    res = YKPIV_GENERIC_ERROR;
    if (SW_ERR_NOT_SUPPORTED == sw) {
      res = YKPIV_NOT_SUPPORTED;
    }
    goto Cleanup;
  }
  if (data[0] != 0x30) {
    res = YKPIV_GENERIC_ERROR;
    goto Cleanup;
  }

Cleanup:
  _ykpiv_end_transaction(state);
  return res;
}


ykpiv_rc ykpiv_auth_getchallenge(ykpiv_state *state, uint8_t *challenge, const size_t challenge_len) {
  ykpiv_rc res = YKPIV_OK;
  APDU apdu = { 0 };
  unsigned char data[261] = { 0 };
  uint32_t recv_len = sizeof(data);
  int sw = 0;

  if (NULL == state) return YKPIV_GENERIC_ERROR;
  if (NULL == challenge) return YKPIV_GENERIC_ERROR;
  if (8 != challenge_len) return YKPIV_SIZE_ERROR;

  if (YKPIV_OK != (res = _ykpiv_begin_transaction(state))) return YKPIV_PCSC_ERROR;
  if (YKPIV_OK != (res = _ykpiv_ensure_application_selected(state))) goto Cleanup;

  /* get a challenge from the card */
  memset(apdu.raw, 0, sizeof(apdu));
  apdu.st.ins = YKPIV_INS_AUTHENTICATE;
  apdu.st.p1 = YKPIV_ALGO_3DES; /* triple des */
  apdu.st.p2 = YKPIV_KEY_CARDMGM; /* management key */
  apdu.st.lc = 0x04;
  apdu.st.data[0] = 0x7c;
  apdu.st.data[1] = 0x02;
  apdu.st.data[2] = 0x81; //0x80;
  if ((res = _send_data(state, &apdu, data, &recv_len, &sw)) != YKPIV_OK) {
    goto Cleanup;
  }
  else if (sw != SW_SUCCESS) {
    res = YKPIV_AUTHENTICATION_ERROR;
    goto Cleanup;
  }
  memcpy(challenge, data + 4, 8);

Cleanup:

  _ykpiv_end_transaction(state);
  return res;
}

ykpiv_rc ykpiv_auth_verifyresponse(ykpiv_state *state, uint8_t *response, const size_t response_len) {
  ykpiv_rc res = YKPIV_OK;
  APDU apdu = { 0 };
  unsigned char data[261] = { 0 };
  uint32_t recv_len = sizeof(data);
  int sw = 0;
  unsigned char *dataptr = apdu.st.data;

  if (NULL == state) return YKPIV_GENERIC_ERROR;
  if (NULL == response) return YKPIV_GENERIC_ERROR;
  if (8 != response_len) return YKPIV_SIZE_ERROR;

  if (YKPIV_OK != (res = _ykpiv_begin_transaction(state))) return YKPIV_PCSC_ERROR;
  /* note: do not select the applet here, as it resets the challenge state */

  /* send the response to the card and a challenge of our own. */
  recv_len = sizeof(data);
  memset(apdu.raw, 0, sizeof(apdu));
  apdu.st.ins = YKPIV_INS_AUTHENTICATE;
  apdu.st.p1 = YKPIV_ALGO_3DES; /* triple des */
  apdu.st.p2 = YKPIV_KEY_CARDMGM; /* management key */
  *dataptr++ = 0x7c;
  *dataptr++ = 0x0a; /* 2 + 8 */
  *dataptr++ = 0x82;
  *dataptr++ = 8;
  memcpy(dataptr, response, response_len);
  dataptr += 8;
  apdu.st.lc = (unsigned char)(dataptr - apdu.st.data);
  if ((res = _send_data(state, &apdu, data, &recv_len, &sw)) != YKPIV_OK) {
    goto Cleanup;
  }
  else if (sw != SW_SUCCESS) {
    res = YKPIV_AUTHENTICATION_ERROR;
    goto Cleanup;
  }

Cleanup:

  _ykpiv_end_transaction(state);
  return res;
}
