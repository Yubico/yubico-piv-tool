 /*
 * Copyright (c) 2014-2020 Yubico AB
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
 * DISABLE_MGM_KEY_CACHE - disable in-RAM cache of MGM_KEY (SO PIN)
 *
 * By default, the MGM_KEY is cached in RAM when provided to \p ykpiv_authenticate() or
 * changed with \p ykpiv_set_mgmkey().  If the USB connection is lost between
 * calls, the device will be re-authenticated on the next call using the cached
 * MGM_KEY.  The MGM_KEY is cleared with a call to \p ykpiv_done().
 *
 * The MGM_KEY cache prevents problems with long-running applications losing their
 * authentication in some cases, such as when a laptop sleeps.
 *
 * The cache can be disabled by setting this define to 1 if it is not desired
 * to store the MGM_KEY in RAM.
 *
 */
#ifndef DISABLE_MGM_KEY_CACHE
#define DISABLE_MGM_KEY_CACHE 0
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


/**
 * ENABLE_IMPLICIT_TRANSACTIONS - call SCardBeginTransaction for all public API calls
 *
 * If this is enabled, every public call (prefixed with \r ykpiv_) will call
 * SCardBeginTransaction on entry and SCardEndTransaction on exit.
 *
 * For applications that do not do their own transaction management, like the piv tool
 * itself, retaining the default setting of enabled can allow other applications and
 * threads to make calls to CCID that can interfere with multi-block data sent to the
 * card via SCardTransmitData.
 */
#ifndef ENABLE_IMPLICIT_TRANSACTIONS
#define ENABLE_IMPLICIT_TRANSACTIONS 1
#endif

/**
 * Platform specific definitions
 */
#ifdef _MSC_VER
#define strncasecmp _strnicmp
#endif

#define YKPIV_MGM_DEFAULT "\x01\x02\x03\x04\x05\x06\x07\x08\x01\x02\x03\x04\x05\x06\x07\x08\x01\x02\x03\x04\x05\x06\x07\x08"

static ykpiv_rc _cache_pin(ykpiv_state *state, const char *pin, size_t len);
static ykpiv_rc _cache_mgm_key(ykpiv_state *state, unsigned const char *key, size_t len);
static ykpiv_rc _ykpiv_get_serial(ykpiv_state *state);
static ykpiv_rc _ykpiv_get_version(ykpiv_state *state);
static ykpiv_rc _ykpiv_verify(ykpiv_state *state, const char *pin, const size_t pin_len);
static ykpiv_rc _ykpiv_authenticate2(ykpiv_state *state, unsigned const char *key, size_t len);
static ykpiv_rc _ykpiv_auth_deauthenticate(ykpiv_state *state);

static unsigned const char piv_aid[] = {
	0xa0, 0x00, 0x00, 0x03, 0x08
};

static unsigned const char yk_aid[] = {
  0xa0, 0x00, 0x00, 0x05, 0x27, 0x20, 0x01, 0x01
};

static unsigned const char mgmt_aid[] = {
  0xa0, 0x00, 0x00, 0x05, 0x27, 0x47, 0x11, 0x17
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
  if (!data || !state || !(state->allocator.pfn_free)) return;
  state->allocator.pfn_free(state->allocator.alloc_data, data);
}

static void dump_hex(const unsigned char *buf, unsigned int len) {
  unsigned int i;
  for (i = 0; i < len; i++) {
    fprintf(stderr, "%02x ", buf[i]);
  }
}

size_t _ykpiv_get_length_size(size_t length) {
  if(length < 0x80) {
    return 1;
  } else if(length < 0x100) {
    return 2;
  } else {
    return 3;
  }
}

size_t _ykpiv_set_length(unsigned char *buffer, size_t length) {
  if(length < 0x80) {
    *buffer++ = (unsigned char)length;
    return 1;
  } else if(length < 0x100) {
    *buffer++ = 0x81;
    *buffer++ = (unsigned char)length;
    return 2;
  } else {
    *buffer++ = 0x82;
    *buffer++ = (length >> 8) & 0xff;
    *buffer++ = length & 0xff;
    return 3;
  }
}

size_t _ykpiv_get_length(const unsigned char *buffer, const unsigned char* end, size_t *len) {
  if(buffer + 1 <= end && buffer[0] < 0x80) {
    *len = buffer[0];
    return buffer + 1 + *len <= end ? 1 : 0;
  } else if(buffer + 2 <= end && buffer[0] == 0x81) {
    *len = buffer[1];
    return buffer + 2 + *len <= end ? 2 : 0;
  } else if(buffer + 3 <= end && buffer[0] == 0x82) {
    size_t tmp = buffer[1];
    *len = (tmp << 8) + buffer[2];
    return buffer + 3 + *len <= end ? 3 : 0;
  }
  *len = 0;
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
  } else {
    return NULL;
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
  s->allocator = *allocator;
  s->verbose = verbose;
  s->context = (SCARDCONTEXT)-1;
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
  _cache_mgm_key(state, NULL, 0);
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
    if(state->verbose) {
      fprintf(stderr, "Disconnect card #%u.\n", state->serial);
    }
    SCardDisconnect(state->card, SCARD_RESET_CARD);
    state->card = 0;
  }

  if(SCardIsValidContext(state->context) == SCARD_S_SUCCESS) {
    SCardReleaseContext(state->context);
    state->context = (SCARDCONTEXT)-1;
  }

  state->serial = 0;
  state->ver.major = 0;
  state->ver.minor = 0;
  state->ver.patch = 0;

  return YKPIV_OK;
}

ykpiv_rc _ykpiv_select_application(ykpiv_state *state) {
  unsigned char templ[] = {0x00, YKPIV_INS_SELECT_APPLICATION, 0x04, 0x00};
  unsigned char data[261] = {0};
  unsigned long recv_len = sizeof(data);
  int sw;
  ykpiv_rc res = YKPIV_OK;

  if((res = _ykpiv_transfer_data(state, templ, piv_aid, sizeof(piv_aid), data, &recv_len, &sw)) != YKPIV_OK) {
    if(state->verbose) {
      fprintf(stderr, "Failed communicating with card: '%s'\n", ykpiv_strerror(res));
    }
    return res;
  }
  else if(sw != SW_SUCCESS) {
    if(state->verbose) {
      fprintf(stderr, "Failed selecting application: %04x\n", sw);
    }
    return YKPIV_GENERIC_ERROR;
  }

  /* now that the PIV application is selected, retrieve the version
   * and serial number.  Previously the NEO/YK4 required switching
   * to the yk applet to retrieve the serial, YK5 implements this
   * as a PIV applet command.  Unfortunately, this change requires
   * that we retrieve the version number first, so that get_serial
   * can determine how to get the serial number, which for the NEO/Yk4
   * will result in another selection of the PIV applet. */

  // This stores the number of PIN retries left in state
  _ykpiv_verify(state, NULL, 0);
  // WRONG_PIN or PIN_LOCKED is expected on successful query.

  res = _ykpiv_get_version(state);
  if (res != YKPIV_OK) {
    if (state->verbose) {
      fprintf(stderr, "Failed to retrieve version: '%s'\n", ykpiv_strerror(res));
    }
    return res;
  }

  res = _ykpiv_get_serial(state);
  if (res != YKPIV_OK) {
    if (state->verbose) {
      fprintf(stderr, "Failed to retrieve serial number: '%s'\n", ykpiv_strerror(res));
    }
    res = YKPIV_OK;
  }

  return res;
}

ykpiv_rc _ykpiv_ensure_application_selected(ykpiv_state *state) {
  ykpiv_rc res = YKPIV_OK;
#if ENABLE_APPLICATION_RESELECTION
  if (NULL == state) {
    return YKPIV_GENERIC_ERROR;
  }

  res = _ykpiv_verify(state, NULL, 0);

  if ((YKPIV_OK != res) && (YKPIV_WRONG_PIN != res) && (YKPIV_PIN_LOCKED != res)) {
    res = _ykpiv_select_application(state);
  }
  else {
    res = YKPIV_OK;
  }

  return res;
#else
  (void)state;
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
    char reader[CB_BUF_MAX] = {0};
    pcsc_word reader_len = sizeof(reader);
    uint8_t atr[CB_ATR_MAX] = {0};
    pcsc_word atr_len = sizeof(atr);

    // Cannot set the reader len to NULL.  Confirmed in OSX 10.10, so we have to retrieve it even though we don't need it.
    if (SCARD_S_SUCCESS != SCardStatus(card, reader, &reader_len, NULL, NULL, atr, &atr_len)) {
      return YKPIV_PCSC_ERROR;
    }

    if(atr_len + 1 == sizeof(YKPIV_ATR_NEO_R3) && !memcmp(atr, YKPIV_ATR_NEO_R3, atr_len))
      state->model = DEVTYPE_NEOr3;
    else if(atr_len + 1 == sizeof(YKPIV_ATR_NEO_R3_NFC) && !memcmp(atr, YKPIV_ATR_NEO_R3_NFC, atr_len))
      state->model = DEVTYPE_NEOr3;
    else if(atr_len + 1 == sizeof(YKPIV_ATR_YK4) && !memcmp(atr, YKPIV_ATR_YK4, atr_len))
      state->model = DEVTYPE_YK4;
    else if(atr_len + 1 == sizeof(YKPIV_ATR_YK5_P1) && !memcmp(atr, YKPIV_ATR_YK5_P1, atr_len))
      state->model = DEVTYPE_YK5;
    else if(atr_len + 1 == sizeof(YKPIV_ATR_YK5) && !memcmp(atr, YKPIV_ATR_YK5, atr_len))
      state->model = DEVTYPE_YK5;
    else if(atr_len + 1 == sizeof(YKPIV_ATR_YK5_NFC) && !memcmp(atr, YKPIV_ATR_YK5_NFC, atr_len))
      state->model = DEVTYPE_YK5;
    else
      state->model = DEVTYPE_UNKNOWN;
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

ykpiv_rc ykpiv_validate(ykpiv_state *state, const char *wanted) {
  if(state->card) {
    if(state->verbose) {
      fprintf(stderr, "Validate reader '%s'.\n", wanted);
    }
    char reader[CB_BUF_MAX] = {0};
    pcsc_word reader_len = sizeof(reader);
    uint8_t atr[CB_ATR_MAX] = {0};
    pcsc_word atr_len = sizeof(atr);
    pcsc_long rc = SCardStatus(state->card, reader, &reader_len, NULL, NULL, atr, &atr_len);
    if(rc != SCARD_S_SUCCESS) {
      if(state->verbose) {
        fprintf (stderr, "SCardStatus failed on reader '%s', rc=%lx\n", wanted, (long)rc);
      }
      rc = SCardDisconnect(state->card, SCARD_RESET_CARD);
      if(rc != SCARD_S_SUCCESS) {
        if(state->verbose) {
          fprintf (stderr, "SCardDisconnect failed on reader '%s', rc=%lx\n", wanted, (long)rc);
        }
      }
      state->card = 0;
      state->serial = 0;
      state->ver.major = 0;
      state->ver.minor = 0;
      state->ver.patch = 0;
      _cache_pin(state, NULL, 0);
      _cache_mgm_key(state, NULL, 0);
      return YKPIV_PCSC_ERROR;
    }
    if (strcmp(wanted, reader)) {
      if(state->verbose) {
        fprintf (stderr, "Disconnecting incorrect reader '%s' (wanted '%s'), rc=%lx\n", reader, wanted, (long)rc);
      }
      rc = SCardDisconnect(state->card, SCARD_RESET_CARD);
      if(rc != SCARD_S_SUCCESS) {
        if(state->verbose) {
          fprintf (stderr, "SCardDisconnect failed on reader '%s' (wanted '%s'), rc=%lx\n", reader, wanted, (long)rc);
        }
      }
      state->card = 0;
      state->serial = 0;
      state->ver.major = 0;
      state->ver.minor = 0;
      state->ver.patch = 0;
      _cache_pin(state, NULL, 0);
      _cache_mgm_key(state, NULL, 0);
      return YKPIV_GENERIC_ERROR;
    }
    return YKPIV_OK;
  }
  return YKPIV_GENERIC_ERROR;
}

ykpiv_rc ykpiv_connect(ykpiv_state *state, const char *wanted) {
  char reader_buf[2048] = {0};
  size_t num_readers = sizeof(reader_buf);
  pcsc_long rc;
  char *reader_ptr;
  ykpiv_rc ret;
  SCARDHANDLE card = (SCARDHANDLE)-1;

  if(wanted && *wanted == '@') {
    wanted++; // Skip the '@' 
    if(state->verbose) {
      fprintf(stderr, "Connect reader '%s'.\n", wanted);
    }
    if(SCardIsValidContext(state->context) != SCARD_S_SUCCESS) {
      rc = SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, &state->context);
      if (rc != SCARD_S_SUCCESS) {
        if(state->verbose) {
          fprintf (stderr, "SCardEstablishContext failed, rc=%lx\n", (long)rc);
        }
        return YKPIV_PCSC_ERROR;
      }
    }
    rc = SCardConnect(state->context, wanted, SCARD_SHARE_SHARED,
          SCARD_PROTOCOL_T0|SCARD_PROTOCOL_T1, &card, &state->protocol);
    if(rc != SCARD_S_SUCCESS)
    {
      if(state->verbose) {
        fprintf(stderr, "SCardConnect failed for '%s', rc=%lx\n", wanted, (long)rc);
      }
      SCardReleaseContext(state->context);
      state->context = (SCARDCONTEXT)-1;
      return YKPIV_PCSC_ERROR;
    } else {
      if(state->verbose > 2) {
        fprintf(stderr, "SCardConnect succeeded for '%s', protocol=%lx\n", wanted, (unsigned long)state->protocol);
      }
    }
    strncpy(state->reader, wanted, sizeof(state->reader));
    state->reader[sizeof(state->reader) - 1] = 0;
  } else
  {
    ret = ykpiv_list_readers(state, reader_buf, &num_readers);
    if(ret != YKPIV_OK) {
      return ret;
    }

    for(reader_ptr = reader_buf; *reader_ptr != '\0'; reader_ptr += strlen(reader_ptr) + 1) {
      if(wanted) {
        char *ptr = reader_ptr;
        bool found = false;
        do {
          if(strlen(ptr) < strlen(wanted)) {
            break;
          }
          if(strncasecmp(ptr, wanted, strlen(wanted)) == 0) {
            found = true;
            break;
          }
        } while(*ptr++);

        if(found == false) {
          if(state->verbose) {
            fprintf(stderr, "Skipping reader '%s' since it doesn't match '%s'.\n", reader_ptr, wanted);
          }
          continue;
        }
      }
      if(state->verbose) {
        fprintf(stderr, "Connect reader '%s' matching '%s'.\n", reader_ptr, wanted);
      }
      rc = SCardConnect(state->context, reader_ptr, SCARD_SHARE_SHARED,
            SCARD_PROTOCOL_T0|SCARD_PROTOCOL_T1, &card, &state->protocol);
      if(rc == SCARD_S_SUCCESS) {
        strncpy(state->reader, reader_ptr, sizeof(state->reader));
        state->reader[sizeof(state->reader) - 1] = 0;
        if(state->verbose > 2) {
          fprintf(stderr, "SCardConnect succeeded for '%s', protocol=%lx\n", reader_ptr, (unsigned long)state->protocol);
        }
        break;
      }
      if(state->verbose) {
        fprintf(stderr, "SCardConnect failed for '%s', rc=%lx\n", reader_ptr, (long)rc);
      }
    }

    if(*reader_ptr == '\0') {
      if(state->verbose) {
        fprintf(stderr, "No usable reader found matching '%s'.\n", wanted);
      }
      SCardReleaseContext(state->context);
      state->context = (SCARDCONTEXT)-1;
      return YKPIV_PCSC_ERROR;
    }
  }

  // at this point, card should not equal state->card, to allow _ykpiv_connect() to determine device type
  if (YKPIV_OK == _ykpiv_connect(state, state->context, card)) {
    /*
      * Select applet.  This is done here instead of in _ykpiv_connect() because
      * you may not want to select the applet when connecting to a card handle that
      * was supplied by an external library.
      */
    if (YKPIV_OK != (ret = _ykpiv_begin_transaction(state))) return ret;
#if ENABLE_APPLICATION_RESELECTION
    ret = _ykpiv_ensure_application_selected(state);
#else
    ret = _ykpiv_select_application(state);
#endif
    _ykpiv_end_transaction(state);
    return ret;
  }

  return YKPIV_GENERIC_ERROR;
}

ykpiv_rc ykpiv_list_readers(ykpiv_state *state, char *readers, size_t *len) {
  pcsc_word num_readers = 0;
  pcsc_long rc;

  if(SCardIsValidContext(state->context) != SCARD_S_SUCCESS) {
    rc = SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, &state->context);
    if (rc != SCARD_S_SUCCESS) {
      if(state->verbose) {
        fprintf (stderr, "SCardEstablishContext failed, rc=%lx\n", (long)rc);
      }
      return YKPIV_PCSC_ERROR;
    }
  }

  rc = SCardListReaders(state->context, NULL, NULL, &num_readers);
  if (rc != SCARD_S_SUCCESS) {
    if(state->verbose) {
      fprintf (stderr, "SCardListReaders failed, rc=%lx\n", (long)rc);
    }
    if(rc == SCARD_E_NO_READERS_AVAILABLE) {
      *readers = 0;
      *len = 1;
      return YKPIV_OK;
    }
    SCardReleaseContext(state->context);
    state->context = (SCARDCONTEXT)-1;
    return YKPIV_PCSC_ERROR;
  }

  if (num_readers > *len) {
    num_readers = (pcsc_word)*len;
  } else if (num_readers < *len) {
    *len = (size_t)num_readers;
  }

  rc = SCardListReaders(state->context, NULL, readers, &num_readers);
  if (rc != SCARD_S_SUCCESS)
  {
    if(state->verbose) {
      fprintf (stderr, "SCardListReaders failed, rc=%lx\n", (long)rc);
    }
    SCardReleaseContext(state->context);
    state->context = (SCARDCONTEXT)-1;
    return YKPIV_PCSC_ERROR;
  }

  *len = num_readers;

  return YKPIV_OK;
}

ykpiv_rc _ykpiv_begin_transaction(ykpiv_state *state) {
#if ENABLE_IMPLICIT_TRANSACTIONS
  int retries = 0;
  pcsc_long rc = SCardBeginTransaction(state->card);
  if (rc != SCARD_S_SUCCESS) {
    retries++;
    if(state->verbose) {
      fprintf(stderr, "SCardBeginTransaction on card #%u failed, rc=%lx\n", state->serial, (long)rc);
    }
    if (SCardIsValidContext(state->context) != SCARD_S_SUCCESS || (rc != SCARD_W_RESET_CARD && rc != SCARD_W_REMOVED_CARD)) {
      pcsc_long rc2 = SCardDisconnect(state->card, SCARD_RESET_CARD);
      if(state->verbose) {
        fprintf(stderr, "SCardDisconnect on card #%u rc=%lx\n", state->serial, (long)rc2);
      }
      state->card = 0;
    }
    if (SCardIsValidContext(state->context) != SCARD_S_SUCCESS || rc == SCARD_E_NO_SERVICE) {
      rc = SCardReleaseContext(state->context);
      if(state->verbose) {
        fprintf(stderr, "SCardReleaseContext on card #%u rc=%lx\n", state->serial, (long)rc);
      }
      state->context = 0;
      rc = SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, &state->context);
      if(state->verbose) {
        fprintf(stderr, "SCardEstablishContext on card #%u rc=%lx\n", state->serial, (long)rc);
      }
      if(rc != SCARD_S_SUCCESS) {
        return YKPIV_PCSC_ERROR;
      }
    }
    if(state->card) {
      rc = SCardReconnect(state->card, SCARD_SHARE_SHARED,
              SCARD_PROTOCOL_T0|SCARD_PROTOCOL_T1, SCARD_RESET_CARD, &state->protocol);
      if(state->verbose) {
        fprintf(stderr, "SCardReconnect on card #%u rc=%lx\n", state->serial, (long)rc);
      }
      if(rc != SCARD_S_SUCCESS) {
        return YKPIV_PCSC_ERROR;
      }
    } else {
      rc = SCardConnect(state->context, state->reader, SCARD_SHARE_SHARED,
              SCARD_PROTOCOL_T0|SCARD_PROTOCOL_T1, &state->card, &state->protocol);
      if(state->verbose) {
        fprintf(stderr, "SCardConnect on reader %s card #%u rc=%lx\n", state->reader, state->serial, (long)rc);
      }
      if(rc != SCARD_S_SUCCESS) {
        return YKPIV_PCSC_ERROR;
      }
    }
    rc = SCardBeginTransaction(state->card);
    if (rc != SCARD_S_SUCCESS) {
      if(state->verbose) {
        fprintf(stderr, "SCardBeginTransaction on card #%u failed, rc=%lx\n", state->serial, (long)rc);
      }
      return YKPIV_PCSC_ERROR;
    }
  }

  if(retries) {
    uint32_t serial = state->serial;
    state->serial = 0;
    state->ver.major = 0;
    state->ver.minor = 0;
    state->ver.patch = 0;
    ykpiv_rc res;
    if ((res = _ykpiv_select_application(state)) != YKPIV_OK)
      return res;
    if(state->serial != serial) {
      if(state->verbose) {
        fprintf(stderr, "Card #%u detected, was expecting card #%u\n", state->serial, serial);
      }
      return YKPIV_GENERIC_ERROR;
    }
    if(state->mgm_key) {
      if((res = _ykpiv_authenticate2(state, state->mgm_key, state->mgm_len)) != YKPIV_OK)
        return res;
    }
    if (state->pin) {
      if((res = _ykpiv_verify(state, state->pin, strlen(state->pin))) != YKPIV_OK)
        return res;
      // De-authenticate always-authenticate keys by running an arbitrary command
      unsigned char data[80] = {0};
      unsigned long recv_len = sizeof(data);
      if((res = _ykpiv_fetch_object(state, YKPIV_OBJ_DISCOVERY, data, &recv_len)) != YKPIV_OK)
        return res;
    }
  }
#endif /* ENABLE_IMPLICIT_TRANSACTIONS */
  return YKPIV_OK;
}

ykpiv_rc _ykpiv_end_transaction(ykpiv_state *state) {
#if ENABLE_IMPLICIT_TRANSACTIONS
  pcsc_long rc = SCardEndTransaction(state->card, SCARD_LEAVE_CARD);
  if(rc != SCARD_S_SUCCESS && state->verbose) {
    fprintf(stderr, "SCardEndTransaction on card #%u failed, rc=%lx\n", state->serial, (long)rc);
    // Ending the transaction can only fail because it's already ended - it's ended now either way so we don't fail here
  }
#endif /* ENABLE_IMPLICIT_TRANSACTIONS */
  return YKPIV_OK;
}

static const SCARD_IO_REQUEST* _pci(pcsc_word protocol) {
  switch (protocol) {
  case SCARD_PROTOCOL_T0:
    return SCARD_PCI_T0;
  case SCARD_PROTOCOL_T1:
    return SCARD_PCI_T1;
  case SCARD_PROTOCOL_RAW:
    return SCARD_PCI_RAW;
  default:
    return NULL;
  }
}

static ykpiv_rc _send_tpdu(ykpiv_state *state, const unsigned char *send_data, pcsc_word send_len,
    unsigned char *recv_data, pcsc_word *recv_len, int *sw) {
  if(state->verbose > 1) {
    fprintf(stderr, "> ");
    dump_hex(send_data, send_len);
    fprintf(stderr, " (%zu)\n", (size_t)send_len);
  }
  pcsc_long rc = SCardTransmit(state->card, _pci(state->protocol), send_data, send_len, NULL, recv_data, recv_len);
  if(rc != SCARD_S_SUCCESS) {
    if(state->verbose) {
      fprintf (stderr, "SCardTransmit on card #%u failed, rc=%lx\n", state->serial, (long)rc);
    }
    return YKPIV_PCSC_ERROR;
  }
  if(state->verbose > 1) {
    fprintf(stderr, "< ");
    dump_hex(recv_data, *recv_len);
    fprintf(stderr, " (%zu)\n", (size_t)*recv_len);
  }
  if(*recv_len >= 2) {
    *sw = (recv_data[*recv_len - 2] << 8) | recv_data[*recv_len - 1];
    *recv_len -= 2;
  } else {
    *sw = 0;
  }
  return YKPIV_OK;
}

ykpiv_rc _ykpiv_transfer_data(ykpiv_state *state,
    const unsigned char *templ,
    const unsigned char *in_data,
    unsigned long in_len,
    unsigned char *out_data,
    unsigned long *out_len,
    int *sw) {
  const unsigned char *in_ptr = in_data;
  unsigned long max_out = *out_len;
  ykpiv_rc res = YKPIV_OK;
  *out_len = 0;

  do {
    APDU apdu = {templ[0], templ[1], templ[2], templ[3], 0xff};
    unsigned char data[261] = {0};

    if(in_ptr + apdu.st.lc < in_data + in_len) {
      apdu.st.cla |= 0x10;
    } else {
      apdu.st.lc = (uint8_t)((in_data + in_len) - in_ptr);
    }
    if(apdu.st.lc) {
      memcpy(apdu.st.data, in_ptr, apdu.st.lc);
      in_ptr += apdu.st.lc;
    }
    unsigned char send_len = apdu.st.lc;
  Retry:
    if(state->verbose > 2) {
      fprintf(stderr, "Going to send %u bytes in this go.\n", send_len);
    }
    pcsc_word recv_len = sizeof(data);
    res = _send_tpdu(state, apdu.raw, send_len + 5, data, &recv_len, sw);
    if(res != YKPIV_OK) {
      goto Cleanup;
    }
    // Case 2S.3 — Process aborted; Ne not accepted, Na indicated
    if(*sw >> 8 == 0x6c) {
      apdu.st.lc = *sw & 0xff;
      goto Retry;
    }
    if(*sw != SW_SUCCESS && *sw >> 8 != 0x61) {
      goto Cleanup;
    }
    if(*out_len + recv_len > max_out) {
      if(state->verbose) {
        fprintf(stderr, "Output buffer to small, wanted to write %lu, max was %lu.\n", *out_len + recv_len, max_out);
      }
      res = YKPIV_SIZE_ERROR;
      goto Cleanup;
    }
    if(out_data) {
      memcpy(out_data, data, recv_len);
      out_data += recv_len;
      *out_len += recv_len;
    }
  } while(in_ptr < in_data + in_len);
  while(*sw >> 8 == 0x61) {
    unsigned char tpdu[] = {0, YKPIV_INS_GET_RESPONSE_APDU, 0, 0, *sw & 0xff};
    unsigned char data[261] = {0};

    if(state->verbose > 2) {
      fprintf(stderr, "The card indicates there is %u bytes more data for us.\n", tpdu[4] ? tpdu[4] : 0x100);
    }

    pcsc_word recv_len = sizeof(data);
    res = _send_tpdu(state, tpdu, sizeof(tpdu), data, &recv_len, sw);
    if(res != YKPIV_OK) {
      goto Cleanup;
    } else if(*sw != SW_SUCCESS && *sw >> 8 != 0x61) {
      goto Cleanup;
    }
    if(*out_len + recv_len > max_out) {
      if(state->verbose) {
        fprintf(stderr, "Output buffer to small, wanted to write %lu, max was %lu.", *out_len + recv_len, max_out);
      }
      res = YKPIV_SIZE_ERROR;
      goto Cleanup;
    }
    if(out_data) {
      memcpy(out_data, data, recv_len);
      out_data += recv_len;
      *out_len += recv_len;
    }
  }
Cleanup:
  return res;
}

ykpiv_rc ykpiv_transfer_data(ykpiv_state *state, const unsigned char *templ,
    const unsigned char *in_data, long in_len,
    unsigned char *out_data, unsigned long *out_len, int *sw) {
  ykpiv_rc res;

  if ((res = _ykpiv_begin_transaction(state)) != YKPIV_OK) {
    *out_len = 0;
    return res;
  }
  res = _ykpiv_transfer_data(state, templ, in_data, in_len, out_data, out_len, sw);
  _ykpiv_end_transaction(state);
  return res;
}

ykpiv_rc _ykpiv_send_apdu(ykpiv_state *state, APDU *apdu,
    unsigned char *data, unsigned long *recv_len, int *sw) {
  return _ykpiv_transfer_data(state, apdu->raw, apdu->st.data, apdu->st.lc, data, recv_len, sw);
}

static ykpiv_rc _ykpiv_get_metadata(ykpiv_state *state, const unsigned char key, unsigned char *data, unsigned long *data_len) {
  ykpiv_rc res;
  unsigned char templ[] = {0, YKPIV_INS_GET_METADATA, 0, key};
  int sw;

  if (state == NULL || data == NULL || data_len == NULL) {
    return YKPIV_ARGUMENT_ERROR;
  }

  if ((res = _ykpiv_transfer_data(state, templ, NULL, 0, data, data_len, &sw)) != YKPIV_OK) {
    goto Cleanup;
  }

  if (SW_SUCCESS != sw) {
    res = YKPIV_GENERIC_ERROR;
    if (SW_ERR_NOT_SUPPORTED == sw) {
      res = YKPIV_NOT_SUPPORTED;
    }
    if (SW_ERR_REFERENCE_NOT_FOUND == sw) {
      res = YKPIV_KEY_ERROR;
    }
    if (SW_ERR_INCORRECT_PARAM == sw) {
      res = YKPIV_ARGUMENT_ERROR;
    }
  }

Cleanup:
  return res;
}

ykpiv_rc ykpiv_authenticate(ykpiv_state *state, unsigned const char *key) {
  return ykpiv_authenticate2(state, key, DES_LEN_3DES);
}

ykpiv_rc ykpiv_authenticate2(ykpiv_state *state, unsigned const char *key, size_t len) {
  ykpiv_rc res;

  if (NULL == state) return YKPIV_GENERIC_ERROR;

  if (YKPIV_OK != (res = _ykpiv_begin_transaction(state))) return res;
  if (YKPIV_OK != (res = _ykpiv_ensure_application_selected(state))) goto Cleanup;

  res = _ykpiv_authenticate2(state, key, len);

Cleanup:
  _ykpiv_end_transaction(state);
  return res;
}

static ykpiv_rc _ykpiv_authenticate2(ykpiv_state *state, unsigned const char *key, size_t len) {
  if (NULL == state)
    return YKPIV_GENERIC_ERROR;

  if (NULL == key) {
    key = (unsigned const char*)YKPIV_MGM_DEFAULT;
    len = DES_LEN_3DES;
  }

  ykpiv_metadata metadata = {YKPIV_ALGO_3DES};
  unsigned char data[261] = {0};
  unsigned long recv_len = sizeof(data);
  ykpiv_rc res = _ykpiv_get_metadata(state, YKPIV_KEY_CARDMGM, data, &recv_len);
  if (res == YKPIV_OK) {
    res = ykpiv_util_parse_metadata(data, recv_len, &metadata);
    if (res != YKPIV_OK) {
      return res;
    }
  }

  /* set up our key */
  cipher_key mgm_key = NULL;
  cipher_rc drc = cipher_import_key(metadata.algorithm, key, len, &mgm_key);
  if (drc != CIPHER_OK) {
    if(state->verbose) {
      fprintf(stderr, "%s: cipher_import_key: %d\n", ykpiv_strerror(YKPIV_ALGORITHM_ERROR), drc);
    }
    res = YKPIV_ALGORITHM_ERROR;
    goto Cleanup;
  }

  /* get a challenge from the card */
  {
    int sw = 0;
    APDU apdu = {0};
    recv_len = sizeof(data);
    apdu.st.ins = YKPIV_INS_AUTHENTICATE;
    apdu.st.p1 = metadata.algorithm;
    apdu.st.p2 = YKPIV_KEY_CARDMGM; /* management key */
    apdu.st.lc = 0x04;
    apdu.st.data[0] = 0x7c;
    apdu.st.data[1] = 0x02;
    apdu.st.data[2] = 0x80;
    apdu.st.data[3] = 0x00;
    if ((res = _ykpiv_send_apdu(state, &apdu, data, &recv_len, &sw)) != YKPIV_OK) {
      goto Cleanup;
    }
    else if (sw != SW_SUCCESS) {
      res = YKPIV_ALGORITHM_ERROR;
      goto Cleanup;
    }
  }

  uint8_t *challenge = data + 4;
  uint32_t challenge_len = recv_len - 4;

  /* send a response to the cards challenge and a challenge of our own. */
  {
    int sw = 0;
    APDU apdu = {0};
    apdu.st.ins = YKPIV_INS_AUTHENTICATE;
    apdu.st.p1 = metadata.algorithm;
    apdu.st.p2 = YKPIV_KEY_CARDMGM; /* management key */
    unsigned char *dataptr = apdu.st.data;
    *dataptr++ = 0x7c;
    *dataptr++ = 2 + challenge_len + 2 + challenge_len;
    *dataptr++ = 0x80;
    *dataptr++ = challenge_len;
    uint32_t out_len = challenge_len;
    drc = cipher_decrypt(mgm_key, challenge, challenge_len, dataptr, &out_len);
    if (drc != CIPHER_OK) {
      if(state->verbose) {
        fprintf(stderr, "%s: cipher_decrypt: %d\n", ykpiv_strerror(YKPIV_AUTHENTICATION_ERROR), drc);
      }
      res = YKPIV_AUTHENTICATION_ERROR;
      goto Cleanup;
    }
    dataptr += out_len;
    *dataptr++ = 0x81;
    *dataptr++ = challenge_len;
    challenge = dataptr;
    if (PRNG_GENERAL_ERROR == _ykpiv_prng_generate(challenge, challenge_len)) {
      if (state->verbose) {
        fprintf(stderr, "Failed getting randomness for authentication.\n");
      }
      res = YKPIV_RANDOMNESS_ERROR;
      goto Cleanup;
    }
    dataptr += challenge_len;
    apdu.st.lc = (unsigned char)(dataptr - apdu.st.data);
    recv_len = sizeof(data);
    if ((res = _ykpiv_send_apdu(state, &apdu, data, &recv_len, &sw)) != YKPIV_OK)
    {
      goto Cleanup;
    }
    else if (sw != SW_SUCCESS) {
      res = YKPIV_AUTHENTICATION_ERROR;
      goto Cleanup;
    }
  }

  /* compare the response from the card with our challenge */
  {
    uint32_t out_len = challenge_len;
    drc = cipher_encrypt(mgm_key, challenge, challenge_len, challenge, &out_len);

    if (drc != CIPHER_OK) {
      if(state->verbose) {
        fprintf(stderr, "%s: cipher_encrypt: %d\n", ykpiv_strerror(YKPIV_AUTHENTICATION_ERROR), drc);
      }
      res = YKPIV_AUTHENTICATION_ERROR;
      goto Cleanup;
    }

    if (memcmp(data + 4, challenge, challenge_len) == 0) {
      _cache_mgm_key(state, key, len);
      res = YKPIV_OK;
    }
    else {
      res = YKPIV_AUTHENTICATION_ERROR;
    }
  }

Cleanup:

  if (mgm_key) {
    cipher_destroy_key(mgm_key);
  }

  return res;
}

ykpiv_rc ykpiv_set_mgmkey(ykpiv_state *state, const unsigned char *new_key) {
  return ykpiv_set_mgmkey2(state, new_key, YKPIV_TOUCHPOLICY_DEFAULT);
}

ykpiv_rc ykpiv_set_mgmkey2(ykpiv_state *state, const unsigned char *new_key, const unsigned char touch) {
  return ykpiv_set_mgmkey3(state, new_key, DES_LEN_3DES, YKPIV_ALGO_3DES, touch);
}

ykpiv_rc ykpiv_set_mgmkey3(ykpiv_state *state, const unsigned char *new_key, size_t len, unsigned char algo, unsigned char touch) {
  unsigned char data[261] = {0};
  ykpiv_rc res = YKPIV_OK;

  if (YKPIV_OK != (res = _ykpiv_begin_transaction(state))) return res;
  if (YKPIV_OK != (res = _ykpiv_ensure_application_selected(state))) goto Cleanup;

  if(algo == YKPIV_ALGO_AUTO || touch == YKPIV_TOUCHPOLICY_AUTO) {
    ykpiv_metadata metadata = {YKPIV_ALGO_3DES};
    unsigned long data_len = sizeof(data);
    res = _ykpiv_get_metadata(state, YKPIV_KEY_CARDMGM, data, &data_len);
    if (res == YKPIV_OK) {
      res = ykpiv_util_parse_metadata(data, data_len, &metadata);
      if (res != YKPIV_OK) {
        goto Cleanup;
      }
    }
    if(algo == YKPIV_ALGO_AUTO) {
      algo = metadata.algorithm;
    }
    if(touch == YKPIV_TOUCHPOLICY_AUTO) {
      touch = metadata.touch_policy;
    }
  }

  if (algo == YKPIV_ALGO_3DES && yk_des_is_weak_key(new_key, len)) {
    if (state->verbose) {
      fprintf(stderr, "Won't set new key '");
      dump_hex(new_key, len);
      fprintf(stderr, "' since it's weak (with odd parity).\n");
    }
    res = YKPIV_KEY_ERROR;
    goto Cleanup;
  }

  APDU apdu = {0};
  apdu.st.ins = YKPIV_INS_SET_MGMKEY;
  apdu.st.p1 = 0xff;
  if (touch <= YKPIV_TOUCHPOLICY_NEVER) {
    apdu.st.p2 = 0xff;
  }
  else if(touch == YKPIV_TOUCHPOLICY_ALWAYS) {
    apdu.st.p2 = 0xfe;
  }
  else {
    if (state->verbose) {
      fprintf(stderr, "Invalid touch policy for card management key (slot %02x).\n", YKPIV_KEY_CARDMGM);
    }
    res = YKPIV_GENERIC_ERROR;
    goto Cleanup;
  }

  apdu.st.lc = len + 3;
  apdu.st.data[0] = algo;
  apdu.st.data[1] = YKPIV_KEY_CARDMGM;
  apdu.st.data[2] = len;
  memcpy(apdu.st.data + 3, new_key, len);

  int sw = 0;
  unsigned long recv_len = sizeof(data);
  if ((res = _ykpiv_send_apdu(state, &apdu, data, &recv_len, &sw)) != YKPIV_OK) {
    goto Cleanup;
  }
  else if (sw == SW_SUCCESS) {
    _cache_mgm_key(state, new_key, len);
    goto Cleanup;
  }
  res = YKPIV_GENERIC_ERROR;

Cleanup:
  yc_memzero(&apdu, sizeof(APDU));
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
      index = (int)(ind_ptr - hex_translate);
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
  unsigned char indata[1024] = {0};
  unsigned char *dataptr = indata;
  unsigned char data[1024] = {0};
  unsigned char templ[] = {0, YKPIV_INS_AUTHENTICATE, algorithm, key};
  unsigned long recv_len = sizeof(data);
  size_t key_len = 0;
  int sw = 0;
  size_t bytes, offs;
  size_t len = 0;
  ykpiv_rc res;

  switch(algorithm) {
    case YKPIV_ALGO_RSA1024:
      key_len = 128;
      // fall through
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
      // fall through
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

  bytes = _ykpiv_get_length_size(in_len);
  
  *dataptr++ = 0x7c;
  dataptr += _ykpiv_set_length(dataptr, in_len + bytes + 3);
  *dataptr++ = 0x82;
  *dataptr++ = 0x00;
  *dataptr++ = YKPIV_IS_EC(algorithm) && decipher ? 0x85 : 0x81;
  dataptr += _ykpiv_set_length(dataptr, in_len);
  memcpy(dataptr, sign_in, in_len);
  dataptr += in_len;

  if((res = _ykpiv_transfer_data(state, templ, indata, dataptr - indata, data, &recv_len, &sw)) != YKPIV_OK) {
    if(state->verbose) {
      fprintf(stderr, "Sign command failed to communicate with status %x.\n", res);
    }
    return res;
  } else if(sw != SW_SUCCESS) {
    if(state->verbose) {
      fprintf(stderr, "Sign command failed with code %x.\n", sw);
    }
    if (sw == SW_ERR_SECURITY_STATUS)
      return YKPIV_AUTHENTICATION_ERROR;
    else if(sw != SW_SUCCESS)
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
  offs = _ykpiv_get_length(dataptr, data + recv_len, &len);
  dataptr += offs;
  /* skip the 82 tag */
  if(!offs || *dataptr != 0x82) {
    if(state->verbose) {
      fprintf(stderr, "Failed parsing signature reply.\n");
    }
    return YKPIV_PARSE_ERROR;
  }
  dataptr++;
  offs = _ykpiv_get_length(dataptr, data + recv_len, &len);
  dataptr += offs;
  if(!offs || len > *out_len) {
    if(state->verbose) {
      fprintf(stderr, "Wrong size on output buffer.\n");
    }
    return YKPIV_PARSE_ERROR;
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

  if (YKPIV_OK != (res = _ykpiv_begin_transaction(state))) return res;
  /* don't attempt to reselect in crypt operations to avoid problems with PIN_ALWAYS */
  /*if (YKPIV_OK != (res = _ykpiv_ensure_application_selected(state))) goto Cleanup;*/

  res = _general_authenticate(state, raw_in, in_len, sign_out, out_len,
                              algorithm, key, false);
/* Cleanup: */
  _ykpiv_end_transaction(state);
  return res;
}

ykpiv_rc ykpiv_decipher_data(ykpiv_state *state, const unsigned char *in,
    size_t in_len, unsigned char *out, size_t *out_len,
    unsigned char algorithm, unsigned char key) {
  ykpiv_rc res = YKPIV_OK;

  if (NULL == state) return YKPIV_GENERIC_ERROR;

  if (YKPIV_OK != (res = _ykpiv_begin_transaction(state))) return res;
  /* don't attempt to reselect in crypt operations to avoid problems with PIN_ALWAYS */
  /*if (YKPIV_OK != (res = _ykpiv_ensure_application_selected(state))) goto Cleanup;*/

  res = _general_authenticate(state, in, in_len, out, out_len,
     algorithm, key, true);

/* Cleanup: */

  _ykpiv_end_transaction(state);
  return res;
}

static ykpiv_rc _ykpiv_get_version(ykpiv_state *state) {
  unsigned char templ[] = {0x00, YKPIV_INS_GET_VERSION, 0x00, 0x00};
  unsigned char data[261] = {0};
  unsigned long recv_len = sizeof(data);
  int sw;
  ykpiv_rc res;
  
  if (!state) {
    return YKPIV_ARGUMENT_ERROR;
  }

  /* get version from state if already retrieved from device */
  if (state->ver.major || state->ver.minor || state->ver.patch) {
    return YKPIV_OK;
  }

  /* get version from device */

  if((res = _ykpiv_transfer_data(state, templ, NULL, 0, data, &recv_len, &sw)) != YKPIV_OK) {
    return res;
  } else if(sw == SW_SUCCESS) {

    /* check that we received enough data for the verson number */
    if (recv_len < 3) {
      return YKPIV_SIZE_ERROR;
    }

    state->ver.major = data[0];
    state->ver.minor = data[1];
    state->ver.patch = data[2];
  } else {
    res = YKPIV_GENERIC_ERROR;
  }

  return res;
}

ykpiv_rc ykpiv_get_version(ykpiv_state *state, char *version, size_t len) {
  ykpiv_rc res;

  if ((res = _ykpiv_begin_transaction(state)) < YKPIV_OK) return res;
  if ((res = _ykpiv_ensure_application_selected(state)) < YKPIV_OK) goto Cleanup;

  if ((res = _ykpiv_get_version(state)) >= YKPIV_OK) {
    int result = snprintf(version, len, "%d.%d.%d", state->ver.major, state->ver.minor, state->ver.patch);
    if(result <= 0 || result >= (int)len) {
      res = YKPIV_SIZE_ERROR;
    }
  }

Cleanup:

  _ykpiv_end_transaction(state);
  return res;
}

/* caller must make sure that this is wrapped in a transaction for synchronized operation */
static ykpiv_rc _ykpiv_get_serial(ykpiv_state *state) {
  ykpiv_rc res = YKPIV_OK;
  uint8_t select_templ[] = {0x00, YKPIV_INS_SELECT_APPLICATION, 0x04, 0x00};
  uint8_t data[261] = {0};
  unsigned long recv_len = sizeof(data);
  int sw;

  if (!state) {
    return YKPIV_ARGUMENT_ERROR;
  }

  /* get serial from state if already retrieved from device */
  if (state->serial != 0) {
    return YKPIV_OK;
  }

  if (state->ver.major > 0 && state->ver.major < 5) {
    /* get serial from neo/yk4 devices using the otp applet */
    uint8_t temp[261] = {0};

    recv_len = sizeof(temp);

    if ((res = _ykpiv_transfer_data(state, select_templ, yk_aid, sizeof(yk_aid), temp, &recv_len, &sw)) < YKPIV_OK) {
      if (state->verbose) {
        fprintf(stderr, "Failed communicating with card: '%s'\n", ykpiv_strerror(res));
      }
      goto Cleanup;
    }
    else if (sw != SW_SUCCESS) {
      if (state->verbose) {
        fprintf(stderr, "Failed selecting yk application: %04x\n", sw);
      }
      res = YKPIV_GENERIC_ERROR;
      goto Cleanup;
    }

    uint8_t yk_get_serial_templ[] = {0x00, 0x01, 0x10, 0x00};

    recv_len = sizeof(data);

    if ((res = _ykpiv_transfer_data(state, yk_get_serial_templ, NULL, 0, data, &recv_len, &sw)) < YKPIV_OK) {
      if (state->verbose) {
        fprintf(stderr, "Failed communicating with card: '%s'\n", ykpiv_strerror(res));
      }
      goto Cleanup;
    }
    else if (sw != SW_SUCCESS) {
      if (state->verbose) {
        fprintf(stderr, "Failed retrieving serial number: %04x\n", sw);
      }
      res = YKPIV_GENERIC_ERROR;
      goto Cleanup;
    }

    recv_len = sizeof(temp);

    if((res = _ykpiv_transfer_data(state, select_templ, piv_aid, sizeof(piv_aid), temp, &recv_len, &sw)) < YKPIV_OK) {
      if(state->verbose) {
        fprintf(stderr, "Failed communicating with card: '%s'\n", ykpiv_strerror(res));
      }
      return res;
    }
    else if(sw != SW_SUCCESS) {
      if(state->verbose) {
        fprintf(stderr, "Failed selecting application: %04x\n", sw);
      }
      return YKPIV_GENERIC_ERROR;
    }
  }
  else {
    /* get serial from yk5 and later devices using the YKPIV_INS_GET_SERIAL command */
    uint8_t yk5_get_serial_templ[] = {0x00, YKPIV_INS_GET_SERIAL, 0x00, 0x00};

    if ((res = _ykpiv_transfer_data(state, yk5_get_serial_templ, NULL, 0, data, &recv_len, &sw)) != YKPIV_OK) {
      if(state->verbose) {
        fprintf(stderr, "Failed communicating with card: '%s'\n", ykpiv_strerror(res));
      }
      return res;
    }
    else if(sw != SW_SUCCESS) {
      if(state->verbose) {
        fprintf(stderr, "Failed retrieving serial number: %04x\n", sw);
      }
      return YKPIV_GENERIC_ERROR;
    }
  }

  /* check that we received enough data for the serial number */
  if (recv_len < 4) {
    return YKPIV_SIZE_ERROR;
  }

  state->serial = data[0];
  state->serial <<= 8;
  state->serial += data[1];
  state->serial <<= 8;
  state->serial += data[2];
  state->serial <<= 8;
  state->serial += data[3];

Cleanup:

  return res;
}

ykpiv_rc ykpiv_get_serial(ykpiv_state *state, uint32_t *p_serial) {
  ykpiv_rc res = YKPIV_OK;

  if (!state || !p_serial) return YKPIV_ARGUMENT_ERROR;

  if ((res = _ykpiv_begin_transaction(state)) != YKPIV_OK) return res;
  if ((res = _ykpiv_ensure_application_selected(state)) != YKPIV_OK) goto Cleanup;

  res = _ykpiv_get_serial(state);
  *p_serial = state->serial;

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
    yc_memzero(state->pin, strnlen(state->pin, CB_PIN_MAX));
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

static ykpiv_rc _cache_mgm_key(ykpiv_state *state, unsigned const char *key, size_t len) {
#if DISABLE_MGM_KEY_CACHE
  // Some embedded applications of this library may not want to keep the MGM_KEY
  // data in RAM for security reasons.
  return YKPIV_OK;
#else
  if (!state)
    return YKPIV_ARGUMENT_ERROR;
  if (key && state->mgm_key == key) {
    return YKPIV_OK;
  }
  if (state->mgm_key) {
    yc_memzero(state->mgm_key, state->mgm_len);
    _ykpiv_free(state, state->mgm_key);
    state->mgm_key = NULL;
    state->mgm_len = 0;
  }
  if (key) {
    state->mgm_key = _ykpiv_alloc(state, len);
    if (state->mgm_key == NULL) {
      return YKPIV_MEMORY_ERROR;
    }
    memcpy(state->mgm_key, key, len);
    state->mgm_len = len;
  }
  return YKPIV_OK;
#endif
}

static ykpiv_rc _ykpiv_verify(ykpiv_state *state, const char *pin, const size_t pin_len) {

  if (pin_len > CB_PIN_MAX) {
    return YKPIV_SIZE_ERROR;
  }

  APDU apdu = {0};
  apdu.st.ins = YKPIV_INS_VERIFY;
  apdu.st.p1 = 0x00;
  apdu.st.p2 = 0x80;
  apdu.st.lc = pin ? 0x08 : 0;
  if (pin) {
    memcpy(apdu.st.data, pin, pin_len);
    if (pin_len < CB_PIN_MAX) {
      memset(apdu.st.data + pin_len, 0xff, CB_PIN_MAX - pin_len);
    }
  }

  int sw = 0;
  unsigned char data[261] = {0};
  unsigned long recv_len = sizeof(data);
  ykpiv_rc res = _ykpiv_send_apdu(state, &apdu, data, &recv_len, &sw);
  yc_memzero(&apdu, sizeof(apdu));

  if (res != YKPIV_OK) {
    state->tries = -1;
    return res;
  }
  else if (sw == SW_SUCCESS) {
    if (pin) {
      // Intentionally ignore errors.  If the PIN fails to save, it will only
      // be a problem if a reconnect is attempted.  Failure deferred until then.
      _cache_pin(state, pin, pin_len);
    }
    state->tries = -1;
    return YKPIV_OK;
  }
  else if ((sw >> 8) == 0x63) {
    if(pin)
      _cache_pin(state, NULL, 0);
    state->tries = (sw & 0xf);
    return YKPIV_WRONG_PIN;
  }
  else if (sw == SW_ERR_AUTH_BLOCKED) {
    if(pin)
      _cache_pin(state, NULL, 0);
    state->tries = 0;
    return YKPIV_PIN_LOCKED;
  }
  else {
    state->tries = -1;
    return YKPIV_GENERIC_ERROR;
  }
}

ykpiv_rc ykpiv_verify(ykpiv_state *state, const char *pin, int *tries) {
  return ykpiv_verify_select(state, pin, pin ? strlen(pin) : 0, tries, false);
}

ykpiv_rc ykpiv_verify_select(ykpiv_state *state, const char *pin, const size_t pin_len, int *tries, bool force_select) {
  ykpiv_rc res = YKPIV_OK;
  if (YKPIV_OK != (res = _ykpiv_begin_transaction(state))) return res;
  if (force_select) {
    if (YKPIV_OK != (res = _ykpiv_ensure_application_selected(state))) goto Cleanup;
  }
  res = _ykpiv_verify(state, pin, pin_len);
  if(tries) *tries = state->tries;
Cleanup:

  _ykpiv_end_transaction(state);
  return res;
}

ykpiv_rc ykpiv_get_pin_retries(ykpiv_state *state, int *tries) {
  ykpiv_rc res;

  if (NULL == state || NULL == tries) {
    return YKPIV_ARGUMENT_ERROR;
  }

  // Just get the stored value if we get the magic flag
  if(*tries == YKPIV_RETRIES_MAX) {
    *tries = state->tries;
    return YKPIV_OK;
  }

  if (YKPIV_OK != (res = _ykpiv_begin_transaction(state))) return res;

  // Force a re-select to unverify, because once verified the spec dictates that
  // subsequent verify calls will return a "verification not needed" instead of
  // the number of tries left...

  res = _ykpiv_auth_deauthenticate(state);
  if (res != YKPIV_OK) goto Cleanup;
  res = _ykpiv_select_application(state);
  if (res != YKPIV_OK) goto Cleanup;
  *tries = state->tries;
Cleanup:
  _ykpiv_end_transaction(state);
  return (res == YKPIV_WRONG_PIN || res == YKPIV_PIN_LOCKED) ? YKPIV_OK : res;
}

ykpiv_rc ykpiv_set_pin_retries(ykpiv_state *state, int pin_tries, int puk_tries) {
  ykpiv_rc res = YKPIV_OK;
  unsigned char templ[] = {0, YKPIV_INS_SET_PIN_RETRIES, 0, 0};
  unsigned char data[261] = {0};
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

  if (YKPIV_OK != (res = _ykpiv_begin_transaction(state))) return res;
  if (YKPIV_OK != (res = _ykpiv_ensure_application_selected(state))) goto Cleanup;

  res = _ykpiv_transfer_data(state, templ, NULL, 0, data, &recv_len, &sw);
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
  unsigned char indata[0x10] = {0};
  unsigned char data[261] = {0};
  unsigned long recv_len = sizeof(data);
  ykpiv_rc res;
  if (current_pin_len > CB_PIN_MAX) {
    return YKPIV_SIZE_ERROR;
  }
  if (new_pin_len > CB_PIN_MAX) {
    return YKPIV_SIZE_ERROR;
  }
  if(action == CHREF_ACT_UNBLOCK_PIN) {
    templ[1] = YKPIV_INS_RESET_RETRY;
  }
  else if(action == CHREF_ACT_CHANGE_PUK) {
    templ[3] = 0x81;
  }
  memcpy(indata, current_pin, current_pin_len);
  if(current_pin_len < CB_PIN_MAX) {
    memset(indata + current_pin_len, 0xff, CB_PIN_MAX - current_pin_len);
  }
  memcpy(indata + CB_PIN_MAX, new_pin, new_pin_len);
  if(new_pin_len < CB_PIN_MAX) {
    memset(indata + CB_PIN_MAX + new_pin_len, 0xff, CB_PIN_MAX - new_pin_len);
  }

  res = _ykpiv_transfer_data(state, templ, indata, sizeof(indata), data, &recv_len, &sw);
  yc_memzero(indata, sizeof(indata));

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

  if (YKPIV_OK != (res = _ykpiv_begin_transaction(state))) return res;
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

  if (YKPIV_OK != (res = _ykpiv_begin_transaction(state))) return res;
  if (YKPIV_OK != (res = _ykpiv_ensure_application_selected(state))) goto Cleanup;

  res = _ykpiv_change_pin(state, CHREF_ACT_CHANGE_PUK, current_puk, current_puk_len, new_puk, new_puk_len, tries);

Cleanup:
  _ykpiv_end_transaction(state);
  return res;
}

ykpiv_rc ykpiv_unblock_pin(ykpiv_state *state, const char * puk, size_t puk_len, const char * new_pin, size_t new_pin_len, int *tries) {
  ykpiv_rc res = YKPIV_GENERIC_ERROR;

  if (YKPIV_OK != (res = _ykpiv_begin_transaction(state))) return res;
  if (YKPIV_OK != (res = _ykpiv_ensure_application_selected(state))) goto Cleanup;

  res = _ykpiv_change_pin(state, CHREF_ACT_UNBLOCK_PIN, puk, puk_len, new_pin, new_pin_len, tries);

Cleanup:
  _ykpiv_end_transaction(state);
  return res;
}

ykpiv_rc ykpiv_fetch_object(ykpiv_state *state, int object_id,
    unsigned char *data, unsigned long *len) {
  ykpiv_rc res;

  if (YKPIV_OK != (res = _ykpiv_begin_transaction(state))) return res;
  if (YKPIV_OK != (res = _ykpiv_ensure_application_selected(state))) goto Cleanup;

  res = _ykpiv_fetch_object(state, object_id, data, len);

Cleanup:
  _ykpiv_end_transaction(state);
  return res;
}

ykpiv_rc _ykpiv_fetch_object(ykpiv_state *state, int object_id,
    unsigned char *data, unsigned long *len) {
  int sw;
  unsigned char indata[5] = {0};
  unsigned char *inptr = indata;
  unsigned char templ[] = {0, YKPIV_INS_GET_DATA, 0x3f, 0xff};
  ykpiv_rc res;

  inptr = set_object(object_id, inptr);
  if(inptr == NULL) {
    return YKPIV_INVALID_OBJECT;
  }

  if((res = _ykpiv_transfer_data(state, templ, indata, inptr - indata, data, len, &sw))
      != YKPIV_OK) {
    return res;
  }

  if(sw == SW_SUCCESS) {
    size_t outlen = 0;
    size_t offs = _ykpiv_get_length(data + 1, data + *len, &outlen);    
    if(!offs) {
      return YKPIV_PARSE_ERROR;
    }
    if(outlen + offs + 1 != *len) {
      if(state->verbose) {
        fprintf(stderr, "Invalid length indicated in object, total objlen is %lu, indicated length is %lu.", *len, (unsigned long)outlen);
      }
      return YKPIV_SIZE_ERROR;
    }
    memmove(data, data + 1 + offs, outlen);
    *len = (unsigned long)outlen;
    return YKPIV_OK;
  } else {
    if (SW_ERR_FILE_NOT_FOUND == sw) {
      return YKPIV_INVALID_OBJECT;
    }
    if (SW_ERR_SECURITY_STATUS == sw) {
      return YKPIV_AUTHENTICATION_ERROR;
    }
    if(state->verbose) {
      fprintf(stderr, "Failed to get data for object %x with status %x\n", object_id, sw);
    }
    return YKPIV_GENERIC_ERROR;
  }
}

ykpiv_rc ykpiv_save_object(ykpiv_state *state, int object_id,
    unsigned char *indata, size_t len) {
  ykpiv_rc res;

  if (YKPIV_OK != (res = _ykpiv_begin_transaction(state))) return res;
  if (YKPIV_OK != (res = _ykpiv_ensure_application_selected(state))) goto Cleanup;

  res = _ykpiv_save_object(state, object_id, indata, len);

Cleanup:
  _ykpiv_end_transaction(state);
  return res;
}

ykpiv_rc _ykpiv_save_object(
    ykpiv_state *state,
    int object_id,
    unsigned char *indata,
    size_t len) {
  unsigned char data[CB_BUF_MAX] = {0};
  unsigned char *dataptr = data;
  unsigned char templ[] = {0, YKPIV_INS_PUT_DATA, 0x3f, 0xff};
  int sw;
  ykpiv_rc res;
  unsigned long outlen = 0;

  dataptr = set_object(object_id, dataptr);
  if(dataptr == NULL) {
    return YKPIV_INVALID_OBJECT;
  }
  *dataptr++ = 0x53;
  dataptr += _ykpiv_set_length(dataptr, len);
  if(dataptr + len > data + sizeof(data)) {
    return YKPIV_SIZE_ERROR;
  }
  if(indata)
    memcpy(dataptr, indata, len);
  dataptr += len;

  if((res = _ykpiv_transfer_data(state, templ, data, dataptr - data, NULL, &outlen,
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

  unsigned char key_data[1024] = {0};
  unsigned char *in_ptr = key_data;
  unsigned char templ[] = {0, YKPIV_INS_IMPORT_KEY, algorithm, key};
  unsigned char data[261] = {0};
  unsigned long recv_len = sizeof(data);
  unsigned elem_len;
  int sw;
  const unsigned char *params[5] = {0};
  size_t lens[5] = {0};
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
      /* This can never be true, but check to be explicit. */
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
      res = YKPIV_ALGORITHM_ERROR;
      goto Cleanup;
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

  if (YKPIV_OK != (res = _ykpiv_begin_transaction(state))) return res;
  if (YKPIV_OK != (res = _ykpiv_ensure_application_selected(state))) goto Cleanup;

  if ((res = _ykpiv_transfer_data(state, templ, key_data, in_ptr - key_data, data, &recv_len, &sw)) != YKPIV_OK) {
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
  yc_memzero(key_data, sizeof(key_data));
  _ykpiv_end_transaction(state);
  return res;
}

ykpiv_rc ykpiv_attest(ykpiv_state *state, const unsigned char key, unsigned char *data, size_t *data_len) {
  ykpiv_rc res;
  unsigned char templ[] = {0, YKPIV_INS_ATTEST, key, 0};
  int sw;
  unsigned long ul_data_len;

  if (state == NULL || data == NULL || data_len == NULL) {
    return YKPIV_ARGUMENT_ERROR;
  }

  ul_data_len = (unsigned long)*data_len;

  if (YKPIV_OK != (res = _ykpiv_begin_transaction(state))) return res;
  if (YKPIV_OK != (res = _ykpiv_ensure_application_selected(state))) goto Cleanup;

  if ((res = _ykpiv_transfer_data(state, templ, NULL, 0, data, &ul_data_len, &sw)) != YKPIV_OK) {
    goto Cleanup;
  }
  if (SW_SUCCESS != sw) {
    res = YKPIV_GENERIC_ERROR;
    if (SW_ERR_NOT_SUPPORTED == sw) {
      res = YKPIV_NOT_SUPPORTED;
    }
    if (SW_ERR_REFERENCE_NOT_FOUND == sw) {
      res = YKPIV_KEY_ERROR;
    }
    if (SW_ERR_INCORRECT_PARAM == sw) {
      res = YKPIV_ARGUMENT_ERROR;
    }
    goto Cleanup;
  }
  if (data[0] != 0x30) {
    res = YKPIV_GENERIC_ERROR;
    goto Cleanup;
  }

  *data_len = (size_t)ul_data_len;

Cleanup:
  _ykpiv_end_transaction(state);
  return res;
}

ykpiv_rc ykpiv_get_metadata(ykpiv_state *state, const unsigned char key, unsigned char *data, size_t *data_len) {
  ykpiv_rc res;
  unsigned long ul_data_len;

  if (state == NULL || data == NULL || data_len == NULL) {
    return YKPIV_ARGUMENT_ERROR;
  }

  ul_data_len = (unsigned long)*data_len;

  if (YKPIV_OK != (res = _ykpiv_begin_transaction(state))) return res;
  if (YKPIV_OK != (res = _ykpiv_ensure_application_selected(state))) goto Cleanup;

  res = _ykpiv_get_metadata(state, key, data, &ul_data_len);

Cleanup:
  *data_len = ul_data_len;
  _ykpiv_end_transaction(state);
  return res;
}

ykpiv_rc ykpiv_auth_getchallenge(ykpiv_state *state, uint8_t *challenge, size_t *challenge_len) {
  ykpiv_rc res;
  
  if (NULL == state) return YKPIV_GENERIC_ERROR;
  if (NULL == challenge) return YKPIV_GENERIC_ERROR;
  if (NULL == challenge_len) return YKPIV_GENERIC_ERROR;

  if (YKPIV_OK != (res = _ykpiv_begin_transaction(state))) return res;
  if (YKPIV_OK != (res = _ykpiv_ensure_application_selected(state))) goto Cleanup;

  ykpiv_metadata metadata = {YKPIV_ALGO_3DES};
  unsigned char data[261] = {0};
  unsigned long recv_len = sizeof(data);
  res = _ykpiv_get_metadata(state, YKPIV_KEY_CARDMGM, data, &recv_len);
  if (res == YKPIV_OK) {
    res = ykpiv_util_parse_metadata(data, recv_len, &metadata);
    if (res != YKPIV_OK) {
      goto Cleanup;
    }
  }

  /* get a challenge from the card */
  APDU apdu = {0};
  apdu.st.ins = YKPIV_INS_AUTHENTICATE;
  apdu.st.p1 = metadata.algorithm;
  apdu.st.p2 = YKPIV_KEY_CARDMGM; /* management key */
  apdu.st.lc = 0x04;
  apdu.st.data[0] = 0x7c;
  apdu.st.data[1] = 0x02;
  apdu.st.data[2] = 0x81; //0x80;
  apdu.st.data[3] = 0x00;
  int sw = 0;
  recv_len = sizeof(data);
  if ((res = _ykpiv_send_apdu(state, &apdu, data, &recv_len, &sw)) != YKPIV_OK)
  {
    goto Cleanup;
  }
  else if (sw != SW_SUCCESS) {
    res = YKPIV_AUTHENTICATION_ERROR;
    goto Cleanup;
  }

  if(*challenge_len >= recv_len - 4) {
    *challenge_len = recv_len - 4;
    memcpy(challenge, data + 4, *challenge_len);
  } else {
    *challenge_len = recv_len - 4;
    res = YKPIV_SIZE_ERROR;
  }

Cleanup:

  _ykpiv_end_transaction(state);
  return res;
}

ykpiv_rc ykpiv_auth_verifyresponse(ykpiv_state *state, uint8_t *response, size_t response_len) {
  ykpiv_rc res;

  if (NULL == state) return YKPIV_GENERIC_ERROR;
  if (NULL == response) return YKPIV_GENERIC_ERROR;

  if (YKPIV_OK != (res = _ykpiv_begin_transaction(state))) return res;
  /* note: do not select the applet here, as it resets the challenge state */

  ykpiv_metadata metadata = {YKPIV_ALGO_3DES};
  unsigned char data[261] = {0};
  unsigned long recv_len = sizeof(data);
  res = _ykpiv_get_metadata(state, YKPIV_KEY_CARDMGM, data, &recv_len);
  if (res == YKPIV_OK) {
    res = ykpiv_util_parse_metadata(data, recv_len, &metadata);
    if (res != YKPIV_OK) {
      goto Cleanup;
    }
  }

  /* send the response to the card and a challenge of our own. */
  APDU apdu = {0};
  apdu.st.ins = YKPIV_INS_AUTHENTICATE;
  apdu.st.p1 = metadata.algorithm;
  apdu.st.p2 = YKPIV_KEY_CARDMGM; /* management key */
  unsigned char *dataptr = apdu.st.data;
  *dataptr++ = 0x7c;
  *dataptr++ = 2 + response_len;
  *dataptr++ = 0x82;
  *dataptr++ = response_len;
  memcpy(dataptr, response, response_len);
  dataptr += response_len;
  apdu.st.lc = (unsigned char)(dataptr - apdu.st.data);
  int sw = 0;
  recv_len = sizeof(data);
  if ((res = _ykpiv_send_apdu(state, &apdu, data, &recv_len, &sw)) != YKPIV_OK)
  {
    goto Cleanup;
  }
  else if (sw != SW_SUCCESS) {
    res = YKPIV_AUTHENTICATION_ERROR;
    goto Cleanup;
  }

Cleanup:

  yc_memzero(&apdu, sizeof(apdu));
  _ykpiv_end_transaction(state);
  return res;
}

/* deauthenticates the user pin and mgm key */
ykpiv_rc ykpiv_auth_deauthenticate(ykpiv_state *state) {
  ykpiv_rc res = YKPIV_OK;

  if (NULL == state) return YKPIV_GENERIC_ERROR;

  if (YKPIV_OK != (res = _ykpiv_begin_transaction(state))) return res;

  res = _ykpiv_auth_deauthenticate(state);

  _ykpiv_end_transaction(state);
  return res;
}

/* deauthenticates the user pin and mgm key */
static ykpiv_rc _ykpiv_auth_deauthenticate(ykpiv_state *state) {
  ykpiv_rc res = YKPIV_OK;
  unsigned char templ[] = {0x00, YKPIV_INS_SELECT_APPLICATION, 0x04, 0x00};
  unsigned char data[261] = {0};
  unsigned long recv_len = sizeof(data);
  const unsigned char *aid;
  unsigned long aid_len;
  int sw;

  if (!state) {
    return YKPIV_ARGUMENT_ERROR;
  }

  // Once mgmt_aid is selected on NEO we can't select piv_aid again... So we use yk_aid.
  // But... YK 5 below 5.3 doesn't allow access to yk_aid, so still use mgmt_aid on non-NEO devices

  if (state->ver.major < 4) {
    aid = yk_aid;
    aid_len = sizeof(yk_aid);
  } else {
    aid = mgmt_aid;
    aid_len = sizeof(mgmt_aid);
  }

  if ((res = _ykpiv_transfer_data(state, templ, aid, aid_len, data, &recv_len, &sw)) < YKPIV_OK) {
    if (state->verbose) {
      fprintf(stderr, "Failed communicating with card: '%s'\n", ykpiv_strerror(res));
    }
    return res;
  }
  else if (sw != SW_SUCCESS) {
    if (state->verbose) {
      fprintf(stderr, "Failed selecting mgmt/yk application: %04x\n", sw);
    }
    return YKPIV_GENERIC_ERROR;
  }

  return res;
}
