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
#include <stdarg.h>
#include <stdio.h>
#include <stdint.h>
#include <ctype.h>

#include "internal.h"
#include "ykpiv.h"
#include "scp11_util.h"
#include "ecdh.h"
#ifndef _WIN32
#include "../common/util.h"
#endif
#include "../aes_cmac/aes.h"

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
static ykpiv_rc _ykpiv_verify(ykpiv_state *state, char *pin, size_t *pin_len, bool bio, bool verify_spin);
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

static unsigned const char sd_aid[] = {
  0xa0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00, 0x00
};


//INTERNAL AUTHENTICATE Data Field as defined in GPC 2.3 F SCP11 v1.4 PublicRelease
// TLV: '0xA6' = Control Reference Template (Key Agreement), 13 bytes, the following 4 TLVs
//     TLV: '0x90' = SCP identifier and parameters, 2 bytes, SCP11 ID (0x11), SCP11b ID (0x00)
//     TLV: '0x95' = Key Usage Qualifier, 1 byte, 0x3c = Secure messaging with C-MAC, R-MAC, and encryption
//     TLV: '0x80' = Key type, 1 byte, AES key (0x88)
//     TLV: '0x81' = Key length, 1 byte, 16
// TLV: '0x5F49' = ePK.OCE.ECKA
static unsigned const char scp11_keyagreement_template[] = {
        0xa6, 13,
        0x90, 2, 0x11, 0x00, 0x95, 1, SCP11_KEY_USAGE, 0x80, 1, SCP11_KEY_TYPE, 0x81, 1, SCP11_SESSION_KEY_LEN,
        SCP11_ePK_SD_ECKA_TAG >> 8, SCP11_ePK_SD_ECKA_TAG & 0xff
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

static ykpiv_rc pcsc_to_yrc(pcsc_long rc) {
  switch(rc) {
    case SCARD_E_NO_SERVICE:
    case SCARD_E_SERVICE_STOPPED:
      return YKPIV_PCSC_SERVICE_ERROR;
    default:
      return YKPIV_PCSC_ERROR;
  }
}

static void ykpiv_stderr_debug(const char *buf) {
  fprintf(stderr, "%s\n", buf);
}

static void (*ykpiv_debug)(const char *) = ykpiv_stderr_debug;
static int ykpiv_verbose = 0;

void _ykpiv_set_debug(void (*dbg)(const char *)) {
  ykpiv_debug = dbg ? dbg : ykpiv_stderr_debug;
}

void _ykpiv_debug(const char *file, int line, const char *func, int lvl, const char *format, ...) {
  if(lvl <= ykpiv_verbose) {
    char buf[8192];
#ifdef _WIN32
    const char *name = strrchr(file, '\\');
#else
    const char *name = strrchr(file, '/');
#endif
    if(snprintf(buf, sizeof(buf), "DBG %s:%d (%s): ", name ? name + 1 : file, line, func) < 0) {
      buf[0] = 0;
    }
    size_t len = strlen(buf);
    va_list args;
    va_start(args, format);
    if(vsnprintf(buf + len, sizeof(buf) - len, format, args) < 0) {
      buf[len] = 0;
    }
    if(format[0] && format[strlen(format) - 1] == '@') { // Format ends with marker, expect two extra args
      len = strlen(buf) - 1; // Overwrite the marker
      uint8_t *p = va_arg(args, uint8_t *);
      size_t n = va_arg(args, size_t);
      for(size_t i = 0; i < n; i++) {
        if(snprintf(buf + len, sizeof(buf) - len, "%02x", p[i]) < 0) {
          buf[len] = 0;
        }
        len = strlen(buf);
      }
      if(snprintf(buf + len, sizeof(buf) - len, " (%zu)", n) < 0) {
        buf[len] = 0;
      }
    }
    va_end(args);
    ykpiv_debug(buf);
  }
}

ykpiv_rc ykpiv_init_with_allocator(ykpiv_state **state, int verbose, const ykpiv_allocator *allocator) {
  ykpiv_state *s;
  if (NULL == state) {
    return YKPIV_ARGUMENT_ERROR;
  }
  if (NULL == allocator || !allocator->pfn_alloc || !allocator->pfn_realloc || !allocator->pfn_free) {
    return YKPIV_MEMORY_ERROR;
  }

  s = allocator->pfn_alloc(allocator->alloc_data, sizeof(ykpiv_state));
  if (NULL == s) {
    return YKPIV_MEMORY_ERROR;
  }

  ykpiv_verbose = verbose;

  memset(s, 0, sizeof(ykpiv_state));
  s->allocator = *allocator;
  s->context = (SCARDCONTEXT)-1;
  *state = s;
  ecdh_init();
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
  ecdh_done();
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
    DBG("Disconnect card #%u.", state->serial);
    pcsc_long rc = SCardDisconnect(state->card, SCARD_RESET_CARD);
    if(rc != SCARD_S_SUCCESS) {
      DBG("SCardDisconnect failed on card #%u rc=%lx", state->serial, (long)rc);
    }
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

typedef struct {
    uint8_t tag;
    size_t length;
    uint8_t *value;
} _tlv;

static uint8_t next_tlv(uint8_t *ptr, uint8_t *end, _tlv *tlv) {
  if(ptr + 1 > end) {
    DBG("Tag offset is not within range");
    return 0;
  }
  tlv->tag = *ptr;
  size_t len = _ykpiv_get_length(ptr + 1, end, &tlv->length);
  if(len == 0) {
    DBG("Length index not within data range");
    return 0;
  }
  if (ptr + 1 + len + tlv->length > end) {
    DBG("Tag value too long for available data");
    return 0;
  }
  tlv->value = ptr + 1 + len;
  return tlv->tag;
}


static ykpiv_rc skip_next_tlv(uint8_t **ptr, uint8_t *end, uint8_t expected_tag, const char *tag_str) {
  _tlv tlv = {0};
  if(next_tlv(*ptr, end, &tlv) != expected_tag) {
    DBG("Failed to parse data. Expected tag for %s was %x, found %x", tag_str, expected_tag, tlv.tag);
    return YKPIV_PARSE_ERROR;
  }
  *ptr = tlv.value + tlv.length;
  return YKPIV_OK;
}

static uint8_t *
get_pubkey_offset(uint8_t *cert_ptr, uint8_t *cert_end, size_t pubkey_len, uint8_t *algo, size_t algo_len) {
  //DER structure:
  //subjectPublicKeyInfo SubjectPublicKeyInfo SEQUENCE (2 elem)
  //    algorithm AlgorithmIdentifier SEQUENCE (2 elem)
  //        algorithm OBJECT IDENTIFIER 1.2.840.10045.2.1 ecPublicKey (ANSI X9.62 public key type)
  //        parameters ANY OBJECT IDENTIFIER 1.2.840.10045.3.1.7 prime256v1 (ANSI X9.62 named elliptic curve)
  //    subjectPublicKey BIT STRING (520 bit)

  //subjectPublicKeyInfo SubjectPublicKeyInfo SEQUENCE (2 elem)
  _tlv pubkey_info = {0};
  if (next_tlv(cert_ptr, cert_end, &pubkey_info) != 0x30) {
    DBG("Failed to parse certificate. Expected tag for subjectPublicKeyInfo SEQUENCE was 0x30, found %x",
        pubkey_info.tag);
    return 0;
  }

  //    algorithm AlgorithmIdentifier SEQUENCE (2 elem)
  //        algorithm OBJECT IDENTIFIER 1.2.840.10045.2.1 ecPublicKey (ANSI X9.62 public key type)
  //        parameters ANY OBJECT IDENTIFIER 1.2.840.10045.3.1.7 prime256v1 (ANSI X9.62 named elliptic curve)
  _tlv algo_oid = {0};
  if (next_tlv(pubkey_info.value, cert_end, &algo_oid) != 0x30) {
    DBG("Failed to parse certificate. Expected tag for subjectPublicKeyInfo.algorithm SEQUENCE was 0x30, found %x",
        algo_oid.tag);
    return NULL;
  }
  if (algo_oid.length != algo_len) {
    DBG("Failed to parse certificate. Unexpected length of public key algorithm data");
    return 0;
  }
  if (memcmp(algo, algo_oid.value, algo_len) != 0) {
    DBG("Failed to parse certificate. Unexpected public key algorithm data");
    return 0;
  }

  //    subjectPublicKey BIT STRING (520 bit)
  _tlv pubkey = {0};
  if (next_tlv(algo_oid.value + algo_oid.length, cert_end, &pubkey) != 0x03) {
    DBG("Failed to parse certificate. Expected tag for subjectPublicKeyInfo.algorithm SEQUENCE was 0x30, found %x",
        algo_oid.tag);
    return NULL;
  }
  if (pubkey.value && (*(pubkey.value) == 0)) {
    pubkey.value++;
    pubkey.length--;
  }
  if (pubkey.length != pubkey_len) {
    DBG("Failed to parse certificate. Unexpected length of public key data");
    return 0;
  }

  return pubkey.value;
}

static ykpiv_rc
scp11_get_sd_pubkey(ykpiv_state *state, uint8_t *pubkey, size_t *pubkey_len, uint8_t *algo, size_t algo_len) {
   ykpiv_rc rc;

  // Select the globalplatform application
  unsigned char templ[] = {0x00, YKPIV_INS_SELECT_APPLICATION, 0x04, 0x00};
  unsigned long recv_len;
  int sw = 0;

  if ((rc = _ykpiv_transfer_data(state, templ, sd_aid, sizeof(sd_aid), NULL, &recv_len, &sw)) != YKPIV_OK) {
    *pubkey_len = 0;
    return rc;
  }
  rc = ykpiv_translate_sw_ex(__FUNCTION__, sw);
  if (rc != YKPIV_OK) {
    DBG("Failed selecting application");
    *pubkey_len = 0;
    return rc;
  }

  unsigned char apdu[] = {0x00, GP_INS_GET_DATA, SCP11_CERTIFICATE_STORE_TAG >> 8, SCP11_CERTIFICATE_STORE_TAG & 0xff};
  unsigned char apdu_data[6] = {0xa6, 0x04, 0x83, 0x2, SCP11B_KID, SCP11B_KVN};
  unsigned char certchain[YKPIV_OBJ_MAX_SIZE] = {0};
  unsigned long certchain_len = sizeof(certchain);

  if ((rc = _ykpiv_transfer_data(state, apdu, apdu_data, sizeof(apdu_data), certchain, &certchain_len, &sw)) !=
      YKPIV_OK) {
    DBG("Failed to communicate with device. res: %d    sw: %08x", rc, sw);
    *pubkey_len = 0;
    return rc;
  }
  rc = ykpiv_translate_sw_ex(__FUNCTION__, sw);
  if (rc != YKPIV_OK) {
    DBG("Failed to get SCP11 SD public key (CERT.SD.ECKA). res: %d    sw: %08x", rc, sw);
    *pubkey_len = 0;
    return rc;
  }

  // Find the last certificate in the chain
  // Good resources about parsing certificate data: https://lapo.it/asn1js and https://letsencrypt.org/docs/a-warm-welcome-to-asn1-and-der/
  uint8_t *ptr = certchain;
  uint8_t *end = certchain + certchain_len;
  size_t len = 0;
  do {
    ptr += len; // skip the previous certificate
    if (*ptr != 0x30) {
      DBG("Failed to parse data as certificate chain. Data does not start with a SEQUENCE in DER format");
      *pubkey_len = 0;
      return YKPIV_PARSE_ERROR;
    }
    ptr++; // skip the next 0x30 tag
    ptr += _ykpiv_get_length(ptr, end, &len); // skip the length bytes
  } while (ptr + len < end); // if we haven't reached the end of the data, skip to the next certificate

  // Now we go into the TBScertificate data
  if (*ptr != 0x30) {
    DBG("Failed to parse data as certificate. Data does not start with a SEQUENCE in DER format");
    return YKPIV_PARSE_ERROR;
  }
  ptr++; // skip the 0x30 tag starting the TBSCertificate
  ptr += _ykpiv_get_length(ptr, end, &len); // skip the length bytes for the TBSCertificate

  if(*ptr == 0xa0) { // If certificate version is present, skip it
    if ((rc = skip_next_tlv(&ptr, end, 0xa0, "Certificate Version")) != YKPIV_OK) { return rc; }
  }
  if ((rc = skip_next_tlv(&ptr, end, 0x02, "SerialNumber")) != YKPIV_OK) { return rc; }
  if ((rc = skip_next_tlv(&ptr, end, 0x30, "Signature Algorithm SEQUENCE")) != YKPIV_OK) { return rc; }
  if ((rc = skip_next_tlv(&ptr, end, 0x30, "Issuer SEQUENCE")) != YKPIV_OK) { return rc; }
  if ((rc = skip_next_tlv(&ptr, end, 0x30, "Validity SEQUENCE")) != YKPIV_OK) { return rc; }
  if ((rc = skip_next_tlv(&ptr, end, 0x30, "Subject SEQUENCE")) != YKPIV_OK) { return rc; }

  if ((ptr = get_pubkey_offset(ptr, end, *pubkey_len, algo, algo_len)) == 0) {
    DBG("Failed to find public key in certificate data");
    return YKPIV_PARSE_ERROR;
  }

  memcpy(pubkey, ptr, *pubkey_len);
  return YKPIV_OK;
}

static ykpiv_rc scp11_derive_session_keys(uint8_t *oce_privkey, size_t oce_privkey_len, uint8_t *sde_pubkey,
                                          size_t sde_pubkey_len, uint8_t *sd_pubkey, size_t sd_pubkey_len,
                                          uint8_t *session_keys) {
  size_t ecdh_len = SCP11_SESSION_KEY_LEN * 2;
  uint8_t sh_see[SCP11_SESSION_KEY_LEN * 2] = {0};
  uint8_t sh_ses[SCP11_SESSION_KEY_LEN * 2] = {0};
  size_t len = ecdh_calculate_secret(ecdh_curve_p256(), oce_privkey, oce_privkey_len, sde_pubkey, sde_pubkey_len,
                                     sh_see, ecdh_len);
  if (len != ecdh_len) {
    DBG("Failed to derive ECDH shared key (ShSee). ECDH length does not match. Expected %d. Found %d", ecdh_len, len);
    return YKPIV_AUTHENTICATION_ERROR;
  }

  len = ecdh_calculate_secret(ecdh_curve_p256(), oce_privkey, oce_privkey_len, sd_pubkey, sd_pubkey_len, sh_ses,
                              ecdh_len);
  if (len != ecdh_len) {
    DBG("Failed to derive ECDH shared key (SHSes). ECDH length does not match. Expected %d. Found %d", ecdh_len, len);
    return YKPIV_AUTHENTICATION_ERROR;
  }

  // Hash data: sh_see + sh_ses + 4 bytes counter with initial value 0 + shared_data
  uint8_t shared_data[] = {SCP11_KEY_USAGE, SCP11_KEY_TYPE, SCP11_SESSION_KEY_LEN};
  size_t hash_data_len = (ecdh_len * 2) + 4 + sizeof(shared_data);
  uint8_t hash_data[(SCP11_SESSION_KEY_LEN * 4) + 7] = {0};
  memcpy(hash_data, sh_see, ecdh_len);
  memcpy(hash_data + ecdh_len, sh_ses, ecdh_len);
  memcpy(hash_data + hash_data_len - sizeof(shared_data), shared_data, sizeof(shared_data));
  // We will only need to increase the counter 3 times (to the value 3) so it will only occupy 1 byte
  size_t counter_index = (ecdh_len * 2) + 3;
  // We need 5 keys, 16 bytes each. Each iteration produces 32 bytes, so we need to run 3 iteration to get at least 5
  for (int i = 0; i < 3; i++) {
    hash_data[counter_index]++;
    hash_sha256(hash_data, hash_data_len, session_keys + (i * ecdh_len));
  }
  return YKPIV_OK;
}

static ykpiv_rc scp11_internal_authenticate(ykpiv_state *state, uint8_t *data, size_t data_len,
                                            uint8_t* epubkey_sd, size_t* epubkey_sd_len, uint8_t* receipt) {

  uint8_t apdu[] = {0x80, GP_INS_INTERNAL_AUTHENTICATE, SCP11B_KVN, SCP11B_KID};

  ykpiv_rc rc;
  uint8_t recv[YKPIV_OBJ_MAX_SIZE] = {0};
  unsigned long recv_len = sizeof(recv);
  int sw = 0;
  if ((rc = _ykpiv_transfer_data(state, apdu, data, (unsigned long)data_len, recv, &recv_len, &sw)) != YKPIV_OK) {
    return rc;
  }
  rc = ykpiv_translate_sw_ex(__FUNCTION__, sw);
  if (rc != YKPIV_OK) {
    DBG("Failed to get SCP11b public key. res: %d    sw: %08x", rc, sw);
    return rc;
  }

  if ((recv[0] != (SCP11_ePK_SD_ECKA_TAG >> 8)) || (recv[1] != (SCP11_ePK_SD_ECKA_TAG & 0xff))) {
    DBG("Received response for INTERNAL AUTHENTICATE command does not start with 0x5F49 (ePK.SD.ECKA)");
    return YKPIV_AUTHENTICATION_ERROR;
  }

  uint8_t *ptr = recv + 2;
  if (*ptr > *epubkey_sd_len) {
    DBG("Buffer size too small. Found key length %d", *ptr);
    return YKPIV_SIZE_ERROR;
  }
  *epubkey_sd_len = *ptr;
  ptr++;
  memcpy(epubkey_sd, ptr, *epubkey_sd_len);
  ptr += *epubkey_sd_len;

  if (*ptr != 0x86) { // Receipt TLV tag
    DBG("Received response for INTERNAL AUTHENTICATE command does not contains no receipt");
    return YKPIV_AUTHENTICATION_ERROR;
  }
  ptr++;
  if (*ptr != SCP11_MAC_LEN) {
    DBG("Wrong receipt length. Expected 16. Found %d\n", (*ptr));
    return YKPIV_AUTHENTICATION_ERROR;
  }
  ptr++;

  memcpy(receipt, ptr, SCP11_MAC_LEN);

  return YKPIV_OK;
}

static ykpiv_rc
scp11_verify_channel(uint8_t *verification_key, uint8_t *receipt, uint8_t *apdu_data, uint32_t apdu_data_len,
                     uint8_t *epubkey_sd, size_t epubkey_sd_len) {
  uint32_t ka_data_len = apdu_data_len + (uint32_t)epubkey_sd_len + 3;
  uint8_t *ka_data = malloc(ka_data_len);
  if (!ka_data) {
    DBG("Failed to allocate memory for key agreement data");
    return YKPIV_MEMORY_ERROR;
  }
  memcpy(ka_data, apdu_data, apdu_data_len);
  ka_data[apdu_data_len] = SCP11_ePK_SD_ECKA_TAG >> 8;
  ka_data[apdu_data_len + 1] = SCP11_ePK_SD_ECKA_TAG & 0xff;
  ka_data[apdu_data_len + 2] = (uint8_t)epubkey_sd_len;
  memcpy(ka_data + apdu_data_len + 3, epubkey_sd, epubkey_sd_len);

  ykpiv_rc rc = YKPIV_OK;
  uint8_t mac_out[SCP11_MAC_LEN] = {0};
  if ((rc = scp11_mac_data(verification_key, NULL, ka_data, ka_data_len, mac_out)) != YKPIV_OK) {
    DBG("Failed to calculate CMAC value");
    goto sc_verify_cleanup;
  }

  if (memcmp(mac_out, receipt, SCP11_MAC_LEN) != 0) {
    DBG("Failed to verify SCP11 connection");
    rc = YKPIV_AUTHENTICATION_ERROR;
    goto sc_verify_cleanup;
  }

sc_verify_cleanup:
  if (ka_data) {
    free(ka_data);
  }
  return rc;
 }

ykpiv_rc scp11_open_secure_channel(ykpiv_state *state) {
  ykpiv_rc rc;

  //DER encode:
  // 0x06 tag for OID followed by the length the OID (7 bytes) followed by the OID representing EC PublicKey
  // 0x06 tag for OID followed by the length the OID (8 bytes) followed by the OID representing prime256v1 curve
  uint8_t sd_pubkey_algo[] = {0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01,
                              0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07};
  uint8_t oce_privkey[32] = {0};
  size_t oce_privkey_len = sizeof(oce_privkey);
  uint8_t oce_pubkey[65] = {0};
  size_t oce_pubkey_len = sizeof(oce_pubkey);
  uint8_t sd_pubkey[65] = {0};
  size_t sd_pubkey_len = sizeof(sd_pubkey);
  uint8_t data[1024] = {0};
  size_t data_len = sizeof(data);

  if ((rc = scp11_get_sd_pubkey(state, sd_pubkey, &sd_pubkey_len, sd_pubkey_algo, sizeof(sd_pubkey_algo))) != YKPIV_OK) {
    DBG("Failed to get SD public key (PK.SD.ECKA)");
    return rc;
  }

  // Select the PIV application
  unsigned char select_templ[] = {0x00, YKPIV_INS_SELECT_APPLICATION, 0x04, 0x00};
  unsigned long recv_len;
  int sw = 0;
  if ((rc = _ykpiv_transfer_data(state, select_templ, piv_aid, sizeof(piv_aid), NULL, &recv_len, &sw)) != YKPIV_OK) {
    return rc;
  }
  if ((rc = ykpiv_translate_sw_ex(__FUNCTION__, sw)) != YKPIV_OK) {
    DBG("Failed selecting application");
    return rc;
  }

  if (!ecdh_generate_keypair(ecdh_curve_p256(), oce_privkey, sizeof(oce_privkey), oce_pubkey, sizeof(oce_pubkey))) {
    DBG("Failed to generate the OCE ephemeral keypair");
    return YKPIV_AUTHENTICATION_ERROR;
  }

  data_len = sizeof(scp11_keyagreement_template) + 1 + oce_pubkey_len;
  if (data_len + 5 > YKPIV_OBJ_MAX_SIZE) { // Total APDU length
    DBG("Message too long");
    return YKPIV_SIZE_ERROR;
  }
  memcpy(data, scp11_keyagreement_template, sizeof(scp11_keyagreement_template));
  data[sizeof(scp11_keyagreement_template)] = (uint8_t)oce_pubkey_len;
  memcpy(data + sizeof(scp11_keyagreement_template) + 1, oce_pubkey, oce_pubkey_len);

  uint8_t sde_pubkey[512] = {0};
  size_t sde_pubkey_len = sizeof(sde_pubkey);
  uint8_t receipt[SCP11_MAC_LEN] = {0};
  if ((rc = scp11_internal_authenticate(state, data, data_len, sde_pubkey, &sde_pubkey_len, receipt)) != YKPIV_OK) {
    DBG("Failed to do SCP11 internal authentication");
    return rc;
  }

  uint8_t session_keys[SCP11_SESSION_KEY_LEN * 6] = {0};
  if ((rc = scp11_derive_session_keys(oce_privkey, oce_privkey_len, sde_pubkey, sde_pubkey_len, sd_pubkey,
                                      sd_pubkey_len,
                                      session_keys)) != YKPIV_OK) {
    DBG("Failed to derive SCP11 session keys");
    return rc;
  }

  if ((rc = scp11_verify_channel(session_keys, receipt, data, (uint32_t)data_len, sde_pubkey, sde_pubkey_len)) !=
      YKPIV_OK) {
    DBG("Failed to verify SCP11 session");
    return rc;
  }

  state->scp11_state.security_level = SCP11_KEY_USAGE;
  memcpy(state->scp11_state.senc, session_keys + SCP11_SESSION_KEY_LEN, SCP11_SESSION_KEY_LEN);
  memcpy(state->scp11_state.smac, session_keys + (SCP11_SESSION_KEY_LEN * 2), SCP11_SESSION_KEY_LEN);
  memcpy(state->scp11_state.srmac, session_keys + (SCP11_SESSION_KEY_LEN * 3), SCP11_SESSION_KEY_LEN);
  memcpy(state->scp11_state.mac_chain, receipt, SCP11_MAC_LEN);
  state->scp11_state.enc_counter = 1;

  DBG("SCardConnect succeeded for 'Yubico YubiKey OTP+FIDO+CCID', protocol=2");

  return YKPIV_OK;
}

ykpiv_rc _ykpiv_select_application(ykpiv_state *state, bool scp11) {

  ykpiv_rc res = YKPIV_OK;
  if(scp11) {
    // reset scp11 state if previously negotiated security level
    yc_memzero(&(state->scp11_state), sizeof(ykpiv_scp11_state));
    res = scp11_open_secure_channel(state);
  } else {
    unsigned char templ[] = {0x00, YKPIV_INS_SELECT_APPLICATION, 0x04, 0x00};
    unsigned long recv_len;
    int sw = 0;

    if ((res = _ykpiv_transfer_data(state, templ, piv_aid, sizeof(piv_aid), NULL, &recv_len, &sw)) != YKPIV_OK) {
      return res;
    }
    res = ykpiv_translate_sw_ex(__FUNCTION__, sw);
  }
  if (res != YKPIV_OK) {
    DBG("Failed selecting application");
    return res;
  }

  /* now that the PIV application is selected, retrieve the version
   * and serial number.  Previously the NEO/YK4 required switching
   * to the yk applet to retrieve the serial, YK5 implements this
   * as a PIV applet command.  Unfortunately, this change requires
   * that we retrieve the version number first, so that get_serial
   * can determine how to get the serial number, which for the NEO/Yk4
   * will result in another selection of the PIV applet. */

  // This stores the number of PIN retries left in state
  _ykpiv_verify(state, NULL, 0, false, false);
  // WRONG_PIN or PIN_LOCKED is expected on successful query.

  res = _ykpiv_get_version(state);
  if (res != YKPIV_OK) {
    DBG("Failed to retrieve version: '%s'", ykpiv_strerror(res));
    return res;
  }

  res = _ykpiv_get_serial(state);
  if (res != YKPIV_OK) {
    DBG("Failed to retrieve serial number: '%s'", ykpiv_strerror(res));
    res = YKPIV_OK;
  }

  return res;
}

ykpiv_rc _ykpiv_ensure_application_selected(ykpiv_state *state, bool scp11) {
  ykpiv_rc res = YKPIV_OK;
#if ENABLE_APPLICATION_RESELECTION
  if (NULL == state) {
    return YKPIV_ARGUMENT_ERROR;
  }

  res = _ykpiv_verify(state, NULL, 0, false, false);

  if ((YKPIV_OK != res) && (YKPIV_WRONG_PIN != res) && (YKPIV_PIN_LOCKED != res)) {
    DBG("Failed to detect PIV application: '%s'", ykpiv_strerror(res));
    res = _ykpiv_select_application(state, scp11);
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
  if (NULL == state) {
    return YKPIV_ARGUMENT_ERROR;
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
    pcsc_long rc = SCardStatus(card, reader, &reader_len, NULL, &(state->protocol), atr, &atr_len);
    if (rc != SCARD_S_SUCCESS) {
      DBG("SCardStatus failed: rc=%lx", (long)rc);
      return pcsc_to_yrc(rc);
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
  return YKPIV_OK;
}

ykpiv_rc ykpiv_connect_with_external_card(ykpiv_state *state, uintptr_t context, uintptr_t card) {
  return _ykpiv_connect(state, context, card);
}

ykpiv_rc ykpiv_validate(ykpiv_state *state, const char *wanted) {
  if(state->card) {
    DBG("Validate reader '%s'.", wanted);
    char reader[CB_BUF_MAX] = {0};
    pcsc_word reader_len = sizeof(reader);
    uint8_t atr[CB_ATR_MAX] = {0};
    pcsc_word atr_len = sizeof(atr);
    pcsc_long rc = SCardStatus(state->card, reader, &reader_len, NULL, NULL, atr, &atr_len);
    if(rc != SCARD_S_SUCCESS) {
      DBG("SCardStatus failed on reader '%s', rc=%lx", wanted, (long)rc);
      rc = SCardDisconnect(state->card, SCARD_RESET_CARD);
      if(rc != SCARD_S_SUCCESS) {
        DBG("SCardDisconnect failed on reader '%s', rc=%lx", wanted, (long)rc);
      }
      state->card = 0;
      state->serial = 0;
      state->ver.major = 0;
      state->ver.minor = 0;
      state->ver.patch = 0;
      _cache_pin(state, NULL, 0);
      _cache_mgm_key(state, NULL, 0);
      return pcsc_to_yrc(rc);
    }
    if (strcmp(wanted, reader)) {
      DBG("Disconnecting incorrect reader '%s' (wanted '%s'), rc=%lx", reader, wanted, (long)rc);
      rc = SCardDisconnect(state->card, SCARD_RESET_CARD);
      if(rc != SCARD_S_SUCCESS) {
        DBG("SCardDisconnect failed on reader '%s' (wanted '%s'), rc=%lx", reader, wanted, (long)rc);
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
  return YKPIV_ARGUMENT_ERROR;
}

ykpiv_rc ykpiv_connect(ykpiv_state *state, const char *wanted) {
  return ykpiv_connect_ex(state, wanted, false);
}

ykpiv_rc ykpiv_connect_ex(ykpiv_state *state, const char *wanted, bool scp11) {
  char reader_buf[2048] = {0};
  size_t num_readers = sizeof(reader_buf);
  pcsc_long rc;
  char *reader_ptr;
  ykpiv_rc ret;
  SCARDHANDLE card = (SCARDHANDLE)-1;

  if(wanted && *wanted == '@') {
    wanted++; // Skip the '@'
    DBG("Connect reader '%s'.", wanted);
    if(SCardIsValidContext(state->context) != SCARD_S_SUCCESS) {
      rc = SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, &state->context);
      if (rc != SCARD_S_SUCCESS) {
        DBG("SCardEstablishContext failed, rc=%lx", (long)rc);
        return pcsc_to_yrc(rc);
      }
    }
    rc = SCardConnect(state->context, wanted, SCARD_SHARE_SHARED,
          SCARD_PROTOCOL_T0|SCARD_PROTOCOL_T1, &card, &state->protocol);
    if(rc != SCARD_S_SUCCESS) {
      DBG("SCardConnect failed for '%s', rc=%lx", wanted, (long)rc);
      SCardReleaseContext(state->context);
      state->context = (SCARDCONTEXT)-1;
      return pcsc_to_yrc(rc);
    } else {
      DBG("SCardConnect succeeded for '%s', protocol=%lx", wanted, (unsigned long)state->protocol);
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
          DBG("Skipping reader '%s' since it doesn't match '%s'.", reader_ptr, wanted);
          continue;
        }
      }
      DBG("Connect reader '%s' matching '%s'.", reader_ptr, wanted);
      rc = SCardConnect(state->context, reader_ptr, SCARD_SHARE_SHARED,
            SCARD_PROTOCOL_T0|SCARD_PROTOCOL_T1, &card, &state->protocol);
      if(rc == SCARD_S_SUCCESS) {
        strncpy(state->reader, reader_ptr, sizeof(state->reader));
        state->reader[sizeof(state->reader) - 1] = 0;
        DBG("SCardConnect succeeded for '%s', protocol=%lx", reader_ptr, (unsigned long)state->protocol);
        break;
      }
      DBG("SCardConnect failed for '%s', rc=%lx", reader_ptr, (long)rc);
    }

    if(*reader_ptr == '\0') {
      DBG("No usable reader found matching '%s'.", wanted);
      SCardReleaseContext(state->context);
      state->context = (SCARDCONTEXT)-1;
      return YKPIV_PCSC_ERROR;
    }
  }

  // at this point, card should not equal state->card, to allow _ykpiv_connect() to determine device type
  if (YKPIV_OK == _ykpiv_connect(state, state->context, card)) {
    state->scp11_state.security_level = 0;
    /*
      * Select applet.  This is done here instead of in _ykpiv_connect() because
      * you may not want to select the applet when connecting to a card handle that
      * was supplied by an external library.
      */
    if (YKPIV_OK != (ret = _ykpiv_begin_transaction(state))) return ret;


#if ENABLE_APPLICATION_RESELECTION
    ret = _ykpiv_ensure_application_selected(state, scp11);
#else
    ret = _ykpiv_select_application(state, scp11);
#endif
    _ykpiv_end_transaction(state);
    return ret;

  }

  return YKPIV_GENERIC_ERROR;
}

ykpiv_rc ykpiv_list_readers(ykpiv_state *state, char *readers, size_t *len) {
  pcsc_word num_readers = (pcsc_word)*len;
  pcsc_long rc;

  if(SCardIsValidContext(state->context) != SCARD_S_SUCCESS) {
    rc = SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, &state->context);
    if (rc != SCARD_S_SUCCESS) {
      DBG("SCardEstablishContext failed, rc=%lx", (long)rc);
      return pcsc_to_yrc(rc);
    }
  }

  rc = SCardListReaders(state->context, NULL, readers, &num_readers);
  if (rc != SCARD_S_SUCCESS) {
    DBG("SCardListReaders failed, rc=%lx", (long)rc);
    if(rc == SCARD_E_NO_READERS_AVAILABLE || rc == SCARD_E_SERVICE_STOPPED) {
      *readers = 0;
      *len = 1;
      return YKPIV_OK;
    }
    SCardReleaseContext(state->context);
    state->context = (SCARDCONTEXT)-1;
    return pcsc_to_yrc(rc);
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
    DBG("SCardBeginTransaction on card #%u failed, rc=%lx", state->serial, (long)rc);
    if (SCardIsValidContext(state->context) != SCARD_S_SUCCESS || (rc != SCARD_W_RESET_CARD && rc != SCARD_W_REMOVED_CARD)) {
      pcsc_long rc2 = SCardDisconnect(state->card, SCARD_RESET_CARD);
      DBG("SCardDisconnect on card #%u rc=%lx", state->serial, (long)rc2);
      state->card = 0;
    }
    if (SCardIsValidContext(state->context) != SCARD_S_SUCCESS || rc == SCARD_E_NO_SERVICE) {
      rc = SCardReleaseContext(state->context);
      DBG("SCardReleaseContext on card #%u rc=%lx", state->serial, (long)rc);
      state->context = 0;
      rc = SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, &state->context);
      DBG("SCardEstablishContext on card #%u rc=%lx", state->serial, (long)rc);
      if(rc != SCARD_S_SUCCESS) {
        return pcsc_to_yrc(rc);
      }
    }
    if(state->card) {
      rc = SCardReconnect(state->card, SCARD_SHARE_SHARED,
              SCARD_PROTOCOL_T0|SCARD_PROTOCOL_T1, SCARD_RESET_CARD, &state->protocol);
      DBG("SCardReconnect on card #%u rc=%lx", state->serial, (long)rc);
      if(rc != SCARD_S_SUCCESS) {
        return pcsc_to_yrc(rc);
      }
    } else {
      rc = SCardConnect(state->context, state->reader, SCARD_SHARE_SHARED,
              SCARD_PROTOCOL_T0|SCARD_PROTOCOL_T1, &state->card, &state->protocol);
      DBG("SCardConnect on reader %s card #%u rc=%lx", state->reader, state->serial, (long)rc);
      if(rc != SCARD_S_SUCCESS) {
        return pcsc_to_yrc(rc);
      }
    }
    rc = SCardBeginTransaction(state->card);
    if (rc != SCARD_S_SUCCESS) {
      DBG("SCardBeginTransaction on card #%u failed, rc=%lx", state->serial, (long)rc);
      return pcsc_to_yrc(rc);
    }
  }

  if(retries) {
    uint32_t serial = state->serial;
    state->serial = 0;
    state->ver.major = 0;
    state->ver.minor = 0;
    state->ver.patch = 0;
    ykpiv_rc res;
    if ((res = _ykpiv_select_application(state, state->scp11_state.security_level)) != YKPIV_OK)
      return res;
    if(state->serial != serial) {
      DBG("Card #%u detected, was expecting card #%u", state->serial, serial);
      return YKPIV_GENERIC_ERROR;
    }
    if(state->mgm_key) {
      if((res = _ykpiv_authenticate2(state, state->mgm_key, state->mgm_len)) != YKPIV_OK)
        return res;
    }
    if (state->pin) {
      size_t pin_len = strlen(state->pin);
      if((res = _ykpiv_verify(state, state->pin, &pin_len, false, false)) != YKPIV_OK)
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
  if(rc != SCARD_S_SUCCESS) {
    DBG("SCardEndTransaction on card #%u failed, rc=%lx", state->serial, (long)rc);
    // Ending the transaction can only fail because it's already ended - it's ended now either way so we don't fail here
  }
#endif /* ENABLE_IMPLICIT_TRANSACTIONS */
  return YKPIV_OK;
}

ykpiv_rc ykpiv_translate_sw(int sw) {
  return ykpiv_translate_sw_ex(__FUNCTION__, sw);
}

ykpiv_rc ykpiv_translate_sw_ex(const char *whence, int sw) {
  switch(sw) {
    case SW_SUCCESS:
      DBG2("%s: SW_SUCCESS", whence);
      return YKPIV_OK;
    case SW_ERR_SECURITY_STATUS:
      DBG("%s: SW_ERR_SECURITY_STATUS", whence);
      return YKPIV_AUTHENTICATION_ERROR;
    case SW_ERR_AUTH_BLOCKED:
      DBG("%s: SW_ERR_AUTH_BLOCKED", whence);
      return YKPIV_PIN_LOCKED;
    case SW_ERR_INCORRECT_PARAM:
      DBG("%s: SW_ERR_INCORRECT_PARAM", whence);
      return YKPIV_ARGUMENT_ERROR;
    case SW_ERR_FILE_NOT_FOUND:
      DBG("%s: SW_ERR_FILE_NOT_FOUND", whence);
      return YKPIV_INVALID_OBJECT;
    case SW_ERR_REFERENCE_NOT_FOUND:
      DBG("%s: SW_ERR_REFERENCE_NOT_FOUND", whence);
      return YKPIV_KEY_ERROR;
    case SW_ERR_INCORRECT_SLOT:
      DBG("%s: SW_ERR_INCORRECT_SLOT", whence);
      return YKPIV_KEY_ERROR;
    case SW_ERR_NOT_SUPPORTED:
      DBG("%s: SW_ERR_NOT_SUPPORTED", whence);
      return YKPIV_NOT_SUPPORTED;
    case SW_ERR_CONDITIONS_OF_USE:
      DBG("%s: SW_ERR_CONDITIONS_OF_USE", whence);
      return YKPIV_CONDITION_ERROR;
    case SW_ERR_NO_INPUT_DATA:
      DBG("%s: SW_ERR_NO_INPUT_DATA", whence);
      return YKPIV_ARGUMENT_ERROR;
    case SW_ERR_VERIFY_FAIL_NO_RETRY:
      DBG("%s: SW_ERR_VERIFY_FAIL_NO_RETRY", whence);
      return YKPIV_AUTHENTICATION_ERROR;
    case SW_ERR_MEMORY_ERROR:
      DBG("%s: SW_ERR_MEMORY_ERROR", whence);
      return YKPIV_MEMORY_ERROR;
    case SW_ERR_WRONG_LENGTH:
      DBG("%s: SW_ERR_WRONG_LENGTH", whence);
      return YKPIV_PARSE_ERROR;
    case SW_ERR_DATA_INVALID:
      DBG("%s: SW_ERR_DATA_INVALID", whence);
      return YKPIV_PARSE_ERROR;
    case SW_ERR_COMMAND_NOT_ALLOWED:
      DBG("%s: SW_ERR_COMMAND_NOT_ALLOWED", whence);
      return YKPIV_NOT_SUPPORTED;
    case SW_ERR_NO_SPACE:
      DBG("%s: SW_ERR_NO_SPACE", whence);
      return YKPIV_SIZE_ERROR;
    case SW_ERR_CLASS_NOT_SUPPORTED:
      DBG("%s: SW_ERR_CLASS_NOT_SUPPORTED", whence);
      return YKPIV_NOT_SUPPORTED;
    case SW_ERR_COMMAND_ABORTED:
      DBG("%s: SW_ERR_COMMAND_ABORTED", whence);
      return YKPIV_GENERIC_ERROR;
    default:
      DBG("%s: SW_%04x", whence, sw);
      return YKPIV_GENERIC_ERROR;
  }
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

static ykpiv_rc _ykpiv_transmit(ykpiv_state *state, const unsigned char *send_data, pcsc_word send_len,
    unsigned char *recv_data, pcsc_word *recv_len, int *sw) {
  DBG("> @", send_data, (size_t)send_len);
  pcsc_long rc = SCardTransmit(state->card, _pci(state->protocol), send_data, send_len, NULL, recv_data, recv_len);
  if(rc != SCARD_S_SUCCESS) {
    DBG("SCardTransmit on card #%u failed, rc=%lx", state->serial, (long)rc);
    *sw = 0;
    return pcsc_to_yrc(rc);
  }
  DBG("< @", recv_data, (size_t)*recv_len);
  if(*recv_len >= 2) {
    *sw = (recv_data[*recv_len - 2] << 8) | recv_data[*recv_len - 1];
    *recv_len -= 2;
  } else {
    *sw = 0;
  }
  return YKPIV_OK;
}

static ykpiv_rc scp11_prepare_transfer(ykpiv_scp11_state *state, APDU *apdu, const uint8_t *apdu_data, uint32_t apdu_data_len, size_t *apdu_len) {
  ykpiv_rc rc = YKPIV_OK;
  uint8_t enc[YKPIV_OBJ_MAX_SIZE] = {0};
  uint32_t enc_len = sizeof(enc);

  if ((rc = scp11_encrypt_data(state->senc, state->enc_counter++, apdu_data, apdu_data_len, enc, &enc_len)) !=
      YKPIV_OK) {
    DBG("Failed to perform AES ECD encryption on APDU");
    return rc;
  }

  uint8_t cla = apdu->st.cla | 0x04;
  APDU maced_apdu = {cla, apdu->st.ins, apdu->st.p1, apdu->st.p2, 0};
  maced_apdu.st.data[0] = (enc_len + SCP11_HALF_MAC_LEN) >> 8;
  maced_apdu.st.data[1] = (enc_len + SCP11_HALF_MAC_LEN) & 0xff;
  memcpy(maced_apdu.st.data + 2, enc, enc_len);

  uint8_t mac[SCP11_MAC_LEN] = {0};
  if ((rc = scp11_mac_data(state->smac, state->mac_chain, maced_apdu.raw, 7 + enc_len, mac)) != YKPIV_OK) {
    DBG("Failed to calculate APDU mac value");
    return rc;
  }

  apdu->st.cla = cla;
  apdu->st.lc = 0;
  apdu->st.data[0] = (enc_len + SCP11_HALF_MAC_LEN) >> 8;
  apdu->st.data[1] = (enc_len + SCP11_HALF_MAC_LEN) & 0xff;
  memcpy(apdu->st.data + 2, enc, enc_len);
  memcpy(apdu->st.data + 2 + enc_len, mac, SCP11_HALF_MAC_LEN);
  *apdu_len = enc_len + SCP11_HALF_MAC_LEN + 7;

  memcpy(state->mac_chain, mac, SCP11_MAC_LEN);
  return rc;
}

static ykpiv_rc
scp11_decrypt_response(ykpiv_scp11_state *state, uint8_t *data, uint32_t data_len, uint8_t *dec, uint32_t *dec_len,
                       int sw) {
  if (data_len == 0) {
    DBG("No response data to decrypt");
    return YKPIV_OK;
  }
  ykpiv_rc rc = YKPIV_OK;
  if ((rc = scp11_unmac_data(state->srmac, state->mac_chain, data, data_len, sw)) != YKPIV_OK) {
    DBG("Failed to verify response MAC");
    return rc;
  }

  if ((rc = scp11_decrypt_data(state->senc, state->enc_counter - 1, data, data_len - SCP11_HALF_MAC_LEN, dec,
                                dec_len)) != YKPIV_OK) {
    DBG("Failed to decrypt response");
    return rc;
  }

  return rc;
 }

ykpiv_rc _ykpiv_transfer_data(ykpiv_state *state,
    const unsigned char *templ,
    const unsigned char *in_data,
    unsigned long in_len,
    unsigned char *out_data,
    unsigned long *out_len,
    int *sw) {
  unsigned long max_out = *out_len;
  *out_len = 0;

  do {
    APDU apdu = {templ[0], templ[1], templ[2], templ[3], 0xff};
    unsigned char data[YKPIV_OBJ_MAX_SIZE] = {0};


    ykpiv_rc res = YKPIV_OK;
    pcsc_word apdu_len;
    if (state->scp11_state.security_level) {
      size_t apdu_length;
      if((res = scp11_prepare_transfer(&state->scp11_state, &apdu, in_data, in_len, &apdu_length)) != YKPIV_OK) {
        return res;
      }
      in_len = 0;
      apdu_len = (pcsc_word)apdu_length;
    } else {
      if(in_len > 0xff) {
        apdu.st.cla |= 0x10;
      } else {
        apdu.st.lc = (unsigned char)in_len;
      }

      apdu_len = apdu.st.lc + 5;

      if(apdu.st.lc) {
        memcpy(apdu.st.data, in_data, apdu.st.lc);
        in_data += apdu.st.lc;
        in_len -= apdu.st.lc;

        // Add Le for T=1
        if (state->protocol == SCARD_PROTOCOL_T1) {
          apdu.st.data[apdu.st.lc] = 0;
          apdu_len++;
        }
      }
    }

  Retry:
    DBG("Going to send %u bytes in this go.", apdu_len);
    pcsc_word recv_len = sizeof(data);
    if((res = _ykpiv_transmit(state, apdu.raw, apdu_len, data, &recv_len, sw)) != YKPIV_OK) {
      return res;
    }
    // Case 2S.3 — Process aborted; Ne not accepted, Na indicated
    if((*sw & 0xff00) == 0x6c00) {
      apdu.st.lc = *sw & 0xff;
      DBG3("The card indicates we must retry with Le = %u.", apdu.st.lc);
      goto Retry;
    }
    if (*sw != SW_SUCCESS && (*sw & 0xff00) != 0x6100) {
      return YKPIV_OK;
    }

    if (out_data) {
      if (state->scp11_state.security_level) {
        uint8_t dec[2048] = {0};
        uint32_t dec_len = sizeof(dec);
        if ((res = scp11_decrypt_response(&state->scp11_state, data, recv_len, dec, &dec_len, *sw)) != YKPIV_OK) {
          return res;
        }
        if (*out_len + dec_len > max_out) {
          DBG("Output buffer to small, wanted to write %lu, max was %lu.", *out_len + dec_len, max_out);
          return YKPIV_SIZE_ERROR;
        }
        memcpy(out_data, dec, dec_len);
        out_data += dec_len;
        *out_len += dec_len;
      } else {
        if (*out_len + recv_len > max_out) {
          DBG("Output buffer to small, wanted to write %lu, max was %lu.", *out_len + recv_len, max_out);
          return YKPIV_SIZE_ERROR;
        }
        memcpy(out_data, data, recv_len);
        out_data += recv_len;
        *out_len += recv_len;
      }
    }

  } while (in_len);
  while((*sw & 0xff00) == 0x6100) {
    unsigned char apdu[] = {0, YKPIV_INS_GET_RESPONSE_APDU, 0, 0, *sw & 0xff};
    unsigned char data[258] = {0};

    DBG3("The card indicates there is %u bytes more data for us.", apdu[4] ? apdu[4] : 0x100);

    pcsc_word recv_len = sizeof(data);
    ykpiv_rc res = _ykpiv_transmit(state, apdu, sizeof(apdu), data, &recv_len, sw);
    if (res != YKPIV_OK) {
      return res;
    } else if (*sw != SW_SUCCESS && (*sw & 0xff00) != 0x6100) {
      return YKPIV_OK;
    }

    if (out_data) {
      if (state->scp11_state.security_level) {
        DBG("Reading response in chunks is not supported through encrypted sessions");
        return YKPIV_NOT_SUPPORTED;
      } else {
        if (*out_len + recv_len > max_out) {
          DBG("Output buffer to small, wanted to write %lu, max was %lu.", *out_len + recv_len, max_out);
          return YKPIV_SIZE_ERROR;
        }
        memcpy(out_data, data, recv_len);
        out_data += recv_len;
        *out_len += recv_len;
      }
    }
  }
  return YKPIV_OK;
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
  int sw = 0;

  if (state == NULL || data == NULL || data_len == NULL) {
    return YKPIV_ARGUMENT_ERROR;
  }

  if ((res = _ykpiv_transfer_data(state, templ, NULL, 0, data, data_len, &sw)) != YKPIV_OK) {
    goto Cleanup;
  }

  res = ykpiv_translate_sw_ex(__FUNCTION__, sw);

Cleanup:
  return res;
}

ykpiv_rc ykpiv_authenticate(ykpiv_state *state, unsigned const char *key) {
  return ykpiv_authenticate2(state, key, DES_LEN_3DES);
}

ykpiv_rc ykpiv_authenticate2(ykpiv_state *state, unsigned const char *key, size_t len) {
  ykpiv_rc res;

  if (NULL == state) return YKPIV_ARGUMENT_ERROR;
  uint8_t scp11 = state->scp11_state.security_level;
  if (YKPIV_OK != (res = _ykpiv_begin_transaction(state))) return res;
  if (YKPIV_OK != (res = _ykpiv_ensure_application_selected(state, scp11))) goto Cleanup;

  res = _ykpiv_authenticate2(state, key, len);

Cleanup:
  _ykpiv_end_transaction(state);
  return res;
}

static ykpiv_rc _ykpiv_authenticate2(ykpiv_state *state, unsigned const char *key, size_t len) {
  if (NULL == state)
    return YKPIV_ARGUMENT_ERROR;

  if (NULL == key) {
    key = (unsigned const char*)YKPIV_MGM_DEFAULT;
    len = DES_LEN_3DES;
  }

  ykpiv_metadata metadata = {YKPIV_ALGO_3DES};
  unsigned char data[256] = {0};
  unsigned long recv_len = sizeof(data);
  ykpiv_rc res = _ykpiv_get_metadata(state, YKPIV_KEY_CARDMGM, data, &recv_len);
  if (res == YKPIV_OK) {
    res = ykpiv_util_parse_metadata(data, recv_len, &metadata);
    if (res != YKPIV_OK) {
      return res;
    }
  }

  /* set up our key */
  aes_context mgm_key = {0};
  int drc = aes_set_key(key, (uint32_t)len, metadata.algorithm, &mgm_key);
  if (drc) {
    DBG("%s: cipher_import_key: %d", ykpiv_strerror(YKPIV_ALGORITHM_ERROR), drc);
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
    res = ykpiv_translate_sw_ex(__FUNCTION__, sw);
    if (res != YKPIV_OK) {
      goto Cleanup;
    }
  }

  uint8_t *challenge = data + 4;
  uint32_t challenge_len = recv_len - 4;
  uint32_t mgm_blocksize = aes_blocksize(&mgm_key);
  if(challenge_len != mgm_blocksize) { // Only management key block size allowed
    DBG("%s: management key block size is %u but received %u bytes challenge", ykpiv_strerror(YKPIV_PARSE_ERROR), mgm_blocksize, challenge_len);
    res = YKPIV_PARSE_ERROR;
    goto Cleanup;
  }

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
    drc = aes_decrypt(challenge, challenge_len, dataptr, &out_len, &mgm_key);
    if (drc) {
      DBG("%s: cipher_decrypt: %d", ykpiv_strerror(YKPIV_AUTHENTICATION_ERROR), drc);
      res = YKPIV_AUTHENTICATION_ERROR;
      goto Cleanup;
    }
    dataptr += out_len;
    *dataptr++ = 0x81;
    *dataptr++ = challenge_len;
    challenge = dataptr;
    if (PRNG_OK != _ykpiv_prng_generate(challenge, challenge_len)) {
      DBG("%s: Failed getting randomness for authentication.", ykpiv_strerror(YKPIV_RANDOMNESS_ERROR));
      res = YKPIV_RANDOMNESS_ERROR;
      goto Cleanup;
    }
    dataptr += challenge_len;
    apdu.st.lc = (unsigned char)(dataptr - apdu.st.data);
    recv_len = sizeof(data);
    if ((res = _ykpiv_send_apdu(state, &apdu, data, &recv_len, &sw)) != YKPIV_OK) {
      goto Cleanup;
    }
    res = ykpiv_translate_sw_ex(__FUNCTION__, sw);
    if (res != YKPIV_OK) {
      goto Cleanup;
    }

    /* compare the response from the card with our challenge */
    out_len = challenge_len;
    drc = aes_encrypt(challenge, challenge_len, challenge, &out_len, &mgm_key);
    if (drc) {
      DBG("%s: cipher_encrypt: %d", ykpiv_strerror(YKPIV_AUTHENTICATION_ERROR), drc);
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
  aes_destroy(&mgm_key);

  return res;
}

ykpiv_rc ykpiv_set_mgmkey(ykpiv_state *state, const unsigned char *new_key) {
  return ykpiv_set_mgmkey2(state, new_key, YKPIV_TOUCHPOLICY_DEFAULT);
}

ykpiv_rc ykpiv_set_mgmkey2(ykpiv_state *state, const unsigned char *new_key, const unsigned char touch) {
  return ykpiv_set_mgmkey3(state, new_key, DES_LEN_3DES, YKPIV_ALGO_3DES, touch);
}

ykpiv_rc ykpiv_set_mgmkey3(ykpiv_state *state, const unsigned char *new_key, size_t len, unsigned char algo, unsigned char touch) {
  unsigned char data[256] = {0};
  ykpiv_rc res = YKPIV_OK;
  uint8_t scp11 = state->scp11_state.security_level;
  if (YKPIV_OK != (res = _ykpiv_begin_transaction(state))) return res;
  if (YKPIV_OK != (res = _ykpiv_ensure_application_selected(state, scp11))) goto Cleanup;

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
    DBG("Wont set new key since it's weak (or has odd parity) @", new_key, len);
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
    DBG("Invalid touch policy for card management key (slot %02x).", YKPIV_KEY_CARDMGM);
    res = YKPIV_GENERIC_ERROR;
    goto Cleanup;
  }

  apdu.st.lc = (unsigned char)(len + 3);
  apdu.st.data[0] = algo;
  apdu.st.data[1] = YKPIV_KEY_CARDMGM;
  apdu.st.data[2] = (unsigned char)len;
  memcpy(apdu.st.data + 3, new_key, len);

  int sw = 0;
  unsigned long recv_len = sizeof(data);
  if ((res = _ykpiv_send_apdu(state, &apdu, data, &recv_len, &sw)) != YKPIV_OK) {
    goto Cleanup;
  }
  res = ykpiv_translate_sw_ex(__FUNCTION__, sw);
  if (res == YKPIV_OK) {
    _cache_mgm_key(state, new_key, len);
    goto Cleanup;
  }

Cleanup:
  yc_memzero(&apdu, sizeof(APDU));
  _ykpiv_end_transaction(state);
  return res;
}

static char hex_translate[] = "0123456789abcdef";

ykpiv_rc ykpiv_hex_decode(const char *hex_in, size_t in_len,
    unsigned char *hex_out, size_t *out_len) {

  if (hex_in == NULL || hex_out == NULL || out_len == NULL) {
    return YKPIV_ARGUMENT_ERROR;
  }

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
  unsigned char indata[YKPIV_OBJ_MAX_SIZE] = {0};
  unsigned char *dataptr = indata;
  unsigned char data[YKPIV_OBJ_MAX_SIZE] = {0};
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
    case YKPIV_ALGO_RSA3072:
      if(key_len == 0) {
        key_len = 384;
      }
    case YKPIV_ALGO_RSA4096:
      if(key_len == 0) {
        key_len = 512;
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
        DBG("Data to sign truncated to EC key length (%zu bytes)", key_len);
        in_len = key_len;
      } else if(decipher && in_len != (key_len * 2) + 1) {
	      return YKPIV_SIZE_ERROR;
      }
      break;
    case YKPIV_ALGO_X25519:
      if(!decipher) {
        DBG("Signing with x25519 keys is not supported");
        return YKPIV_NOT_SUPPORTED;
      }
      if(in_len != 32) {
        return YKPIV_SIZE_ERROR;
      }
      break;
    case YKPIV_ALGO_ED25519:
      if(decipher) {
        DBG("Deciphering with ed25519 keys is not supported");
        return YKPIV_NOT_SUPPORTED;
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
  *dataptr++ = !YKPIV_IS_RSA(algorithm) && decipher ? 0x85 : 0x81;
  dataptr += _ykpiv_set_length(dataptr, in_len);
  if(dataptr - indata + in_len > sizeof(indata)) {
    return YKPIV_SIZE_ERROR;
  }
  memcpy(dataptr, sign_in, in_len);
  dataptr += in_len;

  if((res = _ykpiv_transfer_data(state, templ, indata, (unsigned long)(dataptr - indata), data, &recv_len, &sw)) != YKPIV_OK) {
    return res;
  }
  res = ykpiv_translate_sw_ex(__FUNCTION__, sw);
  if(res != YKPIV_OK) {
    DBG("Sign command failed");
    return res;
  }
  /* skip the first 7c tag */
  if(data[0] != 0x7c) {
    DBG("Failed parsing signature reply.");
    return YKPIV_PARSE_ERROR;
  }
  dataptr = data + 1;
  offs = _ykpiv_get_length(dataptr, data + recv_len, &len);
  dataptr += offs;
  /* skip the 82 tag */
  if(!offs || *dataptr != 0x82) {
    DBG("Failed parsing signature reply.");
    return YKPIV_PARSE_ERROR;
  }
  dataptr++;
  offs = _ykpiv_get_length(dataptr, data + recv_len, &len);
  dataptr += offs;
  if(!offs || len > *out_len) {
    DBG("Wrong size on output buffer.");
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

  if (NULL == state) return YKPIV_ARGUMENT_ERROR;

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

  if (NULL == state) return YKPIV_ARGUMENT_ERROR;

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
  unsigned char data[256] = {0};
  unsigned long recv_len = sizeof(data);
  int sw = 0;
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
  }
  res = ykpiv_translate_sw_ex(__FUNCTION__, sw);
  if(res == YKPIV_OK) {

    /* check that we received enough data for the verson number */
    if (recv_len < 3) {
      return YKPIV_SIZE_ERROR;
    }

    state->ver.major = data[0];
    state->ver.minor = data[1];
    state->ver.patch = data[2];
  }

  return res;
}

ykpiv_rc ykpiv_get_version(ykpiv_state *state, char *version, size_t len) {
  ykpiv_rc res;
  uint8_t scp11 = state->scp11_state.security_level;
  if ((res = _ykpiv_begin_transaction(state)) < YKPIV_OK) return res;
  if ((res = _ykpiv_ensure_application_selected(state, scp11)) < YKPIV_OK) goto Cleanup;

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
  uint8_t data[256] = {0};
  unsigned long recv_len = sizeof(data);
  int sw = 0;

  if (!state) {
    return YKPIV_ARGUMENT_ERROR;
  }

  /* get serial from state if already retrieved from device */
  if (state->serial != 0) {
    return YKPIV_OK;
  }

  if (state->ver.major > 0 && state->ver.major < 5) {
    /* get serial from neo/yk4 devices using the otp applet */
    uint8_t temp[256] = {0};

    recv_len = sizeof(temp);

    if ((res = _ykpiv_transfer_data(state, select_templ, yk_aid, sizeof(yk_aid), temp, &recv_len, &sw)) < YKPIV_OK) {
      goto Cleanup;
    }
    res = ykpiv_translate_sw_ex(__FUNCTION__, sw);
    if (res != YKPIV_OK) {
      DBG("Failed selecting yk application");
      goto Cleanup;
    }

    uint8_t yk_get_serial_templ[] = {0x00, 0x01, 0x10, 0x00};

    recv_len = sizeof(data);

    if ((res = _ykpiv_transfer_data(state, yk_get_serial_templ, NULL, 0, data, &recv_len, &sw)) < YKPIV_OK) {
      goto Cleanup;
    }
    res = ykpiv_translate_sw_ex(__FUNCTION__, sw);
    if (res != YKPIV_OK) {
      DBG("Failed retrieving serial number");
      goto Cleanup;
    }

    recv_len = sizeof(temp);

    if((res = _ykpiv_transfer_data(state, select_templ, piv_aid, sizeof(piv_aid), temp, &recv_len, &sw)) < YKPIV_OK) {
      return res;
    }
    res = ykpiv_translate_sw_ex(__FUNCTION__, sw);
    if(res != YKPIV_OK) {
      DBG("Failed selecting piv application");
    }
  }
  else {
    /* get serial from yk5 and later devices using the YKPIV_INS_GET_SERIAL command */
    uint8_t yk5_get_serial_templ[] = {0x00, YKPIV_INS_GET_SERIAL, 0x00, 0x00};

    if ((res = _ykpiv_transfer_data(state, yk5_get_serial_templ, NULL, 0, data, &recv_len, &sw)) != YKPIV_OK) {
      return res;
    }
    res = ykpiv_translate_sw_ex(__FUNCTION__, sw);
    if(res != YKPIV_OK) {
      DBG("Failed retrieving serial number");
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
  uint8_t scp11 = state->scp11_state.security_level;
  if ((res = _ykpiv_begin_transaction(state)) != YKPIV_OK) return res;
  if ((res = _ykpiv_ensure_application_selected(state, scp11)) != YKPIV_OK) goto Cleanup;

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
    state->mgm_len = (uint32_t)len;
  }
  return YKPIV_OK;
#endif
}

static ykpiv_rc _verify_pin_apdu(char *pin, size_t *p_pin_len, bool verify_spin, APDU *apdu) {
  if (p_pin_len && (*p_pin_len > CB_PIN_MAX)) {
    return YKPIV_SIZE_ERROR;
  }

  apdu->st.ins = YKPIV_INS_VERIFY;
  apdu->st.p1 = 0x00;
  apdu->st.p2 = 0x80;
  apdu->st.lc = pin ? 0x08 : 0x00;
  if (pin) {
    if (p_pin_len && (*p_pin_len > 0)) {
      memcpy(apdu->st.data, pin, *p_pin_len);
      if (*p_pin_len < CB_PIN_MAX) {
        memset(apdu->st.data + *p_pin_len, 0xff, CB_PIN_MAX - *p_pin_len);
      }
    } else if (verify_spin && p_pin_len) {
      apdu->st.data[0] = 0x01;
      apdu->st.data[1] = (uint8_t)*p_pin_len;
      memcpy(apdu->st.data + 2, pin, *p_pin_len);
    }
  }
  return YKPIV_OK;
}

static ykpiv_rc _verify_bio_apdu(char *pin, size_t *p_pin_len, bool verify_spin, APDU *apdu) {

  if (verify_spin && (!pin || !p_pin_len || *p_pin_len != 16)) {
    return YKPIV_WRONG_PIN;
  }

  apdu->st.ins = YKPIV_INS_VERIFY;
  apdu->st.p1 = 0x00;
  apdu->st.p2 = 0x96;
  apdu->st.lc = verify_spin ? (uint8_t)(*p_pin_len + 2) : 0x02;
  if (pin) {
    if (verify_spin && p_pin_len) {
      apdu->st.data[0] = 0x01;
      apdu->st.data[1] = (uint8_t) *p_pin_len;
      memcpy(apdu->st.data + 2, pin, *p_pin_len);
    } else {
      memcpy(apdu->st.data, "\x02\x00", 2);
    }
  } else {
    if (verify_spin) {
      apdu->st.lc = 0;
    } else {
      memcpy(apdu->st.data, "\x03\x00", 2);
    }
  }
  return YKPIV_OK;
}

static ykpiv_rc _ykpiv_verify(ykpiv_state *state, char *pin, size_t *p_pin_len, bool bio, bool verify_spin) {

  if (!bio && p_pin_len && (*p_pin_len > CB_PIN_MAX)) {
    return YKPIV_SIZE_ERROR;
  }

  if (bio && verify_spin && (!pin || !p_pin_len || *p_pin_len != 16)) {
    return YKPIV_WRONG_PIN;
  }

  APDU apdu = {0};
  if(bio) {
    _verify_bio_apdu(pin, p_pin_len, verify_spin, &apdu);
  } else {
    _verify_pin_apdu(pin, p_pin_len, verify_spin, &apdu);
  }

  int sw = 0;
  unsigned char data[256] = {0};
  unsigned long recv_len = sizeof(data);
  ykpiv_rc res = _ykpiv_send_apdu(state, &apdu, data, &recv_len, &sw);
  yc_memzero(&apdu, sizeof(apdu));

  if (res != YKPIV_OK) {
    state->tries = -1;
    return res;
  }
  res = ykpiv_translate_sw_ex(__FUNCTION__, sw);
  if (res == YKPIV_OK) {
    if (!bio && pin && p_pin_len) {
      // Intentionally ignore errors.  If the PIN fails to save, it will only
      // be a problem if a reconnect is attempted.  Failure deferred until then.
      _cache_pin(state, pin, *p_pin_len);
    }
    else if (bio && !verify_spin && pin && p_pin_len && *p_pin_len >= 16 && (recv_len >= 16)) {
      memcpy(pin, data, 16);
      *p_pin_len = 16;
    }
    state->tries = -1;
    return YKPIV_OK;
  }
  else {
    if (bio && !verify_spin && p_pin_len) {
      *p_pin_len = 0;
    }

    if ((sw >> 8) == 0x63) {
      if (pin)
        _cache_pin(state, NULL, 0);
      state->tries = (sw & 0xf);
      return YKPIV_WRONG_PIN;
    }
    else if (sw == SW_ERR_AUTH_BLOCKED) {
      if (pin)
        _cache_pin(state, NULL, 0);
      state->tries = 0;
      return YKPIV_PIN_LOCKED;
    }
    else {
      state->tries = -1;
      return res;
    }
  }
}

static ykpiv_rc _ykpiv_verify_select(ykpiv_state *state, char *pin, size_t* p_pin_len, int *tries, bool force_select, bool bio, bool verify_spin) {
  ykpiv_rc res = YKPIV_OK;
  uint8_t scp11 = state->scp11_state.security_level;
  if (YKPIV_OK != (res = _ykpiv_begin_transaction(state))) {
    return res;
  }
  if (force_select) {
    if (YKPIV_OK != (res = _ykpiv_ensure_application_selected(state, scp11))) {
      goto Cleanup;
    }
  }
  res = _ykpiv_verify(state, pin, p_pin_len, bio, verify_spin);
  if(tries) *tries = state->tries;
Cleanup:

  _ykpiv_end_transaction(state);
  return res;
}

ykpiv_rc ykpiv_verify(ykpiv_state *state, const char *pin, int *tries) {
  size_t pin_len = pin ? strlen(pin) : 0;
  return _ykpiv_verify_select(state, (char*)pin, &pin_len, tries, false, false, false);
}

ykpiv_rc ykpiv_verify_bio(ykpiv_state *state, uint8_t *spin, size_t *p_spin_len, int *tries, bool verify_spin) {
  return _ykpiv_verify_select(state, (char*)spin, p_spin_len, tries, false, true, verify_spin);
}

ykpiv_rc ykpiv_verify_select(ykpiv_state *state, const char *pin, const size_t pin_len, int *tries, bool force_select) {
  size_t temp_pin_len = pin_len;
  return _ykpiv_verify_select(state, (char*)pin, &temp_pin_len, tries, force_select, false, false);
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
  res = _ykpiv_select_application(state, state->scp11_state.security_level);
  if (res != YKPIV_OK) goto Cleanup;
  *tries = state->tries;
Cleanup:
  _ykpiv_end_transaction(state);
  return (res == YKPIV_WRONG_PIN || res == YKPIV_PIN_LOCKED) ? YKPIV_OK : res;
}

ykpiv_rc ykpiv_set_pin_retries(ykpiv_state *state, int pin_tries, int puk_tries) {
  ykpiv_rc res = YKPIV_OK;
  unsigned char templ[] = {0, YKPIV_INS_SET_PIN_RETRIES, 0, 0};
  unsigned char data[256] = {0};
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

  uint8_t scp11 = state->scp11_state.security_level;
  if (YKPIV_OK != (res = _ykpiv_begin_transaction(state))) return res;
  if (YKPIV_OK != (res = _ykpiv_ensure_application_selected(state, scp11))) goto Cleanup;

  res = _ykpiv_transfer_data(state, templ, NULL, 0, data, &recv_len, &sw);
  if (res == YKPIV_OK) {
    res = ykpiv_translate_sw_ex(__FUNCTION__, sw);
  }

Cleanup:
  _ykpiv_end_transaction(state);
  return res;
}

static ykpiv_rc _ykpiv_change_pin(ykpiv_state *state, int action, const char * current_pin, size_t current_pin_len, const char * new_pin, size_t new_pin_len, int *tries) {
  int sw = 0;
  unsigned char templ[] = {0, YKPIV_INS_CHANGE_REFERENCE, 0, 0x80};
  unsigned char indata[0x10] = {0};
  unsigned char data[256] = {0};
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
  }
  res = ykpiv_translate_sw_ex(__FUNCTION__, sw);
  if(res != YKPIV_OK) {
    if((sw >> 8) == 0x63) {
      if (tries) *tries = sw & 0xf;
      return YKPIV_WRONG_PIN;
    } else {
      DBG("Failed changing pin");
    }
  }
  return res;
}

ykpiv_rc ykpiv_change_pin(ykpiv_state *state, const char * current_pin, size_t current_pin_len, const char * new_pin, size_t new_pin_len, int *tries) {
  ykpiv_rc res = YKPIV_GENERIC_ERROR;
  uint8_t scp11 = state->scp11_state.security_level;
  if (YKPIV_OK != (res = _ykpiv_begin_transaction(state))) return res;
  if (YKPIV_OK != (res = _ykpiv_ensure_application_selected(state, scp11))) goto Cleanup;

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
  uint8_t scp11 = state->scp11_state.security_level;
  if (YKPIV_OK != (res = _ykpiv_begin_transaction(state))) return res;
  if (YKPIV_OK != (res = _ykpiv_ensure_application_selected(state, scp11))) goto Cleanup;

  res = _ykpiv_change_pin(state, CHREF_ACT_CHANGE_PUK, current_puk, current_puk_len, new_puk, new_puk_len, tries);

Cleanup:
  _ykpiv_end_transaction(state);
  return res;
}

ykpiv_rc ykpiv_unblock_pin(ykpiv_state *state, const char * puk, size_t puk_len, const char * new_pin, size_t new_pin_len, int *tries) {
  ykpiv_rc res = YKPIV_GENERIC_ERROR;
  uint8_t scp11 = state->scp11_state.security_level;
  if (YKPIV_OK != (res = _ykpiv_begin_transaction(state))) return res;
  if (YKPIV_OK != (res = _ykpiv_ensure_application_selected(state, scp11))) goto Cleanup;

  res = _ykpiv_change_pin(state, CHREF_ACT_UNBLOCK_PIN, puk, puk_len, new_pin, new_pin_len, tries);

Cleanup:
  _ykpiv_end_transaction(state);
  return res;
}

ykpiv_rc ykpiv_fetch_object(ykpiv_state *state, int object_id,
    unsigned char *data, unsigned long *len) {
  ykpiv_rc res;
  uint8_t scp11 = state->scp11_state.security_level;
  if (YKPIV_OK != (res = _ykpiv_begin_transaction(state))) return res;
  if (YKPIV_OK != (res = _ykpiv_ensure_application_selected(state, scp11))) goto Cleanup;

  res = _ykpiv_fetch_object(state, object_id, data, len);

Cleanup:
  _ykpiv_end_transaction(state);
  return res;
}

ykpiv_rc _ykpiv_fetch_object(ykpiv_state *state, int object_id,
    unsigned char *data, unsigned long *len) {
  int sw = 0;
  unsigned char indata[5] = {0};
  unsigned char *inptr = indata;
  unsigned char templ[] = {0, YKPIV_INS_GET_DATA, 0x3f, 0xff};
  ykpiv_rc res;

  inptr = set_object(object_id, inptr);
  if(inptr == NULL) {
    return YKPIV_INVALID_OBJECT;
  }

  if((res = _ykpiv_transfer_data(state, templ, indata, (unsigned long)(inptr - indata), data, len, &sw))
      != YKPIV_OK) {
    return res;
  }
  res = ykpiv_translate_sw_ex(__FUNCTION__, sw);
  if(res == YKPIV_OK) {
    size_t outlen = 0;
    size_t offs = _ykpiv_get_length(data + 1, data + *len, &outlen);
    if(!offs) {
      return YKPIV_PARSE_ERROR;
    }
    if(outlen + offs + 1 != *len) {
      DBG("Invalid length indicated in object, total objlen is %lu, indicated length is %lu.", *len, (unsigned long)outlen);
      return YKPIV_SIZE_ERROR;
    }
    memmove(data, data + 1 + offs, outlen);
    *len = (unsigned long)outlen;
  } else {
    DBG("Failed to get data for object %x", object_id);
  }
  return res;
}

ykpiv_rc ykpiv_save_object(ykpiv_state *state, int object_id,
    unsigned char *indata, size_t len) {
  ykpiv_rc res;
  uint8_t scp11 = state->scp11_state.security_level;
  if (YKPIV_OK != (res = _ykpiv_begin_transaction(state))) return res;
  if (YKPIV_OK != (res = _ykpiv_ensure_application_selected(state, scp11))) goto Cleanup;

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
  int sw = 0;
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

  if((res = _ykpiv_transfer_data(state, templ, data, (unsigned long)(dataptr - data), NULL, &outlen,
    &sw)) != YKPIV_OK) {
    return res;
  }
  return ykpiv_translate_sw_ex(__FUNCTION__, sw);
}

ykpiv_rc ykpiv_import_private_key(ykpiv_state *state, const unsigned char key, unsigned char algorithm,
                                  const unsigned char *p, size_t p_len,
                                  const unsigned char *q, size_t q_len,
                                  const unsigned char *dp, size_t dp_len,
                                  const unsigned char *dq, size_t dq_len,
                                  const unsigned char *qinv, size_t qinv_len,
                                  const unsigned char *ec_data, unsigned char ec_data_len,
                                  const unsigned char pin_policy, const unsigned char touch_policy) {

  unsigned char key_data[2048] = {0};
  unsigned char *in_ptr = key_data;
  unsigned char templ[] = {0, YKPIV_INS_IMPORT_KEY, algorithm, key};
  unsigned char data[256] = {0};
  unsigned long recv_len = sizeof(data);
  size_t elem_len = 0;
  int sw = 0;
  const unsigned char *params[5] = {0};
  size_t lens[5] = {0};
  unsigned char n_params;
  unsigned char param_tag;
  ykpiv_rc res;

  if (state == NULL)
    return YKPIV_ARGUMENT_ERROR;
  uint8_t scp11 = state->scp11_state.security_level;

  if (key == YKPIV_KEY_CARDMGM ||
      key < YKPIV_KEY_RETIRED1 ||
      (key > YKPIV_KEY_RETIRED20 && key < YKPIV_KEY_AUTHENTICATION) ||
      (key > YKPIV_KEY_CARDAUTH && key != YKPIV_KEY_ATTESTATION)) {
    return YKPIV_KEY_ERROR;
  }

  if (pin_policy != YKPIV_PINPOLICY_DEFAULT &&
      pin_policy != YKPIV_PINPOLICY_NEVER &&
      pin_policy != YKPIV_PINPOLICY_ONCE &&
      pin_policy != YKPIV_PINPOLICY_ALWAYS &&
      pin_policy != YKPIV_PINPOLICY_MATCH_ONCE &&
      pin_policy != YKPIV_PINPOLICY_MATCH_ALWAYS)
    return YKPIV_GENERIC_ERROR;

  if (touch_policy != YKPIV_TOUCHPOLICY_DEFAULT &&
      touch_policy != YKPIV_TOUCHPOLICY_NEVER &&
      touch_policy != YKPIV_TOUCHPOLICY_ALWAYS &&
      touch_policy != YKPIV_TOUCHPOLICY_CACHED)
    return YKPIV_GENERIC_ERROR;

  if (YKPIV_IS_RSA(algorithm)) {
    if ((algorithm == YKPIV_ALGO_RSA3072 || algorithm == YKPIV_ALGO_RSA4096) && !is_version_compatible(state, 5, 7, 0)) {
      DBG("RSA3072 and RSA4096 keys are only supported in YubiKey version 5.7.0 and above");
      return YKPIV_NOT_SUPPORTED;
    }

    switch (algorithm) {
      case YKPIV_ALGO_RSA1024:
        elem_len = 64;
        break;
      case YKPIV_ALGO_RSA2048:
        elem_len = 128;
        break;
      case YKPIV_ALGO_RSA3072:
        elem_len = 192;
        break;
      case YKPIV_ALGO_RSA4096:
        elem_len = 256;
        break;
    }

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
  else if (YKPIV_IS_EC(algorithm)) {

    if (algorithm == YKPIV_ALGO_ECCP256)
      elem_len = 32;
    if (algorithm == YKPIV_ALGO_ECCP384)
      elem_len = 48;

    params[0] = ec_data;
    lens[0] = ec_data_len;
    param_tag = 0x06;
    n_params = 1;
  }
  else if (YKPIV_IS_25519(algorithm)) {
    elem_len = 32;

    params[0] = ec_data;
    lens[0] = ec_data_len;
    if (algorithm == YKPIV_ALGO_ED25519) {
      param_tag = 0x07;
    } else {
      param_tag = 0x08;
    }
    n_params = 1;
  }
  else {
    return YKPIV_ALGORITHM_ERROR;
  }

  for (int i = 0; i < n_params; i++) {
    if(params[i] == NULL || lens[i] > elem_len) {
      res = YKPIV_ARGUMENT_ERROR;
      goto Cleanup;
    }
    size_t padding = elem_len - lens[i];
    *in_ptr++ = param_tag + i;
    in_ptr += _ykpiv_set_length(in_ptr, elem_len + padding);
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
  if (YKPIV_OK != (res = _ykpiv_ensure_application_selected(state, scp11))) goto Cleanup;

  if ((res = _ykpiv_transfer_data(state, templ, key_data, (unsigned long)(in_ptr - key_data), data, &recv_len, &sw)) != YKPIV_OK) {
    goto Cleanup;
  }
  res = ykpiv_translate_sw_ex(__FUNCTION__, sw);
  if (res != YKPIV_OK) {
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
  int sw = 0;
  unsigned long ul_data_len;

  if (state == NULL || data == NULL || data_len == NULL) {
    return YKPIV_ARGUMENT_ERROR;
  }
  uint8_t scp11 = state->scp11_state.security_level;

  ul_data_len = (unsigned long)*data_len;

  if (YKPIV_OK != (res = _ykpiv_begin_transaction(state))) return res;
  if (YKPIV_OK != (res = _ykpiv_ensure_application_selected(state, scp11))) goto Cleanup;

  if ((res = _ykpiv_transfer_data(state, templ, NULL, 0, data, &ul_data_len, &sw)) != YKPIV_OK) {
    goto Cleanup;
  }
  res = ykpiv_translate_sw_ex(__FUNCTION__, sw);
  if (res != YKPIV_OK) {
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
  uint8_t scp11 = state->scp11_state.security_level;

  ul_data_len = (unsigned long)*data_len;

  if (YKPIV_OK != (res = _ykpiv_begin_transaction(state))) return res;
  if (YKPIV_OK != (res = _ykpiv_ensure_application_selected(state, scp11))) goto Cleanup;

  res = _ykpiv_get_metadata(state, key, data, &ul_data_len);

Cleanup:
  *data_len = ul_data_len;
  _ykpiv_end_transaction(state);
  return res;
}

ykpiv_rc ykpiv_auth_getchallenge(ykpiv_state *state, ykpiv_metadata *metadata, uint8_t *challenge, unsigned long *challenge_len) {
  ykpiv_rc res;

  if (NULL == state) return YKPIV_ARGUMENT_ERROR;
  if (NULL == metadata) return YKPIV_ARGUMENT_ERROR;
  if (NULL == challenge) return YKPIV_ARGUMENT_ERROR;
  if (NULL == challenge_len) return YKPIV_ARGUMENT_ERROR;
  uint8_t scp11 = state->scp11_state.security_level;

  if (YKPIV_OK != (res = _ykpiv_begin_transaction(state))) return res;
  if (YKPIV_OK != (res = _ykpiv_ensure_application_selected(state, scp11))) goto Cleanup;

  metadata->algorithm = YKPIV_ALGO_3DES;

  unsigned char data[256] = {0};
  unsigned long recv_len = sizeof(data);
  res = _ykpiv_get_metadata(state, YKPIV_KEY_CARDMGM, data, &recv_len);
  if (res == YKPIV_OK) {
    res = ykpiv_util_parse_metadata(data, recv_len, metadata);
    if (res != YKPIV_OK) {
      goto Cleanup;
    }
  }

  /* get a challenge from the card */
  APDU apdu = {0};
  apdu.st.ins = YKPIV_INS_AUTHENTICATE;
  apdu.st.p1 = metadata->algorithm;
  apdu.st.p2 = YKPIV_KEY_CARDMGM; /* management key */
  apdu.st.lc = 0x04;
  apdu.st.data[0] = 0x7c;
  apdu.st.data[1] = 0x02;
  apdu.st.data[2] = 0x81; //0x80;
  apdu.st.data[3] = 0x00;
  int sw = 0;
  recv_len = sizeof(data);
  if ((res = _ykpiv_send_apdu(state, &apdu, data, &recv_len, &sw)) != YKPIV_OK) {
    goto Cleanup;
  }
  res = ykpiv_translate_sw_ex(__FUNCTION__, sw);
  if (res != YKPIV_OK) {
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

ykpiv_rc ykpiv_auth_verifyresponse(ykpiv_state *state, ykpiv_metadata *metadata, uint8_t *response, unsigned long response_len) {
  ykpiv_rc res;

  if (NULL == state) return YKPIV_ARGUMENT_ERROR;
  if (NULL == metadata) return YKPIV_ARGUMENT_ERROR;
  if (NULL == response) return YKPIV_ARGUMENT_ERROR;
  if (16 < response_len) return YKPIV_ARGUMENT_ERROR;

  if (YKPIV_OK != (res = _ykpiv_begin_transaction(state))) return res;
  /* note: do not select the applet here, as it resets the challenge state */

  unsigned char data[256] = {0};
  unsigned long recv_len = sizeof(data);

  /* send the response to the card. */
  APDU apdu = {0};
  apdu.st.ins = YKPIV_INS_AUTHENTICATE;
  apdu.st.p1 = metadata->algorithm;
  apdu.st.p2 = YKPIV_KEY_CARDMGM; /* management key */
  unsigned char *dataptr = apdu.st.data;
  *dataptr++ = 0x7c;
  *dataptr++ = (unsigned char)(2 + response_len);
  *dataptr++ = 0x82;
  *dataptr++ = (unsigned char)response_len;
  memcpy(dataptr, response, response_len);
  dataptr += response_len;
  apdu.st.lc = (unsigned char)(dataptr - apdu.st.data);
  int sw = 0;
  if ((res = _ykpiv_send_apdu(state, &apdu, data, &recv_len, &sw)) != YKPIV_OK) {
    goto Cleanup;
  }
  res = ykpiv_translate_sw_ex(__FUNCTION__, sw);
  if (res != YKPIV_OK) {
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

  if (NULL == state) return YKPIV_ARGUMENT_ERROR;

  if (YKPIV_OK != (res = _ykpiv_begin_transaction(state))) return res;

  res = _ykpiv_auth_deauthenticate(state);

  _ykpiv_end_transaction(state);
  return res;
}

/* deauthenticates the user pin */
static ykpiv_rc _ykpiv_auth_deauthenticate(ykpiv_state *state) {
  ykpiv_rc res = YKPIV_OK;
  unsigned char data[256] = { 0 };
  unsigned long recv_len = sizeof(data);
  int sw = 0;

  if (!state) {
    return YKPIV_ARGUMENT_ERROR;
  }

  if (is_version_compatible(state, 5, 4, 3)) {
    unsigned char templ[] = { 0x00, YKPIV_INS_VERIFY, 0xFF, 0x80 };

    res = _ykpiv_transfer_data(state, templ, data, 0, data, &recv_len, &sw);

    if (res < YKPIV_OK) {
      res = ykpiv_translate_sw_ex(__FUNCTION__, sw);
      if (res != YKPIV_OK) {
        DBG("Failed deauthenticating pin");
      }
    }
  }
  else {
    unsigned char templ[] = { 0x00, YKPIV_INS_SELECT_APPLICATION, 0x04, 0x00 };
    const unsigned char* aid;
    unsigned long aid_len;

    // Once mgmt_aid is selected on NEO we can't select piv_aid again... So we use yk_aid.
    // But... YK 5 below 5.3 doesn't allow access to yk_aid, so still use mgmt_aid on non-NEO devices

    if (state->ver.major < 4 && state->ver.major != 0) {
      aid = yk_aid;
      aid_len = sizeof(yk_aid);
    }
    else {
      aid = mgmt_aid;
      aid_len = sizeof(mgmt_aid);
    }

    if ((res = _ykpiv_transfer_data(state, templ, aid, aid_len, data, &recv_len, &sw)) < YKPIV_OK) {
      return res;
    }
    res = ykpiv_translate_sw_ex(__FUNCTION__, sw);
    if (res != YKPIV_OK) {
      DBG("Failed selecting mgmt/yk application");
    }
  }

  return res;
}

bool is_version_compatible(ykpiv_state *state, uint8_t major, uint8_t minor, uint8_t patch) {
#ifdef DEBUG_YK
  if (state->ver.major == 0) {
    return true;
  }
#endif

  return state->ver.major > major ||
         (state->ver.major == major && state->ver.minor > minor) ||
         (state->ver.major == major && state->ver.minor == minor && state->ver.patch >= patch);
}

// if to_slot is set to 0xff, the key will be deleted
ykpiv_rc ykpiv_move_key(ykpiv_state *state, const unsigned char from_slot, const unsigned char to_slot) {
  if(!is_version_compatible(state, 5, 7, 0)) {
    DBG("Move key operation available with firmware version 5.7.0 or higher");
    return YKPIV_NOT_SUPPORTED;
  }
  ykpiv_rc res = YKPIV_OK;
  unsigned char data[256] = {0};
  unsigned long recv_len = sizeof(data);
  int sw = 0;
  unsigned char adpu[] = {0, YKPIV_INS_MOVE_KEY, to_slot, from_slot};
  DBG("Moving key from slot %x to slot %x", from_slot, to_slot);

  if ((res = _ykpiv_transfer_data(state, adpu, NULL, 0, data, &recv_len, &sw)) != YKPIV_OK) {
    return res;
  }
  res = ykpiv_translate_sw_ex(__FUNCTION__, sw);
  if (res != YKPIV_OK) {
    DBG("Failed to move key");
  } else {
    DBG("Key moved from slot %x to %x", from_slot, to_slot);
  }

  return res;
}

ykpiv_rc ykpiv_auth_get_verified(ykpiv_state* state) {
  ykpiv_rc res = YKPIV_OK;

  if (NULL == state) {
    return YKPIV_ARGUMENT_ERROR;
  }

  res = _ykpiv_verify(state, NULL, 0, false, false);

  if (res != YKPIV_OK) {
    res = YKPIV_AUTHENTICATION_ERROR;
  }

  return res;
}

ykpiv_rc ykpiv_auth_verify(ykpiv_state* state, uint8_t* pin, size_t* p_pin_len, int *tries, bool force_select, bool bio, bool verify_spin) {
  return _ykpiv_verify_select(state, (char*)pin, p_pin_len, tries, force_select, bio, verify_spin);
}

ykpiv_rc ykpiv_global_reset(ykpiv_state *state) {
  ykpiv_rc res = YKPIV_OK;
  unsigned char mgm_templ[] = {0x00, YKPIV_INS_SELECT_APPLICATION, 0x04, 0x00};
  unsigned char recv[256] = {0};
  unsigned long recv_len = sizeof(recv);
  int sw = 0;
  if ((res = _ykpiv_transfer_data(state, mgm_templ, mgmt_aid, sizeof(mgmt_aid), recv, &recv_len, &sw)) < YKPIV_OK) {
    return res;
  }
  res = ykpiv_translate_sw_ex(__FUNCTION__, sw);
  if (res != YKPIV_OK) {
    DBG("Failed selecting mgmt/yk application");
    return res;
  }

  unsigned char reset_templ[] = {0, MGM_INS_GLOBAL_RESET, 0, 0};
  recv_len = 0;
  sw = 0;
  res = ykpiv_transfer_data(state, reset_templ, NULL, 0, NULL, &recv_len, &sw);
  if (res != YKPIV_OK) {
    return res;
  }
  return ykpiv_translate_sw_ex(__FUNCTION__, sw);
}