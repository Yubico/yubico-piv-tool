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


const uint8_t CHUID_TMPL[] = {
  0x30, 0x19, 0xd4, 0xe7, 0x39, 0xda, 0x73, 0x9c, 0xed, 0x39, 0xce, 0x73, 0x9d,
  0x83, 0x68, 0x58, 0x21, 0x08, 0x42, 0x10, 0x84, 0x21, 0x38, 0x42, 0x10, 0xc3,
  0xf5, 0x34, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x35, 0x08, 0x32, 0x30, 0x33, 0x30, 0x30,
  0x31, 0x30, 0x31, 0x3e, 0x00, 0xfe, 0x00,
};
#define CHUID_GUID_OFFS 29
#define CB_CARDID 16

const uint8_t CCC_TMPL[] = {
  0xf0, 0x15, 0xa0, 0x00, 0x00, 0x01, 0x16, 0xff, 0x02, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf1, 0x01, 0x21,
  0xf2, 0x01, 0x21, 0xf3, 0x00, 0xf4, 0x01, 0x00, 0xf5, 0x01, 0x10, 0xf6, 0x00,
  0xf7, 0x00, 0xfa, 0x00, 0xfb, 0x00, 0xfc, 0x00, 0xfd, 0x00, 0xfe, 0x00
};

#define CCC_ID_OFFS 9
#define CB_CCC_ID 14

#define TAG_CERT            0x70
#define TAG_CERT_COMPRESS   0x71
#define TAG_CERT_LRC        0xFE
#define TAG_PIVMAN_DATA     0x80
#define TAG_FLAGS_1         0x81
#define TAG_SALT            0x82
#define TAG_PIN_TIMESTAMP   0x83
#define TAG_MSCMAP          0x81
#define TAG_MSROOTS_END     0x82
#define TAG_MSROOTS_MID     0x83

#define TAG_RSA_MODULUS     0x81
#define TAG_RSA_EXP         0x82
#define TAG_ECC_POINT       0x86

#define CB_ECC_POINTP256    65
#define CB_ECC_POINTP384    97


#define YKPIV_OBJ_PIVMAN_DATA 0x5fff00
#define YKPIV_OBJ_ATTESTATION 0x5fff01
#define	YKPIV_OBJ_MSCMAP      0x5fff10
#define	YKPIV_OBJ_MSROOTS1    0x5fff11
#define YKPIV_OBJ_MSROOTS2    0x5fff12
#define YKPIV_OBJ_MSROOTS3    0x5fff13
#define YKPIV_OBJ_MSROOTS4    0x5fff14
#define YKPIV_OBJ_MSROOTS5    0x5fff15

#define CB_OBJ_TAG_MIN      2                       // 1 byte tag + 1 byte len
#define CB_OBJ_TAG_MAX      (CB_OBJ_TAG_MIN + 2)      // 1 byte tag + 3 bytes len

typedef enum {
  PRNG_OK = 0,
  PRNG_GENERAL_ERROR = -1
} prng_rc;

static ykpiv_rc _read_certificate(ykpiv_state *state, uint8_t slot, uint8_t *buf, size_t *buf_len);
static ykpiv_rc _write_certificate(ykpiv_state *state, uint8_t slot, uint8_t *data, size_t data_len);

prng_rc prng_generate(unsigned char *buffer, const size_t cb_req) {
  // TREV TODO: ykpiv.c needs to use this
  prng_rc rc = PRNG_OK;

#ifdef _WINDOWS
  HCRYPTPROV hProv = 0;

  if (CryptAcquireContext(&hProv, NULL, MS_ENHANCED_PROV, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
    if (!CryptGenRandom(hProv, (DWORD)cb_req, buffer)) {
      rc = PRNG_GENERAL_ERROR;
    }

    CryptReleaseContext(hProv, 0);
  }
  else {
    rc = PRNG_GENERAL_ERROR;
  }

#else
  if (-1 == RAND_pseudo_bytes(buffer, cb_req)) {
    rc = PRNG_GENERAL_ERROR;
  }

#endif

  return rc;
}

static size_t _obj_size_max(ykpiv_state *state) {
  return (state && state->isNEO) ? CB_OBJ_MAX_NEO : CB_OBJ_MAX;
}

#define MAX(a,b) (a) > (b) ? (a) : (b)
#define MIN(a,b) (a) < (b) ? (a) : (b)

void* _ykpiv_alloc(ykpiv_state *state, size_t size);
void* _ykpiv_realloc(ykpiv_state *state, void *address, size_t size);
void _ykpiv_free(ykpiv_state *state, void *data);
int _ykpiv_set_length(unsigned char *buffer, size_t length);
int _ykpiv_get_length(const unsigned char *buffer, size_t *len);
ykpiv_rc _ykpiv_begin_transaction(ykpiv_state *state);
ykpiv_rc _ykpiv_end_transaction(ykpiv_state *state);
ykpiv_rc _ykpiv_ensure_application_selected(ykpiv_state *state);

/*
** YKPIV Utility API - aggregate functions and slightly nicer interface
*/

ykpiv_rc ykpiv_util_get_cardid(ykpiv_state *state, ykpiv_cardid *cardid) {
  ykpiv_rc res = YKPIV_OK;
  uint8_t buf[CB_OBJ_MAX];
  size_t len = sizeof(buf);

  if (!cardid) return YKPIV_GENERIC_ERROR;

  if (YKPIV_OK != (res = _ykpiv_begin_transaction(state))) return YKPIV_PCSC_ERROR;
  if (YKPIV_OK != (res = _ykpiv_ensure_application_selected(state))) goto Cleanup;

  res = ykpiv_fetch_object(state, YKPIV_OBJ_CHUID, buf, (unsigned long *)&len);
  if (YKPIV_OK == res) {
    if (len != sizeof(CHUID_TMPL)) {
      res = YKPIV_GENERIC_ERROR;
    }
    else {
      memcpy(cardid->data, buf + CHUID_GUID_OFFS, CB_CARDID);
    }
  }

Cleanup:

  _ykpiv_end_transaction(state);
  return res;
}

ykpiv_rc ykpiv_util_set_cardid(ykpiv_state *state, const ykpiv_cardid *cardid) {
  ykpiv_rc res = YKPIV_OK;
  uint8_t id[CB_CARDID];
  uint8_t buf[sizeof(CHUID_TMPL)];
  size_t len = 0;

  if (!state) return YKPIV_GENERIC_ERROR;

  if (!cardid) {
    if (PRNG_OK != prng_generate(id, sizeof(id))) {
      return YKPIV_RANDOMNESS_ERROR;
    }
  }
  else {
    memcpy(id, cardid->data, sizeof(id));
  }

  if (YKPIV_OK != (res = _ykpiv_begin_transaction(state))) return YKPIV_PCSC_ERROR;
  if (YKPIV_OK != (res = _ykpiv_ensure_application_selected(state))) goto Cleanup;

  memcpy(buf, CHUID_TMPL, sizeof(CHUID_TMPL));
  memcpy(buf + CHUID_GUID_OFFS, id, sizeof(id));
  len = sizeof(CHUID_TMPL);

  res = ykpiv_save_object(state, YKPIV_OBJ_CHUID, buf, len);

  if (YKPIV_OK == res) {
    // also set the CCC for use with systems that require it
    len = sizeof(CCC_TMPL);
    memcpy(buf, CCC_TMPL, len);
    memcpy(buf + CCC_ID_OFFS, id, CB_CCC_ID);

    res = ykpiv_save_object(state, YKPIV_OBJ_CAPABILITY, buf, len);
  }

Cleanup:

  _ykpiv_end_transaction(state);
  return res;
}

ykpiv_devmodel ykpiv_util_devicemodel(ykpiv_state *state) {
  if (!state || state->context == SCARD_E_INVALID_HANDLE)
    return DEVTYPE_UNKNOWN;
  return (state->isNEO ? DEVTYPE_NEOr3 : DEVTYPE_YK4);
}

ykpiv_rc ykpiv_util_list_keys(ykpiv_state *state, uint8_t *key_count, ykpiv_key **data, size_t *data_len) {
  ykpiv_rc res = YKPIV_OK;
  ykpiv_key *pKey = NULL;
  uint8_t *pData = NULL;
  size_t cbData = 0;
  size_t offset = 0;
  uint8_t buf[CB_BUF_MAX];
  size_t cbBuf = 0;
  bool transaction = false;
  size_t i = 0;
  size_t cbRealloc = 0;

  const size_t CB_PAGE = 4096;

  const uint8_t SLOTS[] = {
    YKPIV_KEY_AUTHENTICATION,
    YKPIV_KEY_SIGNATURE,
    YKPIV_KEY_KEYMGM,   
    YKPIV_KEY_RETIRED1,
    YKPIV_KEY_RETIRED2,
    YKPIV_KEY_RETIRED3,
    YKPIV_KEY_RETIRED4,
    YKPIV_KEY_RETIRED5,
    YKPIV_KEY_RETIRED6,
    YKPIV_KEY_RETIRED7,
    YKPIV_KEY_RETIRED8,
    YKPIV_KEY_RETIRED9,
    YKPIV_KEY_RETIRED10,
    YKPIV_KEY_RETIRED11,
    YKPIV_KEY_RETIRED12,
    YKPIV_KEY_RETIRED13,
    YKPIV_KEY_RETIRED14,
    YKPIV_KEY_RETIRED15,
    YKPIV_KEY_RETIRED16,
    YKPIV_KEY_RETIRED17,
    YKPIV_KEY_RETIRED18,
    YKPIV_KEY_RETIRED19,
    YKPIV_KEY_RETIRED20,
    YKPIV_KEY_CARDAUTH
  };

  if ((NULL == data) || (NULL == data_len) || (NULL == key_count)) { return YKPIV_GENERIC_ERROR; }

  if (YKPIV_OK != (res = _ykpiv_begin_transaction(state))) return YKPIV_PCSC_ERROR;
  if (YKPIV_OK != (res = _ykpiv_ensure_application_selected(state))) goto Cleanup;

  // init return parameters
  *key_count = 0;
  *data = NULL;
  *data_len = 0;

  // allocate initial page of buffer
  if (NULL == (pData = _ykpiv_alloc(state, CB_PAGE))) {
    res = YKPIV_MEMORY_ERROR;
    goto Cleanup;
  }

  cbData = CB_PAGE;

  for (i = 0; i < sizeof(SLOTS); i++) {
    cbBuf = sizeof(buf);

    if (YKPIV_OK == (res = _read_certificate(state, SLOTS[i], buf, &cbBuf))) {
      // add current slot to result, grow result buffer if necessary

      cbRealloc = (sizeof(ykpiv_key) + cbBuf - 1) > (cbData - offset) ? MAX((sizeof(ykpiv_key) + cbBuf - 1) - (cbData - offset), CB_PAGE) : 0;

      if (0 != cbRealloc) {
        if (NULL == (pData = _ykpiv_realloc(state, pData, cbData + cbRealloc))) {
          res = YKPIV_MEMORY_ERROR;
          goto Cleanup;
        }
      }

      cbData += cbRealloc;

      // If ykpiv_key is misaligned or results in padding, this causes problems 
      // in the array we return.  If this becomes a problem, we'll probably want 
      // to go with a flat byte array.

      pKey = (ykpiv_key*)(pData + offset);

      pKey->slot = SLOTS[i];
      pKey->cert_len = (uint16_t)cbBuf;
      memcpy(pKey->cert, buf, cbBuf);

      offset += sizeof(ykpiv_key) + cbBuf - 1;
      (*key_count)++;
    }
  }

  *data = (ykpiv_key*)pData;
  pData = NULL;

  if (data_len) {
    *data_len = offset;
  }

  res = YKPIV_OK;

Cleanup:

  if (pData) { _ykpiv_free(state, pData); }

  _ykpiv_end_transaction(state);
  return res;
}

ykpiv_rc ykpiv_util_free(ykpiv_state *state, void *data) {
  if (!data) return YKPIV_OK;
  if (!state || (!(state->allocator.pfn_free))) return YKPIV_GENERIC_ERROR;

  _ykpiv_free(state, data);

  return YKPIV_OK;
}

ykpiv_rc ykpiv_util_read_cert(ykpiv_state *state, uint8_t slot, uint8_t **data, size_t *data_len) {
  ykpiv_rc res = YKPIV_OK;
  uint8_t buf[CB_BUF_MAX];
  size_t cbBuf = sizeof(buf);

  if ((NULL == data )|| (NULL == data_len)) return YKPIV_GENERIC_ERROR;

  if (YKPIV_OK != (res = _ykpiv_begin_transaction(state))) return YKPIV_PCSC_ERROR;
  if (YKPIV_OK != (res = _ykpiv_ensure_application_selected(state))) goto Cleanup;

  *data = 0;
  *data_len = 0;

  if (YKPIV_OK == (res = _read_certificate(state, slot, buf, &cbBuf))) {
    if (NULL == (*data = _ykpiv_alloc(state, cbBuf))) {
      res = YKPIV_MEMORY_ERROR;
      goto Cleanup;
    }

    memcpy(*data, buf, cbBuf);

    *data_len = cbBuf;
  }

Cleanup:

  _ykpiv_end_transaction(state);
  return res;
}

ykpiv_rc ykpiv_util_write_cert(ykpiv_state *state, uint8_t slot, uint8_t *data, size_t data_len) {
  ykpiv_rc res = YKPIV_OK;

  if (YKPIV_OK != (res = _ykpiv_begin_transaction(state))) return YKPIV_PCSC_ERROR;
  if (YKPIV_OK != (res = _ykpiv_ensure_application_selected(state))) goto Cleanup;

  res = _write_certificate(state, slot, data, data_len);

Cleanup:

  _ykpiv_end_transaction(state);
  return res;
}

ykpiv_rc ykpiv_util_delete_cert(ykpiv_state *state, uint8_t slot) {
  return ykpiv_util_write_cert(state, slot, NULL, 0);
}

ykpiv_rc ykpiv_util_read_mscmap(ykpiv_state *state, ykpiv_container **containers, size_t *n_containers) {
  ykpiv_rc res = YKPIV_OK;
  uint8_t buf[CB_BUF_MAX];
  size_t cbBuf = sizeof(buf);
  size_t len = 0;
  uint8_t *ptr = NULL;

  if ((NULL == containers) || (NULL == n_containers)) { res = YKPIV_GENERIC_ERROR; goto Cleanup; }
  if (YKPIV_OK != (res = _ykpiv_begin_transaction(state))) return YKPIV_PCSC_ERROR;
  if (YKPIV_OK != (res = _ykpiv_ensure_application_selected(state))) goto Cleanup;

  *containers = 0;
  *n_containers = 0;

  if (YKPIV_OK == (res = ykpiv_fetch_object(state, YKPIV_OBJ_MSCMAP, buf, (unsigned long*)&cbBuf))) {
    ptr = buf;

    // check that object contents are at least large enough to read the header
    if (cbBuf < CB_OBJ_TAG_MIN) {
      res = YKPIV_OK;
      goto Cleanup;
    }

    if (*ptr++ == TAG_MSCMAP) {
      ptr += _ykpiv_get_length(ptr, &len);

      // check that decoded length represents object contents
      if (len > (cbBuf - (ptr - buf))) {
        res = YKPIV_OK;
        goto Cleanup;
      }

      if (NULL == (*containers = _ykpiv_alloc(state, len))) {
        res = YKPIV_MEMORY_ERROR;
        goto Cleanup;
      }

      // should check if container map isn't corrupt

      memcpy(*containers, ptr, len);
      *n_containers = len / sizeof(ykpiv_container);
    }
  }

Cleanup:

  _ykpiv_end_transaction(state);
  return res;
}

ykpiv_rc ykpiv_util_write_mscmap(ykpiv_state *state, ykpiv_container *containers, size_t n_containers) {
  ykpiv_rc res = YKPIV_OK;
  uint8_t buf[CB_OBJ_MAX];
  size_t cbBuf = sizeof(buf);
  size_t offset = 0;
  size_t req_len = 0;
  size_t data_len = n_containers * sizeof(ykpiv_container);

  if (YKPIV_OK != (res = _ykpiv_begin_transaction(state))) return YKPIV_PCSC_ERROR;
  if (YKPIV_OK != (res = _ykpiv_ensure_application_selected(state))) goto Cleanup;

  // check if data and data_len are zero, this means that
  // we intend to delete the object
  if ((NULL == containers) || (0 == n_containers)) {

    // if either containers or n_containers are non-zero, return an error, 
    // that we only delete strictly when both are set properly
    if ((NULL != containers) || (0 != n_containers)) {
      res = YKPIV_GENERIC_ERROR;
    }
    else {
      res = ykpiv_save_object(state, YKPIV_OBJ_MSCMAP, NULL, 0);
    }

    goto Cleanup;
  }

  // encode object data for storage

  // calculate the required length of the encoded object
  req_len = 1 /* data tag */ + _ykpiv_set_length(buf, data_len) + data_len;

  if (req_len > _obj_size_max(state)) return YKPIV_SIZE_ERROR;

  buf[offset++] = TAG_MSCMAP;
  offset += _ykpiv_set_length(buf + offset, data_len);
  memcpy(buf + offset, (uint8_t*)containers, data_len);
  offset += data_len;

  // write onto device
  res = ykpiv_save_object(state, YKPIV_OBJ_MSCMAP, buf, offset);

Cleanup:

  _ykpiv_end_transaction(state);
  return res;
}

ykpiv_rc ykpiv_util_read_msroots(ykpiv_state *state, uint8_t **data, size_t *data_len) {
  ykpiv_rc res = YKPIV_OK;
  uint8_t buf[CB_BUF_MAX];
  size_t cbBuf = sizeof(buf);
  size_t len = 0;
  uint8_t *ptr = NULL;
  int object_id = 0;
  uint8_t tag = 0;
  uint8_t *pData = NULL;
  size_t cbData = 0;
  size_t cbRealloc = 0;
  size_t offset = 0;

  if (!data || !data_len) return YKPIV_GENERIC_ERROR;

  if (YKPIV_OK != (res = _ykpiv_begin_transaction(state))) return YKPIV_PCSC_ERROR;
  if (YKPIV_OK != (res = _ykpiv_ensure_application_selected(state))) goto Cleanup;

  *data = 0;
  *data_len = 0;

  // allocate first page
  cbData = _obj_size_max(state);
  if (NULL == (pData = _ykpiv_alloc(state, cbData))) { res = YKPIV_MEMORY_ERROR; goto Cleanup; }

  for (object_id = YKPIV_OBJ_MSROOTS1; object_id <= YKPIV_OBJ_MSROOTS5; object_id++) {
    cbBuf = sizeof(buf);

    if (YKPIV_OK != (res = ykpiv_fetch_object(state, object_id, buf, (unsigned long*)&cbBuf))) {
      goto Cleanup;
    }

    ptr = buf;

    if (cbBuf < CB_OBJ_TAG_MIN) {
      res = YKPIV_OK;
      goto Cleanup;
    }

    tag = *ptr++;

    if (((TAG_MSROOTS_MID != tag) && (TAG_MSROOTS_END != tag)) ||
        ((YKPIV_OBJ_MSROOTS5 == object_id) && (TAG_MSROOTS_END != tag))) {
      // the current object doesn't contain a valid part of a msroots file
      res = YKPIV_OK; // treat condition as object isn't found
      goto Cleanup;
    }

    ptr += _ykpiv_get_length(ptr, &len);

    // check that decoded length represents object contents
    if (len > (cbBuf - (ptr - buf))) {
      res = YKPIV_OK;
      goto Cleanup;
    }

    cbRealloc = len > (cbData - offset) ? len - (cbData - offset) : 0;

    if (0 != cbRealloc) {
      if (NULL == (pData = _ykpiv_realloc(state, pData, cbData + cbRealloc))) {
        res = YKPIV_MEMORY_ERROR;
        goto Cleanup;
      }
    }

    cbData += cbRealloc;

    memcpy(pData + offset, ptr, len);
    offset += len;

    if (TAG_MSROOTS_END == tag) {
      break;
    }
  }

  // return data
  *data = pData;
  pData = NULL;
  *data_len = offset;

  res = YKPIV_OK;

Cleanup:

  if (pData) { _ykpiv_free(state, pData); }

  _ykpiv_end_transaction(state);
  return res;
}

ykpiv_rc ykpiv_util_write_msroots(ykpiv_state *state, uint8_t *data, size_t data_len) {
  ykpiv_rc res = YKPIV_OK;
  uint8_t buf[CB_OBJ_MAX];
  size_t offset = 0;
  size_t data_offset = 0;
  size_t data_chunk = 0;
  size_t n_objs = 0;
  unsigned int i = 0;
  size_t cb_obj_max = _obj_size_max(state);

  if (YKPIV_OK != (res = _ykpiv_begin_transaction(state))) return YKPIV_PCSC_ERROR;
  if (YKPIV_OK != (res = _ykpiv_ensure_application_selected(state))) goto Cleanup;

  // check if either data and data_len are zero, this means that
  // we intend to delete the object
  if ((NULL == data) || (0 == data_len)) {

    // if either data or data_len are non-zero, return an error, 
    // that we only delete strictly when both are set properly
    if ((NULL != data) || (0 != data_len)) {
      res = YKPIV_GENERIC_ERROR;
    }
    else {
      // it should be sufficient to just delete the first object, though
      // to be complete we should erase all of the MSROOTS objects
      res = ykpiv_save_object(state, YKPIV_OBJ_MSROOTS1, NULL, 0);
    }

    goto Cleanup;
  }

  // calculate number of objects required to store blob
  n_objs = (data_len / (cb_obj_max - CB_OBJ_TAG_MAX)) + 1;

  // we're allowing 5 objects to be used to span the msroots file
  if (n_objs > 5) {
    res = YKPIV_SIZE_ERROR;
    goto Cleanup;
  }

  for (i = 0; i < n_objs; i++) {
    offset = 0;
    data_chunk = MIN(cb_obj_max - CB_OBJ_TAG_MAX, data_len - data_offset);

    // encode object data for storage
    buf[offset++] = (i == (n_objs - 1)) ? TAG_MSROOTS_END : TAG_MSROOTS_MID;
    offset += _ykpiv_set_length(buf + offset, data_chunk);
    memcpy(buf + offset, data + data_offset, data_chunk);
    offset += data_chunk;

    // write onto device
    res = ykpiv_save_object(state, YKPIV_OBJ_MSROOTS1 + i, buf, offset);

    if (YKPIV_OK != res) {
      goto Cleanup;
    }

    data_offset += data_chunk;
  }

Cleanup:

  _ykpiv_end_transaction(state);
  return res;
}

ykpiv_rc ykpiv_util_generate_key(ykpiv_state *state, uint8_t slot, uint8_t algorithm, uint8_t pin_policy, uint8_t touch_policy, uint8_t **modulus, size_t *modulus_len, uint8_t **exp, size_t *exp_len, uint8_t **point, size_t *point_len) {
  ykpiv_rc res = YKPIV_OK;
  unsigned char in_data[11];
  unsigned char *in_ptr = in_data;
  unsigned char data[1024];
  unsigned char templ[] = { 0, YKPIV_INS_GENERATE_ASYMMETRIC, 0, 0 };
  unsigned long recv_len = sizeof(data);
  int sw;
  uint8_t *ptr_modulus = NULL;
  size_t  cb_modulus = 0;
  uint8_t *ptr_exp = NULL;
  size_t  cb_exp = 0;
  uint8_t *ptr_point = NULL;
  size_t  cb_point = 0;

  switch (algorithm) {
  case YKPIV_ALGO_RSA1024:
  case YKPIV_ALGO_RSA2048:
    if (!modulus || !modulus_len || !exp || !exp_len) {
      if (state->verbose) { fprintf(stderr, "Invalid output parameter for RSA algorithm"); }
      return YKPIV_GENERIC_ERROR;
    }
    *modulus = NULL;
    *modulus_len = 0;
    *exp = NULL;
    *exp_len = 0;
    break;

  case  YKPIV_ALGO_ECCP256:
  case  YKPIV_ALGO_ECCP384:
    if (!point || !point_len) {
      if (state->verbose) { fprintf(stderr, "Invalid output parameter for ECC algorithm"); }
      return YKPIV_GENERIC_ERROR;
    }
    *point = NULL;
    *point_len = 0;
    break;

  default:
    if (state->verbose) { fprintf(stderr, "Invalid algorithm specified"); }
    return YKPIV_GENERIC_ERROR;
  }

  if (YKPIV_OK != (res = _ykpiv_begin_transaction(state))) return YKPIV_PCSC_ERROR;
  if (YKPIV_OK != (res = _ykpiv_ensure_application_selected(state))) goto Cleanup;

  templ[3] = slot;

  *in_ptr++ = 0xac;
  *in_ptr++ = 3;
  *in_ptr++ = YKPIV_ALGO_TAG;
  *in_ptr++ = 1;
  *in_ptr++ = algorithm;

  if (in_data[4] == 0) {
    res = YKPIV_ALGORITHM_ERROR;
    if (state->verbose) { fprintf(stderr, "Unexpected algorithm.\n"); }
    goto Cleanup;
  }

  if (pin_policy != YKPIV_PINPOLICY_DEFAULT) {
    in_data[1] += 3;
    *in_ptr++ = YKPIV_PINPOLICY_TAG;
    *in_ptr++ = 1;
    *in_ptr++ = pin_policy;
  }

  if (touch_policy != YKPIV_TOUCHPOLICY_DEFAULT) {
    in_data[1] += 3;
    *in_ptr++ = YKPIV_TOUCHPOLICY_TAG;
    *in_ptr++ = 1;
    *in_ptr++ = touch_policy;
  }

  if (YKPIV_OK != (res = ykpiv_transfer_data(state, templ, in_data, (long)(in_ptr - in_data), data, &recv_len, &sw))) {
    if (state->verbose) { fprintf(stderr, "Failed to communicate.\n"); }
    goto Cleanup;
  }
  else if (sw != SW_SUCCESS) {
    if (state->verbose) { fprintf(stderr, "Failed to generate new key ("); }

    if (sw == SW_ERR_INCORRECT_SLOT) {
      res = YKPIV_KEY_ERROR;
      if (state->verbose) { fprintf(stderr, "incorrect slot)\n"); }
    }
    else if (sw == SW_ERR_INCORRECT_PARAM) {
      res = YKPIV_ALGORITHM_ERROR;

      if (state->verbose) {
        if (pin_policy != YKPIV_PINPOLICY_DEFAULT) {
          fprintf(stderr, "pin policy not supported?)\n");
        }
        else if (touch_policy != YKPIV_TOUCHPOLICY_DEFAULT) {
          fprintf(stderr, "touch policy not supported?)\n");
        }
        else {
          fprintf(stderr, "algorithm not supported?)\n");
        }
      }
    }
    else {
      res = YKPIV_GENERIC_ERROR;
      if (state->verbose) { fprintf(stderr, "error %x)\n", sw); }
    }

    goto Cleanup;
  }

  if ((YKPIV_ALGO_RSA1024 == algorithm) || (YKPIV_ALGO_RSA2048 == algorithm)) {
    unsigned char *data_ptr = data + 5;
    size_t len = 0;

    if (*data_ptr != TAG_RSA_MODULUS) {
      if (state->verbose) { fprintf(stderr, "Failed to parse public key structure (modulus).\n"); }
      res = YKPIV_PARSE_ERROR;
      goto Cleanup;
    }

    data_ptr++;
    data_ptr += _ykpiv_get_length(data_ptr, &len);

    cb_modulus = len;
    if (NULL == (ptr_modulus = _ykpiv_alloc(state, cb_modulus))) {
      if (state->verbose) { fprintf(stderr, "Failed to allocate memory for modulus.\n"); }
      res = YKPIV_MEMORY_ERROR;
      goto Cleanup;
    }

    memcpy(ptr_modulus, data_ptr, cb_modulus);

    data_ptr += len;

    if (*data_ptr != TAG_RSA_EXP) {
      if (state->verbose) { fprintf(stderr, "Failed to parse public key structure (public exponent).\n"); }
      res = YKPIV_PARSE_ERROR;
      goto Cleanup;
    }

    data_ptr++;
    data_ptr += _ykpiv_get_length(data_ptr, &len);

    cb_exp = len;
    if (NULL == (ptr_exp = _ykpiv_alloc(state, cb_exp))) {
      if (state->verbose) { fprintf(stderr, "Failed to allocate memory for public exponent.\n"); }
      res = YKPIV_MEMORY_ERROR;
      goto Cleanup;
    }

    memcpy(ptr_exp, data_ptr, cb_exp);

    // set output parameters

    *modulus = ptr_modulus;
    ptr_modulus = NULL;
    *modulus_len = cb_modulus;
    *exp = ptr_exp;
    ptr_exp = NULL;
    *exp_len = cb_exp;
  }
  else if ((YKPIV_ALGO_ECCP256 == algorithm) || (YKPIV_ALGO_ECCP384 == algorithm)) {
    unsigned char *data_ptr = data + 3;
    size_t len;

    if (YKPIV_ALGO_ECCP256 == algorithm) {
      len = CB_ECC_POINTP256;
    }
    else {
      len = CB_ECC_POINTP384;
    }

    if (*data_ptr++ != TAG_ECC_POINT) {
      if (state->verbose) { fprintf(stderr, "Failed to parse public key structure.\n"); }
      res = YKPIV_PARSE_ERROR;
      goto Cleanup;
    }

    if (*data_ptr++ != len) { /* the curve point should always be determined by the curve */
      if (state->verbose) { fprintf(stderr, "Unexpected length.\n"); }
      res = YKPIV_ALGORITHM_ERROR;
      goto Cleanup;
    }

    cb_point = len;
    if (NULL == (ptr_point = _ykpiv_alloc(state, cb_point))) {
      if (state->verbose) { fprintf(stderr, "Failed to allocate memory for public point.\n"); }
      res = YKPIV_MEMORY_ERROR;
      goto Cleanup;
    }

    memcpy(ptr_point, data_ptr, cb_point);

    // set output parameters

    *point = ptr_point;
    ptr_point = NULL;
    *point_len = cb_point;
  }
  else {
    if (state->verbose) { fprintf(stderr, "Wrong algorithm.\n"); }
    res = YKPIV_ALGORITHM_ERROR;
    goto Cleanup;
  }

Cleanup:

  if (ptr_modulus) { _ykpiv_free(state, modulus); }
  if (ptr_exp) { _ykpiv_free(state, ptr_exp); }
  if (ptr_point) { _ykpiv_free(state, ptr_exp); }

  _ykpiv_end_transaction(state);
  return res;
}


ykpiv_rc ykpiv_util_reset(ykpiv_state *state) {
  unsigned char templ[] = {0, YKPIV_INS_RESET, 0, 0};
  unsigned char data[0xff];
  unsigned long recv_len = sizeof(data);
  ykpiv_rc res;
  int sw;

  /* note: the reset function is only available when both pins are blocked. */
  res = ykpiv_transfer_data(state, templ, NULL, 0, data, &recv_len, &sw);
  if (YKPIV_OK == res && SW_SUCCESS == sw) {
     return YKPIV_OK;
  }
  return YKPIV_GENERIC_ERROR;
}

static int _slot2object(uint8_t slot) {
  int object_id = -1;

  switch (slot) {
  case YKPIV_KEY_AUTHENTICATION:
    object_id = YKPIV_OBJ_AUTHENTICATION;
    break;

  case YKPIV_KEY_SIGNATURE:
    object_id = YKPIV_OBJ_SIGNATURE;
    break;

  case  YKPIV_KEY_KEYMGM:
    object_id = YKPIV_OBJ_KEY_MANAGEMENT;
    break;

  case YKPIV_KEY_CARDAUTH:
    object_id = YKPIV_OBJ_CARD_AUTH;
    break;

  case YKPIV_KEY_ATTESTATION:
    object_id = YKPIV_OBJ_ATTESTATION;
    break;

  default:
    if ((slot >= YKPIV_KEY_RETIRED1) && (slot <= YKPIV_KEY_RETIRED20)) {
      object_id = YKPIV_OBJ_RETIRED1 + (slot - YKPIV_KEY_RETIRED1);
    }
    break;
  }

  return object_id;
}

static ykpiv_rc _read_certificate(ykpiv_state *state, uint8_t slot, uint8_t *buf, size_t *buf_len) {
  ykpiv_rc res = YKPIV_OK;
  uint8_t *ptr = NULL;
  int object_id = _slot2object(slot);
  size_t len = 0;

  if (-1 == object_id) return YKPIV_INVALID_OBJECT;

  if (YKPIV_OK == (res = ykpiv_fetch_object(state, object_id, buf, (unsigned long*)buf_len))) {
    ptr = buf;

    // check that object contents are at least large enough to read the tag
    if (*buf_len < CB_OBJ_TAG_MIN) {
      *buf_len = 0;
      return YKPIV_OK;
    }

    // check that first byte indicates "certificate" type

    if (*ptr++ == TAG_CERT) {
      ptr += _ykpiv_get_length(ptr, &len);

      // check that decoded length represents object contents
      if (len > (*buf_len - (ptr - buf))) {
        *buf_len = 0;
        return YKPIV_OK;
      }

      memmove(buf, ptr, len);
      *buf_len = len;
    }
  }
  else {
    *buf_len = 0;
  }

  return res;
}

static ykpiv_rc _write_certificate(ykpiv_state *state, uint8_t slot, uint8_t *data, size_t data_len) {
  uint8_t buf[CB_OBJ_MAX];
  size_t cbBuf = sizeof(buf);
  int object_id = _slot2object(slot);
  size_t offset = 0;
  size_t req_len = 0;

  if (-1 == object_id) return YKPIV_INVALID_OBJECT;

  // check if data or data_len are zero, this means that we intend to delete the object
  if ((NULL == data) || (0 == data_len)) {

    // if either data or data_len are non-zero, return an error, 
    // that we only delete strictly when both are set properly
    if ((NULL != data) || (0 != data_len)) {
      return YKPIV_GENERIC_ERROR;
    }

    return ykpiv_save_object(state, object_id, NULL, 0);
  }

  // encode certificate data for storage

  // calculate the required length of the encoded object
  req_len = 1 /* cert tag */ + 3 /* compression tag + data*/ + 2 /* lrc */;
  req_len += _ykpiv_set_length(buf, data_len);

  if (req_len > _obj_size_max(state)) return YKPIV_SIZE_ERROR;

  buf[offset++] = TAG_CERT;
  offset += _ykpiv_set_length(buf + offset, data_len);
  memcpy(buf + offset, data, data_len);
  offset += data_len;

  // write compression info and LRC trailer
  buf[offset++] = TAG_CERT_COMPRESS;
  buf[offset++] = 0x01;
  buf[offset++] = 0x00; // TODO: Handle compression when certificate exceeds buffer size
  buf[offset++] = TAG_CERT_LRC; // LRC
  buf[offset++] = 00;

  // write onto device
  return ykpiv_save_object(state, object_id, buf, offset);
}
