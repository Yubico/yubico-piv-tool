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

#include <string.h>
#include <stdio.h>
#include <time.h>
 
#ifdef USE_CERT_COMPRESS
#include <zlib.h>
#endif

#include "internal.h"
#include "ykpiv.h"

#define MAX(a,b) (a) > (b) ? (a) : (b)
#define MIN(a,b) (a) < (b) ? (a) : (b)

/*
 * Format defined in SP-800-73-4, Appendix A, Table 9
 *
 * FASC-N containing S9999F9999F999999F0F1F0000000000300001E encoded in
 * 4-bit BCD with 1 bit parity. run through the tools/fasc.pl script to get
 * bytes. This CHUID has an expiry of 2030-01-01.
 *
 * Defined fields:
 *  - 0x30: FASC-N (hard-coded)
 *  - 0x34: Card UUID / GUID (settable)
 *  - 0x35: Exp. Date (hard-coded)
 *  - 0x3e: Signature (hard-coded, empty)
 *  - 0xfe: Error Detection Code (hard-coded)
 */
const uint8_t CHUID_TMPL[] = {
  0x30, 0x19, 0xd4, 0xe7, 0x39, 0xda, 0x73, 0x9c, 0xed, 0x39, 0xce, 0x73, 0x9d,
  0x83, 0x68, 0x58, 0x21, 0x08, 0x42, 0x10, 0x84, 0x21, 0xc8, 0x42, 0x10, 0xc3,
  0xeb, 0x34, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x35, 0x08, 0x32, 0x30, 0x33, 0x30, 0x30,
  0x31, 0x30, 0x31, 0x3e, 0x00, 0xfe, 0x00,
};
#define CHUID_GUID_OFFS 29
#define TAG_CHUID_UUID 0x34

// f0: Card Identifier
//  - 0xa000000116 == GSC-IS RID
//  - 0xff == Manufacturer ID (dummy)
//  - 0x02 == Card type (javaCard)
//  - next 14 bytes: card ID
const uint8_t CCC_TMPL[] = {
  0xf0, 0x15, 0xa0, 0x00, 0x00, 0x01, 0x16, 0xff, 0x02, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf1, 0x01, 0x21,
  0xf2, 0x01, 0x21, 0xf3, 0x00, 0xf4, 0x01, 0x00, 0xf5, 0x01, 0x10, 0xf6, 0x00,
  0xf7, 0x00, 0xfa, 0x00, 0xfb, 0x00, 0xfc, 0x00, 0xfd, 0x00, 0xfe, 0x00
};
#define CCC_ID_OFFS 9

static ykpiv_rc _read_certificate(ykpiv_state *state, uint8_t slot, uint8_t *buf, size_t *buf_len);
static ykpiv_rc _write_certificate(ykpiv_state *state, uint8_t slot, uint8_t *data, size_t data_len, uint8_t certinfo);

static ykpiv_rc _read_metadata(ykpiv_state *state, uint8_t tag, uint8_t* data, size_t* pcb_data);
static ykpiv_rc _write_metadata(ykpiv_state *state, uint8_t tag, uint8_t *data, size_t cb_data);
static ykpiv_rc _get_metadata_item(uint8_t *data, size_t cb_data, uint8_t tag, uint8_t **pp_item, size_t *pcb_item);
static ykpiv_rc _set_metadata_item(uint8_t *data, size_t *pcb_data, size_t cb_data_max, uint8_t tag, uint8_t *p_item, size_t cb_item);

static size_t _obj_size_max(ykpiv_state *state) {
  return (state && state->model == DEVTYPE_NEOr3) ? CB_OBJ_MAX_NEO : CB_OBJ_MAX;
}

static unsigned long get_length_size(unsigned long length) {
  if (length < 0x80) {
    return 1;
  }
  else if (length < 0x100) {
    return 2;
  }
  else {
    return 3;
  }
}

/*
** YKPIV Utility API - aggregate functions and slightly nicer interface
*/

ykpiv_rc ykpiv_util_get_cardid(ykpiv_state *state, ykpiv_cardid *cardid) {
  ykpiv_rc res = YKPIV_OK;
  uint8_t buf[CB_OBJ_MAX] = {0};
  unsigned long len = sizeof(buf);
  uint8_t *p_temp = NULL;
  size_t offs, cb_temp = 0;
  uint8_t tag = 0;

  if (!cardid) return YKPIV_ARGUMENT_ERROR;
   uint8_t scp11 = state->scp11_state.security_level;

  if (YKPIV_OK != (res = _ykpiv_begin_transaction(state))) return res;
  if (YKPIV_OK != (res = _ykpiv_ensure_application_selected(state, scp11))) goto Cleanup;

  if ((res = _ykpiv_fetch_object(state, YKPIV_OBJ_CHUID, buf, &len)) == YKPIV_OK) {
    p_temp = buf;

    while (p_temp < (buf + len)) {
      tag = *p_temp++;

      offs = _ykpiv_get_length(p_temp, buf + len, &cb_temp);
      if (!offs) {
        res = YKPIV_PARSE_ERROR;
        goto Cleanup;
      }

      p_temp += offs;

      if (tag == TAG_CHUID_UUID) {
        /* found card uuid */
        if (cb_temp < YKPIV_CARDID_SIZE || p_temp + YKPIV_CARDID_SIZE > buf + len) {
          res = YKPIV_SIZE_ERROR;
          goto Cleanup;
        }

        res = YKPIV_OK;
        memcpy(cardid->data, p_temp, YKPIV_CARDID_SIZE);
        goto Cleanup;
      }

      p_temp += cb_temp;
    }

    /* not found, not malformed */
    res = YKPIV_GENERIC_ERROR;
  }

Cleanup:

  _ykpiv_end_transaction(state);
  return res;
}

ykpiv_rc ykpiv_util_set_cardid(ykpiv_state *state, const ykpiv_cardid *cardid) {
  ykpiv_rc res = YKPIV_OK;
  uint8_t id[YKPIV_CARDID_SIZE] = {0};
  uint8_t buf[sizeof(CHUID_TMPL)] = {0};
  size_t len = 0;

  if (!state) return YKPIV_ARGUMENT_ERROR;
  uint8_t scp11 = state->scp11_state.security_level;

  if (!cardid) {
    if (PRNG_OK != _ykpiv_prng_generate(id, sizeof(id))) {
      return YKPIV_RANDOMNESS_ERROR;
    }
  }
  else {
    memcpy(id, cardid->data, sizeof(id));
  }

  if (YKPIV_OK != (res = _ykpiv_begin_transaction(state))) return res;
  if (YKPIV_OK != (res = _ykpiv_ensure_application_selected(state, scp11))) goto Cleanup;

  memcpy(buf, CHUID_TMPL, sizeof(CHUID_TMPL));
  memcpy(buf + CHUID_GUID_OFFS, id, sizeof(id));
  len = sizeof(CHUID_TMPL);

  res = _ykpiv_save_object(state, YKPIV_OBJ_CHUID, buf, len);

Cleanup:

  _ykpiv_end_transaction(state);
  return res;
}

ykpiv_rc ykpiv_util_get_cccid(ykpiv_state *state, ykpiv_cccid *ccc) {
  ykpiv_rc res = YKPIV_OK;
  uint8_t buf[CB_OBJ_MAX] = {0};
  unsigned long len = sizeof(buf);

  if (!ccc) return YKPIV_ARGUMENT_ERROR;

  uint8_t scp11 = state->scp11_state.security_level;
  if (YKPIV_OK != (res = _ykpiv_begin_transaction(state))) return res;
  if (YKPIV_OK != (res = _ykpiv_ensure_application_selected(state, scp11))) goto Cleanup;

  res = _ykpiv_fetch_object(state, YKPIV_OBJ_CAPABILITY, buf, &len);
  if (YKPIV_OK == res) {
    if (len != sizeof(CCC_TMPL)) {
      res = YKPIV_GENERIC_ERROR;
    }
    else {
      memcpy(ccc->data, buf + CCC_ID_OFFS, YKPIV_CCCID_SIZE);
    }
  }

Cleanup:

  _ykpiv_end_transaction(state);
  return res;
}

ykpiv_rc ykpiv_util_set_cccid(ykpiv_state *state, const ykpiv_cccid *ccc) {
  ykpiv_rc res = YKPIV_OK;
  uint8_t id[YKPIV_CCCID_SIZE] = {0};
  uint8_t buf[sizeof(CCC_TMPL)] = {0};
  size_t len = 0;

  if (!state) return YKPIV_ARGUMENT_ERROR;
  uint8_t scp11 = state->scp11_state.security_level;

  if (!ccc) {
    if (PRNG_OK != _ykpiv_prng_generate(id, sizeof(id))) {
      return YKPIV_RANDOMNESS_ERROR;
    }
  }
  else {
    memcpy(id, ccc->data, sizeof(id));
  }

  if (YKPIV_OK != (res = _ykpiv_begin_transaction(state))) return res;
  if (YKPIV_OK != (res = _ykpiv_ensure_application_selected(state, scp11))) goto Cleanup;

  len = sizeof(CCC_TMPL);
  memcpy(buf, CCC_TMPL, len);
  memcpy(buf + CCC_ID_OFFS, id, YKPIV_CCCID_SIZE);
  res = _ykpiv_save_object(state, YKPIV_OBJ_CAPABILITY, buf, len);

Cleanup:
  _ykpiv_end_transaction(state);
  return res;
}

ykpiv_devmodel ykpiv_util_devicemodel(ykpiv_state *state) {
  if (!state || !state->context || (state->context == (SCARDCONTEXT)-1)) {
    return DEVTYPE_UNKNOWN;
  }
  return state->model;
}

ykpiv_rc ykpiv_util_list_keys(ykpiv_state *state, uint8_t *key_count, ykpiv_key **data, size_t *data_len) {
  ykpiv_rc res = YKPIV_OK;
  ykpiv_key *pKey = NULL;
  uint8_t *pData = NULL;
  uint8_t *pTemp = NULL;
  size_t cbData = 0;
  size_t offset = 0;
  uint8_t buf[CB_BUF_MAX] = {0};
  size_t cbBuf = 0;
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

  if ((NULL == data) || (NULL == data_len) || (NULL == key_count)) { return YKPIV_ARGUMENT_ERROR; }

  uint8_t scp11 = state->scp11_state.security_level;
  if (YKPIV_OK != (res = _ykpiv_begin_transaction(state))) return res;
  if (YKPIV_OK != (res = _ykpiv_ensure_application_selected(state, scp11))) goto Cleanup;

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
    res = _read_certificate(state, SLOTS[i], buf, &cbBuf);

    if ((res == YKPIV_OK) && (cbBuf > 0)) {
      // add current slot to result, grow result buffer if necessary

      cbRealloc = (sizeof(ykpiv_key) + cbBuf - 1) > (cbData - offset) ? MAX((sizeof(ykpiv_key) + cbBuf - 1) - (cbData - offset), CB_PAGE) : 0;

      if (0 != cbRealloc) {
        if (!(pTemp = _ykpiv_realloc(state, pData, cbData + cbRealloc))) {
          /* realloc failed, pData will be freed in cleanup */
          res = YKPIV_MEMORY_ERROR;
          goto Cleanup;
        }
        yc_memzero(pTemp + cbData, cbRealloc); // clear newly allocated memory
        pData = pTemp;
        pTemp = NULL;
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
  if (!state || (!(state->allocator.pfn_free))) return YKPIV_ARGUMENT_ERROR;

  _ykpiv_free(state, data);

  return YKPIV_OK;
}

ykpiv_rc ykpiv_util_read_cert(ykpiv_state *state, uint8_t slot, uint8_t **data, size_t *data_len) {
  ykpiv_rc res = YKPIV_OK;
  uint8_t buf[CB_BUF_MAX] = {0};
  size_t cbBuf = sizeof(buf);

  if ((NULL == data )|| (NULL == data_len)) return YKPIV_ARGUMENT_ERROR;

  uint8_t scp11 = state->scp11_state.security_level;
  if (YKPIV_OK != (res = _ykpiv_begin_transaction(state))) return res;
  if (YKPIV_OK != (res = _ykpiv_ensure_application_selected(state, scp11))) goto Cleanup;

  *data = 0;
  *data_len = 0;

  if (YKPIV_OK == (res = _read_certificate(state, slot, buf, &cbBuf))) {

    /* handle those who write empty certificate blobs to PIV objects */
    if (cbBuf == 0) {
      *data = NULL;
      *data_len = 0;
      goto Cleanup;
    }

    if (!(*data = _ykpiv_alloc(state, cbBuf))) {
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

ykpiv_rc ykpiv_util_write_cert(ykpiv_state *state, uint8_t slot, uint8_t *data, size_t data_len, uint8_t certinfo) {
  ykpiv_rc res = YKPIV_OK;
  uint8_t scp11 = state->scp11_state.security_level;
  if (YKPIV_OK != (res = _ykpiv_begin_transaction(state))) return res;
  if (YKPIV_OK != (res = _ykpiv_ensure_application_selected(state, scp11))) goto Cleanup;

  res = _write_certificate(state, slot, data, data_len, certinfo);

Cleanup:

  _ykpiv_end_transaction(state);
  return res;
}

ykpiv_rc ykpiv_util_delete_cert(ykpiv_state *state, uint8_t slot) {
  return ykpiv_util_write_cert(state, slot, NULL, 0, YKPIV_CERTINFO_UNCOMPRESSED);
}

ykpiv_rc ykpiv_util_block_puk(ykpiv_state *state) {
  ykpiv_rc res = YKPIV_OK;
  uint8_t puk[] = { 0x30, 0x42, 0x41, 0x44, 0x46, 0x30, 0x30, 0x44 };
  int tries = -1;
  uint8_t data[CB_BUF_MAX] = {0};
  size_t  cb_data = sizeof(data);
  uint8_t *p_item = NULL;
  size_t  cb_item = 0;
  uint8_t flags = 0;

  if (!state) return YKPIV_ARGUMENT_ERROR;
  uint8_t scp11 = state->scp11_state.security_level;

  if (YKPIV_OK != (res = _ykpiv_begin_transaction(state))) return res;
  if (YKPIV_OK != (res = _ykpiv_ensure_application_selected(state, scp11))) goto Cleanup;

  while (tries != 0) {
    if (YKPIV_OK == (res = ykpiv_change_puk(state, (const char*)puk, sizeof(puk), (const char*)puk, sizeof(puk), &tries))) {
      /* did we accidentally choose the correct PUK?, change our puk and try again */
      puk[0]++;
    }
    else {
      /* depending on the firmware, tries may not be set to zero when the PUK is blocked, */
      /* instead, the return code will be PIN_LOCKED and tries will be unset */
      if (YKPIV_PIN_LOCKED == res) {
        tries = 0;
        res = YKPIV_OK;
      }
    }
  }

  /* attempt to set the puk blocked flag in admin data */

  if (YKPIV_OK == _read_metadata(state, TAG_ADMIN, data, &cb_data)) {
    if (YKPIV_OK == _get_metadata_item(data, cb_data, TAG_ADMIN_FLAGS_1, &p_item, &cb_item)) {
      if (sizeof(flags) == cb_item) {
        memcpy(&flags, p_item, cb_item);
      }
      else {
        DBG("admin flags exist, but are incorrect size = %lu", (unsigned long)cb_item);
      }
    }
  }

  flags |= ADMIN_FLAGS_1_PUK_BLOCKED;

  if (YKPIV_OK != _set_metadata_item(data, &cb_data, CB_OBJ_MAX, TAG_ADMIN_FLAGS_1, (uint8_t*)&flags, sizeof(flags))) {
    DBG("could not set admin flags");
  }
  else {
    if (YKPIV_OK != _write_metadata(state, TAG_ADMIN, data, cb_data)) {
      DBG("could not write admin metadata");
    }
  }

Cleanup:

  _ykpiv_end_transaction(state);
  return res;
}

ykpiv_rc ykpiv_util_read_mscmap(ykpiv_state *state, ykpiv_container **containers, size_t *n_containers) {
  ykpiv_rc res = YKPIV_OK;
  uint8_t buf[CB_BUF_MAX] = {0};
  unsigned long cbBuf = sizeof(buf);
  size_t offs, len = 0;
  uint8_t *ptr = NULL;

  if ((NULL == containers) || (NULL == n_containers)) { res = YKPIV_ARGUMENT_ERROR; goto Cleanup; }

  uint8_t scp11 = state->scp11_state.security_level;
  if (YKPIV_OK != (res = _ykpiv_begin_transaction(state))) return res;
  if (YKPIV_OK != (res = _ykpiv_ensure_application_selected(state, scp11))) goto Cleanup;

  *containers = 0;
  *n_containers = 0;

  if (YKPIV_OK == (res = _ykpiv_fetch_object(state, YKPIV_OBJ_MSCMAP, buf, &cbBuf))) {
    ptr = buf;

    /* check that object contents are at least large enough to read the header */
    if (cbBuf < CB_OBJ_TAG_MIN) {
      res = YKPIV_OK;
      goto Cleanup;
    }

    if (*ptr++ == TAG_MSCMAP) {
      offs = _ykpiv_get_length(ptr, buf + cbBuf, &len);
      if(!offs) {
        res = YKPIV_OK;
        goto Cleanup;
      }
      ptr += offs;

      if (NULL == (*containers = _ykpiv_alloc(state, len))) {
        res = YKPIV_MEMORY_ERROR;
        goto Cleanup;
      }

      /* should check if container map isn't corrupt */

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
  uint8_t buf[CB_OBJ_MAX] = {0};
  size_t offset = 0;
  size_t req_len = 0;
  size_t data_len = n_containers * sizeof(ykpiv_container);
  uint8_t scp11 = state->scp11_state.security_level;

  if (YKPIV_OK != (res = _ykpiv_begin_transaction(state))) return res;
  if (YKPIV_OK != (res = _ykpiv_ensure_application_selected(state, scp11))) goto Cleanup;

  // check if data and data_len are zero, this means that
  // we intend to delete the object
  if ((NULL == containers) || (0 == n_containers)) {

    // if either containers or n_containers are non-zero, return an error,
    // that we only delete strictly when both are set properly
    if ((NULL != containers) || (0 != n_containers)) {
      res = YKPIV_ARGUMENT_ERROR;
    }
    else {
      res = _ykpiv_save_object(state, YKPIV_OBJ_MSCMAP, NULL, 0);
    }

    goto Cleanup;
  }

  // encode object data for storage

  // calculate the required length of the encoded object
  req_len = 1 /* data tag */ + (unsigned long)_ykpiv_set_length(buf, data_len) + data_len;

  if (req_len > _obj_size_max(state)) {
    res = YKPIV_SIZE_ERROR;
    goto Cleanup;
  }

  buf[offset++] = TAG_MSCMAP;
  offset += _ykpiv_set_length(buf + offset, data_len);
  memcpy(buf + offset, (uint8_t*)containers, data_len);
  offset += data_len;

  // write onto device
  res = _ykpiv_save_object(state, YKPIV_OBJ_MSCMAP, buf, offset);

Cleanup:

  _ykpiv_end_transaction(state);
  return res;
}

ykpiv_rc ykpiv_util_read_msroots(ykpiv_state *state, uint8_t **data, size_t *data_len) {
  ykpiv_rc res = YKPIV_OK;
  uint8_t buf[CB_BUF_MAX] = {0};
  unsigned long cbBuf = sizeof(buf);
  size_t offs, len = 0;
  uint8_t *ptr = NULL;
  int object_id = 0;
  uint8_t tag = 0;
  uint8_t *pData = NULL;
  uint8_t *pTemp = NULL;
  size_t cbData = 0;
  size_t cbRealloc = 0;
  size_t offset = 0;

  if (!data || !data_len) return YKPIV_ARGUMENT_ERROR;

  uint8_t scp11 = state->scp11_state.security_level;
  if (YKPIV_OK != (res = _ykpiv_begin_transaction(state))) return res;
  if (YKPIV_OK != (res = _ykpiv_ensure_application_selected(state, scp11))) goto Cleanup;

  *data = 0;
  *data_len = 0;

  // allocate first page
  cbData = _obj_size_max(state);
  if (NULL == (pData = _ykpiv_alloc(state, cbData))) { res = YKPIV_MEMORY_ERROR; goto Cleanup; }

  for (object_id = YKPIV_OBJ_MSROOTS1; object_id <= YKPIV_OBJ_MSROOTS5; object_id++) {
    cbBuf = sizeof(buf);

    if (YKPIV_OK != (res = _ykpiv_fetch_object(state, object_id, buf, &cbBuf))) {
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

    offs = _ykpiv_get_length(ptr, buf + cbBuf, &len);
    if(!offs) {
      res = YKPIV_OK;
      goto Cleanup;
    }
    ptr += offs;

    cbRealloc = len > (cbData - offset) ? len - (cbData - offset) : 0;

    if (0 != cbRealloc) {
      if (!(pTemp = _ykpiv_realloc(state, pData, cbData + cbRealloc))) {
        /* realloc failed, pData will be freed in cleanup */
        res = YKPIV_MEMORY_ERROR;
        goto Cleanup;
      }
      pData = pTemp;
      pTemp = NULL;
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
  uint8_t buf[CB_OBJ_MAX] = {0};
  size_t offset = 0;
  size_t data_offset = 0;
  size_t data_chunk = 0;
  size_t n_objs = 0;
  unsigned int i = 0;
  size_t cb_obj_max = _obj_size_max(state);
  uint8_t scp11 = state->scp11_state.security_level;

  if (YKPIV_OK != (res = _ykpiv_begin_transaction(state))) return res;
  if (YKPIV_OK != (res = _ykpiv_ensure_application_selected(state, scp11))) goto Cleanup;

  // check if either data and data_len are zero, this means that
  // we intend to delete the object
  if ((NULL == data) || (0 == data_len)) {

    // if either data or data_len are non-zero, return an error,
    // that we only delete strictly when both are set properly
    if ((NULL != data) || (0 != data_len)) {
      res = YKPIV_ARGUMENT_ERROR;
    }
    else {
      // it should be sufficient to just delete the first object, though
      // to be complete we should erase all of the MSROOTS objects
      res = _ykpiv_save_object(state, YKPIV_OBJ_MSROOTS1, NULL, 0);
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

    /* encode object data for storage */
    buf[offset++] = (i == (n_objs - 1)) ? TAG_MSROOTS_END : TAG_MSROOTS_MID;
    offset += _ykpiv_set_length(buf + offset, data_chunk);
    memcpy(buf + offset, data + data_offset, data_chunk);
    offset += data_chunk;

    /* write onto device */
    res = _ykpiv_save_object(state, (int)(YKPIV_OBJ_MSROOTS1 + i), buf, offset);

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
  unsigned char in_data[11] = {0};
  unsigned char *in_ptr = in_data;
  unsigned char data[1024] = {0};
  unsigned char templ[] = { 0, YKPIV_INS_GENERATE_ASYMMETRIC, 0, 0 };
  unsigned long recv_len = sizeof(data);
  int sw = 0;
  uint8_t *ptr_modulus = NULL;
  size_t  cb_modulus = 0;
  uint8_t *ptr_exp = NULL;
  size_t  cb_exp = 0;
  uint8_t *ptr_point = NULL;
  size_t  cb_point = 0;
  size_t offs;

  setting_bool_t setting_roca = { 0 };
  const char sz_setting_roca[] = "Enable_Unsafe_Keygen_ROCA";
  const char sz_roca_format[] = "YubiKey serial number %u is affected by vulnerability "
    "CVE-2017-15361 (ROCA) and should be replaced. On-chip key generation %s  "
    "See YSA-2017-01 <https://www.yubico.com/support/security-advisories/ysa-2017-01/> "
    "for additional information on device replacement and mitigation assistance.\n";
  const char sz_roca_allow_user[] = "was permitted by an end-user configuration setting, but is not recommended.";
  const char sz_roca_allow_admin[] = "was permitted by an administrator configuration setting, but is not recommended.";
  const char sz_roca_block_user[] = "was blocked due to an end-user configuration setting.";
  const char sz_roca_block_admin[] = "was blocked due to an administrator configuration setting.";
  const char sz_roca_default[] = "was permitted by default, but is not recommended.  "
    "The default behavior will change in a future Yubico release.";

  if (!state) return YKPIV_ARGUMENT_ERROR;
  uint8_t scp11 = state->scp11_state.security_level;

  if ((algorithm == YKPIV_ALGO_RSA3072 || algorithm == YKPIV_ALGO_RSA4096 || YKPIV_IS_25519(algorithm))
       && !is_version_compatible(state, 5, 7, 0)) {
    DBG("RSA3072, RSA4096, ED25519 and X25519 keys are only supported in YubiKey version 5.7.0 and newer");
    return YKPIV_NOT_SUPPORTED;
  }
  if ((algorithm == YKPIV_ALGO_RSA1024 || algorithm == YKPIV_ALGO_RSA2048) && !is_version_compatible(state, 4, 3, 5)) {
    const char *psz_msg = NULL;
    setting_roca = setting_get_bool(sz_setting_roca, true);

    switch (setting_roca.source) {
      case SETTING_SOURCE_ADMIN:
        psz_msg = setting_roca.value ? sz_roca_allow_admin : sz_roca_block_admin;
        break;

      case SETTING_SOURCE_USER:
        psz_msg = setting_roca.value ? sz_roca_allow_user : sz_roca_block_user;
        break;

      default:
      case SETTING_SOURCE_DEFAULT:
        psz_msg = sz_roca_default;
        break;
    }

    DBG(sz_roca_format, state->serial, psz_msg);
    yc_log_event("YubiKey PIV Library", 1, setting_roca.value ? YC_LOG_LEVEL_WARN : YC_LOG_LEVEL_ERROR, sz_roca_format,
                 state->serial, psz_msg);

    if (!setting_roca.value) {
      return YKPIV_NOT_SUPPORTED;
    }
  }

  switch (algorithm) {
  case YKPIV_ALGO_RSA1024:
  case YKPIV_ALGO_RSA2048:
  case YKPIV_ALGO_RSA3072:
  case YKPIV_ALGO_RSA4096:
    if (!modulus || !modulus_len || !exp || !exp_len) {
      DBG("Invalid output parameter for RSA algorithm");
      return YKPIV_ARGUMENT_ERROR;
    }
    *modulus = NULL;
    *modulus_len = 0;
    *exp = NULL;
    *exp_len = 0;
    break;

  case YKPIV_ALGO_ECCP256:
  case YKPIV_ALGO_ECCP384:
  case YKPIV_ALGO_ED25519:
  case YKPIV_ALGO_X25519:
    if (!point || !point_len) {
      DBG("Invalid output parameter for ECC algorithm");
      return YKPIV_ARGUMENT_ERROR;
    }
    *point = NULL;
    *point_len = 0;
    break;

  default:
    DBG("Invalid algorithm specified");
    return YKPIV_GENERIC_ERROR;
  }

  if (YKPIV_OK != (res = _ykpiv_begin_transaction(state))) return res;
  if (YKPIV_OK != (res = _ykpiv_ensure_application_selected(state, scp11))) goto Cleanup;

  templ[3] = slot;

  *in_ptr++ = 0xac;
  *in_ptr++ = 3;
  *in_ptr++ = YKPIV_ALGO_TAG;
  *in_ptr++ = 1;
  *in_ptr++ = algorithm;

  if (in_data[4] == 0) {
    res = YKPIV_ALGORITHM_ERROR;
    DBG("Unexpected algorithm");
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

  if (YKPIV_OK != (res = _ykpiv_transfer_data(state, templ, in_data, (unsigned long)(in_ptr - in_data), data, &recv_len, &sw))) {
    goto Cleanup;
  }
  res = ykpiv_translate_sw_ex(__FUNCTION__, sw);
  if (res != YKPIV_OK) {
    DBG("Failed to generate new key");
    goto Cleanup;
  }

  if (YKPIV_IS_RSA(algorithm)) {
    size_t len;
    unsigned char *data_ptr = data + 2 + _ykpiv_get_length(data + 2, data + recv_len, &len);

    if (*data_ptr != TAG_RSA_MODULUS) {
      DBG("Failed to parse public key structure (modulus).");
      res = YKPIV_PARSE_ERROR;
      goto Cleanup;
    }

    data_ptr++;
    offs = _ykpiv_get_length(data_ptr, data + recv_len, &len);
    if(!offs) {
      DBG("Failed to parse public key structure (modulus length).");
      res = YKPIV_PARSE_ERROR;
      goto Cleanup;
    }
    data_ptr += offs;

    cb_modulus = len;
    if (NULL == (ptr_modulus = _ykpiv_alloc(state, cb_modulus))) {
      DBG("Failed to allocate memory for modulus.");
      res = YKPIV_MEMORY_ERROR;
      goto Cleanup;
    }

    memcpy(ptr_modulus, data_ptr, cb_modulus);

    data_ptr += len;

    if (*data_ptr != TAG_RSA_EXP) {
      DBG("Failed to parse public key structure (public exponent).");
      res = YKPIV_PARSE_ERROR;
      goto Cleanup;
    }

    data_ptr++;
    offs = _ykpiv_get_length(data_ptr, data + recv_len, &len);
    if(!offs) {
      DBG("Failed to parse public key structure (public exponent length).");
      res = YKPIV_PARSE_ERROR;
      goto Cleanup;
    }
    data_ptr += offs;

    cb_exp = len;
    if (NULL == (ptr_exp = _ykpiv_alloc(state, cb_exp))) {
      DBG("Failed to allocate memory for public exponent.");
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
  else if (YKPIV_IS_EC(algorithm) || YKPIV_IS_25519(algorithm)) {
    unsigned char *data_ptr = data + 3;
    size_t len = 0;

    if (YKPIV_ALGO_ECCP256 == algorithm) {
      len = CB_ECC_POINTP256;
    } else if (YKPIV_ALGO_ECCP384 == algorithm) {
      len = CB_ECC_POINTP384;
    } else if (YKPIV_IS_25519(algorithm)) {
      len = CB_ECC_POINT25519;
    }

    if (*data_ptr++ != TAG_ECC_POINT) {
      DBG("Failed to parse public key structure.");
      res = YKPIV_PARSE_ERROR;
      goto Cleanup;
    }

    if (*data_ptr++ != len) { /* the curve point should always be determined by the curve */
      DBG("Unexpected length.");
      res = YKPIV_ALGORITHM_ERROR;
      goto Cleanup;
    }

    cb_point = len;
    if (NULL == (ptr_point = _ykpiv_alloc(state, cb_point))) {
      DBG("Failed to allocate memory for public point.");
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
    DBG("Wrong algorithm.");
    res = YKPIV_ALGORITHM_ERROR;
    goto Cleanup;
  }

Cleanup:

  if (ptr_modulus) { _ykpiv_free(state, ptr_modulus); }
  if (ptr_exp) { _ykpiv_free(state, ptr_exp); }
  if (ptr_point) { _ykpiv_free(state, ptr_point); }

  _ykpiv_end_transaction(state);
  return res;
}

ykpiv_rc ykpiv_util_get_config(ykpiv_state *state, ykpiv_config *config) {
  ykpiv_rc res = YKPIV_OK;
  uint8_t data[CB_BUF_MAX] = { 0 };
  size_t cb_data = sizeof(data);
  uint8_t *p_item = NULL;
  size_t cb_item = 0;

  if (NULL == state) return YKPIV_ARGUMENT_ERROR;
  if (NULL == config) return YKPIV_ARGUMENT_ERROR;

  uint8_t scp11 = state->scp11_state.security_level;

  // initialize default values

  config->puk_blocked = false;
  config->puk_noblock_on_upgrade = false;
  config->pin_last_changed = 0;
  config->mgm_type = YKPIV_CONFIG_MGM_MANUAL;

  if (YKPIV_OK != (res = _ykpiv_begin_transaction(state))) return res;
  if (YKPIV_OK != (res = _ykpiv_ensure_application_selected(state, scp11))) goto Cleanup;

  /* recover admin data */
  if (YKPIV_OK == _read_metadata(state, TAG_ADMIN, data, &cb_data)) {
    if (YKPIV_OK == _get_metadata_item(data, cb_data, TAG_ADMIN_FLAGS_1, &p_item, &cb_item)) {
      if (*p_item & ADMIN_FLAGS_1_PUK_BLOCKED) config->puk_blocked = true;
      if (*p_item & ADMIN_FLAGS_1_PROTECTED_MGM) config->mgm_type = YKPIV_CONFIG_MGM_PROTECTED;
    }

    if (YKPIV_OK == _get_metadata_item(data, cb_data, TAG_ADMIN_SALT, &p_item, &cb_item)) {
      if (config->mgm_type != YKPIV_CONFIG_MGM_MANUAL) {
        DBG("conflicting types of mgm key administration configured");
        config->mgm_type = YKPIV_CONFIG_MGM_INVALID;
      }
      else {
        config->mgm_type = YKPIV_CONFIG_MGM_DERIVED;
      }
    }

    if (YKPIV_OK == _get_metadata_item(data, cb_data, TAG_ADMIN_TIMESTAMP, &p_item, &cb_item)) {
      if (CB_ADMIN_TIMESTAMP != cb_item)  {
        DBG("pin timestamp in admin metadata is an invalid size");
      }
      else {
        memcpy(&(config->pin_last_changed), p_item, cb_item);
      }
    }
  }

  /* recover protected data */
  cb_data = sizeof(data);

  if (YKPIV_OK == _read_metadata(state, TAG_PROTECTED, data, &cb_data)) {

    if (YKPIV_OK == _get_metadata_item(data, cb_data, TAG_PROTECTED_FLAGS_1, &p_item, &cb_item)) {
      if (*p_item & PROTECTED_FLAGS_1_PUK_NOBLOCK) config->puk_noblock_on_upgrade = true;
    }

    if (YKPIV_OK == _get_metadata_item(data, cb_data, TAG_PROTECTED_MGM, &p_item, &cb_item)) {
      if(sizeof(config->mgm_key) >= cb_item) {
        memcpy(config->mgm_key, p_item, cb_item);
        config->mgm_len = cb_item;
        if (config->mgm_type != YKPIV_CONFIG_MGM_PROTECTED) {
          DBG("conflicting types of mgm key administration configured - protected mgm exists");
          config->mgm_type = YKPIV_CONFIG_MGM_INVALID;
        }
      } else {
        DBG("protected data contains mgm, but is the wrong size = %lu", (unsigned long)cb_item);
        config->mgm_type = YKPIV_CONFIG_MGM_INVALID;
      }
    }
  }
  else {
    if (config->mgm_type == YKPIV_CONFIG_MGM_PROTECTED) {
      DBG("admin data indicates protected mgm present, but the object cannot be read");
      config->mgm_type = YKPIV_CONFIG_MGM_INVALID;
    }
  }

Cleanup:

  _ykpiv_end_transaction(state);
  return res;
}

ykpiv_rc ykpiv_util_set_pin_last_changed(ykpiv_state *state) {
  ykpiv_rc res = YKPIV_OK;
  ykpiv_rc ykrc = YKPIV_OK;
  uint8_t  data[CB_BUF_MAX] = { 0 };
  size_t   cb_data = sizeof(data);
  time_t   tnow = 0;

  if (NULL == state) return YKPIV_ARGUMENT_ERROR;
  uint8_t scp11 = state->scp11_state.security_level;

  if (YKPIV_OK != (res = _ykpiv_begin_transaction(state))) return res;
  if (YKPIV_OK != (res = _ykpiv_ensure_application_selected(state, scp11))) goto Cleanup;

  /* recover admin data */
  if (YKPIV_OK != (ykrc = _read_metadata(state, TAG_ADMIN, data, &cb_data))) {
    cb_data = 0; /* set current metadata blob size to zero, we'll add the timestamp to the blank blob */
  }

  tnow = time(NULL);

  if (YKPIV_OK != (res = _set_metadata_item(data, &cb_data, CB_OBJ_MAX, TAG_ADMIN_TIMESTAMP, (uint8_t*)&tnow, CB_ADMIN_TIMESTAMP))) {
    DBG("could not set pin timestamp, err = %d", res);
  }
  else {
    if (YKPIV_OK != (res = _write_metadata(state, TAG_ADMIN, data, cb_data))) {
      /* Note: this can fail if authenticate() wasn't called previously - expected behavior */
      DBG("could not write admin data, err = %d", res);
    }
  }

Cleanup:

  _ykpiv_end_transaction(state);
  return res;
}

ykpiv_rc ykpiv_util_get_derived_mgm(ykpiv_state *state, const uint8_t *pin, const size_t pin_len, ykpiv_mgm *mgm) {
  ykpiv_rc res = YKPIV_OK;
  pkcs5_rc p5rc = PKCS5_OK;
  uint8_t  data[CB_BUF_MAX] = { 0 };
  size_t   cb_data = sizeof(data);
  uint8_t  *p_item = NULL;
  size_t   cb_item = 0;

  if (NULL == state) return YKPIV_ARGUMENT_ERROR;
  if ((NULL == pin) || (0 == pin_len) || (NULL == mgm)) return YKPIV_ARGUMENT_ERROR;

  uint8_t scp11 = state->scp11_state.security_level;
  if (YKPIV_OK != (res = _ykpiv_begin_transaction(state))) return res;
  if (YKPIV_OK != (res = _ykpiv_ensure_application_selected(state, scp11))) goto Cleanup;

  /* recover management key */
  if (YKPIV_OK == (res = _read_metadata(state, TAG_ADMIN, data, &cb_data))) {
    if (YKPIV_OK == (res = _get_metadata_item(data, cb_data, TAG_ADMIN_SALT, &p_item, &cb_item))) {
      if (cb_item != CB_ADMIN_SALT) {
        DBG("derived mgm salt exists, but is incorrect size = %lu", (unsigned long)cb_item);
        res = YKPIV_GENERIC_ERROR;
        goto Cleanup;
      }
      mgm->len = DES_LEN_3DES;
      if (PKCS5_OK != (p5rc = pkcs5_pbkdf2_sha1(pin, pin_len, p_item, cb_item, ITER_MGM_PBKDF2, mgm->data, mgm->len))) {
        DBG("pbkdf2 failure, err = %d", p5rc);
        res = YKPIV_GENERIC_ERROR;
        goto Cleanup;
      }
    }
  }

Cleanup:

  _ykpiv_end_transaction(state);
  return res;
}

ykpiv_rc ykpiv_util_get_protected_mgm(ykpiv_state *state, ykpiv_mgm *mgm) {
  ykpiv_rc res = YKPIV_OK;
  uint8_t  data[CB_BUF_MAX] = { 0 };
  size_t   cb_data = sizeof(data);
  uint8_t  *p_item = NULL;
  size_t   cb_item = 0;

  if (NULL == state) return YKPIV_ARGUMENT_ERROR;
  if (NULL == mgm) return YKPIV_ARGUMENT_ERROR;
  uint8_t scp11 = state->scp11_state.security_level;

  if (YKPIV_OK != (res = _ykpiv_begin_transaction(state))) return res;
  if (YKPIV_OK != (res = _ykpiv_ensure_application_selected(state, scp11))) goto Cleanup;

  if (YKPIV_OK != (res = _read_metadata(state, TAG_PROTECTED, data, &cb_data))) {
    DBG("could not read protected data, err = %d", res);
    goto Cleanup;
  }

  if (YKPIV_OK != (res = _get_metadata_item(data, cb_data, TAG_PROTECTED_MGM, &p_item, &cb_item))) {
    DBG("could not read protected mgm from metadata, err = %d", res);
    goto Cleanup;
  }

  if (cb_item > sizeof(mgm->data)) {
    DBG("protected data contains mgm, but is the wrong size = %lu", (unsigned long)cb_item);
    res = YKPIV_AUTHENTICATION_ERROR;
    goto Cleanup;
  }

  mgm->len = cb_item;
  memcpy(mgm->data, p_item, cb_item);

Cleanup:

  yc_memzero(data, sizeof(data));

  _ykpiv_end_transaction(state);
  return res;

}

ykpiv_rc ykpiv_util_update_protected_mgm(ykpiv_state *state, ykpiv_mgm *mgm) {
  ykpiv_rc res = YKPIV_OK;
  uint8_t data[CB_BUF_MAX] = {0};
  size_t cb_data = sizeof(data);
  uint8_t scp11 = state->scp11_state.security_level;

  if (YKPIV_OK != (res = _ykpiv_begin_transaction(state))) goto Cleanup;
  if (YKPIV_OK != (res = _ykpiv_ensure_application_selected(state, scp11))) goto Cleanup;

  if (YKPIV_OK != (res = _read_metadata(state, TAG_PROTECTED, data, &cb_data))) {
    cb_data = 0; /* set current metadata blob size to zero, we'll add to the blank blob */
  }

  if (YKPIV_OK != (res = _set_metadata_item(data, &cb_data, CB_OBJ_MAX, TAG_PROTECTED_MGM, mgm->data, mgm->len))) {
    DBG("could not set protected mgm item, err = %d", res);
  }
  else {
    if (YKPIV_OK != (res = _write_metadata(state, TAG_PROTECTED, data, cb_data))) {
      DBG("could not write protected data, err = %d", res);
      goto Cleanup;
    }
  }

Cleanup:

  _ykpiv_end_transaction(state);
  return res;
}

/* to set a generated mgm, pass NULL for mgm, or set mgm.data to all zeroes */
ykpiv_rc ykpiv_util_set_protected_mgm(ykpiv_state *state, ykpiv_mgm *mgm) {
  ykpiv_rc res = YKPIV_OK;
  ykpiv_rc ykrc = YKPIV_OK;
  prng_rc  prngrc = PRNG_OK;
  bool     fGenerate = false;
  size_t   mgm_len = DES_LEN_3DES;
  uint8_t  mgm_key[sizeof(mgm->data)] = { 0 };
  size_t   i = 0;
  uint8_t  data[CB_BUF_MAX] = { 0 };
  size_t   cb_data = sizeof(data);
  uint8_t  *p_item = NULL;
  size_t   cb_item = 0;
  uint8_t  flags_1 = 0;

  if (NULL == state) return YKPIV_ARGUMENT_ERROR;
   uint8_t scp11 = state->scp11_state.security_level;

  fGenerate = true;
  if (mgm) {
    mgm_len = mgm->len;
    memcpy(mgm_key, mgm->data, mgm->len);

    for (i = 0; i < mgm_len; i++) {
      if (mgm_key[i] != 0) {
        fGenerate = false;
        break;
      }
    }
  }

  if (YKPIV_OK != (res = _ykpiv_begin_transaction(state))) goto Cleanup;
  if (YKPIV_OK != (res = _ykpiv_ensure_application_selected(state, scp11))) goto Cleanup;

  /* try to set the mgm key as long as we don't encounter a fatal error */
  do {
    if (fGenerate) {
      /* generate a new mgm key */
      if (PRNG_OK != (prngrc = _ykpiv_prng_generate(mgm_key, mgm_len))) {
        DBG("could not generate new mgm, err = %d", prngrc);
        res = YKPIV_RANDOMNESS_ERROR;
        goto Cleanup;
      }
    }

    if (YKPIV_OK != (ykrc = ykpiv_set_mgmkey3(state, mgm_key, mgm_len, YKPIV_ALGO_AUTO, YKPIV_TOUCHPOLICY_AUTO))) {
      /*
      ** if _set_mgmkey fails with YKPIV_KEY_ERROR, it means the generated key is weak
      ** otherwise, log a warning, since the device mgm key is corrupt or we're in
      ** a state where we can't set the mgm key
      */
      if (YKPIV_KEY_ERROR != ykrc) {
        DBG("could not set new derived mgm key, err = %d", ykrc);
        res = ykrc;
        goto Cleanup;
      }
    }
    else {
      /* _set_mgmkey succeeded, stop generating */
      fGenerate = false;
    }
  } while (fGenerate);

  /* set output mgm */
  if (mgm) {
    memcpy(mgm->data, mgm_key, mgm_len);
  }

  /* after this point, we've set the mgm key, so the function should succeed, regardless of being able to set the metadata */

  /* set the new mgm key in protected data */
  if (YKPIV_OK != (ykrc = _read_metadata(state, TAG_PROTECTED, data, &cb_data))) {
    cb_data = 0; /* set current metadata blob size to zero, we'll add to the blank blob */
  }

  if (YKPIV_OK != (ykrc = _set_metadata_item(data, &cb_data, CB_OBJ_MAX, TAG_PROTECTED_MGM, mgm_key, mgm_len))) {
    DBG("could not set protected mgm item, err = %d", ykrc);
  }
  else {
    if (YKPIV_OK != (ykrc = _write_metadata(state, TAG_PROTECTED, data, cb_data))) {
      DBG("could not write protected data, err = %d", ykrc);
      goto Cleanup;
    }
  }

  /* set the protected mgm flag in admin data */
  cb_data = sizeof(data);

  if (YKPIV_OK != (ykrc = _read_metadata(state, TAG_ADMIN, data, &cb_data))) {
    cb_data = 0;
  }
  else {

    if (YKPIV_OK != (ykrc = _get_metadata_item(data, cb_data, TAG_ADMIN_FLAGS_1, &p_item, &cb_item))) {
      /* flags are not set */
      DBG("admin data exists, but flags are not present");
    }

    if (cb_item == sizeof(flags_1)) {
      memcpy(&flags_1, p_item, cb_item);
    }
    else {
      DBG("admin data flags are an incorrect size = %lu", (unsigned long)cb_item);
    }

    /* remove any existing salt */
    if (YKPIV_OK != (ykrc = _set_metadata_item(data, &cb_data, CB_OBJ_MAX, TAG_ADMIN_SALT, NULL, 0))) {
      DBG("could not unset derived mgm salt, err = %d", ykrc);
    }
  }

  flags_1 |= ADMIN_FLAGS_1_PROTECTED_MGM;

  if (YKPIV_OK != (ykrc = _set_metadata_item(data, &cb_data, CB_OBJ_MAX, TAG_ADMIN_FLAGS_1, &flags_1, sizeof(flags_1)))) {
    DBG("could not set admin flags item, err = %d", ykrc);
  }
  else {
    if (YKPIV_OK != (ykrc = _write_metadata(state, TAG_ADMIN, data, cb_data))) {
      DBG("could not write admin data, err = %d", ykrc);
      goto Cleanup;
    }
  }


Cleanup:

  yc_memzero(data, sizeof(data));
  yc_memzero(mgm_key, sizeof(mgm_key));

  _ykpiv_end_transaction(state);
  return res;
}

ykpiv_rc ykpiv_util_reset(ykpiv_state *state) {
  unsigned char templ[] = {0, YKPIV_INS_RESET, 0, 0};
  unsigned char data[256] = {0};
  unsigned long recv_len = sizeof(data);
  ykpiv_rc res;
  int sw;

  /* note: the reset function is only available when both pins are blocked. */
  res = ykpiv_transfer_data(state, templ, NULL, 0, data, &recv_len, &sw);
  if(res != YKPIV_OK) {
    return res;
  }
  return ykpiv_translate_sw_ex(__FUNCTION__, sw);
}

uint32_t ykpiv_util_slot_object(uint8_t slot) {
  int object_id = -1;

  switch (slot) {
  case YKPIV_KEY_AUTHENTICATION:
    object_id = YKPIV_OBJ_AUTHENTICATION;
    break;

  case YKPIV_KEY_SIGNATURE:
    object_id = YKPIV_OBJ_SIGNATURE;
    break;

  case YKPIV_KEY_KEYMGM:
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

  return (uint32_t)object_id;
}

 ykpiv_rc ykpiv_util_get_certdata(uint8_t *buf, size_t buf_len, uint8_t* certdata, size_t *certdata_len) {
   uint8_t compress_info = YKPIV_CERTINFO_UNCOMPRESSED;
   uint8_t *certptr = 0;
   size_t cert_len = 0;
   uint8_t *ptr = buf;

   while (ptr < buf + buf_len) {
     uint8_t tag = *ptr++;
     size_t len = 0;
     size_t offs = _ykpiv_get_length(ptr, buf + buf_len, &len);
     if(!offs) {
       DBG("Found invalid length for tag 0x%02x.", tag);
       goto invalid_tlv;
     }
     ptr += offs; // move to after length bytes

     switch (tag) {
       case TAG_CERT:
         certptr = ptr;
         cert_len = len;
         DBG("Found TAG_CERT with length %zu", cert_len);
         break;
       case TAG_CERT_COMPRESS:
         if(len != 1) {
           DBG("Found TAG_CERT_COMPRESS with invalid length %zu", len);
           goto invalid_tlv;
         }
         compress_info = *ptr;
         DBG("Found TAG_CERT_COMPRESS with length %zu value 0x%02x", len, compress_info);
         break;
       case TAG_CERT_LRC: {
         // basically ignore it
         DBG("Found TAG_CERT_LRC with length %zu", len);
         break;
       }
       default:
         DBG("Unknown cert tag 0x%02x", tag);
         goto invalid_tlv;
         break;
     }
     ptr += len; // move to after value bytes
   }

invalid_tlv:
   if(certptr == 0 || cert_len == 0 || ptr != buf + buf_len || compress_info > YKPIV_CERTINFO_GZIP) {
     DBG("Invalid TLV encoding, treating as a raw certificate");
     certptr = buf;
     cert_len = buf_len;
   }

   if (compress_info == YKPIV_CERTINFO_GZIP) {
#ifdef USE_CERT_COMPRESS
     z_stream zs;
     zs.zalloc = Z_NULL;
     zs.zfree = Z_NULL;
     zs.opaque = Z_NULL;
     zs.avail_in = (uInt) cert_len;
     zs.next_in = (Bytef *) certptr;
     zs.avail_out = (uInt) *certdata_len;
     zs.next_out = (Bytef *) certdata;

     if (inflateInit2(&zs, MAX_WBITS | 16) != Z_OK) {
       DBG("Failed to initialize certificate decompression");
       *certdata_len = 0;
       return YKPIV_INVALID_OBJECT;
     }

     int res = inflate(&zs, Z_FINISH);
     if (res != Z_STREAM_END) {
       *certdata_len = 0;
       if (res == Z_BUF_ERROR) {
         DBG("Failed to decompress certificate. Allocated buffer is too small");
         return YKPIV_SIZE_ERROR;
       }
       DBG("Failed to decompress certificate");
       return YKPIV_INVALID_OBJECT;
     }
     if (inflateEnd(&zs) != Z_OK) {
       DBG("Failed to finish certificate decompression");
       *certdata_len = 0;
       return YKPIV_INVALID_OBJECT;
     }
     *certdata_len = zs.total_out;
#else
     DBG("Found compressed certificate. Decompressing certificate not supported");
     *certdata_len = 0;
     return YKPIV_PARSE_ERROR;
#endif
   } else {
     if (*certdata_len < cert_len) {
       DBG("Buffer too small");
       *certdata_len = 0;
       return YKPIV_SIZE_ERROR;
     }
     memmove(certdata, certptr, cert_len);
     *certdata_len = cert_len;
   }
   return YKPIV_OK;
}

 ykpiv_rc ykpiv_util_write_certdata(uint8_t *rawdata, size_t rawdata_len, uint8_t compress_info, uint8_t* certdata, size_t *certdata_len) {
  size_t offset = 0;
  size_t buf_len = 0;

  unsigned long len_bytes = get_length_size((unsigned long)rawdata_len);

   // calculate the required length of the encoded object
   buf_len = 1 /* cert tag */ + 3 /* compression tag + data*/ + 2 /* lrc */;
   buf_len += len_bytes + rawdata_len;

   if (buf_len > *certdata_len) {
     DBG("Buffer too small");
     *certdata_len = 0;
     return YKPIV_SIZE_ERROR;
   }

  memmove(certdata + len_bytes + 1, rawdata, rawdata_len);

  certdata[offset++] = TAG_CERT;
  offset += _ykpiv_set_length(certdata+offset, rawdata_len);
  offset += rawdata_len;
  certdata[offset++] = TAG_CERT_COMPRESS;
  certdata[offset++] = 1;
  certdata[offset++] = compress_info;
  certdata[offset++] = TAG_CERT_LRC;
  certdata[offset++] = 0;
  *certdata_len = offset;
  return YKPIV_OK;
}

 static ykpiv_rc _read_certificate(ykpiv_state *state, uint8_t slot, uint8_t *buf, size_t *buf_len) {
  ykpiv_rc res = YKPIV_OK;
  int object_id = (int)ykpiv_util_slot_object(slot);

  if (-1 == object_id) return YKPIV_INVALID_OBJECT;

   unsigned char data[YKPIV_OBJ_MAX_SIZE] = {0};
   unsigned long data_len = sizeof (data);

  if (YKPIV_OK == (res = _ykpiv_fetch_object(state, object_id, data, &data_len))) {
    if ((res = ykpiv_util_get_certdata(data, data_len, buf, buf_len)) != YKPIV_OK) {
      DBG("Failed to get certificate data");
      return res;
    }
  } else {
    *buf_len = 0;
  }

  return res;
}

static ykpiv_rc _write_certificate(ykpiv_state *state, uint8_t slot, uint8_t *data, size_t data_len, uint8_t certinfo) {
  uint8_t buf[CB_OBJ_MAX] = {0};
  size_t buf_len = sizeof(buf);
  int object_id = (int)ykpiv_util_slot_object(slot);


  if (-1 == object_id) return YKPIV_INVALID_OBJECT;

  // check if data or data_len are zero, this means that we intend to delete the object
  if ((NULL == data) || (0 == data_len)) {

    // if either data or data_len are non-zero, return an error,
    // that we only delete strictly when both are set properly
    if ((NULL != data) || (0 != data_len)) {
      return YKPIV_ARGUMENT_ERROR;
    }

    return _ykpiv_save_object(state, object_id, NULL, 0);
  }

  // encode certificate data for storage
  ykpiv_rc res = YKPIV_OK;
  if ( (res=ykpiv_util_write_certdata(data, data_len, certinfo, buf, &buf_len)) != YKPIV_OK) {
    return res;
  }

  // write onto device
  return _ykpiv_save_object(state, object_id, buf, buf_len);
}

/*
** PIV Manager data helper functions
**
** These functions allow the PIV Manager to extend the YKPIV_OBJ_ADMIN_DATA object without having to change
** this implementation.  New items may be added without modifying these functions.  Data items are picked
** from the pivman_data buffer by tag, and replaced either in place if length allows or the data object is
** expanded to fit a new/updated data item.
*/

/*
** _get_metadata_item
**
** Parses the metadata blob, specified by data, looking for the specified tag.  If found, the item is
** returned in pp_item and its size in pcb_item.
**
** If the item is not found, this function returns YKPIV_GENERIC_ERROR.
*/
static ykpiv_rc _get_metadata_item(uint8_t *data, size_t cb_data, uint8_t tag, uint8_t **pp_item, size_t *pcb_item) {
  uint8_t *p_temp = data;
  size_t  offs, cb_temp = 0;
  uint8_t tag_temp = 0;
  bool found = false;

  if (!data || !pp_item || !pcb_item) return YKPIV_ARGUMENT_ERROR;

  *pp_item = NULL;
  *pcb_item = 0;

  while (p_temp < (data + cb_data)) {
    tag_temp = *p_temp++;

    offs = _ykpiv_get_length(p_temp, data + cb_data, &cb_temp);
    if (!offs) {
      return YKPIV_PARSE_ERROR;
    }

    p_temp += offs;

    if (tag_temp == tag) {
      // found tag
      found = true;
      break;
    }

    p_temp += cb_temp;
  }

  if (found) {
    *pp_item = p_temp;
    *pcb_item = cb_temp;
  }

  return found ? YKPIV_OK : YKPIV_GENERIC_ERROR;
}

ykpiv_rc ykpiv_util_parse_metadata(uint8_t *data, size_t data_len, ykpiv_metadata *metadata) {
  uint8_t *p = 0;
  size_t cb = 0;
  uint32_t cnt = 0;

  ykpiv_rc rc = _get_metadata_item(data, data_len, YKPIV_METADATA_ALGORITHM_TAG, &p, &cb);
  if(rc == YKPIV_OK && cb == 1) {
    metadata->algorithm = p[0];
    cnt++;
  }

  rc = _get_metadata_item(data, data_len, YKPIV_METADATA_POLICY_TAG, &p, &cb);
  if(rc == YKPIV_OK && cb == 2) {
    metadata->pin_policy = p[0];
    metadata->touch_policy = p[1];
    cnt++;
  }

  rc = _get_metadata_item(data, data_len, YKPIV_METADATA_ORIGIN_TAG, &p, &cb);
  if(rc == YKPIV_OK && cb == 1) {
    metadata->origin = p[0];
    cnt++;
  }

  rc = _get_metadata_item(data, data_len, YKPIV_METADATA_PUBKEY_TAG, &p, &cb);
  if(rc == YKPIV_OK && cb > 0 && cb <= sizeof(metadata->pubkey)) {
    metadata->pubkey_len = cb;
    memcpy(metadata->pubkey, p, cb);
    cnt++;
  }

  return cnt ? YKPIV_OK : YKPIV_PARSE_ERROR;
}

/*
** _set_metadata_item
**
** Adds or replaces a data item encoded in a metadata blob, specified by tag to the existing
** metadata blob (data) until it reaches the a maximum buffer size (cb_data_max).
**
** If adding/replacing the item would exceed cb_data_max, this function returns YKPIV_GENERIC_ERROR.
**
** The new size of the blob is returned in pcb_data.
*/
static ykpiv_rc _set_metadata_item(uint8_t *data, size_t *pcb_data, size_t cb_data_max, uint8_t tag, uint8_t *p_item, size_t cb_item) {
  uint8_t *p_temp = data;
  size_t  cb_temp = 0;
  uint8_t tag_temp = 0;
  size_t  cb_len = 0;
  uint8_t *p_next = NULL;
  long    cb_moved = 0; /* must be signed to have negative offsets */

  if (!data || !pcb_data) return YKPIV_ARGUMENT_ERROR;

  while (p_temp < (data + *pcb_data)) {
    tag_temp = *p_temp++;
    cb_len = _ykpiv_get_length(p_temp, data + *pcb_data, &cb_temp);
    if(!cb_len) {
        return YKPIV_PARSE_ERROR;
    }
    p_temp += cb_len;

    if (tag_temp == tag) {
      /* found tag */

      /* check length, if it matches, overwrite */
      if (cb_temp == cb_item) {
        memcpy(p_temp, p_item, cb_item);
        return YKPIV_OK;
      }

      /* length doesn't match, expand/shrink to fit */
      p_next = p_temp + cb_temp;
      cb_moved = (long)cb_item - (long)cb_temp +
        ((long)(cb_item != 0 ? (long)_ykpiv_get_length_size(cb_item) : -1l /* for tag, if deleting */) -
        (long)cb_len); /* accounts for different length encoding */

      /* length would cause buffer overflow, return error */
      if ((size_t)(*pcb_data + cb_moved) > cb_data_max) {
        return YKPIV_GENERIC_ERROR;
      }

      /* move remaining data */
      memmove(p_next + cb_moved, p_next, *pcb_data - (size_t)(p_next - data));
      *pcb_data += cb_moved;

      /* re-encode item and insert */
      if (cb_item != 0) {
        p_temp -= cb_len;
        p_temp += _ykpiv_set_length(p_temp, cb_item);
        memcpy(p_temp, p_item, cb_item);
      }

      return YKPIV_OK;
    } /* if tag found */

    p_temp += cb_temp;
  }

  if (cb_item == 0) {
    /* we've been asked to delete an existing item that isn't in the blob */
    return YKPIV_OK;
  }

  // we did not find an existing tag, append
  p_temp = data + *pcb_data;
  cb_len = _ykpiv_get_length_size(cb_item);

  // length would cause buffer overflow, return error
  if (*pcb_data + 1 + cb_len + cb_item > cb_data_max) {
    return YKPIV_GENERIC_ERROR;
  }

  *p_temp++ = tag;
  p_temp += _ykpiv_set_length(p_temp, cb_item);
  memcpy(p_temp, p_item, cb_item);
  *pcb_data += 1 + cb_len + cb_item;

  return YKPIV_OK;
}

/*
** _read_metadata
**
** Reads admin or protected data (specified by tag) from its associated object.
**
** The data stored in the object is parsed to ensure it has the correct tag and valid length.
**
** data must point to a buffer of at least CB_BUF_MAX bytes, and pcb_data should point to
** the size of data.
**
** To read from protected data, the pin must be verified prior to calling this function.
*/
static ykpiv_rc _read_metadata(ykpiv_state *state, uint8_t tag, uint8_t* data, size_t* pcb_data) {
  ykpiv_rc res = YKPIV_OK;
  uint8_t *p_temp = NULL;
  unsigned long cb_temp = 0;
  size_t offs;
  int obj_id = 0;

  if (!data || !pcb_data || (CB_BUF_MAX > *pcb_data)) return YKPIV_ARGUMENT_ERROR;

  switch (tag) {
  case TAG_ADMIN: obj_id = YKPIV_OBJ_ADMIN_DATA; break;
  case TAG_PROTECTED: obj_id = YKPIV_OBJ_PRINTED; break;
  default: return YKPIV_INVALID_OBJECT;
  }

  cb_temp = (unsigned long)*pcb_data;
  *pcb_data = 0;

  if (YKPIV_OK != (res = _ykpiv_fetch_object(state, obj_id, data, &cb_temp))) {
    return res;
  }

  if (cb_temp < CB_OBJ_TAG_MIN) return YKPIV_PARSE_ERROR;

  p_temp = data;

  if (tag != *p_temp++) return YKPIV_PARSE_ERROR;

  offs = _ykpiv_get_length(p_temp, data + cb_temp, pcb_data);
  if (!offs) {
    *pcb_data = 0;
    return YKPIV_PARSE_ERROR;
  }

  p_temp += offs;

  memmove(data, p_temp, *pcb_data);

  return YKPIV_OK;
}

/*
** _write_metadata
**
** Writes admin/protected data, specified by tag to its associated object.
**
** To delete the metadata, set data to NULL and cb_data to 0.
**
** To write protected data, the pin must be verified prior to calling this function.
*/
static ykpiv_rc _write_metadata(ykpiv_state *state, uint8_t tag, uint8_t *data, size_t cb_data) {
  ykpiv_rc res = YKPIV_OK;
  uint8_t buf[CB_OBJ_MAX] = { 0 };
  uint8_t *pTemp = buf;
  int obj_id = 0;

  if (cb_data > (_obj_size_max(state) - CB_OBJ_TAG_MAX)) {
    return YKPIV_GENERIC_ERROR;
  }

  switch (tag) {
  case TAG_ADMIN: obj_id = YKPIV_OBJ_ADMIN_DATA; break;
  case TAG_PROTECTED: obj_id = YKPIV_OBJ_PRINTED; break;
  default: return YKPIV_INVALID_OBJECT;
  }

  if (!data || (0 == cb_data)) {
    // deleting metadata
    res = _ykpiv_save_object(state, obj_id, NULL, 0);
  }
  else {
    *pTemp++ = tag;
    pTemp += _ykpiv_set_length(pTemp, cb_data);

    memcpy(pTemp, data, cb_data);
    pTemp += cb_data;

    res = _ykpiv_save_object(state, obj_id, buf, (size_t)(pTemp - buf));
  }

  return res;
}