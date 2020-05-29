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

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <ctype.h>
#include <time.h>

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

/*
** YKPIV Utility API - aggregate functions and slightly nicer interface
*/

ykpiv_rc ykpiv_util_get_cardid(ykpiv_state *state, ykpiv_cardid *cardid) {
  ykpiv_rc res = YKPIV_OK;
  uint8_t buf[CB_OBJ_MAX];
  unsigned long len = sizeof(buf);
  uint8_t *p_temp = NULL;
  size_t cb_temp = 0;
  uint8_t tag = 0;

  if (!cardid) return YKPIV_GENERIC_ERROR;

  if (YKPIV_OK != (res = _ykpiv_begin_transaction(state))) return res;
  if (YKPIV_OK != (res = _ykpiv_ensure_application_selected(state))) goto Cleanup;

  if ((res = _ykpiv_fetch_object(state, YKPIV_OBJ_CHUID, buf, &len)) == YKPIV_OK) {
    p_temp = buf;

    while (p_temp < (buf + len)) {
      tag = *p_temp++;

      if (!_ykpiv_has_valid_length(p_temp, buf + len - p_temp)) {
        res = YKPIV_SIZE_ERROR;
        goto Cleanup;
      }

      p_temp += _ykpiv_get_length(p_temp, &cb_temp);

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
  uint8_t id[YKPIV_CARDID_SIZE];
  uint8_t buf[sizeof(CHUID_TMPL)];
  size_t len = 0;

  if (!state) return YKPIV_GENERIC_ERROR;

  if (!cardid) {
    if (PRNG_OK != _ykpiv_prng_generate(id, sizeof(id))) {
      return YKPIV_RANDOMNESS_ERROR;
    }
  }
  else {
    memcpy(id, cardid->data, sizeof(id));
  }

  if (YKPIV_OK != (res = _ykpiv_begin_transaction(state))) return res;
  if (YKPIV_OK != (res = _ykpiv_ensure_application_selected(state))) goto Cleanup;

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
  uint8_t buf[CB_OBJ_MAX];
  unsigned long len = sizeof(buf);

  if (!ccc) return YKPIV_GENERIC_ERROR;

  if (YKPIV_OK != (res = _ykpiv_begin_transaction(state))) return res;
  if (YKPIV_OK != (res = _ykpiv_ensure_application_selected(state))) goto Cleanup;

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
  uint8_t id[YKPIV_CCCID_SIZE];
  uint8_t buf[sizeof(CCC_TMPL)];
  size_t len = 0;

  if (!state) return YKPIV_GENERIC_ERROR;

  if (!ccc) {
    if (PRNG_OK != _ykpiv_prng_generate(id, sizeof(id))) {
      return YKPIV_RANDOMNESS_ERROR;
    }
  }
  else {
    memcpy(id, ccc->data, sizeof(id));
  }

  if (YKPIV_OK != (res = _ykpiv_begin_transaction(state))) return res;
  if (YKPIV_OK != (res = _ykpiv_ensure_application_selected(state))) goto Cleanup;

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
  uint8_t buf[CB_BUF_MAX];
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

  if ((NULL == data) || (NULL == data_len) || (NULL == key_count)) { return YKPIV_GENERIC_ERROR; }

  if (YKPIV_OK != (res = _ykpiv_begin_transaction(state))) return res;
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
  if (!state || (!(state->allocator.pfn_free))) return YKPIV_GENERIC_ERROR;

  _ykpiv_free(state, data);

  return YKPIV_OK;
}

ykpiv_rc ykpiv_util_read_cert(ykpiv_state *state, uint8_t slot, uint8_t **data, size_t *data_len) {
  ykpiv_rc res = YKPIV_OK;
  uint8_t buf[CB_BUF_MAX];
  size_t cbBuf = sizeof(buf);

  if ((NULL == data )|| (NULL == data_len)) return YKPIV_GENERIC_ERROR;

  if (YKPIV_OK != (res = _ykpiv_begin_transaction(state))) return res;
  if (YKPIV_OK != (res = _ykpiv_ensure_application_selected(state))) goto Cleanup;

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

  if (YKPIV_OK != (res = _ykpiv_begin_transaction(state))) return res;
  if (YKPIV_OK != (res = _ykpiv_ensure_application_selected(state))) goto Cleanup;

  res = _write_certificate(state, slot, data, data_len, certinfo);

Cleanup:

  _ykpiv_end_transaction(state);
  return res;
}

ykpiv_rc ykpiv_util_delete_cert(ykpiv_state *state, uint8_t slot) {
  return ykpiv_util_write_cert(state, slot, NULL, 0, 0);
}

ykpiv_rc ykpiv_util_block_puk(ykpiv_state *state) {
  ykpiv_rc res = YKPIV_OK;
  uint8_t puk[] = { 0x30, 0x42, 0x41, 0x44, 0x46, 0x30, 0x30, 0x44 };
  int tries = -1;
  uint8_t data[CB_BUF_MAX];
  size_t  cb_data = sizeof(data);
  uint8_t *p_item = NULL;
  size_t  cb_item = 0;
  uint8_t flags = 0;

  if (NULL == state) return YKPIV_GENERIC_ERROR;

  if (YKPIV_OK != (res = _ykpiv_begin_transaction(state))) return res;
  if (YKPIV_OK != (res = _ykpiv_ensure_application_selected(state))) goto Cleanup;

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
        if (state->verbose) { fprintf(stderr, "admin flags exist, but are incorrect size = %lu", (unsigned long)cb_item); }
      }
    }
  }

  flags |= ADMIN_FLAGS_1_PUK_BLOCKED;

  if (YKPIV_OK != _set_metadata_item(data, &cb_data, CB_OBJ_MAX, TAG_ADMIN_FLAGS_1, (uint8_t*)&flags, sizeof(flags))) {
    if (state->verbose) { fprintf(stderr, "could not set admin flags"); }
  }
  else {
    if (YKPIV_OK != _write_metadata(state, TAG_ADMIN, data, cb_data)) {
      if (state->verbose) { fprintf(stderr, "could not write admin metadata"); }
    }
  }

Cleanup:

  _ykpiv_end_transaction(state);
  return res;
}

ykpiv_rc ykpiv_util_read_mscmap(ykpiv_state *state, ykpiv_container **containers, size_t *n_containers) {
  ykpiv_rc res = YKPIV_OK;
  uint8_t buf[CB_BUF_MAX];
  unsigned long cbBuf = sizeof(buf);
  size_t len = 0;
  uint8_t *ptr = NULL;

  if ((NULL == containers) || (NULL == n_containers)) { res = YKPIV_GENERIC_ERROR; goto Cleanup; }
  if (YKPIV_OK != (res = _ykpiv_begin_transaction(state))) return res;
  if (YKPIV_OK != (res = _ykpiv_ensure_application_selected(state))) goto Cleanup;

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
      ptr += (unsigned long)_ykpiv_get_length(ptr, &len);

      /* check that decoded length represents object contents */
      if (len > (cbBuf - (size_t)(ptr - buf))) {
        res = YKPIV_OK;
        goto Cleanup;
      }

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
  uint8_t buf[CB_OBJ_MAX];
  size_t offset = 0;
  size_t req_len = 0;
  size_t data_len = n_containers * sizeof(ykpiv_container);

  if (YKPIV_OK != (res = _ykpiv_begin_transaction(state))) return res;
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
  uint8_t buf[CB_BUF_MAX];
  unsigned long cbBuf = sizeof(buf);
  size_t len = 0;
  uint8_t *ptr = NULL;
  int object_id = 0;
  uint8_t tag = 0;
  uint8_t *pData = NULL;
  uint8_t *pTemp = NULL;
  size_t cbData = 0;
  size_t cbRealloc = 0;
  size_t offset = 0;

  if (!data || !data_len) return YKPIV_GENERIC_ERROR;

  if (YKPIV_OK != (res = _ykpiv_begin_transaction(state))) return res;
  if (YKPIV_OK != (res = _ykpiv_ensure_application_selected(state))) goto Cleanup;

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

    ptr += _ykpiv_get_length(ptr, &len);

    // check that decoded length represents object contents
    if (len > (cbBuf - (size_t)(ptr - buf))) {
      res = YKPIV_OK;
      goto Cleanup;
    }

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
  uint8_t buf[CB_OBJ_MAX];
  size_t offset = 0;
  size_t data_offset = 0;
  size_t data_chunk = 0;
  size_t n_objs = 0;
  unsigned int i = 0;
  size_t cb_obj_max = _obj_size_max(state);

  if (YKPIV_OK != (res = _ykpiv_begin_transaction(state))) return res;
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

  if (ykpiv_util_devicemodel(state) == DEVTYPE_YK4 && (algorithm == YKPIV_ALGO_RSA1024 || algorithm == YKPIV_ALGO_RSA2048)) {
    if ((state->ver.major == 4) && (state->ver.minor < 3 || ((state->ver.minor == 3) && (state->ver.patch < 5)))) {
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

      fprintf(stderr, sz_roca_format, state->serial, psz_msg);
      yc_log_event(1, setting_roca.value ? YC_LOG_LEVEL_WARN : YC_LOG_LEVEL_ERROR, sz_roca_format, state->serial, psz_msg);

      if (!setting_roca.value) {
        return YKPIV_NOT_SUPPORTED;
      }
    }
  }

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

  if (YKPIV_OK != (res = _ykpiv_begin_transaction(state))) return res;
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

  if (YKPIV_OK != (res = _ykpiv_transfer_data(state, templ, in_data, (long)(in_ptr - in_data), data, &recv_len, &sw))) {
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
    else if (sw == SW_ERR_SECURITY_STATUS) {
      res = YKPIV_AUTHENTICATION_ERROR;
      if (state->verbose) { fprintf(stderr, "not authenticated)\n"); }
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

  if (NULL == state) return YKPIV_GENERIC_ERROR;
  if (NULL == config) return YKPIV_GENERIC_ERROR;

  // initialize default values

  config->protected_data_available = false;
  config->puk_blocked = false;
  config->puk_noblock_on_upgrade = false;
  config->pin_last_changed = 0;
  config->mgm_type = YKPIV_CONFIG_MGM_MANUAL;

  if (YKPIV_OK != (res = _ykpiv_begin_transaction(state))) return res;
  if (YKPIV_OK != (res = _ykpiv_ensure_application_selected(state))) goto Cleanup;

  /* recover admin data */
  if (YKPIV_OK == _read_metadata(state, TAG_ADMIN, data, &cb_data)) {
    if (YKPIV_OK == _get_metadata_item(data, cb_data, TAG_ADMIN_FLAGS_1, &p_item, &cb_item)) {
      if (*p_item & ADMIN_FLAGS_1_PUK_BLOCKED) config->puk_blocked = true;
      if (*p_item & ADMIN_FLAGS_1_PROTECTED_MGM) config->mgm_type = YKPIV_CONFIG_MGM_PROTECTED;
    }

    if (YKPIV_OK == _get_metadata_item(data, cb_data, TAG_ADMIN_SALT, &p_item, &cb_item)) {
      if (config->mgm_type != YKPIV_CONFIG_MGM_MANUAL) {
        if (state->verbose) {
          fprintf(stderr, "conflicting types of mgm key administration configured\n");
        }
      }
      else {
        config->mgm_type = YKPIV_CONFIG_MGM_DERIVED;
      }
    }

    if (YKPIV_OK == _get_metadata_item(data, cb_data, TAG_ADMIN_TIMESTAMP, &p_item, &cb_item)) {
      if (CB_ADMIN_TIMESTAMP != cb_item)  {
        if (state->verbose) {
          fprintf(stderr, "pin timestamp in admin metadata is an invalid size");
        }
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
      if(sizeof(config->protected_data) == cb_item) {
        config->protected_data_available = true;
        memcpy(config->protected_data, p_item, cb_item);
        if (config->mgm_type != YKPIV_CONFIG_MGM_PROTECTED) {
          if (state->verbose) fprintf(stderr, "conflicting types of mgm key administration configured - protected mgm exists\n");
        }
      } else {
        if (state->verbose) fprintf(stderr, "protected data contains mgm, but is the wrong size = %lu\n", (unsigned long)cb_item);
      }
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

  if (NULL == state) return YKPIV_GENERIC_ERROR;

  if (YKPIV_OK != (res = _ykpiv_begin_transaction(state))) return res;
  if (YKPIV_OK != (res = _ykpiv_ensure_application_selected(state))) goto Cleanup;

  /* recover admin data */
  if (YKPIV_OK != (ykrc = _read_metadata(state, TAG_ADMIN, data, &cb_data))) {
    cb_data = 0; /* set current metadata blob size to zero, we'll add the timestamp to the blank blob */
  }

  tnow = time(NULL);

  if (YKPIV_OK != (res = _set_metadata_item(data, &cb_data, CB_OBJ_MAX, TAG_ADMIN_TIMESTAMP, (uint8_t*)&tnow, CB_ADMIN_TIMESTAMP))) {
    if (state->verbose) fprintf(stderr, "could not set pin timestamp, err = %d\n", res);
  }
  else {
    if (YKPIV_OK != (res = _write_metadata(state, TAG_ADMIN, data, cb_data))) {
      /* Note: this can fail if authenticate() wasn't called previously - expected behavior */
      if (state->verbose) fprintf(stderr, "could not write admin data, err = %d\n", res);
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

  if (NULL == state) return YKPIV_GENERIC_ERROR;
  if ((NULL == pin) || (0 == pin_len) || (NULL == mgm)) return YKPIV_GENERIC_ERROR;

  if (YKPIV_OK != (res = _ykpiv_begin_transaction(state))) return res;
  if (YKPIV_OK != (res = _ykpiv_ensure_application_selected(state))) goto Cleanup;

  /* recover management key */
  if (YKPIV_OK == (res = _read_metadata(state, TAG_ADMIN, data, &cb_data))) {
    if (YKPIV_OK == (res = _get_metadata_item(data, cb_data, TAG_ADMIN_SALT, &p_item, &cb_item))) {
      if (cb_item != CB_ADMIN_SALT) {
        if (state->verbose) fprintf(stderr, "derived mgm salt exists, but is incorrect size = %lu\n", (unsigned long)cb_item);
        res = YKPIV_GENERIC_ERROR;
        goto Cleanup;
      }

      if (PKCS5_OK != (p5rc = pkcs5_pbkdf2_sha1(pin, pin_len, p_item, cb_item, ITER_MGM_PBKDF2, mgm->data, member_size(ykpiv_mgm, data)))) {
        if (state->verbose) fprintf(stderr, "pbkdf2 failure, err = %d\n", p5rc);
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

  if (NULL == state) return YKPIV_GENERIC_ERROR;
  if (NULL == mgm) return YKPIV_GENERIC_ERROR;

  if (YKPIV_OK != (res = _ykpiv_begin_transaction(state))) return res;
  if (YKPIV_OK != (res = _ykpiv_ensure_application_selected(state))) goto Cleanup;

  if (YKPIV_OK != (res = _read_metadata(state, TAG_PROTECTED, data, &cb_data))) {
    if (state->verbose) fprintf(stderr, "could not read protected data, err = %d\n", res);
    goto Cleanup;
  }

  if (YKPIV_OK != (res = _get_metadata_item(data, cb_data, TAG_PROTECTED_MGM, &p_item, &cb_item))) {
    if (state->verbose) fprintf(stderr, "could not read protected mgm from metadata, err = %d\n", res);
    goto Cleanup;
  }

  if (cb_item != member_size(ykpiv_mgm, data)) {
    if (state->verbose) fprintf(stderr, "protected data contains mgm, but is the wrong size = %lu\n", (unsigned long)cb_item);
    res = YKPIV_AUTHENTICATION_ERROR;
    goto Cleanup;
  }

  memcpy(mgm->data, p_item, cb_item);

Cleanup:

  yc_memzero(data, sizeof(data));

  _ykpiv_end_transaction(state);
  return res;

}

/* to set a generated mgm, pass NULL for mgm, or set mgm.data to all zeroes */
ykpiv_rc ykpiv_util_set_protected_mgm(ykpiv_state *state, ykpiv_mgm *mgm) {
  ykpiv_rc res = YKPIV_OK;
  ykpiv_rc ykrc = YKPIV_OK;
  prng_rc  prngrc = PRNG_OK;
  bool     fGenerate = false;
  uint8_t  mgm_key[member_size(ykpiv_mgm, data)] = { 0 };
  size_t   i = 0;
  uint8_t  data[CB_BUF_MAX] = { 0 };
  size_t   cb_data = sizeof(data);
  uint8_t  *p_item = NULL;
  size_t   cb_item = 0;
  uint8_t  flags_1 = 0;

  if (NULL == state) return YKPIV_GENERIC_ERROR;

  if (!mgm) {
    fGenerate = true;
  }
  else {
    fGenerate = true;
    memcpy(mgm_key, mgm->data, sizeof(mgm_key));

    for (i = 0; i < sizeof(mgm_key); i++) {
      if (mgm_key[i] != 0) {
        fGenerate = false;
        break;
      }
    }
  }

  if (YKPIV_OK != (res = _ykpiv_begin_transaction(state))) goto Cleanup;
  if (YKPIV_OK != (res = _ykpiv_ensure_application_selected(state))) goto Cleanup;

  /* try to set the mgm key as long as we don't encounter a fatal error */
  do {
    if (fGenerate) {
      /* generate a new mgm key */
      if (PRNG_OK != (prngrc = _ykpiv_prng_generate(mgm_key, sizeof(mgm_key)))) {
        if (state->verbose) fprintf(stderr, "could not generate new mgm, err = %d\n", prngrc);
        res = YKPIV_RANDOMNESS_ERROR;
        goto Cleanup;
      }
    }

    if (YKPIV_OK != (ykrc = ykpiv_set_mgmkey(state, mgm_key))) {
      /*
      ** if _set_mgmkey fails with YKPIV_KEY_ERROR, it means the generated key is weak
      ** otherwise, log a warning, since the device mgm key is corrupt or we're in
      ** a state where we can't set the mgm key
      */
      if (YKPIV_KEY_ERROR != ykrc) {
        if (state->verbose) fprintf(stderr, "could not set new derived mgm key, err = %d\n", ykrc);
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
    memcpy(mgm->data, mgm_key, sizeof(mgm_key));
  }

  /* after this point, we've set the mgm key, so the function should succeed, regardless of being able to set the metadata */

  /* set the new mgm key in protected data */
  if (YKPIV_OK != (ykrc = _read_metadata(state, TAG_PROTECTED, data, &cb_data))) {
    cb_data = 0; /* set current metadata blob size to zero, we'll add to the blank blob */
  }

  if (YKPIV_OK != (ykrc = _set_metadata_item(data, &cb_data, CB_OBJ_MAX, TAG_PROTECTED_MGM, mgm_key, sizeof(mgm_key)))) {
    if (state->verbose) fprintf(stderr, "could not set protected mgm item, err = %d\n", ykrc);
  }
  else {
    if (YKPIV_OK != (ykrc = _write_metadata(state, TAG_PROTECTED, data, cb_data))) {
      if (state->verbose) fprintf(stderr, "could not write protected data, err = %d\n", ykrc);
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
      if (state->verbose) fprintf(stderr, "admin data exists, but flags are not present\n");
    }

    if (cb_item == sizeof(flags_1)) {
      memcpy(&flags_1, p_item, cb_item);
    }
    else {
      if (state->verbose) fprintf(stderr, "admin data flags are an incorrect size = %lu\n", (unsigned long)cb_item);
    }

    /* remove any existing salt */
    if (YKPIV_OK != (ykrc = _set_metadata_item(data, &cb_data, CB_OBJ_MAX, TAG_ADMIN_SALT, NULL, 0))) {
      if (state->verbose) fprintf(stderr, "could not unset derived mgm salt, err = %d\n", ykrc);
    }
  }

  flags_1 |= ADMIN_FLAGS_1_PROTECTED_MGM;

  if (YKPIV_OK != (ykrc = _set_metadata_item(data, &cb_data, CB_OBJ_MAX, TAG_ADMIN_FLAGS_1, &flags_1, sizeof(flags_1)))) {
    if (state->verbose) fprintf(stderr, "could not set admin flags item, err = %d\n", ykrc);
  }
  else {
    if (YKPIV_OK != (ykrc = _write_metadata(state, TAG_ADMIN, data, cb_data))) {
      if (state->verbose) fprintf(stderr, "could not write admin data, err = %d\n", ykrc);
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

static ykpiv_rc _read_certificate(ykpiv_state *state, uint8_t slot, uint8_t *buf, size_t *buf_len) {
  ykpiv_rc res = YKPIV_OK;
  uint8_t *ptr = NULL;
  int object_id = (int)ykpiv_util_slot_object(slot);
  size_t len = 0;

  if (-1 == object_id) return YKPIV_INVALID_OBJECT;

  if (YKPIV_OK == (res = _ykpiv_fetch_object(state, object_id, buf, (unsigned long*)buf_len))) {
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
      if (len > (*buf_len - (size_t)(ptr - buf))) {
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

static ykpiv_rc _write_certificate(ykpiv_state *state, uint8_t slot, uint8_t *data, size_t data_len, uint8_t certinfo) {
  uint8_t buf[CB_OBJ_MAX];
  int object_id = (int)ykpiv_util_slot_object(slot);
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

    return _ykpiv_save_object(state, object_id, NULL, 0);
  }

  // encode certificate data for storage

  // calculate the required length of the encoded object
  req_len = 1 /* cert tag */ + 3 /* compression tag + data*/ + 2 /* lrc */;
  req_len += _ykpiv_set_length(buf, data_len);
  req_len += data_len;

  if (req_len < data_len) return YKPIV_SIZE_ERROR; /* detect overflow of unsigned size_t */
  if (req_len > _obj_size_max(state)) return YKPIV_SIZE_ERROR; /* obj_size_max includes limits for TLV encoding */

  buf[offset++] = TAG_CERT;
  offset += _ykpiv_set_length(buf + offset, data_len);
  memcpy(buf + offset, data, data_len);
  offset += data_len;

  // write compression info and LRC trailer
  buf[offset++] = TAG_CERT_COMPRESS;
  buf[offset++] = 0x01;
  buf[offset++] = certinfo == YKPIV_CERTINFO_GZIP ? 0x01 : 0x00;
  buf[offset++] = TAG_CERT_LRC;
  buf[offset++] = 00;

  // write onto device
  return _ykpiv_save_object(state, object_id, buf, offset);
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
  size_t  cb_temp = 0;
  uint8_t tag_temp = 0;

  if (!data || !pp_item || !pcb_item) return YKPIV_GENERIC_ERROR;

  *pp_item = NULL;
  *pcb_item = 0;

  while (p_temp < (data + cb_data)) {
    tag_temp = *p_temp++;

    if (!_ykpiv_has_valid_length(p_temp, data + cb_data - p_temp)) {
      return YKPIV_SIZE_ERROR;
    }

    p_temp += _ykpiv_get_length(p_temp, &cb_temp);

    if (tag_temp == tag) {
      // found tag
      break;
    }

    p_temp += cb_temp;
  }

  // Make sure the item doesn't end after the buffer
  if ((p_temp + cb_temp) <= (data + cb_data)) {
    *pp_item = p_temp;
    *pcb_item = cb_temp;
    return YKPIV_OK;
  }

  return YKPIV_GENERIC_ERROR;
}

ykpiv_rc ykpiv_util_parse_metadata(uint8_t *data, size_t data_len, ykpiv_metadata *metadata) {
  uint8_t *p;
  size_t cb;

  ykpiv_rc rc = _get_metadata_item(data, data_len, YKPIV_METADATA_ALGORITHM_TAG, &p, &cb);
  if(rc != YKPIV_OK)
    return rc;
  if(cb != 1)
    return YKPIV_PARSE_ERROR;
  metadata->algorithm = p[0];

  rc = _get_metadata_item(data, data_len, YKPIV_METADATA_POLICY_TAG, &p, &cb);
  if(rc != YKPIV_OK)
    return rc;
  if(cb != 2)
    return YKPIV_PARSE_ERROR;
  metadata->pin_policy = p[0];
  metadata->touch_policy = p[1];

  rc = _get_metadata_item(data, data_len, YKPIV_METADATA_ORIGIN_TAG, &p, &cb);
  if(rc != YKPIV_OK)
    return rc;
  if(cb != 1)
    return YKPIV_PARSE_ERROR;
  metadata->origin = p[0];

  rc = _get_metadata_item(data, data_len, YKPIV_METADATA_PUBKEY_TAG, &p, &cb);
  if(rc != YKPIV_OK)
    return rc;
  if(cb > sizeof(metadata->pubkey))
    return YKPIV_PARSE_ERROR;

  metadata->pubkey_len = cb;
  memcpy(metadata->pubkey, p, cb);

  return YKPIV_OK;
}

static int _get_length_size(size_t length) {
  if (length < 0x80) {
    return 1;
  }
  else if (length < 0xff) {
    return 2;
  }
  else {
    return 3;
  }
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

  if (!data || !pcb_data) return YKPIV_GENERIC_ERROR;

  while (p_temp < (data + *pcb_data)) {
    tag_temp = *p_temp++;
    cb_len = _ykpiv_get_length(p_temp, &cb_temp);
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
        ((long)(cb_item != 0 ? _get_length_size(cb_item) : -1 /* for tag, if deleting */) -
        (long)cb_len); /* accounts for different length encoding */

      /* length would cause buffer overflow, return error */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wsign-conversion"
      if ((size_t)(*pcb_data + cb_moved) > cb_data_max) {
        return YKPIV_GENERIC_ERROR;
      }
#pragma GCC diagnostic pop

      /* move remaining data */
      memmove(p_next + cb_moved, p_next, *pcb_data - (size_t)(p_next - data));
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wsign-conversion"
      *pcb_data += cb_moved;
#pragma GCC diagnostic pop

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
  cb_len = (size_t)_get_length_size(cb_item);

  // length would cause buffer overflow, return error
  if (*pcb_data + cb_len + cb_item > cb_data_max) {
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
  int obj_id = 0;

  if (!data || !pcb_data || (CB_BUF_MAX > *pcb_data)) return YKPIV_GENERIC_ERROR;

  switch (tag) {
  case TAG_ADMIN: obj_id = YKPIV_OBJ_ADMIN_DATA; break;
  case TAG_PROTECTED: obj_id = YKPIV_OBJ_PRINTED; break;
  default: return YKPIV_INVALID_OBJECT;
  }

  cb_temp = *pcb_data;
  *pcb_data = 0;

  if (YKPIV_OK != (res = _ykpiv_fetch_object(state, obj_id, data, &cb_temp))) {
    return res;
  }

  if (cb_temp < CB_OBJ_TAG_MIN) return YKPIV_GENERIC_ERROR;

  p_temp = data;

  if (tag != *p_temp++) return YKPIV_GENERIC_ERROR;

  p_temp += _ykpiv_get_length(p_temp, pcb_data);

  if (*pcb_data > (cb_temp - (size_t)(p_temp - data))) {
    *pcb_data = 0;
    return YKPIV_GENERIC_ERROR;
  }

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
