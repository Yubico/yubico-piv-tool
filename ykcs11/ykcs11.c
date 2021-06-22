/*
 * Copyright (c) 2014-2017,2019-2020 Yubico AB
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

#include "ykcs11.h"
#include "ykcs11-config.h"
#include <stdlib.h>
#include "ykpiv.h"
#include <string.h>
#include "obj_types.h"
#include "objects.h"
#include "utils.h"
#include "mechanisms.h"
#include "token.h"
#include "openssl_types.h"
#include "openssl_utils.h"
#include "debug.h"

#include <stdbool.h>

#define YKCS11_MANUFACTURER "Yubico (www.yubico.com)"
#define YKCS11_LIBDESC      "PKCS#11 PIV Library (SP-800-73)"

#define YKCS11_MAX_SLOTS       16
#define YKCS11_MAX_SESSIONS    16

static ykcs11_slot_t slots[YKCS11_MAX_SLOTS];
static CK_ULONG      n_slots = 0;

static ykcs11_session_t sessions[YKCS11_MAX_SESSIONS];

static CK_C_INITIALIZE_ARGS locking;
static void *global_mutex;
static uint64_t pid;
int verbose;

static const CK_FUNCTION_LIST function_list;
static const CK_FUNCTION_LIST_3_0 function_list_3;

static CK_SESSION_HANDLE get_session_handle(ykcs11_session_t *session) {
  return (CK_SESSION_HANDLE)(session - sessions + 1);
}

static ykcs11_session_t* get_session(CK_SESSION_HANDLE handle) {
  if(handle < 1 || handle > YKCS11_MAX_SESSIONS)
    return NULL;
  return sessions + handle - 1;
}

static ykcs11_session_t* get_free_session(void) {
  for(int i = 0; i < YKCS11_MAX_SESSIONS; i++) {
    if(sessions[i].slot == NULL) {
      return sessions + i;
    }
  }
  return NULL;
}

static void cleanup_session(ykcs11_session_t *session) {
  DBG("Cleaning up session %lu", get_session_handle(session));
  memset(session, 0, sizeof(*session));
}

static void cleanup_slot(ykcs11_slot_t *slot) {
  DBG("Cleaning up slot %lu", slot - slots);
  for(size_t i = 0; i < sizeof(slot->data) / sizeof(slot->data[0]); i++) {
    free(slot->data[i].data);
    slot->data[i].data = NULL;
  }
  for(size_t i = 0; i < sizeof(slot->certs) / sizeof(slot->certs[0]); i++) {
    do_delete_pubk(slot->pkeys + i);
    do_delete_cert(slot->certs + i);
    do_delete_cert(slot->atst + i);
  }
  memset(slot->objects, 0, sizeof(slot->objects));
  slot->login_state = YKCS11_PUBLIC;
  slot->n_objects = 0;
}

/* General Purpose */

CK_DEFINE_FUNCTION(CK_RV, C_Initialize)(
  CK_VOID_PTR pInitArgs
)
{
#if YKCS11_DBG
  verbose = YKCS11_DBG;
#else
  const char *dbg = getenv("YKCS11_DBG");
  verbose = dbg ? atoi(dbg) : 0;
#endif

  DIN;
  CK_RV rv;

  // Allow C_Initialize only if we are not initialized or initialized by our parent
  if ((rv = check_pid(pid)) != CKR_OK) {
    DBG("Library already initialized");
    goto init_out;
  }

  locking.pfnCreateMutex = noop_create_mutex;
  locking.pfnDestroyMutex = noop_destroy_mutex;
  locking.pfnLockMutex = noop_mutex_fn;
  locking.pfnUnlockMutex = noop_mutex_fn;

  if(pInitArgs)
  {
    CK_C_INITIALIZE_ARGS_PTR pArgs = (CK_C_INITIALIZE_ARGS_PTR)pInitArgs;
    if(pArgs->pReserved) {
      rv = CKR_ARGUMENTS_BAD;
      goto init_out;
    }
    bool os_locking = pArgs->flags & CKF_OS_LOCKING_OK;
    if(os_locking || pArgs->pfnCreateMutex)
      locking.pfnCreateMutex = pArgs->pfnCreateMutex;
    if(os_locking || pArgs->pfnDestroyMutex)
      locking.pfnDestroyMutex = pArgs->pfnDestroyMutex;
    if(os_locking || pArgs->pfnLockMutex)
      locking.pfnLockMutex = pArgs->pfnLockMutex;
    if(os_locking || pArgs->pfnUnlockMutex)
      locking.pfnUnlockMutex = pArgs->pfnUnlockMutex;
    if(os_locking) {
      if(locking.pfnCreateMutex == 0)
        locking.pfnCreateMutex = native_create_mutex;
      if(locking.pfnDestroyMutex == 0)
        locking.pfnDestroyMutex = native_destroy_mutex;
      if(locking.pfnLockMutex == 0)
        locking.pfnLockMutex = native_lock_mutex;
      if(locking.pfnUnlockMutex == 0)
        locking.pfnUnlockMutex = native_unlock_mutex;
    }
    if(locking.pfnCreateMutex == 0) {
      rv = CKR_CANT_LOCK;
      goto init_out;
    }
    if(locking.pfnDestroyMutex == 0) {
      rv = CKR_CANT_LOCK;
      goto init_out;
    }
    if(locking.pfnLockMutex == 0) {
      rv = CKR_CANT_LOCK;
      goto init_out;
    }
    if(locking.pfnUnlockMutex == 0) {
      rv = CKR_CANT_LOCK;
      goto init_out;
    }
  }

  // Set up pid to disallow further re-init by this process, and to allow our potential children to re-init
  if ((rv = get_pid(&pid)) != CKR_OK) {
    DBG("Library can't be initialized");
    goto init_out;
  }

  // Overwrite global mutex even if inherited (global state is per-process)
  if((rv = locking.pfnCreateMutex(&global_mutex)) != CKR_OK) {
    DBG("Unable to create global mutex");
    pid = 0;
    goto init_out;
  }

  // Re-use inherited per-slot mutex if available (slots are shared with parent)
  for(int i = 0; i < YKCS11_MAX_SLOTS; i++) {
    if(slots[i].mutex == NULL) {
      if((rv = locking.pfnCreateMutex(&slots[i].mutex)) != CKR_OK) {
        DBG("Unable to create mutex for slot %d", i);
        pid = 0;
        goto init_out;
      }
    }
  }
  rv = CKR_OK;

init_out:
  DOUT;
  return rv;
}

CK_DEFINE_FUNCTION(CK_RV, C_Finalize)(
  CK_VOID_PTR pReserved
)
{
  DIN;

  CK_RV rv;

  if (!pid) {
    DBG("libykpiv is not initialized or already finalized");
    rv = CKR_CRYPTOKI_NOT_INITIALIZED;
    goto fin_out;
  }

  if (pReserved != NULL) {
    DBG("Finalized called with pReserved != NULL");
    rv = CKR_ARGUMENTS_BAD;
    goto fin_out;
  }

  // Clean up all sessions
  for(int i = 0; i < YKCS11_MAX_SESSIONS; i++) {
    if(sessions[i].slot)
      cleanup_session(sessions + i);
  }

  // Close all slot states (will reset cards)
  for(int i = 0; i < YKCS11_MAX_SLOTS; i++) {
    if(slots[i].n_objects) {
      cleanup_slot(slots + i);
    }
    if(slots[i].piv_state) {
      ykpiv_done(slots[i].piv_state);
    }
    locking.pfnDestroyMutex(slots[i].mutex);
  }

  memset(&slots, 0, sizeof(slots));
  n_slots = 0;

  locking.pfnDestroyMutex(global_mutex);
  global_mutex = NULL;
  pid = 0;
  rv = CKR_OK;

fin_out:
  DOUT;
  return rv;
}

CK_DEFINE_FUNCTION(CK_RV, C_GetInfo)(
  CK_INFO_PTR pInfo
)
{
  CK_RV rv;
  DIN;

  if (!pid) {
    DBG("libykpiv is not initialized or already finalized");
    rv = CKR_CRYPTOKI_NOT_INITIALIZED;
    goto info_out;
  }

  if (pInfo == NULL) {
    DBG("Wrong/Missing parameter");
    rv = CKR_ARGUMENTS_BAD;
    goto info_out;
  }
  
  pInfo->cryptokiVersion = function_list.version;
  pInfo->libraryVersion.major = YKCS11_VERSION_MAJOR;
  pInfo->libraryVersion.minor = (YKCS11_VERSION_MINOR * 10) + YKCS11_VERSION_PATCH;
  pInfo->flags = 0;

  memstrcpy(pInfo->manufacturerID, sizeof(pInfo->manufacturerID), YKCS11_MANUFACTURER);
  memstrcpy(pInfo->libraryDescription, sizeof(pInfo->libraryDescription), YKCS11_LIBDESC);
  rv = CKR_OK;

info_out:
  DOUT;
  return rv;
}

CK_DEFINE_FUNCTION(CK_RV, C_GetFunctionList)(
  CK_FUNCTION_LIST_PTR_PTR ppFunctionList
)
{
  DIN;
  CK_RV rv;

  if(ppFunctionList == NULL) {
    DBG("GetFunctionList called with ppFunctionList = NULL");
    rv = CKR_ARGUMENTS_BAD;
    goto funclist_out;
  }
  *ppFunctionList = &function_list;
  rv = CKR_OK;


funclist_out:
  DOUT;
  return rv;
}

/* Slot and token management */

CK_DEFINE_FUNCTION(CK_RV, C_GetSlotList)(
  CK_BBOOL tokenPresent,
  CK_SLOT_ID_PTR pSlotList,
  CK_ULONG_PTR pulCount
)
{
  DIN;
  char readers[2048] = {0};
  size_t len = sizeof(readers);
  CK_RV rv;

  if (!pid) {
    DBG("libykpiv is not initialized or already finalized");
    rv = CKR_CRYPTOKI_NOT_INITIALIZED;
    goto slotlist_out;
  }

  if(pulCount == NULL) {
    DBG("GetSlotList called with pulCount = NULL");
    rv = CKR_ARGUMENTS_BAD;
    goto slotlist_out;
  }

  ykpiv_state *piv_state;
  if (ykpiv_init(&piv_state, verbose) != YKPIV_OK) {
    DBG("Unable to initialize libykpiv");
    rv = CKR_FUNCTION_FAILED;
    goto slotlist_out;
  }

  if (ykpiv_list_readers(piv_state, readers, &len) != YKPIV_OK) {
    DBG("Unable to list readers");
    ykpiv_done(piv_state);
    rv = CKR_DEVICE_ERROR;
    goto slotlist_out;
  }

  ykpiv_done(piv_state);

  locking.pfnLockMutex(global_mutex);

  // Mark existing slots as candidates for disconnect
  bool mark[YKCS11_MAX_SLOTS] = { false };
  for(CK_ULONG i = 0; i < n_slots; i++) {
    mark[i] = true;
  }

  for(char *reader = readers; *reader; reader += strlen(reader) + 1) {

    if(is_yubico_reader(reader)) {

      ykcs11_slot_t *slot = slots + n_slots;

      // Values must NOT be null terminated and ' ' padded

      memstrcpy(slot->slot_info.slotDescription, sizeof(slot->slot_info.slotDescription), reader);
      memstrcpy(slot->slot_info.manufacturerID, sizeof(slot->slot_info.manufacturerID), YKCS11_MANUFACTURER);

      slot->slot_info.hardwareVersion.major = 1;
      slot->slot_info.hardwareVersion.minor = 0;
      slot->slot_info.firmwareVersion.major = 1;
      slot->slot_info.firmwareVersion.minor = 0;
      slot->slot_info.flags = CKF_HW_SLOT | CKF_REMOVABLE_DEVICE;

      // Find existing slot, if any
      for(CK_ULONG i = 0; i < n_slots; i++) {
        if(!memcmp(slot->slot_info.slotDescription, slots[i].slot_info.slotDescription, sizeof(slot->slot_info.slotDescription))) {
          slot = slots + i;
          mark[i] = false; // Un-mark for disconnect
          break;
        }
      }

      // Initialize piv_state and increase slot count if this is a new slot
      if(slot == slots + n_slots) {
        DBG("Initializing slot %lu for '%s'", slot-slots, reader);
        ykpiv_rc rc;
        if((rc = ykpiv_init(&slot->piv_state, verbose)) != YKPIV_OK) {
          DBG("Unable to initialize libykpiv: %s", ykpiv_strerror(rc));
          locking.pfnUnlockMutex(global_mutex);
          rv = CKR_FUNCTION_FAILED;
          goto slotlist_out;
        }
        n_slots++;
      }

      // Try to connect if unconnected (both new and existing slots)
      if (ykpiv_validate(slot->piv_state, reader) != YKPIV_OK) {

        slot->login_state = YKCS11_PUBLIC;
        slot->slot_info.flags &= ~CKF_TOKEN_PRESENT;

        char buf[sizeof(readers) + 1] = {0};
        snprintf(buf, sizeof(buf), "@%s", reader);

        if (ykpiv_connect(slot->piv_state, buf) == YKPIV_OK) {

          DBG("Connected slot %lu to '%s'", slot-slots, reader);

          slot->slot_info.flags |= CKF_TOKEN_PRESENT;
          slot->token_info.flags = CKF_RNG | CKF_LOGIN_REQUIRED | CKF_USER_PIN_INITIALIZED | CKF_TOKEN_INITIALIZED;

          slot->token_info.ulMinPinLen = YKPIV_MIN_PIN_LEN;
          slot->token_info.ulMaxPinLen = YKPIV_MGM_KEY_LEN;

          slot->token_info.ulMaxRwSessionCount = YKCS11_MAX_SESSIONS;
          slot->token_info.ulMaxSessionCount = YKCS11_MAX_SESSIONS;

          slot->token_info.ulTotalPublicMemory = CK_UNAVAILABLE_INFORMATION;
          slot->token_info.ulFreePublicMemory = CK_UNAVAILABLE_INFORMATION;
          slot->token_info.ulTotalPrivateMemory = CK_UNAVAILABLE_INFORMATION;
          slot->token_info.ulFreePrivateMemory = CK_UNAVAILABLE_INFORMATION;

          slot->token_info.hardwareVersion.major = 1;
          slot->token_info.hardwareVersion.minor = 0;

          memstrcpy(slot->token_info.manufacturerID, sizeof(slot->token_info.manufacturerID), YKCS11_MANUFACTURER);
          memset(slot->token_info.utcTime, ' ', sizeof(slot->token_info.utcTime));

          get_token_model(slot->piv_state, slot->token_info.model, sizeof(slot->token_info.model));
          get_token_serial(slot->piv_state, slot->token_info.serialNumber, sizeof(slot->token_info.serialNumber));
          get_token_version(slot->piv_state, &slot->token_info.firmwareVersion);
          get_token_label(slot->piv_state, slot->token_info.label, sizeof(slot->token_info.label));
        }
      }
    }
  }

  // Disconnect connected slots that are no longer present
  for(CK_ULONG i = 0; i < n_slots; i++) {
    if(mark[i] && (slots[i].slot_info.flags & CKF_TOKEN_PRESENT)) {
      DBG("Disconnecting slot %lu", i);
      ykpiv_disconnect(slots[i].piv_state);
      slots[i].slot_info.flags &= ~CKF_TOKEN_PRESENT;
    }
  }

  // Count and return slots with or without tokens as requested
  CK_ULONG count = 0;
  for (CK_ULONG i = 0; i < n_slots; i++) {
    if(!tokenPresent || (slots[i].slot_info.flags & CKF_TOKEN_PRESENT)) {
      if(pSlotList) {
        if(count >= *pulCount) {
          DBG("Buffer too small: needed %lu, provided %lu", count, *pulCount);
          locking.pfnUnlockMutex(global_mutex);
          rv = CKR_BUFFER_TOO_SMALL;
          goto slotlist_out;
        }
        pSlotList[count] = i;
      }
      count++;
    }
  }

  *pulCount = count;

  locking.pfnUnlockMutex(global_mutex);

  DBG("token present is %d", tokenPresent);
  DBG("number of slots is %lu", *pulCount);
  rv = CKR_OK;

slotlist_out:
  DOUT;
  return rv;
}

CK_DEFINE_FUNCTION(CK_RV, C_GetSlotInfo)(
  CK_SLOT_ID slotID,
  CK_SLOT_INFO_PTR pInfo
)
{
  DIN;
  CK_RV rv;

  if (!pid) {
    DBG("libykpiv is not initialized or already finalized");
    rv = CKR_CRYPTOKI_NOT_INITIALIZED;
    goto slotinfo_out;
  }

  if (pInfo == NULL) {
    DBG("Wrong/Missing parameter");
    rv = CKR_ARGUMENTS_BAD;
    goto slotinfo_out;
  }

  locking.pfnLockMutex(global_mutex);

  if (slotID >= n_slots) {
    DBG("Invalid slot ID %lu", slotID);
    locking.pfnUnlockMutex(global_mutex);
    rv = CKR_SLOT_ID_INVALID;
    goto slotinfo_out;
  }

  memcpy(pInfo, &slots[slotID].slot_info, sizeof(CK_SLOT_INFO));

  locking.pfnUnlockMutex(global_mutex);
  rv = CKR_OK;

slotinfo_out:  
  DOUT;
  return rv;
}

CK_DEFINE_FUNCTION(CK_RV, C_GetTokenInfo)(
  CK_SLOT_ID slotID,
  CK_TOKEN_INFO_PTR pInfo
)
{
  DIN;
  CK_RV rv;

  if (!pid) {
    DBG("libykpiv is not initialized or already finalized");
    rv = CKR_CRYPTOKI_NOT_INITIALIZED;
    goto tokeninfo_out;
  }

  if (pInfo == NULL) {
    DBG("Wrong/Missing parameter");
    rv = CKR_ARGUMENTS_BAD;
    goto tokeninfo_out;
  }

  locking.pfnLockMutex(global_mutex);

  if (slotID >= n_slots) {
    DBG("Invalid slot ID %lu", slotID);
    locking.pfnUnlockMutex(global_mutex);
    rv = CKR_SLOT_ID_INVALID;
    goto tokeninfo_out;
  }

  if(!(slots[slotID].slot_info.flags & CKF_TOKEN_PRESENT)) {
    DBG("A token is not present in slot %lu", slotID);
    locking.pfnUnlockMutex(global_mutex);
    rv = CKR_TOKEN_NOT_PRESENT;
    goto tokeninfo_out;
  }

  memcpy(pInfo, &slots[slotID].token_info, sizeof(CK_TOKEN_INFO));

  int tries = YKPIV_RETRIES_MAX;
  ykpiv_get_pin_retries(slots[slotID].piv_state, &tries);

  switch(tries) {
    case 0:
      pInfo->flags |= CKF_USER_PIN_LOCKED;
      break;
    case 1:
      pInfo->flags |= CKF_USER_PIN_FINAL_TRY;
      break;
    case 2:
      pInfo->flags |= CKF_USER_PIN_COUNT_LOW;
      break;
    default:
      break;
  }

  for(int i = 0; i < YKCS11_MAX_SESSIONS; i++) {
    if(sessions[i].slot) {
      if(sessions[i].info.flags & CKF_RW_SESSION) {
        pInfo->ulRwSessionCount++;
      }
      else {
        pInfo->ulSessionCount++;
      }
    }
  }

  locking.pfnUnlockMutex(global_mutex);
  rv = CKR_OK;

tokeninfo_out:  
  DOUT;
  return rv;
}

CK_DEFINE_FUNCTION(CK_RV, C_WaitForSlotEvent)(
  CK_FLAGS flags,
  CK_SLOT_ID_PTR pSlot,
  CK_VOID_PTR pReserved
)
{
  DIN;
  DBG("TODO!!!");
  DOUT;
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_GetMechanismList)(
  CK_SLOT_ID slotID,
  CK_MECHANISM_TYPE_PTR pMechanismList,
  CK_ULONG_PTR pulCount
)
{
  DIN;
  CK_RV rv;

  if (!pid) {
    DBG("libykpiv is not initialized or already finalized");
    rv = CKR_CRYPTOKI_NOT_INITIALIZED;
    goto mechlist_out;
  }

  if (pulCount == NULL) {
    DBG("Wrong/Missing parameter");
    rv = CKR_ARGUMENTS_BAD;
    goto mechlist_out;
  }

  locking.pfnLockMutex(global_mutex);

  if (slotID >= n_slots) {
    DBG("Invalid slot ID %lu", slotID);
    locking.pfnUnlockMutex(global_mutex);
    rv = CKR_SLOT_ID_INVALID;
    goto mechlist_out;
  }

  if(!(slots[slotID].slot_info.flags & CKF_TOKEN_PRESENT)) {
    DBG("A token is not present in slot %lu", slotID);
    locking.pfnUnlockMutex(global_mutex);
    rv = CKR_TOKEN_NOT_PRESENT;
    goto mechlist_out;
  }

  locking.pfnUnlockMutex(global_mutex);

  if ((rv = get_token_mechanism_list(pMechanismList, pulCount)) != CKR_OK) {
    DBG("Unable to retrieve mechanism list");
    goto mechlist_out;
  }

  rv = CKR_OK;

mechlist_out:
  DOUT;
  return rv;
}

CK_DEFINE_FUNCTION(CK_RV, C_GetMechanismInfo)(
  CK_SLOT_ID slotID,
  CK_MECHANISM_TYPE type,
  CK_MECHANISM_INFO_PTR pInfo
)
{
  DIN;
  CK_RV rv;

  if (!pid) {
    DBG("libykpiv is not initialized or already finalized");
    rv = CKR_CRYPTOKI_NOT_INITIALIZED;
    goto mechinfo_out;
  }

  if (pInfo == NULL) {
    DBG("Wrong/Missing parameter");
    rv = CKR_ARGUMENTS_BAD;
    goto mechinfo_out;
  }

  locking.pfnLockMutex(global_mutex);

  if (slotID >= n_slots) {
    DBG("Invalid slot ID %lu", slotID);
    locking.pfnUnlockMutex(global_mutex);
    rv = CKR_SLOT_ID_INVALID;
    goto mechinfo_out;
  }

  if(!(slots[slotID].slot_info.flags & CKF_TOKEN_PRESENT)) {
    DBG("A token is not present in slot %lu", slotID);
    locking.pfnUnlockMutex(global_mutex);
    rv = CKR_TOKEN_NOT_PRESENT;
    goto mechinfo_out;
  }

  locking.pfnUnlockMutex(global_mutex);

  if ((rv = get_token_mechanism_info(type, pInfo)) != CKR_OK) {
    DBG("Unable to retrieve mechanism information");
    goto mechinfo_out;
  }

  rv = CKR_OK;

mechinfo_out:
  DOUT;
  return rv;
}

CK_DEFINE_FUNCTION(CK_RV, C_InitToken)(
  CK_SLOT_ID slotID,
  CK_UTF8CHAR_PTR pPin,
  CK_ULONG ulPinLen,
  CK_UTF8CHAR_PTR pLabel
)
{
  DIN;
  CK_RV rv;

  if (!pid) {
    DBG("libykpiv is not initialized or already finalized");
    rv = CKR_CRYPTOKI_NOT_INITIALIZED;
    goto inittoken_out;
  }

  locking.pfnLockMutex(global_mutex);

  if (slotID >= n_slots) {
    DBG("Invalid slot ID %lu", slotID);
    locking.pfnUnlockMutex(global_mutex);
    rv = CKR_SLOT_ID_INVALID;
    goto inittoken_out;
  }

  if(!(slots[slotID].slot_info.flags & CKF_TOKEN_PRESENT)) {
    DBG("A token is not present in slot %lu", slotID);
    locking.pfnUnlockMutex(global_mutex);
    rv = CKR_TOKEN_NOT_PRESENT;
    goto inittoken_out;
  }

  for(int i = 0; i < YKCS11_MAX_SESSIONS; i++) {
    ykcs11_session_t *session = sessions + i;
    if(session->slot && session->info.slotID == slotID) {
      locking.pfnUnlockMutex(global_mutex);
      rv = CKR_SESSION_EXISTS;
      goto inittoken_out;
    }
  }

  locking.pfnUnlockMutex(global_mutex);

  CK_BYTE mgm_key[24] = {0};
  size_t len = sizeof(mgm_key);
  ykpiv_rc rc;

  if(pPin == NULL) {
    DBG("Missing SO PIN");
    rv = CKR_ARGUMENTS_BAD;
    goto inittoken_out;
  }

  if((rc = ykpiv_hex_decode((const char*)pPin, ulPinLen, mgm_key, &len)) != YKPIV_OK || len != 24) {
    DBG("ykpiv_hex_decode failed %s", ykpiv_strerror(rc));
    rv = CKR_PIN_INVALID;
    goto inittoken_out;
  }

  int tries;
  ykcs11_slot_t *slot = slots + slotID;

  locking.pfnLockMutex(slot->mutex);

  // Verify existing mgm key (SO_PIN)
  if((rc = ykpiv_authenticate(slot->piv_state, mgm_key)) != YKPIV_OK) {
    DBG("ykpiv_authenticate failed %s", ykpiv_strerror(rc));
    locking.pfnUnlockMutex(slot->mutex);
    rv = rc == YKPIV_AUTHENTICATION_ERROR ? CKR_PIN_INCORRECT : CKR_DEVICE_ERROR;
    goto inittoken_out;
  }

  // Block PIN
  while((rc = ykpiv_verify(slot->piv_state, "", &tries)) == YKPIV_WRONG_PIN && tries > 0) {
    DBG("ykpiv_verify (%s), %d tries left", ykpiv_strerror(rc), tries);
  }

  // Block PUK
  while((rc = ykpiv_unblock_pin(slot->piv_state, "", 0, "", 0, &tries)) == YKPIV_WRONG_PIN && tries > 0) {
    DBG("ykpiv_unblock_pin (%s), %d tries left", ykpiv_strerror(rc), tries);
  }

  // Reset PIV (requires PIN and PUK to be blocked)
  if((rc = ykpiv_util_reset(slot->piv_state)) != YKPIV_OK) {
    DBG("ykpiv_util_reset failed %s", ykpiv_strerror(rc));
    locking.pfnUnlockMutex(slot->mutex);
    rv = CKR_DEVICE_ERROR;
    goto inittoken_out;
  }

  // Authenticate with default mgm key (SO PIN)
  if((rc = ykpiv_authenticate(slot->piv_state, NULL)) != YKPIV_OK) {
    DBG("ykpiv_authenticate failed %s", ykpiv_strerror(rc));
    locking.pfnUnlockMutex(slot->mutex);
    rv = rc == YKPIV_AUTHENTICATION_ERROR ? CKR_PIN_INCORRECT : CKR_DEVICE_ERROR;
    goto inittoken_out;
  }

  // Set new mgm key (SO PIN)
  if((rc = ykpiv_set_mgmkey(slot->piv_state, mgm_key)) != YKPIV_OK) {
    DBG("ykpiv_set_mgmkey failed %s", ykpiv_strerror(rc));
    locking.pfnUnlockMutex(slot->mutex);
    rv = CKR_DEVICE_ERROR;
    goto inittoken_out;
  }

  locking.pfnUnlockMutex(slot->mutex);
  rv = CKR_OK;

inittoken_out:
  DOUT;
  return rv;
}

CK_DEFINE_FUNCTION(CK_RV, C_InitPIN)(
  CK_SESSION_HANDLE hSession,
  CK_UTF8CHAR_PTR pPin,
  CK_ULONG ulPinLen
)
{
  DIN;
  DBG("PIN initialization unsupported");
  DOUT;
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_SetPIN)(
  CK_SESSION_HANDLE hSession,
  CK_UTF8CHAR_PTR pOldPin,
  CK_ULONG ulOldLen,
  CK_UTF8CHAR_PTR pNewPin,
  CK_ULONG ulNewLen
)
{
  DIN;
  CK_RV rv;

  if (!pid) {
    DBG("libykpiv is not initialized or already finalized");
    rv = CKR_CRYPTOKI_NOT_INITIALIZED;
    goto setpin_out;
  }
  
  ykcs11_session_t* session = get_session(hSession);

  if (session == NULL || session->slot == NULL) {
    DBG("User called SetPIN on closed session");
    rv = CKR_SESSION_HANDLE_INVALID;
    goto setpin_out;
  }

  if((session->info.flags & CKF_RW_SESSION) == 0) {
    DBG("User called SetPIN on read-only session");
    rv = CKR_SESSION_READ_ONLY;
    goto setpin_out;
  }

  locking.pfnLockMutex(session->slot->mutex);

  CK_USER_TYPE user_type = session->slot->login_state == YKCS11_SO ? CKU_SO : CKU_USER;

  rv = token_change_pin(session->slot->piv_state, user_type, pOldPin, ulOldLen, pNewPin, ulNewLen);
  if (rv != CKR_OK) {
    DBG("Pin change failed %lx", rv);
    locking.pfnUnlockMutex(session->slot->mutex);
    goto setpin_out;
  }

  locking.pfnUnlockMutex(session->slot->mutex);
  rv = CKR_OK;

setpin_out:
  DOUT;
  return rv;
}

CK_DEFINE_FUNCTION(CK_RV, C_OpenSession)(
  CK_SLOT_ID slotID,
  CK_FLAGS flags,
  CK_VOID_PTR pApplication,
  CK_NOTIFY Notify,
  CK_SESSION_HANDLE_PTR phSession
)
{
  DIN; // TODO: pApplication and Notify
  CK_RV rv;

  if (!pid) {
    DBG("libykpiv is not initialized or already finalized");
    rv = CKR_CRYPTOKI_NOT_INITIALIZED;
    goto opensession_out;
  }

  if (phSession == NULL) {
    DBG("Wrong/Missing parameter");
    rv = CKR_ARGUMENTS_BAD;
    goto opensession_out;
  }

  if ((flags & CKF_SERIAL_SESSION) == 0) {
    DBG("Open session called without CKF_SERIAL_SESSION set"); // Required by specs
    rv = CKR_SESSION_PARALLEL_NOT_SUPPORTED;
    goto opensession_out;
  }

  locking.pfnLockMutex(global_mutex);

  if (slotID >= n_slots) {
    DBG("Invalid slot ID %lu", slotID);
    locking.pfnUnlockMutex(global_mutex);
    rv = CKR_SLOT_ID_INVALID;
    goto opensession_out;
  }

  if(!(slots[slotID].slot_info.flags & CKF_TOKEN_PRESENT)) {
    DBG("A token is not present in slot %lu", slotID);
    locking.pfnUnlockMutex(global_mutex);
    rv = CKR_TOKEN_NOT_PRESENT;
    goto opensession_out;
  }

  ykcs11_session_t* session = get_free_session();
  if (session == NULL) {
    DBG("The maximum number of open session have already been reached");
    locking.pfnUnlockMutex(global_mutex);
    rv = CKR_SESSION_COUNT;
    goto opensession_out;
  }

  session->info.slotID = slotID;
  session->info.flags = flags;
  session->slot = slots + slotID;

  locking.pfnUnlockMutex(global_mutex);
  locking.pfnLockMutex(session->slot->mutex);

  if(session->slot->n_objects == 0) {
    const piv_obj_id_t *obj_ids;
    CK_ULONG num_ids;
    get_token_object_ids(&obj_ids, &num_ids);
    for(CK_ULONG i = 0; i < num_ids; i++) {
      ykpiv_rc rc = YKPIV_KEY_ERROR;
      CK_BYTE sub_id = get_sub_id(obj_ids[i]);
      piv_obj_id_t cert_id = find_cert_object(sub_id);
      piv_obj_id_t pubk_id = find_pubk_object(sub_id);
      piv_obj_id_t pvtk_id = find_pvtk_object(sub_id);
      piv_obj_id_t atst_id = find_atst_object(sub_id);
      CK_BYTE data[YKPIV_OBJ_MAX_SIZE] = {0};  // Max cert value for ykpiv
      size_t len;
      if(pvtk_id != PIV_INVALID_OBJ) {
        CK_ULONG slot = piv_2_ykpiv(pvtk_id);
        len = sizeof(data);
        if((rc = ykpiv_attest(session->slot->piv_state, slot, data, &len)) == YKPIV_OK) {
          DBG("Created attestation for object %u slot %lx", pvtk_id, slot);
          if((rv = do_store_cert(data, len, &session->slot->atst[sub_id])) == CKR_OK) {
            if(atst_id != PIV_INVALID_OBJ)
              add_object(session->slot, atst_id);
            if((rv = do_store_pubk(session->slot->atst[sub_id], &session->slot->pkeys[sub_id])) == CKR_OK) {
              session->slot->local[sub_id] = CK_TRUE;
              add_object(session->slot, pvtk_id);
              add_object(session->slot, pubk_id);
            } else {
              DBG("Failed to store key objects %u and %u in session: %lu", pubk_id, pvtk_id, rv);
            }
          } else {
            DBG("Failed to store attestation certificate object %u in session: %lu", atst_id, rv);
          }
        } else {
          DBG("Failed to create attestation for object %u slot %lx: %s", pvtk_id, slot, ykpiv_strerror(rc));
          len = sizeof(data);
          if((rc = ykpiv_get_metadata(session->slot->piv_state, slot, data, &len)) == YKPIV_OK) {
            DBG("Fetched %lu bytes metadata for object %u slot %lx", len, pvtk_id, slot);
            ykpiv_metadata md = {0};
            if((rc = ykpiv_util_parse_metadata(data, len, &md)) == YKPIV_OK) {
              if((rv = do_create_public_key(md.pubkey, md.pubkey_len, md.algorithm, &session->slot->pkeys[sub_id])) == CKR_OK) {
                session->slot->local[sub_id] = md.origin == YKPIV_METADATA_ORIGIN_GENERATED ? CK_TRUE : CK_FALSE;
                add_object(session->slot, pvtk_id);
                add_object(session->slot, pubk_id);
              } else {
                DBG("Failed to create public key for slot %lx, algorithm %u from metadata: %lu", slot, md.algorithm, rv);
              }
            } else {
              DBG("Failed to parse metadata for object %u slot %lx: %s", pvtk_id, slot, ykpiv_strerror(rc));
            }
          } else {
            DBG("Failed to fetch metadata for object %u slot %lx: %s", pvtk_id, slot, ykpiv_strerror(rc));
          }
        }
      }
      unsigned long ulen = sizeof(data);
      ykpiv_rc rcc = ykpiv_fetch_object(session->slot->piv_state, piv_2_ykpiv(obj_ids[i]), data, &ulen);
      if(rcc != YKPIV_OK) {
        DBG("Failed to fetch object %u slot %lx: %s", obj_ids[i], piv_2_ykpiv(obj_ids[i]), ykpiv_strerror(rcc));
        continue;
      }
      DBG("Fetched %lu bytes for object %u slot %lx", ulen, obj_ids[i], piv_2_ykpiv(obj_ids[i]));
      rv = store_data(session->slot, sub_id, data, ulen);
      if (rv != CKR_OK) {
        DBG("Failed to store data object %u in session: %lu", obj_ids[i], rv);
        continue;
      }
      add_object(session->slot, obj_ids[i]);
      if(cert_id != PIV_INVALID_OBJ) {
        rv = store_cert(session->slot, sub_id, data, ulen, CK_FALSE); // Will only overwrite key if not set from attestation or metadata
        if (rv != CKR_OK) {
          DBG("Failed to store certificate object %u in session: %lu", cert_id, rv);
          continue; // Bail out, can't create key objects without the public key from the cert
        }
        add_object(session->slot, cert_id);
        if(rc != YKPIV_OK) { // Failed to get attestation or metadata, fall back to assuming we have keys for cert objects
          add_object(session->slot, pvtk_id);
          add_object(session->slot, pubk_id);
        }
      }
    }
    sort_objects(session->slot);
  }

  locking.pfnUnlockMutex(session->slot->mutex);

  *phSession = get_session_handle(session);
  rv = CKR_OK;

opensession_out:
  DOUT;
  return rv;
}

CK_DEFINE_FUNCTION(CK_RV, C_CloseSession)(
  CK_SESSION_HANDLE hSession
)
{
  DIN;
  CK_RV rv;

  if (!pid) {
    DBG("libykpiv is not initialized or already finalized");
    rv = CKR_CRYPTOKI_NOT_INITIALIZED;
    goto closesession_out;
  }

  ykcs11_session_t *session = get_session(hSession);

  if (session == NULL || session->slot == NULL) {
    DBG("Trying to close a session, but there is no existing one");
    rv = CKR_SESSION_HANDLE_INVALID;
    goto closesession_out;
  }

  ykcs11_slot_t *slot = session->slot;
  int other_sessions = 0;

  locking.pfnLockMutex(global_mutex);

  cleanup_session(session);

  for(int i = 0; i < YKCS11_MAX_SESSIONS; i++) {
    session = sessions + i;
    if(session->slot == slot) {
      other_sessions++;
    }
  }

  locking.pfnUnlockMutex(global_mutex);

  if(other_sessions == 0) {
    locking.pfnLockMutex(slot->mutex);
    cleanup_slot(slot);
    locking.pfnUnlockMutex(slot->mutex);
  }
  rv = CKR_OK;

closesession_out:
  DOUT;
  return rv;
}

CK_DEFINE_FUNCTION(CK_RV, C_CloseAllSessions)(
  CK_SLOT_ID slotID
)
{
  DIN;
  CK_RV rv;

  if (!pid) {
    DBG("libykpiv is not initialized or already finalized");
    rv = CKR_CRYPTOKI_NOT_INITIALIZED;
    goto closeallsessions_out;
  }

  locking.pfnLockMutex(global_mutex);

  if (slotID >= n_slots) {
    DBG("Invalid slot ID %lu", slotID);
    locking.pfnUnlockMutex(global_mutex);
    rv = CKR_SLOT_ID_INVALID;
    goto closeallsessions_out;
  }

  int cleaned_sessions = 0;

  for(int i = 0; i < YKCS11_MAX_SESSIONS; i++) {
    ykcs11_session_t *session = sessions + i;
    if(session->slot && session->info.slotID == slotID) {
      cleanup_session(session);
      cleaned_sessions++;
    }
  }

  locking.pfnUnlockMutex(global_mutex);

  if(cleaned_sessions > 0) {
    locking.pfnLockMutex(slots[slotID].mutex);
    cleanup_slot(slots + slotID);
    locking.pfnUnlockMutex(slots[slotID].mutex);
  }
  rv = CKR_OK;

closeallsessions_out:
  DOUT;
  return rv;
}

CK_DEFINE_FUNCTION(CK_RV, C_GetSessionInfo)(
  CK_SESSION_HANDLE hSession,
  CK_SESSION_INFO_PTR pInfo
)
{
  DIN;
  CK_RV rv;

  if (!pid) {
    DBG("libykpiv is not initialized or already finalized");
    rv = CKR_CRYPTOKI_NOT_INITIALIZED;
    goto sessioninfo_out;
  }

  if (pInfo == NULL) {
    DBG("Wrong/Missing parameter");
    rv = CKR_ARGUMENTS_BAD;
    goto sessioninfo_out;
  }

  ykcs11_session_t* session = get_session(hSession);

  if (session == NULL || session->slot == NULL) {
    DBG("Session is not open");
    rv = CKR_SESSION_HANDLE_INVALID;
    goto sessioninfo_out;
  }

  memcpy(pInfo, &session->info, sizeof(CK_SESSION_INFO));

  locking.pfnLockMutex(session->slot->mutex);
  
  switch(session->slot->login_state) {
    case YKCS11_PUBLIC:
    default:
      pInfo->state = (session->info.flags & CKF_RW_SESSION) ? CKS_RW_PUBLIC_SESSION : CKS_RO_PUBLIC_SESSION;
      break;
    case YKCS11_USER:
      pInfo->state = (session->info.flags & CKF_RW_SESSION) ? CKS_RW_USER_FUNCTIONS : CKS_RO_USER_FUNCTIONS;
      break;
    case YKCS11_SO:
      pInfo->state = CKS_RW_SO_FUNCTIONS;
      break;
  }

  locking.pfnUnlockMutex(session->slot->mutex);
  rv = CKR_OK;

sessioninfo_out:  
  DOUT;
  return rv;
}

CK_DEFINE_FUNCTION(CK_RV, C_GetOperationState)(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pOperationState,
  CK_ULONG_PTR pulOperationStateLen
)
{
  DIN;
  DBG("TODO!!!");
  DOUT;
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_SetOperationState)(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pOperationState,
  CK_ULONG ulOperationStateLen,
  CK_OBJECT_HANDLE hEncryptionKey,
  CK_OBJECT_HANDLE hAuthenticationKey
)
{
  DIN;
  DBG("TODO!!!");
  DOUT;
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_Login)(
  CK_SESSION_HANDLE hSession,
  CK_USER_TYPE userType,
  CK_UTF8CHAR_PTR pPin,
  CK_ULONG ulPinLen
)
{
  DIN;
  CK_RV rv;

  if (!pid) {
    DBG("libykpiv is not initialized or already finalized");
    rv = CKR_CRYPTOKI_NOT_INITIALIZED;
    goto login_out;
  }

  if (userType != CKU_SO &&
      userType != CKU_USER &&
      userType != CKU_CONTEXT_SPECIFIC) {
    rv = CKR_USER_TYPE_INVALID;
    goto login_out;
  }

  DBG("userType %lu, pinLen %lu", userType, ulPinLen);

  ykcs11_session_t* session = get_session(hSession);

  if (session == NULL || session->slot == NULL) {
    DBG("Session is not open");
    rv = CKR_SESSION_HANDLE_INVALID;
    goto login_out;
  }

  switch (userType) {
  case CKU_CONTEXT_SPECIFIC:
    if (session->op_info.type != YKCS11_SIGN && session->op_info.type != YKCS11_DECRYPT) {
      DBG("No sign or decrypt operation in progress. Context specific user is forbidden.");
      rv = CKR_USER_TYPE_INVALID;
      goto login_out;
    }
    // Fall through
  case CKU_USER:
    locking.pfnLockMutex(session->slot->mutex);

    // We allow multiple logins for CKU_CONTEXT_SPECIFIC (we allow it regardless of CKA_ALWAYS_AUTHENTICATE because it's based on hardcoded tables and might be wrong)
    if (session->slot->login_state == YKCS11_USER && userType == CKU_USER) {
      DBG("Tried to log-in USER to a USER session");
      locking.pfnUnlockMutex(session->slot->mutex);
      rv = CKR_USER_ALREADY_LOGGED_IN;
      goto login_out;
    }

    // We allow multiple logins for CKU_CONTEXT_SPECIFIC (we allow it regardless of CKA_ALWAYS_AUTHENTICATE because it's based on hardcoded tables and might be wrong)
    if (session->slot->login_state == YKCS11_SO && userType == CKU_USER) {
      DBG("Tried to log-in USER to a SO session");
      locking.pfnUnlockMutex(session->slot->mutex);
      rv = CKR_USER_ANOTHER_ALREADY_LOGGED_IN;
      goto login_out;
    }

    rv = token_login(session->slot->piv_state, CKU_USER, pPin, ulPinLen);
    if (rv != CKR_OK) {
      DBG("Unable to login as regular user");
      locking.pfnUnlockMutex(session->slot->mutex);
      goto login_out;
    }

    // This allows contect-specific login while already logged in as SO, allowing creation of objects AND signing in one session
    if(session->slot->login_state == YKCS11_PUBLIC)
      session->slot->login_state = YKCS11_USER;
    locking.pfnUnlockMutex(session->slot->mutex);
    break;

  case CKU_SO:
    locking.pfnLockMutex(session->slot->mutex);

    if (session->slot->login_state == YKCS11_USER) {
      DBG("Tried to log-in SO to a USER session");
      locking.pfnUnlockMutex(session->slot->mutex);
      rv = CKR_USER_ANOTHER_ALREADY_LOGGED_IN;
      goto login_out;
    }

    if (session->slot->login_state == YKCS11_SO) {
      DBG("Tried to log-in SO to a SO session");
      locking.pfnUnlockMutex(session->slot->mutex);
      rv = CKR_USER_ALREADY_LOGGED_IN;
      goto login_out;
    }

    for(CK_ULONG i = 0; i < YKCS11_MAX_SESSIONS; i++) {
      if (sessions[i].slot == session->slot && !(sessions[i].info.flags & CKF_RW_SESSION)) {
        DBG("Tried to log-in SO with existing RO sessions");
        locking.pfnUnlockMutex(session->slot->mutex);
        rv = CKR_SESSION_READ_ONLY_EXISTS;
        goto login_out;
      }
    }

    rv = token_login(session->slot->piv_state, CKU_SO, pPin, ulPinLen);
    if (rv != CKR_OK) {
      DBG("Unable to login as SO");
      locking.pfnUnlockMutex(session->slot->mutex);
      goto login_out;
    }

    session->slot->login_state = YKCS11_SO;
    locking.pfnUnlockMutex(session->slot->mutex);
    break;

  default:
    rv = CKR_USER_TYPE_INVALID;
    goto login_out;
  }

  DBG("Successfully logged in");
  rv = CKR_OK;

login_out:
  DOUT;
  return rv;
}

CK_DEFINE_FUNCTION(CK_RV, C_Logout)(
  CK_SESSION_HANDLE hSession
)
{
  DIN;
  CK_RV rv;

  if (!pid) {
    DBG("libykpiv is not initialized or already finalized");
    rv = CKR_CRYPTOKI_NOT_INITIALIZED;
    goto logout_out;
  }

  ykcs11_session_t* session = get_session(hSession);

  if (session == NULL || session->slot == NULL) {
    DBG("Session is not open");
    rv = CKR_SESSION_HANDLE_INVALID;
    goto logout_out;
  }

  locking.pfnLockMutex(session->slot->mutex);

  if (session->slot->login_state == YKCS11_PUBLIC) {
    locking.pfnUnlockMutex(session->slot->mutex);
    rv = CKR_USER_NOT_LOGGED_IN;
    goto logout_out;
  }

  session->slot->login_state = YKCS11_PUBLIC;
  locking.pfnUnlockMutex(session->slot->mutex);
  rv = CKR_OK;

logout_out:  
  DOUT;
  return rv;
}

CK_DEFINE_FUNCTION(CK_RV, C_CreateObject)(
  CK_SESSION_HANDLE hSession,
  CK_ATTRIBUTE_PTR pTemplate,
  CK_ULONG ulCount,
  CK_OBJECT_HANDLE_PTR phObject
)
{
  DIN;

  CK_ULONG         i;
  CK_RV            rv;
  CK_OBJECT_CLASS  class;
  CK_BYTE          id;
  CK_BYTE_PTR      value;
  CK_ULONG         value_len;
  CK_BYTE_PTR      p;
  CK_BYTE_PTR      q;
  CK_BYTE_PTR      dp;
  CK_BYTE_PTR      dq;
  CK_BYTE_PTR      qinv;
  CK_ULONG         p_len;
  CK_ULONG         q_len;
  CK_ULONG         dp_len;
  CK_ULONG         dq_len;
  CK_ULONG         qinv_len;
  CK_BYTE_PTR      ec_data;
  CK_ULONG         ec_data_len;
  CK_BBOOL         is_rsa;
  piv_obj_id_t     dobj_id;
  piv_obj_id_t     cert_id;
  piv_obj_id_t     pubk_id;
  piv_obj_id_t     pvtk_id;

  if (!pid) {
    DBG("libykpiv is not initialized or already finalized");
    rv = CKR_CRYPTOKI_NOT_INITIALIZED;
    goto create_out;
  }
  
  if (pTemplate == NULL ||
      phObject == NULL) {
    DBG("Wrong/Missing parameter");
    rv = CKR_ARGUMENTS_BAD;
    goto create_out;
  }

  ykcs11_session_t* session = get_session(hSession);

  if (session == NULL || session->slot == NULL) {
    DBG("Session is not open");
    rv = CKR_SESSION_HANDLE_INVALID;
    goto create_out;
  }

  class = CKO_VENDOR_DEFINED; // Use this as a known value
  for (i = 0; i < ulCount; i++) {
    if (pTemplate[i].type == CKA_CLASS) {
      class = *((CK_ULONG_PTR)pTemplate[i].pValue);
    }
  }

  switch (class) {
  case CKO_CERTIFICATE:
    DBG("Importing certificate");

    rv = check_create_cert(pTemplate, ulCount, &id, &value, &value_len);
    if (rv != CKR_OK) {
      DBG("Certificate template not valid");
      goto create_out;
    }

    DBG("Certificate id is %u", id);

    dobj_id = find_data_object(id);
    cert_id = find_cert_object(id);
    pubk_id = find_pubk_object(id);
    pvtk_id = find_pvtk_object(id);

    locking.pfnLockMutex(session->slot->mutex);

    if (session->slot->login_state != YKCS11_SO) {
      DBG("Authentication as SO required to import objects");
      locking.pfnUnlockMutex(session->slot->mutex);
      rv = CKR_USER_TYPE_INVALID;
      goto create_out;
    }

    rv = token_import_cert(session->slot->piv_state, piv_2_ykpiv(cert_id), value, value_len);
    if (rv != CKR_OK) {
      DBG("Unable to import certificate");
      locking.pfnUnlockMutex(session->slot->mutex);
      goto create_out;
    }

    rv = store_data(session->slot, id, value, value_len);
    if (rv != CKR_OK) {
      DBG("Unable to store data in session");
      locking.pfnUnlockMutex(session->slot->mutex);
      goto create_out;
    }

    rv = store_cert(session->slot, id, value, value_len, CK_TRUE);
    if (rv != CKR_OK) {
      DBG("Unable to store certificate in session");
      locking.pfnUnlockMutex(session->slot->mutex);
      goto create_out;
    }

    session->slot->local[id] = CK_FALSE;

    // Add objects that were not already present

    add_object(session->slot, dobj_id);
    add_object(session->slot, cert_id);
    add_object(session->slot, pvtk_id);
    add_object(session->slot, pubk_id);

    // No attestation can be created for imported objects

    sort_objects(session->slot);

    locking.pfnUnlockMutex(session->slot->mutex);

    *phObject = (CK_OBJECT_HANDLE)cert_id;
    break;

  case CKO_PRIVATE_KEY:
    DBG("Importing private key");

    // Try to parse the key as EC
    is_rsa = CK_FALSE;
    rv = check_create_ec_key(pTemplate, ulCount, &id, &ec_data, &ec_data_len);
    if (rv != CKR_OK) {
      // Try to parse the key as RSA
      is_rsa = CK_TRUE;
      rv = check_create_rsa_key(pTemplate, ulCount, &id,
                                &p, &p_len,
                                &q, &q_len,
                                &dp, &dp_len,
                                &dq, &dq_len,
                                &qinv, &qinv_len);
      if (rv != CKR_OK) {
        DBG("Private key template not valid");
        goto create_out;
      }
    }

    DBG("Key id is %u", id);

    pvtk_id = find_pvtk_object(id);

    locking.pfnLockMutex(session->slot->mutex);

    if (session->slot->login_state != YKCS11_SO) {
      DBG("Authentication as SO required to import objects");
      locking.pfnUnlockMutex(session->slot->mutex);
      rv = CKR_USER_TYPE_INVALID;
      goto create_out;
    }

    if (is_rsa == CK_TRUE) {
      DBG("Key is RSA");
      rv = token_import_private_key(session->slot->piv_state, piv_2_ykpiv(pvtk_id),
                                          p, p_len,
                                          q, q_len,
                                          dp, dp_len,
                                          dq, dq_len,
                                          qinv, qinv_len,
                                          NULL, 0);
      if (rv != CKR_OK) {
        DBG("Unable to import RSA private key");
        locking.pfnUnlockMutex(session->slot->mutex);
        goto create_out;
      }
    }
    else {
      DBG("Key is ECDSA");
      rv = token_import_private_key(session->slot->piv_state, piv_2_ykpiv(pvtk_id),
                                          NULL, 0,
                                          NULL, 0,
                                          NULL, 0,
                                          NULL, 0,
                                          NULL, 0,
                                          ec_data, ec_data_len);
      if (rv != CKR_OK) {
        DBG("Unable to import ECDSA private key");
        locking.pfnUnlockMutex(session->slot->mutex);
        goto create_out;
      }
    }

    session->slot->local[id] = CK_FALSE;

    add_object(session->slot, pvtk_id);

    // No attestation can be created for imported objects

    sort_objects(session->slot);

    locking.pfnUnlockMutex(session->slot->mutex);
    *phObject = (CK_OBJECT_HANDLE)pvtk_id;
    break;

  default:
    DBG("Unknown object type");
    rv = CKR_ATTRIBUTE_VALUE_INVALID;
    goto create_out;
  }
  
  rv = CKR_OK;

create_out:
  DOUT;
  return rv;
}

CK_DEFINE_FUNCTION(CK_RV, C_CopyObject)(
  CK_SESSION_HANDLE hSession,
  CK_OBJECT_HANDLE hObject,
  CK_ATTRIBUTE_PTR pTemplate,
  CK_ULONG ulCount,
  CK_OBJECT_HANDLE_PTR phNewObject
)
{
  DIN;
  DBG("TODO!!!");
  DOUT;
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_DestroyObject)(
  CK_SESSION_HANDLE hSession,
  CK_OBJECT_HANDLE hObject
)
{
  DIN;
  CK_RV rv;

  if (!pid) {
    DBG("libykpiv is not initialized or already finalized");
    rv = CKR_CRYPTOKI_NOT_INITIALIZED;
    goto destroy_out;
  }

  ykcs11_session_t* session = get_session(hSession);

  if (session == NULL || session->slot == NULL) {
    DBG("Session is not open");
    rv = CKR_SESSION_HANDLE_INVALID;
    goto destroy_out;
  }

  // Silently ignore valid but not-present handles for compatibility with applications
  CK_BYTE id = get_sub_id(hObject);
  if(id == 0 && hObject != PIV_SECRET_OBJ) {
    DBG("Object handle is invalid");
    rv = CKR_OBJECT_HANDLE_INVALID;
    goto destroy_out;
  }

  locking.pfnLockMutex(session->slot->mutex);

  if(id) {
    // SO must be logged in
    if (session->slot->login_state != YKCS11_SO) {
      DBG("Authentication as SO required to delete objects");
      locking.pfnUnlockMutex(session->slot->mutex);
      rv = CKR_USER_TYPE_INVALID;
      goto destroy_out;
    }

    DBG("Deleting object %lx from token", piv_2_ykpiv(find_data_object(id)));
 
    rv = token_delete_cert(session->slot->piv_state, piv_2_ykpiv(find_data_object(id)));
    if (rv != CKR_OK) {
      DBG("Unable to delete object %lx from token", piv_2_ykpiv(find_data_object(id)));
      locking.pfnUnlockMutex(session->slot->mutex);
      goto destroy_out;
    }
  }

  // Remove the related objects from the session

  DBG("%lu slot objects before destroying object %lu", session->slot->n_objects, hObject);

  CK_ULONG j = 0;
  for (CK_ULONG i = 0; i < session->slot->n_objects; i++) {
    if(get_sub_id(session->slot->objects[i]) != id)
      session->slot->objects[j++] = session->slot->objects[i];
  }
  session->slot->n_objects = j;

  DBG("%lu slot objects after destroying object %lu", session->slot->n_objects, hObject);

  rv = delete_data(session->slot, id);
  if (rv != CKR_OK) {
    DBG("Unable to delete data from slot");
    locking.pfnUnlockMutex(session->slot->mutex);
    goto destroy_out;
  }

  rv = delete_cert(session->slot, id);
  if (rv != CKR_OK) {
    DBG("Unable to delete certificate from slot");
    locking.pfnUnlockMutex(session->slot->mutex);
    goto destroy_out;
  }

  locking.pfnUnlockMutex(session->slot->mutex);
  rv = CKR_OK;

destroy_out:
  DOUT;
  return rv;
}

CK_DEFINE_FUNCTION(CK_RV, C_GetObjectSize)(
  CK_SESSION_HANDLE hSession,
  CK_OBJECT_HANDLE hObject,
  CK_ULONG_PTR pulSize
)
{
  DIN;
  CK_RV rv;

  if (!pid) {
    DBG("libykpiv is not initialized or already finalized");
    rv = CKR_CRYPTOKI_NOT_INITIALIZED;
    goto getobj_out;
  }

  if (pulSize == NULL) {
    rv = CKR_ARGUMENTS_BAD;
    goto getobj_out;
  }

  ykcs11_session_t* session = get_session(hSession);

  if (session == NULL || session->slot == NULL) {
    DBG("Session is not open");
    rv = CKR_SESSION_HANDLE_INVALID;
    goto getobj_out;
  }

  locking.pfnLockMutex(session->slot->mutex);

  if (!is_present(session->slot, hObject)) {
    DBG("Object handle is invalid");
    locking.pfnUnlockMutex(session->slot->mutex);
    rv = CKR_OBJECT_HANDLE_INVALID;
    goto getobj_out;
  }

  rv = get_data_len(session->slot, get_sub_id(hObject), pulSize);

  locking.pfnUnlockMutex(session->slot->mutex);

getobj_out:
  DOUT;
  return rv;
}

CK_DEFINE_FUNCTION(CK_RV, C_GetAttributeValue)(
  CK_SESSION_HANDLE hSession,
  CK_OBJECT_HANDLE hObject,
  CK_ATTRIBUTE_PTR pTemplate,
  CK_ULONG ulCount
)
{
  CK_ULONG i;
  CK_RV rv, rv_final;

  DIN;

  if (!pid) {
    DBG("libykpiv is not initialized or already finalized");
    rv_final = CKR_CRYPTOKI_NOT_INITIALIZED;
    goto getattr_out;
  }

  if (pTemplate == NULL || ulCount == 0) {
    rv_final = CKR_ARGUMENTS_BAD;
    goto getattr_out;
  }

  ykcs11_session_t* session = get_session(hSession);

  if (session == NULL || session->slot == NULL) {
    DBG("Session is not open");
    rv_final = CKR_SESSION_HANDLE_INVALID;
    goto getattr_out;
  }

  locking.pfnLockMutex(session->slot->mutex);

  if (!is_present(session->slot, hObject)) {
    DBG("Object handle is invalid");
    locking.pfnUnlockMutex(session->slot->mutex);
    rv_final = CKR_OBJECT_HANDLE_INVALID;
    goto getattr_out;
  }

  rv_final = CKR_OK;
  for (i = 0; i < ulCount; i++) {

    rv = get_attribute(session->slot, hObject, pTemplate + i);

    // TODO: this function has some complex cases for return value. Make sure to check them.
    if (rv != CKR_OK) {
      DBG("Unable to get attribute 0x%lx of object %lu", (pTemplate + i)->type, hObject);
      rv_final = rv;
    }
  }

  locking.pfnUnlockMutex(session->slot->mutex);

getattr_out:
  DOUT;
  return rv_final;
}

CK_DEFINE_FUNCTION(CK_RV, C_SetAttributeValue)(
  CK_SESSION_HANDLE hSession,
  CK_OBJECT_HANDLE hObject,
  CK_ATTRIBUTE_PTR pTemplate,
  CK_ULONG ulCount
)
{
  DIN;
  DBG("TODO!!!");
  DOUT;
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_FindObjectsInit)(
  CK_SESSION_HANDLE hSession,
  CK_ATTRIBUTE_PTR pTemplate,
  CK_ULONG ulCount
)
{
  DIN;
  CK_RV rv;

  if (!pid) {
    DBG("libykpiv is not initialized or already finalized");
    rv = CKR_CRYPTOKI_NOT_INITIALIZED;
    goto findinit_out;
  }

  ykcs11_session_t* session = get_session(hSession);

  if (session == NULL || session->slot == NULL) {
    DBG("Session is not open");
    rv = CKR_SESSION_HANDLE_INVALID;
    goto findinit_out;
  }

  if (session->find_obj.active)  {
    DBG("Search is already active");
    rv = CKR_OPERATION_ACTIVE;
    goto findinit_out;
  }

  if (ulCount != 0 && pTemplate == NULL) {
    DBG("Bad arguments");
    rv = CKR_ARGUMENTS_BAD;
    goto findinit_out;
  }

  session->find_obj.active = CK_TRUE;
  session->find_obj.n_objects = 0;
  session->find_obj.idx = 0;

  DBG("Initialized search with %lu parameters", ulCount);

  locking.pfnLockMutex(session->slot->mutex);

  // Match parameters
  for (CK_ULONG i = 0; i < session->slot->n_objects; i++) {

    // Strip away private objects if needed
    if (session->slot->login_state == YKCS11_PUBLIC) {
      if (is_private_object(session->slot->objects[i]) == CK_TRUE) {
        DBG("Removing private object %u", session->slot->objects[i]);
        continue;
      }
    }
  
    bool keep = true;
    for (CK_ULONG j = 0; j < ulCount; j++) {
      if (attribute_match(session->slot, session->slot->objects[i], pTemplate + j) == CK_FALSE) {
        DBG("Removing object %u", session->slot->objects[i]);
        keep = false;
        break;
      }
    }

    if(keep) {
      DBG("Keeping object %u", session->slot->objects[i]);
      session->find_obj.objects[session->find_obj.n_objects++] = session->slot->objects[i];
    }
  }

  locking.pfnUnlockMutex(session->slot->mutex);

  DBG("%lu object(s) left after attribute matching", session->find_obj.n_objects);
  rv = CKR_OK;

findinit_out:  
  DOUT;
  return rv;
}

CK_DEFINE_FUNCTION(CK_RV, C_FindObjects)(
  CK_SESSION_HANDLE hSession,
  CK_OBJECT_HANDLE_PTR phObject,
  CK_ULONG ulMaxObjectCount,
  CK_ULONG_PTR pulObjectCount
)
{
  DIN;
  CK_RV rv;

  if (!pid) {
    DBG("libykpiv is not initialized or already finalized");
    rv = CKR_CRYPTOKI_NOT_INITIALIZED;
    goto find_out;
  }

  ykcs11_session_t* session = get_session(hSession);

  if (session == NULL || session->slot == NULL) {
    DBG("Session is not open");
    rv = CKR_SESSION_HANDLE_INVALID;
    goto find_out;
  }

  if (phObject == NULL ||
      ulMaxObjectCount == 0 ||
      pulObjectCount == NULL) {
    rv = CKR_ARGUMENTS_BAD;
    goto find_out;
  }

  if (!session->find_obj.active) {
    rv = CKR_OPERATION_NOT_INITIALIZED;
    goto find_out;
  }

  DBG("Can return %lu object(s), %lu remaining", ulMaxObjectCount, session->find_obj.n_objects - session->find_obj.idx);
  *pulObjectCount = 0;

  // Return the next object, if any
  while(session->find_obj.idx < session->find_obj.n_objects && *pulObjectCount < ulMaxObjectCount) {
    *phObject++ = (CK_OBJECT_HANDLE)session->find_obj.objects[session->find_obj.idx++];
    (*pulObjectCount)++;
  }

  DBG("Returning %lu objects, %lu remaining", *pulObjectCount, session->find_obj.n_objects - session->find_obj.idx);
  rv = CKR_OK;

find_out:
  DOUT;
  return rv;  
}

CK_DEFINE_FUNCTION(CK_RV, C_FindObjectsFinal)(
  CK_SESSION_HANDLE hSession
)
{
  DIN;
  CK_RV rv;

  if (!pid) {
    DBG("libykpiv is not initialized or already finalized");
    rv = CKR_CRYPTOKI_NOT_INITIALIZED;
    goto findfinal_out;
  }

  ykcs11_session_t* session = get_session(hSession);

  if (session == NULL || session->slot == NULL) {
    DBG("Session is not open");
    rv = CKR_SESSION_HANDLE_INVALID;
    goto findfinal_out;
  }

  if (!session->find_obj.active) {
    rv = CKR_OPERATION_NOT_INITIALIZED;
    goto findfinal_out;
  }

  session->find_obj.active = CK_FALSE;
  rv = CKR_OK;

findfinal_out:  
  DOUT;
  return rv;
}

CK_DEFINE_FUNCTION(CK_RV, C_EncryptInit)(
  CK_SESSION_HANDLE hSession,
  CK_MECHANISM_PTR pMechanism,
  CK_OBJECT_HANDLE hKey
)
{
  DIN;
  CK_RV rv;

  if (!pid) {
    DBG("libykpiv is not initialized or already finalized");
    rv = CKR_CRYPTOKI_NOT_INITIALIZED;
    goto encinit_out;
  }

  ykcs11_session_t* session = get_session(hSession);

  if (session == NULL || session->slot == NULL) {
    DBG("Session is not open");
    rv = CKR_SESSION_HANDLE_INVALID;
    goto encinit_out;
  }

  if (session->op_info.type != YKCS11_NOOP) {
    DBG("Other operation in process");
    rv = CKR_OPERATION_ACTIVE;
    goto encinit_out;
  }

  if (pMechanism == NULL) {
    rv = CKR_ARGUMENTS_BAD;
    goto encinit_out;
  }

  if (hKey < PIV_PUBK_OBJ_PIV_AUTH || hKey > PIV_PUBK_OBJ_ATTESTATION) {
    DBG("Key handle %lu is not a public key", hKey);
    rv = CKR_KEY_HANDLE_INVALID;
    goto encinit_out;
  }

  CK_BYTE id = get_sub_id(hKey);

  locking.pfnLockMutex(session->slot->mutex);

  if (!is_present(session->slot, hKey)) {
    DBG("Key handle is invalid");
    locking.pfnUnlockMutex(session->slot->mutex);
    rv = CKR_OBJECT_HANDLE_INVALID;
    goto encinit_out;
  }

  session->op_info.op.encrypt.piv_key = piv_2_ykpiv(find_pvtk_object(id));

  rv = decrypt_mechanism_init(session, session->slot->pkeys[id], pMechanism);
  if(rv != CKR_OK) {
    DBG("Failed to initialize encryption operation");
    locking.pfnUnlockMutex(session->slot->mutex);
    goto encinit_out;
  }

  locking.pfnUnlockMutex(session->slot->mutex);

  session->op_info.buf_len = 0;
  session->op_info.type = YKCS11_ENCRYPT;
  rv = CKR_OK;

encinit_out:  
  DOUT;
  return rv;
}

CK_DEFINE_FUNCTION(CK_RV, C_Encrypt)(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pData,
  CK_ULONG ulDataLen,
  CK_BYTE_PTR pEncryptedData,
  CK_ULONG_PTR pulEncryptedDataLen
)
{
  DIN;
  CK_RV rv;
  
  if (!pid) {
    DBG("libykpiv is not initialized or already finalized");
    DOUT;
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  ykcs11_session_t* session = get_session(hSession);

  if (session == NULL || session->slot == NULL) {
    DBG("Session is not open");
    DOUT;
    return CKR_SESSION_HANDLE_INVALID;
  }

  if (pData == NULL || pulEncryptedDataLen == NULL) {
    DBG("Invalid parameters");
    rv = CKR_ARGUMENTS_BAD;
    goto enc_out;
  }

  if (session->op_info.type != YKCS11_ENCRYPT) {
    DBG("Encryption operation not initialized");
    rv = CKR_OPERATION_NOT_INITIALIZED;
    goto enc_out;
  }

  DBG("Using public key for slot %x for encryption", session->op_info.op.encrypt.piv_key);

  rv = do_rsa_encrypt(session->op_info.op.encrypt.key,
                      session->op_info.op.encrypt.padding,
                      session->op_info.op.encrypt.oaep_md, session->op_info.op.encrypt.mgf1_md,
                      session->op_info.op.encrypt.oaep_label, session->op_info.op.encrypt.oaep_label_len,
                      pData, ulDataLen,
                      pEncryptedData, pulEncryptedDataLen);
  if(rv != CKR_OK) {
    DBG("Encryption operation failed");
    goto enc_out;
  }

  DBG("Got %lu encrypted bytes back", *pulEncryptedDataLen);
  rv = CKR_OK;

enc_out:
  if(pEncryptedData) {
    session->op_info.type = YKCS11_NOOP;
    session->op_info.buf_len = 0;
  }
  DOUT;
  return rv;
}

CK_DEFINE_FUNCTION(CK_RV, C_EncryptUpdate)(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pPart,
  CK_ULONG ulPartLen,
  CK_BYTE_PTR pEncryptedPart,
  CK_ULONG_PTR pulEncryptedPartLen
)
{
  DIN;
  CK_RV rv;
  
  if (!pid) {
    DBG("libykpiv is not initialized or already finalized");
    rv = CKR_CRYPTOKI_NOT_INITIALIZED;
    goto encupdate_out;
  }

  ykcs11_session_t* session = get_session(hSession);

  if (session == NULL || session->slot == NULL) {
    DBG("Session is not open");
    rv = CKR_SESSION_HANDLE_INVALID;
    goto encupdate_out;
  }

  if (pPart == NULL || pulEncryptedPartLen == NULL) {
    DBG("Invalid parameters");
    rv = CKR_ARGUMENTS_BAD;
    goto encupdate_out;
  }

  if (session->op_info.type != YKCS11_ENCRYPT) {
    DBG("Encryption operation not initialized");
    rv = CKR_OPERATION_NOT_INITIALIZED;
    goto encupdate_out;
  }

  if(session->op_info.buf_len + ulPartLen > sizeof(session->op_info.buf)) {
    DBG("Too much data added to operation buffer, max is %lu bytes", sizeof(session->op_info.buf));
    rv = CKR_DATA_LEN_RANGE;
    goto encupdate_out;
  }

  memcpy(session->op_info.buf + session->op_info.buf_len, pPart, ulPartLen);
  session->op_info.buf_len += ulPartLen;

  *pulEncryptedPartLen = 0;
  rv = CKR_OK;

encupdate_out: 
  DOUT;
  return rv;
}

CK_DEFINE_FUNCTION(CK_RV, C_EncryptFinal)(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pLastEncryptedPart,
  CK_ULONG_PTR pulLastEncryptedPartLen
)
{
  DIN;
  CK_RV rv;
  
  if (!pid) {
    DBG("libykpiv is not initialized or already finalized");
    DOUT;
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  ykcs11_session_t* session = get_session(hSession);

  if (session == NULL || session->slot == NULL) {
    DBG("Session is not open");
    DOUT;
    return CKR_SESSION_HANDLE_INVALID;
  }

  if (pulLastEncryptedPartLen == NULL) {
    DBG("Invalid parameters");
    rv = CKR_ARGUMENTS_BAD;  
    goto encfinal_out;
  }

  if (session->op_info.type != YKCS11_ENCRYPT) {
    DBG("Encryption operation not initialized");
    rv = CKR_OPERATION_NOT_INITIALIZED;
    goto encfinal_out;
  }

  DBG("Using slot %x for encryption", session->op_info.op.encrypt.piv_key);

  rv = do_rsa_encrypt(session->op_info.op.encrypt.key,
                      session->op_info.op.encrypt.padding,
                      session->op_info.op.encrypt.oaep_md, session->op_info.op.encrypt.mgf1_md,
                      session->op_info.op.encrypt.oaep_label, session->op_info.op.encrypt.oaep_label_len,
                      session->op_info.buf,
                      session->op_info.buf_len,
                      pLastEncryptedPart,
                      pulLastEncryptedPartLen);
  if(rv != CKR_OK) {
    DBG("Encryption operation failed");
    goto encfinal_out;
  }

  DBG("Got %lu encrypted bytes back", *pulLastEncryptedPartLen);
  rv = CKR_OK;
  
encfinal_out:  
  if(pLastEncryptedPart) {
    session->op_info.type = YKCS11_NOOP;
    session->op_info.buf_len = 0;
  }
  DOUT;
  return rv;
}

CK_DEFINE_FUNCTION(CK_RV, C_DecryptInit)(
  CK_SESSION_HANDLE hSession,
  CK_MECHANISM_PTR pMechanism,
  CK_OBJECT_HANDLE hKey
)
{
  DIN;
  CK_RV rv;
  
  if (!pid) {
    DBG("libykpiv is not initialized or already finalized");
    rv = CKR_CRYPTOKI_NOT_INITIALIZED;
    goto decinit_out;
  }

  ykcs11_session_t* session = get_session(hSession);

  if (session == NULL || session->slot == NULL) {
    DBG("Session is not open");
    rv = CKR_SESSION_CLOSED;
    goto decinit_out;
  }

  if (session->op_info.type != YKCS11_NOOP) {
    DBG("Other operation in process");
    rv = CKR_OPERATION_ACTIVE;
    goto decinit_out;
  }

  if (pMechanism == NULL) {
    rv = CKR_ARGUMENTS_BAD;
    goto decinit_out;
  }

  if (hKey < PIV_PVTK_OBJ_PIV_AUTH || hKey > PIV_PVTK_OBJ_ATTESTATION) {
    DBG("Key handle %lu is not a private key", hKey);
    rv = CKR_KEY_HANDLE_INVALID;
    goto decinit_out;
  }

  CK_BYTE id = get_sub_id(hKey);

  locking.pfnLockMutex(session->slot->mutex);

  if (!is_present(session->slot, hKey)) {
    DBG("Key handle is invalid");
    locking.pfnUnlockMutex(session->slot->mutex);
    rv = CKR_OBJECT_HANDLE_INVALID;
    goto decinit_out;
  }

  // This allows decrypting when logged in as SO and then doing a context-specific login as USER
  if (session->slot->login_state == YKCS11_PUBLIC) {
    DBG("User is not logged in");
    locking.pfnUnlockMutex(session->slot->mutex);
    rv = CKR_USER_NOT_LOGGED_IN;
    goto decinit_out;
  }

  session->op_info.op.encrypt.piv_key = piv_2_ykpiv(hKey);

  rv = decrypt_mechanism_init(session, session->slot->pkeys[id], pMechanism);
  if(rv != CKR_OK) {
    DBG("Failed to initialize decryption operation");
    locking.pfnUnlockMutex(session->slot->mutex);
    goto decinit_out;
  }

  locking.pfnUnlockMutex(session->slot->mutex);
  
  session->op_info.buf_len = 0;
  session->op_info.type = YKCS11_DECRYPT;
  rv = CKR_OK;

decinit_out:
  DOUT;
  return rv;
}

CK_DEFINE_FUNCTION(CK_RV, C_Decrypt)(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pEncryptedData,
  CK_ULONG ulEncryptedDataLen,
  CK_BYTE_PTR pData,
  CK_ULONG_PTR pulDataLen
)
{
  DIN;
  CK_RV rv;

  if (!pid) {
    DBG("libykpiv is not initialized or already finalized");
    DOUT;
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  ykcs11_session_t* session = get_session(hSession);

  if (session == NULL || session->slot == NULL) {
    DBG("Session is not open");
    DOUT;
    return CKR_SESSION_HANDLE_INVALID;
  }

  if (pEncryptedData == NULL || pulDataLen == NULL) {
    DBG("Invalid parameters");
    rv = CKR_ARGUMENTS_BAD;
    goto decrypt_out;
  }

  if (session->op_info.type != YKCS11_DECRYPT) {
    DBG("Decryption operation not initialized");
    rv = CKR_OPERATION_NOT_INITIALIZED;
    goto decrypt_out;
  }

  CK_ULONG key_len = do_get_key_size(session->op_info.op.encrypt.key);
  CK_ULONG datalen = (key_len + 7) / 8; // When RSA_NO_PADDING is used
  if(session->op_info.op.encrypt.padding == RSA_PKCS1_PADDING) {
    datalen -= 11;
  } else if(session->op_info.op.encrypt.padding == RSA_PKCS1_OAEP_PADDING) {
    datalen -= 41;
  }
  DBG("The maximum size of the data will be %lu", datalen);

  if (pData == NULL) {
    // Just return the size of the decrypted data
    *pulDataLen = datalen;
    DBG("The size of the data will be %lu", *pulDataLen);
    DOUT;
    return CKR_OK;
  }

  DBG("Using slot %x to decrypt %lu bytes", session->op_info.op.encrypt.piv_key, ulEncryptedDataLen);

  if(ulEncryptedDataLen > sizeof(session->op_info.buf)) {
    DBG("Too much data added to operation buffer, max is %lu bytes", sizeof(session->op_info.buf));
    rv = CKR_DATA_LEN_RANGE;
    goto decrypt_out;
  }

  session->op_info.buf_len = ulEncryptedDataLen;
  memcpy(session->op_info.buf, pEncryptedData, ulEncryptedDataLen);

  locking.pfnLockMutex(session->slot->mutex);

  // This allows decrypting when logged in as SO and then doing a context-specific login as USER
  if (session->slot->login_state == YKCS11_PUBLIC) {
    DBG("User is not logged in");
    rv = CKR_USER_NOT_LOGGED_IN;
    locking.pfnUnlockMutex(session->slot->mutex);
    goto decrypt_out;
  }

  rv = decrypt_mechanism_final(session, pData, pulDataLen, key_len);

  locking.pfnUnlockMutex(session->slot->mutex);

  DBG("Got %lu bytes back", *pulDataLen);

decrypt_out:
  session->op_info.type = YKCS11_NOOP;
  DOUT;
  return rv;
}

CK_DEFINE_FUNCTION(CK_RV, C_DecryptUpdate)(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pEncryptedPart,
  CK_ULONG ulEncryptedPartLen,
  CK_BYTE_PTR pPart,
  CK_ULONG_PTR pulPartLen
)
{
  DIN;
  CK_RV rv;

  if (!pid) {
    DBG("libykpiv is not initialized or already finalized");
    rv = CKR_CRYPTOKI_NOT_INITIALIZED;
    goto decrypt_out;
  }

  ykcs11_session_t* session = get_session(hSession);

  if (session == NULL || session->slot == NULL) {
    DBG("Session is not open");
    rv = CKR_SESSION_HANDLE_INVALID;
    goto decrypt_out;
  }

  if (pEncryptedPart == NULL || pulPartLen == NULL) {
    DBG("Invalid parameters");
    rv = CKR_ARGUMENTS_BAD;
    goto decrypt_out;
  }

  if (session->op_info.type != YKCS11_DECRYPT) {
    DBG("Decryption operation not initialized");
    rv = CKR_OPERATION_NOT_INITIALIZED;
    goto decrypt_out;
  }

  DBG("Adding %lu bytes to be decrypted", ulEncryptedPartLen);

  if(session->op_info.buf_len + ulEncryptedPartLen > sizeof(session->op_info.buf)) {
    DBG("Too much data added to operation buffer, max is %lu bytes", sizeof(session->op_info.buf));
    rv = CKR_DATA_LEN_RANGE;
    goto decrypt_out;
  }

  memcpy(session->op_info.buf + session->op_info.buf_len, pEncryptedPart, ulEncryptedPartLen);
  session->op_info.buf_len += ulEncryptedPartLen;

  *pulPartLen = 0;
  rv = CKR_OK;

decrypt_out:
  DOUT;
  return rv;
}

CK_DEFINE_FUNCTION(CK_RV, C_DecryptFinal)(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pLastPart,
  CK_ULONG_PTR pulLastPartLen
)
{
  DIN;
  CK_RV rv;

  if (!pid) {
    DBG("libykpiv is not initialized or already finalized");
    DOUT;
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  ykcs11_session_t* session = get_session(hSession);

  if (session == NULL || session->slot == NULL) {
    DBG("Session is not open");
    DOUT;
    return CKR_SESSION_HANDLE_INVALID;
  }

  if (pulLastPartLen == NULL) {
    DBG("Invalid parameters");
    rv = CKR_ARGUMENTS_BAD;
    goto decrypt_out;
  }

  if (session->op_info.type != YKCS11_DECRYPT) {
    DBG("Decryption operation not initialized");
    rv = CKR_OPERATION_NOT_INITIALIZED;
    goto decrypt_out;
  }

  CK_ULONG key_len = do_get_key_size(session->op_info.op.encrypt.key);
  CK_ULONG datalen = (key_len + 7) / 8; // When RSA_NO_PADDING is used
  if(session->op_info.op.encrypt.padding == RSA_PKCS1_PADDING) {
    datalen -= 11;
  } else if(session->op_info.op.encrypt.padding == RSA_PKCS1_OAEP_PADDING) {
    datalen -= 41;
  }
  DBG("The maximum size of the data will be %lu", datalen);

  if (pLastPart == NULL) {
    // Just return the size of the decrypted data
    *pulLastPartLen = datalen;
    DBG("The size of the decrypted data will be %lu", *pulLastPartLen);
    DOUT;
    return CKR_OK;
  }

  DBG("Using slot %x to decrypt %lu bytes", session->op_info.op.encrypt.piv_key, session->op_info.buf_len);

  locking.pfnLockMutex(session->slot->mutex);

    // This allows decrypting when logged in as SO and then doing a context-specific login as USER
  if (session->slot->login_state == YKCS11_PUBLIC) {
    DBG("User is not logged in");
    rv = CKR_USER_NOT_LOGGED_IN;
    locking.pfnUnlockMutex(session->slot->mutex);
    goto decrypt_out;
  }

  rv = decrypt_mechanism_final(session, pLastPart, pulLastPartLen, key_len);

  locking.pfnUnlockMutex(session->slot->mutex);

  DBG("Got %lu bytes back", *pulLastPartLen);

decrypt_out:
  session->op_info.type = YKCS11_NOOP;

  DOUT;
  return rv;
}

CK_DEFINE_FUNCTION(CK_RV, C_DigestInit)(
  CK_SESSION_HANDLE hSession,
  CK_MECHANISM_PTR pMechanism
)
{
  DIN;
  CK_RV rv;

  if (!pid) {
    DBG("libykpiv is not initialized or already finalized");
    rv = CKR_CRYPTOKI_NOT_INITIALIZED;
    goto digest_out;
  }

  ykcs11_session_t* session = get_session(hSession);

  if (session == NULL || session->slot == NULL) {
    DBG("Session is not open");
    rv = CKR_SESSION_HANDLE_INVALID;
    goto digest_out;
  }

  if (session->op_info.type != YKCS11_NOOP) {
    DBG("Other operation in process");
    rv = CKR_OPERATION_ACTIVE;
    goto digest_out;
  }

  if (pMechanism == NULL) {
    DBG("Wrong/Missing parameter");
    rv = CKR_ARGUMENTS_BAD;
    goto digest_out;
  }

  rv = digest_mechanism_init(session, pMechanism);
  if(rv != CKR_OK) {
    DBG("Unable to initialize digest operation");
    goto digest_out;
  }

  session->op_info.type = YKCS11_DIGEST;
  rv = CKR_OK;

digest_out:
  DOUT;
  return rv;
}

CK_DEFINE_FUNCTION(CK_RV, C_Digest)(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pData,
  CK_ULONG ulDataLen,
  CK_BYTE_PTR pDigest,
  CK_ULONG_PTR pulDigestLen
)
{
  DIN;
  CK_RV rv;

  if (!pid) {
    DBG("libykpiv is not initialized or already finalized");
    DOUT;
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  ykcs11_session_t* session = get_session(hSession);

  if (session == NULL || session->slot == NULL) {
    DBG("Session is not open");
    DOUT;
    return CKR_SESSION_HANDLE_INVALID;
  }

  if (session->op_info.type != YKCS11_DIGEST) {
    DBG("Digest operation not in process");
    rv = CKR_OPERATION_ACTIVE;
    goto digest_out;
  }

  if (pulDigestLen == NULL) {
    DBG("Wrong/missing parameter");
    rv = CKR_ARGUMENTS_BAD;
    goto digest_out;
  }

  if (pDigest == NULL) {
    // Just return the size of the digest
    DBG("The size of the digest will be %lu", session->op_info.out_len);
    *pulDigestLen = session->op_info.out_len;
    DOUT;
    return CKR_OK;
  }

  if (*pulDigestLen < session->op_info.out_len) {
    DBG("pulDigestLen too small, data will not fit, expected = %lu, got %lu",
      session->op_info.out_len, *pulDigestLen);
    *pulDigestLen = session->op_info.out_len;
    DOUT;
    return CKR_BUFFER_TOO_SMALL;
  }

  rv = digest_mechanism_update(session, pData, ulDataLen);
  if (rv != CKR_OK) {
    goto digest_out;
  }

  rv = digest_mechanism_final(session, pDigest, pulDigestLen);
  if (rv != CKR_OK) {
    goto digest_out;
  }

  DBG("Got %lu bytes back", *pulDigestLen);
  rv = CKR_OK;

digest_out:
  session->op_info.type = YKCS11_NOOP;
  DOUT;
  return rv;
}

CK_DEFINE_FUNCTION(CK_RV, C_DigestUpdate)(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pPart,
  CK_ULONG ulPartLen
)
{
  DIN;
  CK_RV rv;

  if (!pid) {
    DBG("libykpiv is not initialized or already finalized");
    rv = CKR_CRYPTOKI_NOT_INITIALIZED;
    goto digest_out;
  }

  ykcs11_session_t* session = get_session(hSession);

  if (session == NULL || session->slot == NULL) {
    DBG("Session is not open");
    rv = CKR_SESSION_HANDLE_INVALID;
    goto digest_out;
  }

  if (session->op_info.type != YKCS11_DIGEST) {
    DBG("Digest operation not in process");
    rv = CKR_OPERATION_ACTIVE;
    goto digest_out;
  }

  rv = digest_mechanism_update(session, pPart, ulPartLen);

digest_out:
  DOUT;
  return rv;
}

CK_DEFINE_FUNCTION(CK_RV, C_DigestKey)(
  CK_SESSION_HANDLE hSession,
  CK_OBJECT_HANDLE hKey
)
{
  DIN;
  DBG("TODO!!!");
  DOUT;
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_DigestFinal)(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pDigest,
  CK_ULONG_PTR pulDigestLen
)
{
  DIN;
  CK_RV rv;

  if (!pid) {
    DBG("libykpiv is not initialized or already finalized");
    DOUT;
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  ykcs11_session_t* session = get_session(hSession);

  if (session == NULL || session->slot == NULL) {
    DBG("Session is not open");
    DOUT;
    return CKR_SESSION_HANDLE_INVALID;
  }

  if (session->op_info.type != YKCS11_DIGEST) {
    DBG("Digest operation not in process");
    rv = CKR_OPERATION_ACTIVE;
    goto digest_out;
  }

  if (pulDigestLen == NULL) {
    DBG("Wrong/missing parameter");
    rv = CKR_ARGUMENTS_BAD;
    goto digest_out;
  }

  if (pDigest == NULL) {
    // Just return the size of the digest
    DBG("The size of the digest will be %lu", session->op_info.out_len);
    *pulDigestLen = session->op_info.out_len;
    DOUT;
    return CKR_OK;
  }

  if (*pulDigestLen < session->op_info.out_len) {
    DBG("pulDigestLen too small, data will not fit, expected = %lu, got %lu",
      session->op_info.out_len, *pulDigestLen);
    *pulDigestLen = session->op_info.out_len;
    DOUT;
    return CKR_BUFFER_TOO_SMALL;
  }

  rv = digest_mechanism_final(session, pDigest, pulDigestLen);
  if (rv != CKR_OK) {
    DBG("Unable to finalize digest operation");
  }

digest_out:
  session->op_info.type = YKCS11_NOOP;
  DOUT;
  return rv;
}

CK_DEFINE_FUNCTION(CK_RV, C_SignInit)(
  CK_SESSION_HANDLE hSession,
  CK_MECHANISM_PTR pMechanism,
  CK_OBJECT_HANDLE hKey
)
{
  DIN;
  CK_RV rv;

  if (!pid) {
    DBG("libykpiv is not initialized or already finalized");
    rv = CKR_CRYPTOKI_NOT_INITIALIZED;
    goto signinit_out;
  }

  ykcs11_session_t* session = get_session(hSession);

  if (session == NULL || session->slot == NULL) {
    DBG("Session is not open");
    rv = CKR_SESSION_HANDLE_INVALID;
    goto signinit_out;
  }

  if (session->op_info.type != YKCS11_NOOP) {
    DBG("Other operation in process");
    rv = CKR_OPERATION_ACTIVE;
    goto signinit_out;
  }

  if (pMechanism == NULL) {
    DBG("Mechanism not specified");
    rv = CKR_ARGUMENTS_BAD;
    goto signinit_out;
  }

  if (hKey < PIV_PVTK_OBJ_PIV_AUTH || hKey > PIV_PVTK_OBJ_ATTESTATION) {
    DBG("Key handle %lu is not a private key", hKey);
    rv = CKR_KEY_HANDLE_INVALID;
    goto signinit_out;
  }

  CK_BYTE id = get_sub_id(hKey);

  locking.pfnLockMutex(session->slot->mutex);

  if (!is_present(session->slot, hKey)) {
    DBG("Key handle %lu is invalid", hKey);
    locking.pfnUnlockMutex(session->slot->mutex);
    rv = CKR_OBJECT_HANDLE_INVALID;
    goto signinit_out;
  }

  // This allows signing when logged in as SO and then doing a context-specific login to sign
  if (session->slot->login_state == YKCS11_PUBLIC) {
    DBG("User is not logged in");
    locking.pfnUnlockMutex(session->slot->mutex);
    rv = CKR_USER_NOT_LOGGED_IN;
    goto signinit_out;
  }

  session->op_info.op.sign.piv_key = piv_2_ykpiv(hKey);

  rv = sign_mechanism_init(session, session->slot->pkeys[id], pMechanism);
  if (rv != CKR_OK) {
    DBG("Unable to initialize signing operation");
    sign_mechanism_cleanup(session);
    locking.pfnUnlockMutex(session->slot->mutex);
    goto signinit_out;
  }

  locking.pfnUnlockMutex(session->slot->mutex);

  session->op_info.type = YKCS11_SIGN;
  rv = CKR_OK;

signinit_out:
  DOUT;
  return rv;
}

CK_DEFINE_FUNCTION(CK_RV, C_Sign)(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pData,
  CK_ULONG ulDataLen,
  CK_BYTE_PTR pSignature,
  CK_ULONG_PTR pulSignatureLen
)
{
  DIN;
  CK_RV rv;

  if (!pid) {
    DBG("libykpiv is not initialized or already finalized");
    DOUT;
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  ykcs11_session_t* session = get_session(hSession);

  if (session == NULL || session->slot == NULL) {
    DBG("Session is not open");
    DOUT;
    return CKR_SESSION_HANDLE_INVALID;
  }

  if (session->op_info.type != YKCS11_SIGN) {
    DBG("Signature operation not initialized");
    rv = CKR_OPERATION_NOT_INITIALIZED;
    goto sign_out;
  }

  if (pData == NULL || pulSignatureLen == NULL) {
    DBG("Invalid parameters");
    rv = CKR_ARGUMENTS_BAD;
    goto sign_out;
  }

  if (pSignature == NULL) {
    // Just return the size of the signature
    *pulSignatureLen = session->op_info.out_len;
    DBG("The signature requires %lu bytes", *pulSignatureLen);
    DOUT;
    return CKR_OK;
  }

  if (*pulSignatureLen < session->op_info.out_len) {
    DBG("The signature requires %lu bytes, got %lu", session->op_info.out_len, *pulSignatureLen);
    DOUT;
    return CKR_BUFFER_TOO_SMALL;
  }

  locking.pfnLockMutex(session->slot->mutex);

  // This allows signing when logged in as SO and then doing a context-specific login to sign
  if (session->slot->login_state == YKCS11_PUBLIC) {
    DBG("User is not logged in");
    rv = CKR_USER_NOT_LOGGED_IN;
    locking.pfnUnlockMutex(session->slot->mutex);
    goto sign_out;
  }

  if ((rv = digest_mechanism_update(session, pData, ulDataLen)) != CKR_OK) {
    DBG("digest_mechanism_update failed");
    locking.pfnUnlockMutex(session->slot->mutex);
    goto sign_out;
  }

  if((rv = sign_mechanism_final(session, pSignature, pulSignatureLen)) != CKR_OK) {
    DBG("sign_mechanism_final failed");
    locking.pfnUnlockMutex(session->slot->mutex);
    goto sign_out;
  }

  locking.pfnUnlockMutex(session->slot->mutex);

  DBG("The signature is %lu bytes", *pulSignatureLen);
  rv = CKR_OK;

sign_out:
  session->op_info.type = YKCS11_NOOP;
  sign_mechanism_cleanup(session);
  DOUT;
  return rv;
}

CK_DEFINE_FUNCTION(CK_RV, C_SignUpdate)(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pPart,
  CK_ULONG ulPartLen
)
{
  DIN;
  CK_RV rv;

  if (!pid) {
    DBG("libykpiv is not initialized or already finalized");
    DOUT;
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  ykcs11_session_t* session = get_session(hSession);

  if (session == NULL || session->slot == NULL) {
    DBG("Session is not open");
    DOUT;
    return CKR_SESSION_HANDLE_INVALID;
  }

  if (session->op_info.type != YKCS11_SIGN) {
    DBG("Signature operation not initialized");
    rv = CKR_OPERATION_NOT_INITIALIZED;
    goto sign_out;
  }

  if (pPart == NULL) {
    DBG("Invalid parameters");
    rv = CKR_ARGUMENTS_BAD;
    goto sign_out;
  }

  if ((rv = digest_mechanism_update(session, pPart, ulPartLen)) != CKR_OK) {
    DBG("digest_mechanism_update failed");
    goto sign_out;
  }

  rv = CKR_OK;

sign_out:
  if(rv != CKR_OK) {
    session->op_info.type = YKCS11_NOOP;
    sign_mechanism_cleanup(session);
  }
  DOUT;
  return rv;
}

CK_DEFINE_FUNCTION(CK_RV, C_SignFinal)(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pSignature,
  CK_ULONG_PTR pulSignatureLen
)
{
  DIN;
  CK_RV rv;

  if (!pid) {
    DBG("libykpiv is not initialized or already finalized");
    DOUT;
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  ykcs11_session_t* session = get_session(hSession);

  if (session == NULL || session->slot == NULL) {
    DBG("Session is not open");
    DOUT;
    return CKR_SESSION_HANDLE_INVALID;
  }

  if (session->op_info.type != YKCS11_SIGN) {
    DBG("Signature operation not initialized");
    rv = CKR_OPERATION_NOT_INITIALIZED;
    goto sign_out;
  }

  if (pulSignatureLen == NULL) {
    DBG("Invalid parameters");
    rv = CKR_ARGUMENTS_BAD;
    goto sign_out;
  }

  if (pSignature == NULL) {
    // Just return the size of the signature
    *pulSignatureLen = session->op_info.out_len;
    DBG("The signature requires %lu bytes", *pulSignatureLen);
    DOUT;
    return CKR_OK;
  }

  if (*pulSignatureLen < session->op_info.out_len) {
    DBG("The signature requires %lu bytes, got %lu", session->op_info.out_len, *pulSignatureLen);
    DOUT;
    return CKR_BUFFER_TOO_SMALL;
  }

  locking.pfnLockMutex(session->slot->mutex);

  // This allows signing when logged in as SO and then doing a context-specific login to sign
  if (session->slot->login_state == YKCS11_PUBLIC) {
    DBG("User is not logged in");
    rv = CKR_USER_NOT_LOGGED_IN;
    locking.pfnUnlockMutex(session->slot->mutex);
    goto sign_out;
  }

  if((rv = sign_mechanism_final(session, pSignature, pulSignatureLen)) != CKR_OK) {
    DBG("sign_mechanism_final failed");
    locking.pfnUnlockMutex(session->slot->mutex);
    goto sign_out;
  }

  locking.pfnUnlockMutex(session->slot->mutex);

  DBG("The signature is %lu bytes", *pulSignatureLen);
  rv = CKR_OK;

sign_out:
  session->op_info.type = YKCS11_NOOP;
  sign_mechanism_cleanup(session);
  DOUT;
  return rv;
}

CK_DEFINE_FUNCTION(CK_RV, C_SignRecoverInit)(
  CK_SESSION_HANDLE hSession,
  CK_MECHANISM_PTR pMechanism,
  CK_OBJECT_HANDLE hKey
)
{
  DIN;
  DBG("TODO!!!");
  DOUT;
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_SignRecover)(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pData,
  CK_ULONG ulDataLen,
  CK_BYTE_PTR pSignature,
  CK_ULONG_PTR pulSignatureLen
)
{
  DIN;
  DBG("TODO!!!");
  DOUT;
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_VerifyInit)(
  CK_SESSION_HANDLE hSession,
  CK_MECHANISM_PTR pMechanism,
  CK_OBJECT_HANDLE hKey
)
{
  DIN;
  CK_RV rv;

  if (!pid) {
    DBG("libykpiv is not initialized or already finalized");
    rv = CKR_CRYPTOKI_NOT_INITIALIZED;
    goto verifyinit_out;
  }

  ykcs11_session_t* session = get_session(hSession);

  if (session == NULL || session->slot == NULL) {
    DBG("Session is not open");
    rv = CKR_SESSION_HANDLE_INVALID;
    goto verifyinit_out;
  }

  if (session->op_info.type != YKCS11_NOOP) {
    DBG("Other operation in process");
    rv = CKR_OPERATION_ACTIVE;
    goto verifyinit_out;
  }

  if (hKey < PIV_PUBK_OBJ_PIV_AUTH || hKey > PIV_PUBK_OBJ_ATTESTATION) {
    DBG("Key handle %lu is not a public key", hKey);
    rv = CKR_KEY_HANDLE_INVALID;
    goto verifyinit_out;
  }

  if (pMechanism == NULL) {
    DBG("Mechanism not specified");
    rv = CKR_ARGUMENTS_BAD;
    goto verifyinit_out;
  }

  CK_BYTE id = get_sub_id(hKey);

  locking.pfnLockMutex(session->slot->mutex);

  if (!is_present(session->slot, hKey)) {
    DBG("Key handle %lu is invalid", hKey);
    locking.pfnUnlockMutex(session->slot->mutex);
    rv = CKR_OBJECT_HANDLE_INVALID;
    goto verifyinit_out;
  }
  
  rv = verify_mechanism_init(session, session->slot->pkeys[id], pMechanism);
  if (rv != CKR_OK) {
    DBG("Unable to initialize verification operation");
    verify_mechanism_cleanup(session);
    locking.pfnUnlockMutex(session->slot->mutex);
    goto verifyinit_out;
  }

  locking.pfnUnlockMutex(session->slot->mutex);

  session->op_info.type = YKCS11_VERIFY;
  rv = CKR_OK;

verifyinit_out:
  DOUT;
  return rv;
}

CK_DEFINE_FUNCTION(CK_RV, C_Verify)(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pData,
  CK_ULONG ulDataLen,
  CK_BYTE_PTR pSignature,
  CK_ULONG ulSignatureLen
)
{
  DIN;
  CK_RV rv;

  if (!pid) {
    DBG("libykpiv is not initialized or already finalized");
    DOUT;
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  ykcs11_session_t* session = get_session(hSession);

  if (session == NULL || session->slot == NULL) {
    DBG("Session is not open");
    DOUT;
    return CKR_SESSION_HANDLE_INVALID;
  }

  if (pData == NULL || pSignature == NULL) {
    DBG("Invalid parameters");
    rv = CKR_ARGUMENTS_BAD;
    goto verify_out;
  }

  if (session->op_info.type != YKCS11_VERIFY) {
    DBG("Signature verification operation not initialized");
    rv = CKR_OPERATION_NOT_INITIALIZED;
    goto verify_out;
  }

  rv = digest_mechanism_update(session, pData, ulDataLen);
  if (rv != CKR_OK) {
    DBG("Failed to update verification operation");
    goto verify_out;
  }

  rv = verify_mechanism_final(session, pSignature, ulSignatureLen);
  if (rv != CKR_OK) {
    DBG("Unable to verify signature");
    goto verify_out;
  }

  DBG("Signature successfully verified");
  rv = CKR_OK;

verify_out:
  session->op_info.type = YKCS11_NOOP;
  verify_mechanism_cleanup(session);
  DOUT;
  return rv;
}

CK_DEFINE_FUNCTION(CK_RV, C_VerifyUpdate)(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pPart,
  CK_ULONG ulPartLen
)
{
  DIN;
  CK_RV rv;

  if (!pid) {
    DBG("libykpiv is not initialized or already finalized");
    DOUT;
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  ykcs11_session_t* session = get_session(hSession);

  if (session == NULL || session->slot == NULL) {
    DBG("Session is not open");
    DOUT;
    return CKR_SESSION_HANDLE_INVALID;
  }

  if (pPart == NULL) {
    DBG("Invalid parameters");
    rv = CKR_ARGUMENTS_BAD;
    goto verify_out;
  }

  if (session->op_info.type != YKCS11_VERIFY) {
    DBG("Signature verification operation not initialized");
    rv = CKR_OPERATION_NOT_INITIALIZED;
    goto verify_out;
  }

  if ((rv = digest_mechanism_update(session, pPart, ulPartLen)) != CKR_OK) {
    DBG("Failed to update verification operation");
    goto verify_out;
  }

  rv = CKR_OK;

verify_out:
  if(rv != CKR_OK) {
    session->op_info.type = YKCS11_NOOP;
    verify_mechanism_cleanup(session);
  }
  DOUT;
  return rv;
}

CK_DEFINE_FUNCTION(CK_RV, C_VerifyFinal)(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pSignature,
  CK_ULONG ulSignatureLen
)
{
  DIN;
  CK_RV rv;
  
  if (!pid) {
    DBG("libykpiv is not initialized or already finalized");
    DOUT;
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  ykcs11_session_t* session = get_session(hSession);

  if (session == NULL || session->slot == NULL) {
    DBG("Session is not open");
    DOUT;
    return CKR_SESSION_HANDLE_INVALID;
  }

  if (pSignature == NULL) {
    DBG("Invalid parameters");
    rv = CKR_ARGUMENTS_BAD;
    goto verify_out;
  }

  if (session->op_info.type != YKCS11_VERIFY) {
    DBG("Signature verification operation not initialized");
    rv = CKR_OPERATION_NOT_INITIALIZED;
    goto verify_out;
  }

  rv = verify_mechanism_final(session, pSignature, ulSignatureLen);
  if (rv != CKR_OK) {
    DBG("Unable to verify signature");
    goto verify_out;
  }

  DBG("Signature successfully verified");
  rv = CKR_OK;

verify_out:
  session->op_info.type = YKCS11_NOOP;
  verify_mechanism_cleanup(session);
  DOUT;
  return rv;
}

CK_DEFINE_FUNCTION(CK_RV, C_VerifyRecoverInit)(
  CK_SESSION_HANDLE hSession,
  CK_MECHANISM_PTR pMechanism,
  CK_OBJECT_HANDLE hKey
)
{
  DIN;
  DBG("TODO!!!");
  DOUT;
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_VerifyRecover)(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pSignature,
  CK_ULONG ulSignatureLen,
  CK_BYTE_PTR pData,
  CK_ULONG_PTR pulDataLen
)
{
  DIN;
  DBG("TODO!!!");
  DOUT;
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_DigestEncryptUpdate)(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pPart,
  CK_ULONG ulPartLen,
  CK_BYTE_PTR pEncryptedPart,
  CK_ULONG_PTR pulEncryptedPartLen
)
{
  DIN;
  DBG("TODO!!!");
  DOUT;
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_DecryptDigestUpdate)(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pEncryptedPart,
  CK_ULONG ulEncryptedPartLen,
  CK_BYTE_PTR pPart,
  CK_ULONG_PTR pulPartLen
)
{
  DIN;
  DBG("TODO!!!");
  DOUT;
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_SignEncryptUpdate)(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pPart,
  CK_ULONG ulPartLen,
  CK_BYTE_PTR pEncryptedPart,
  CK_ULONG_PTR pulEncryptedPartLen
)
{
  DIN;
  DBG("TODO!!!");
  DOUT;
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_DecryptVerifyUpdate)(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pEncryptedPart,
  CK_ULONG ulEncryptedPartLen,
  CK_BYTE_PTR pPart,
  CK_ULONG_PTR pulPartLen
)
{
  DIN;
  DBG("TODO!!!");
  DOUT;
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_GenerateKey)(
  CK_SESSION_HANDLE hSession,
  CK_MECHANISM_PTR pMechanism,
  CK_ATTRIBUTE_PTR pTemplate,
  CK_ULONG ulCount,
  CK_OBJECT_HANDLE_PTR phKey
)
{
  DIN;
  DBG("TODO!!!");
  DOUT;
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_GenerateKeyPair)(
  CK_SESSION_HANDLE hSession,
  CK_MECHANISM_PTR pMechanism,
  CK_ATTRIBUTE_PTR pPublicKeyTemplate,
  CK_ULONG ulPublicKeyAttributeCount,
  CK_ATTRIBUTE_PTR pPrivateKeyTemplate,
  CK_ULONG ulPrivateKeyAttributeCount,
  CK_OBJECT_HANDLE_PTR phPublicKey,
  CK_OBJECT_HANDLE_PTR phPrivateKey
)
{
  DIN;

  CK_RV          rv;
  piv_obj_id_t   dobj_id;
  piv_obj_id_t   cert_id;
  piv_obj_id_t   pvtk_id;
  piv_obj_id_t   pubk_id;
  piv_obj_id_t   atst_id;
  CK_BYTE        cert_data[YKPIV_OBJ_MAX_SIZE] = {0};
  CK_ULONG       cert_len;
  
  if (!pid) {
    DBG("libykpiv is not initialized or already finalized");
    rv = CKR_CRYPTOKI_NOT_INITIALIZED;
    goto genkp_out;
  }

  ykcs11_session_t* session = get_session(hSession);

  if (session == NULL || session->slot == NULL) {
    DBG("Session is not open");
    rv = CKR_SESSION_HANDLE_INVALID;
    goto genkp_out;
  }

  if (session->op_info.type != YKCS11_NOOP) {
    DBG("Other operation in process");
    rv = CKR_OPERATION_ACTIVE;
    goto genkp_out;
  }

  if (pMechanism == NULL ||
      pPublicKeyTemplate == NULL ||
      pPrivateKeyTemplate == NULL ||
      phPublicKey == NULL ||
      phPrivateKey == NULL) {
    DBG("Wrong/Missing parameter");
    rv = CKR_ARGUMENTS_BAD;
    goto genkp_out;
  }

  DBG("Trying to generate a key pair with mechanism %lx", pMechanism->mechanism);

  DBG("Found %lu attributes for the public key and %lu attributes for the private key", ulPublicKeyAttributeCount, ulPrivateKeyAttributeCount);

  // Check if mechanism is supported
  if ((rv = check_generation_mechanism(pMechanism)) != CKR_OK) {
    DBG("Mechanism %lu is not supported either by the token or the module", pMechanism->mechanism);
    goto genkp_out;
  }

  gen_info_t gen = {0};

  // Check the template for the public key
  if ((rv = check_pubkey_template(&gen, pMechanism, pPublicKeyTemplate, ulPublicKeyAttributeCount)) != CKR_OK) {
    DBG("Invalid public key template");
    goto genkp_out;
  }

  // Check the template for the private key
  if ((rv = check_pvtkey_template(&gen, pMechanism, pPrivateKeyTemplate, ulPrivateKeyAttributeCount)) != CKR_OK) {
    DBG("Invalid private key template");
    goto genkp_out;
  }

  if (gen.algorithm == 0) {
    DBG("Key type or length not specified");
    rv = CKR_TEMPLATE_INCOMPLETE;
    goto genkp_out;
  }

  if (gen.key_id == 0) {
    DBG("Key id not specified");
    rv = CKR_TEMPLATE_INCOMPLETE;
    goto genkp_out;
  }

  dobj_id = find_data_object(gen.key_id);
  cert_id = find_cert_object(gen.key_id);
  pubk_id = find_pubk_object(gen.key_id);
  pvtk_id = find_pvtk_object(gen.key_id);
  atst_id = find_atst_object(gen.key_id);

  CK_ULONG slot = piv_2_ykpiv(pvtk_id);

  DBG("Generating key with algorithm %u in object %u and %u in slot %lx", gen.algorithm, pvtk_id, pubk_id, slot);

  locking.pfnLockMutex(session->slot->mutex);

  if (session->slot->login_state != YKCS11_SO) {
    DBG("Authentication as SO required to generate keys");
    locking.pfnUnlockMutex(session->slot->mutex);
    rv = CKR_USER_TYPE_INVALID;
    goto genkp_out;
  }

  cert_len = sizeof(cert_data);
  if ((rv = token_generate_key(session->slot->piv_state, gen.algorithm, slot, cert_data, &cert_len)) != CKR_OK) {
    DBG("Unable to generate key pair");
    locking.pfnUnlockMutex(session->slot->mutex);
    goto genkp_out;
  }

  rv = store_data(session->slot, gen.key_id, cert_data, cert_len);
  if (rv != CKR_OK) {
    DBG("Unable to store data in session");
    locking.pfnUnlockMutex(session->slot->mutex);
    goto genkp_out;
  }

  rv = store_cert(session->slot, gen.key_id, cert_data, cert_len, CK_TRUE);
  if (rv != CKR_OK) {
    DBG("Unable to store certificate in session");
    locking.pfnUnlockMutex(session->slot->mutex);
    goto genkp_out;
  }

  session->slot->local[gen.key_id] = CK_TRUE;

  // Add objects that were not already present

  add_object(session->slot, dobj_id);
  add_object(session->slot, cert_id);
  add_object(session->slot, pvtk_id);
  add_object(session->slot, pubk_id);

  // Create an attestation, if appropriate and able

  if(atst_id != PIV_INVALID_OBJ) {
    unsigned char data[YKPIV_OBJ_MAX_SIZE] = {0};
    size_t len = sizeof(data);
    ykpiv_rc rc = ykpiv_attest(session->slot->piv_state, slot, data, &len);
    if(rc == YKPIV_OK) {
      DBG("Created attestation for slot %lx", slot);
      if((rv = do_store_cert(data, len, session->slot->atst + gen.key_id)) == CKR_OK) {
        // Add attestation object if not already present
        add_object(session->slot, atst_id);
      } else {
        DBG("Failed to store attestation certificate %u in session: %lu", atst_id, rv);
      }
    } else {
      DBG("Failed to create attestation for slot %lx: %s", slot, ykpiv_strerror(rc));
    }
  }

  sort_objects(session->slot);

  locking.pfnUnlockMutex(session->slot->mutex);

  *phPrivateKey = (CK_OBJECT_HANDLE)pvtk_id;
  *phPublicKey  = (CK_OBJECT_HANDLE)pubk_id;
  rv = CKR_OK;

genkp_out:
  DOUT;
  return rv;
}

CK_DEFINE_FUNCTION(CK_RV, C_WrapKey)(
  CK_SESSION_HANDLE hSession,
  CK_MECHANISM_PTR pMechanism,
  CK_OBJECT_HANDLE hWrappingKey,
  CK_OBJECT_HANDLE hKey,
  CK_BYTE_PTR pWrappedKey,
  CK_ULONG_PTR pulWrappedKeyLen
)
{
  DIN;
  DBG("TODO!!!");
  DOUT;
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_UnwrapKey)(
  CK_SESSION_HANDLE hSession,
  CK_MECHANISM_PTR pMechanism,
  CK_OBJECT_HANDLE hUnwrappingKey,
  CK_BYTE_PTR pWrappedKey,
  CK_ULONG ulWrappedKeyLen,
  CK_ATTRIBUTE_PTR pTemplate,
  CK_ULONG ulAttributeCount,
  CK_OBJECT_HANDLE_PTR phKey
)
{
  DIN;
  DBG("TODO!!!");
  DOUT;
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_DeriveKey)(
  CK_SESSION_HANDLE hSession,
  CK_MECHANISM_PTR pMechanism,
  CK_OBJECT_HANDLE hBaseKey,
  CK_ATTRIBUTE_PTR pTemplate,
  CK_ULONG ulAttributeCount,
  CK_OBJECT_HANDLE_PTR phKey
)
{
  DIN;
  ykcs11_session_t* session = get_session(hSession);

  if (session == NULL || session->slot == NULL) {
    DBG("Session is not open");
    return CKR_SESSION_HANDLE_INVALID;
  }

  if (hBaseKey < PIV_PVTK_OBJ_PIV_AUTH || hBaseKey > PIV_PVTK_OBJ_ATTESTATION) {
    DBG("Key handle %lu is not a private key", hBaseKey);
    return CKR_KEY_HANDLE_INVALID;
  }

  CK_BYTE id = get_sub_id(hBaseKey);
  CK_BYTE algo = do_get_key_algorithm(session->slot->pkeys[id]);
  CK_ULONG size;

  switch(algo) {
    case YKPIV_ALGO_ECCP256:
      size = 65;
      break;
    case YKPIV_ALGO_ECCP384:
      size = 97;
      break;
    default:
      DBG("Key handle %lu is not an ECDH private key", hBaseKey);
      return CKR_KEY_TYPE_INCONSISTENT;
  }

  if (pMechanism->mechanism != CKM_ECDH1_DERIVE) {
    DBG("Mechanism invalid");
    return CKR_MECHANISM_INVALID;
  }

  if (pMechanism->pParameter == NULL || pMechanism->ulParameterLen != sizeof(CK_ECDH1_DERIVE_PARAMS)) {
    DBG("Mechanism parameters invalid");
    return CKR_MECHANISM_PARAM_INVALID;
  }

  CK_ECDH1_DERIVE_PARAMS *params = pMechanism->pParameter;

  if (params->kdf != CKD_NULL || params->ulSharedDataLen != 0 || params->pPublicData == NULL || params->ulPublicDataLen != size) {
    DBG("Key derivation parameters invalid");
    return CKR_MECHANISM_PARAM_INVALID;
  }

  for(CK_ULONG i = 0; i < ulAttributeCount; i++) {
    CK_RV rv = validate_derive_key_attribute(pTemplate[i].type, pTemplate[i].pValue);
    if(rv != CKR_OK) {
      DOUT;
      return rv;
    }
  }

  CK_ULONG slot = piv_2_ykpiv(hBaseKey);
  unsigned char buf[128];
  size_t len = sizeof(buf);

  locking.pfnLockMutex(session->slot->mutex);

  DBG("Deriving ECDH shared secret into object %u using slot %lx", PIV_SECRET_OBJ, slot);
  ykpiv_rc rc = ykpiv_decipher_data(session->slot->piv_state, params->pPublicData, params->ulPublicDataLen, &buf, &len, algo, slot);

  if(rc != YKPIV_OK) {
    DBG("Failed to derive key in slot %lx: %s", slot, ykpiv_strerror(rc));
    locking.pfnUnlockMutex(session->slot->mutex);
    DOUT;
    return CKR_FUNCTION_FAILED;
  }

  *phKey = PIV_SECRET_OBJ;

  store_data(session->slot, 0, buf, len);
  add_object(session->slot, *phKey);
  sort_objects(session->slot);

  locking.pfnUnlockMutex(session->slot->mutex);
  
  DOUT;
  return CKR_OK;
}

/* Random number generation functions */

CK_DEFINE_FUNCTION(CK_RV, C_SeedRandom)(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pSeed,
  CK_ULONG ulSeedLen
)
{
  DIN;
  CK_RV rv;

  if (!pid) {
    DBG("libykpiv is not initialized or already finalized");
    rv = CKR_CRYPTOKI_NOT_INITIALIZED;
    goto seed_out;
  }

  if (pSeed == NULL && ulSeedLen != 0) {
    DBG("Invalid parameter");
    rv = CKR_ARGUMENTS_BAD;
    goto seed_out;
  }

  ykcs11_session_t* session = get_session(hSession);

  if (session == NULL || session->slot == NULL) {
    DBG("Session is not open");
    rv = CKR_SESSION_HANDLE_INVALID;
    goto seed_out;
  }

  if(ulSeedLen != 0) {
    rv = do_rand_seed(pSeed, ulSeedLen);
    if (rv != CKR_OK) {
      goto seed_out;
    }
  }
  rv = CKR_OK;

seed_out:
  DOUT;
  return rv;
}

CK_DEFINE_FUNCTION(CK_RV, C_GenerateRandom)(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pRandomData,
  CK_ULONG ulRandomLen
)
{
  DIN;
  CK_RV rv;

  if (!pid) {
    DBG("libykpiv is not initialized or already finalized");
    rv = CKR_CRYPTOKI_NOT_INITIALIZED;
    goto genrand_out;
  }

  if (pRandomData == NULL && ulRandomLen != 0) {
    DBG("Invalid parameter");
    rv = CKR_ARGUMENTS_BAD;
    goto genrand_out;
  }

  ykcs11_session_t* session = get_session(hSession);

  if (session == NULL || session->slot == NULL) {
    DBG("Session is not open");
    rv = CKR_SESSION_HANDLE_INVALID;
    goto genrand_out;
  }

  // the OpenSC pkcs11 test calls with 0 and expects CKR_OK, do that..
  if (ulRandomLen != 0) {
    rv = do_rand_bytes(pRandomData, ulRandomLen);
    if (rv != CKR_OK) {
      goto genrand_out;
    }
  }
  rv = CKR_OK;

genrand_out:
  DOUT;
  return rv;
}

CK_DEFINE_FUNCTION(CK_RV, C_GetFunctionStatus)(
  CK_SESSION_HANDLE hSession
)
{
  DIN;
  DBG("TODO!!!");
  DOUT;
  return CKR_FUNCTION_NOT_PARALLEL;
}

CK_DEFINE_FUNCTION(CK_RV, C_CancelFunction)(
  CK_SESSION_HANDLE hSession
)
{
  DIN;
  DBG("TODO!!!");
  DOUT;
  return CKR_FUNCTION_NOT_PARALLEL;
}

static const CK_INTERFACE interfaces_list[] = {{(CK_CHAR_PTR) "PKCS 11",
                                                &function_list_3, 0},
                                               {(CK_CHAR_PTR) "PKCS 11",
                                                &function_list, 0}};

/* C_GetInterfaceList returns all the interfaces supported by the module*/
CK_DEFINE_FUNCTION(CK_RV, C_GetInterfaceList)
(CK_INTERFACE_PTR pInterfacesList, /* returned interfaces */
 CK_ULONG_PTR pulCount             /* number of interfaces returned */
) {
  DIN;
  CK_RV rv = CKR_OK;
  if (!pulCount) {
    DBG("C_GetInterfaceList called with pulCount = NULL");
    rv = CKR_ARGUMENTS_BAD;
    goto out;
  }
  if (pInterfacesList) {
    if (*pulCount < sizeof(interfaces_list) / sizeof(interfaces_list[0])) {
      DBG("C_GetInterfaceList called with *pulCount = %lu", *pulCount);
      *pulCount = sizeof(interfaces_list) / sizeof(interfaces_list[0]);
      rv = CKR_BUFFER_TOO_SMALL;
      goto out;
    }
    memcpy(pInterfacesList, interfaces_list, sizeof(interfaces_list));
  }
  *pulCount = sizeof(interfaces_list) / sizeof(interfaces_list[0]);
out:
  DOUT;
  return rv;
}

/* C_GetInterface returns a specific interface from the module. */
CK_DEFINE_FUNCTION(CK_RV, C_GetInterface)
(CK_UTF8CHAR_PTR pInterfaceName,   /* name of the interface */
 CK_VERSION_PTR pVersion,          /* version of the interface */
 CK_INTERFACE_PTR_PTR ppInterface, /* returned interface */
 CK_FLAGS flags                    /* flags controlling the semantics
                                    * of the interface */
) {
  DIN;
  CK_RV rv = CKR_FUNCTION_FAILED;
  if (!ppInterface) {
    DBG("C_GetInterface called with ppInterface = NULL");
    rv = CKR_ARGUMENTS_BAD;
    goto out;
  }
  size_t i;
  for (i = 0; i < sizeof(interfaces_list) / sizeof(interfaces_list[0]); i++) {
    CK_FUNCTION_LIST_PTR function_list =
      (CK_FUNCTION_LIST_PTR) interfaces_list[i].pFunctionList;
    if ((flags & interfaces_list[i].flags) != flags) {
      DBG("C_GetInterface skipped interface %zu (%s %u.%u) because flags "
               "was %lu",
               i, interfaces_list[i].pInterfaceName,
               function_list->version.major, function_list->version.minor,
               flags);
      continue;
    }
    if (pVersion && (pVersion->major != function_list->version.major ||
                     pVersion->minor != function_list->version.minor)) {
      DBG("C_GetInterface skipped interface %zu (%s %u.%u) because "
               "pVersion was %u.%u",
               i, interfaces_list[i].pInterfaceName,
               function_list->version.major, function_list->version.minor,
               pVersion->major, pVersion->minor);
      continue;
    }
    if (pInterfaceName && strcmp((char *) pInterfaceName,
                                 (char *) interfaces_list[i].pInterfaceName)) {
      DBG("C_GetInterface skipped interface %zu (%s %u.%u) because "
               "pInterfacename was %s",
               i, interfaces_list[i].pInterfaceName,
               function_list->version.major, function_list->version.minor,
               pInterfaceName);
      continue;
    }
    DBG("C_GetInterface selected interface %zu (%s %u.%u)", i,
             interfaces_list[i].pInterfaceName, function_list->version.major,
             function_list->version.minor);
    *ppInterface = (CK_INTERFACE_PTR) &interfaces_list[i];
    rv = CKR_OK;
    break;
  }
out:
  DOUT;
  return rv;
}

CK_DEFINE_FUNCTION(CK_RV, C_LoginUser)
(CK_SESSION_HANDLE hSession, /* the session's handle */
 CK_USER_TYPE userType,      /* the user type */
 CK_UTF8CHAR_PTR pPin,       /* the user's PIN */
 CK_ULONG ulPinLen,          /* the length of the PIN */
 CK_UTF8CHAR_PTR pUsername,  /* the user's name */
 CK_ULONG ulUsernameLen      /*the length of the user's name */
) {
  DIN;
  DOUT;
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_SessionCancel)
(CK_SESSION_HANDLE hSession, /* the session's handle */
 CK_FLAGS flags              /* flags control which sessions are cancelled */
) {
  DIN;
  DOUT;
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_MessageEncryptInit)
(CK_SESSION_HANDLE hSession,  /* the session's handle */
 CK_MECHANISM_PTR pMechanism, /* the encryption mechanism */
 CK_OBJECT_HANDLE hKey        /* handle of encryption key */
) {
  DIN;
  DOUT;
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_EncryptMessage)
(CK_SESSION_HANDLE hSession,   /* the session's handle */
 CK_VOID_PTR pParameter,       /* message specific parameter */
 CK_ULONG ulParameterLen,      /* length of message specific parameter */
 CK_BYTE_PTR pAssociatedData,  /* AEAD Associated data */
 CK_ULONG ulAssociatedDataLen, /* AEAD Associated data length */
 CK_BYTE_PTR pPlaintext,       /* plain text  */
 CK_ULONG ulPlaintextLen,      /* plain text length */
 CK_BYTE_PTR pCiphertext,      /* gets cipher text */
 CK_ULONG_PTR pulCiphertextLen /* gets cipher text length */
) {
  DIN;
  DOUT;
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_EncryptMessageBegin)
(CK_SESSION_HANDLE hSession,  /* the session's handle */
 CK_VOID_PTR pParameter,      /* message specific parameter */
 CK_ULONG ulParameterLen,     /* length of message specific parameter */
 CK_BYTE_PTR pAssociatedData, /* AEAD Associated data */
 CK_ULONG ulAssociatedDataLen /* AEAD Associated data length */
) {
  DIN;
  DOUT;
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_EncryptMessageNext)
(CK_SESSION_HANDLE hSession,        /* the session's handle */
 CK_VOID_PTR pParameter,            /* message specific parameter */
 CK_ULONG ulParameterLen,           /* length of message specific parameter */
 CK_BYTE_PTR pPlaintextPart,        /* plain text */
 CK_ULONG ulPlaintextPartLen,       /* plain text length */
 CK_BYTE_PTR pCiphertextPart,       /* gets cipher text */
 CK_ULONG_PTR pulCiphertextPartLen, /* gets cipher text length */
 CK_FLAGS flags                     /* multi mode flag */
) {
  DIN;
  DOUT;
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_MessageEncryptFinal)
(CK_SESSION_HANDLE hSession /* the session's handle */
) {
  DIN;
  DOUT;
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_MessageDecryptInit)
(CK_SESSION_HANDLE hSession,  /* the session's handle */
 CK_MECHANISM_PTR pMechanism, /* the decryption mechanism */
 CK_OBJECT_HANDLE hKey        /* handle of decryption key */
) {
  DIN;
  DOUT;
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_DecryptMessage)
(CK_SESSION_HANDLE hSession,   /* the session's handle */
 CK_VOID_PTR pParameter,       /* message specific parameter */
 CK_ULONG ulParameterLen,      /* length of message specific parameter */
 CK_BYTE_PTR pAssociatedData,  /* AEAD Associated data */
 CK_ULONG ulAssociatedDataLen, /* AEAD Associated data length */
 CK_BYTE_PTR pCiphertext,      /* cipher text */
 CK_ULONG ulCiphertextLen,     /* cipher text length */
 CK_BYTE_PTR pPlaintext,       /* gets plain text */
 CK_ULONG_PTR pulPlaintextLen  /* gets plain text length */
) {
  DIN;
  DOUT;
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_DecryptMessageBegin)
(CK_SESSION_HANDLE hSession,  /* the session's handle */
 CK_VOID_PTR pParameter,      /* message specific parameter */
 CK_ULONG ulParameterLen,     /* length of message specific parameter */
 CK_BYTE_PTR pAssociatedData, /* AEAD Associated data */
 CK_ULONG ulAssociatedDataLen /* AEAD Associated data length */
) {
  DIN;
  DOUT;
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_DecryptMessageNext)
(CK_SESSION_HANDLE hSession,   /* the session's handle */
 CK_VOID_PTR pParameter,       /* message specific parameter */
 CK_ULONG ulParameterLen,      /* length of message specific parameter */
 CK_BYTE_PTR pCiphertext,      /* cipher text */
 CK_ULONG ulCiphertextLen,     /* cipher text length */
 CK_BYTE_PTR pPlaintext,       /* gets plain text */
 CK_ULONG_PTR pulPlaintextLen, /* gets plain text length */
 CK_FLAGS flags                /* multi mode flag */
) {
  DIN;
  DOUT;
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_MessageDecryptFinal)
(CK_SESSION_HANDLE hSession /* the session's handle */
) {
  DIN;
  DOUT;
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_MessageSignInit)
(CK_SESSION_HANDLE hSession,  /* the session's handle */
 CK_MECHANISM_PTR pMechanism, /* the signing mechanism */
 CK_OBJECT_HANDLE hKey        /* handle of signing key */
) {
  DIN;
  DOUT;
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_SignMessage)
(CK_SESSION_HANDLE hSession,  /* the session's handle */
 CK_VOID_PTR pParameter,      /* message specific parameter */
 CK_ULONG ulParameterLen,     /* length of message specific parameter */
 CK_BYTE_PTR pData,           /* data to sign */
 CK_ULONG ulDataLen,          /* data to sign length */
 CK_BYTE_PTR pSignature,      /* gets signature */
 CK_ULONG_PTR pulSignatureLen /* gets signature length */
) {
  DIN;
  DOUT;
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_SignMessageBegin)
(CK_SESSION_HANDLE hSession, /* the session's handle */
 CK_VOID_PTR pParameter,     /* message specific parameter */
 CK_ULONG ulParameterLen     /* length of message specific parameter */
) {
  DIN;
  DOUT;
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_SignMessageNext)
(CK_SESSION_HANDLE hSession,  /* the session's handle */
 CK_VOID_PTR pParameter,      /* message specific parameter */
 CK_ULONG ulParameterLen,     /* length of message specific parameter */
 CK_BYTE_PTR pData,           /* data to sign */
 CK_ULONG ulDataLen,          /* data to sign length */
 CK_BYTE_PTR pSignature,      /* gets signature */
 CK_ULONG_PTR pulSignatureLen /* gets signature length */
) {
  DIN;
  DOUT;
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_MessageSignFinal)
(CK_SESSION_HANDLE hSession /* the session's handle */
) {
  DIN;
  DOUT;
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_MessageVerifyInit)
(CK_SESSION_HANDLE hSession,  /* the session's handle */
 CK_MECHANISM_PTR pMechanism, /* the signing mechanism */
 CK_OBJECT_HANDLE hKey        /* handle of signing key */
) {
  DIN;
  DOUT;
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_VerifyMessage)
(CK_SESSION_HANDLE hSession, /* the session's handle */
 CK_VOID_PTR pParameter,     /* message specific parameter */
 CK_ULONG ulParameterLen,    /* length of message specific parameter */
 CK_BYTE_PTR pData,          /* data to sign */
 CK_ULONG ulDataLen,         /* data to sign length */
 CK_BYTE_PTR pSignature,     /* signature */
 CK_ULONG ulSignatureLen     /* signature length */
) {
  DIN;
  DOUT;
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_VerifyMessageBegin)
(CK_SESSION_HANDLE hSession, /* the session's handle */
 CK_VOID_PTR pParameter,     /* message specific parameter */
 CK_ULONG ulParameterLen     /* length of message specific parameter */
) {
  DIN;
  DOUT;
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_VerifyMessageNext)
(CK_SESSION_HANDLE hSession, /* the session's handle */
 CK_VOID_PTR pParameter,     /* message specific parameter */
 CK_ULONG ulParameterLen,    /* length of message specific parameter */
 CK_BYTE_PTR pData,          /* data to sign */
 CK_ULONG ulDataLen,         /* data to sign length */
 CK_BYTE_PTR pSignature,     /* signature */
 CK_ULONG ulSignatureLen     /* signature length */
) {
  DIN;
  DOUT;
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_MessageVerifyFinal)
(CK_SESSION_HANDLE hSession /* the session's handle */
) {
  DIN;
  DOUT;
  return CKR_FUNCTION_NOT_SUPPORTED;
}

static const CK_FUNCTION_LIST function_list = {
  {CRYPTOKI_LEGACY_VERSION_MAJOR, CRYPTOKI_LEGACY_VERSION_MINOR},
  C_Initialize,
  C_Finalize,
  C_GetInfo,
  C_GetFunctionList,
  C_GetSlotList,
  C_GetSlotInfo,
  C_GetTokenInfo,
  C_GetMechanismList,
  C_GetMechanismInfo,
  C_InitToken,
  C_InitPIN,
  C_SetPIN,
  C_OpenSession,
  C_CloseSession,
  C_CloseAllSessions,
  C_GetSessionInfo,
  C_GetOperationState,
  C_SetOperationState,
  C_Login,
  C_Logout,
  C_CreateObject,
  C_CopyObject,
  C_DestroyObject,
  C_GetObjectSize,
  C_GetAttributeValue,
  C_SetAttributeValue,
  C_FindObjectsInit,
  C_FindObjects,
  C_FindObjectsFinal,
  C_EncryptInit,
  C_Encrypt,
  C_EncryptUpdate,
  C_EncryptFinal,
  C_DecryptInit,
  C_Decrypt,
  C_DecryptUpdate,
  C_DecryptFinal,
  C_DigestInit,
  C_Digest,
  C_DigestUpdate,
  C_DigestKey,
  C_DigestFinal,
  C_SignInit,
  C_Sign,
  C_SignUpdate,
  C_SignFinal,
  C_SignRecoverInit,
  C_SignRecover,
  C_VerifyInit,
  C_Verify,
  C_VerifyUpdate,
  C_VerifyFinal,
  C_VerifyRecoverInit,
  C_VerifyRecover,
  C_DigestEncryptUpdate,
  C_DecryptDigestUpdate,
  C_SignEncryptUpdate,
  C_DecryptVerifyUpdate,
  C_GenerateKey,
  C_GenerateKeyPair,
  C_WrapKey,
  C_UnwrapKey,
  C_DeriveKey,
  C_SeedRandom,
  C_GenerateRandom,
  C_GetFunctionStatus,
  C_CancelFunction,
  C_WaitForSlotEvent,
};

static const CK_FUNCTION_LIST_3_0 function_list_3 = {
  {CRYPTOKI_VERSION_MAJOR, CRYPTOKI_VERSION_MINOR},
  C_Initialize,
  C_Finalize,
  C_GetInfo,
  C_GetFunctionList,
  C_GetSlotList,
  C_GetSlotInfo,
  C_GetTokenInfo,
  C_GetMechanismList,
  C_GetMechanismInfo,
  C_InitToken,
  C_InitPIN,
  C_SetPIN,
  C_OpenSession,
  C_CloseSession,
  C_CloseAllSessions,
  C_GetSessionInfo,
  C_GetOperationState,
  C_SetOperationState,
  C_Login,
  C_Logout,
  C_CreateObject,
  C_CopyObject,
  C_DestroyObject,
  C_GetObjectSize,
  C_GetAttributeValue,
  C_SetAttributeValue,
  C_FindObjectsInit,
  C_FindObjects,
  C_FindObjectsFinal,
  C_EncryptInit,
  C_Encrypt,
  C_EncryptUpdate,
  C_EncryptFinal,
  C_DecryptInit,
  C_Decrypt,
  C_DecryptUpdate,
  C_DecryptFinal,
  C_DigestInit,
  C_Digest,
  C_DigestUpdate,
  C_DigestKey,
  C_DigestFinal,
  C_SignInit,
  C_Sign,
  C_SignUpdate,
  C_SignFinal,
  C_SignRecoverInit,
  C_SignRecover,
  C_VerifyInit,
  C_Verify,
  C_VerifyUpdate,
  C_VerifyFinal,
  C_VerifyRecoverInit,
  C_VerifyRecover,
  C_DigestEncryptUpdate,
  C_DecryptDigestUpdate,
  C_SignEncryptUpdate,
  C_DecryptVerifyUpdate,
  C_GenerateKey,
  C_GenerateKeyPair,
  C_WrapKey,
  C_UnwrapKey,
  C_DeriveKey,
  C_SeedRandom,
  C_GenerateRandom,
  C_GetFunctionStatus,
  C_CancelFunction,
  C_WaitForSlotEvent,
  C_GetInterfaceList,
  C_GetInterface,
  C_LoginUser,
  C_SessionCancel,
  C_MessageEncryptInit,
  C_EncryptMessage,
  C_EncryptMessageBegin,
  C_EncryptMessageNext,
  C_MessageEncryptFinal,
  C_MessageDecryptInit,
  C_DecryptMessage,
  C_DecryptMessageBegin,
  C_DecryptMessageNext,
  C_MessageDecryptFinal,
  C_MessageSignInit,
  C_SignMessage,
  C_SignMessageBegin,
  C_SignMessageNext,
  C_MessageSignFinal,
  C_MessageVerifyInit,
  C_VerifyMessage,
  C_VerifyMessageBegin,
  C_VerifyMessageNext,
  C_MessageVerifyFinal,
};
