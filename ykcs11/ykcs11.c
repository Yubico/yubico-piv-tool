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

#include "ykcs11.h"
#include "ykcs11-version.h"
#include <stdlib.h>
#include <ykpiv.h>
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

#define PIV_MIN_PIN_LEN 6
#define PIV_MAX_PIN_LEN 8
#define PIV_MGM_KEY_LEN 48

#define YKCS11_MAX_SLOTS       16
#define YKCS11_MAX_SESSIONS    16

static ykcs11_slot_t slots[YKCS11_MAX_SLOTS];
static CK_ULONG      n_slots = 0;

static ykcs11_session_t sessions[YKCS11_MAX_SESSIONS];

static CK_C_INITIALIZE_ARGS locking;
static void *global_mutex;
static uint64_t pid;

static CK_FUNCTION_LIST function_list;

static CK_SESSION_HANDLE get_session_handle(ykcs11_session_t *session) {
  return session - sessions + 1;
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
  CK_RV rv;

  DIN;

  // Allow C_Initialize only if we are not initialized or initialized by our parent
  if ((rv = check_pid(pid)) != CKR_OK) {
    DBG("Library already initialized");
    return rv;
  }

  locking.pfnCreateMutex = noop_create_mutex;
  locking.pfnDestroyMutex = noop_destroy_mutex;
  locking.pfnLockMutex = noop_mutex_fn;
  locking.pfnUnlockMutex = noop_mutex_fn;

  if(pInitArgs)
  {
    CK_C_INITIALIZE_ARGS_PTR pArgs = (CK_C_INITIALIZE_ARGS_PTR)pInitArgs;
    if(pArgs->pReserved)
      return CKR_ARGUMENTS_BAD;
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
    if(locking.pfnCreateMutex == 0)
      return CKR_CANT_LOCK;
    if(locking.pfnDestroyMutex == 0)
      return CKR_CANT_LOCK;
    if(locking.pfnLockMutex == 0)
      return CKR_CANT_LOCK;
    if(locking.pfnUnlockMutex == 0)
      return CKR_CANT_LOCK;
  }

  // Set up pid to disallow further re-init by this process, and to allow our potential children to re-init
  if ((rv = get_pid(&pid)) != CKR_OK) {
    DBG("Library can't be initialized");
    return rv;
  }

  // Overwrite global mutex even if inherited (global state is per-process)
  if((rv = locking.pfnCreateMutex(&global_mutex)) != CKR_OK) {
    DBG("Unable to create global mutex");
    pid = 0;
    return rv;
  }

  // Re-use inherited per-slot mutex if available (slots are shared with parent)
  for(int i = 0; i < YKCS11_MAX_SLOTS; i++) {
    if(slots[i].mutex == NULL) {
      if((rv = locking.pfnCreateMutex(&slots[i].mutex)) != CKR_OK) {
        DBG("Unable to create mutex for slot %d", i);
        pid = 0;
        return rv;
      }
    }
  }

  DOUT;
  return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_Finalize)(
  CK_VOID_PTR pReserved
)
{
  DIN;

  if (!pid) {
    DBG("libykpiv is not initialized or already finalized");
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  if (pReserved != NULL) {
    DBG("Finalized called with pReserved != NULL");
    return CKR_ARGUMENTS_BAD;
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

  DOUT;
  return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_GetInfo)(
  CK_INFO_PTR pInfo
)
{
  CK_VERSION ver = {YKCS11_VERSION_MAJOR, (YKCS11_VERSION_MINOR * 10) + YKCS11_VERSION_PATCH};

  DIN;

  if (pInfo == NULL) {
    DBG("Wrong/Missing parameter");
    return CKR_ARGUMENTS_BAD;
  }
  
  pInfo->cryptokiVersion = function_list.version;
  pInfo->libraryVersion = ver;
  pInfo->flags = 0;

  memstrcpy(pInfo->manufacturerID, sizeof(pInfo->manufacturerID), YKCS11_MANUFACTURER);
  memstrcpy(pInfo->libraryDescription, sizeof(pInfo->libraryDescription), YKCS11_LIBDESC);

  DOUT;
  return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_GetFunctionList)(
  CK_FUNCTION_LIST_PTR_PTR ppFunctionList
)
{
  DIN;

  if(ppFunctionList == NULL) {
    DBG("GetFunctionList called with ppFunctionList = NULL");
    return CKR_ARGUMENTS_BAD;
  }
  *ppFunctionList = &function_list;

  DOUT;
  return CKR_OK;
}

/* Slot and token management */

CK_DEFINE_FUNCTION(CK_RV, C_GetSlotList)(
  CK_BBOOL tokenPresent,
  CK_SLOT_ID_PTR pSlotList,
  CK_ULONG_PTR pulCount
)
{
  char readers[2048];
  size_t len = sizeof(readers);

  DIN;

  if (!pid) {
    DBG("libykpiv is not initialized or already finalized");
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  if(pulCount == NULL) {
    DBG("GetSlotList called with pulCount = NULL");
    return CKR_ARGUMENTS_BAD;
  }

  ykpiv_state *piv_state;
  if (ykpiv_init(&piv_state, YKCS11_DBG) != YKPIV_OK) {
    DBG("Unable to initialize libykpiv");
    return CKR_FUNCTION_FAILED;
  }

  if (ykpiv_list_readers(piv_state, readers, &len) != YKPIV_OK) {
    DBG("Unable to list readers");
    ykpiv_done(piv_state);
    return CKR_FUNCTION_FAILED;
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
        if(ykpiv_init(&slot->piv_state, YKCS11_DBG) != YKPIV_OK) {
          DBG("Unable to initialize libykpiv");
          locking.pfnUnlockMutex(global_mutex);
          return CKR_FUNCTION_FAILED;
        }
        n_slots++;
      }

      char buf[sizeof(readers) + 1];
      snprintf(buf, sizeof(buf), "@%s", reader);

      // Try to connect if unconnected (both new and existing slots)
      if (!(slot->slot_info.flags & CKF_TOKEN_PRESENT) && ykpiv_connect(slot->piv_state, buf) == YKPIV_OK) {

        DBG("Connected slot %lu to '%s'", slot-slots, reader);

        slot->slot_info.flags |= CKF_TOKEN_PRESENT;
        slot->token_info.flags = CKF_RNG | CKF_LOGIN_REQUIRED | CKF_USER_PIN_INITIALIZED | CKF_TOKEN_INITIALIZED;

        slot->token_info.ulMinPinLen = PIV_MIN_PIN_LEN;
        slot->token_info.ulMaxPinLen = PIV_MGM_KEY_LEN;

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
          return CKR_BUFFER_TOO_SMALL;
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

  DOUT;
  return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_GetSlotInfo)(
  CK_SLOT_ID slotID,
  CK_SLOT_INFO_PTR pInfo
)
{
  DIN;

  if (!pid) {
    DBG("libykpiv is not initialized or already finalized");
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  if (pInfo == NULL) {
    DBG("Wrong/Missing parameter");
    return CKR_ARGUMENTS_BAD;
  }

  locking.pfnLockMutex(global_mutex);

  if (slotID >= n_slots) {
    DBG("Invalid slot ID %lu", slotID);
    locking.pfnUnlockMutex(global_mutex);
    return CKR_SLOT_ID_INVALID;
  }

  memcpy(pInfo, &slots[slotID].slot_info, sizeof(CK_SLOT_INFO));

  locking.pfnUnlockMutex(global_mutex);

  DOUT;
  return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_GetTokenInfo)(
  CK_SLOT_ID slotID,
  CK_TOKEN_INFO_PTR pInfo
)
{
  DIN;

  if (!pid) {
    DBG("libykpiv is not initialized or already finalized");
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  if (pInfo == NULL) {
    DBG("Wrong/Missing parameter");
    return CKR_ARGUMENTS_BAD;
  }

  locking.pfnLockMutex(global_mutex);

  if (slotID >= n_slots) {
    DBG("Invalid slot ID %lu", slotID);
    locking.pfnUnlockMutex(global_mutex);
    return CKR_SLOT_ID_INVALID;
  }

  if(!(slots[slotID].slot_info.flags & CKF_TOKEN_PRESENT)) {
    DBG("A token is not present in slot %lu", slotID);
    locking.pfnUnlockMutex(global_mutex);
    return CKR_TOKEN_NOT_PRESENT;
  }

  memcpy(pInfo, &slots[slotID].token_info, sizeof(CK_TOKEN_INFO));

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

  DOUT;
  return CKR_OK;
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

  if (!pid) {
    DBG("libykpiv is not initialized or already finalized");
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  if (pulCount == NULL) {
    DBG("Wrong/Missing parameter");
    return CKR_ARGUMENTS_BAD;
  }

  locking.pfnLockMutex(global_mutex);

  if (slotID >= n_slots) {
    DBG("Invalid slot ID %lu", slotID);
    locking.pfnUnlockMutex(global_mutex);
    return CKR_SLOT_ID_INVALID;
  }

  if(!(slots[slotID].slot_info.flags & CKF_TOKEN_PRESENT)) {
    DBG("A token is not present in slot %lu", slotID);
    locking.pfnUnlockMutex(global_mutex);
    return CKR_TOKEN_NOT_PRESENT;
  }

  locking.pfnUnlockMutex(global_mutex);

  CK_RV rv;

  if ((rv = get_token_mechanism_list(pMechanismList, pulCount)) != CKR_OK) {
    DBG("Unable to retrieve mechanism list");
    return rv;
  }

  DOUT;
  return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_GetMechanismInfo)(
  CK_SLOT_ID slotID,
  CK_MECHANISM_TYPE type,
  CK_MECHANISM_INFO_PTR pInfo
)
{
  DIN;

  if (!pid) {
    DBG("libykpiv is not initialized or already finalized");
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  if (pInfo == NULL) {
    DBG("Wrong/Missing parameter");
    return CKR_ARGUMENTS_BAD;
  }

  locking.pfnLockMutex(global_mutex);

  if (slotID >= n_slots) {
    DBG("Invalid slot ID %lu", slotID);
    locking.pfnUnlockMutex(global_mutex);
    return CKR_SLOT_ID_INVALID;
  }

  if(!(slots[slotID].slot_info.flags & CKF_TOKEN_PRESENT)) {
    DBG("A token is not present in slot %lu", slotID);
    locking.pfnUnlockMutex(global_mutex);
    return CKR_TOKEN_NOT_PRESENT;
  }

  locking.pfnUnlockMutex(global_mutex);

  CK_RV rv;

  if ((rv = get_token_mechanism_info(type, pInfo)) != CKR_OK) {
    DBG("Unable to retrieve mechanism information");
    return rv;
  }

  DOUT;
  return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_InitToken)(
  CK_SLOT_ID slotID,
  CK_UTF8CHAR_PTR pPin,
  CK_ULONG ulPinLen,
  CK_UTF8CHAR_PTR pLabel
)
{
  DIN;

  if (!pid) {
    DBG("libykpiv is not initialized or already finalized");
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  locking.pfnLockMutex(global_mutex);

  if (slotID >= n_slots) {
    DBG("Invalid slot ID %lu", slotID);
    locking.pfnUnlockMutex(global_mutex);
    return CKR_SLOT_ID_INVALID;
  }

  if(!(slots[slotID].slot_info.flags & CKF_TOKEN_PRESENT)) {
    DBG("A token is not present in slot %lu", slotID);
    locking.pfnUnlockMutex(global_mutex);
    return CKR_TOKEN_NOT_PRESENT;
  }

  for(int i = 0; i < YKCS11_MAX_SESSIONS; i++) {
    ykcs11_session_t *session = sessions + i;
    if(session->slot && session->info.slotID == slotID) {
      locking.pfnUnlockMutex(global_mutex);
      return CKR_SESSION_EXISTS;
    }
  }

  locking.pfnUnlockMutex(global_mutex);

  CK_BYTE mgm_key[24];
  size_t len = sizeof(mgm_key);
  ykpiv_rc rc;

  if(pPin == NULL) {
    DBG("Missing SO PIN");
    return CKR_ARGUMENTS_BAD;
  }

  if((rc = ykpiv_hex_decode((const char*)pPin, ulPinLen, mgm_key, &len)) != YKPIV_OK || len != 24) {
    DBG("ykpiv_hex_decode failed %d", rc);
    return CKR_PIN_INVALID;
  }

  int tries;
  ykcs11_slot_t *slot = slots + slotID;

  locking.pfnLockMutex(slot->mutex);

  // Verify existing mgm key (SO_PIN)
  if((rc = ykpiv_authenticate(slot->piv_state, mgm_key)) != YKPIV_OK) {
    DBG("ykpiv_authenticate failed %d", rc);
    locking.pfnUnlockMutex(slot->mutex);
    return CKR_PIN_INCORRECT;
  }

  // Block PIN
  while((rc = ykpiv_verify(slot->piv_state, "", &tries)) == YKPIV_WRONG_PIN && tries > 0) {
    DBG("ykpiv_verify (%d), %d tries left", rc, tries);
  }

  // Block PUK
  while((rc = ykpiv_unblock_pin(slot->piv_state, "", 0, "", 0, &tries)) == YKPIV_WRONG_PIN && tries > 0) {
    DBG("ykpiv_unblock_pin (%d), %d tries left", rc, tries);
  }

  // Reset PIV (requires PIN and PUK to be blocked)
  if((rc = ykpiv_util_reset(slot->piv_state)) != YKPIV_OK) {
    DBG("ykpiv_util_reset failed %d", rc);
    locking.pfnUnlockMutex(slot->mutex);
    return CKR_FUNCTION_FAILED;
  }

  // Authenticate with default mgm key (SO PIN)
  if((rc = ykpiv_authenticate(slot->piv_state, NULL)) != YKPIV_OK) {
    DBG("ykpiv_authenticate failed %d", rc);
    locking.pfnUnlockMutex(slot->mutex);
    return CKR_FUNCTION_FAILED;
  }

  // Set new mgm key (SO PIN)
  if((rc = ykpiv_set_mgmkey(slot->piv_state, mgm_key)) != YKPIV_OK) {
    DBG("ykpiv_set_mgmkey failed %d", rc);
    locking.pfnUnlockMutex(slot->mutex);
    return CKR_FUNCTION_FAILED;
  }

  locking.pfnUnlockMutex(slot->mutex);

  DOUT;
  return CKR_OK;
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

  if (!pid) {
    DBG("libykpiv is not initialized or already finalized");
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  
  ykcs11_session_t* session = get_session(hSession);

  if (session == NULL || session->slot == NULL) {
    DBG("User called SetPIN on closed session");
    return CKR_SESSION_HANDLE_INVALID;
  }

  locking.pfnLockMutex(session->slot->mutex);

  CK_USER_TYPE user_type = session->slot->login_state == YKCS11_SO ? CKU_SO : CKU_USER;

  CK_RV rv = token_change_pin(session->slot->piv_state, user_type, pOldPin, ulOldLen, pNewPin, ulNewLen);
  if (rv != CKR_OK) {
    DBG("Pin change failed %lx", rv);
    locking.pfnUnlockMutex(session->slot->mutex);
    return rv;
  }

  locking.pfnUnlockMutex(session->slot->mutex);

  DOUT;
  return CKR_OK;
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

  if (!pid) {
    DBG("libykpiv is not initialized or already finalized");
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  if (phSession == NULL) {
    DBG("Wrong/Missing parameter");
    return CKR_ARGUMENTS_BAD;
  }

  if ((flags & CKF_SERIAL_SESSION) == 0) {
    DBG("Open session called without CKF_SERIAL_SESSION set"); // Required by specs
    return CKR_SESSION_PARALLEL_NOT_SUPPORTED;
  }

  locking.pfnLockMutex(global_mutex);

  if (slotID >= n_slots) {
    DBG("Invalid slot ID %lu", slotID);
    locking.pfnUnlockMutex(global_mutex);
    return CKR_SLOT_ID_INVALID;
  }

  if(!(slots[slotID].slot_info.flags & CKF_TOKEN_PRESENT)) {
    DBG("A token is not present in slot %lu", slotID);
    locking.pfnUnlockMutex(global_mutex);
    return CKR_TOKEN_NOT_PRESENT;
  }

  ykcs11_session_t* session = get_free_session();
  if (session == NULL) {
    DBG("The maximum number of open session have already been reached");
    locking.pfnUnlockMutex(global_mutex);
    return CKR_SESSION_COUNT;
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
      CK_RV rv;
      ykpiv_rc rc = YKPIV_KEY_ERROR;
      CK_BYTE sub_id = get_sub_id(obj_ids[i]);
      piv_obj_id_t cert_id = find_cert_object(sub_id);
      piv_obj_id_t pubk_id = find_pubk_object(sub_id);
      piv_obj_id_t pvtk_id = find_pvtk_object(sub_id);
      piv_obj_id_t atst_id = find_atst_object(sub_id);
      CK_ULONG slot = piv_2_ykpiv(pvtk_id);
      CK_BYTE data[YKPIV_OBJ_MAX_SIZE];  // Max cert value for ykpiv
      unsigned long len;
      if(pvtk_id != PIV_INVALID_OBJ) {
        len = sizeof(data);
        if((rc = ykpiv_get_metadata(session->slot->piv_state, slot, data, &len)) == YKPIV_OK) {
          DBG("Read %lu bytes metadata for private key %u (slot %lx)", len, pvtk_id, slot);
          ykpiv_metadata md = {0};
          if((rc = ykpiv_util_parse_metadata(data, len, &md)) == YKPIV_OK) {
            if((rv = do_create_public_key(md.pubkey, md.pubkey_len, md.algorithm, &session->slot->pkeys[sub_id])) == CKR_OK) {
              add_object(session->slot, pubk_id);
              add_object(session->slot, pvtk_id);
              if(atst_id != PIV_INVALID_OBJ && md.origin == YKPIV_METADATA_ORIGIN_GENERATED) { // Attestation key doesn't have an attestation
                len = sizeof(data);
                ykpiv_rc rcc = ykpiv_attest(session->slot->piv_state, slot, data, &len);
                if(rcc  == YKPIV_OK) {
                  DBG("Created attestation for key %u (slot %lx)", pvtk_id, slot);
                  if((rv = do_store_cert(data, len, session->slot->atst + sub_id)) == CKR_OK) {
                    add_object(session->slot, atst_id);
                  } else {
                    DBG("Failed to store certificate object %u in session: %lu", atst_id, rv);
                  }
                } else {
                  DBG("Failed to create attestation for key %u (slot %lx): %s", pvtk_id, slot, ykpiv_strerror(rcc));
                }
              }
            } else {
              DBG("Failed to create public key info for private key %u (slot %lx, algorithm %u) from metadata: %lu", pvtk_id, slot, md.algorithm, rv);
              rc = YKPIV_KEY_ERROR; // Ensure we create the key from the certificate instead
            }
          } else {
            DBG("Failed to parse metadata for private key %u (slot %lx): %s", pvtk_id, slot, ykpiv_strerror(rc));
          }
        }
      }
      len = sizeof(data);
      if(ykpiv_fetch_object(session->slot->piv_state, piv_2_ykpiv(obj_ids[i]), data, &len) == YKPIV_OK) {
        DBG("Read %lu bytes for data object %u (%lx)", len, obj_ids[i], piv_2_ykpiv(obj_ids[i]));
        rv = store_data(session->slot, sub_id, data, len);
        if (rv != CKR_OK) {
          DBG("Failed to store data object %u in session: %lu", obj_ids[i], rv);
          continue;
        }
        add_object(session->slot, obj_ids[i]);
        if(cert_id != PIV_INVALID_OBJ) {
          rv = store_cert(session->slot, sub_id, data, len, CK_FALSE);
          if (rv != CKR_OK) {
            DBG("Failed to store certificate object %u in session: %lu", cert_id, rv);
            continue; // Bail out, can't create key objects without the public key from the cert
          }
          add_object(session->slot, cert_id);
          if(rc != YKPIV_OK) { // Failed to get metadata, fall back to assuming we have keys for cert objects
            add_object(session->slot, pubk_id);
            add_object(session->slot, pvtk_id);
            if(atst_id != PIV_INVALID_OBJ) { // Attestation key doesn't have an attestation
              len = sizeof(data);
              ykpiv_rc rcc = ykpiv_attest(session->slot->piv_state, slot, data, &len);
              if(rcc  == YKPIV_OK) {
                DBG("Created attestation for key %u (slot %lx)", pvtk_id, slot);
                if((rv = do_store_cert(data, len, session->slot->atst + sub_id)) == CKR_OK) {
                  add_object(session->slot, atst_id);
                } else {
                  DBG("Failed to store certificate object %u in session: %lu", atst_id, rv);
                }
              } else {
                DBG("Failed to create attestation for key %u (slot %lx): %s", pvtk_id, slot, ykpiv_strerror(rcc));
              }
            }
          }
        }
      }
    }
    sort_objects(session->slot);
  }

  locking.pfnUnlockMutex(session->slot->mutex);

  *phSession = get_session_handle(session);

  DOUT;
  return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_CloseSession)(
  CK_SESSION_HANDLE hSession
)
{
  DIN;

  if (!pid) {
    DBG("libykpiv is not initialized or already finalized");
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  locking.pfnLockMutex(global_mutex);
  ykcs11_session_t *session = get_session(hSession);

  if (session == NULL || session->slot == NULL) {
    DBG("Trying to close a session, but there is no existing one");
    locking.pfnUnlockMutex(global_mutex);
    return CKR_SESSION_HANDLE_INVALID;
  }

  ykcs11_slot_t *slot = session->slot;
  cleanup_session(session);

  int other_sessions = 0;

  for(int i = 0; i < YKCS11_MAX_SESSIONS; i++) {
    session = sessions + i;
    if(session->slot == slot) {
      other_sessions++;
    }
  }

  locking.pfnUnlockMutex(global_mutex);

  if(!other_sessions) {
    locking.pfnLockMutex(slot->mutex);
    cleanup_slot(slot);
    locking.pfnUnlockMutex(slot->mutex);
  }

  DOUT;
  return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_CloseAllSessions)(
  CK_SLOT_ID slotID
)
{
  DIN;

  if (!pid) {
    DBG("libykpiv is not initialized or already finalized");
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  locking.pfnLockMutex(global_mutex);

  if (slotID >= n_slots) {
    DBG("Invalid slot ID %lu", slotID);
    locking.pfnUnlockMutex(global_mutex);
    return CKR_SLOT_ID_INVALID;
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

  if(cleaned_sessions) {
    locking.pfnLockMutex(slots[slotID].mutex);
    cleanup_slot(slots + slotID);
    locking.pfnUnlockMutex(slots[slotID].mutex);
  }

  DOUT;
  return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_GetSessionInfo)(
  CK_SESSION_HANDLE hSession,
  CK_SESSION_INFO_PTR pInfo
)
{
  DIN;

  if (!pid) {
    DBG("libykpiv is not initialized or already finalized");
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  if (pInfo == NULL) {
    DBG("Wrong/Missing parameter");
    return CKR_ARGUMENTS_BAD;
  }

  ykcs11_session_t* session = get_session(hSession);

  if (session == NULL || session->slot == NULL) {
    DBG("Session is not open");
    return CKR_SESSION_HANDLE_INVALID;
  }

  memcpy(pInfo, &session->info, sizeof(CK_SESSION_INFO));
  
  switch(session->slot->login_state) {
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

  DOUT;
  return CKR_OK;
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
  CK_RV          rv;

  if (!pid) {
    DBG("libykpiv is not initialized or already finalized");
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  if (userType != CKU_SO &&
      userType != CKU_USER &&
      userType != CKU_CONTEXT_SPECIFIC)
    return CKR_USER_TYPE_INVALID;

  DBG("user %lu, pin %s, pinlen %lu", userType, pPin, ulPinLen);

  ykcs11_session_t* session = get_session(hSession);

  if (session == NULL || session->slot == NULL) {
    DBG("Session is not open");
    return CKR_SESSION_HANDLE_INVALID;
  }

  switch (userType) {
  case CKU_CONTEXT_SPECIFIC:
    if (session->op_info.type != YKCS11_SIGN && session->op_info.type != YKCS11_DECRYPT) {
      DBG("No sign or decrypt operation in progress. Context specific user is forbidden.");
      return CKR_USER_TYPE_INVALID;
    }
    // Fall through
  case CKU_USER:
    if (ulPinLen < PIV_MIN_PIN_LEN || ulPinLen > PIV_MAX_PIN_LEN)
      return CKR_ARGUMENTS_BAD;

    locking.pfnLockMutex(session->slot->mutex);

    // We allow multiple logins for CKU_CONTEXT_SPECIFIC (we allow it regardless of CKA_ALWAYS_AUTHENTICATE because it's based on hardcoded tables and might be wrong)
    if (session->slot->login_state == YKCS11_USER && userType == CKU_USER) {
      DBG("Tried to log-in USER to a USER session");
      locking.pfnUnlockMutex(session->slot->mutex);
      return CKR_USER_ALREADY_LOGGED_IN;
    }

    // We allow multiple logins for CKU_CONTEXT_SPECIFIC (we allow it regardless of CKA_ALWAYS_AUTHENTICATE because it's based on hardcoded tables and might be wrong)
    if (session->slot->login_state == YKCS11_SO && userType == CKU_USER) {
      DBG("Tried to log-in USER to a SO session");
      locking.pfnUnlockMutex(session->slot->mutex);
      return CKR_USER_ANOTHER_ALREADY_LOGGED_IN;
    }

    rv = token_login(session->slot->piv_state, CKU_USER, pPin, ulPinLen);
    if (rv != CKR_OK) {
      DBG("Unable to login as regular user");
      locking.pfnUnlockMutex(session->slot->mutex);
      return rv;
    }

    // This allows contect-specific login while already logged in as SO, allowing creation of objects AND signing in one session
    if(session->slot->login_state == YKCS11_PUBLIC)
      session->slot->login_state = YKCS11_USER;
    locking.pfnUnlockMutex(session->slot->mutex);
    break;

  case CKU_SO:
    if (ulPinLen != PIV_MGM_KEY_LEN)
      return CKR_ARGUMENTS_BAD;

    locking.pfnLockMutex(session->slot->mutex);

    if (session->slot->login_state == YKCS11_USER) {
      DBG("Tried to log-in SO to a USER session");
      locking.pfnUnlockMutex(session->slot->mutex);
      return CKR_USER_ANOTHER_ALREADY_LOGGED_IN;
    }

    if (session->slot->login_state == YKCS11_SO) {
      DBG("Tried to log-in SO to a SO session");
      locking.pfnUnlockMutex(session->slot->mutex);
      return CKR_USER_ALREADY_LOGGED_IN;
    }

    for(CK_ULONG i = 0; i < YKCS11_MAX_SESSIONS; i++) {
      if (sessions[i].slot == session->slot && !(sessions[i].info.flags & CKF_RW_SESSION)) {
        DBG("Tried to log-in SO with existing RO sessions");
        locking.pfnUnlockMutex(session->slot->mutex);
        return CKR_SESSION_READ_ONLY_EXISTS;
      }
    }

    rv = token_login(session->slot->piv_state, CKU_SO, pPin, ulPinLen);
    if (rv != CKR_OK) {
      DBG("Unable to login as SO");
      locking.pfnUnlockMutex(session->slot->mutex);
      return rv;
    }

    session->slot->login_state = YKCS11_SO;
    locking.pfnUnlockMutex(session->slot->mutex);
    break;

  default:
    return CKR_USER_TYPE_INVALID;
  }

  DBG("Successfully logged in");

  DOUT;
  return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_Logout)(
  CK_SESSION_HANDLE hSession
)
{
  DIN;

  if (!pid) {
    DBG("libykpiv is not initialized or already finalized");
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  ykcs11_session_t* session = get_session(hSession);

  if (session == NULL || session->slot == NULL) {
    DBG("Session is not open");
    return CKR_SESSION_HANDLE_INVALID;
  }

  locking.pfnLockMutex(session->slot->mutex);

  if (session->slot->login_state == YKCS11_PUBLIC) {
    locking.pfnUnlockMutex(session->slot->mutex);
    return CKR_USER_NOT_LOGGED_IN;
  }

  session->slot->login_state = YKCS11_PUBLIC;
  locking.pfnUnlockMutex(session->slot->mutex);

  DOUT;
  return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_CreateObject)(
  CK_SESSION_HANDLE hSession,
  CK_ATTRIBUTE_PTR pTemplate,
  CK_ULONG ulCount,
  CK_OBJECT_HANDLE_PTR phObject
)
{
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
  piv_obj_id_t     atst_id;
  piv_obj_id_t     *obj_ptr;

  DIN;

  if (!pid) {
    DBG("libykpiv is not initialized or already finalized");
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  
  if (pTemplate == NULL ||
      phObject == NULL) {
    DBG("Wrong/Missing parameter");
    return CKR_ARGUMENTS_BAD;
  }

  ykcs11_session_t* session = get_session(hSession);

  if (session == NULL || session->slot == NULL) {
    DBG("Session is not open");
    return CKR_SESSION_HANDLE_INVALID;
  }

  class = CKO_VENDOR_DEFINED; // Use this as a known value
  for (i = 0; i < ulCount; i++) {
    if (pTemplate[i].type == CKA_CLASS) {
      class = *((CK_ULONG_PTR)pTemplate[i].pValue);

      // Can only import certificates and private keys
      if (class != CKO_CERTIFICATE &&
          class != CKO_PRIVATE_KEY) {
        DBG("Unsupported class %lu", class);
        return CKR_ATTRIBUTE_VALUE_INVALID;
      }
    }
  }

  if (class == CKO_VENDOR_DEFINED) {
    DBG("Object class must be specified");
    return CKR_TEMPLATE_INCOMPLETE;
  }

  switch (class) {
  case CKO_CERTIFICATE:
    DBG("Importing certificate");

    rv = check_create_cert(pTemplate, ulCount, &id, &value, &value_len);
    if (rv != CKR_OK) {
      DBG("Certificate template not valid");
      return rv;
    }

    DBG("Certificate id is %u", id);

    dobj_id = find_data_object(id);
    cert_id = find_cert_object(id);
    pubk_id = find_pubk_object(id);
    pvtk_id = find_pvtk_object(id);
    atst_id = find_atst_object(id);

    locking.pfnLockMutex(session->slot->mutex);

    if (session->slot->login_state != YKCS11_SO) {
      DBG("Authentication as SO required to import objects");
      locking.pfnUnlockMutex(session->slot->mutex);
      return CKR_USER_TYPE_INVALID;
    }

    rv = token_import_cert(session->slot->piv_state, piv_2_ykpiv(cert_id), value);
    if (rv != CKR_OK) {
      DBG("Unable to import certificate");
      locking.pfnUnlockMutex(session->slot->mutex);
      return rv;
    }

    // Add objects that were not already present

    if(!is_present(session->slot, dobj_id))
      add_object(session->slot, dobj_id);
    if(!is_present(session->slot, cert_id))
      add_object(session->slot, cert_id);
    if(!is_present(session->slot, pvtk_id))
      add_object(session->slot, pvtk_id);
    if(!is_present(session->slot, pubk_id))
      add_object(session->slot, pubk_id);
    if(atst_id != PIV_INVALID_OBJ && !is_present(session->slot, atst_id))
      add_object(session->slot, atst_id);

    sort_objects(session->slot);

    rv = store_data(session->slot, id, value, value_len);
    if (rv != CKR_OK) {
      DBG("Unable to store data in session");
      return CKR_FUNCTION_FAILED;
    }

    rv = store_cert(session->slot, id, value, value_len, CK_TRUE);
    if (rv != CKR_OK) {
      DBG("Unable to store certificate in session");
      return CKR_FUNCTION_FAILED;
    }

    locking.pfnUnlockMutex(session->slot->mutex);

    *phObject = cert_id;
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
        return rv;
      }
    }

    DBG("Key id is %u", id);

    pvtk_id = find_pvtk_object(id);

    locking.pfnLockMutex(session->slot->mutex);

    if (session->slot->login_state != YKCS11_SO) {
      DBG("Authentication as SO required to import objects");
      locking.pfnUnlockMutex(session->slot->mutex);
      return CKR_USER_TYPE_INVALID;
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
        return rv;
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
        return rv;
      }
    }

    locking.pfnUnlockMutex(session->slot->mutex);
    *phObject = pvtk_id;
    break;

  default:
    DBG("Unknown object type");
    return CKR_ATTRIBUTE_VALUE_INVALID;
  }

  DOUT;
  return CKR_OK;
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

  if (!pid) {
    DBG("libykpiv is not initialized or already finalized");
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  ykcs11_session_t* session = get_session(hSession);

  if (session == NULL || session->slot == NULL) {
    DBG("Session is not open");
    return CKR_SESSION_HANDLE_INVALID;
  }

  // SO must be logged in
  if (session->slot->login_state != YKCS11_SO) {
    DBG("Authentication as SO required to delete objects");
    return CKR_USER_TYPE_INVALID;
  }

  DBG("Deleting object %lu", hObject);

  // Silently ignore valid but not-present handles for compatibility with applications
  CK_BYTE id = get_sub_id(hObject);
  if(id == 0) {
    DBG("Object handle is invalid");
    return CKR_OBJECT_HANDLE_INVALID;
  }

  locking.pfnLockMutex(session->slot->mutex);

  CK_RV rv = token_delete_cert(session->slot->piv_state, piv_2_ykpiv(find_data_object(id)));
  if (rv != CKR_OK) {
    DBG("Unable to delete object %lx from token", piv_2_ykpiv(find_data_object(id)));
    locking.pfnUnlockMutex(session->slot->mutex);
    return rv;
  }

  // Remove the related objects from the session

  DBG("%lu session objects before destroying object %lu", session->slot->n_objects, hObject);

  CK_ULONG j = 0;
  for (CK_ULONG i = 0; i < session->slot->n_objects; i++) {
    if(get_sub_id(session->slot->objects[i]) != id)
      session->slot->objects[j++] = session->slot->objects[i];
  }
  session->slot->n_objects = j;

  DBG("%lu session objects after destroying object %lu", session->slot->n_objects, hObject);

  rv = delete_data(session->slot, id);
  if (rv != CKR_OK) {
    DBG("Unable to delete data from session");
    locking.pfnUnlockMutex(session->slot->mutex);
    return CKR_FUNCTION_FAILED;
  }

  rv = delete_cert(session->slot, id);
  if (rv != CKR_OK) {
    DBG("Unable to delete certificate from session");
    locking.pfnUnlockMutex(session->slot->mutex);
    return CKR_FUNCTION_FAILED;
  }

  locking.pfnUnlockMutex(session->slot->mutex);

  DOUT;
  return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_GetObjectSize)(
  CK_SESSION_HANDLE hSession,
  CK_OBJECT_HANDLE hObject,
  CK_ULONG_PTR pulSize
)
{
  DIN;

  if (!pid) {
    DBG("libykpiv is not initialized or already finalized");
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  if (pulSize == NULL)
    return CKR_ARGUMENTS_BAD;

  ykcs11_session_t* session = get_session(hSession);

  if (session == NULL || session->slot == NULL) {
    DBG("Session is not open");
    return CKR_SESSION_HANDLE_INVALID;
  }

  locking.pfnLockMutex(session->slot->mutex);

  if (!is_present(session->slot, hObject)) {
    DBG("Object handle is invalid");
    locking.pfnUnlockMutex(session->slot->mutex);
    return CKR_OBJECT_HANDLE_INVALID;
  }

  CK_RV rv = get_data_len(session->slot, get_sub_id(hObject), pulSize);

  locking.pfnUnlockMutex(session->slot->mutex);

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
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  if (pTemplate == NULL || ulCount == 0)
    return CKR_ARGUMENTS_BAD;

  ykcs11_session_t* session = get_session(hSession);

  if (session == NULL || session->slot == NULL) {
    DBG("Session is not open");
    return CKR_SESSION_HANDLE_INVALID;
  }

  locking.pfnLockMutex(session->slot->mutex);

  if (!is_present(session->slot, hObject)) {
    DBG("Object handle is invalid");
    locking.pfnUnlockMutex(session->slot->mutex);
    return CKR_OBJECT_HANDLE_INVALID;
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

  if (!pid) {
    DBG("libykpiv is not initialized or already finalized");
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  ykcs11_session_t* session = get_session(hSession);

  if (session == NULL || session->slot == NULL) {
    DBG("Session is not open");
    return CKR_SESSION_HANDLE_INVALID;
  }

  if (session->find_obj.active)  {
    DBG("Search is already active");
    return CKR_OPERATION_ACTIVE;
  }

  if (ulCount != 0 && pTemplate == NULL) {
    DBG("Bad arguments");
    return CKR_ARGUMENTS_BAD;
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

  DOUT;
  return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_FindObjects)(
  CK_SESSION_HANDLE hSession,
  CK_OBJECT_HANDLE_PTR phObject,
  CK_ULONG ulMaxObjectCount,
  CK_ULONG_PTR pulObjectCount
)
{
  DIN;

  if (!pid) {
    DBG("libykpiv is not initialized or already finalized");
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  ykcs11_session_t* session = get_session(hSession);

  if (session == NULL || session->slot == NULL) {
    DBG("Session is not open");
    return CKR_SESSION_HANDLE_INVALID;
  }

  if (phObject == NULL ||
      ulMaxObjectCount == 0 ||
      pulObjectCount == NULL)
    return CKR_ARGUMENTS_BAD;

  if (!session->find_obj.active)
    return CKR_OPERATION_NOT_INITIALIZED;

  DBG("Can return %lu object(s), %lu remaining", ulMaxObjectCount, session->find_obj.n_objects - session->find_obj.idx);
  *pulObjectCount = 0;

  // Return the next object, if any
  while(session->find_obj.idx < session->find_obj.n_objects && *pulObjectCount < ulMaxObjectCount) {
    *phObject++ = session->find_obj.objects[session->find_obj.idx++];
    (*pulObjectCount)++;
  }

  DBG("Returning %lu objects, %lu remaining", *pulObjectCount, session->find_obj.n_objects - session->find_obj.idx);
  return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_FindObjectsFinal)(
  CK_SESSION_HANDLE hSession
)
{
  DIN;

  if (!pid) {
    DBG("libykpiv is not initialized or already finalized");
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  ykcs11_session_t* session = get_session(hSession);

  if (session == NULL || session->slot == NULL) {
    DBG("Session is not open");
    return CKR_SESSION_HANDLE_INVALID;
  }

  if (!session->find_obj.active)
    return CKR_OPERATION_NOT_INITIALIZED;

  session->find_obj.active = CK_FALSE;

  DOUT;
  return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_EncryptInit)(
  CK_SESSION_HANDLE hSession,
  CK_MECHANISM_PTR pMechanism,
  CK_OBJECT_HANDLE hKey
)
{
  DIN;

  if (!pid) {
    DBG("libykpiv is not initialized or already finalized");
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  ykcs11_session_t* session = get_session(hSession);

  if (session == NULL || session->slot == NULL) {
    DBG("Session is not open");
    return CKR_SESSION_HANDLE_INVALID;
  }

  if (session->op_info.type != YKCS11_NOOP) {
    DBG("Other operation in process");
    return CKR_OPERATION_ACTIVE;
  }

  if (pMechanism == NULL)
    return CKR_ARGUMENTS_BAD;

  CK_BYTE id = get_sub_id(hKey);
  if (id == 0) {
    DBG("Invalid key handle %lu", hKey);
    return CKR_KEY_HANDLE_INVALID;
  }

  locking.pfnLockMutex(session->slot->mutex);

  if (!is_present(session->slot, hKey)) {
    DBG("Key handle is invalid");
    locking.pfnUnlockMutex(session->slot->mutex);
    return CKR_OBJECT_HANDLE_INVALID;
  }

  session->op_info.op.encrypt.piv_key = piv_2_ykpiv(hKey);

  CK_RV rv = decrypt_mechanism_init(session, session->slot->pkeys[id], pMechanism);
  if(rv != CKR_OK) {
    DBG("Failed to initialize encryption operation");
    locking.pfnUnlockMutex(session->slot->mutex);
    return rv;
  }

  locking.pfnUnlockMutex(session->slot->mutex);

  session->op_info.buf_len = 0;
  session->op_info.type = YKCS11_ENCRYPT;

  DOUT;
  return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_Encrypt)(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pData,
  CK_ULONG ulDataLen,
  CK_BYTE_PTR pEncryptedData,
  CK_ULONG_PTR pulEncryptedDataLen
)
{
  CK_RV rv;

  DIN;
  
  if (!pid) {
    DBG("libykpiv is not initialized or already finalized");
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  ykcs11_session_t* session = get_session(hSession);

  if (session == NULL || session->slot == NULL) {
    DBG("Session is not open");
    return CKR_SESSION_HANDLE_INVALID;
  }

  if (pData == NULL || pulEncryptedDataLen == NULL) {
    DBG("Invalid parameters");
    return CKR_ARGUMENTS_BAD;
  }

  if (session->op_info.type != YKCS11_ENCRYPT) {
    DBG("Encryption operation not initialized");
    return CKR_OPERATION_NOT_INITIALIZED;
  }

  DBG("Using public key for slot %x for encryption", session->op_info.op.encrypt.piv_key);
#if YKCS11_DBG > 1
  dump_data(pData, ulDataLen, stderr, CK_TRUE, format_arg_hex);
#endif

  rv = do_rsa_encrypt(session->op_info.op.encrypt.key,
                      session->op_info.op.encrypt.padding,
                      session->op_info.op.encrypt.oaep_md, session->op_info.op.encrypt.mgf1_md,
                      session->op_info.op.encrypt.oaep_label, session->op_info.op.encrypt.oaep_label_len,
                      pData, ulDataLen,
                      pEncryptedData, pulEncryptedDataLen);
  if(rv != CKR_OK) {
    DBG("Encryption operation failed");
    return rv;
  }

  DBG("Got %lu encrypted bytes back", *pulEncryptedDataLen);
#if YKCS11_DBG > 1
  dump_data(pEncryptedData, *pulEncryptedDataLen, stderr, CK_TRUE, format_arg_hex);
#endif

  session->op_info.type = YKCS11_NOOP;
  session->op_info.buf_len = 0;

  DOUT;
  return CKR_OK;
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
  
  if (!pid) {
    DBG("libykpiv is not initialized or already finalized");
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  ykcs11_session_t* session = get_session(hSession);

  if (session == NULL || session->slot == NULL) {
    DBG("Session is not open");
    return CKR_SESSION_HANDLE_INVALID;
  }

  if (pPart == NULL || pulEncryptedPartLen == NULL) {
    DBG("Invalid parameters");
    return CKR_ARGUMENTS_BAD;
  }

  if (session->op_info.type != YKCS11_ENCRYPT) {
    DBG("Encryption operation not initialized");
    return CKR_OPERATION_NOT_INITIALIZED;
  }

  if(session->op_info.buf_len + ulPartLen > sizeof(session->op_info.buf)) {
    DBG("Too much data added to operation buffer, max is %lu bytes", sizeof(session->op_info.buf));
    return CKR_DATA_LEN_RANGE;
  }

  memcpy(session->op_info.buf + session->op_info.buf_len, pPart, ulPartLen);
  session->op_info.buf_len += ulPartLen;

  *pulEncryptedPartLen = 0;

  DOUT;
  return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_EncryptFinal)(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pLastEncryptedPart,
  CK_ULONG_PTR pulLastEncryptedPartLen
)
{
  CK_RV rv;

  DIN;
  
  if (!pid) {
    DBG("libykpiv is not initialized or already finalized");
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  ykcs11_session_t* session = get_session(hSession);

  if (session == NULL || session->slot == NULL) {
    DBG("Session is not open");
    return CKR_SESSION_HANDLE_INVALID;
  }

  if (pulLastEncryptedPartLen == NULL) {
    DBG("Invalid parameters");
    return CKR_ARGUMENTS_BAD;
  }

  if (session->op_info.type != YKCS11_ENCRYPT) {
    DBG("Encryption operation not initialized");
    return CKR_OPERATION_NOT_INITIALIZED;
  }

  DBG("Using slot %x for encryption", session->op_info.op.encrypt.piv_key);
#if YKCS11_DBG > 1
  dump_data(session->op_info.buf, session->op_info.buf_len, stderr, CK_TRUE, format_arg_hex);
#endif

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
    return rv;
  }

  DBG("Got %lu encrypted bytes back", *pulLastEncryptedPartLen);
#if YKCS11_DBG > 1
  dump_data(pLastEncryptedPart, *pulLastEncryptedPartLen, stderr, CK_TRUE, format_arg_hex);
#endif

  session->op_info.type = YKCS11_NOOP;
  session->op_info.buf_len = 0;

  DOUT;
  return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_DecryptInit)(
  CK_SESSION_HANDLE hSession,
  CK_MECHANISM_PTR pMechanism,
  CK_OBJECT_HANDLE hKey
)
{
  DIN;
  
  if (!pid) {
    DBG("libykpiv is not initialized or already finalized");
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  ykcs11_session_t* session = get_session(hSession);

  if (session == NULL || session->slot == NULL) {
    DBG("Session is not open");
    return CKR_SESSION_CLOSED;
  }

  if (session->op_info.type != YKCS11_NOOP) {
    DBG("Other operation in process");
    return CKR_OPERATION_ACTIVE;
  }

  if (pMechanism == NULL)
    return CKR_ARGUMENTS_BAD;

  CK_BYTE id = get_sub_id(hKey);
  if (id == 0) {
    DBG("Invalid key handle %lu", hKey);
    return CKR_KEY_HANDLE_INVALID;
  }

  locking.pfnLockMutex(session->slot->mutex);

  if (!is_present(session->slot, hKey)) {
    DBG("Key handle is invalid");
    locking.pfnUnlockMutex(session->slot->mutex);
    return CKR_OBJECT_HANDLE_INVALID;
  }

  session->op_info.op.encrypt.piv_key = piv_2_ykpiv(hKey);

  CK_RV rv = decrypt_mechanism_init(session, session->slot->pkeys[id], pMechanism);
  if(rv != CKR_OK) {
    DBG("Failed to initialize decryption operation");
    locking.pfnUnlockMutex(session->slot->mutex);
    return rv;
  }

  locking.pfnUnlockMutex(session->slot->mutex);
  
  session->op_info.buf_len = 0;
  session->op_info.type = YKCS11_DECRYPT;

  DOUT;
  return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_Decrypt)(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pEncryptedData,
  CK_ULONG ulEncryptedDataLen,
  CK_BYTE_PTR pData,
  CK_ULONG_PTR pulDataLen
)
{
  CK_RV    rv;
  
  DIN;

  if (!pid) {
    DBG("libykpiv is not initialized or already finalized");
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  ykcs11_session_t* session = get_session(hSession);

  if (session == NULL || session->slot == NULL) {
    DBG("Session is not open");
    rv = CKR_SESSION_HANDLE_INVALID;
    goto decrypt_out;
  }

  // This allows decrypting when logged in as SO and then doing a context-specific login as USER
  if (session->slot->login_state == YKCS11_PUBLIC) {
    DBG("User is not logged in");
    rv = CKR_USER_NOT_LOGGED_IN;
    goto decrypt_out;
  }

  if (pEncryptedData == NULL || pulDataLen == NULL) {
    DBG("Invalid parameters");
    return CKR_ARGUMENTS_BAD;
  }

  if (session->op_info.type != YKCS11_DECRYPT) {
    DBG("Decryption operation not initialized");
    rv = CKR_OPERATION_NOT_INITIALIZED;
    goto decrypt_out;
  }

  CK_ULONG key_len = do_get_key_size(session->op_info.op.encrypt.key);
  CK_ULONG datalen = (key_len + 7) / 8 - 11;
  DBG("The size of the data will be %lu", datalen);

  if (pData == NULL) {
    // Just return the size of the decrypted data
    *pulDataLen = datalen;
    DBG("The size of the signature will be %lu", *pulDataLen);
    DOUT;
    return CKR_OK;
  }

  DBG("Using slot %x to decrypt %lu bytes", session->op_info.op.encrypt.piv_key, ulEncryptedDataLen);
#if YKCS11_DBG > 1
  dump_data(pEncryptedData, ulEncryptedDataLen, stderr, CK_TRUE, format_arg_hex);
#endif

  if(ulEncryptedDataLen > sizeof(session->op_info.buf)) {
    DBG("Too much data added to operation buffer, max is %lu bytes", sizeof(session->op_info.buf));
    return CKR_DATA_LEN_RANGE;
  }

  session->op_info.buf_len = ulEncryptedDataLen;
  memcpy(session->op_info.buf, pEncryptedData, ulEncryptedDataLen);

  locking.pfnLockMutex(session->slot->mutex);

  rv = decrypt_mechanism_final(session, pData, pulDataLen, key_len);

  locking.pfnUnlockMutex(session->slot->mutex);

  DBG("Got %lu bytes back", *pulDataLen);
#if YKCS11_DBG > 1
  dump_data(pData, *pulDataLen, stderr, CK_TRUE, format_arg_hex);
#endif

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
  CK_RV    rv;
  
  DIN;

  if (!pid) {
    DBG("libykpiv is not initialized or already finalized");
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  ykcs11_session_t* session = get_session(hSession);

  if (session == NULL || session->slot == NULL) {
    DBG("Session is not open");
    rv = CKR_SESSION_HANDLE_INVALID;
    goto decrypt_out;
  }

  // This allows decrypting when logged in as SO and then doing a context-specific login as USER
  if (session->slot->login_state == YKCS11_PUBLIC) {
    DBG("User is not logged in");
    rv = CKR_USER_NOT_LOGGED_IN;
    goto decrypt_out;
  }

  if (pEncryptedPart == NULL || pulPartLen == NULL) {
    DBG("Invalid parameters");
    return CKR_ARGUMENTS_BAD;
  }

  if (session->op_info.type != YKCS11_DECRYPT) {
    DBG("Decryption operation not initialized");
    rv = CKR_OPERATION_NOT_INITIALIZED;
    goto decrypt_out;
  }

  DBG("Adding %lu bytes to be decrypted", ulEncryptedPartLen);
#if YKCS11_DBG > 1
  dump_data(pEncryptedPart, ulEncryptedPartLen, stderr, CK_TRUE, format_arg_hex);
#endif

  if(session->op_info.buf_len + ulEncryptedPartLen > sizeof(session->op_info.buf)) {
    DBG("Too much data added to operation buffer, max is %lu bytes", sizeof(session->op_info.buf));
    return CKR_DATA_LEN_RANGE;
  }

  memcpy(session->op_info.buf + session->op_info.buf_len, pEncryptedPart, ulEncryptedPartLen);
  session->op_info.buf_len += ulEncryptedPartLen;

  *pulPartLen = 0;
  rv = CKR_OK;

  decrypt_out:
  if(rv != CKR_OK) {
    session->op_info.type = YKCS11_NOOP;
    session->op_info.buf_len = 0;
  }

  DOUT;
  return rv;
}

CK_DEFINE_FUNCTION(CK_RV, C_DecryptFinal)(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pLastPart,
  CK_ULONG_PTR pulLastPartLen
)
{
  CK_RV    rv;
  
  DIN;

  if (!pid) {
    DBG("libykpiv is not initialized or already finalized");
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  ykcs11_session_t* session = get_session(hSession);

  if (session == NULL || session->slot == NULL) {
    DBG("Session is not open");
    rv = CKR_SESSION_HANDLE_INVALID;
    goto decrypt_out;
  }

  // This allows decrypting when logged in as SO and then doing a context-specific login as USER
  if (session->slot->login_state == YKCS11_PUBLIC) {
    DBG("User is not logged in");
    rv = CKR_USER_NOT_LOGGED_IN;
    goto decrypt_out;
  }

  if (pulLastPartLen == NULL) {
    DBG("Invalid parameters");
    return CKR_ARGUMENTS_BAD;
  }

  if (session->op_info.type != YKCS11_DECRYPT) {
    DBG("Decryption operation not initialized");
    rv = CKR_OPERATION_NOT_INITIALIZED;
    goto decrypt_out;
  }

  CK_ULONG key_len = do_get_key_size(session->op_info.op.encrypt.key);
  CK_ULONG datalen = (key_len + 7) / 8 - 11;
  DBG("The size of the data will be %lu", datalen);

  if (pLastPart == NULL) {
    // Just return the size of the decrypted data
    *pulLastPartLen = datalen;
    DBG("The size of the decrypted data will be %lu", *pulLastPartLen);
    DOUT;
    return CKR_OK;
  }

  DBG("Using slot %x to decrypt %lu bytes", session->op_info.op.encrypt.piv_key, session->op_info.buf_len);
#if YKCS11_DBG > 1
  dump_data(session->op_info.buf, session->op_info.buf_len, stderr, CK_TRUE, format_arg_hex);
#endif

  locking.pfnLockMutex(session->slot->mutex);

  rv = decrypt_mechanism_final(session, pLastPart, pulLastPartLen, key_len);

  locking.pfnUnlockMutex(session->slot->mutex);

  DBG("Got %lu bytes back", *pulLastPartLen);
#if YKCS11_DBG > 1
  dump_data(session->op_info.buf, *pulLastPartLen, stderr, CK_TRUE, format_arg_hex);
#endif

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

  if (!pid) {
    DBG("libykpiv is not initialized or already finalized");
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  ykcs11_session_t* session = get_session(hSession);

  if (session == NULL || session->slot == NULL) {
    DBG("Session is not open");
    return CKR_SESSION_HANDLE_INVALID;
  }

  if (session->op_info.type != YKCS11_NOOP) {
    DBG("Other operation in process");
    return CKR_OPERATION_ACTIVE;
  }

  if (pMechanism == NULL) {
    DBG("Wrong/Missing parameter");
    return CKR_ARGUMENTS_BAD;
  }

  CK_RV rv = digest_mechanism_init(session, pMechanism);
  if(rv != CKR_OK) {
    DBG("Unable to initialize digest operation");
    return rv;
  }

  session->op_info.type = YKCS11_DIGEST;

  DOUT;
  return CKR_OK;
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

  if (!pid) {
    DBG("libykpiv is not initialized or already finalized");
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  ykcs11_session_t* session = get_session(hSession);

  if (session == NULL || session->slot == NULL) {
    DBG("Session is not open");
    return CKR_SESSION_HANDLE_INVALID;
  }

  if (session->op_info.type != YKCS11_DIGEST) {
    DBG("Digest operation not in process");
    return CKR_OPERATION_ACTIVE;
  }

  if (pulDigestLen == NULL) {
    DBG("Wrong/missing parameter");
    return CKR_ARGUMENTS_BAD;
  }

  if (pDigest == NULL) {
    // Just return the size of the digest
    DBG("The size of the digest will be %lu", session->op_info.out_len);
    *pulDigestLen = session->op_info.out_len;
    return CKR_OK;
  }

  if (*pulDigestLen < session->op_info.out_len) {
    DBG("pulDigestLen too small, data will not fit, expected = %lu, got %lu",
      session->op_info.out_len, *pulDigestLen);
    *pulDigestLen = session->op_info.out_len;
    return CKR_BUFFER_TOO_SMALL;
  }

  CK_RV rv;
  rv = digest_mechanism_update(session, pData, ulDataLen);
  if (rv != CKR_OK) {
    return rv;
  }

  rv = digest_mechanism_final(session, pDigest, pulDigestLen);
  if (rv != CKR_OK) {
    return rv;
  }

  DBG("Got %lu bytes back", *pulDigestLen);

  session->op_info.type = YKCS11_NOOP;

  DOUT;
  return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_DigestUpdate)(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pPart,
  CK_ULONG ulPartLen
)
{
  CK_RV rv;

  DIN;

  if (!pid) {
    DBG("libykpiv is not initialized or already finalized");
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  ykcs11_session_t* session = get_session(hSession);

  if (session == NULL || session->slot == NULL) {
    DBG("Session is not open");
    return CKR_SESSION_HANDLE_INVALID;
  }

  if (session->op_info.type != YKCS11_DIGEST) {
    DBG("Digest operation not in process");
    return CKR_OPERATION_ACTIVE;
  }

  rv = digest_mechanism_update(session, pPart, ulPartLen);
  if (rv != CKR_OK) {
    return rv;
  }

  DOUT;
  return CKR_OK;
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
  CK_RV rv;

  DIN;

  if (!pid) {
    DBG("libykpiv is not initialized or already finalized");
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  ykcs11_session_t* session = get_session(hSession);

  if (session == NULL || session->slot == NULL) {
    DBG("Session is not open");
    return CKR_SESSION_HANDLE_INVALID;
  }

  if (session->op_info.type != YKCS11_DIGEST) {
    DBG("Digest operation not in process");
    return CKR_OPERATION_ACTIVE;
  }

  if (pulDigestLen == NULL) {
    DBG("Wrong/missing parameter");
    return CKR_ARGUMENTS_BAD;
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
    return CKR_BUFFER_TOO_SMALL;
  }

  rv = digest_mechanism_final(session, pDigest, pulDigestLen);
  if (rv != CKR_OK) {
    DBG("Unable to finalize digest operation");
    return rv;
  }

  session->op_info.type = YKCS11_NOOP;

  DOUT;
  return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_SignInit)(
  CK_SESSION_HANDLE hSession,
  CK_MECHANISM_PTR pMechanism,
  CK_OBJECT_HANDLE hKey
)
{
  DIN;

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

  // This allows signing when logged in as SO and then doing a context-specific login to sign
  if (session->slot->login_state == YKCS11_PUBLIC) {
    DBG("User is not logged in");
    DOUT;
    return CKR_USER_NOT_LOGGED_IN;
  }

  if (session->op_info.type != YKCS11_NOOP) {
    DBG("Other operation in process");
    DOUT;
    return CKR_OPERATION_ACTIVE;
  }

  if (pMechanism == NULL) {
    DBG("Mechanism not specified");
    DOUT;
    return CKR_ARGUMENTS_BAD;
  }

  if (!is_present(session->slot, hKey)) {
    DBG("Key handle %lu is invalid", hKey);
    DOUT;
    return CKR_OBJECT_HANDLE_INVALID;
  }

  if (hKey < PIV_PVTK_OBJ_PIV_AUTH || hKey > PIV_PVTK_OBJ_ATTESTATION) {
    DBG("Key handle %lu is not a private key", hKey);
    DOUT;
    return CKR_KEY_HANDLE_INVALID;
  }

  session->op_info.op.sign.piv_key = piv_2_ykpiv(hKey);
  CK_BYTE id = get_sub_id(hKey);

  CK_RV rv = sign_mechanism_init(session, session->slot->pkeys[id], pMechanism);
  if (rv != CKR_OK) {
    DBG("Unable to initialize signing operation");
    sign_mechanism_cleanup(session);
    DOUT;
    return rv;
  }

  session->op_info.type = YKCS11_SIGN;

  DOUT;
  return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_Sign)(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pData,
  CK_ULONG ulDataLen,
  CK_BYTE_PTR pSignature,
  CK_ULONG_PTR pulSignatureLen
)
{
  CK_RV rv;

  DIN;

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
    DOUT;
    return CKR_OPERATION_NOT_INITIALIZED;
  }

  if (pData == NULL || pulSignatureLen == NULL) {
    DBG("Invalid parameters");
    DOUT;
    return CKR_ARGUMENTS_BAD;
  }

  // This allows signing when logged in as SO and then doing a context-specific login to sign
  if (session->slot->login_state == YKCS11_PUBLIC) {
    DBG("User is not logged in");
    rv =  CKR_USER_NOT_LOGGED_IN;
    goto sign_out;
  }

  if (pSignature == NULL) {
    // Just return the size of the signature
    *pulSignatureLen = session->op_info.out_len;
    DBG("The signature requires %lu bytes", *pulSignatureLen);
    DOUT;
    return CKR_OK;
  }

#if YKCS11_DBG > 1
  dump_data(pData, ulDataLen, stderr, CK_TRUE, format_arg_hex);
#endif

  if ((rv = digest_mechanism_update(session, pData, ulDataLen)) != CKR_OK) {
    DBG("digest_mechanism_update failed");
    goto sign_out;
  }

  if (*pulSignatureLen < session->op_info.out_len) {
    DBG("The signature requires %lu bytes, got %lu", session->op_info.out_len, *pulSignatureLen);
    DOUT;
    return CKR_BUFFER_TOO_SMALL;
  }

  locking.pfnLockMutex(session->slot->mutex);

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
  CK_RV    rv;
  
  DIN;

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
    DOUT;
    return CKR_OPERATION_NOT_INITIALIZED;
  }

  if (pPart == NULL) {
    DBG("Invalid parameters");
    DOUT;
    return CKR_ARGUMENTS_BAD;
  }

  // This allows signing when logged in as SO and then doing a context-specific login to sign
  if (session->slot->login_state == YKCS11_PUBLIC) {
    DBG("User is not logged in");
    rv = CKR_USER_NOT_LOGGED_IN;
    goto sign_out;
  }

#if YKCS11_DBG > 1
  dump_data(pPart, ulPartLen, stderr, CK_TRUE, format_arg_hex);
#endif

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
  CK_RV    rv;
  
  DIN;

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
    DOUT;
    return CKR_OPERATION_NOT_INITIALIZED;
  }

  if (pulSignatureLen == NULL) {
    DBG("Invalid parameters");
    DOUT;
    return CKR_ARGUMENTS_BAD;
  }

  // This allows signing when logged in as SO and then doing a context-specific login to sign
  if (session->slot->login_state == YKCS11_PUBLIC) {
    DBG("User is not logged in");
    rv = CKR_USER_NOT_LOGGED_IN;
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

  if (!is_present(session->slot, hKey)) {
    DBG("Key handle %lu is invalid", hKey);
    DOUT;
    return CKR_OBJECT_HANDLE_INVALID;
  }

  if (hKey < PIV_PUBK_OBJ_PIV_AUTH || hKey > PIV_PUBK_OBJ_ATTESTATION) {
    DBG("Key handle %lu is not a public key", hKey);
    DOUT;
    return CKR_KEY_HANDLE_INVALID;
  }

  if (session->op_info.type != YKCS11_NOOP) {
    DBG("Other operation in process");
    DOUT;
    return CKR_OPERATION_ACTIVE;
  }

  if (pMechanism == NULL) {
    DBG("Mechanism not specified");
    DOUT;
    return CKR_ARGUMENTS_BAD;
  }

  CK_BYTE id = get_sub_id(hKey);
  
  CK_RV rv = verify_mechanism_init(session, session->slot->pkeys[id], pMechanism);
  if (rv != CKR_OK) {
    DBG("Unable to initialize verification operation");
    verify_mechanism_cleanup(session);
    DOUT;
    return rv;
  }

  session->op_info.type = YKCS11_VERIFY;

  DOUT;
  return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_Verify)(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pData,
  CK_ULONG ulDataLen,
  CK_BYTE_PTR pSignature,
  CK_ULONG ulSignatureLen
)
{
  CK_RV    rv;

  DIN;
  
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
    DOUT;
    return CKR_ARGUMENTS_BAD;
  }

  if (session->op_info.type != YKCS11_VERIFY) {
    DBG("Signature verification operation not initialized");
    DOUT;
    return CKR_OPERATION_NOT_INITIALIZED;
  }

  rv = digest_mechanism_update(session, pData, ulDataLen);
  if (rv != CKR_OK) {
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
  CK_RV    rv;

  DIN;

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
    DOUT;
    return CKR_ARGUMENTS_BAD;
  }

  if (session->op_info.type != YKCS11_VERIFY) {
    DBG("Signature verification operation not initialized");
    DOUT;
    return CKR_OPERATION_NOT_INITIALIZED;
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
  CK_RV    rv;

  DIN;
  
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
    DOUT;
    return CKR_ARGUMENTS_BAD;
  }

  if (session->op_info.type != YKCS11_VERIFY) {
    DBG("Signature verification operation not initialized");
    DOUT;
    return CKR_OPERATION_NOT_INITIALIZED;
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
  CK_RV          rv;
  piv_obj_id_t   dobj_id;
  piv_obj_id_t   cert_id;
  piv_obj_id_t   pvtk_id;
  piv_obj_id_t   pubk_id;
  piv_obj_id_t   atst_id;
  piv_obj_id_t   *obj_ptr;
  CK_BYTE        cert_data[YKPIV_OBJ_MAX_SIZE];
  CK_ULONG       cert_len;

  DIN;

  if (!pid) {
    DBG("libykpiv is not initialized or already finalized");
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  ykcs11_session_t* session = get_session(hSession);

  if (session == NULL || session->slot == NULL) {
    DBG("Session is not open");
    return CKR_SESSION_HANDLE_INVALID;
  }

  if (session->slot->login_state != YKCS11_SO) {
    DBG("Authentication as SO required to generate keys");
    return CKR_USER_TYPE_INVALID;
  }

  if (session->op_info.type != YKCS11_NOOP) {
    DBG("Other operation in process");
    return CKR_OPERATION_ACTIVE;
  }

  if (pMechanism == NULL ||
      pPublicKeyTemplate == NULL ||
      pPrivateKeyTemplate == NULL ||
      phPublicKey == NULL ||
      phPrivateKey == NULL) {
    DBG("Wrong/Missing parameter");
    return CKR_ARGUMENTS_BAD;
  }

  DBG("Trying to generate a key pair with mechanism %lx", pMechanism->mechanism);

  DBG("Found %lu attributes for the public key and %lu attributes for the private key", ulPublicKeyAttributeCount, ulPrivateKeyAttributeCount);

  // Check if mechanism is supported
  if ((rv = check_generation_mechanism(pMechanism)) != CKR_OK) {
    DBG("Mechanism %lu is not supported either by the token or the module", pMechanism->mechanism);
    return rv;
  }

  gen_info_t gen = {0};

  // Check the template for the public key
  if ((rv = check_pubkey_template(&gen, pMechanism, pPublicKeyTemplate, ulPublicKeyAttributeCount)) != CKR_OK) {
    DBG("Invalid public key template");
    return rv;
  }

  // Check the template for the private key
  if ((rv = check_pvtkey_template(&gen, pMechanism, pPrivateKeyTemplate, ulPrivateKeyAttributeCount)) != CKR_OK) {
    DBG("Invalid private key template");
    return rv;
  }

  if (gen.algorithm == 0) {
    DBG("Key length not specified");
    return CKR_TEMPLATE_INCOMPLETE;
  }

  if (gen.key_id == 0) {
    DBG("Key id not specified");
    return CKR_TEMPLATE_INCOMPLETE;
  }

  dobj_id = find_data_object(gen.key_id);
  cert_id = find_cert_object(gen.key_id);
  pubk_id = find_pubk_object(gen.key_id);
  pvtk_id = find_pvtk_object(gen.key_id);
  atst_id = find_atst_object(gen.key_id);

  DBG("Generating key with algorithm %u in object %u and %u (slot %lx)", gen.algorithm, pvtk_id, pubk_id, piv_2_ykpiv(pvtk_id));

  locking.pfnLockMutex(session->slot->mutex);

  cert_len = sizeof(cert_data);
  if ((rv = token_generate_key(session->slot->piv_state, gen.algorithm, piv_2_ykpiv(pvtk_id), cert_data, &cert_len)) != CKR_OK) {
    DBG("Unable to generate key pair");
    locking.pfnUnlockMutex(session->slot->mutex);
    return rv;
  }

  // Add objects that were not already present

  if(!is_present(session->slot, dobj_id))
    add_object(session->slot, dobj_id);
  if(!is_present(session->slot, cert_id))
    add_object(session->slot, cert_id);
  if(!is_present(session->slot, pvtk_id))
    add_object(session->slot, pvtk_id);
  if(!is_present(session->slot, pubk_id))
    add_object(session->slot, pubk_id);
  if(atst_id != PIV_INVALID_OBJ && !is_present(session->slot, atst_id))
    add_object(session->slot, atst_id);

  sort_objects(session->slot);

  // Write/Update the object

  rv = store_data(session->slot, gen.key_id, cert_data, cert_len);
  if (rv != CKR_OK) {
    DBG("Unable to store data in session");
    return CKR_FUNCTION_FAILED;
  }

  rv = store_cert(session->slot, gen.key_id, cert_data, cert_len, CK_TRUE);
  if (rv != CKR_OK) {
    DBG("Unable to store certificate in session");
    return CKR_FUNCTION_FAILED;
  }

  locking.pfnUnlockMutex(session->slot->mutex);

  *phPrivateKey = pvtk_id;
  *phPublicKey  = pubk_id;

  DOUT;
  return CKR_OK;
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
  DBG("TODO!!!");
  DOUT;
  return CKR_FUNCTION_NOT_SUPPORTED;
}

/* Random number generation functions */

CK_DEFINE_FUNCTION(CK_RV, C_SeedRandom)(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pSeed,
  CK_ULONG ulSeedLen
)
{
  DIN;

  if (!pid) {
    DBG("libykpiv is not initialized or already finalized");
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  if (pSeed == NULL && ulSeedLen != 0) {
    DBG("Invalid parameter");
    return CKR_ARGUMENTS_BAD;
  }

  ykcs11_session_t* session = get_session(hSession);

  if (session == NULL || session->slot == NULL) {
    DBG("Session is not open");
    return CKR_SESSION_HANDLE_INVALID;
  }

  if(ulSeedLen != 0) {
    CK_RV rv = do_rand_seed(pSeed, ulSeedLen);
    if (rv != CKR_OK) {
      return rv;
    }
  }

  DOUT;
  return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_GenerateRandom)(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pRandomData,
  CK_ULONG ulRandomLen
)
{
  DIN;

  if (!pid) {
    DBG("libykpiv is not initialized or already finalized");
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  if (pRandomData == NULL && ulRandomLen != 0) {
    DBG("Invalid parameter");
    return CKR_ARGUMENTS_BAD;
  }

  ykcs11_session_t* session = get_session(hSession);

  if (session == NULL || session->slot == NULL) {
    DBG("Session is not open");
    return CKR_SESSION_HANDLE_INVALID;
  }

  // the OpenSC pkcs11 test calls with 0 and expects CKR_OK, do that..
  if (ulRandomLen != 0) {
    CK_RV rv = do_rand_bytes(pRandomData, ulRandomLen);
    if (rv != CKR_OK) {
      return rv;
    }
  }

  DOUT;
  return CKR_OK;
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

static CK_FUNCTION_LIST function_list = {
  { 2, 40 },
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
