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
#include "openssl-compat.h"
#include "openssl_types.h"
#include "openssl_utils.h"
#include <openssl/rand.h>
#include "debug.h"

#include <stdbool.h>
#include "../tool/util.h"

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
static void *mutex;

static CK_FUNCTION_LIST function_list;

static CK_SESSION_HANDLE get_session_handle(ykcs11_session_t *session) {
  return session - sessions + 1;
}

static ykcs11_session_t* get_session(CK_SESSION_HANDLE handle) {
  if(handle < 1 || handle > YKCS11_MAX_SESSIONS)
    return NULL;
  return sessions + handle - 1;
}

static ykcs11_session_t* get_free_session() {
  for(int i = 0; i < YKCS11_MAX_SESSIONS; i++) {
    if(sessions[i].slot == NULL) {
      return sessions + i;
    }
  }
  return NULL;
}

CK_STATE get_session_state(ykcs11_session_t *session) {
  switch(session->slot->login_state) {
    case YKCS11_PUBLIC:
      return (session->info.flags & CKF_RW_SESSION) ? CKS_RW_PUBLIC_SESSION : CKS_RO_PUBLIC_SESSION;
    case YKCS11_USER:
      return (session->info.flags & CKF_RW_SESSION) ? CKS_RW_USER_FUNCTIONS : CKS_RO_USER_FUNCTIONS;
    case YKCS11_SO:
      return CKS_RW_SO_FUNCTIONS;
  }
}

/* General Purpose */

CK_DEFINE_FUNCTION(CK_RV, C_Initialize)(
  CK_VOID_PTR pInitArgs
)
{
  CK_RV rv;

  DIN;

  if (mutex != NULL)
    return CKR_CRYPTOKI_ALREADY_INITIALIZED;

  locking.CreateMutex = noop_create_mutex;
  locking.DestroyMutex = noop_mutex_fn;
  locking.LockMutex = noop_mutex_fn;
  locking.UnlockMutex = noop_mutex_fn;

  if(pInitArgs)
  {
    CK_C_INITIALIZE_ARGS_PTR pArgs = (CK_C_INITIALIZE_ARGS_PTR)pInitArgs;
    if(pArgs->pReserved)
      return CKR_ARGUMENTS_BAD;
    bool os_locking = pArgs->flags & CKF_OS_LOCKING_OK;
    if(os_locking || pArgs->CreateMutex)
      locking.CreateMutex = pArgs->CreateMutex;
    if(os_locking || pArgs->DestroyMutex)
      locking.DestroyMutex = pArgs->DestroyMutex;
    if(os_locking || pArgs->LockMutex)
      locking.LockMutex = pArgs->LockMutex;
    if(os_locking || pArgs->UnlockMutex)
      locking.UnlockMutex = pArgs->UnlockMutex;
    if(os_locking) {
      if(locking.CreateMutex == 0)
        locking.CreateMutex = native_create_mutex;
      if(locking.DestroyMutex == 0)
        locking.DestroyMutex = native_destroy_mutex;
      if(locking.LockMutex == 0)
        locking.LockMutex = native_lock_mutex;
      if(locking.UnlockMutex == 0)
        locking.UnlockMutex = native_unlock_mutex;
    }
    if(locking.CreateMutex == 0)
      return CKR_CANT_LOCK;
    if(locking.DestroyMutex == 0)
      return CKR_CANT_LOCK;
    if(locking.LockMutex == 0)
      return CKR_CANT_LOCK;
    if(locking.UnlockMutex == 0)
      return CKR_CANT_LOCK;
  }

  if((rv = locking.CreateMutex(&mutex)) != CKR_OK) {
    DBG("Unable to create global mutex");
    return rv;
  }

  memset(&slots, 0, sizeof(slots));
  memset(&sessions, 0, sizeof(sessions));
  n_slots = 0;

  for(int i = 0; i < YKCS11_MAX_SLOTS; i++) {
    if((rv = locking.CreateMutex(&slots[i].mutex)) != CKR_OK) {
      DBG("Unable to create mutex for slot %d", i);
      return rv;
    }
  }

  DOUT;
  return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_Finalize)(
  CK_VOID_PTR pReserved
)
{
  CK_ULONG i;

  DIN;

  if (pReserved != NULL) {
    DBG("Finalized called with pReserved != NULL");
    return CKR_ARGUMENTS_BAD;
  }

  if (mutex == NULL) {
    DBG("libykpiv is not initialized or already finalized");
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  // Close all slot states (will reset cards)
  for(int i = 0; i < YKCS11_MAX_SLOTS; i++) {
    if(slots[i].piv_state) {
      ykpiv_done(slots[i].piv_state);
    }
    locking.DestroyMutex(slots[i].mutex);
  }

  memset(&slots, 0, sizeof(slots));
  memset(&sessions, 0, sizeof(sessions));
  n_slots = 0;

  locking.DestroyMutex(mutex);
  mutex = NULL;

  DOUT;
  return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_GetInfo)(
  CK_INFO_PTR pInfo
)
{
  CK_VERSION ver = {YKCS11_VERSION_MAJOR, (YKCS11_VERSION_MINOR * 10) + YKCS11_VERSION_PATCH};

  DIN;

  pInfo->cryptokiVersion = function_list.version;

  memset(pInfo->manufacturerID, ' ', sizeof(pInfo->manufacturerID));
  memstrcpy(pInfo->manufacturerID, YKCS11_MANUFACTURER);

  pInfo->flags = 0;

  memset(pInfo->libraryDescription, ' ', sizeof(pInfo->libraryDescription));
  memstrcpy(pInfo->libraryDescription, YKCS11_LIBDESC);

  pInfo->libraryVersion = ver;

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
  CK_ULONG i;
  char readers[2048];
  size_t len = sizeof(readers);

  DIN;

  if(pulCount == NULL) {
    DBG("GetSlotList called with pulCount = NULL");
    return CKR_ARGUMENTS_BAD;
  }

  if (mutex == NULL) {
    DBG("libykpiv is not initialized or already finalized");
    return CKR_CRYPTOKI_NOT_INITIALIZED;
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

  locking.LockMutex(mutex);

  // Mark existing slots as candidates for disconnect
  bool mark[YKCS11_MAX_SLOTS] = { false };
  for(CK_ULONG i = 0; i < n_slots; i++) {
    mark[i] = true;
  }

  for(char *reader = readers; *reader; reader += strlen(reader) + 1) {

    if(is_yubico_reader(reader)) {

      ykcs11_slot_t *slot = slots + n_slots;

      // Values must NOT be null terminated and ' ' padded

      memset(slot->slot_info.slotDescription, ' ', sizeof(slot->slot_info.slotDescription));
      memstrcpy(slot->slot_info.slotDescription, reader);

      memset(slot->slot_info.manufacturerID, ' ', sizeof(slot->slot_info.manufacturerID));
      memstrcpy(slot->slot_info.manufacturerID, YKCS11_MANUFACTURER);

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
          locking.UnlockMutex(mutex);
          return CKR_FUNCTION_FAILED;
        }
        n_slots++;
      }

      char buf[80] = { '@' };
      strcat(buf, reader);
      
      // Try to connect if unconnected (both new and existing slots)
      if (!(slot->slot_info.flags & CKF_TOKEN_PRESENT) && ykpiv_connect(slot->piv_state, buf) == YKPIV_OK) {

        DBG("Connected slot %lu to '%s'", slot-slots, reader);

        slot->slot_info.flags |= CKF_TOKEN_PRESENT;
        slot->token_info.flags = CKF_RNG | CKF_LOGIN_REQUIRED | CKF_USER_PIN_INITIALIZED | CKF_TOKEN_INITIALIZED;

        slot->token_info.ulMinPinLen = 6;
        slot->token_info.ulMaxPinLen = 8;

        slot->token_info.hardwareVersion.major = 1;
        slot->token_info.hardwareVersion.minor = 0;

        slot->token_info.ulMaxRwSessionCount = YKCS11_MAX_SESSIONS;
        slot->token_info.ulMaxSessionCount = YKCS11_MAX_SESSIONS;

        slot->token_info.ulTotalPublicMemory = CK_UNAVAILABLE_INFORMATION;
        slot->token_info.ulFreePublicMemory = CK_UNAVAILABLE_INFORMATION;
        slot->token_info.ulTotalPrivateMemory = CK_UNAVAILABLE_INFORMATION;
        slot->token_info.ulFreePrivateMemory = CK_UNAVAILABLE_INFORMATION;

        memset(slot->token_info.manufacturerID, ' ', sizeof(slot->token_info.manufacturerID));
        memstrcpy(slot->token_info.manufacturerID, YKCS11_MANUFACTURER);

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
  for (i = 0; i < n_slots; i++) {
    if(!tokenPresent || (slots[i].slot_info.flags & CKF_TOKEN_PRESENT)) {
      if(pSlotList) {
        if(count >= *pulCount) {
          DBG("Buffer too small: needed %lu, provided %lu", count, *pulCount);
          locking.UnlockMutex(mutex);
          return CKR_BUFFER_TOO_SMALL;
        }
        pSlotList[count] = i;
      }
      count++;
    }
  }

  *pulCount = count;

  locking.UnlockMutex(mutex);

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

  if (mutex == NULL) {
    DBG("libykpiv is not initialized or already finalized");
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  locking.LockMutex(mutex);

  if (slotID >= n_slots) {
    DBG("Invalid slot ID %lu", slotID);
    locking.UnlockMutex(mutex);
    return CKR_SLOT_ID_INVALID;
  }

  memcpy(pInfo, &slots[slotID].slot_info, sizeof(CK_SLOT_INFO));

  locking.UnlockMutex(mutex);

  DOUT;
  return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_GetTokenInfo)(
  CK_SLOT_ID slotID,
  CK_TOKEN_INFO_PTR pInfo
)
{
  DIN;

  if (mutex == NULL) {
    DBG("libykpiv is not initialized or already finalized");
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  locking.LockMutex(mutex);

  if (slotID >= n_slots) {
    DBG("Invalid slot ID %lu", slotID);
    locking.UnlockMutex(mutex);
    return CKR_SLOT_ID_INVALID;
  }

  if(!(slots[slotID].slot_info.flags & CKF_TOKEN_PRESENT)) {
    DBG("A token is not present in slot %lu", slotID);
    locking.UnlockMutex(mutex);
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

  locking.UnlockMutex(mutex);

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
  CK_ULONG count;

  DIN;

  if (mutex == NULL) {
    DBG("libykpiv is not initialized or already finalized");
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  if (pulCount == NULL) {
    DBG("Wrong/Missing parameter");
    return CKR_ARGUMENTS_BAD;
  }

  locking.LockMutex(mutex);

  if (slotID >= n_slots) {
    DBG("Invalid slot ID %lu", slotID);
    locking.UnlockMutex(mutex);
    return CKR_SLOT_ID_INVALID;
  }

  if(!(slots[slotID].slot_info.flags & CKF_TOKEN_PRESENT)) {
    DBG("A token is not present in slot %lu", slotID);
    locking.UnlockMutex(mutex);
    return CKR_TOKEN_NOT_PRESENT;
  }

  locking.UnlockMutex(mutex);

  // TODO: check more return values

  if (get_token_mechanisms_num(&count) != CKR_OK)
    return CKR_FUNCTION_FAILED;

  if (pMechanismList == NULL) {
    *pulCount = count;
    DBG("Found %lu mechanisms", *pulCount);
    DOUT;
    return CKR_OK;
  }

  if (*pulCount < count) {
    DBG("Buffer too small: needed %lu, provided %lu", count, *pulCount);
    return CKR_BUFFER_TOO_SMALL;
  }

  if (get_token_mechanism_list(pMechanismList, *pulCount) != CKR_OK) {
    DBG("Unable to retrieve mechanism list");
    return CKR_FUNCTION_FAILED;
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

  if (mutex == NULL) {
    DBG("libykpiv is not initialized or already finalized");
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  if (pInfo == NULL) {
    DBG("Wrong/Missing parameter");
    return CKR_ARGUMENTS_BAD;
  }

  locking.LockMutex(mutex);

  if (slotID >= n_slots) {
    DBG("Invalid slot ID %lu", slotID);
    locking.UnlockMutex(mutex);
    return CKR_SLOT_ID_INVALID;
  }

  if(!(slots[slotID].slot_info.flags & CKF_TOKEN_PRESENT)) {
    DBG("A token is not present in slot %lu", slotID);
    locking.UnlockMutex(mutex);
    return CKR_TOKEN_NOT_PRESENT;
  }

  locking.UnlockMutex(mutex);

  if (get_token_mechanism_info(type, pInfo) != CKR_OK) {
    DBG("Unable to retrieve mechanism information");
    return CKR_MECHANISM_INVALID;
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

  if (mutex == NULL) {
    DBG("libykpiv is not initialized or already finalized");
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  locking.LockMutex(mutex);

  if (slotID >= n_slots) {
    DBG("Invalid slot ID %lu", slotID);
    locking.UnlockMutex(mutex);
    return CKR_SLOT_ID_INVALID;
  }

  if(!(slots[slotID].slot_info.flags & CKF_TOKEN_PRESENT)) {
    DBG("A token is not present in slot %lu", slotID);
    locking.UnlockMutex(mutex);
    return CKR_TOKEN_NOT_PRESENT;
  }

  for(int i = 0; i < YKCS11_MAX_SESSIONS; i++) {
    ykcs11_session_t *session = sessions + i;
    if(session->slot && session->info.slotID == slotID) {
      locking.UnlockMutex(mutex);
      return CKR_SESSION_EXISTS;
    }
  }

  locking.UnlockMutex(mutex);

  CK_BYTE mgm_key[24];
  size_t len = sizeof(mgm_key);
  ykpiv_rc rc;

  if((rc = ykpiv_hex_decode((const char*)pPin, ulPinLen, mgm_key, &len)) != YKPIV_OK || len != 24) {
    DBG("ykpiv_hex_decode failed %d", rc);
    return CKR_ARGUMENTS_BAD;
  }

  int tries;
  ykcs11_slot_t *slot = slots + slotID;

  locking.LockMutex(slot->mutex);

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
    locking.UnlockMutex(slot->mutex);
    return CKR_FUNCTION_FAILED;
  }

  // Authenticate with default mgm key (SO PIN)
  if((rc = ykpiv_authenticate(slot->piv_state, NULL)) != YKPIV_OK) {
    DBG("ykpiv_authenticate failed %d", rc);
    locking.UnlockMutex(slot->mutex);
    return CKR_FUNCTION_FAILED;
  }

  // Set new mgm key (SO PIN)
  if((rc = ykpiv_set_mgmkey(slot->piv_state, mgm_key)) != YKPIV_OK) {
    DBG("ykpiv_set_mgmkey failed %d", rc);
    locking.UnlockMutex(slot->mutex);
    return CKR_FUNCTION_FAILED;
  }

  locking.UnlockMutex(slot->mutex);

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

  if (mutex == NULL) {
    DBG("libykpiv is not initialized or already finalized");
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  
  ykcs11_session_t* session = get_session(hSession);

  if (session == NULL || session->slot == NULL) {
    DBG("User called SetPIN on closed session");
    return CKR_SESSION_HANDLE_INVALID;
  }

  CK_USER_TYPE user_type = CKU_USER;
  if (get_session_state(session) == CKS_RW_SO_FUNCTIONS) {
    user_type = CKU_SO;
  }

  locking.LockMutex(session->slot->mutex);

  CK_RV rv = token_change_pin(session->slot->piv_state, user_type, pOldPin, ulOldLen, pNewPin, ulNewLen);
  if (rv != CKR_OK) {
    DBG("Pin change failed %lx", rv);
    locking.UnlockMutex(session->slot->mutex);
    return rv;
  }

  locking.UnlockMutex(session->slot->mutex);

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

  if (mutex == NULL) {
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

  locking.LockMutex(mutex);

  if (slotID >= n_slots) {
    DBG("Invalid slot ID %lu", slotID);
    locking.UnlockMutex(mutex);
    return CKR_SLOT_ID_INVALID;
  }

  if(!(slots[slotID].slot_info.flags & CKF_TOKEN_PRESENT)) {
    DBG("A token is not present in slot %lu", slotID);
    locking.UnlockMutex(mutex);
    return CKR_TOKEN_NOT_PRESENT;
  }

  ykcs11_session_t* session = get_free_session();
  if (session == NULL) {
    DBG("The maximum number of open session have already been reached");
    locking.UnlockMutex(mutex);
    return CKR_SESSION_COUNT;
  }

  memset(session, 0, sizeof(*session));
  session->info.slotID = slotID;
  session->info.flags = flags;
  session->slot = slots + slotID;

  locking.UnlockMutex(mutex);

  piv_obj_id_t *obj_ids;
  CK_ULONG num_ids;
  get_token_object_ids(&obj_ids, &num_ids);

  locking.LockMutex(session->slot->mutex);

  // Save a list of all the available objects in the session

  for(CK_ULONG i = 0; i < num_ids; i++) {
    ykpiv_rc rc = YKPIV_KEY_ERROR;
    ykpiv_metadata md = { 0 };
    CK_BYTE key_id = get_key_id(obj_ids[i]);
    piv_obj_id_t cert_id = find_cert_object(key_id);
    piv_obj_id_t pubk_id = find_pubk_object(key_id);
    piv_obj_id_t pvtk_id = find_pvtk_object(key_id);
    piv_obj_id_t atst_id = find_atst_object(key_id);
    CK_BYTE data[3072];  // Max cert value for ykpiv
    unsigned long len;
    if(pvtk_id != (piv_obj_id_t)-1) {
      len = sizeof(data);
      if((rc = ykpiv_get_metadata(session->slot->piv_state, piv_2_ykpiv(pvtk_id), data, &len)) == YKPIV_OK) {
        DBG("Read %lu bytes metadata for private key %u (slot %lx)", len, pvtk_id, piv_2_ykpiv(pvtk_id));
        if((rc = ykpiv_util_parse_metadata(data, len, &md)) == YKPIV_OK) {
          session->pkeys[key_id] = EVP_PKEY_new();
          int nid = get_curve_name(md.algorithm);
          if(nid) {
            EC_GROUP *group = EC_GROUP_new_by_curve_name(nid);
            EC_GROUP_set_asn1_flag(group, nid);
            EC_KEY *eckey = EC_KEY_new();
            EC_KEY_set_group(eckey, group);
            EC_POINT *ecpoint = EC_POINT_new(group);
            EC_POINT_oct2point(group, ecpoint, md.point, md.point_len, NULL);
            EC_KEY_set_public_key(eckey, ecpoint);
            EVP_PKEY_set1_EC_KEY(session->pkeys[key_id], eckey);
          } else {
            RSA *rsa = RSA_new();
            BIGNUM *n = BN_bin2bn(md.mod, md.mod_len, 0);
            BIGNUM *e = BN_bin2bn(md.exp, md.exp_len, 0);
            RSA_set0_key(rsa, n, e, NULL);
            EVP_PKEY_set1_RSA(session->pkeys[key_id], rsa);
          }
          session->objects[session->n_objects++] = pubk_id;
          session->objects[session->n_objects++] = pvtk_id;
          if(atst_id != (piv_obj_id_t)-1) { // Attestation key doesn't have an attestation
            session->objects[session->n_objects++] = atst_id;
          }
        }
      }
    }
    len = sizeof(data);
    if(ykpiv_fetch_object(session->slot->piv_state, piv_2_ykpiv(obj_ids[i]), data, &len) == YKPIV_OK) {
      DBG("Read %lu bytes for data object %u (%lx)", len, obj_ids[i], piv_2_ykpiv(obj_ids[i]));
      session->objects[session->n_objects++] = obj_ids[i];
      CK_RV rv = store_data(session, obj_ids[i], data, len);
      if (rv != CKR_OK) {
        DBG("Failed to store data object %u in session: %lu", obj_ids[i], rv);
        locking.UnlockMutex(session->slot->mutex);
        session->slot = NULL;
        return rv;
      }
      if(cert_id != (piv_obj_id_t)-1) {
        session->objects[session->n_objects++] = cert_id;
        rv = store_cert(session, cert_id, data, len, CK_FALSE);
        if (rv != CKR_OK) {
          DBG("Failed to store certificate object %u in session: %lu", cert_id, rv);
          locking.UnlockMutex(session->slot->mutex);
          session->slot = NULL;
          return rv;
        }
        if(rc != YKPIV_OK) { // Failed to get metadata, fall back to assuming we have keys for cert objects
          session->objects[session->n_objects++] = pubk_id;
          session->objects[session->n_objects++] = pvtk_id;
          if(atst_id != (piv_obj_id_t)-1) { // Attestation key doesn't have an attestation
            session->objects[session->n_objects++] = atst_id;
          }
        }
      }
    }
  }

  locking.UnlockMutex(session->slot->mutex);

  sort_objects(session);
  *phSession = get_session_handle(session);

  DOUT;
  return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_CloseSession)(
  CK_SESSION_HANDLE hSession
)
{
  DIN;

  if (mutex == NULL) {
    DBG("libykpiv is not initialized or already finalized");
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  ykcs11_session_t *session = get_session(hSession);

  locking.LockMutex(mutex);

  if (session == NULL || session->slot == NULL) {
    DBG("Trying to close a session, but there is no existing one");
    locking.UnlockMutex(mutex);
    return CKR_SESSION_HANDLE_INVALID;
  }

  piv_obj_id_t *obj_ids;
  CK_ULONG num_ids;
  get_token_object_ids(&obj_ids, &num_ids);

  for(CK_ULONG i = 0; i < num_ids; i++) {
    if(is_present(session, obj_ids[i]))
      delete_data(session, obj_ids[i]);
    piv_obj_id_t cert_id = find_cert_object(get_key_id(obj_ids[i]));
    if(is_present(session, cert_id))
      delete_cert(session, cert_id);
  }

  memset(session, 0, sizeof(*session));
  locking.UnlockMutex(mutex);

  DOUT;
  return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_CloseAllSessions)(
  CK_SLOT_ID slotID
)
{
  CK_RV rv;

  DIN;

  if (mutex == NULL) {
    DBG("libykpiv is not initialized or already finalized");
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  locking.LockMutex(mutex);

  if (slotID >= n_slots) {
    DBG("Invalid slot ID %lu", slotID);
    locking.UnlockMutex(mutex);
    return CKR_SLOT_ID_INVALID;
  }

  piv_obj_id_t *obj_ids;
  CK_ULONG num_ids;
  get_token_object_ids(&obj_ids, &num_ids);

  for(int i = 0; i < YKCS11_MAX_SESSIONS; i++) {
    ykcs11_session_t *session = sessions + i;
    if(session->slot && session->info.slotID == slotID) {
      for(CK_ULONG i = 0; i < num_ids; i++) {
        if(is_present(session, obj_ids[i]))
          delete_data(session, obj_ids[i]);
        piv_obj_id_t cert_id = find_cert_object(get_key_id(obj_ids[i]));
        if(is_present(session, cert_id))
          delete_cert(session, cert_id);
      }
      memset(session, 0, sizeof(*session));
    }
  }

  locking.UnlockMutex(mutex);

  DOUT;
  return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_GetSessionInfo)(
  CK_SESSION_HANDLE hSession,
  CK_SESSION_INFO_PTR pInfo
)
{
  DIN;

  if (mutex == NULL) {
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
  pInfo->state = get_session_state(session);

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

  if (mutex == NULL) {
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
  case CKU_USER:
    if (ulPinLen < PIV_MIN_PIN_LEN || ulPinLen > PIV_MAX_PIN_LEN)
      return CKR_ARGUMENTS_BAD;

    if (session->slot->login_state == YKCS11_SO) {
      DBG("Tried to log-in USER to a SO session");
      return CKR_USER_ANOTHER_ALREADY_LOGGED_IN;
    }

    // We allow multiple logins because some keys need it (we indicate so for the signing key)

    locking.LockMutex(session->slot->mutex);

    rv = token_login(session->slot->piv_state, CKU_USER, pPin, ulPinLen);
    if (rv != CKR_OK) {
      DBG("Unable to login as regular user");
      locking.UnlockMutex(session->slot->mutex);
      return rv;
    }

    locking.UnlockMutex(session->slot->mutex);
    session->slot->login_state = YKCS11_USER;
    break;

  case CKU_SO:
    if (ulPinLen != PIV_MGM_KEY_LEN)
      return CKR_ARGUMENTS_BAD;

    if (session->slot->login_state == YKCS11_USER) {
      DBG("Tried to log-in SO to a USER session");
      return CKR_USER_ANOTHER_ALREADY_LOGGED_IN;
    }

    if (session->slot->login_state == YKCS11_SO) {
      DBG("Tried to log-in SO to a SO session");
      return CKR_USER_ALREADY_LOGGED_IN;
    }

    for(CK_ULONG i = 0; i < YKCS11_MAX_SESSIONS; i++) {
      if (sessions[i].slot == session->slot && !(sessions[i].info.flags & CKF_RW_SESSION)) {
        DBG("Tried to log-in SO with existing RO sessions");
        return CKR_SESSION_READ_ONLY_EXISTS;
      }
    }

    locking.LockMutex(session->slot->mutex);

    rv = token_login(session->slot->piv_state, CKU_SO, pPin, ulPinLen);
    if (rv != CKR_OK) {
      DBG("Unable to login as SO");
      locking.UnlockMutex(session->slot->mutex);
      return rv;
    }

    locking.UnlockMutex(session->slot->mutex);
    session->slot->login_state = YKCS11_SO;
    break;

  case CKU_CONTEXT_SPECIFIC:
    if (session->op_info.type == YKCS11_NOOP) {
      DBG("No operation in progress. Context specific user is forbidden.");
      return CKR_USER_TYPE_INVALID;
    }
    if (session->op_info.type == YKCS11_SIGN || session->op_info.type == YKCS11_DECRYPT) {
      return C_Login(hSession, CKU_USER, pPin, ulPinLen);
    }
    else
      return C_Login(hSession, CKU_SO, pPin, ulPinLen);

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

  if (mutex == NULL) {
    DBG("libykpiv is not initialized or already finalized");
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  ykcs11_session_t* session = get_session(hSession);

  if (session == NULL || session->slot == NULL) {
    DBG("Session is not open");
    return CKR_SESSION_HANDLE_INVALID;
  }

  if (session->slot->login_state == YKCS11_PUBLIC)
    return CKR_USER_NOT_LOGGED_IN;

  session->slot->login_state = YKCS11_PUBLIC;

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
  CK_ULONG         dobj_id;
  CK_ULONG         cert_id;
  CK_ULONG         pubk_id;
  CK_ULONG         pvtk_id;
  piv_obj_id_t     *obj_ptr;

  DIN;

  if (mutex == NULL) {
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

  if (get_session_state(session) != CKS_RW_SO_FUNCTIONS) {
    DBG("Authentication required to import objects");
    return CKR_USER_TYPE_INVALID;
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

    locking.LockMutex(session->slot->mutex);

    rv = token_import_cert(session->slot->piv_state, piv_2_ykpiv(cert_id), value); // TODO: make function to get cert id
    if (rv != CKR_OK) {
      DBG("Unable to import certificate");
      locking.UnlockMutex(session->slot->mutex);
      return rv;
    }

    locking.UnlockMutex(session->slot->mutex);

    // Check whether we created a new object or updated an existing one
    if (!is_present(session, cert_id)) {
      // New object created, add it to the object list
      obj_ptr = session->objects + session->n_objects;
      *obj_ptr++ = dobj_id;
      *obj_ptr++ = cert_id;
      *obj_ptr++ = pvtk_id;
      *obj_ptr++ = pubk_id;
      session->n_objects = obj_ptr - session->objects;
      sort_objects(session);
    }

    rv = store_data(session, dobj_id, value, value_len);
    if (rv != CKR_OK) {
      DBG("Unable to store data in session");
      return CKR_FUNCTION_FAILED;
    }

    rv = store_cert(session, cert_id, value, value_len, CK_TRUE);
    if (rv != CKR_OK) {
      DBG("Unable to store certificate in session");
      return CKR_FUNCTION_FAILED;
    }

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

    locking.LockMutex(session->slot->mutex);

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
        locking.UnlockMutex(session->slot->mutex);
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
        locking.UnlockMutex(session->slot->mutex);
        return rv;
      }
    }

    locking.UnlockMutex(session->slot->mutex);
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
  CK_RV          rv;
  CK_ULONG       i;
  CK_ULONG       j;
  CK_BYTE        id;
  CK_ULONG       dobj_id;
  CK_ULONG       pvtk_id;
  CK_ULONG       pubk_id;

  DIN;

  DBG("Deleting object %lu", hObject);

  if (mutex == NULL) {
    DBG("libykpiv is not initialized or already finalized");
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  ykcs11_session_t* session = get_session(hSession);

  if (session == NULL || session->slot == NULL) {
    DBG("Session is not open");
    return CKR_SESSION_HANDLE_INVALID;
  }

  if (!is_present(session, hObject)) {
    DBG("Object handle is invalid");
    return CKR_OBJECT_HANDLE_INVALID;
  }

  // Only certificates can be deleted
  // SO must be logged in
  if (get_session_state(session) != CKS_RW_SO_FUNCTIONS) {
    DBG("Unable to delete objects, SO must be logged in");
    return CKR_USER_TYPE_INVALID;
  }

  rv = check_delete_cert(hObject, &id);
  if (rv != CKR_OK) {
    DBG("Object %lu can not be deleted", hObject);
    return rv;
  }

  locking.LockMutex(session->slot->mutex);

  rv = token_delete_cert(session->slot->piv_state, piv_2_ykpiv(hObject));
  if (rv != CKR_OK) {
    DBG("Unable to delete object %lu", hObject);
    locking.UnlockMutex(session->slot->mutex);
    return rv;
  }

  locking.UnlockMutex(session->slot->mutex);

  // Remove the related objects from the session
  dobj_id = find_data_object(id);
  pvtk_id = find_pvtk_object(id);
  pubk_id = find_pubk_object(id);

  j = 0;
  for (i = 0; i < session->n_objects; i++) {
    if (session->objects[i] == hObject ||
        session->objects[i] == dobj_id ||
        session->objects[i] == pvtk_id ||
        session->objects[i] == pubk_id) {
      continue;
    }
    session->objects[j++] = session->objects[i];
  }
  session->n_objects = j;

  rv = delete_cert(session, hObject);
  if (rv != CKR_OK) {
    DBG("Unable to delete certificate data");
    return CKR_FUNCTION_FAILED;
  }

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

  if (mutex == NULL) {
    DBG("libykpiv is not initialized or already finalized");
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  ykcs11_session_t* session = get_session(hSession);

  if (session == NULL || session->slot == NULL) {
    DBG("Session is not open");
    return CKR_SESSION_HANDLE_INVALID;
  }

  if (!is_present(session, hObject)) {
    DBG("Object handle is invalid");
    return CKR_OBJECT_HANDLE_INVALID;
  }

  if (pulSize == NULL)
    return CKR_ARGUMENTS_BAD;

  CK_RV rv = get_data_len(session, hObject, pulSize);

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

  if (mutex == NULL) {
    DBG("libykpiv is not initialized or already finalized");
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  ykcs11_session_t* session = get_session(hSession);

  if (session == NULL || session->slot == NULL) {
    DBG("Session is not open");
    return CKR_SESSION_HANDLE_INVALID;
  }

  if (!is_present(session, hObject)) {
    DBG("Object handle is invalid");
    return CKR_OBJECT_HANDLE_INVALID;
  }

  if (pTemplate == NULL || ulCount == 0)
    return CKR_ARGUMENTS_BAD;

  locking.LockMutex(session->slot->mutex);

  rv_final = CKR_OK;
  for (i = 0; i < ulCount; i++) {

    rv = get_attribute(session, hObject, pTemplate + i);

    // TODO: this function has some complex cases for return value. Make sure to check them.
    if (rv != CKR_OK) {
      DBG("Unable to get attribute 0x%lx of object %lu", (pTemplate + i)->type, hObject);
      rv_final = rv;
    }
  }

  locking.UnlockMutex(session->slot->mutex);

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

  if (ulCount != 0 && pTemplate == NULL) {
    DBG("Bad arguments");
    return CKR_ARGUMENTS_BAD;
  }

  if (mutex == NULL) {
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

  session->find_obj.active = CK_TRUE;
  session->find_obj.n_objects = 0;
  session->find_obj.idx = 0;

  DBG("Initialized search with %lu parameters", ulCount);

  // Match parameters
  for (CK_ULONG i = 0; i < session->n_objects; i++) {

    // Strip away private objects if needed
    if (session->slot->login_state == YKCS11_PUBLIC)
      if (is_private_object(session, session->objects[i]) == CK_TRUE) {
        DBG("Removing private object %u", session->objects[i]);
        continue;
      }

    locking.LockMutex(session->slot->mutex);
  
    bool keep = true;
    for (CK_ULONG j = 0; j < ulCount; j++) {
      if (attribute_match(session, session->objects[i], pTemplate + j) == CK_FALSE) {
        DBG("Removing object %u", session->objects[i]);
        keep = false;
        break;
      }
    }

    locking.UnlockMutex(session->slot->mutex);

    if(keep) {
      DBG("Keeping object %u", session->objects[i]);
      session->find_obj.objects[session->find_obj.n_objects++] = session->objects[i];
    }
  }

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

  if (mutex == NULL) {
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

  DBG("Can return %lu object(s)", ulMaxObjectCount);
  *pulObjectCount = 0;

  // Return the next object, if any
  while(session->find_obj.idx < session->find_obj.n_objects && *pulObjectCount < ulMaxObjectCount) {
    *phObject++ = session->find_obj.objects[session->find_obj.idx++];
    (*pulObjectCount)++;
  }

  DBG("Returning %lu objects", *pulObjectCount);
  return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_FindObjectsFinal)(
  CK_SESSION_HANDLE hSession
)
{
  DIN;

  if (mutex == NULL) {
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
  DBG("TODO!!!");
  DOUT;
  return CKR_FUNCTION_NOT_SUPPORTED;
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
  DBG("TODO!!!");
  DOUT;
  return CKR_FUNCTION_NOT_SUPPORTED;
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
  DBG("TODO!!!");
  DOUT;
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_EncryptFinal)(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pLastEncryptedPart,
  CK_ULONG_PTR pulLastEncryptedPartLen
)
{
  DIN;
  DBG("TODO!!!");
  DOUT;
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_DecryptInit)(
  CK_SESSION_HANDLE hSession,
  CK_MECHANISM_PTR pMechanism,
  CK_OBJECT_HANDLE hKey
)
{
  CK_KEY_TYPE  type = 0;
  CK_ULONG     key_len = 0;
  CK_ATTRIBUTE template[] = {
    {CKA_KEY_TYPE, &type, sizeof(type)},
    {CKA_MODULUS_BITS, &key_len, sizeof(key_len)},
  };

  DIN;
  
  if (mutex == NULL) {
    DBG("libykpiv is not initialized or already finalized");
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  ykcs11_session_t* session = get_session(hSession);

  if (session == NULL || session->slot == NULL) {
    DBG("Session is not open");
    return CKR_SESSION_CLOSED;
  }

  if (!is_present(session, hKey)) {
    DBG("Key handle is invalid");
    return CKR_OBJECT_HANDLE_INVALID;
  }

  if (session->op_info.type != YKCS11_NOOP) {
    DBG("Other operation in process");
    return CKR_OPERATION_ACTIVE;
  }

  if (pMechanism == NULL)
    return CKR_ARGUMENTS_BAD;

  DBG("Trying to decrypt some data with mechanism %lu and key %lu", pMechanism->mechanism, hKey);

  // Check if mechanism is supported
  if (check_rsa_decrypt_mechanism(session, pMechanism) != CKR_OK) {
    DBG("Mechanism %lu is not supported either by the token or the module", pMechanism->mechanism);
    return CKR_MECHANISM_INVALID; // TODO: also the key has a list of allowed mechanisms, check that
  }
  memcpy(&session->op_info.mechanism, pMechanism, sizeof(CK_MECHANISM));

  //  Get key algorithm
  if (get_attribute(session, hKey, template) != CKR_OK) {
    DBG("Unable to get key type");
    return CKR_KEY_HANDLE_INVALID;
  }

  if(type == CKK_RSA) {
    if (get_attribute(session, hKey, template + 1) != CKR_OK) {
      DBG("Unable to get key length");
      return CKR_KEY_HANDLE_INVALID;
    }

    session->op_info.op.decrypt.key_len = key_len;

    if (key_len == 1024) {
      session->op_info.op.decrypt.algo = YKPIV_ALGO_RSA1024;
    } else {
      session->op_info.op.decrypt.algo = YKPIV_ALGO_RSA2048;
    }

  } else {
    DBG("Referenced key is not an RSA key. Only RSA decryption is supported");
    return CKR_KEY_TYPE_INCONSISTENT;
  }

  DBG("Key length is %lu bit", session->op_info.op.decrypt.key_len);
  
  session->op_info.op.decrypt.key_id = piv_2_ykpiv(hKey);
  if (session->op_info.op.decrypt.key_id == 0) {
    DBG("Incorrect key %lu", hKey);
    return CKR_KEY_HANDLE_INVALID;
  }

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
  ykpiv_rc piv_rv;
  CK_RV    rv;
  size_t   cbDataLen = 0;
  CK_BYTE  dec_unwrap[1024];
  CK_ULONG dec_unwrap_len;
  
  DIN;

  if (mutex == NULL) {
    DBG("libykpiv is not initialized or already finalized");
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  ykcs11_session_t* session = get_session(hSession);

  if (session == NULL || session->slot == NULL) {
    DBG("Session is not open");
    rv = CKR_SESSION_HANDLE_INVALID;
    goto decrypt_out;
  }

  if (get_session_state(session) == CKS_RO_PUBLIC_SESSION ||
      get_session_state(session) == CKS_RW_PUBLIC_SESSION) {
    DBG("User is not logged in");
    rv = CKR_USER_NOT_LOGGED_IN;
    goto decrypt_out;
  }

  if (session->op_info.type != YKCS11_DECRYPT) {
    DBG("Decryption operation not initialized");
    rv = CKR_OPERATION_NOT_INITIALIZED;
    goto decrypt_out;
  }

  CK_ULONG datalen = (session->op_info.op.decrypt.key_len + 7) / 8 - 11;
  DBG("The size of the data will be %lu", datalen);

  if (pData == NULL) {
    // Just return the size of the decrypted data
    *pulDataLen = datalen;
    DBG("The size of the signature will be %lu", *pulDataLen);
    DOUT;
    return CKR_OK;
  }

  DBG("Sending %lu bytes to be decrypted", ulEncryptedDataLen);
#if YKCS11_DBG
  dump_data(pEncryptedData, ulEncryptedDataLen, stderr, CK_TRUE, format_arg_hex);
#endif

  session->op_info.buf_len = ulEncryptedDataLen;
  memcpy(session->op_info.buf, pEncryptedData, ulEncryptedDataLen);

  DBG("Using key %x for decryption", session->op_info.op.decrypt.key_id);

  *pulDataLen = cbDataLen = sizeof(session->op_info.buf);

  locking.LockMutex(session->slot->mutex);

  piv_rv = ykpiv_decipher_data(session->slot->piv_state, session->op_info.buf, session->op_info.buf_len, 
                               session->op_info.buf, &cbDataLen, 
                               session->op_info.op.decrypt.algo, session->op_info.op.decrypt.key_id);

  locking.UnlockMutex(session->slot->mutex);

  if (piv_rv != YKPIV_OK) {
    if (piv_rv == YKPIV_AUTHENTICATION_ERROR) {
      DBG("Operation requires authentication or touch");
      rv = CKR_USER_NOT_LOGGED_IN;
      goto decrypt_out;
    } else {
      DBG("Decrypt error, %s", ykpiv_strerror(piv_rv));
      rv = CKR_FUNCTION_FAILED;
      goto decrypt_out;
    }
  }

  *pulDataLen = RSA_padding_check_PKCS1_type_2(dec_unwrap, sizeof(dec_unwrap), session->op_info.buf + 1, cbDataLen - 1, session->op_info.op.decrypt.key_len/8);

  DBG("Got %lu bytes back", *pulDataLen);
#if YKCS11_DBG
  dump_data(session->op_info.buf, *pulDataLen, stderr, CK_TRUE, format_arg_hex);
#endif

  memcpy(pData, dec_unwrap, *pulDataLen);
  rv = CKR_OK;

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
  DBG("TODO!!!");
  DOUT;
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_DecryptFinal)(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pLastPart,
  CK_ULONG_PTR pulLastPartLen
)
{
  DIN;
  DBG("TODO!!!");
  DOUT;
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_DigestInit)(
  CK_SESSION_HANDLE hSession,
  CK_MECHANISM_PTR pMechanism
)
{
  DIN;

  if (mutex == NULL) {
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

  DBG("Trying to hash some data with mechanism %lu", pMechanism->mechanism);

  // Check if mechanism is supported
  if (check_hash_mechanism(session, pMechanism) != CKR_OK) {
    DBG("Mechanism %lu is not supported either by the token or the module", pMechanism->mechanism);
    return CKR_MECHANISM_INVALID;
  }
  memcpy(&session->op_info.mechanism, pMechanism, sizeof(CK_MECHANISM));

  CK_ULONG hash_length = get_hash_length(pMechanism->mechanism);
  session->op_info.op.hash.hash_len = hash_length;

  CK_RV rv;
  rv = apply_hash_mechanism_init(&session->op_info);
  if(rv != CKR_OK) {
    DBG("Unable to initialize digest operation");
    return rv;
  }

  session->op_info.type = YKCS11_HASH;

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

  if (mutex == NULL) {
    DBG("libykpiv is not initialized or already finalized");
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  ykcs11_session_t* session = get_session(hSession);

  if (session == NULL || session->slot == NULL) {
    DBG("Session is not open");
    return CKR_SESSION_HANDLE_INVALID;
  }

  if (session->op_info.type != YKCS11_HASH) {
    DBG("Other operation in process");
    return CKR_OPERATION_ACTIVE;
  }

  if (pulDigestLen == NULL) {
    DBG("Wrong/missing parameter");
    return CKR_ARGUMENTS_BAD;
  }

  if (pDigest == NULL) {
    // Just return the size of the digest
    DBG("The size of the digest will be %lu", session->op_info.op.hash.hash_len);

    *pulDigestLen = session->op_info.op.hash.hash_len;

    DOUT;
    return CKR_OK;
  }

  if (*pulDigestLen < session->op_info.op.hash.hash_len) {
    DBG("pulDigestLen too small, data will not fit, expected = %lu, got "
            "%lu", session->op_info.op.hash.hash_len, *pulDigestLen);

    *pulDigestLen = session->op_info.op.hash.hash_len;
    return CKR_BUFFER_TOO_SMALL;
  }

  DBG("Sending %lu bytes to digest", ulDataLen);

  CK_RV rv;
  rv = apply_hash_mechanism_update(&session->op_info, pData, ulDataLen);
  if (rv != CKR_OK) {
    DBG("Unable to perform digest operation step");
    return rv;
  }

  rv = apply_hash_mechanism_finalize(&session->op_info);
  if (rv != CKR_OK) {
    DBG("Unable to finalize digest operation");
    return rv;
  }

  memcpy(pDigest, session->op_info.buf, session->op_info.buf_len);
  *pulDigestLen = session->op_info.buf_len;

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
  DIN;
  DBG("TODO!!!");
  DOUT;
  return CKR_FUNCTION_NOT_SUPPORTED;
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
  DBG("TODO!!!");
  DOUT;
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_SignInit)(
  CK_SESSION_HANDLE hSession,
  CK_MECHANISM_PTR pMechanism,
  CK_OBJECT_HANDLE hKey
)
{
  CK_KEY_TYPE  type = 0;
  CK_ULONG     key_len = 0;
  CK_BYTE      exp[3];
  CK_BYTE      buf[1024] = {0};
  CK_ATTRIBUTE template[] = {
    {CKA_KEY_TYPE, &type, sizeof(type)},
    {CKA_MODULUS_BITS, &key_len, sizeof(key_len)},
    {CKA_MODULUS, buf, sizeof(buf)},
    {CKA_PUBLIC_EXPONENT, exp, sizeof(exp)},
    {CKA_EC_POINT, buf, sizeof(buf)},
  };

  DIN;

  if (mutex == NULL) {
    DBG("libykpiv is not initialized or already finalized");
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  ykcs11_session_t* session = get_session(hSession);

  if (session == NULL || session->slot == NULL) {
    DBG("Session is not open");
    return CKR_SESSION_HANDLE_INVALID;
  }

  if (!is_present(session, hKey)) {
    DBG("Key handle is invalid");
    return CKR_OBJECT_HANDLE_INVALID;
  }

  if (session->op_info.type != YKCS11_NOOP) {
    DBG("Other operation in process");
    return CKR_OPERATION_ACTIVE;
  }

  if (pMechanism == NULL)
    return CKR_ARGUMENTS_BAD;

  DBG("Trying to sign some data with mechanism %lu and key %lu", pMechanism->mechanism, hKey);

  // Check if mechanism is supported
  if (check_sign_mechanism(session, pMechanism) != CKR_OK) {
    DBG("Mechanism %lu is not supported either by the token or the module", pMechanism->mechanism);
    return CKR_MECHANISM_INVALID; // TODO: also the key has a list of allowed mechanisms, check that
  }
  memcpy(&session->op_info.mechanism, pMechanism, sizeof(CK_MECHANISM));

  //  Get key algorithm
  if (get_attribute(session, hKey, template) != CKR_OK) {
    DBG("Unable to get key type");
    return CKR_KEY_HANDLE_INVALID;
  }

  // Get key length and algorithm type
  if (type == CKK_RSA) {
    // RSA key
    if (get_attribute(session, hKey, template + 1) != CKR_OK) {
      DBG("Unable to get key length");
      return CKR_KEY_HANDLE_INVALID;
    }

    session->op_info.op.sign.key_len = key_len;
    session->op_info.op.sign.sig_len = (key_len + 7) / 8;

    if (key_len == 1024)
      session->op_info.op.sign.algo = YKPIV_ALGO_RSA1024;
    else
      session->op_info.op.sign.algo = YKPIV_ALGO_RSA2048;

    // Also store the raw public key if the mechanism is PSS
    if (is_PSS_mechanism(pMechanism->mechanism)) {

      if (get_attribute(session, hKey, template + 2) != CKR_OK) {
        DBG("Unable to get public key");
        return CKR_KEY_HANDLE_INVALID;
      }

      if (get_attribute(session, hKey, template + 3) != CKR_OK) {
        DBG("Unable to get public exponent");
        return CKR_KEY_HANDLE_INVALID;
      }

      if (do_encode_rsa_public_key(&session->op_info.op.sign.key, buf, (key_len + 7) / 8, exp, sizeof(exp)) != CKR_OK) {
        return CKR_FUNCTION_FAILED;
      }
    }
    else {
      session->op_info.op.sign.key = NULL;
    }

  }
  else {
    // ECDSA key
    if (get_attribute(session, hKey, template + 4) != CKR_OK) {
      DBG("Unable to get key length");
      return CKR_KEY_HANDLE_INVALID;
    }

    // The buffer contains an uncompressed point of the form 04, len, 04, x, y
    // Where len is |x| + |y| + 1 bytes

    session->op_info.op.sign.key_len = (CK_ULONG) (((buf[1] - 1) / 2) * 8);
    session->op_info.op.sign.sig_len = ((session->op_info.op.sign.key_len + 7) / 8) * 2;

    if (session->op_info.op.sign.key_len == 256)
      session->op_info.op.sign.algo = YKPIV_ALGO_ECCP256;
    else if(session->op_info.op.sign.key_len == 384)
      session->op_info.op.sign.algo = YKPIV_ALGO_ECCP384;
  }

  DBG("Key length is %lu bit", session->op_info.op.sign.key_len);

  session->op_info.op.sign.key_id = piv_2_ykpiv(hKey);
  if (session->op_info.op.sign.key_id == 0) {
    DBG("Incorrect key %lu", hKey);
    return CKR_KEY_HANDLE_INVALID;
  }

  DBG("Algorithm is %d", session->op_info.op.sign.algo);
  // Make sure that both mechanism and key have the same algorithm
  if (!(is_RSA_mechanism(pMechanism->mechanism) && is_rsa_key_algorithm(session->op_info.op.sign.algo)) &&
      !(is_EC_mechanism(pMechanism->mechanism) && is_ec_key_algorithm(session->op_info.op.sign.algo))) {
    DBG("Key and mechanism algorithm do not match");
    return CKR_ARGUMENTS_BAD;
  }

  session->op_info.type = YKCS11_SIGN;

  // TODO: check mechanism parameters and key length and key supported parameters

  if (apply_sign_mechanism_init(&session->op_info) != CKR_OK) {
    DBG("Unable to initialize signing operation");
    return CKR_FUNCTION_FAILED;
  }

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
  ykpiv_rc piv_rv;
  CK_RV    rv;
  size_t   cbSignatureLen = 0;

  DIN;

  if (mutex == NULL) {
    DBG("libykpiv is not initialized or already finalized");
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  ykcs11_session_t* session = get_session(hSession);

  if (session == NULL || session->slot == NULL) {
    DBG("Session is not open");
    rv = CKR_SESSION_HANDLE_INVALID;
    goto sign_out;
  }

  if (get_session_state(session) == CKS_RO_PUBLIC_SESSION ||
      get_session_state(session) == CKS_RW_PUBLIC_SESSION) {
    DBG("User is not logged in");
    rv = CKR_USER_NOT_LOGGED_IN;
    goto sign_out;
  }

  if (session->op_info.type != YKCS11_SIGN) {
    DBG("Signature operation not initialized");
    rv = CKR_OPERATION_NOT_INITIALIZED;
    goto sign_out;
  }

  if (pSignature == NULL) {
    // Just return the size of the signature
    *pulSignatureLen = session->op_info.op.sign.sig_len;
    DBG("The size of the signature will be %lu", *pulSignatureLen);

    DOUT;
    return CKR_OK;
  }

  if (*pulSignatureLen < session->op_info.op.sign.sig_len) {
    DBG("pulSignatureLen too small, signature will not fit, expected %lu, got %lu", 
            session->op_info.op.sign.sig_len, *pulSignatureLen);
    *pulSignatureLen = session->op_info.op.sign.sig_len;
    return CKR_BUFFER_TOO_SMALL;
  }

  DBG("Sending %lu bytes to sign", ulDataLen);
#if YKCS11_DBG
  dump_data(pData, ulDataLen, stderr, CK_TRUE, format_arg_hex);
#endif

  if (is_hashed_mechanism(session->op_info.mechanism.mechanism) == CK_TRUE) {
    if (apply_sign_mechanism_update(&session->op_info, pData, ulDataLen) != CKR_OK) {
      DBG("Unable to perform signing operation step");
      rv = CKR_FUNCTION_FAILED; // TODO: every error in here must stop and clear the signing operation
      goto sign_out;
    }
  }
  else {
    if (is_RSA_mechanism(session->op_info.mechanism.mechanism)) {
      // RSA_X_509
      if (ulDataLen > (session->op_info.op.sign.key_len / 8)) {
          DBG("Data must be shorter than key length (%lu bits)", session->op_info.op.sign.key_len);
          rv = CKR_FUNCTION_FAILED;
          goto sign_out;
      }
    }
    else {
      // ECDSA
      if (is_EC_mechanism(session->op_info.mechanism.mechanism)) {
        if (ulDataLen > 128) {
          // Specs say ECDSA only supports 128 bit
          DBG("Maximum data length for ECDSA is 128 bytes");
          rv = CKR_FUNCTION_FAILED;
          goto sign_out;
        }
      }
    }

    session->op_info.buf_len = ulDataLen;
    memcpy(session->op_info.buf, pData, ulDataLen);
  }

  if (apply_sign_mechanism_finalize(&session->op_info) != CKR_OK) {
    DBG("Unable to finalize signing operation");
    rv = CKR_FUNCTION_FAILED;
    goto sign_out;
  }

  DBG("Using key %x", session->op_info.op.sign.key_id);
  DBG("After padding and transformation there are %lu bytes", session->op_info.buf_len);
#if YKCS11_DBG
  dump_data(session->op_info.buf, session->op_info.buf_len, stderr, CK_TRUE, format_arg_hex);
#endif

  *pulSignatureLen = cbSignatureLen = sizeof(session->op_info.buf);

  locking.LockMutex(session->slot->mutex);

  piv_rv = ykpiv_sign_data(session->slot->piv_state, session->op_info.buf, session->op_info.buf_len, session->op_info.buf, &cbSignatureLen, session->op_info.op.sign.algo, session->op_info.op.sign.key_id);

  locking.UnlockMutex(session->slot->mutex);

  *pulSignatureLen = cbSignatureLen;

  if (piv_rv != YKPIV_OK) {
    if (piv_rv == YKPIV_AUTHENTICATION_ERROR) {
        DBG("Operation requires authentication or touch");
        rv = CKR_USER_NOT_LOGGED_IN;
        goto sign_out;  
    }
    else {
      DBG("Sign error, %s", ykpiv_strerror(piv_rv));
      rv = CKR_FUNCTION_FAILED;
      goto sign_out;
    }
  }

  DBG("Got %lu bytes back", *pulSignatureLen);
#if YKCS11_DBG
  dump_data(session->op_info.buf, *pulSignatureLen, stderr, CK_TRUE, format_arg_hex);
#endif

  if (is_EC_mechanism(session->op_info.mechanism.mechanism)) {
    // ECDSA, we must remove the DER encoding and only return R,S
    // as required by the specs
    strip_DER_encoding_from_ECSIG(session->op_info.buf, pulSignatureLen);

    DBG("After removing DER encoding %lu", *pulSignatureLen);
#if YKCS11_DBG
    dump_data(pSignature, *pulSignatureLen, stderr, CK_TRUE, format_arg_hex);
#endif
  }

  memcpy(pSignature, session->op_info.buf, *pulSignatureLen);

  rv = CKR_OK;

  sign_out:
  session->op_info.type = YKCS11_NOOP;
  sign_mechanism_cleanup(&session->op_info);

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

  if (mutex == NULL) {
    DBG("libykpiv is not initialized or already finalized");
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  ykcs11_session_t* session = get_session(hSession);

  if (session == NULL || session->slot == NULL) {
    DBG("Session is not open");
    rv = CKR_SESSION_HANDLE_INVALID;
    goto sign_out;
  }

  if (session->op_info.type != YKCS11_SIGN) {
    DBG("Signature operation not initialized");
    rv = CKR_OPERATION_NOT_INITIALIZED;
    goto sign_out;
  }

  if (pPart == NULL) {
    DBG("No data provided");
    rv = CKR_ARGUMENTS_BAD;
    goto sign_out;
  }

#if YKCS11_DBG == 1
  dump_data(pPart, ulPartLen, stderr, CK_TRUE, format_arg_hex);
#endif

  if (apply_sign_mechanism_update(&session->op_info, pPart, ulPartLen) != CKR_OK) {
    DBG("Unable to perform signing operation step");
    rv = CKR_FUNCTION_FAILED;
    goto sign_out;
  }

  rv = CKR_OK;

  sign_out:
  if(rv != CKR_OK) {
    session->op_info.type = YKCS11_NOOP;
    sign_mechanism_cleanup(&session->op_info);
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
  ykpiv_rc piv_rv;
  CK_RV    rv;
  size_t   cbSignatureLen = 0;

  DIN;

  if (mutex == NULL) {
    DBG("libykpiv is not initialized or already finalized");
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  ykcs11_session_t* session = get_session(hSession);

  if (session == NULL || session->slot == NULL) {
    DBG("Session is not open");
    rv = CKR_SESSION_HANDLE_INVALID;
    goto sign_out;
  }

  if (get_session_state(session) == CKS_RO_PUBLIC_SESSION ||
      get_session_state(session) == CKS_RW_PUBLIC_SESSION) {
    DBG("User is not logged in");
    rv = CKR_USER_NOT_LOGGED_IN;
    goto sign_out;
  }

  if (session->op_info.type != YKCS11_SIGN) {
    DBG("Signature operation not initialized");
    rv = CKR_OPERATION_NOT_INITIALIZED;
    goto sign_out;
  }

  if (pSignature == NULL) {
    // Just return the size of the signature
    *pulSignatureLen = session->op_info.op.sign.sig_len;
    DBG("The size of the signature will be %lu", *pulSignatureLen);

    DOUT;
    return CKR_OK;
  }

  if (*pulSignatureLen < session->op_info.op.sign.sig_len) {
    DBG("pulSignatureLen too small, signature will not fit, expected %lu, got %lu", 
            session->op_info.op.sign.sig_len, *pulSignatureLen);
    *pulSignatureLen = session->op_info.op.sign.sig_len;
    return CKR_BUFFER_TOO_SMALL;
  }


  if (apply_sign_mechanism_finalize(&session->op_info) != CKR_OK) {
    DBG("Unable to finalize signing operation");
    rv = CKR_FUNCTION_FAILED;
    goto sign_out;
  }

  DBG("Using key %x", session->op_info.op.sign.key_id);
  DBG("After padding and transformation there are %lu bytes", session->op_info.buf_len);
#if YKCS11_DBG == 1
  dump_data(session->op_info.buf, session->op_info.buf_len, stderr, CK_TRUE, format_arg_hex);
#endif

  *pulSignatureLen = cbSignatureLen = sizeof(session->op_info.buf);

  piv_rv = ykpiv_sign_data(session->slot->piv_state, session->op_info.buf, session->op_info.buf_len, session->op_info.buf, &cbSignatureLen, session->op_info.op.sign.algo, session->op_info.op.sign.key_id);

  *pulSignatureLen = cbSignatureLen;

  if (piv_rv != YKPIV_OK) {
    if (piv_rv == YKPIV_AUTHENTICATION_ERROR) {
      DBG("Operation requires authentication or touch");
      rv = CKR_USER_NOT_LOGGED_IN;
      goto sign_out;
    }
    else {
      DBG("Sign error, %s", ykpiv_strerror(piv_rv));
      rv = CKR_FUNCTION_FAILED;
      goto sign_out;
    }
  }

  DBG("Got %lu bytes back", *pulSignatureLen);
#if YKCS11_DBG == 1
  dump_data(session->op_info.buf, *pulSignatureLen, stderr, CK_TRUE, format_arg_hex);
#endif

  if (is_EC_mechanism(session->op_info.mechanism.mechanism)) {
    // ECDSA, we must remove the DER encoding and only return R,S
    // as required by the specs
    strip_DER_encoding_from_ECSIG(session->op_info.buf, pulSignatureLen);

    DBG("After removing DER encoding %lu", *pulSignatureLen);
#if YKCS11_DBG == 1
    dump_data(pSignature, *pulSignatureLen, stderr, CK_TRUE, format_arg_hex);
#endif
  }

  memcpy(pSignature, session->op_info.buf, *pulSignatureLen);
  
  rv = CKR_OK;

  sign_out:
  session->op_info.type = YKCS11_NOOP;
  sign_mechanism_cleanup(&session->op_info);

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
  CK_KEY_TYPE  type = 0;
  CK_ULONG     key_len = 0;
  CK_BYTE      exp[3];
  CK_BYTE      buf[1024] = {0};
  CK_ATTRIBUTE template[] = {
    {CKA_KEY_TYPE, &type, sizeof(type)},
    {CKA_MODULUS_BITS, &key_len, sizeof(key_len)},
    {CKA_EC_POINT, buf, sizeof(buf)},
  };
  
  DIN;

  if (mutex == NULL) {
    DBG("libykpiv is not initialized or already finalized");
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  ykcs11_session_t* session = get_session(hSession);

  if (session == NULL || session->slot == NULL) {
    DBG("Session is not open");
    return CKR_SESSION_HANDLE_INVALID;
  }

  if (!is_present(session, hKey)) {
    DBG("Key handle is invalid");
    return CKR_OBJECT_HANDLE_INVALID;
  }

  if (session->op_info.type != YKCS11_NOOP) {
    DBG("Other operation in process");
    return CKR_OPERATION_ACTIVE;
  }

  if (pMechanism == NULL)
    return CKR_ARGUMENTS_BAD;

  DBG("Trying to verify data with mechanism %lu and key %lu", pMechanism->mechanism, hKey);
  
  // Check if mechanism is supported
  if (check_sign_mechanism(session, pMechanism) != CKR_OK) {
    DBG("Mechanism %lu is not supported either by the token or the module", pMechanism->mechanism);
    return CKR_MECHANISM_INVALID; // TODO: also the key has a list of allowed mechanisms, check that
  }
  memcpy(&session->op_info.mechanism, pMechanism, sizeof(CK_MECHANISM));
  
  //  Get key algorithm
  if (get_attribute(session, hKey, template) != CKR_OK) {
    DBG("Unable to get key type");
    return CKR_KEY_HANDLE_INVALID;
  }
  
  // Get key length and algorithm type
  if (type == CKK_RSA) {
    // RSA key
    if (get_attribute(session, hKey, template + 1) != CKR_OK) {
      DBG("Unable to get key length");
      return CKR_KEY_HANDLE_INVALID;
    }

    session->op_info.op.verify.key_len = key_len;
  } else {
    // ECDSA key
    if (get_attribute(session, hKey, template + 2) != CKR_OK) {
      DBG("Unable to get key length");
      return CKR_KEY_HANDLE_INVALID;
    }

    // The buffer contains an uncompressed point of the form 04, len, 04, x, y
    // Where len is |x| + |y| + 1 bytes
    session->op_info.op.verify.key_len = (CK_ULONG) (((buf[1] - 1) / 2) * 8);    
  }

  DBG("Key length is %lu bit", session->op_info.op.verify.key_len);
  session->op_info.op.verify.key_id = get_key_id(hKey);
  if (session->op_info.op.verify.key_id == 0) {
    DBG("Incorrect key %lu", hKey);
    return CKR_KEY_HANDLE_INVALID;
  }
  
  if (apply_verify_mechanism_init(&session->op_info) != CKR_OK) {
    DBG("Unable to initialize verification operation");
    return CKR_FUNCTION_FAILED;
  }

  if (type == CKK_RSA && is_RSA_sign_mechanism(session->op_info.mechanism.mechanism) ) {
    session->op_info.op.verify.padding = RSA_PKCS1_PADDING;
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
  CK_ULONG siglen;

  DIN;
  
  if (mutex == NULL) {
    DBG("libykpiv is not initialized or already finalized");
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  ykcs11_session_t* session = get_session(hSession);

  if (session == NULL || session->slot == NULL) {
    DBG("Session is not open");
    rv = CKR_SESSION_HANDLE_INVALID;
    goto verify_out;
  }

  if (pData == NULL || pSignature == NULL) {
    DBG("Invalid parameters");
    rv = CKR_ARGUMENTS_BAD;
    goto verify_out;
  }

  if (session->op_info.type != YKCS11_VERIFY) {
    DBG("Signature operation not initialized");
    rv = CKR_OPERATION_NOT_INITIALIZED;
    goto verify_out;
  }

  if (is_RSA_sign_mechanism(session->op_info.mechanism.mechanism)) {
    siglen = (session->op_info.op.verify.key_len + 7) / 8;
  } else if (is_EC_sign_mechanism(session->op_info.mechanism.mechanism)) {
    siglen = ((session->op_info.op.verify.key_len + 7) / 8) * 2;
  } else {
    DBG("Mechanism %lu not supported", session->op_info.mechanism.mechanism);
    rv = CKR_MECHANISM_INVALID;
    goto verify_out;
  }

  if (ulSignatureLen != siglen) {
    DBG("Wrong data length, expected %lu, got %lu", siglen, ulSignatureLen);
    rv = CKR_SIGNATURE_LEN_RANGE;
    goto verify_out;
  }

  rv = apply_verify_mechanism_update(&session->op_info, pData, ulDataLen);
  if (rv != CKR_OK) {
    DBG("Unable to perform verification operation step");
    goto verify_out;
  }

  DBG("Using key %x", session->op_info.op.verify.key_id);

  rv = verify_signature(session, &session->op_info, pSignature, ulSignatureLen);
  if (rv != CKR_OK) {
    DBG("Unable to verify signature");
    goto verify_out;
  }

  DBG("Signature successfully verified");
  rv = CKR_OK;

  verify_out:
  session->op_info.type = YKCS11_NOOP;
  verify_mechanism_cleanup(&session->op_info);

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
  DBG("TODO!!!");
  DOUT;
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_VerifyFinal)(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pSignature,
  CK_ULONG ulSignatureLen
)
{
  DIN;
  DBG("TODO!!!");
  DOUT;
  return CKR_FUNCTION_NOT_SUPPORTED;
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
  CK_ULONG       i;
  CK_ULONG       dobj_id;
  CK_ULONG       cert_id;
  CK_ULONG       pvtk_id;
  CK_ULONG       pubk_id;
  piv_obj_id_t   *obj_ptr;
  CK_BYTE        cert_data[3072];
  CK_ULONG       cert_len;

  DIN;

  if (mutex == NULL) {
    DBG("libykpiv is not initialized or already finalized");
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  ykcs11_session_t* session = get_session(hSession);

  if (session == NULL || session->slot == NULL) {
    DBG("Session is not open");
    return CKR_SESSION_HANDLE_INVALID;
  }

  if (get_session_state(session) != CKS_RW_SO_FUNCTIONS) {
    DBG("Authentication required to generate keys");
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

  gen_info_t gen;

  // Clear values
  gen.key_len = 0;
  gen.key_id = 0;

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

  if (gen.key_len == 0) {
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

  if (gen.rsa) {
    DBG("Generating %lu bit RSA key in object %lu (%lx)", gen.key_len, pvtk_id, piv_2_ykpiv(pvtk_id));
  }
  else {
    DBG("Generating %lu bit EC key in object %lu (%lx)", gen.key_len, pvtk_id, piv_2_ykpiv(pvtk_id));
  }

  locking.LockMutex(session->slot->mutex);

  cert_len = sizeof(cert_data);
  if ((rv = token_generate_key(session->slot->piv_state, gen.rsa, piv_2_ykpiv(pvtk_id), gen.key_len, cert_data, &cert_len)) != CKR_OK) {
    DBG("Unable to generate key pair");
    locking.UnlockMutex(session->slot->mutex);
    return rv;
  }

  locking.UnlockMutex(session->slot->mutex);

  // Check whether we created a new object or updated an existing one
  if (!is_present(session, pvtk_id)) {
    // New object created, add it to the object list
    obj_ptr = session->objects + session->n_objects;
    *obj_ptr++ = dobj_id;
    *obj_ptr++ = cert_id;
    *obj_ptr++ = pvtk_id;
    *obj_ptr++ = pubk_id;
    session->n_objects = obj_ptr - session->objects;
    sort_objects(session);
  }

  // Write/Update the object

  rv = store_data(session, dobj_id, cert_data, cert_len);
  if (rv != CKR_OK) {
    DBG("Unable to store data in session");
    return CKR_FUNCTION_FAILED;
  }

  rv = store_cert(session, cert_id, cert_data, cert_len, CK_TRUE);
  if (rv != CKR_OK) {
    DBG("Unable to store certificate in session");
    return CKR_FUNCTION_FAILED;
  }

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

  if (mutex == NULL) {
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
    RAND_seed(pSeed, ulSeedLen);
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

  if (mutex == NULL) {
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
    if (RAND_bytes(pRandomData, ulRandomLen) == -1) {
      return CKR_GENERAL_ERROR;
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
