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
#include <openssl/rand.h>
#include "debug.h"

#include <stdbool.h>
#include "../tool/util.h"

#define YKCS11_MANUFACTURER "Yubico (www.yubico.com)"
#define YKCS11_LIBDESC      "PKCS#11 PIV Library (SP-800-73)"
#define YKCS11_APPLICATION  "Yubico PIV"

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
    DBG("Unable to create mutex");
    return rv;
  }

  memset(&slots, 0, sizeof(slots));
  memset(&sessions, 0, sizeof(sessions));
  n_slots = 0;

  DOUT;
  return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_Finalize)(
  CK_VOID_PTR pReserved
)
{
  CK_ULONG i;

  DIN;

  if (pReserved != NULL_PTR) {
    DBG("Finalized called with pReserved != NULL");
    return CKR_ARGUMENTS_BAD;
  }

  if (mutex == NULL) {
    DBG("libykpiv is not initialized or already finalized");
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  for(CK_ULONG i = 0; i < n_slots; i++)
    if(slots[i].piv_state)
      ykpiv_done(slots[i].piv_state);

  locking.DestroyMutex(mutex);
  mutex = NULL;

  memset(&slots, 0, sizeof(slots));
  memset(&sessions, 0, sizeof(sessions));
  n_slots = 0;

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

  if(ppFunctionList == NULL_PTR) {
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

  if(pulCount == NULL_PTR) {
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
        ykpiv_init(&slot->piv_state, YKCS11_DBG);
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

        memset(slot->token_info.label, ' ', sizeof(slot->token_info.label));
        memstrcpy(slot->token_info.label, YKCS11_APPLICATION);

        memset(slot->token_info.manufacturerID, ' ', sizeof(slot->token_info.manufacturerID));
        memstrcpy(slot->token_info.manufacturerID, YKCS11_MANUFACTURER);

        memset(slot->token_info.utcTime, ' ', sizeof(slot->token_info.utcTime));

        get_token_model(slot->piv_state, slot->token_info.model, sizeof(slot->token_info.model));
        get_token_serial(slot->piv_state, slot->token_info.serialNumber, sizeof(slot->token_info.serialNumber));
        get_token_version(slot->piv_state, &slot->token_info.firmwareVersion);
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

  locking.UnlockMutex(mutex);

  CK_ULONG count = 0;
  for (i = 0; i < n_slots; i++) {
    if(!tokenPresent || (slots[i].slot_info.flags & CKF_TOKEN_PRESENT)) {
      if(pSlotList) {
        if(count >= *pulCount) {
          DBG("Buffer too small: needed %lu, provided %lu", count, *pulCount);
          return CKR_BUFFER_TOO_SMALL;
        }
        pSlotList[count] = i;
      }
      count++;
    }
  }

  *pulCount = count;

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

  if (pulCount == NULL_PTR) {
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

  if (pMechanismList == NULL_PTR) {
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

  if (pInfo == NULL_PTR) {
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
  DBG("Token initialization unsupported");
  DOUT;
  return CKR_FUNCTION_NOT_SUPPORTED;
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
  CK_RV          rv;

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

  rv = token_change_pin(session->slot->piv_state, user_type, pOldPin, ulOldLen, pNewPin, ulNewLen);
  if (rv != CKR_OK) {
    DBG("Pin change failed %lx", rv);
    return rv;
  }

  DOUT;
  return CKR_OK;
}

static int compare_piv_obj_id(const void *a, const void *b) {

  return (*(piv_obj_id_t*)a - *(piv_obj_id_t*)b);
}

CK_DEFINE_FUNCTION(CK_RV, C_OpenSession)(
  CK_SLOT_ID slotID,
  CK_FLAGS flags,
  CK_VOID_PTR pApplication,
  CK_NOTIFY Notify,
  CK_SESSION_HANDLE_PTR phSession
)
{
  CK_RV          rv;
  CK_ULONG       i;
  CK_BYTE        data[3072];  // Max cert value for ykpiv
  CK_ULONG       len;

  DIN; // TODO: pApplication and Notify

  if (mutex == NULL) {
    DBG("libykpiv is not initialized or already finalized");
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  if (phSession == NULL_PTR) {
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
  session->slot = slots + slotID;

  locking.UnlockMutex(mutex);

  session->info.slotID = slotID;
  session->info.flags = flags;
  session->info.ulDeviceError = 0;
  session->n_objects = 0;

  piv_obj_id_t *obj_ids;
  CK_ULONG num_ids;
  rv = get_token_object_ids(&obj_ids, &num_ids);

  // Save a list of all the available objects in the session

  for(i = 0; i < num_ids; i++) {
    len = sizeof(data);
    if(get_token_object(session->slot->piv_state, obj_ids[i], data, &len) == CKR_OK) {
      session->objects[session->n_objects++] = obj_ids[i];
      rv = store_data(session, obj_ids[i], data, len);
      if (rv != CKR_OK) {
        DBG("Unable to store object data");
        session->slot = NULL;
        goto failure;
      }
      CK_BYTE key_id = get_key_id(obj_ids[i]);
      piv_obj_id_t cert_id = find_cert_object(key_id);
      if(cert_id != (piv_obj_id_t)-1) {
        session->objects[session->n_objects++] = cert_id;
        session->objects[session->n_objects++] = find_pubk_object(key_id);
        session->objects[session->n_objects++] = find_pvtk_object(key_id);
        rv = store_cert(session, cert_id, data, len);
        if (rv != CKR_OK) {
          DBG("Unable to store certificate data");
          session->slot = NULL;
          goto failure;
        }
      }
    }
  }

  qsort(session->objects, session->n_objects, sizeof(piv_obj_id_t), compare_piv_obj_id);

  *phSession = get_session_handle(session);

  DOUT;
  return CKR_OK;

failure:
  //free_certs(); // TODO: remove the one allocated so far

  return rv;
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

  locking.LockMutex(mutex);

  ykcs11_session_t *session = get_session(hSession);

  if (session == NULL || session->slot == NULL) {
    DBG("Trying to close a session, but there is no existing one");
    locking.UnlockMutex(mutex);
    return CKR_SESSION_HANDLE_INVALID;
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

  for(int i = 0; i < YKCS11_MAX_SESSIONS; i++) {
    ykcs11_session_t *session = sessions + i;
    if(session->slot && session->info.slotID == slotID) {
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
    // Multiple logins are allowed because we hard code that CKA_ALWAYS_AUTHENTICATE is always true
    if (ulPinLen < PIV_MIN_PIN_LEN || ulPinLen > PIV_MAX_PIN_LEN)
      return CKR_ARGUMENTS_BAD;

    if (session->slot->login_state == YKCS11_SO) {
      DBG("Tried to log-in USER to a SO session");
      return CKR_USER_ANOTHER_ALREADY_LOGGED_IN;
    }

    rv = token_login(session->slot->piv_state, CKU_USER, pPin, ulPinLen);
    if (rv != CKR_OK) {
      DBG("Unable to login as regular user");
      return rv;
    }

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

    rv = token_login(session->slot->piv_state, CKU_SO, pPin, ulPinLen);
    if (rv != CKR_OK) {
      DBG("Unable to login as SO");
      return rv;
    }

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
  CK_BBOOL         is_new;
  CK_BBOOL         is_rsa;
  CK_ULONG         dobj_id;
  CK_ULONG         cert_id;
  CK_ULONG         pvtk_id;
  CK_ULONG         pubk_id;
  piv_obj_id_t     *obj_ptr;

  DIN;

  if (mutex == NULL) {
    DBG("libykpiv is not initialized or already finalized");
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  if (pTemplate == NULL_PTR ||
      phObject == NULL_PTR) {
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

    cert_id = find_cert_object(id);
    dobj_id = find_data_object(id);
    pvtk_id = find_pvtk_object(id);
    pubk_id = find_pubk_object(id);

    rv = token_import_cert(session->slot->piv_state, piv_2_ykpiv(cert_id), value); // TODO: make function to get cert id
    if (rv != CKR_OK) {
      DBG("Unable to import certificate");
      return rv;
    }

    is_new = CK_TRUE;
    for (i = 0; i < session->n_objects; i++) {
      if (session->objects[i] == cert_id)
        is_new = CK_FALSE;
    }

    // Check whether we created a new object or updated an existing one
    if (is_new == CK_TRUE) {
      // New object created, add it to the object list
      obj_ptr = session->objects + session->n_objects;
      *obj_ptr++ = dobj_id;
      *obj_ptr++ = cert_id;
      *obj_ptr++ = pvtk_id;
      *obj_ptr++ = pubk_id;
      session->n_objects = obj_ptr - session->objects;
      qsort(session->objects, session->n_objects, sizeof(piv_obj_id_t), compare_piv_obj_id);
    }

    rv = store_data(session, dobj_id, value, value_len);
    if (rv != CKR_OK) {
      DBG("Unable to store data in session");
      return CKR_FUNCTION_FAILED;
    }

    rv = store_cert(session, cert_id, value, value_len);
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
        return rv;
      }
    }

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

  rv = token_delete_cert(session->slot->piv_state, piv_2_ykpiv(hObject));
  if (rv != CKR_OK) {
    DBG("Unable to delete object %lu", hObject);
    return rv;
  }

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
  DBG("TODO!!!");
  DOUT;
  return CKR_FUNCTION_NOT_SUPPORTED;
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

  if (pTemplate == NULL_PTR || ulCount == 0)
    return CKR_ARGUMENTS_BAD;

  rv_final = CKR_OK;
  for (i = 0; i < ulCount; i++) {

    rv = get_attribute(session, hObject, pTemplate + i);

    // TODO: this function has some complex cases for return vlaue. Make sure to check them.
    if (rv != CKR_OK) {
      DBG("Unable to get attribute 0x%lx of object %lu", (pTemplate + i)->type, hObject);
      rv_final = rv;
    }
  }

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
  CK_ULONG i;
  CK_ULONG j;
  CK_ULONG total;
  CK_BBOOL private;

  DIN;

  if (ulCount != 0 && pTemplate == NULL_PTR) {
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

  // Check if we should remove private objects
  if (get_session_state(session) == CKS_RO_PUBLIC_SESSION ||
      get_session_state(session) == CKS_RW_PUBLIC_SESSION) {
    DBG("Removing private objects because state is %lu", get_session_state(session));
    private = CK_FALSE;
  }
  else {
    DBG("Keeping private objects");
    private = CK_TRUE;
  }

  session->find_obj.active = CK_TRUE;
  session->find_obj.idx = 0;
  session->find_obj.n_objects = session->n_objects;

  memcpy(session->find_obj.objects, session->objects, session->n_objects * sizeof(piv_obj_id_t));

  DBG("Initialized search with %lu parameters", ulCount);

  // Match parameters
  total = session->find_obj.n_objects;
  for (i = 0; i < session->find_obj.n_objects; i++) {

    if (session->find_obj.objects[i] == OBJECT_INVALID)
      continue; // Object already discarded, keep going

    // Strip away private objects if needed
    if (private == CK_FALSE)
      if (is_private_object(session, session->find_obj.objects[i]) == CK_TRUE) {
        DBG("Stripping away private object %u", session->find_obj.objects[i]);
        session->find_obj.objects[i] = OBJECT_INVALID;
        total--;
        continue;
      }

    for (j = 0; j < ulCount; j++) {
      DBG("Parameter %lu\nType: %lu Value: %lu Len: %lu", j, pTemplate[j].type, *((CK_ULONG_PTR)pTemplate[j].pValue), pTemplate[j].ulValueLen);

      if (attribute_match(session, session->find_obj.objects[i], pTemplate + j) == CK_FALSE) {
        DBG("Removing object %u from the list", session->find_obj.objects[i]);
        session->find_obj.objects[i] = OBJECT_INVALID;  // Object not matching, mark it
        total--;
        break;
      }
      else
        DBG("Keeping object %u in the list", session->find_obj.objects[i]);
    }
  }

  DBG("%lu object(s) left after attribute matching", total);

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

  if (phObject == NULL_PTR ||
      ulMaxObjectCount == 0 ||
      pulObjectCount == NULL_PTR)
    return CKR_ARGUMENTS_BAD;

  if (!session->find_obj.active)
    return CKR_OPERATION_NOT_INITIALIZED;

  DBG("Can return %lu object(s)", ulMaxObjectCount);
  *pulObjectCount = 0;

  // Return the next object, if any
  while(session->find_obj.idx < session->find_obj.n_objects && *pulObjectCount < ulMaxObjectCount) {
    if(session->find_obj.objects[session->find_obj.idx] != OBJECT_INVALID) {
      *phObject++ = session->find_obj.objects[session->find_obj.idx];
      (*pulObjectCount)++;
    }
    session->find_obj.idx++;
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

  if (session->op_info.type != YKCS11_NOOP) {
    DBG("Other operation in process");
    return CKR_OPERATION_ACTIVE;
  }

  if (pMechanism == NULL_PTR)
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

  DBG("Key type is %lu\n", type);

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

  // NOTE: datalen is just an approximation here since the data is encrypted
  CK_ULONG datalen;
  if (check_rsa_decrypt_mechanism(session, &(session->op_info.mechanism)) != CKR_OK) {
    DBG("Mechanism %lu not supported", session->op_info.mechanism.mechanism);
    rv = CKR_MECHANISM_INVALID;
    goto decrypt_out;
  } else {
    datalen = (session->op_info.op.decrypt.key_len + 7) / 8 - 11;
  }
  DBG("The size of the data will be %lu", datalen);

  if (pData == NULL_PTR) {
    // Just return the size of the decrypted data
    *pulDataLen = datalen;
    DBG("The size of the signature will be %lu", *pulSignatureLen);
    DOUT;
    return CKR_OK;
  }

  DBG("Sending %lu bytes to be decrypted", ulEncryptedDataLen);
#if YKCS11_DBG == 1
  dump_data(pEncryptedData, ulEncryptedDataLen, stderr, CK_TRUE, format_arg_hex);
#endif

  session->op_info.buf_len = ulEncryptedDataLen;
  memcpy(session->op_info.buf, pEncryptedData, ulEncryptedDataLen);

  DBG("Using key %04x for decryption", session->op_info.op.decrypt.key_id);

  *pulDataLen = cbDataLen = sizeof(session->op_info.buf);

  piv_rv = ykpiv_decipher_data(session->slot->piv_state, session->op_info.buf, session->op_info.buf_len, 
                               session->op_info.buf, &cbDataLen, 
                               session->op_info.op.decrypt.algo, session->op_info.op.decrypt.key_id);

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
#if YKCS11_DBG == 1
  dump_data(op_info.buf, *pulDataLen, stderr, CK_TRUE, format_arg_hex);
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

  if (pMechanism == NULL_PTR) {
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
    {CKA_MODULUS, NULL, 0},
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

  if (session->op_info.type != YKCS11_NOOP) {
    DBG("Other operation in process");
    return CKR_OPERATION_ACTIVE;
  }

  if (pMechanism == NULL_PTR)
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

  DBG("Key type is %lu\n", type);

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
      template[2].pValue = buf;
      template[2].ulValueLen = (key_len + 7) / 8;

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

  if (pSignature == NULL_PTR) {
    // Just return the size of the signature
    *pulSignatureLen = session->op_info.op.sign.sig_len;
    DBG("The size of the signature will be %lu", *pulSignatureLen);

    DOUT;
    return CKR_OK;
  }

  if (*pulSignatureLen < session->op_info.op.sign.sig_len) {
    DBG("pulSignatureLen too small, signature will not fit, expected %u, got %lu", 
            session->op_info.op.sign.sig_len, *pulSignatureLen);
    *pulSignatureLen = session->op_info.op.sign.sig_len;
    return CKR_BUFFER_TOO_SMALL;
  }

  DBG("Sending %lu bytes to sign", ulDataLen);
#if YKCS11_DBG == 1
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

  DBG("Using key %lx", session->op_info.op.sign.key_id);
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
  dump_data(op_info.buf, *pulSignatureLen, stderr, CK_TRUE, format_arg_hex);
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

CK_DEFINE_FUNCTION(CK_RV, C_SignUpdate)(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pPart,
  CK_ULONG ulPartLen
)
{
  DIN;
  DBG("TODO!!!");

  ykcs11_session_t* session = get_session(hSession);

  if (session == NULL || session->slot == NULL) {
    DBG("Session is not open");
    return CKR_SESSION_HANDLE_INVALID;
  }

  if(session->op_info.type == YKCS11_SIGN) {
    session->op_info.type = YKCS11_NOOP;
    sign_mechanism_cleanup(&session->op_info);
  }

  DOUT;
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_SignFinal)(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pSignature,
  CK_ULONG_PTR pulSignatureLen
)
{
  DIN;
  DBG("TODO!!!");

  ykcs11_session_t* session = get_session(hSession);

  if (session == NULL || session->slot == NULL) {
    DBG("Session is not open");
    return CKR_SESSION_HANDLE_INVALID;
  }

  if(session->op_info.type == YKCS11_SIGN) {
    session->op_info.type = YKCS11_NOOP;
    sign_mechanism_cleanup(&session->op_info);
  }
  
  DOUT;
  return CKR_FUNCTION_NOT_SUPPORTED;
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
  DBG("TODO!!!");
  DOUT;
  return CKR_FUNCTION_NOT_SUPPORTED;
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
  DBG("TODO!!!");
  DOUT;
  return CKR_FUNCTION_NOT_SUPPORTED;
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
  CK_BBOOL       is_new;
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

  if (pMechanism == NULL_PTR ||
      pPublicKeyTemplate == NULL_PTR ||
      pPrivateKeyTemplate == NULL_PTR ||
      phPublicKey == NULL_PTR ||
      phPrivateKey == NULL_PTR) {
    DBG("Wrong/Missing parameter");
    return CKR_ARGUMENTS_BAD;
  }

  DBG("Trying to generate a key pair with mechanism %lx", pMechanism->mechanism);

  DBG("Found %lu attributes for the public key and %lu attributes for the private key", ulPublicKeyAttributeCount, ulPrivateKeyAttributeCount);

  // Check if mechanism is supported
  if ((rv = check_generation_mechanism(session, pMechanism)) != CKR_OK) {
    DBG("Mechanism %lu is not supported either by the token or the module", pMechanism->mechanism);
    return rv;
  }
  memcpy(&session->op_info.mechanism, pMechanism, sizeof(CK_MECHANISM));

  // Clear values
  session->op_info.op.gen.key_len = 0;
  session->op_info.op.gen.key_id = 0;

  // Check the template for the public key
  if ((rv = check_pubkey_template(&session->op_info, pPublicKeyTemplate, ulPublicKeyAttributeCount)) != CKR_OK) {
    DBG("Invalid public key template");
    return rv;
  }

  // Check the template for the private key
  if ((rv = check_pvtkey_template(&session->op_info, pPrivateKeyTemplate, ulPrivateKeyAttributeCount)) != CKR_OK) {
    DBG("Invalid private key template");
    return rv;
  }

  if (session->op_info.op.gen.key_len == 0) {
    DBG("Key length not specified");
    return CKR_TEMPLATE_INCOMPLETE;
  }

  if (session->op_info.op.gen.key_id == 0) {
    DBG("Key id not specified");
    return CKR_TEMPLATE_INCOMPLETE;
  }

  dobj_id = find_data_object(session->op_info.op.gen.key_id);
  cert_id = find_cert_object(session->op_info.op.gen.key_id);
  pvtk_id = find_pvtk_object(session->op_info.op.gen.key_id);
  pubk_id = find_pubk_object(session->op_info.op.gen.key_id);

  if (session->op_info.op.gen.rsa) {
    DBG("Generating %lu bit RSA key in object %lu (%lx)", session->op_info.op.gen.key_len, pvtk_id, piv_2_ykpiv(pvtk_id));
  }
  else {
    DBG("Generating %lu bit EC key in object %lu (%lx)", session->op_info.op.gen.key_len, pvtk_id, piv_2_ykpiv(pvtk_id));
  }

  if ((rv = token_generate_key(session->slot->piv_state, session->op_info.op.gen.rsa, piv_2_ykpiv(pvtk_id), session->op_info.op.gen.key_len)) != CKR_OK) {
    DBG("Unable to generate key pair");
    return rv;
  }

  is_new = CK_TRUE;
  for (i = 0; i < session->n_objects; i++) {
    if (session->objects[i] == pvtk_id)
      is_new = CK_FALSE;
  }

  // Check whether we created a new object or updated an existing one
  if (is_new == CK_TRUE) {
    // New object created, add it to the object list
    obj_ptr = session->objects + session->n_objects;
    *obj_ptr++ = dobj_id;
    *obj_ptr++ = cert_id;
    *obj_ptr++ = pvtk_id;
    *obj_ptr++ = pubk_id;
    session->n_objects = obj_ptr - session->objects;
    qsort(session->objects, session->n_objects, sizeof(piv_obj_id_t), compare_piv_obj_id);
  }

  // Write/Update the object
  cert_len = sizeof(cert_data);
  rv = get_token_object(session->slot->piv_state, dobj_id, cert_data, &cert_len);
  if (rv != CKR_OK) {
    DBG("Unable to get data from token");
    return CKR_FUNCTION_FAILED;
  }

  rv = store_data(session, dobj_id, cert_data, cert_len);
  if (rv != CKR_OK) {
    DBG("Unable to store data in session");
    return CKR_FUNCTION_FAILED;
  }

  rv = store_cert(session, cert_id, cert_data, cert_len);
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
  DBG("TODO!!!");
  DOUT;
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_GenerateRandom)(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pRandomData,
  CK_ULONG ulRandomLen
)
{
  
  if (mutex == NULL) {
    DBG("libykpiv is not initialized or already finalized");
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  size_t len = ulRandomLen;
  if (len != ulRandomLen || pRandomData == NULL) {
    DBG("Invalid parameter");
    return CKR_ARGUMENTS_BAD;
  }

  ykcs11_session_t* session = get_session(hSession);

  if (session == NULL || session->slot == NULL) {
    DBG("Session is not open");
    return CKR_SESSION_HANDLE_INVALID;
  }

  CK_RV rv = CKR_OK;

// the OpenSC pkcs11 test calls with 0 and expects CKR_OK, do that..
if (len > 0) {
  if (RAND_bytes(pRandomData, len) == -1) {
    rv = CKR_GENERAL_ERROR;
  }
}
  
if (len != ulRandomLen) {
  DBG("Incorrect amount of data returned");
  rv = CKR_FUNCTION_FAILED;
}

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
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_CancelFunction)(
  CK_SESSION_HANDLE hSession
)
{
  DIN;
  DBG("TODO!!!");
  DOUT;
  return CKR_FUNCTION_NOT_SUPPORTED;
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
