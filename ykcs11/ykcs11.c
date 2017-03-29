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
#include "openssl_types.h"
#include "openssl_utils.h"
#include "debug.h"

#include <stdbool.h>
#include "../tool/util.h"

#define YKCS11_MANUFACTURER "Yubico (www.yubico.com)"
#define YKCS11_LIBDESC      "PKCS#11 PIV Library (SP-800-73)"

#define PIV_MIN_PIN_LEN 6
#define PIV_MAX_PIN_LEN 8
#define PIV_MGM_KEY_LEN 48

#define YKCS11_MAX_SLOTS       16
//#define YKCS11_MAX_SIG_BUF_LEN 1024

#define YKCS11_SESSION_ID 5355104

static ykpiv_state *piv_state = NULL;

static ykcs11_slot_t slots[YKCS11_MAX_SLOTS];
static CK_ULONG      n_slots = 0;
static CK_ULONG      n_slots_with_token = 0;

static ykcs11_session_t session;

static struct {
  CK_BBOOL        active;
  CK_ULONG        num;
  CK_ULONG        idx;
  piv_obj_id_t    *objects;
} find_obj;

op_info_t op_info;

extern CK_FUNCTION_LIST function_list;

/* General Purpose */

CK_DEFINE_FUNCTION(CK_RV, C_Initialize)(
  CK_VOID_PTR pInitArgs
)
{
  CK_BYTE readers[2048];
  size_t len = sizeof(readers);

  DIN;

  if (piv_state != NULL)
    return CKR_CRYPTOKI_ALREADY_INITIALIZED;

  if (ykpiv_init(&piv_state, YKCS11_DBG) != YKPIV_OK) {
    DBG("Unable to initialize libykpiv");
    return CKR_FUNCTION_FAILED;
  }

  if (ykpiv_list_readers(piv_state, (char*)readers, &len) != YKPIV_OK) {
    DBG("Unable to list readers");
    return CKR_FUNCTION_FAILED;
  }

  if (parse_readers(piv_state, readers, len, slots, &n_slots, &n_slots_with_token) != CKR_OK)
    return CKR_FUNCTION_FAILED;

  DBG("Found %lu slot(s) of which %lu tokenless/unsupported", n_slots, n_slots - n_slots_with_token);

  find_obj.active = CK_FALSE;
  // TODO: FILL OUT INIT ARGS;

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

  if (piv_state == NULL) {
    DBG("libykpiv is not initialized or already finalized");
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  for (i = 0; i < n_slots; i++) {
    destroy_token(slots + i);
  }
  memset(slots, 0, sizeof(slots));

  ykpiv_done(piv_state);
  piv_state = NULL;

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
  strcpy((char *)pInfo->manufacturerID, YKCS11_MANUFACTURER);

  pInfo->flags = 0;

  memset(pInfo->libraryDescription, ' ', sizeof(pInfo->libraryDescription));
  strcpy((char *)pInfo->libraryDescription, YKCS11_LIBDESC);

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
  int j;

  DIN;

  if (piv_state == NULL) {
    DBG("libykpiv is not initialized or already finalized");
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  if (pulCount) {
    *pulCount = n_slots;

    if (tokenPresent)
      *pulCount = n_slots_with_token;
    else
      *pulCount = n_slots;
  }

  if (pSlotList == NULL_PTR) {
    // Just return the number of slots

    DOUT;
    return CKR_OK;
  }

  if ((tokenPresent && *pulCount < n_slots_with_token) || (!tokenPresent && *pulCount < n_slots)) {
    DBG("Buffer too small: needed %lu, provided %lu", n_slots, *pulCount);
    return CKR_BUFFER_TOO_SMALL;
  }

  for (j = 0, i = 0; i < n_slots; i++) {
    if (tokenPresent) {
      if (has_token(slots + i))
        pSlotList[j++] = i;
    }
    else
      pSlotList[i] = i;
  }

  DBG("token present is %d", tokenPresent);
  DBG("number of slot(s) is %lu", *pulCount);

  DOUT;
  return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_GetSlotInfo)(
  CK_SLOT_ID slotID,
  CK_SLOT_INFO_PTR pInfo
)
{
  DIN;

  if (piv_state == NULL) {
    DBG("libykpiv is not initialized or already finalized");
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  if (slotID >= n_slots) {
    DBG("Invalid slot ID %lu", slotID);
    return CKR_SLOT_ID_INVALID;
  }

  memcpy(pInfo, &slots[slotID].info, sizeof(CK_SLOT_INFO));

  DOUT;
  return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_GetTokenInfo)(
  CK_SLOT_ID slotID,
  CK_TOKEN_INFO_PTR pInfo
)
{
  DIN;

  if (piv_state == NULL) {
    DBG("libykpiv is not initialized or already finalized");
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  if (slotID >= n_slots) {
    DBG("Invalid slot ID %lu", slotID);
    return CKR_SLOT_ID_INVALID;
  }

  if (slots[slotID].vid == UNKNOWN) {
    DBG("No support for slot %lu", slotID);
    return CKR_SLOT_ID_INVALID;
  }

  if (!has_token(slots + slotID)) {
    DBG("Slot %lu has no token inserted", slotID);
    return CKR_TOKEN_NOT_PRESENT;
  }

  if (slots[slotID].token->vid == UNKNOWN) {
    DBG("No support for token in slot %lu", slotID);
    return CKR_TOKEN_NOT_RECOGNIZED;
  }

  memcpy(pInfo, &slots[slotID].token->info, sizeof(CK_TOKEN_INFO));

  // Overwrite values that are application specific
  pInfo->ulMaxSessionCount = CK_UNAVAILABLE_INFORMATION;   // TODO: should this be 1?
  pInfo->ulSessionCount = CK_UNAVAILABLE_INFORMATION;      // number of sessions that this application currently has open with the token
  pInfo->ulMaxRwSessionCount = CK_UNAVAILABLE_INFORMATION; // maximum number of read/write sessions that can be opened with the token at one time by a single TODO: should this be 1?
  pInfo->ulRwSessionCount =  CK_UNAVAILABLE_INFORMATION;   // number of read/write sessions that this application currently has open with the token
  pInfo->ulMaxPinLen = PIV_MAX_PIN_LEN;                    // maximum length in bytes of the PIN
  pInfo->ulMinPinLen = PIV_MIN_PIN_LEN;                    // minimum length in bytes of the PIN
  pInfo->ulTotalPublicMemory = CK_UNAVAILABLE_INFORMATION;
  pInfo->ulFreePublicMemory = CK_UNAVAILABLE_INFORMATION;
  pInfo->ulTotalPrivateMemory = CK_UNAVAILABLE_INFORMATION;
  pInfo->ulFreePrivateMemory = CK_UNAVAILABLE_INFORMATION;

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
  return CKR_FUNCTION_FAILED;
}

CK_DEFINE_FUNCTION(CK_RV, C_GetMechanismList)(
  CK_SLOT_ID slotID,
  CK_MECHANISM_TYPE_PTR pMechanismList,
  CK_ULONG_PTR pulCount
)
{
  token_vendor_t token;
  CK_ULONG count;

  DIN;

  if (piv_state == NULL) {
    DBG("libykpiv is not initialized or already finalized");
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  if (slotID >= n_slots) {
    DBG("Invalid slot ID %lu", slotID);
    return CKR_SLOT_ID_INVALID;
  }

  if (pulCount == NULL_PTR) {
    DBG("Wrong/Missing parameter");
    return CKR_ARGUMENTS_BAD;
  }

  if (slots[slotID].vid == UNKNOWN) {
    DBG("Slot %lu is tokenless/unsupported", slotID);
    return CKR_SLOT_ID_INVALID;
  }

  // TODO: check more return values

  token = get_token_vendor(slots[slotID].vid);

  if (token.get_token_mechanisms_num(&count) != CKR_OK)
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

  if (token.get_token_mechanism_list(pMechanismList, *pulCount) != CKR_OK) {
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
  token_vendor_t token;

  DIN;

  if (piv_state == NULL) {
    DBG("libykpiv is not initialized or already finalized");
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  if (slotID >= n_slots) {
    DBG("Invalid slot ID %lu", slotID);
    return CKR_SLOT_ID_INVALID;
  }

  if (pInfo == NULL_PTR) {
    DBG("Wrong/Missing parameter");
    return CKR_ARGUMENTS_BAD;
  }

  if (slots[slotID].vid == UNKNOWN) {
    DBG("Slot %lu is tokenless/unsupported", slotID);
    return CKR_SLOT_ID_INVALID;
  }

  token = get_token_vendor(slots[slotID].vid);

  if (token.get_token_mechanism_info(type, pInfo) != CKR_OK) {
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
  return CKR_FUNCTION_FAILED;
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
  return CKR_FUNCTION_FAILED;
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
  token_vendor_t token;

  if (piv_state == NULL) {
    DBG("libykpiv is not initialized or already finalized");
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  if (session.handle == CK_INVALID_HANDLE) {
    DBG("User called SetPIN on closed session");
    return CKR_SESSION_CLOSED;
  }

  if (hSession != YKCS11_SESSION_ID) {
    DBG("Unknown session %lu", hSession);
    return CKR_SESSION_HANDLE_INVALID;
  }

  CK_USER_TYPE user_type = CKU_USER;
  if (session.info.state == CKS_RW_SO_FUNCTIONS) {
    user_type = CKU_SO;
  }

  token = get_token_vendor(session.slot->token->vid);
  rv = token.token_change_pin(piv_state, user_type, pOldPin, ulOldLen, pNewPin, ulNewLen);
  if (rv != CKR_OK) {
    DBG("Pin change failed %lx", rv);
    return rv;
  }

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
  token_vendor_t token;
  CK_RV          rv;
  piv_obj_id_t   *cert_ids;
  CK_ULONG       i;
  CK_BYTE        cert_data[3072];  // Max cert value for ykpiv
  CK_ULONG       cert_len = sizeof(cert_data);

  DIN; // TODO: pApplication and Notify

  if (piv_state == NULL) {
    DBG("libykpiv is not initialized or already finalized");
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  if (slotID >= n_slots) {
    DBG("Invalid slot ID %lu", slotID);
    return CKR_SLOT_ID_INVALID;
  }

  if (phSession == NULL_PTR) {
    DBG("Wrong/Missing parameter");
    return CKR_ARGUMENTS_BAD;
  }

  if (slots[slotID].vid == UNKNOWN) {
    DBG("No support for slot %lu", slotID);
    return CKR_TOKEN_NOT_RECOGNIZED;
  }

  if (slots[slotID].token->vid == UNKNOWN) {
    DBG("No support for token in slot %lu", slotID);
    return CKR_TOKEN_NOT_RECOGNIZED;
  }

  if (!has_token(slots + slotID)) {
    DBG("Slot %lu has no token inserted", slotID);
    return CKR_TOKEN_NOT_PRESENT;
  }

  if (session.handle != CK_INVALID_HANDLE) {
    DBG("A session with this or another token already exists");
    return CKR_SESSION_COUNT;
  }

  if ((flags & CKF_SERIAL_SESSION) == 0) {
    DBG("Open session called without CKF_SERIAL_SESSION set"); // Required by specs
    return CKR_SESSION_PARALLEL_NOT_SUPPORTED;
  }

  // Connect to the slot
  if(ykpiv_connect(piv_state, (char *)slots[slotID].info.slotDescription) != YKPIV_OK) {
    DBG("Unable to connect to reader");
    return CKR_FUNCTION_FAILED;
  }

  token = get_token_vendor(slots[slotID].token->vid);

  // Store the slot
  session.slot = slots + slotID;
  //session.slot->info.slotID = slotID; // Redundant but required in CK_SESSION_INFO

  // Store session state
  session.info.state = 0;

  if ((flags & CKF_RW_SESSION)) {
    // R/W Session
    session.info.state = CKS_RW_PUBLIC_SESSION; // Nobody has logged in, default RO session
  }
  else {
    // R/O Session
    session.info.state = CKS_RO_PUBLIC_SESSION; // Nobody has logged in, default RW session
  }

  session.info.slotID = slotID;
  session.info.flags = flags;
  session.info.ulDeviceError = 0;

  // Get the number of token objects
  rv = token.get_token_objects_num(piv_state, &session.slot->token->n_objects, &session.slot->token->n_certs);
  if (rv != CKR_OK) {
    DBG("Unable to retrieve number of token objects");
    return rv;
  }

  // Get memory for the objects
  session.slot->token->objects = malloc(sizeof(piv_obj_id_t) * session.slot->token->n_objects);
  if (session.slot->token->objects == NULL) {
    DBG("Unable to allocate memory for token object ids");
    return CKR_HOST_MEMORY;
  }

  // Get memory for the certificates
  cert_ids = malloc(sizeof(piv_obj_id_t) * session.slot->token->n_certs);
  if (cert_ids == NULL) {
    DBG("Unable to allocate memory for token certificate ids");
    return CKR_HOST_MEMORY;
  }

  // Save a list of all the available objects in the token
  rv = token.get_token_object_list(piv_state, session.slot->token->objects, session.slot->token->n_objects);
  if (rv != CKR_OK) {
    DBG("Unable to retrieve token objects");
    goto failure;
  }

  // Get a list of object ids for available certificates object from the session
  rv = get_available_certificate_ids(&session, cert_ids, session.slot->token->n_certs);
  if (rv != CKR_OK) {
    DBG("Unable to retrieve certificate ids from the session");
    goto failure;
  }

  // Get the actual certificate data from the token and store it as an X509 object
  for (i = 0; i < session.slot->token->n_certs; i++) {
    cert_len = sizeof(cert_data);
    rv = token.get_token_raw_certificate(piv_state, cert_ids[i], cert_data, &cert_len);
    if (rv != CKR_OK) {
      DBG("Unable to get certificate data from token");
      goto failure;
    }

    rv = store_cert(cert_ids[i], cert_data, cert_len);
    if (rv != CKR_OK) {
      DBG("Unable to store certificate data");
      goto failure;
    }
  }

  free(cert_ids);
  cert_ids = NULL;

  session.handle = YKCS11_SESSION_ID;

  *phSession = session.handle;

  DOUT;
  return CKR_OK;

failure:
  if (session.slot->token->objects != NULL) {
    free(session.slot->token->objects);
    session.slot->token->objects = NULL;
  }

  if (cert_ids != NULL) {
    free(cert_ids);
    cert_ids = NULL;
  }

  //free_certs(); // TODO: remove the one allocated so far

  return rv;
}

CK_DEFINE_FUNCTION(CK_RV, C_CloseSession)(
  CK_SESSION_HANDLE hSession
)
{
  DIN;

  if (piv_state == NULL) {
    DBG("libykpiv is not initialized or already finalized");
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  if (session.handle == CK_INVALID_HANDLE) {
    DBG("Trying to close a session, but there is no existing one");
    return CKR_SESSION_CLOSED;
  }

  if (hSession != YKCS11_SESSION_ID) {
    DBG("Unknown session %lu", hSession);
    return CKR_SESSION_HANDLE_INVALID;
  }

  free(session.slot->token->objects);
  session.slot->token->objects = NULL;

  memset(&session, 0, sizeof(ykcs11_session_t));
  session.handle = CK_INVALID_HANDLE;

  ykpiv_disconnect(piv_state);

  DOUT;
  return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_CloseAllSessions)(
  CK_SLOT_ID slotID
)
{
  CK_RV rv;

  DIN;

  if (piv_state == NULL) {
    DBG("libykpiv is not initialized or already finalized");
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  if (session.slot != slots + slotID) {
    DBG("Invalid slot ID %lu", slotID);
    return CKR_SLOT_ID_INVALID;
  }

  rv = C_CloseSession(session.handle);

  DOUT;
  return rv;
}

CK_DEFINE_FUNCTION(CK_RV, C_GetSessionInfo)(
  CK_SESSION_HANDLE hSession,
  CK_SESSION_INFO_PTR pInfo
)
{
  DIN;

  if (piv_state == NULL) {
    DBG("libykpiv is not initialized or already finalized");
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  if (pInfo == NULL) {
    DBG("Wrong/Missing parameter");
    return CKR_ARGUMENTS_BAD;
  }

  if (hSession != session.handle) {
    DBG("Unknown session %lu", hSession);
    return CKR_SESSION_HANDLE_INVALID;
  }

  memcpy(pInfo, &session.info, sizeof(CK_SESSION_INFO));

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
  return CKR_FUNCTION_FAILED;
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
  return CKR_FUNCTION_FAILED;
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
  token_vendor_t token;

  if (piv_state == NULL) {
    DBG("libykpiv is not initialized or already finalized");
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  if (userType != CKU_SO &&
      userType != CKU_USER &&
      userType != CKU_CONTEXT_SPECIFIC)
    return CKR_USER_TYPE_INVALID;

  DBG("user %lu, pin %s, pinlen %lu", userType, pPin, ulPinLen);

  if (session.handle != YKCS11_SESSION_ID) {
    DBG("Session is not open");
    return CKR_SESSION_CLOSED;
  }

  if (hSession != session.handle) {
    DBG("Unknown session %lu", hSession);
    return CKR_SESSION_HANDLE_INVALID;
  }

  if (userType == CKU_SO && (session.info.flags & CKF_RW_SESSION) == 0) { // TODO: make macros for these?
    DBG("Tried to log-in SO user to a read-only session");
    return CKR_SESSION_READ_ONLY_EXISTS;
  }

  token = get_token_vendor(session.slot->token->vid);

  switch (userType) {
  case CKU_USER:
    if (ulPinLen < PIV_MIN_PIN_LEN || ulPinLen > PIV_MAX_PIN_LEN)
      return CKR_ARGUMENTS_BAD;

    /*if (session.info.state == CKS_RW_USER_FUNCTIONS) {
      DBG("This user type is already logged in");
      return CKR_USER_ALREADY_LOGGED_IN;
      }*/ //TODO: FIx to allow multiple login. Decide on context specific.

    if (session.info.state == CKS_RW_SO_FUNCTIONS) {
      DBG("A different uyser type is already logged in");
      return CKR_USER_ANOTHER_ALREADY_LOGGED_IN;
    }

    rv = token.token_login(piv_state, CKU_USER, pPin, ulPinLen);
    if (rv != CKR_OK) {
      DBG("Unable to login as regular user");
      return rv;
    }

    if ((session.info.flags & CKF_RW_SESSION) == 0)
      session.info.state = CKS_RO_USER_FUNCTIONS;
    else
      session.info.state = CKS_RW_USER_FUNCTIONS;
    break;

  case CKU_SO:
    if (ulPinLen != PIV_MGM_KEY_LEN)
      return CKR_ARGUMENTS_BAD;

    if (session.info.state == CKS_RW_SO_FUNCTIONS)
      return CKR_USER_ALREADY_LOGGED_IN;

    if (session.info.state == CKS_RO_USER_FUNCTIONS ||
        session.info.state == CKS_RW_USER_FUNCTIONS)
      return CKR_USER_ANOTHER_ALREADY_LOGGED_IN;

    rv = token.token_login(piv_state, CKU_SO, pPin, ulPinLen);
    if (rv != CKR_OK) {
      DBG("Unable to login as SO");
      return rv;
    }

    session.info.state = CKS_RW_SO_FUNCTIONS;
    break;

  case CKU_CONTEXT_SPECIFIC:
    if (op_info.type == YKCS11_NOOP) {
      DBG("No operation in progress. Context specific user is forbidden.");
      return CKR_USER_TYPE_INVALID;
    }
    if (op_info.type == YKCS11_SIGN) {
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

  if (piv_state == NULL) {
    DBG("libykpiv is not initialized or already finalized");
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  if (session.handle != YKCS11_SESSION_ID) {
    DBG("Session is not open");
    return CKR_SESSION_CLOSED;
  }

  if (hSession != session.handle) {
    DBG("Unknown session %lu", hSession);
    return CKR_SESSION_HANDLE_INVALID;
  }

  if (session.info.state == CKS_RO_PUBLIC_SESSION ||
      session.info.state == CKS_RW_PUBLIC_SESSION)
    return CKR_USER_NOT_LOGGED_IN;

  if ((session.info.flags & CKF_RW_SESSION) == 0)
    session.info.state = CKS_RO_PUBLIC_SESSION;
  else
    session.info.state = CKS_RW_PUBLIC_SESSION;

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
  CK_ULONG         vendor_defined;
  token_vendor_t   token;
  CK_BBOOL         is_new;
  CK_BBOOL         is_rsa;
  CK_OBJECT_HANDLE object;
  CK_ULONG         cert_id;
  CK_ULONG         pvtk_id;
  CK_ULONG         pubk_id;
  piv_obj_id_t     *obj_ptr;

  DIN;

  if (piv_state == NULL) {
    DBG("libykpiv is not initialized or already finalized");
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  if (session.handle != YKCS11_SESSION_ID) {
    DBG("Session is not open");
    return CKR_SESSION_CLOSED;
  }

  if (hSession != session.handle) {
    DBG("Unknown session %lu", hSession);
    return CKR_SESSION_HANDLE_INVALID;
  }

  if (session.info.state != CKS_RW_SO_FUNCTIONS) {
    DBG("Authentication required to import objects");
    return CKR_SESSION_READ_ONLY;
  }

  if (pTemplate == NULL_PTR ||
      phObject == NULL_PTR) {
    DBG("Wrong/Missing parameter");
    return CKR_ARGUMENTS_BAD;
  }

  class = CKO_VENDOR_DEFINED; // Use this as a known value
  for (i = 0; i < ulCount; i++) {
    if (pTemplate[i].type == CKA_CLASS) {
      class = *((CK_ULONG_PTR)pTemplate[i].pValue);

      // Can only import certificates and private keys
      if (*((CK_ULONG_PTR)pTemplate[i].pValue) != CKO_CERTIFICATE &&
          *((CK_ULONG_PTR)pTemplate[i].pValue) != CKO_PRIVATE_KEY) {
        DBG("Unsupported class %lu", class);
        return CKR_ATTRIBUTE_VALUE_INVALID;
      }
    }
  }

  if (class == CKO_VENDOR_DEFINED) {
    DBG("Object class must be specified");
    return CKR_TEMPLATE_INCOMPLETE;
  }

  token = get_token_vendor(session.slot->token->vid);

  switch (class) {
  case CKO_CERTIFICATE:
    DBG("Importing certificate");

    rv = check_create_cert(pTemplate, ulCount, &id, &value, &value_len);
    if (rv != CKR_OK) {
      DBG("Certificate template not valid");
      return rv;
    }
    DBG("Certificate id is %u", id);

    object = PIV_CERT_OBJ_X509_PIV_AUTH + id;

    rv = token.token_import_cert(piv_state, piv_2_ykpiv(object), value); // TODO: make function to get cert id
    if (rv != CKR_OK) {
      DBG("Unable to import certificate");
      return rv;
    }

    is_new = CK_TRUE;
    for (i = 0; i < session.slot->token->n_objects; i++) {
      if (session.slot->token->objects[i] == object)
        is_new = CK_FALSE;
    }

    cert_id = PIV_CERT_OBJ_X509_PIV_AUTH + id; // TODO: make function for these
    pvtk_id = PIV_PVTK_OBJ_PIV_AUTH + id;
    pubk_id = PIV_PUBK_OBJ_PIV_AUTH + id;

    // Check whether we created a new object or updated an existing one
    if (is_new == CK_TRUE) {
      // New object created, add it to the object list

      // Each object counts as three, even if we just only added a certificate
      session.slot->token->n_objects += 3;
      session.slot->token->n_certs++;

      obj_ptr = realloc(session.slot->token->objects, session.slot->token->n_objects * sizeof(piv_obj_id_t));
      if (obj_ptr == NULL) {
        DBG("Unable to store new item in the session");
        return CKR_HOST_MEMORY;
      }
      session.slot->token->objects = obj_ptr;

      obj_ptr = session.slot->token->objects + session.slot->token->n_objects - 3;
      *obj_ptr++ = cert_id;
      *obj_ptr++ = pvtk_id;
      *obj_ptr++ = pubk_id;
    }

    rv = store_cert(cert_id, value, value_len);
    if (rv != CKR_OK) {
      DBG("Unable to store certificate data");
      return CKR_FUNCTION_FAILED;
    }
    *phObject = cert_id;

    break;

  case CKO_PRIVATE_KEY:
    DBG("Importing private key");

    // Try to parse the key as EC
    is_rsa = CK_FALSE;
    rv = check_create_ec_key(pTemplate, ulCount, &id, &ec_data, &ec_data_len, &vendor_defined);
    if (rv != CKR_OK) {
      // Try to parse the key as RSA
      is_rsa = CK_TRUE;
      rv = check_create_rsa_key(pTemplate, ulCount, &id,
                                &p, &p_len,
                                &q, &q_len,
                                &dp, &dp_len,
                                &dq, &dq_len,
                                &qinv, &qinv_len,
                                &vendor_defined);
      if (rv != CKR_OK) {
        DBG("Private key template not valid");
        return rv;
      }
    }

    DBG("Key id is %u", id);

    object = PIV_PVTK_OBJ_PIV_AUTH + id;

    if (is_rsa == CK_TRUE) {
      DBG("Key is RSA");
      rv = token.token_import_private_key(piv_state, piv_2_ykpiv(object),
                                          p, p_len,
                                          q, q_len,
                                          dp, dp_len,
                                          dq, dq_len,
                                          qinv, qinv_len,
                                          NULL, 0,
                                          vendor_defined);
      if (rv != CKR_OK) {
        DBG("Unable to import RSA private key");
        return rv;
      }
    }
    else {
      DBG("Key is ECDSA");
      rv = token.token_import_private_key(piv_state, piv_2_ykpiv(object),
                                          NULL, 0,
                                          NULL, 0,
                                          NULL, 0,
                                          NULL, 0,
                                          NULL, 0,
                                          ec_data, ec_data_len,
                                          vendor_defined);
      if (rv != CKR_OK) {
        DBG("Unable to import ECDSA private key");
        return rv;
      }
    }

    *phObject = PIV_PVTK_OBJ_PIV_AUTH + id;

    break;

  default:
    DBG("Unknown object type");
    return CKR_ATTRIBUTE_TYPE_INVALID;
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
  return CKR_FUNCTION_FAILED;
}

CK_DEFINE_FUNCTION(CK_RV, C_DestroyObject)(
  CK_SESSION_HANDLE hSession,
  CK_OBJECT_HANDLE hObject
)
{
  CK_RV          rv;
  token_vendor_t token;
  CK_ULONG       i;
  CK_ULONG       j;
  CK_BYTE        id;
  CK_ULONG       cert_id;
  CK_ULONG       pvtk_id;
  CK_ULONG       pubk_id;
  piv_obj_id_t   *obj_ptr;

  DIN;

  DBG("Deleting object %lu", hObject);

  if (piv_state == NULL) {
    DBG("libykpiv is not initialized or already finalized");
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  if (session.handle != YKCS11_SESSION_ID) {
    DBG("Session is not open");
    return CKR_SESSION_CLOSED;
  }

  if (hSession != session.handle) {
    DBG("Unknown session %lu", hSession);
    return CKR_SESSION_HANDLE_INVALID;
  }

  // Only certificates can be deleted
  // SO must be logged in
  if (session.info.state != CKS_RW_SO_FUNCTIONS) {
    DBG("Unable to delete objects, SO must be logged in");
    return CKR_USER_NOT_LOGGED_IN;
  }

  rv = check_delete_cert(hObject, &id);
  if (rv != CKR_OK) {
    DBG("Object %lu can not be deleted", hObject);
    return rv;
  }

  token = get_token_vendor(session.slot->token->vid);

  rv = token.token_delete_cert(piv_state, piv_2_ykpiv(hObject));
  if (rv != CKR_OK) {
    DBG("Unable to delete object %lu", hObject);
    return rv;
  }

  // Remove the object from the session
  // Do it in a slightly inefficient way but preserve ordering

  cert_id = PIV_CERT_OBJ_X509_PIV_AUTH + id; // TODO: make function for these
  pvtk_id = PIV_PVTK_OBJ_PIV_AUTH + id;
  pubk_id = PIV_PUBK_OBJ_PIV_AUTH + id;

  obj_ptr = malloc((session.slot->token->n_objects - 3) * sizeof(piv_obj_id_t));
  if (obj_ptr == NULL) {
    DBG("Unable to allocate memory");
    return CKR_HOST_MEMORY;
  }

  i = 0;
  j = 0;
  while (i < session.slot->token->n_objects) {
    if (session.slot->token->objects[i] == cert_id ||
        session.slot->token->objects[i] == pvtk_id ||
        session.slot->token->objects[i] == pubk_id) {
      i++;
      continue;
    }

    obj_ptr[j++] = session.slot->token->objects[i++];
  }

  rv = delete_cert(cert_id);
  if (rv != CKR_OK) {
    DBG("Unable to delete certificate data");
    return CKR_FUNCTION_FAILED;
  }

  free(session.slot->token->objects);

  session.slot->token->n_objects -= 3;
  session.slot->token->n_certs--;
  session.slot->token->objects = obj_ptr;

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
  return CKR_FUNCTION_FAILED;
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

  if (piv_state == NULL) {
    DBG("libykpiv is not initialized or already finalized");
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  if (session.handle != YKCS11_SESSION_ID) {
    DBG("Session is not open");
    return CKR_SESSION_CLOSED;
  }

  if (hSession != session.handle) {
    DBG("Unknown session %lu", hSession);
    return CKR_SESSION_HANDLE_INVALID;
  }

  if (pTemplate == NULL_PTR || ulCount == 0)
    return CKR_ARGUMENTS_BAD;

  rv_final = CKR_OK;
  for (i = 0; i < ulCount; i++) {

    rv = get_attribute(&session, hObject, pTemplate + i);

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
  return CKR_FUNCTION_FAILED;
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

  if (piv_state == NULL) {
    DBG("libykpiv is not initialized or already finalized");
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  if (session.handle != YKCS11_SESSION_ID) {
    DBG("Session is not open");
    return CKR_SESSION_CLOSED;
  }

  if (hSession != session.handle) {
    DBG("Unknown session %lu", hSession);
    return CKR_SESSION_HANDLE_INVALID;
  }

  if (find_obj.active == CK_TRUE)
    return CKR_OPERATION_ACTIVE;

  if (ulCount != 0 && pTemplate == NULL_PTR)
    return CKR_ARGUMENTS_BAD;

  find_obj.idx = 0;
  find_obj.num = session.slot->token->n_objects;

  // Check if we should remove private objects
  if (session.info.state == CKS_RO_PUBLIC_SESSION ||
      session.info.state == CKS_RW_PUBLIC_SESSION) {
    DBG("Removing private objects because state is %lu", session.info.state);
    private = CK_FALSE;
  }
  else {
    DBG("Keeping private objects");
    private = CK_TRUE;
  }

  find_obj.objects = malloc(sizeof(piv_obj_id_t) * find_obj.num);
  if (find_obj.objects == NULL) {
    DBG("Unable to allocate memory for finding objects");
    return CKR_HOST_MEMORY;
  }
  memcpy(find_obj.objects, session.slot->token->objects, sizeof(piv_obj_id_t) * find_obj.num);

  DBG("Initialized search with %lu parameters", ulCount);

  // Match parameters
  total = find_obj.num;
  for (i = 0; i < find_obj.num; i++) {

    if (find_obj.objects[i] == OBJECT_INVALID)
      continue; // Object already discarded, keep going

    // Strip away private objects if needed
    if (private == CK_FALSE)
      if (is_private_object(&session, find_obj.objects[i]) == CK_TRUE) {
        DBG("Stripping away private object %u", find_obj.objects[i]);
        find_obj.objects[i] = OBJECT_INVALID;
        total--;
        continue;
      }

    for (j = 0; j < ulCount; j++) {
      DBG("Parameter %lu\nType: %lu Value: %lu Len: %lu", j, pTemplate[j].type, *((CK_ULONG_PTR)pTemplate[j].pValue), pTemplate[j].ulValueLen);

      if (attribute_match(&session, find_obj.objects[i], pTemplate + j) == CK_FALSE) {
        DBG("Removing object %u from the list", find_obj.objects[i]);
        find_obj.objects[i] = OBJECT_INVALID;  // Object not matching, mark it
        total--;
        break;
      }
      else
        DBG("Keeping object %u in the list", find_obj.objects[i]);
    }
  }

  DBG("%lu object(s) left after attribute matching", total);

  find_obj.active = CK_TRUE;

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

  if (piv_state == NULL) {
    DBG("libykpiv is not initialized or already finalized");
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  if (session.handle != YKCS11_SESSION_ID) {
    DBG("Session is not open");
    return CKR_SESSION_CLOSED;
  }

  if (hSession != session.handle) {
    DBG("Unknown session %lu", hSession);
    return CKR_SESSION_HANDLE_INVALID;
  }

  if (phObject == NULL_PTR ||
      ulMaxObjectCount == 0 ||
      pulObjectCount == NULL_PTR)
    return CKR_ARGUMENTS_BAD;

  if (find_obj.active != CK_TRUE)
    return CKR_OPERATION_NOT_INITIALIZED;

  DBG("Can return %lu object(s)", ulMaxObjectCount);

  // Return the next object, if any
  while(find_obj.idx < find_obj.num &&
        find_obj.objects[find_obj.idx] == OBJECT_INVALID)
    find_obj.idx++;

  if (find_obj.idx == find_obj.num) {
    *pulObjectCount = 0;
    DOUT;
    return CKR_OK;
  }

  *phObject = find_obj.objects[find_obj.idx++];
  *pulObjectCount = 1;

  DBG("Returning object %lu", *phObject);

  return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_FindObjectsFinal)(
  CK_SESSION_HANDLE hSession
)
{
  DIN;

  if (piv_state == NULL) {
    DBG("libykpiv is not initialized or already finalized");
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  if (session.handle != YKCS11_SESSION_ID) {
    DBG("Session is not open");
    return CKR_SESSION_CLOSED;
  }

  if (hSession != session.handle) {
    DBG("Unknown session %lu", hSession);
    return CKR_SESSION_HANDLE_INVALID;
  }

  if (find_obj.active != CK_TRUE)
    return CKR_OPERATION_NOT_INITIALIZED;

  free(find_obj.objects);
  find_obj.objects = NULL;

  find_obj.active = CK_FALSE;

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
  return CKR_FUNCTION_FAILED;
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
  return CKR_FUNCTION_FAILED;
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
  return CKR_FUNCTION_FAILED;
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
  return CKR_FUNCTION_FAILED;
}

CK_DEFINE_FUNCTION(CK_RV, C_DecryptInit)(
  CK_SESSION_HANDLE hSession,
  CK_MECHANISM_PTR pMechanism,
  CK_OBJECT_HANDLE hKey
)
{
  DIN;
  DBG("TODO!!!");
  DOUT;
  return CKR_FUNCTION_FAILED;
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
  DBG("TODO!!!");
  DOUT;
  return CKR_FUNCTION_FAILED;
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
  return CKR_FUNCTION_FAILED;
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
  return CKR_FUNCTION_FAILED;
}

CK_DEFINE_FUNCTION(CK_RV, C_DigestInit)(
  CK_SESSION_HANDLE hSession,
  CK_MECHANISM_PTR pMechanism
)
{
  DIN;

  if (piv_state == NULL) {
    DBG("libykpiv is not initialized or already finalized");
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  if (session.handle != YKCS11_SESSION_ID) {
    DBG("Session is not open");
    return CKR_SESSION_CLOSED;
  }

  if (hSession != session.handle) {
    DBG("Unknown session %lu", hSession);
    return CKR_SESSION_HANDLE_INVALID;
  }

  if (op_info.type != YKCS11_NOOP) {
    DBG("Other operation in process");
    return CKR_OPERATION_ACTIVE;
  }

  if (pMechanism == NULL_PTR) {
    DBG("Wrong/Missing parameter");
    return CKR_ARGUMENTS_BAD;
  }

  DBG("Trying to hash some data with mechanism %lu", pMechanism->mechanism);

  // Check if mechanism is supported
  if (check_hash_mechanism(&session, pMechanism) != CKR_OK) {
    DBG("Mechanism %lu is not supported either by the token or the module", pMechanism->mechanism);
    return CKR_MECHANISM_INVALID;
  }
  memcpy(&op_info.mechanism, pMechanism, sizeof(CK_MECHANISM));

  op_info.type = YKCS11_HASH;

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
  DBG("TODO!!!");
  DOUT;
  return CKR_FUNCTION_FAILED;
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
  return CKR_FUNCTION_FAILED;
}

CK_DEFINE_FUNCTION(CK_RV, C_DigestKey)(
  CK_SESSION_HANDLE hSession,
  CK_OBJECT_HANDLE hKey
)
{
  DIN;
  DBG("TODO!!!");
  DOUT;
  return CKR_FUNCTION_FAILED;
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
  return CKR_FUNCTION_FAILED;
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
  CK_BYTE      buf[1024];
  CK_ATTRIBUTE template[] = {
    {CKA_KEY_TYPE, &type, sizeof(type)},
    {CKA_MODULUS_BITS, &key_len, sizeof(key_len)},
    {CKA_MODULUS, NULL, 0},
    {CKA_PUBLIC_EXPONENT, exp, sizeof(exp)},
    {CKA_EC_POINT, buf, sizeof(buf)},
  };

  DIN;

  if (piv_state == NULL) {
    DBG("libykpiv is not initialized or already finalized");
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  if (session.handle != YKCS11_SESSION_ID) {
    DBG("Session is not open");
    return CKR_SESSION_CLOSED;
  }

  if (hSession != session.handle) {
    DBG("Unknown session %lu", hSession);
    return CKR_SESSION_HANDLE_INVALID;
  }

  if (op_info.type != YKCS11_NOOP) {
    DBG("Other operation in process");
    return CKR_OPERATION_ACTIVE;
  }

  if (pMechanism == NULL_PTR)
    return CKR_ARGUMENTS_BAD;

  DBG("Trying to sign some data with mechanism %lu and key %lu", pMechanism->mechanism, hKey);

  // Check if mechanism is supported
  if (check_sign_mechanism(&session, pMechanism) != CKR_OK) {
    DBG("Mechanism %lu is not supported either by the token or the module", pMechanism->mechanism);
    return CKR_MECHANISM_INVALID; // TODO: also the key has a list of allowed mechanisms, check that
  }
  memcpy(&op_info.mechanism, pMechanism, sizeof(CK_MECHANISM));

  //  Get key algorithm
  if (get_attribute(&session, hKey, template) != CKR_OK) {
    DBG("Unable to get key type");
    return CKR_KEY_HANDLE_INVALID;
  }

  DBG("Key type is %lu\n", type);

  // Get key length and algorithm type
  if (type == CKK_RSA) {
    // RSA key
    if (get_attribute(&session, hKey, template + 1) != CKR_OK) {
      DBG("Unable to get key length");
      return CKR_KEY_HANDLE_INVALID;
    }

    op_info.op.sign.key_len = key_len;

    if (key_len == 1024)
      op_info.op.sign.algo = YKPIV_ALGO_RSA1024;
    else
      op_info.op.sign.algo = YKPIV_ALGO_RSA2048;

    // Also store the raw public key if the mechanism is PSS
    if (is_PSS_mechanism(pMechanism->mechanism)) {
      template[2].pValue = buf;
      template[2].ulValueLen = (key_len + 7) / 8 ;

      if (get_attribute(&session, hKey, template + 2) != CKR_OK) {
        DBG("Unable to get public key");
        return CKR_KEY_HANDLE_INVALID;
      }

      if (get_attribute(&session, hKey, template + 3) != CKR_OK) {
        DBG("Unable to get public exponent");
        return CKR_KEY_HANDLE_INVALID;
      }

      if (do_encode_rsa_public_key(&op_info.op.sign.key, buf, (key_len + 7) / 8, exp, sizeof(exp)) != CKR_OK) {
        return CKR_FUNCTION_FAILED;
      }
    }
    else {
      op_info.op.sign.key = NULL;
    }

  }
  else {
    // ECDSA key
    if (get_attribute(&session, hKey, template + 4) != CKR_OK) {
      DBG("Unable to get key length");
      return CKR_KEY_HANDLE_INVALID;
    }

    // The buffer contains an uncompressed point of the form 04, len, 04, x, y
    // Where len is |x| + |y| + 1 bytes

    op_info.op.sign.key_len = (CK_ULONG) (((buf[1] - 1) / 2) * 8);

    if (op_info.op.sign.key_len == 256)
      op_info.op.sign.algo = YKPIV_ALGO_ECCP256;
    /*else
      op_info.op.sign.algo = YKPIV_ALGO_ECCP384;*/ // TODO: add support for P384
  }

  DBG("Key length is %lu bit", op_info.op.sign.key_len);

  op_info.op.sign.key_id = piv_2_ykpiv(hKey);
  if (op_info.op.sign.key_id == 0) {
    DBG("Incorrect key %lu", hKey);
    return CKR_KEY_HANDLE_INVALID;
  }

  DBG("Algorithm is %d", op_info.op.sign.algo);
  // Make sure that both mechanism and key have the same algorithm
  if ((is_RSA_mechanism(pMechanism->mechanism) && op_info.op.sign.algo == YKPIV_ALGO_ECCP256) ||
      (!is_RSA_mechanism(pMechanism->mechanism) && (op_info.op.sign.algo != YKPIV_ALGO_ECCP256))) {
    DBG("Key and mechanism algorithm do not match");
    return CKR_ARGUMENTS_BAD;
  }

  op_info.type = YKCS11_SIGN;

  // TODO: check mechanism parameters and key length and key supported parameters

  if (apply_sign_mechanism_init(&op_info) != CKR_OK) {
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

  DIN;

  if (op_info.type != YKCS11_SIGN) {
    DBG("Signature operation not initialized");
    rv = CKR_OPERATION_NOT_INITIALIZED;
    goto sign_out;
  }

  if (session.handle != YKCS11_SESSION_ID) {
    DBG("Session is not open");
    rv = CKR_SESSION_CLOSED;
    goto sign_out;
  }

  if (hSession != session.handle) {
    DBG("Unknown session %lu", hSession);
    rv = CKR_SESSION_HANDLE_INVALID;
    goto sign_out;
  }

  if (op_info.type != YKCS11_SIGN) {
    DBG("Operation not initialized");
    rv = CKR_OPERATION_NOT_INITIALIZED;
    goto sign_out;
  }

  if (session.info.state == CKS_RO_PUBLIC_SESSION ||
      session.info.state == CKS_RW_PUBLIC_SESSION) {
    DBG("User is not logged in");
    rv = CKR_USER_NOT_LOGGED_IN;
    goto sign_out;
  }

  if (pSignature == NULL_PTR) {
    // Just return the size of the signature
    if (is_RSA_mechanism(op_info.mechanism.mechanism)) {
      // RSA
       *pulSignatureLen = (op_info.op.sign.key_len + 7) / 8;
    }
    else {
      // ECDSA
      *pulSignatureLen = ((op_info.op.sign.key_len + 7) / 8) * 2;
    }

    DBG("The size of the signature will be %lu", *pulSignatureLen);

    DOUT;
    return CKR_OK;
  }

  DBG("Sending %lu bytes to sign", ulDataLen);
#if YKCS11_DBG == 1
  dump_data(pData, ulDataLen, stderr, CK_TRUE, format_arg_hex);
#endif

  if (is_hashed_mechanism(op_info.mechanism.mechanism) == CK_TRUE) {
    if (apply_sign_mechanism_update(&op_info, pData, ulDataLen) != CKR_OK) {
      DBG("Unable to perform signing operation step");
      rv = CKR_FUNCTION_FAILED; // TODO: every error in here must stop and clear the signing operation
      goto sign_out;
    }
  }
  else {
    if (is_RSA_mechanism(op_info.mechanism.mechanism)) {
      // RSA_X_509
      if (ulDataLen > (op_info.op.sign.key_len / 8)) {
          DBG("Data must be shorter than key length (%lu bits)", op_info.op.sign.key_len);
          rv = CKR_FUNCTION_FAILED;
          goto sign_out;
      }
    }
    else {
      // ECDSA
      if (ulDataLen > 128) {
        // Specs say ECDSA only supports 1024 bit
        DBG("Maximum data length for ECDSA is 128 bytes");
        rv = CKR_FUNCTION_FAILED;
        goto sign_out;
      }
    }

    op_info.buf_len = ulDataLen;
    memcpy(op_info.buf, pData, ulDataLen);
  }

  if (apply_sign_mechanism_finalize(&op_info) != CKR_OK) {
    DBG("Unable to finalize signing operation");
    rv = CKR_FUNCTION_FAILED;
    goto sign_out;
  }

  DBG("Using key %lx", op_info.op.sign.key_id);
  DBG("After padding and transformation there are %lu bytes", op_info.buf_len);
#if YKCS11_DBG == 1
  dump_data(op_info.buf, op_info.buf_len, stderr, CK_TRUE, format_arg_hex);
#endif

  *pulSignatureLen = sizeof(op_info.buf);

  piv_rv = ykpiv_sign_data(piv_state, op_info.buf, op_info.buf_len, pSignature, pulSignatureLen, op_info.op.sign.algo, op_info.op.sign.key_id);
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
  dump_data(pSignature, *pulSignatureLen, stderr, CK_TRUE, format_arg_hex);
#endif

  if (!is_RSA_mechanism(op_info.mechanism.mechanism)) {
    // ECDSA, we must remove the DER encoding and only return R,S
    // as required by the specs
    strip_DER_encoding_from_ECSIG(pSignature, pulSignatureLen);

    DBG("After removing DER encoding %lu", *pulSignatureLen);
#if YKCS11_DBG == 1
    dump_data(pSignature, *pulSignatureLen, stderr, CK_TRUE, format_arg_hex);
#endif
  }

  op_info.type = YKCS11_NOOP;

  rv = CKR_OK;

  sign_out:
  op_info.type = YKCS11_NOOP;
  sign_mechanism_cleanup(&op_info);

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
  DOUT;
  return CKR_FUNCTION_FAILED;
}

CK_DEFINE_FUNCTION(CK_RV, C_SignFinal)(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pSignature,
  CK_ULONG_PTR pulSignatureLen
)
{
  DIN;
  DBG("TODO!!!");
  DOUT;
  return CKR_FUNCTION_FAILED;
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
  return CKR_FUNCTION_FAILED;
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
  return CKR_FUNCTION_FAILED;
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
  return CKR_FUNCTION_FAILED;
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
  return CKR_FUNCTION_FAILED;
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
  return CKR_FUNCTION_FAILED;
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
  return CKR_FUNCTION_FAILED;
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
  return CKR_FUNCTION_FAILED;
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
  return CKR_FUNCTION_FAILED;
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
  return CKR_FUNCTION_FAILED;
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
  return CKR_FUNCTION_FAILED;
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
  return CKR_FUNCTION_FAILED;
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
  return CKR_FUNCTION_FAILED;
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
  return CKR_FUNCTION_FAILED;
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
  token_vendor_t token;
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

  if (piv_state == NULL) {
    DBG("libykpiv is not initialized or already finalized");
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  if (session.handle != YKCS11_SESSION_ID) {
    DBG("Session is not open");
    return CKR_SESSION_CLOSED;
  }

  if (hSession != session.handle) {
    DBG("Unknown session %lu", hSession);
    return CKR_SESSION_HANDLE_INVALID;
  }

  if (session.info.state != CKS_RW_SO_FUNCTIONS) {
    DBG("Authentication required to generate keys");
    return CKR_SESSION_READ_ONLY;
  }

  if (op_info.type != YKCS11_NOOP) {
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
  if ((rv = check_generation_mechanism(&session, pMechanism)) != CKR_OK) {
    DBG("Mechanism %lu is not supported either by the token or the module", pMechanism->mechanism);
    return rv;
  }
  memcpy(&op_info.mechanism, pMechanism, sizeof(CK_MECHANISM));

  // Clear values
  op_info.op.gen.key_len = 0;
  op_info.op.gen.key_id = 0;

  // Check the template for the public key
  if ((rv = check_pubkey_template(&op_info, pPublicKeyTemplate, ulPublicKeyAttributeCount)) != CKR_OK) {
    DBG("Invalid public key template");
    return rv;
  }

  // Check the template for the private key
  if ((rv = check_pvtkey_template(&op_info, pPrivateKeyTemplate, ulPrivateKeyAttributeCount)) != CKR_OK) {
    DBG("Invalid private key template");
    return rv;
  }

  if (op_info.op.gen.key_len == 0) {
    DBG("Key length not specified");
    return CKR_TEMPLATE_INCOMPLETE;
  }

  if (op_info.op.gen.key_id == 0) {
    DBG("Key id not specified");
    return CKR_TEMPLATE_INCOMPLETE;
  }

  if (op_info.op.gen.rsa) {
    DBG("Generating %lu bit RSA key in object %u", op_info.op.gen.key_len, op_info.op.gen.key_id);
  }
  else {
    DBG("Generating %lu bit EC key in object %u", op_info.op.gen.key_len, op_info.op.gen.key_id);
  }

  token = get_token_vendor(session.slot->token->vid);

  if ((rv = token.token_generate_key(piv_state, op_info.op.gen.rsa, piv_2_ykpiv(op_info.op.gen.key_id), op_info.op.gen.key_len, op_info.op.gen.vendor_defined)) != CKR_OK) {
    DBG("Unable to generate key pair");
    return rv;
  }

  is_new = CK_TRUE;
  for (i = 0; i < session.slot->token->n_objects; i++) {
    if (session.slot->token->objects[i] == op_info.op.gen.key_id)
      is_new = CK_FALSE;
  }

  dobj_id = op_info.op.gen.key_id - PIV_PVTK_OBJ_PIV_AUTH; // TODO: make function for these
  cert_id = PIV_DATA_OBJ_LAST + 1 + dobj_id;
  pvtk_id = op_info.op.gen.key_id;
  pubk_id = PIV_PVTK_OBJ_LAST + 1 + dobj_id;

  // Check whether we created a new object or updated an existing one
  if (is_new == CK_TRUE) {
    // New object created, add it to the object list

    // Each object counts as three (data object is always there)
    session.slot->token->n_objects += 3;
    session.slot->token->n_certs++;

    obj_ptr = realloc(session.slot->token->objects, session.slot->token->n_objects * sizeof(piv_obj_id_t));
    if (obj_ptr == NULL) {
      DBG("Unable to store new item in the session");
      return CKR_HOST_MEMORY;
    }
    session.slot->token->objects = obj_ptr;

    obj_ptr = session.slot->token->objects + session.slot->token->n_objects - 3;
    *obj_ptr++ = cert_id;
    *obj_ptr++ = pvtk_id;
    *obj_ptr++ = pubk_id;
  }

  // Write/Update the object
  cert_len = sizeof(cert_data);
  rv = token.get_token_raw_certificate(piv_state, cert_id, cert_data, &cert_len);
  if (rv != CKR_OK) {
    DBG("Unable to get certificate data from token");
    return CKR_FUNCTION_FAILED;
  }

  rv = store_cert(cert_id, cert_data, cert_len);
  if (rv != CKR_OK) {
    DBG("Unable to store certificate data");
    return CKR_FUNCTION_FAILED;
  }

  *phPrivateKey = op_info.op.gen.key_id;
  *phPublicKey  = op_info.op.gen.key_id - PIV_PVTK_OBJ_KM + PIV_PUBK_OBJ_KM; // TODO: make function for these?

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
  return CKR_FUNCTION_FAILED;
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
  return CKR_FUNCTION_FAILED;
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
  return CKR_FUNCTION_FAILED;
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
  return CKR_FUNCTION_FAILED;
}

CK_DEFINE_FUNCTION(CK_RV, C_GenerateRandom)(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pRandomData,
  CK_ULONG ulRandomLen
)
{
  DIN;
  DBG("TODO!!!");
  DOUT;
  return CKR_FUNCTION_FAILED;
}

CK_DEFINE_FUNCTION(CK_RV, C_GetFunctionStatus)(
  CK_SESSION_HANDLE hSession
)
{
  DIN;
  DBG("TODO!!!");
  DOUT;
  return CKR_FUNCTION_FAILED;
}

CK_DEFINE_FUNCTION(CK_RV, C_CancelFunction)(
  CK_SESSION_HANDLE hSession
)
{
  DIN;
  DBG("TODO!!!");
  DOUT;
  return CKR_FUNCTION_FAILED;
}

CK_FUNCTION_LIST function_list = {
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
