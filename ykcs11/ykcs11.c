#include "pkcs11.h"
#include <stdio.h>
#include <ykpiv.h>
#include <string.h>
#include "vendors.h"
#include "utils.h"

#define D(x) do {                                                     \
    printf ("debug: %s:%d (%s): ", __FILE__, __LINE__, __FUNCTION__); \
    printf x;                                                         \
    printf ("\n");                                                    \
  } while (0)

#define YKCS11_DBG    1  // General debug, must be either 1 or 0
#define YKCS11_DINOUT 1  // Function in/out debug, must be either 1 or 0

#define YKCS11_MANUFACTURER "Yubico (www.yubico.com)"
#define YKCS11_LIBDESC      "PKCS#11 PIV Library (SP-800-73)"

#define PIV_MIN_PIN_LEN 6
#define PIV_MAX_PIN_LEN 8

#define YKCS11_MAX_SLOTS 16

#if YKCS11_DBG
#define DBG(x) D(x);
#else
#define DBG(x)
#endif

#if YKCS11_DINOUT
#define DIN D(("In"));
#define DOUT D(("Out"));
#else
#define DIN
#define DOUT
#endif

static ykpiv_state *piv_state = NULL;

static ykcs11_slot_t slots[YKCS11_MAX_SLOTS];
static CK_ULONG      n_slots = 0;
static CK_ULONG      n_tokenless_slots = 0;

extern CK_FUNCTION_LIST function_list;

/* General Purpose */

CK_DEFINE_FUNCTION(CK_RV, C_Initialize)(
  CK_VOID_PTR pInitArgs
)
{
  DIN;
  CK_CHAR_PTR readers;
  CK_ULONG len;

  // TODO: check for locks and mutexes

  if (piv_state != NULL)
    return CKR_CRYPTOKI_ALREADY_INITIALIZED;

  if (ykpiv_init(&piv_state, YKCS11_DBG) != YKPIV_OK) {
    DBG(("Unable to initialize YubiKey"));
    return CKR_FUNCTION_FAILED; // TODO: better error?
  }

  if(ykpiv_connect2(piv_state, NULL, &readers, &len) != YKPIV_OK) {
    DBG(("Unable to connect to reader"));
    return CKR_FUNCTION_FAILED;
  }

  parse_readers(readers, len, slots, &n_slots, &n_tokenless_slots);
  DBG(("Found %lu slot(s) of which %lu tokenless/unsupported", n_slots, n_tokenless_slots));

  DOUT;
  return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_Finalize)(
  CK_VOID_PTR pReserved
)
{
  DIN;
  if (pReserved != NULL_PTR) {
    DBG(("Finalized called with pReserved != NULL"));
    return CKR_ARGUMENTS_BAD;
  }

  if (piv_state == NULL) {
    DBG(("libykpiv is not initialized or already finalized"));
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  memset(slots, 0, sizeof(slots));
  
  ykpiv_done(piv_state); // TODO: this calls disconnect...
  piv_state == NULL;

  DOUT;
  return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_GetInfo)(
  CK_INFO_PTR pInfo
)
{
  DIN;
  CK_VERSION ver = {0, 0}; // TODO: set version number
  pInfo->cryptokiVersion = function_list.version;

  memset(pInfo->manufacturerID, ' ', sizeof(pInfo->manufacturerID));
  strcpy(pInfo->manufacturerID, YKCS11_MANUFACTURER);

  pInfo->flags = 0;

  memset(pInfo->libraryDescription, ' ', sizeof(pInfo->libraryDescription));
  strcpy(pInfo->libraryDescription, YKCS11_LIBDESC);

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
    DBG(("GetFunctionList called with ppFunctionList = NULL"));
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
  DIN;
  int i;
  int j;

  //ykpiv_get_reader_slot_number(piv_state, &n_readers, &tot_reader_len); // TODO: maybe refactor this with a reader struct?
  if (pSlotList == NULL_PTR) {
    // Just return the number of slots
    *pulCount = n_slots;

    if (tokenPresent)
      *pulCount = n_tokenless_slots;
    else
      *pulCount = n_slots;

    DOUT;
    return CKR_OK;
  }

  if ((tokenPresent && *pulCount < n_tokenless_slots) || (!tokenPresent && *pulCount < n_slots)) {
    DBG(("Buffer too small: needed %lu, provided %lu", n_slots, *pulCount));
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

  DBG(("token present is %d", tokenPresent));
  DBG(("number of slot(s) is %lu", *pulCount));

  DOUT;
  return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_GetSlotInfo)(
  CK_SLOT_ID slotID,
  CK_SLOT_INFO_PTR pInfo
)
{
  DIN;

  if (piv_state == NULL)
    return CKR_CRYPTOKI_NOT_INITIALIZED;

  if (slotID >= n_slots)
    return CKR_ARGUMENTS_BAD;

  memcpy(pInfo, &slots[slotID].info, sizeof(CK_SLOT_INFO));

  //DBG(("slotID %lu, pInfo %s", slotID, pInfo->slotDescription));

  DOUT;
  return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_GetTokenInfo)(
  CK_SLOT_ID slotID,
  CK_TOKEN_INFO_PTR pInfo
)
{
  DIN;
  CK_VERSION      ver = {0, 0};
  vendor_id_t     vid;
  vendor_t        vendor;
  CK_BYTE         buf[64];
  CK_UTF8CHAR_PTR p;
  CK_BYTE         len;

  if (piv_state == NULL)
    return CKR_CRYPTOKI_NOT_INITIALIZED;

  if (slotID >= n_slots)
    return CKR_ARGUMENTS_BAD;

  vid = slots[slotID].vid;

  if (vid == UNKNOWN) {
    DBG(("No support for token in slot %lu", slotID));
    return CKR_TOKEN_NOT_RECOGNIZED;
  }

  if (!has_token(slots + slotID)) {
    DBG(("Slot %lu has no token inserted", slotID));
    return CKR_TOKEN_NOT_PRESENT;
  }
  
  vendor = get_vendor(vid); // TODO: make a token field in slot_t ?

  memset(pInfo->label, ' ', sizeof(pInfo->label));
  p = vendor.get_token_label();
  len = strlen(p);
  strncpy(pInfo->label, p, len);

  memset(pInfo->manufacturerID, ' ', sizeof(pInfo->manufacturerID));
  p = vendor.get_token_manufacturer();
  len = strlen(p);
  strncpy(pInfo->manufacturerID, p, len);

  memset(pInfo->model, ' ', sizeof(pInfo->model));
  p = vendor.get_token_model();
  len = strlen(p);
  strncpy(pInfo->model, p, len);

  memset(pInfo->serialNumber, ' ', sizeof(pInfo->serialNumber));
  p = vendor.get_token_serial();
  len = strlen(p);
  strncpy(pInfo->serialNumber, p, len);

  pInfo->flags = vendor.get_token_flags(); // bit flags indicating capabilities and status of the device as defined below

  pInfo->ulMaxSessionCount = CK_UNAVAILABLE_INFORMATION; // TODO: should this be 1?

  pInfo->ulSessionCount = CK_UNAVAILABLE_INFORMATION; // number of sessions that this application currently has open with the token

  pInfo->ulMaxRwSessionCount = CK_UNAVAILABLE_INFORMATION; // maximum number of read/write sessions that can be opened with the token at one time by a single TODO: should this be 1?

  pInfo->ulRwSessionCount =  CK_UNAVAILABLE_INFORMATION; // number of read/write sessions that this application currently has open with the token

  pInfo->ulMaxPinLen = PIV_MAX_PIN_LEN; // maximum length in bytes of the PIN

  pInfo->ulMinPinLen = PIV_MIN_PIN_LEN; // minimum length in bytes of the PIN

  pInfo->ulTotalPublicMemory = CK_UNAVAILABLE_INFORMATION;

  pInfo->ulFreePublicMemory = CK_UNAVAILABLE_INFORMATION;

  pInfo->ulTotalPrivateMemory = CK_UNAVAILABLE_INFORMATION;

  pInfo->ulFreePrivateMemory = CK_UNAVAILABLE_INFORMATION;

  ykpiv_get_version(piv_state, buf, sizeof(buf));
  ver = vendor.get_token_version(buf, strlen(buf));

  pInfo->hardwareVersion = ver; // version number of hardware

  pInfo->firmwareVersion = ver; // version number of firmware

  memset(pInfo->utcTime, ' ', sizeof(pInfo->utcTime)); // No clock present, clear

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
  DBG(("TODO!!!"));
  DOUT;
  return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_GetMechanismList)(
  CK_SLOT_ID slotID,
  CK_MECHANISM_TYPE_PTR pMechanismList,
  CK_ULONG_PTR pulCount
)
{
  DIN;

  int i;

  if (pMechanismList == NULL_PTR) {
    // Just return the number of mechanisms
    *pulCount = 3;
    DOUT;
    return CKR_OK;
  }

  if (*pulCount < 3) {
    DBG(("Buffer too small: needed %lu, provided %lu", 1l, *pulCount));
    return CKR_BUFFER_TOO_SMALL;
  }

  for (i = 0; i < 3; i++) {
    pMechanismList[i] = CKM_SHA_1;
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
  DBG(("TODO!!!"));
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

  return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_InitPIN)(
  CK_SESSION_HANDLE hSession,
  CK_UTF8CHAR_PTR pPin,
  CK_ULONG ulPinLen
)
{
  DIN;
  DBG(("TODO!!!"));
  DOUT;
  return CKR_OK;
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
  DBG(("TODO!!!"));
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
  DIN;
  DBG(("TODO!!!"));
  DOUT;
  return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_CloseSession)(
  CK_SESSION_HANDLE hSession
)
{
  DIN;
  DBG(("TODO!!!"));
  DOUT;
  return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_CloseAllSessions)(
  CK_SLOT_ID slotID
)
{
  DIN;
  DBG(("TODO!!!"));
  DOUT;
  return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_GetSessionInfo)(
  CK_SESSION_HANDLE hSession,
  CK_SESSION_INFO_PTR pInfo
)
{
  DIN;
  DBG(("TODO!!!"));
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
  DBG(("TODO!!!"));
  DOUT;
  return CKR_OK;
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
  DBG(("TODO!!!"));
  DOUT;
  return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_Login)(
  CK_SESSION_HANDLE hSession,
  CK_USER_TYPE userType,
  CK_UTF8CHAR_PTR pPin,
  CK_ULONG ulPinLen
)
{
  DIN;
  DBG(("TODO!!!"));
  DOUT;
  return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_Logout)(
  CK_SESSION_HANDLE hSession
)
{
  DIN;
  DBG(("TODO!!!"));
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
  DIN;
  DBG(("TODO!!!"));
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
  DBG(("TODO!!!"));
  DOUT;
  return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_DestroyObject)(
  CK_SESSION_HANDLE hSession,
  CK_OBJECT_HANDLE hObject
)
{
  DIN;
  DBG(("TODO!!!"));
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
  DBG(("TODO!!!"));
  DOUT;
  return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_GetAttributeValue)(
  CK_SESSION_HANDLE hSession,
  CK_OBJECT_HANDLE hObject,
  CK_ATTRIBUTE_PTR pTemplate,
  CK_ULONG ulCount
)
{
  DIN;
  DBG(("TODO!!!"));
  DOUT;
  return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_SetAttributeValue)(
  CK_SESSION_HANDLE hSession,
  CK_OBJECT_HANDLE hObject,
  CK_ATTRIBUTE_PTR pTemplate,
  CK_ULONG ulCount
)
{
  DIN;
  DBG(("TODO!!!"));
  DOUT;
  return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_FindObjectsInit)(
  CK_SESSION_HANDLE hSession,
  CK_ATTRIBUTE_PTR pTemplate,
  CK_ULONG ulCount
)
{
  DIN;
  DBG(("TODO!!!"));
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
  DBG(("TODO!!!"));
  DOUT;
  return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_FindObjectsFinal)(
  CK_SESSION_HANDLE hSession
)
{
  DIN;
  DBG(("TODO!!!"));
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
  DBG(("TODO!!!"));
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
  DIN;
  DBG(("TODO!!!"));
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
  DBG(("TODO!!!"));
  DOUT;
  return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_EncryptFinal)(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pLastEncryptedPart,
  CK_ULONG_PTR pulLastEncryptedPartLen
)
{
  DIN;
  DBG(("TODO!!!"));
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
  DBG(("TODO!!!"));
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
  DIN;
  DBG(("TODO!!!"));
  DOUT;
  return CKR_OK;
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
  DBG(("TODO!!!"));
  DOUT;
  return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_DecryptFinal)(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pLastPart,
  CK_ULONG_PTR pulLastPartLen
)
{
  DIN;
  DBG(("TODO!!!"));
  DOUT;
  return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_DigestInit)(
  CK_SESSION_HANDLE hSession,
  CK_MECHANISM_PTR pMechanism
)
{
  DIN;
  DBG(("TODO!!!"));
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
  DBG(("TODO!!!"));
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
  DBG(("TODO!!!"));
  DOUT;
  return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_DigestKey)(
  CK_SESSION_HANDLE hSession,
  CK_OBJECT_HANDLE hKey
)
{
  DIN;
  DBG(("TODO!!!"));
  DOUT;
  return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_DigestFinal)(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pDigest,
  CK_ULONG_PTR pulDigestLen
)
{
  DIN;
  DBG(("TODO!!!"));
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
  DBG(("TODO!!!"));
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
  DIN;
  DBG(("TODO!!!"));
  DOUT;
  return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_SignUpdate)(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pPart,
  CK_ULONG ulPartLen
)
{
  DIN;
  DBG(("TODO!!!"));
  DOUT;
  return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_SignFinal)(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pSignature,
  CK_ULONG_PTR pulSignatureLen
)
{
  DIN;
  DBG(("TODO!!!"));
  DOUT;
  return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_SignRecoverInit)(
  CK_SESSION_HANDLE hSession,
  CK_MECHANISM_PTR pMechanism,
  CK_OBJECT_HANDLE hKey
)
{
  DIN;
  DBG(("TODO!!!"));
  DOUT;
  return CKR_OK;
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
  DBG(("TODO!!!"));
  DOUT;
  return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_VerifyInit)(
  CK_SESSION_HANDLE hSession,
  CK_MECHANISM_PTR pMechanism,
  CK_OBJECT_HANDLE hKey
)
{
  DIN;
  DBG(("TODO!!!"));
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
  DIN;
  DBG(("TODO!!!"));
  DOUT;
  return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_VerifyUpdate)(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pPart,
  CK_ULONG ulPartLen
)
{
  DIN;
  DBG(("TODO!!!"));
  DOUT;
  return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_VerifyFinal)(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pSignature,
  CK_ULONG ulSignatureLen
)
{
  DIN;
  DBG(("TODO!!!"));
  DOUT;
  return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_VerifyRecoverInit)(
  CK_SESSION_HANDLE hSession,
  CK_MECHANISM_PTR pMechanism,
  CK_OBJECT_HANDLE hKey
)
{
  DIN;
  DBG(("TODO!!!"));
  DOUT;
  return CKR_OK;
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
  DBG(("TODO!!!"));
  DOUT;
  return CKR_OK;
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
  DBG(("TODO!!!"));
  DOUT;
  return CKR_OK;
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
  DBG(("TODO!!!"));
  DOUT;
  return CKR_OK;
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
  DBG(("TODO!!!"));
  DOUT;
  return CKR_OK;
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
  DBG(("TODO!!!"));
  DOUT;
  return CKR_OK;
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
  DBG(("TODO!!!"));
  DOUT;
  return CKR_OK;
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
  DBG(("TODO!!!"));
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
  DBG(("TODO!!!"));
  DOUT;
  return CKR_OK;
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
  DBG(("TODO!!!"));
  DOUT;
  return CKR_OK;
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
  DBG(("TODO!!!"));
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
  DBG(("TODO!!!"));
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
  DBG(("TODO!!!"));
  DOUT;
  return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_GetFunctionStatus)(
  CK_SESSION_HANDLE hSession
)
{
  DIN;
  DBG(("TODO!!!"));
  DOUT;
  return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_CancelFunction)(
  CK_SESSION_HANDLE hSession
)
{
  DIN;
  DBG(("TODO!!!"));
  DOUT;
  return CKR_OK;
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
