#include "pkcs11.h"
#include <stdio.h>
#include <ykpiv.h>
#include <string.h>
#include "vendors.h"
#include "utils.h"

#define D(x) do {                                                     \
    printf ("debug: %s:%d (%s): ", __FILE__, __LINE__, __FUNCTION__); \
    printf x;;                                                        \
    printf ("\n");                                                    \
  } while (0)

#define YKCS11_DBG    1  // General debug, must be either 1 or 0
#define YKCS11_DINOUT 0  // Function in/out debug, must be either 1 or 0

#define YKCS11_MANUFACTURER "Yubico (www.yubico.com)"
#define YKCS11_LIBDESC      "PKCS#11 PIV Library (SP-800-73)"

#define PIV_MIN_PIN_LEN 6
#define PIV_MAX_PIN_LEN 8

#define YKCS11_MAX_SLOTS 16

#define YKCS11_SESSION_ID 5355104

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

static ykcs11_slot_t slots[YKCS11_MAX_SLOTS]; // TODO: build at runtime?
static CK_ULONG      n_slots = 0;
static CK_ULONG      n_slots_with_token = 0;

static CK_SESSION_HANDLE session = CK_INVALID_HANDLE; // TODO: support multiple sessions?
static CK_SESSION_INFO   session_info;

static struct {
  CK_BBOOL        active;
  CK_ULONG        num;
  CK_ULONG        idx;
  piv_obj_id_t    *objects;
} find_obj;

static piv_obj_id_t token_objects[PIV_CERT_OBJ_LAST]; // TODO: tide this up, also build at runtime (during open session)?
static CK_ULONG n_token_objects = 0;

extern CK_FUNCTION_LIST function_list; // TODO: check all return values

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

  if (parse_readers(readers, len, slots, &n_slots, &n_slots_with_token) != CK_TRUE)
    CKR_FUNCTION_FAILED;

  DBG(("Found %lu slot(s) of which %lu tokenless/unsupported", n_slots, n_slots - n_slots_with_token));

  find_obj.active = CK_FALSE;
  // TODO: FILL OUT INIT ARGS;

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
  piv_state = NULL;

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

  // TODO: check more preconditions
  if (pSlotList == NULL_PTR) {
    // Just return the number of slots
    *pulCount = n_slots;

    if (tokenPresent)
      *pulCount = n_slots_with_token;
    else
      *pulCount = n_slots;

    DOUT;
    return CKR_OK;
  }

  if ((tokenPresent && *pulCount < n_slots_with_token) || (!tokenPresent && *pulCount < n_slots)) {
    DBG(("Buffer too small: needed %lu, provided %lu", n_slots, *pulCount));
    return CKR_BUFFER_TOO_SMALL;
  }

  for (j = 0, i = 0; i < n_slots; i++) {
    if (tokenPresent) {
      if (has_token(slots + i)) // TODO: use more to check if TOKEN_REMOVED
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
  if (vendor.get_token_label(pInfo->label, sizeof(pInfo->label)) != CKR_OK)
    return CKR_FUNCTION_FAILED;

  memset(pInfo->manufacturerID, ' ', sizeof(pInfo->manufacturerID));
  if(vendor.get_token_manufacturer(pInfo->manufacturerID, sizeof(pInfo->manufacturerID)) != CKR_OK)
    return CKR_FUNCTION_FAILED;

  memset(pInfo->model, ' ', sizeof(pInfo->model));
  if(vendor.get_token_model(pInfo->model, sizeof(pInfo->model)) != CKR_OK)
    return CKR_FUNCTION_FAILED;

  memset(pInfo->serialNumber, ' ', sizeof(pInfo->serialNumber));
  if(vendor.get_token_serial(pInfo->serialNumber, sizeof(pInfo->serialNumber)) != CKR_OK)
    return CKR_FUNCTION_FAILED;

  // bit flags indicating capabilities and status of the device as defined below // TODO: what about other flags? Like last attempt
  if (vendor.get_token_flags(&pInfo->flags) != CKR_OK)
    return CKR_FUNCTION_FAILED;

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
  if (vendor.get_token_version(buf, strlen(buf), &ver) != CKR_OK)
    return CKR_FUNCTION_FAILED;

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
  vendor_t vendor;
  CK_ULONG count;

  if (piv_state == NULL) {
    DBG(("libykpiv is not initialized or already finalized"));
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  if (slotID > n_slots || pulCount == NULL_PTR)
    return CKR_ARGUMENTS_BAD;

  if (slots[slotID].vid == UNKNOWN) {
    DBG(("Slot %lu is tokenless/unsupported", slotID));
    return CKR_SLOT_ID_INVALID;
  }

  // TODO: check more return values
  // TODO: user NULL_PTR more for coherence

  vendor = get_vendor(slots[slotID].vid); // TODO: make a token field in slot_t ?;

  if (vendor.get_token_mechanisms_num(&count) != CKR_OK)
    return CKR_FUNCTION_FAILED;

  if (pMechanismList == NULL_PTR) {
    *pulCount = count;
    DBG(("Found %lu mechanisms", *pulCount));
    DOUT;
    return CKR_OK;
  }

  if (*pulCount < count) {
    DBG(("Buffer too small: needed %lu, provided %lu", count, *pulCount));
    return CKR_BUFFER_TOO_SMALL;
  }

  if (vendor.get_token_mechanism_list(pMechanismList, *pulCount) != CKR_OK)
    return CKR_FUNCTION_FAILED;

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
  vendor_t vendor;

  if (piv_state == NULL) {
    DBG(("libykpiv is not initialized or already finalized"));
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  if (slotID > n_slots || pInfo == NULL_PTR)
    return CKR_ARGUMENTS_BAD;

  if (slots[slotID].vid == UNKNOWN) {
    DBG(("Slot %lu is tokenless/unsupported", slotID));
    return CKR_SLOT_ID_INVALID;
  }

  // TODO: check more return values
  // TODO: user NULL_PTR more for coherence

  vendor = get_vendor(slots[slotID].vid); // TODO: make a token field in slot_t ?;

  if (vendor.get_token_mechanism_info(type, pInfo) != CKR_OK)
    return CKR_MECHANISM_INVALID;


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

  vendor_t vendor;

  if (piv_state == NULL)
    return CKR_CRYPTOKI_NOT_INITIALIZED;

  if (slotID >= n_slots || phSession == NULL)
    return CKR_ARGUMENTS_BAD;

  if (slots[slotID].vid == UNKNOWN) {
    DBG(("No support for token in slot %lu", slotID));
    return CKR_TOKEN_NOT_RECOGNIZED;
  }

  if (!has_token(slots + slotID)) {
    DBG(("Slot %lu has no token inserted", slotID));
    return CKR_TOKEN_NOT_PRESENT;
  }

  vendor = get_vendor(slots[slotID].vid); // TODO: make a token field in slot_t ?
  
  // Store all the objects available in the token
  n_token_objects = sizeof(token_objects) / sizeof(piv_obj_id_t);
  if (vendor.get_token_object_list(piv_state, token_objects, &n_token_objects) != CKR_OK) {
    DBG(("Unable to retrieve token objects"));
    return CKR_FUNCTION_FAILED;
  }

  if ((flags & CKF_SERIAL_SESSION) == 0) { // TODO: check more error conditions
    DBG(("Open session called without CKF_SERIAL_SESSION set"));
    return CKR_SESSION_PARALLEL_NOT_SUPPORTED;
  }

  if (session != CK_INVALID_HANDLE) {
    DBG(("A session with this or another token already exists"));
    return CKR_SESSION_COUNT;
  }

  // TODO: make sue we don't open a session with an UNKNOWN slot/token

  session = YKCS11_SESSION_ID;
  session_info.slotID = slotID;
  // TODO: KEEP TRACK OF THE APPLICATION

  if ((flags & CKF_RW_SESSION)) {
    // R/W Session
    session_info.state = CKS_RW_PUBLIC_SESSION; // Nobody has logged in, default session
  }
  else {
    // R/O Session
    session_info.state = CKS_RO_PUBLIC_SESSION; // Nobody has logged in, default session
  }

  session_info.flags = flags;
  session_info.ulDeviceError = 0;

  *phSession = session;

  DOUT;
  return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_CloseSession)(
  CK_SESSION_HANDLE hSession
)
{
  DIN;

  if (piv_state == NULL)
    return CKR_CRYPTOKI_NOT_INITIALIZED;

  if (session == CK_INVALID_HANDLE) {
    DBG(("There is no existing session"));
    return CKR_SESSION_CLOSED;
  }

  if (hSession != YKCS11_SESSION_ID)
    return CKR_SESSION_HANDLE_INVALID;

  session = CK_INVALID_HANDLE;
  memset(&session_info, 0, sizeof(CK_SESSION_INFO));

  DOUT;
  return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_CloseAllSessions)(
  CK_SLOT_ID slotID
)
{
  DIN;

  if (piv_state == NULL)
    return CKR_CRYPTOKI_NOT_INITIALIZED;

  if (session_info.slotID != slotID)
    return CKR_SLOT_ID_INVALID;

  session = CK_INVALID_HANDLE;
  memset(&session_info, 0, sizeof(CK_SESSION_INFO)); // TODO: Better to call close session?

  DOUT;
  return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_GetSessionInfo)(
  CK_SESSION_HANDLE hSession,
  CK_SESSION_INFO_PTR pInfo
)
{
  DIN;

  if (piv_state == NULL)
    return CKR_CRYPTOKI_NOT_INITIALIZED;

  if (pInfo == NULL)
    return CKR_ARGUMENTS_BAD;

  if (hSession != session)
    return CKR_SESSION_HANDLE_INVALID;

  memcpy(pInfo, &session_info, sizeof(CK_SESSION_INFO));

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
  CK_ULONG        tries;

  if (piv_state == NULL)
    return CKR_CRYPTOKI_NOT_INITIALIZED;

  if (userType != CKU_USER &&
      userType != CKU_SO &&
      userType != CKU_CONTEXT_SPECIFIC)
    return CKR_ARGUMENTS_BAD;

  if (ulPinLen < PIV_MIN_PIN_LEN ||
      ulPinLen > PIV_MAX_PIN_LEN)
    return CKR_ARGUMENTS_BAD;

  DBG(("user %lu, pin %s, pinlen %lu", userType, pPin, ulPinLen));

  if (session == CK_INVALID_HANDLE)
    return CKR_SESSION_CLOSED;

  if (hSession != session)
    return CKR_SESSION_HANDLE_INVALID;

  if (userType != CKU_SO &&
      userType != CKU_USER &&
      userType != CKU_CONTEXT_SPECIFIC)
    return CKR_USER_TYPE_INVALID;

  if ((session_info.flags & CKF_RW_SESSION) == 0) { // TODO: make macros for these?
    DBG(("Tried to log-in to a read-only session"));
    return CKR_SESSION_READ_ONLY_EXISTS;
  }

  switch (userType) {
  case CKU_USER:
    if (session_info.state == CKS_RW_USER_FUNCTIONS)
      return CKR_USER_ALREADY_LOGGED_IN;

    tries = 0;
    if (ykpiv_verify(piv_state, pPin, (int *)&tries) != YKPIV_OK) {
      DBG(("You loose! %lu", tries));
      return CKR_PIN_INCORRECT;
    }
    break;

  case CKU_SO:
  case CKU_CONTEXT_SPECIFIC:
  default:
    return CKR_USER_TYPE_INVALID; // TODO: only allow regular user for now
  }

  DBG(("You win! %lu", tries))

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

  if (piv_state == NULL)
    return CKR_CRYPTOKI_NOT_INITIALIZED;

  if (session != YKCS11_SESSION_ID)
    return CKR_SESSION_CLOSED;

  if (hSession != session)
    return CKR_SESSION_HANDLE_INVALID;

  if (pTemplate == NULL_PTR || ulCount == 0)
    return CKR_ARGUMENTS_BAD;

  if (find_obj.active != CK_TRUE)
    return CKR_OPERATION_NOT_INITIALIZED;

  if (pTemplate[0].pValue == NULL_PTR) {
    DBG(("Just get size"));
    get_attribute(hObject, pTemplate); // TODO: get attribute size
    DOUT;
    return CKR_OK;
  }
  DBG(("Trying to get %lu attributes for object %lx", ulCount, hObject));
  DBG(("Type: 0x%lx Value: %lu Len: %lu", pTemplate[0].type, *((CK_ULONG_PTR)pTemplate[0].pValue), pTemplate[0].ulValueLen));
  // TODO: here for i in ulCount
  return get_attribute(hObject, pTemplate);

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
  CK_ULONG i;
  vendor_t vendor;

  if (piv_state == NULL)
    return CKR_CRYPTOKI_NOT_INITIALIZED;

  if (session != YKCS11_SESSION_ID)
    return CKR_SESSION_CLOSED;

  if (hSession != session)
    return CKR_SESSION_HANDLE_INVALID; // TODO: or session closed?

  if (find_obj.active == CK_TRUE)
    return CKR_OPERATION_ACTIVE;

  if (slots[session_info.slotID].vid == UNKNOWN) {
    DBG(("Slot %lu is tokenless/unsupported", session_info.slotID));
    return CKR_SLOT_ID_INVALID;
  }
  vendor = get_vendor(slots[session_info.slotID].vid); // TODO: make a token field in slot_t ?;

  if (ulCount == 0) {
    DBG(("Find ALL the objects!"));
    find_obj.active = CK_TRUE;
    find_obj.num = n_token_objects;
    find_obj.idx = 0;
    find_obj.objects = token_objects;
    DOUT;
    return CKR_OK;
  }
//  return CKR_FUNCTION_FAILED;
  DBG(("Initialized search with %lu parameters", ulCount));

  if (pTemplate == NULL_PTR)
    return CKR_ARGUMENTS_BAD;

  find_obj.active = CK_TRUE;

  for (i = 0; i < ulCount; i++) {
    DBG(("Parameter %lu\nType: %lu Value: %lu Len: %lu", i, pTemplate[i].type, *((CK_ULONG_PTR)pTemplate[i].pValue), pTemplate[i].ulValueLen));
  }


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

  if (piv_state == NULL)
    return CKR_CRYPTOKI_NOT_INITIALIZED;

  if (session != YKCS11_SESSION_ID)
    return CKR_SESSION_CLOSED;

  if (hSession != session)
    return CKR_SESSION_HANDLE_INVALID;

  if (phObject == NULL_PTR ||
      ulMaxObjectCount == 0 ||
      pulObjectCount == NULL_PTR)
    return CKR_ARGUMENTS_BAD;

  if (find_obj.active != CK_TRUE)
    return CKR_OPERATION_NOT_INITIALIZED;

  DBG(("Can return %lu object(s)", ulMaxObjectCount));

  // Return the next object
  if (find_obj.idx == find_obj.num) {
    *pulObjectCount = 0;
    DOUT;
    return CKR_OK;
  }

  *phObject = find_obj.objects[find_obj.idx++];
  *pulObjectCount = 1;
  return CKR_OK;

  // NEVER REACHED
  DBG(("GETTING SOMETHING ELSE"));
  *phObject = PIV_DATA_OBJ_X509_DS;
  *pulObjectCount = 2;
  DOUT;
  return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_FindObjectsFinal)(
  CK_SESSION_HANDLE hSession
)
{
  DIN;

  if (piv_state == NULL)
    return CKR_CRYPTOKI_NOT_INITIALIZED;

  if (session != YKCS11_SESSION_ID)
    return CKR_SESSION_CLOSED;

  if (hSession != session)
    return CKR_SESSION_HANDLE_INVALID;

  if (find_obj.active != CK_TRUE)
    return CKR_OPERATION_NOT_INITIALIZED;

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

  if (piv_state == NULL)
    return CKR_CRYPTOKI_NOT_INITIALIZED;

  if (session != YKCS11_SESSION_ID)
    return CKR_SESSION_CLOSED;

  if (hSession != session)
    return CKR_SESSION_HANDLE_INVALID;

  if (pMechanism == NULL_PTR ||
      hKey == NULL_PTR)
    return CKR_ARGUMENTS_BAD;

  DBG(("Trying to sign some data with mechanism %lu and key %lu", pMechanism->mechanism, hKey));
  DOUT;
  return CKR_OK;
}
/* TOTOD: DELETE */
CK_BYTE  sig_buf[1024];
CK_ULONG sig_len = 1024;
void dump_hex(const unsigned char *buf, unsigned int len, FILE *output, CK_BBOOL space) {
  unsigned int i;
  for (i = 0; i < len; i++) {
    fprintf(output, "%02x%s", buf[i], space == CK_TRUE ? " " : "");
  }
  fprintf(output, "\n");
}
/* TODO: DELETE END*/
CK_DEFINE_FUNCTION(CK_RV, C_Sign)(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pData,
  CK_ULONG ulDataLen,
  CK_BYTE_PTR pSignature,
  CK_ULONG_PTR pulSignatureLen
)
{
  DIN;
  // TODO: check conditions
  char test_buf[] = "\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20\xa7\x47\x16\x1b\x15\x5f\xd0\x05\xbc\xbe\x84\x4a\x28\xa9\x6c\x74\xfe\xf6\x6a\x42\x84\xa0\x4e\x05\x7a\x0c\x88\xe2\xc8\x83\xc0\x00";
  CK_ULONG sig_len_in = sizeof(test_buf) - 1;
  CK_ULONG sig_len_out = 1024;
  ykpiv_rc r;
  DBG(("Sending %lu bytes to sign", /*ulDataLen*/sig_len_in));
  dump_hex(test_buf, sig_len_in, stderr, CK_TRUE);
  if ((r = ykpiv_sign_data(piv_state, /*pData*/test_buf, /*ulDataLen*/sig_len_in, sig_buf, &sig_len_out, YKPIV_ALGO_RSA2048, YKPIV_KEY_AUTHENTICATION)) != YKPIV_OK) {
      DBG(("Sign error %s", ykpiv_strerror(r)));
    return CKR_FUNCTION_FAILED;
  }
  DBG(("Got %lu bytes back", sig_len_out));
  dump_hex(sig_buf, sig_len_out, stderr, CK_TRUE);
  memcpy(pSignature, sig_buf, sig_len_out);
  *pulSignatureLen = sig_len_out;
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
