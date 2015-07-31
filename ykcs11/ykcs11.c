#include "ykcs11.h"
//#include "pkcs11.h"
#include <stdio.h>
#include <stdlib.h>
#include <ykpiv.h>
#include <string.h>
#include "obj_types.h"
#include "utils.h"
#include "mechanisms.h"

#define D(x) do {                                                     \
    printf ("debug: %s:%d (%s): ", __FILE__, __LINE__, __FUNCTION__); \
    printf x;                                                         \
    printf ("\n");                                                    \
  } while (0)

#define YKCS11_DBG    1  // General debug, must be either 1 or 0
#define YKCS11_DINOUT 0  // Function in/out debug, must be either 1 or 0

#define YKCS11_MANUFACTURER "Yubico (www.yubico.com)"
#define YKCS11_LIBDESC      "PKCS#11 PIV Library (SP-800-73)"

#define PIV_MIN_PIN_LEN 6
#define PIV_MAX_PIN_LEN 8

#define YKCS11_MAX_SLOTS       16
#define YKCS11_MAX_SIG_BUF_LEN 1024

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

static ykcs11_session_t session; // TODO: support multiple sessions?

static struct {
  CK_BBOOL        active;
  CK_ULONG        num;
  CK_ULONG        idx;
  piv_obj_id_t    *objects;
} find_obj;

/*static piv_obj_id_t token_objects[PIV_CERT_OBJ_LAST]; // TODO: tide this up, also build at runtime (during open session)? And include inside a session struct?
  static CK_ULONG n_token_objects = 0;*/

static struct {
  CK_BBOOL     active;
  CK_MECHANISM mechanism;
  CK_ULONG     key;
  CK_ULONG     key_len;
  CK_BYTE      algo;
} sign_info;

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

  if (piv_state == NULL) {
    DBG(("libykpiv is not initialized or already finalized"));
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

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
  token_vendor_t  token;
  CK_BYTE         buf[64];

  if (piv_state == NULL) {
    DBG(("libykpiv is not initialized or already finalized"));
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  if (slotID >= n_slots)
    return CKR_ARGUMENTS_BAD;

  if (slots[slotID].vid == UNKNOWN) {
    DBG(("No support for slot %lu", slotID));
    return CKR_TOKEN_NOT_RECOGNIZED;
  }

  if (!has_token(slots + slotID)) {
    DBG(("Slot %lu has no token inserted", slotID));
    return CKR_TOKEN_NOT_PRESENT;
  }

  if (slots[slotID].token->vid == UNKNOWN) {
    DBG(("No support for token in slot %lu", slotID));
    return CKR_TOKEN_NOT_RECOGNIZED;
  }

  token = get_token_vendor(slots[slotID].token->vid);

  memcpy(pInfo, &slots[slotID].token->info, sizeof(CK_TOKEN_INFO));

  // Overwrite value that are application specific
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
  token_vendor_t token;
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

  token = get_token_vendor(slots[slotID].vid);

  if (token.get_token_mechanisms_num(&count) != CKR_OK)
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

  if (token.get_token_mechanism_list(pMechanismList, *pulCount) != CKR_OK)
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
  token_vendor_t token;

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

  token = get_token_vendor(slots[slotID].vid);

  if (token.get_token_mechanism_info(type, pInfo) != CKR_OK)
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
  DIN; // TODO: pApplication and Notify

  token_vendor_t token;
  CK_RV          rv;
  piv_obj_id_t   *cert_ids;
  CK_ULONG       i;
  CK_BYTE        cert_data[2100];  // Max cert value for ykpiv
  CK_ULONG       cert_len = sizeof(cert_data);

  if (piv_state == NULL) {
    DBG(("libykpiv is not initialized or already finalized"));
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  if (slotID >= n_slots || phSession == NULL)
    return CKR_ARGUMENTS_BAD;

  if (slots[slotID].vid == UNKNOWN) {
    DBG(("No support for slot %lu", slotID));
    return CKR_TOKEN_NOT_RECOGNIZED;
  }

  if (slots[slotID].token->vid == UNKNOWN) {
    DBG(("No support for token in slot %lu", slotID));
    return CKR_TOKEN_NOT_RECOGNIZED;
  }

  if (!has_token(slots + slotID)) {
    DBG(("Slot %lu has no token inserted", slotID));
    return CKR_TOKEN_NOT_PRESENT;
  }

  if (session.handle != CK_INVALID_HANDLE) {
    DBG(("A session with this or another token already exists"));
    return CKR_SESSION_COUNT;
  }

  if ((flags & CKF_SERIAL_SESSION) == 0) { // TODO: check more error conditions
    DBG(("Open session called without CKF_SERIAL_SESSION set")); // Reuired by specs
    return CKR_SESSION_PARALLEL_NOT_SUPPORTED;
  }

  token = get_token_vendor(slots[slotID].token->vid);

  // Store the slot
  session.slot = slots + slotID;
  //session.slot->info.slotID = slotID; // Redundant but required in CK_SESSION_INFO

  // Store session flags
  if ((flags & CKF_RW_SESSION)) {
    // R/W Session
    session.info.state = CKS_RW_PUBLIC_SESSION; // Nobody has logged in, default session
  }
  else {
    // R/O Session
    session.info.state = CKS_RO_PUBLIC_SESSION; // Nobody has logged in, default session
  }

  session.info.flags = flags;
  session.info.ulDeviceError = 0;

  // Get the number of token objects
  rv = token.get_token_objects_num(piv_state, &session.slot->token->n_objects, &session.slot->token->n_certs);
  if (rv != CKR_OK) {
    DBG(("Unable to retrieve number of token objects"));
    return rv;
  }

  // Get memory for the objects
  session.slot->token->objects = malloc(sizeof(piv_obj_id_t) * session.slot->token->n_objects);
  if (session.slot->token->objects == NULL) {
    DBG(("Unable to allocate memory for token object ids"));
    return CKR_HOST_MEMORY;
  }

  // Get memory for the certificates
  cert_ids = malloc(sizeof(piv_obj_id_t) * session.slot->token->n_certs);
  if (cert_ids == NULL) {
    DBG(("Unable to allocate memory for token certificate ids"));
    return CKR_HOST_MEMORY;
  }

  // Save a list of all the available objects in the token // TODO: change behavior based on login status
  rv = token.get_token_object_list(piv_state, session.slot->token->objects, session.slot->token->n_objects);
  if (rv != CKR_OK) {
    DBG(("Unable to retrieve token objects"));
    goto failure;
  }

  // Get a list object ids for available certificates object from the session
  rv = get_available_certificate_ids(&session, cert_ids, session.slot->token->n_certs); // TODO: better to get this from token? how?
  if (rv != CKR_OK) {
    DBG(("Unable to retrieve certificate ids from the session"));
    goto failure;
  }

  // Get the actual certificate data from the token and store it as an X509 object
  for (i = 0; i < session.slot->token->n_certs; i++) {
    rv = token.get_token_raw_certificate(piv_state, cert_ids[i], cert_data, cert_len);
    if (rv != CKR_OK) {
      DBG(("Unable to get certificate data from token"));
      goto failure;
    }

    rv = store_cert(cert_ids[i], cert_data, cert_len);
    if (rv != CKR_OK) {
      DBG(("Unable to store certificate data"));
      goto failure;
    }
  }

  session.handle = YKCS11_SESSION_ID;
  // TODO: KEEP TRACK OF THE APPLICATION (possble to steal a session?)

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

  free_certs(); // TODO

  return rv;
}

CK_DEFINE_FUNCTION(CK_RV, C_CloseSession)(
  CK_SESSION_HANDLE hSession
)
{
  DIN;

  if (piv_state == NULL) {
    DBG(("libykpiv is not initialized or already finalized"));
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  if (session.handle == CK_INVALID_HANDLE) {
    DBG(("There is no existing session"));
    return CKR_SESSION_CLOSED;
  }

  if (hSession != YKCS11_SESSION_ID) {
    DBG(("Unknown session %lu", hSession));
    return CKR_SESSION_HANDLE_INVALID;
  }

  free(session.slot->token->objects); // TODO: make objects survive a session so there is no need to get them again?
  session.slot->token->objects = NULL;

  memset(&session, 0, sizeof(ykcs11_session_t));
  session.handle = CK_INVALID_HANDLE;

  DOUT;
  return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_CloseAllSessions)(
  CK_SLOT_ID slotID
)
{
  DIN;
  CK_RV rv;

  if (piv_state == NULL) {
    DBG(("libykpiv is not initialized or already finalized"));
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  if (session.slot != slots + slotID)
    return CKR_SLOT_ID_INVALID;

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
    DBG(("libykpiv is not initialized or already finalized"));
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  if (pInfo == NULL)
    return CKR_ARGUMENTS_BAD;

  if (hSession != session.handle)
    return CKR_SESSION_HANDLE_INVALID;

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

  if (piv_state == NULL) {
    DBG(("libykpiv is not initialized or already finalized"));
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  if (userType != CKU_USER &&
      userType != CKU_SO &&
      userType != CKU_CONTEXT_SPECIFIC)
    return CKR_ARGUMENTS_BAD;

  if (ulPinLen < PIV_MIN_PIN_LEN ||
      ulPinLen > PIV_MAX_PIN_LEN)
    return CKR_ARGUMENTS_BAD;

  DBG(("user %lu, pin %s, pinlen %lu", userType, pPin, ulPinLen));

  if (session.handle == CK_INVALID_HANDLE)
    return CKR_SESSION_CLOSED;

  if (hSession != session.handle)
    return CKR_SESSION_HANDLE_INVALID;

  if (userType != CKU_SO && // TODO: what can SO do?
      userType != CKU_USER &&
      userType != CKU_CONTEXT_SPECIFIC)
    return CKR_USER_TYPE_INVALID;

  if ((session.info.flags & CKF_RW_SESSION) == 0) { // TODO: make macros for these?
    DBG(("Tried to log-in to a read-only session"));
    return CKR_SESSION_READ_ONLY_EXISTS;
  }

  switch (userType) {
  case CKU_USER:
    if (session.info.state == CKS_RW_USER_FUNCTIONS)
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

  DBG(("You win! %lu", tries));

  // TODO: update session objects now that we're logged in ?

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
  CK_RV rv;

  if (piv_state == NULL) {
    DBG(("libykpiv is not initialized or already finalized"));
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  if (session.handle != YKCS11_SESSION_ID)
    return CKR_SESSION_CLOSED;

  if (hSession != session.handle)
    return CKR_SESSION_HANDLE_INVALID;

  if (pTemplate == NULL_PTR || ulCount == 0)
    return CKR_ARGUMENTS_BAD;

  if (find_obj.active != CK_TRUE)
    return CKR_OPERATION_NOT_INITIALIZED;

  if (pTemplate[0].pValue == NULL_PTR) {
    DBG(("Just get size"));
    rv = get_attribute(&session, hObject, pTemplate);

    if (rv != CKR_OK) {
      DBG(("Unable to get size for attribute %lu of object %lu", pTemplate->type, hObject));
    }
    DOUT;
    return CKR_OK;
  }
  DBG(("Trying to get %lu attribute(s) for object %lu", ulCount, hObject));
  DBG(("Type: 0x%lx Value: %lu Len: %lu", pTemplate[0].type, *((CK_ULONG_PTR)pTemplate[0].pValue), pTemplate[0].ulValueLen));
  // TODO: here for i in ulCount (get all the attributes)

  return get_attribute(&session, hObject, pTemplate);

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

  if (piv_state == NULL) {
    DBG(("libykpiv is not initialized or already finalized"));
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  if (session.handle != YKCS11_SESSION_ID)
    return CKR_SESSION_CLOSED;

  if (hSession != session.handle)
    return CKR_SESSION_HANDLE_INVALID;

  if (find_obj.active == CK_TRUE)
    return CKR_OPERATION_ACTIVE;

  find_obj.idx = 0;
  find_obj.num = session.slot->token->n_objects;

  find_obj.objects = malloc(sizeof(piv_obj_id_t) * find_obj.num);
  if (find_obj.objects == NULL) {
    DBG(("Unable to allocate memory for finding objects"));
    return CKR_HOST_MEMORY;
  }
  memcpy(find_obj.objects, session.slot->token->objects, sizeof(piv_obj_id_t) * find_obj.num); // TODO: add another 'num' field for then objects have to be excluded because of attribute matching;

  find_obj.active = CK_TRUE;

  if (ulCount == 0) {
    DBG(("Find ALL the objects!"));
    DOUT;
    return CKR_OK;
  }

  DBG(("Initialized search with %lu parameters", ulCount));

  if (pTemplate == NULL_PTR) {
    find_obj.active = CK_FALSE;
    return CKR_ARGUMENTS_BAD;
  }

  for (i = 0; i < ulCount; i++) {
    DBG(("Parameter %lu\nType: %lu Value: %lu Len: %lu", i, pTemplate[i].type, *((CK_ULONG_PTR)pTemplate[i].pValue), pTemplate[i].ulValueLen));
    // TODO: remove objects that don't match
  }

  // TODO: do it properly here, just a test now
  //find_obj.objects = session.slot->token->objects + 3;
  memmove(find_obj.objects, find_obj.objects + 13, sizeof(piv_obj_id_t) * (find_obj.num - 13));
  find_obj.num = 1;

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
    DBG(("libykpiv is not initialized or already finalized"));
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  if (session.handle != YKCS11_SESSION_ID)
    return CKR_SESSION_CLOSED;

  if (hSession != session.handle)
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

  DBG(("Returning object %lu", *phObject));

  return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_FindObjectsFinal)(
  CK_SESSION_HANDLE hSession
)
{
  DIN;

  if (piv_state == NULL) {
    DBG(("libykpiv is not initialized or already finalized"));
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  if (session.handle != YKCS11_SESSION_ID)
    return CKR_SESSION_CLOSED;

  if (hSession != session.handle)
    return CKR_SESSION_HANDLE_INVALID;

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
  CK_KEY_TYPE  type = 0; // TODO: replace these with sign_info's fields?
  CK_ULONG     key_len = 0;
  CK_BYTE      buf[1024];
  CK_ATTRIBUTE template[] = {
    {CKA_KEY_TYPE, &type, sizeof(type)},
    {CKA_MODULUS_BITS, &key_len, sizeof(key_len)},
    {CKA_EC_POINT, buf, sizeof(buf)}
  };

  if (piv_state == NULL) {
    DBG(("libykpiv is not initialized or already finalized"));
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }

  if (session.handle != YKCS11_SESSION_ID)
    return CKR_SESSION_CLOSED;

  if (hSession != session.handle)
    return CKR_SESSION_HANDLE_INVALID;

  if (pMechanism == NULL_PTR ||
      hKey == NULL_PTR)
    return CKR_ARGUMENTS_BAD;

  DBG(("Trying to sign some data with mechanism %lu and key %lu", pMechanism->mechanism, hKey));

  // Check if mechanism is supported
  if (check_sign_mechanism(&session, pMechanism) != CKR_OK) {
    DBG(("Mechanism %lu is not supported either by the token or the slot", pMechanism->mechanism));
    return CKR_MECHANISM_INVALID; // TODO: also the key has a list of allowed mechanisms, check that
  }
  memcpy(&sign_info.mechanism, pMechanism, sizeof(CK_MECHANISM));

  //  Get key algorithm
  if (get_attribute(&session, hKey, template) != CKR_OK) {
    DBG(("Unable to get key type"));
    return CKR_KEY_HANDLE_INVALID;
  }

  DBG(("Key algorithm is %lu\n", type));

  // Get key length and algorithm type
  if (type == CKK_RSA) {
    // RSA key
    if (get_attribute(&session, hKey, template + 1) != CKR_OK) {
      DBG(("Unable to get key length"));
      return CKR_KEY_HANDLE_INVALID;
    }

    sign_info.key_len = key_len;

    if (key_len == 1024)
      sign_info.algo = YKPIV_ALGO_RSA1024;
    else
      sign_info.algo = YKPIV_ALGO_RSA2048;

  }
  else {
    // ECDSA key
    if (get_attribute(&session, hKey, template + 2) != CKR_OK) {
      DBG(("Unable to get key length"));
      return CKR_KEY_HANDLE_INVALID;
    }

    // The buffer contains an uncompressed point of the form 04, x, y
    // TODO: is this a fine representation for an EC public key?
    sign_info.key_len = ((template[2].ulValueLen - 1) / 2) * 8;

    if (sign_info.key_len == 256)
      sign_info.algo = YKPIV_ALGO_ECCP256;
    /*else
      sign_info.algo = ;*/
  }

  DBG(("Key length is %lu bit", sign_info.key_len));
  //sign_info.key_len /= 8;
    
  sign_info.key = piv_2_ykpiv(hKey);
  if (sign_info.key == 0) {
    DBG(("Incorrect key %lu", hKey));
    return CKR_KEY_HANDLE_INVALID;
  }

  DBG(("Algorithm is %d", sign_info.algo));
  // Make sure that both mechanism and key have the same algorithm
  if ((is_RSA_mechanism(pMechanism->mechanism) && sign_info.algo == YKPIV_ALGO_ECCP256) ||
      (!is_RSA_mechanism(pMechanism->mechanism) && (sign_info.algo != YKPIV_ALGO_ECCP256))) {
    DBG(("Key and mechanism algorithm do not match"));
    return CKR_ARGUMENTS_BAD;
  }

  // TODO: also allocate some space for the signature in case of multipart

  sign_info.active = CK_TRUE;

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
  CK_BYTE  buf[YKCS11_MAX_SIG_BUF_LEN];
  CK_ULONG buf_len = sizeof(buf);

  if (sign_info.active == CK_FALSE)
    return CKR_OPERATION_NOT_INITIALIZED;

  // TODO: check conditions
  ykpiv_rc r;
  CK_CHAR algo;

  DBG(("Sending %lu bytes to sign", ulDataLen));
  dump_hex(pData, ulDataLen, stderr, CK_TRUE);

/*  if (do_sign_padding(&sign_info.mechanism, pData, ulDataLen, buf, buf_len, 2048 / 8) != CKR_OK) {
    DBG(("Unable to apply padding scheme"));
    return CKR_FUNCTION_FAILED;
    }*/
  memcpy(buf, pData, ulDataLen); // ykpiv does padding already
  //dump_hex(buf, 256, stderr, CK_TRUE);
  //*pulSignatureLen = 256;
  DBG(("Using key %lx", sign_info.key)); // TODO: test what happens if there is no key on the card
  if ((r = ykpiv_sign_data(piv_state, buf, ulDataLen, pSignature, pulSignatureLen, sign_info.algo, sign_info.key)) != YKPIV_OK) {
      DBG(("Sign error, %s", ykpiv_strerror(r)));
    return CKR_FUNCTION_FAILED;
  }
  DBG(("Got %lu bytes back", *pulSignatureLen));
  dump_hex(pSignature, *pulSignatureLen, stderr, CK_TRUE);
/*  memcpy(pSignature, sig_buf, sig_len_out);
 *pulSignatureLen = sig_len_out;*/
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
