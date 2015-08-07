#include "token_vendors.h"
#include "yubico_token.h"

static CK_RV COMMON_token_generate_key(ykpiv_state *state, CK_BBOOL rsa, CK_BYTE key, CK_ULONG key_len) {
  // TODO: make a function in ykpiv for this
  unsigned char in_data[5];
  unsigned char data[1024];
  unsigned char templ[] = {0, YKPIV_INS_GENERATE_ASYMMERTRIC, 0, 0};
  unsigned long recv_len = sizeof(data);
  unsigned long received = 0;
  int sw;

  templ[3] = key;

  in_data[0] = 0xac;
  in_data[1] = 3;
  in_data[2] = 0x80;
  in_data[3] = 1;

  switch(key_len) {
  case 2048:
    in_data[4] = YKPIV_ALGO_RSA2048;
    break;

  case 1024:
    in_data[4] = YKPIV_ALGO_RSA1024;
    break;

  case 256:
    in_data[4] = YKPIV_ALGO_ECCP256;
    break;

  default:
    return CKR_FUNCTION_FAILED;
  }
  //DBG(("Generating key %x with algorithm %u and length %lu", templ[3], in_data[4], key_len));
  if(ykpiv_transfer_data(state, templ, in_data, sizeof(in_data), data, &recv_len, &sw) != YKPIV_OK ||
     sw != 0x9000)
    return CKR_DEVICE_ERROR;


  /* to drop the 90 00 and the 7f 49 at the start */
  received += recv_len - 4;
  return CKR_OK;
}

token_vendor_t get_token_vendor(vendor_id_t vid) {
   token_vendor_t v;

  switch (vid) {
  case YUBICO:
    v.get_token_label           = YUBICO_get_token_label;
    v.get_token_manufacturer    = YUBICO_get_token_manufacturer;
    v.get_token_model           = YUBICO_get_token_model;
    v.get_token_flags           = YUBICO_get_token_flags;
    v.get_token_version         = YUBICO_get_token_version;
    v.get_token_serial          = YUBICO_get_token_serial;
    v.get_token_mechanisms_num  = YUBICO_get_token_mechanisms_num;
    v.get_token_mechanism_list  = YUBICO_get_token_mechanism_list;
    v.get_token_mechanism_info  = YUBICO_get_token_mechanism_info;
    v.get_token_objects_num     = YUBICO_get_token_objects_num;
    v.get_token_object_list     = YUBICO_get_token_object_list;
    v.get_token_raw_certificate = YUBICO_get_token_raw_certificate;
    v.token_generate_key        = COMMON_token_generate_key;
    break;

  case UNKNOWN:
  default:
    v.get_token_label           = NULL;
    v.get_token_manufacturer    = NULL;
    v.get_token_model           = NULL;
    v.get_token_flags           = NULL;
    v.get_token_version         = NULL;
    v.get_token_serial          = NULL;
    v.get_token_mechanisms_num  = NULL;
    v.get_token_mechanism_list  = NULL;
    v.get_token_mechanism_info  = NULL;
    v.get_token_objects_num     = NULL;
    v.get_token_object_list     = NULL;
    v.get_token_raw_certificate = NULL;
    v.token_generate_key        = NULL;
  }

  return v;

}
