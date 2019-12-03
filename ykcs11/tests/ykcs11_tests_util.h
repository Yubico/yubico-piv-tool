#ifndef TEST_UTIL_H
#define TEST_UTIL_H

void dump_hex(const unsigned char *buf, unsigned int len, FILE *output, int space);

void test_digest_func(CK_FUNCTION_LIST_PTR funcs, CK_SESSION_HANDLE session, CK_MECHANISM_TYPE mech_type);

EC_KEY* import_ec_key(CK_FUNCTION_LIST_PTR funcs, CK_SESSION_HANDLE session, 
                      int curve, CK_ULONG key_len, CK_BYTE* ec_params, CK_ULONG ec_params_len, 
                      CK_OBJECT_HANDLE_PTR obj_cert, CK_OBJECT_HANDLE_PTR obj_pvtkey);
void generate_ec_keys(CK_FUNCTION_LIST_PTR funcs, CK_SESSION_HANDLE session, CK_BYTE n_keys, 
                      CK_BYTE* ec_params, CK_ULONG ec_params_len, 
                      CK_OBJECT_HANDLE_PTR obj_pubkey, CK_OBJECT_HANDLE_PTR obj_pvtkey);                      

void import_rsa_key(CK_FUNCTION_LIST_PTR funcs, CK_SESSION_HANDLE session, EVP_PKEY* evp, RSA* rsak,
                      CK_OBJECT_HANDLE_PTR obj_cert, CK_OBJECT_HANDLE_PTR obj_pvtkey);

void generate_rsa_keys(CK_FUNCTION_LIST_PTR funcs, CK_SESSION_HANDLE session, CK_BYTE n_keys, 
                      CK_OBJECT_HANDLE_PTR obj_pubkey, CK_OBJECT_HANDLE_PTR obj_pvtkey);

void test_ec_sign(CK_FUNCTION_LIST_PTR funcs, CK_SESSION_HANDLE session, CK_OBJECT_HANDLE_PTR obj_pvtkey, 
                   EC_KEY *eck, CK_MECHANISM_TYPE mech_type, CK_ULONG key_len);

void test_rsa_sign(CK_FUNCTION_LIST_PTR funcs, CK_SESSION_HANDLE session, CK_OBJECT_HANDLE_PTR obj_pvtkey, 
                    EVP_PKEY* evp, CK_MECHANISM_TYPE mech_type);

void test_rsa_decrypt(CK_FUNCTION_LIST_PTR funcs, CK_SESSION_HANDLE session, CK_OBJECT_HANDLE_PTR obj_pvtkey, 
                    RSA* rsak, CK_MECHANISM_TYPE mech_type); 

void test_rsa_encrypt(CK_FUNCTION_LIST_PTR funcs, CK_SESSION_HANDLE session, CK_OBJECT_HANDLE_PTR obj_pvtkey, 
                    RSA* rsak, CK_MECHANISM_TYPE mech_type, CK_ULONG padding);                                        

void destroy_test_objects(CK_FUNCTION_LIST_PTR funcs, CK_SESSION_HANDLE session, CK_OBJECT_HANDLE_PTR obj_cert);
void destroy_test_objects_by_privkey(CK_FUNCTION_LIST_PTR funcs, CK_SESSION_HANDLE session, CK_OBJECT_HANDLE_PTR obj_pvtkey, CK_BYTE n_obj);


#endif