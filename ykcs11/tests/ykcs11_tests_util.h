/*
 * Copyright (c) 2019-2020 Yubico AB
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

#ifndef TEST_UTIL_H
#define TEST_UTIL_H

void dump_hex(const unsigned char *buf, unsigned int len, FILE *output, int space);

void test_digest_func(CK_FUNCTION_LIST_PTR funcs, CK_SESSION_HANDLE session, CK_MECHANISM_TYPE mech_type);

void destroy_test_objects(CK_FUNCTION_LIST_PTR funcs, CK_SESSION_HANDLE session, CK_OBJECT_HANDLE_PTR obj_cert, CK_ULONG n);

EC_KEY* import_ec_key(CK_FUNCTION_LIST_PTR funcs, CK_SESSION_HANDLE session, CK_BYTE n_keys,
                      int curve, CK_ULONG key_len, CK_BYTE* ec_params, CK_ULONG ec_params_len, 
                      CK_OBJECT_HANDLE_PTR obj_cert, CK_OBJECT_HANDLE_PTR obj_pvtkey);
void generate_ec_keys(CK_FUNCTION_LIST_PTR funcs, CK_SESSION_HANDLE session, CK_BYTE n_keys, 
                      CK_BYTE* ec_params, CK_ULONG ec_params_len, 
                      CK_OBJECT_HANDLE_PTR obj_pubkey, CK_OBJECT_HANDLE_PTR obj_pvtkey);                      

void import_rsa_key(CK_FUNCTION_LIST_PTR funcs, CK_SESSION_HANDLE session, int keylen, EVP_PKEY* evp, RSA* rsak,
                    CK_BYTE n_keys, CK_OBJECT_HANDLE_PTR obj_cert, CK_OBJECT_HANDLE_PTR obj_pvtkey);

void generate_rsa_keys(CK_FUNCTION_LIST_PTR funcs, CK_SESSION_HANDLE session, CK_ULONG key_size, CK_BYTE n_keys, 
                      CK_OBJECT_HANDLE_PTR obj_pubkey, CK_OBJECT_HANDLE_PTR obj_pvtkey);
void test_ec_sign_simple(CK_FUNCTION_LIST_PTR funcs, CK_SESSION_HANDLE session, CK_OBJECT_HANDLE_PTR obj_pvtkey, 
                         CK_BYTE n_keys, EC_KEY *eck, CK_ULONG key_len);
void test_ec_sign_thorough(CK_FUNCTION_LIST_PTR funcs, CK_SESSION_HANDLE session, CK_OBJECT_HANDLE_PTR obj_pvtkey, 
                           CK_MECHANISM_TYPE mech_type, EC_KEY *eck, CK_ULONG key_len);

void test_rsa_sign_simple(CK_FUNCTION_LIST_PTR funcs, CK_SESSION_HANDLE session, CK_OBJECT_HANDLE_PTR obj_pvtkey, 
                          CK_BYTE n_keys, EVP_PKEY* evp);
void test_rsa_sign_thorough(CK_FUNCTION_LIST_PTR funcs, CK_SESSION_HANDLE session, CK_OBJECT_HANDLE_PTR obj_pvtkey, 
                            CK_BYTE n_keys, EVP_PKEY* evp, CK_MECHANISM_TYPE mech_type);
void test_rsa_sign_pss(CK_FUNCTION_LIST_PTR funcs, CK_SESSION_HANDLE session, CK_OBJECT_HANDLE_PTR obj_pvtkey, 
                       CK_BYTE n_keys, RSA* rsak, CK_MECHANISM_TYPE mech_type);

void test_rsa_decrypt(CK_FUNCTION_LIST_PTR funcs, CK_SESSION_HANDLE session, CK_OBJECT_HANDLE_PTR obj_pvtkey, 
                      CK_BYTE n_keys, RSA* rsak, CK_MECHANISM_TYPE mech_type, CK_ULONG padding); 
void test_rsa_decrypt_oaep(CK_FUNCTION_LIST_PTR funcs, CK_SESSION_HANDLE session, CK_OBJECT_HANDLE_PTR obj_pvtkey, 
                           CK_BYTE n_keys, CK_MECHANISM_TYPE mdhash, RSA* rsak);
                           
void test_rsa_encrypt(CK_FUNCTION_LIST_PTR funcs, CK_SESSION_HANDLE session, CK_OBJECT_HANDLE_PTR obj_pvtkey, 
                      CK_BYTE n_keys, RSA* rsak, CK_MECHANISM_TYPE mech_type, CK_ULONG padding);                                        

void test_pubkey_attributes_ec(CK_FUNCTION_LIST_PTR funcs, CK_SESSION_HANDLE session, 
                                CK_OBJECT_HANDLE pubkey, CK_ULONG key_size, 
                                const unsigned char* label, CK_ULONG ec_point_len,
                                CK_BYTE_PTR ec_params, CK_ULONG ec_params_len, CK_BBOOL is_neo);
void test_privkey_attributes_ec(CK_FUNCTION_LIST_PTR funcs, CK_SESSION_HANDLE session, 
                                CK_OBJECT_HANDLE pubkey, CK_ULONG key_size, 
                                const unsigned char* label, CK_ULONG ec_point_len,
                                CK_BYTE_PTR ec_params, CK_ULONG ec_params_len,
                                CK_BBOOL always_authenticate, CK_BBOOL is_neo);
void test_pubkey_attributes_rsa(CK_FUNCTION_LIST_PTR funcs, CK_SESSION_HANDLE session, 
                                CK_OBJECT_HANDLE pubkey, CK_ULONG key_size, 
                                const unsigned char* label, CK_ULONG modulus_len,
                                CK_BYTE* pubexp, CK_ULONG pubexp_len, CK_BBOOL is_neo);
void test_privkey_attributes_rsa(CK_FUNCTION_LIST_PTR funcs, CK_SESSION_HANDLE session, 
                                CK_OBJECT_HANDLE pubkey, CK_ULONG key_size, 
                                const unsigned char* label, CK_ULONG modulus_len,
                                CK_BYTE_PTR pubexp, CK_ULONG pubexp_len, 
                                CK_BBOOL always_authenticate, CK_BBOOL is_neo); 

void test_find_objects_by_class(CK_FUNCTION_LIST_PTR funcs, CK_SESSION_HANDLE session, 
                                CK_ULONG class, CK_BYTE ckaid,
                                CK_ULONG n_expected, CK_OBJECT_HANDLE obj_expected);                                                              
                             

#endif