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

#ifndef YKPIV_INTERNAL_H
#define YKPIV_INTERNAL_H

#include "ykpiv.h"

#include <stdbool.h>

#if BACKEND_PCSC
#if defined HAVE_PCSC_WINSCARD_H
# include <PCSC/wintypes.h>
# include <PCSC/winscard.h>
#else
# include <winscard.h>
#endif
#endif

#define READER_LEN  32
#define MAX_READERS 16

#define DES_LEN_3DES  8*3
#define CB_MGM_KEY DES_LEN_3DES

struct ykpiv_state {
  SCARDCONTEXT context;
  SCARDHANDLE card;
  int  verbose;
  char *pin;

  ykpiv_allocator allocator;
  bool isNEO;
  uint8_t mgmKey[CB_MGM_KEY];
  bool fMgmKeySet;

};

union u_APDU {
  struct {
    unsigned char cla;
    unsigned char ins;
    unsigned char p1;
    unsigned char p2;
    unsigned char lc;
    unsigned char data[0xff];
  } st;
  unsigned char raw[0xff + 5];
};

typedef union u_APDU APDU;

extern unsigned const char aid[];

// the object size is restricted to the firmware's message buffer size, which
// always contains 0x5C + 1 byte len + 3 byte id + 0x53 + 3 byte len = 9 bytes,
// so while the message buffer == CB_BUF_MAX, the maximum object we can store
// is CB_BUF_MAX - 9
#define CB_OBJ_MAX_NEO      (CB_BUF_MAX_NEO - 9)
#define CB_OBJ_MAX_YK4      (CB_BUF_MAX_YK4 - 9)
#define CB_OBJ_MAX          CB_OBJ_MAX_YK4

#define CB_BUF_MAX_NEO      2048
#define CB_BUF_MAX_YK4      3072
#define CB_BUF_MAX          CB_BUF_MAX_YK4

#define CB_ATR_MAX          33

#define ATR_NEO_R3 "\x3b\xfc\x13\x00\x00\x81\x31\xfe\x15\x59\x75\x62\x69\x6b\x65\x79\x4e\x45\x4f\x72\x33\xe1"
#define ATR_YK4    "\x3b\xf8\x13\x00\x00\x81\x31\xfe\x15\x59\x75\x62\x69\x6b\x65\x79\x34\xd4"

#endif
