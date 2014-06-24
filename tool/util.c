 /*
 * Copyright (c) 2014 Yubico AB
 * All rights reserved.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 * Additional permission under GNU GPL version 3 section 7
 *
 * If you modify this program, or any covered work, by linking or
 * combining it with the OpenSSL project's OpenSSL library (or a
 * modified version of that library), containing parts covered by the
 * terms of the OpenSSL or SSLeay licenses, We grant you additional 
 * permission to convey the resulting work. Corresponding Source for a
 * non-source form of such a combination shall include the source code
 * for the parts of OpenSSL used as well as that of the covered work.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#endif

#include <openssl/x509.h>

#include <ykpiv.h>

#include "cmdline.h"
#include "util.h"

FILE *open_file(const char *file_name, int mode) {
  FILE *file;
  if(!strcmp(file_name, "-")) {
    file = mode == INPUT ? stdin : stdout;
  } else {
    file = fopen(file_name, mode == INPUT ? "r" : "w");
    if(!file) {
      fprintf(stderr, "Failed opening '%s'!\n", file_name);
      return NULL;
    }
  }
  return file;
}

unsigned char get_algorithm(EVP_PKEY *key) {
  int type = EVP_PKEY_type(key->type);
  switch(type) {
    case EVP_PKEY_RSA:
      {
        RSA *rsa = EVP_PKEY_get1_RSA(key);
        int size = RSA_size(rsa);
        if(size == 256) {
          return YKPIV_ALGO_RSA2048;
        } else if(size == 128) {
          return YKPIV_ALGO_RSA1024;
        } else {
          fprintf(stderr, "Unuseable key of %d bits, only 1024 and 2048 is supported.\n", size * 8);
          return 0;
        }
      }
    case EVP_PKEY_EC:
      {
        EC_KEY *ec = EVP_PKEY_get1_EC_KEY(key);
        const EC_GROUP *group = EC_KEY_get0_group(ec);
        int curve = EC_GROUP_get_curve_name(group);
        if(curve == NID_X9_62_prime256v1) {
          return YKPIV_ALGO_ECCP256;
        } else {
          fprintf(stderr, "Unknown EC curve %d\n", curve);
          return 0;
        }
      }
    default:
      fprintf(stderr, "Unknown algorithm %d.\n", type);
      return 0;
  }
}

X509_NAME *parse_name(char *name) {
  X509_NAME *parsed = NULL;
  char *ptr = name;
  char *part;
  if(*name != '/') {
    fprintf(stderr, "Name does not start with '/'!\n");
    return NULL;
  }
  parsed = X509_NAME_new();
  if(!parsed) {
    fprintf(stderr, "Failed to allocate memory\n");
    return NULL;
  }
  while((part = strtok(ptr, "/"))) {
    char *key;
    char *value;
    char *equals = strchr(part, '=');
    if(!equals) {
      fprintf(stderr, "The part '%s' doesn't seem to contain a =.\n", part);
      goto parse_err;
    }
    *equals++ = '\0';
    value = equals;
    key = part;

    ptr = NULL;
    if(!key) {
      fprintf(stderr, "Malformed name (%s)\n", part);
      goto parse_err;
    }
    if(!value) {
      fprintf(stderr, "Malformed name (%s)\n", part);
      goto parse_err;
    }
    if(!X509_NAME_add_entry_by_txt(parsed, key, MBSTRING_UTF8, (unsigned char*)value, -1, -1, 0)) {
      fprintf(stderr, "Failed adding %s=%s to name.\n", key, value);
      goto parse_err;
    }
  }
  return parsed;
parse_err:
  X509_NAME_free(parsed);
  return NULL;
}

void dump_hex(const unsigned char *buf, unsigned int len) {
  unsigned int i;
  for (i = 0; i < len; i++) {
    fprintf(stderr, "%02x ", buf[i]);
  }
}

int get_length(unsigned char *buffer, int *len) {
  if(buffer[0] < 0x81) {
    *len = buffer[0];
    return 1;
  } else if((*buffer & 0x7f) == 1) {
    *len = buffer[1];
    return 2;
  } else if((*buffer & 0x7f) == 2) {
    *len = (buffer[1] << 8) + buffer[2];
    return 3;
  }
  return 0;
}

int set_length(unsigned char *buffer, int length) {
  if(length < 0x80) {
    *buffer++ = length;
    return 1;
  } else if(length < 0xff) {
    *buffer++ = 0x81;
    *buffer++ = length;
    return 2;
  } else {
    *buffer++ = 0x82;
    *buffer++ = (length >> 8) & 0xff;
    *buffer++ = length & 0xff;
    return 3;
  }
}

int get_object_id(enum enum_slot slot) {
  int object;

  switch(slot) {
    case slot_arg_9a:
      object = 0x5fc105;
      break;
    case slot_arg_9c:
      object = 0x5fc10a;
      break;
    case slot_arg_9d:
      object = 0x5fc10b;
      break;
    case slot_arg_9e:
      object = 0x5fc101;
      break;
    case slot__NULL:
    default:
      object = 0;
  }
  return object;
}
