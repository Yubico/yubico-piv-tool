/*
 * Copyright (c) 2015 Yubico AB
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
 */

#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>

#include "util.h"

#ifdef _WIN32
#define pipe(fds) _pipe(fds,4096, 0)
#endif

static void test_inout(enum enum_format format) {
  const unsigned char buf[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
  unsigned char buf2[sizeof(buf)];
  int pipefd[2];
  FILE *tmp1, *tmp2;

  assert(pipe(pipefd) == 0);
  tmp1 = fdopen(pipefd[1], "w");
  dump_data(buf, sizeof(buf), tmp1, false, format);
  fclose(tmp1);
  tmp2 = fdopen(pipefd[0], "r");
  read_data(buf2, sizeof(buf2), tmp2, format);
  assert(memcmp(buf, buf2, sizeof(buf)) == 0);
  fclose(tmp2);
}

int main(void) {
  test_inout(format_arg_base64);
  test_inout(format_arg_hex);
  test_inout(format_arg_binary);
  exit(0);
}
