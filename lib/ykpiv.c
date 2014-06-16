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

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "internal.h"
#include "ykpiv.h"

ykpiv_rc ykpiv_init(ykpiv_state **state, int verbose) {
  ykpiv_state *s = malloc(sizeof(ykpiv_state));
  if(s == NULL) {
    return YKPIV_MEMORY_ERROR;
  }
  memset(s, 0, sizeof(ykpiv_state));
  s->verbose = verbose;
  *state = s;
  return YKPIV_OK;
}

ykpiv_rc ykpiv_done(ykpiv_state *state) {
  free(state);
  return YKPIV_OK;
}

ykpiv_rc ykpiv_connect(ykpiv_state *state, const char *wanted) {
  unsigned long num_readers = 0;
  unsigned long active_protocol;
  char reader_buf[1024];
  long rc;
  char *reader_ptr;

  rc = SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, &state->context);
  if (rc != SCARD_S_SUCCESS) {
    if(state->verbose) {
      fprintf (stderr, "error: SCardEstablishContext failed, rc=%08lx\n", rc);
    }
    return YKPIV_PCSC_ERROR;
  }

  rc = SCardListReaders(state->context, NULL, NULL, &num_readers);
  if (rc != SCARD_S_SUCCESS) {
    if(state->verbose) {
      fprintf (stderr, "error: SCardListReaders failed, rc=%08lx\n", rc);
    }
    SCardReleaseContext(state->context);
    return YKPIV_PCSC_ERROR;
  }

  if (num_readers > sizeof(reader_buf)) {
    num_readers = sizeof(reader_buf);
  }

  rc = SCardListReaders(state->context, NULL, reader_buf, &num_readers);
  if (rc != SCARD_S_SUCCESS)
  {
    if(state->verbose) {
      fprintf (stderr, "error: SCardListReaders failed, rc=%08lx\n", rc);
    }
    SCardReleaseContext(state->context);
    return YKPIV_PCSC_ERROR;
  }

  reader_ptr = reader_buf;
  if(wanted) {
    while(*reader_ptr != '\0') {
      if(strstr(reader_ptr, wanted)) {
	if(state->verbose) {
	  fprintf(stderr, "using reader '%s' matching '%s'.\n", reader_ptr, wanted);
	}
	break;
      } else {
	if(state->verbose) {
	  fprintf(stderr, "skipping reader '%s' since it doesn't match.\n", reader_ptr);
	}
	reader_ptr += strlen(reader_ptr) + 1;
      }
    }
  }
  if(*reader_ptr == '\0') {
    if(state->verbose) {
      fprintf(stderr, "error: no useable reader found.\n");
    }
    SCardReleaseContext(state->context);
    return YKPIV_PCSC_ERROR;
  }

  rc = SCardConnect(state->context, reader_ptr, SCARD_SHARE_SHARED,
      SCARD_PROTOCOL_T1, &state->card, &active_protocol);
  if(rc != SCARD_S_SUCCESS)
  {
    if(state->verbose) {
      fprintf(stderr, "error: SCardConnect failed, rc=%08lx\n", rc);
    }
    SCardReleaseContext(state->context);
    return YKPIV_PCSC_ERROR;
  }

  return YKPIV_OK;
}
