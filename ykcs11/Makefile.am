# Copyright (c) 2015 Yubico AB
# All rights reserved.
# 
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are
# met:
#
#     * Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#
#     * Redistributions in binary form must reproduce the above
#       copyright notice, this list of conditions and the following
#       disclaimer in the documentation and/or other materials provided
#       with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

SUBDIRS = . tests

AM_CFLAGS = $(WERROR_CFLAGS) $(WARN_CFLAGS)
AM_CPPFLAGS = $(OPENSSL_CFLAGS) $(PCSC_CFLAGS)
AM_CPPFLAGS += -I$(top_srcdir)/lib -I$(top_builddir)/lib

lib_LTLIBRARIES = libykcs11.la

libykcs11_la_SOURCES = ykcs11.c version.c ykcs11.pc.in ykcs11.map
libykcs11_la_SOURCES += ykcs11.h debug.h
libykcs11_la_SOURCES += vendors.c vendors.h vendor_ids.h
libykcs11_la_SOURCES += slot_vendors.c slot_vendors.h
libykcs11_la_SOURCES += token_vendors.c token_vendors.h
libykcs11_la_SOURCES += mechanisms.c mechanisms.h
libykcs11_la_SOURCES += yubico_slot.c yubico_slot.h yubico_token.c yubico_token.h
libykcs11_la_SOURCES += utils.c utils.h
libykcs11_la_SOURCES += openssl_utils.c openssl_utils.h openssl_types.h
libykcs11_la_SOURCES += objects.c objects.h obj_types.h
libykcs11_la_SOURCES += pkcs11.h  pkcs11y.h

#internal.h
#libykcs11_la_SOURCES += error.c
#libykcs11_la_LDADD = ../lib/libykpiv.la
#$(OPENSSL_LIBS)
libykcs11_la_includedir = $(includedir)/ykcs11
libykcs11_la_include_HEADERS = ykcs11-version.h
#ykcs11.h
EXTRA_libykcs11_la_DEPENDENCIES = ykcs11.map

#libykcs11_la_LIBADD = $(OPENSSL_LIBS) $(PCSC_LIBS)
#libykcs11_la_LIBADD += $(PCSC_WIN_LIBS) $(PCSC_MACOSX_LIBS)
libykcs11_la_LIBADD = ../lib/libykpiv.la
libykcs11_la_LIBADD += ../tool/libpiv_util.la

libykcs11_la_LDFLAGS = -no-undefined
libykcs11_la_LDFLAGS += -version-info $(LT_CURRENT):$(LT_REVISION):$(LT_AGE)

if HAVE_LD_VERSION_SCRIPT
libykcs11_la_LDFLAGS += -Wl,--version-script=$(srcdir)/ykcs11.map
else
libykcs11_la_LDFLAGS += -export-symbols-regex '^C_.*'
endif

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = ykcs11.pc

if ENABLE_COV
AM_CFLAGS += --coverage
AM_LDFLAGS = --coverage
endif
