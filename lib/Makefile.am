# Copyright (c) 2014-2016 Yubico AB
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

lib_LTLIBRARIES = libykpiv.la

libykpiv_la_SOURCES = ykpiv.c version.c ykpiv.pc.in ykpiv.map internal.h
libykpiv_la_SOURCES += error.c
libykpiv_la_includedir = $(includedir)/ykpiv
libykpiv_la_include_HEADERS = ykpiv.h ykpiv-version.h
EXTRA_libykpiv_la_DEPENDENCIES = ykpiv.map

libykpiv_la_LIBADD = $(OPENSSL_LIBS) $(PCSC_LIBS)
libykpiv_la_LIBADD += $(PCSC_WIN_LIBS) $(PCSC_MACOSX_LIBS)

libykpiv_la_LDFLAGS = -no-undefined
libykpiv_la_LDFLAGS += -version-info $(LT_CURRENT):$(LT_REVISION):$(LT_AGE)

if HAVE_LD_VERSION_SCRIPT
libykpiv_la_LDFLAGS += -Wl,--version-script=$(srcdir)/ykpiv.map
else
libykpiv_la_LDFLAGS += -export-symbols-regex '^ykpiv_.*'
endif

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = ykpiv.pc

if ENABLE_COV
AM_CFLAGS += --coverage
AM_LDFLAGS = --coverage
endif
