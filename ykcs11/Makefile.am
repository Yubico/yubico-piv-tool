# Copyright (c) 2015-2016 Yubico AB
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
AM_CPPFLAGS += -I$(top_srcdir)/tool -I$(top_builddir)/tool

EXTRA_DIST  = ykcs11.module.in ykcs11.pc.in

lib_LTLIBRARIES = libykcs11.la

libykcs11_la_SOURCES = ykcs11.c
libykcs11_la_SOURCES += ykcs11.h debug.h
libykcs11_la_SOURCES += token.c token.h
libykcs11_la_SOURCES += mechanisms.c mechanisms.h
libykcs11_la_SOURCES += utils.c utils.h
libykcs11_la_SOURCES += openssl_utils.c openssl_utils.h openssl_types.h
libykcs11_la_SOURCES += objects.c objects.h obj_types.h
libykcs11_la_SOURCES += pkcs11.h pkcs11y.h pkcs11.exports
libykcs11_la_SOURCES += ykcs11-version.h

libykcs11_la_LIBADD = ../lib/libykpiv.la
libykcs11_la_LIBADD += ../tool/libpiv_util.la

libykcs11_la_LDFLAGS = -no-undefined
libykcs11_la_LDFLAGS += -export-symbols "$(srcdir)/pkcs11.exports"
libykcs11_la_LDFLAGS += -module -avoid-version

libykcs11dir = $(libdir)/pkcs11

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = ykcs11.pc

p11kitdir = $(datadir)/p11-kit/modules
p11kit_DATA = ykcs11.module

if ENABLE_COV
AM_CFLAGS += --coverage
AM_LDFLAGS = --coverage
endif

# see http://wiki.cacert.org/wiki/Pkcs11TaskForce
install-exec-hook:
	$(MKDIR_P) "$(DESTDIR)$(pkcs11dir)"
	for l in libykcs11$(DYN_LIB_EXT); do \
		rm -f "$(DESTDIR)$(pkcs11dir)/$$l"; \
		$(LN_S) ../$$l "$(DESTDIR)$(pkcs11dir)/$$l"; \
	done
