# Copyright (c) 2015 Yubico AB
# All rights reserved.
# 
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.
#
# Additional permission under GNU GPL version 3 section 7
#
# If you modify this program, or any covered work, by linking or
# combining it with the OpenSSL project's OpenSSL library (or a
# modified version of that library), containing parts covered by the
# terms of the OpenSSL or SSLeay licenses, We grant you additional 
# permission to convey the resulting work. Corresponding Source for a
# non-source form of such a combination shall include the source code
# for the parts of OpenSSL used as well as that of the covered work.

SUBDIRS = .
#tests

AM_CFLAGS = $(WERROR_CFLAGS) $(WARN_CFLAGS)
AM_CPPFLAGS = $(OPENSSL_CFLAGS) $(PCSC_CFLAGS) $(LIBNSPR_CFLAGS)
AM_CPPFLAGS += -I$(top_srcdir)/lib -I$(top_builddir)/lib

lib_LTLIBRARIES = libykcs11.la

libykcs11_la_SOURCES = ykcs11.c version.c ykcs11.pc.in ykcs11.map
libykcs11_la_SOURCES += vendors.c vendor.h yubico.c yubico.h
libykcs11_la_SOURCES += utils.h utils.c

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
libykcs11_la_LIBADD = $(LIBNSPR) ../lib/libykpiv.la

libykcs11_la_LDFLAGS = -no-undefined
libykcs11_la_LDFLAGS += -version-info $(LT_CURRENT):$(LT_REVISION):$(LT_AGE)

if HAVE_LD_VERSION_SCRIPT
libykcs11_la_LDFLAGS += -Wl,--version-script=$(srcdir)/ykcs11.map
else
libykcs11_la_LDFLAGS += -export-symbols-regex '^ykcs11_.*'
endif

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = ykcs11.pc

if ENABLE_COV
AM_CFLAGS += --coverage
AM_LDFLAGS = --coverage
endif
