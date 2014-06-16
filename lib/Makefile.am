# Copyright (c) 2014 Yubico AB
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

AM_CFLAGS = $(WERROR_CFLAGS) $(WARN_CFLAGS)
AM_CPPFLAGS = $(OPENSSL_CFLAGS) $(PCSC_CFLAGS)

lib_LTLIBRARIES = libykpiv.la

libykpiv_la_SOURCES = ykpiv.c version.c ykpiv.pc.in ykpiv.map
libykpiv_la_includedir = $(includedir)/ykpiv
libykpiv_la_include_HEADERS = ykpiv.h ykpiv-version.h

libykpiv_la_LIBADD = $(OPENSSL_LIBS) $(PCSC_LIBS)
libykpiv_la_LIBADD += $(LTLIBWINSCARD) $(PCSC_MACOSX_LIBS)

libykpiv_la_LDFLAGS = -no-undefined
libykpiv_la_LDFLAGS += -version-info $(LT_CURRENT):$(LT_REVISION):$(LT_AGE)

if HAVE_LD_VERSION_SCRIPT
libykpiv_la_LDFLAGS += -Wl,--version-script=$(srcdir)/ykpiv.map
else
libykpiv_la_LDFLAGS += -export-symbols-regex '^ykpiv_.*'
endif

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = ykpiv.pc
