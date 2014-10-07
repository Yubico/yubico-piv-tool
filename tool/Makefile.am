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

SUBDIRS = . tests

AM_CFLAGS = $(WERROR_CFLAGS) $(WARN_CFLAGS)
AM_CPPFLAGS = $(OPENSSL_CFLAGS)
AM_CPPFLAGS += -I$(top_srcdir)/lib -I$(top_builddir)/lib

bin_PROGRAMS = yubico-piv-tool
yubico_piv_tool_SOURCES = yubico-piv-tool.c yubico-piv-tool.h2m
yubico_piv_tool_LDADD = $(OPENSSL_LIBS) ../lib/libykpiv.la
yubico_piv_tool_LDADD += libpiv_cmd.la libpiv_util.la

noinst_LTLIBRARIES = libpiv_cmd.la libpiv_util.la
libpiv_cmd_la_SOURCES = cmdline.ggo cmdline.c cmdline.h
libpiv_cmd_la_CFLAGS =

libpiv_util_la_SOURCES = util.c util.h
libpiv_util_la_LIBADD = $(OPENSSL_LIBS)

cmdline.c cmdline.h: cmdline.ggo Makefile.am
	$(GENGETOPT) --input $^

BUILT_SOURCES = cmdline.c cmdline.h
MAINTAINERCLEANFILES = $(BUILT_SOURCES)

# Doc.

dist_man_MANS = yubico-piv-tool.1
MAINTAINERCLEANFILES += $(dist_man_MANS)

yubico-piv-tool.1: $(yubico_piv_tool_SOURCES) \
		$(top_srcdir)/configure.ac
	$(HELP2MAN) --no-info \
		--name="Yubico PIV tool" \
		--include=$(srcdir)/yubico-piv-tool.h2m \
		--output=$@ $(builddir)/yubico-piv-tool$(EXEEXT)
