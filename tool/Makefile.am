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
AM_CPPFLAGS = $(OPENSSL_CFLAGS)
AM_CPPFLAGS += -I$(top_srcdir)/lib -I$(top_builddir)/lib

bin_PROGRAMS = yubico-piv-tool
yubico_piv_tool_SOURCES = yubico-piv-tool.c yubico-piv-tool.h2m
yubico_piv_tool_LDADD = $(OPENSSL_LIBS) $(top_builddir)/lib/libykpiv.la
yubico_piv_tool_LDADD += libpiv_cmd.la libpiv_util.la

noinst_LTLIBRARIES = libpiv_cmd.la libpiv_util.la
libpiv_cmd_la_SOURCES = cmdline.ggo cmdline.c cmdline.h
libpiv_cmd_la_CFLAGS =

libpiv_util_la_SOURCES = util.c util.h openssl-compat.c openssl-compat.h
libpiv_util_la_LIBADD = $(top_builddir)/lib/libykpiv.la $(OPENSSL_LIBS)

cmdline.c cmdline.h: cmdline.ggo Makefile.am $(top_srcdir)/configure.ac
	$(GENGETOPT) --input $^

BUILT_SOURCES = cmdline.c cmdline.h
MAINTAINERCLEANFILES = $(BUILT_SOURCES)

# Doc.

dist_man_MANS = yubico-piv-tool.1
MAINTAINERCLEANFILES += $(dist_man_MANS)

yubico-piv-tool.1: $(yubico_piv_tool_SOURCES) $(libpiv_cmd_la_SOURCES) $(top_srcdir)/configure.ac | $(builddir)/yubico-piv-tool$(EXEEXT)
	$(HELP2MAN) --no-info \
		--name="Yubico PIV tool" \
		--include=$(srcdir)/yubico-piv-tool.h2m \
		--output=$@ $(builddir)/yubico-piv-tool$(EXEEXT)

if ENABLE_COV
AM_CFLAGS += --coverage
AM_LDFLAGS = --coverage
endif
