# Copyright (c) 2014-2016 Yubico AB
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are
# met:
#
#   * Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
#
#   * Redistributions in binary form must reproduce the above
#     copyright notice, this list of conditions and the following
#     disclaimer in the documentation and/or other materials provided
#     with the distribution.
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

TESTS_ENVIRONMENT = export VERSION=$(PACKAGE_VERSION); export EXEEXT=$(EXEEXT);

LOG_COMPILER = $(VALGRIND)

AM_CFLAGS = $(WARN_CFLAGS) @CHECK_CFLAGS@
AM_CPPFLAGS = -I$(top_srcdir)/lib -I$(top_builddir)/lib
AM_CPPFLAGS += -I$(top_srcdir)/tool -I$(top_builddir)/tool
AM_CPPFLAGS += $(OPENSSL_CFLAGS)

AM_LDFLAGS = @CHECK_LIBS@

if COMPILER_CLANG
AM_LDFLAGS += -no-fast-install
else
AM_LDFLAGS += -no-install
endif

parse_name_LDADD = ../libpiv_util.la $(OPENSSL_LIBS)
test_inout_LDADD = ../libpiv_util.la

check_PROGRAMS = parse_name test_inout
TESTS = basic.sh $(check_PROGRAMS)

if ENABLE_COV
AM_LDFLAGS += --coverage
endif
