# Copyright (c) 2014-2017 Yubico AB
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

#
# Note: this build script is for testing OpenSSL 1.1 builds.  The official
# Linux release builds are handled by the standard Makefile.
#
PACKAGE=yubico-piv-tool
OPENSSLVERSION=1.1.0g

all: linux

doit:
	rm -rf tmp && mkdir tmp && cd tmp && \
	mkdir -p root/licenses && \
	cp ../openssl-$(OPENSSLVERSION).tar.gz . || \
		curl -L -O "https://www.openssl.org/source/openssl-$(OPENSSLVERSION).tar.gz" && \
	tar xfz openssl-$(OPENSSLVERSION).tar.gz && \
	cd openssl-$(OPENSSLVERSION) && \
	./Configure linux-x86_64 shared --prefix=$(PWD)/tmp/root $(CFLAGS) && \
	make all install VERSION="$(OPENSSLVERSION)" && \
	cp LICENSE $(PWD)/tmp$(ARCH)/root/licenses/openssl.txt && \
	cd .. && \
	cp ../$(PACKAGE)-$(VERSION).tar.gz . && \
	tar xfz $(PACKAGE)-$(VERSION).tar.gz && \
	cd $(PACKAGE)-$(VERSION)/ && \
	CFLAGS=$(CFLAGS) PKG_CONFIG_PATH=$(PWD)/tmp/root/lib/pkgconfig ./configure --prefix=$(PWD)/tmp/root && \
	make install $(CHECK) && \
	cd .. && \
	cd root && \
	zip -r ../../$(PACKAGE)-$(VERSION)-linux-openssl-$(OPENSSLVERSION).zip *

linux:
	$(MAKE) -f linux.mk doit CHECK=check
