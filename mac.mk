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

PACKAGE=yubico-piv-tool
OPENSSLVERSION=1.0.2l
CFLAGS="-mmacosx-version-min=10.6"

all: usage mac

.PHONY: usage
usage:
	@if test -z "$(VERSION)" || test -z "$(PGPKEYID)"; then \
		echo "Try this instead:"; \
		echo "  make PGPKEYID=[PGPKEYID] VERSION=[VERSION]"; \
		echo "For example:"; \
		echo "  make PGPKEYID=2117364A VERSION=1.6.0"; \
		exit 1; \
	fi

doit:
	rm -rf tmp && mkdir tmp && cd tmp && \
	mkdir -p root/licenses && \
	cp ../openssl-$(OPENSSLVERSION).tar.gz . || \
		curl -L -O "https://www.openssl.org/source/openssl-$(OPENSSLVERSION).tar.gz" && \
	tar xfz openssl-$(OPENSSLVERSION).tar.gz && \
	cd openssl-$(OPENSSLVERSION) && \
	./Configure darwin64-x86_64-cc shared no-ssl2 no-ssl3 no-engines --prefix=$(PWD)/tmp/root $(CFLAGS) && \
	make all install_sw && \
	cp LICENSE $(PWD)/tmp$(ARCH)/root/licenses/openssl.txt && \
	rm -rf $(PWD)/tmp/root/ssl/ && \
	rm -rf $(PWD)/tmp/root/bin/ && \
	rm -rf $(PWD)/tmp/root/lib/engines/ && \
	rm -rf $(PWD)/tmp/root/lib/libssl* && \
	rm $(PWD)/tmp/root/lib/pkgconfig/libssl.pc && \
	rm $(PWD)/tmp/root/lib/pkgconfig/openssl.pc && \
	cd .. && \
	cp ../$(PACKAGE)-$(VERSION).tar.gz . && \
	tar xfz $(PACKAGE)-$(VERSION).tar.gz && \
	cd $(PACKAGE)-$(VERSION)/ && \
	CFLAGS=$(CFLAGS) PKG_CONFIG_PATH=$(PWD)/tmp/root/lib/pkgconfig ./configure --prefix=$(PWD)/tmp/root && \
	make install $(CHECK) && \
	chmod u+w $(PWD)/tmp/root/lib/libcrypto.1.0.0.dylib && \
	install_name_tool -id @loader_path/libcrypto.1.0.0.dylib $(PWD)/tmp/root/lib/libcrypto.1.0.0.dylib && \
	install_name_tool -id @loader_path/libykpiv.1.dylib $(PWD)/tmp/root/lib/libykpiv.1.dylib && \
	install_name_tool -id @loader_path/libykcs11.1.dylib $(PWD)/tmp/root/lib/libykcs11.1.dylib && \
	install_name_tool -change $(PWD)/tmp/root/lib/libcrypto.1.0.0.dylib @loader_path/libcrypto.1.0.0.dylib $(PWD)/tmp/root/lib/libykpiv.1.dylib && \
	install_name_tool -change $(PWD)/tmp/root/lib/libcrypto.1.0.0.dylib @loader_path/libcrypto.1.0.0.dylib $(PWD)/tmp/root/lib/libykcs11.1.dylib && \
	install_name_tool -change $(PWD)/tmp/root/lib/libcrypto.1.0.0.dylib @executable_path/../lib/libcrypto.1.0.0.dylib $(PWD)/tmp/root/bin/yubico-piv-tool && \
	install_name_tool -change $(PWD)/tmp/root/lib/libykpiv.1.dylib @loader_path/libykpiv.1.dylib $(PWD)/tmp/root/lib/libykcs11.1.dylib && \
	install_name_tool -change $(PWD)/tmp/root/lib/libykpiv.1.dylib @executable_path/../lib/libykpiv.1.dylib $(PWD)/tmp/root/bin/yubico-piv-tool ; \
	if otool -L $(PWD)/tmp/root/lib/*.dylib $(PWD)/tmp/root/bin/* | grep '$(PWD)/tmp/root' | grep -q compatibility; then \
		echo "something is incorrectly linked!"; \
		exit 1; \
	fi && \
	rm $(PWD)/tmp/root/lib/*.la && \
	rm -rf $(PWD)/tmp/root/lib/pkgconfig && \
	cp COPYING $(PWD)/tmp/root/licenses/$(PACKAGE).txt && \
	cd .. && \
	cd root && \
	zip -r ../../$(PACKAGE)-$(VERSION)-mac.zip *

mac:
	$(MAKE) -f mac.mk doit CHECK=check

upload-mac:
	@if test ! -d "$(YUBICO_GITHUB_REPO)"; then \
		echo "yubico.github.com repo not found!"; \
		echo "Make sure that YUBICO_GITHUB_REPO is set"; \
		exit 1; \
		fi
	gpg --detach-sign --default-key $(PGPKEYID) \
		$(PACKAGE)-$(VERSION)-mac.zip
	gpg --verify $(PACKAGE)-$(VERSION)-mac.zip.sig
	$(YUBICO_GITHUB_REPO)/publish $(PACKAGE) $(VERSION) $(PACKAGE)-$(VERSION)-mac.zip*
