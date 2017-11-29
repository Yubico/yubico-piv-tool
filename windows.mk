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
OPENSSLVERSION=1.0.2m
CHECKVERSION=0.12.0

all: usage 32bit 64bit

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
	rm -rf tmp$(ARCH) && mkdir tmp$(ARCH) && cd tmp$(ARCH) && \
	mkdir -p root/licenses && \
	cp ../openssl-$(OPENSSLVERSION).tar.gz . || \
		curl -L -O "https://www.openssl.org/source/openssl-$(OPENSSLVERSION).tar.gz" && \
	tar xfa openssl-$(OPENSSLVERSION).tar.gz && \
	cd openssl-$(OPENSSLVERSION) && \
	CROSS_COMPILE="$(HOST)-" ./Configure mingw$(64) no-ssl2 no-ssl3 no-engines shared --prefix=$(PWD)/tmp$(ARCH)/root -static-libgcc && \
	make depend all install_sw VERSION="$(OPENSSLVERSION)" && \
	cp LICENSE $(PWD)/tmp$(ARCH)/root/licenses/openssl.txt && \
	rm -rf $(PWD)/tmp$(ARCH)/root/ssl/ && \
	rm $(PWD)/tmp$(ARCH)/root/bin/openssl.exe && \
	rm $(PWD)/tmp$(ARCH)/root/bin/c_rehash && \
	rm -rf $(PWD)/tmp$(ARCH)/root/lib/engines/ && \
	cd .. && \
	cp ../check-$(CHECKVERSION).tar.gz . || \
		curl -L -O "https://github.com/libcheck/check/releases/download/$(CHECKVERSION)/check-$(CHECKVERSION).tar.gz" && \
	tar xfa check-$(CHECKVERSION).tar.gz && \
	cd check-$(CHECKVERSION) && \
	CC=$(HOST)-gcc PKG_CONFIG_PATH=$(PWD)/tmp$(ARCH)/root/lib/pkgconfig ./configure --host=$(HOST) --build=x86_64-unknown-linux-gnu --prefix=$(PWD)/tmp$(ARCH)/root --disable-subunit --enable-static --disable-shared && \
	make all install && \
	cd .. && \
	cp ../$(PACKAGE)-$(VERSION).tar.gz . && \
	tar xfa $(PACKAGE)-$(VERSION).tar.gz && \
	cd $(PACKAGE)-$(VERSION)/ && \
	CC=$(HOST)-gcc PKG_CONFIG_PATH=$(PWD)/tmp$(ARCH)/root/lib/pkgconfig lt_cv_deplibs_check_method=pass_all ./configure --host=$(HOST) --build=x86_64-unknown-linux-gnu --prefix=$(PWD)/tmp$(ARCH)/root LDFLAGS=-L$(PWD)/tmp$(ARCH)/root/lib CPPFLAGS=-I$(PWD)/tmp$(ARCH)/root/include && \
	WINEPATH="/usr/$(HOST)/lib/" make install $(CHECK) && \
	rm $(PWD)/tmp$(ARCH)/root/lib/*.la && \
	rm -rf $(PWD)/tmp$(ARCH)/root/lib/pkgconfig/ && \
	cp COPYING $(PWD)/tmp$(ARCH)/root/licenses/$(PACKAGE).txt && \
	cd .. && \
	cd root && \
	zip -r ../../$(PACKAGE)-$(VERSION)-win$(ARCH).zip *

32bit:
	$(MAKE) -f windows.mk doit ARCH=32 HOST=i686-w64-mingw32 CHECK=check

64bit:
	$(MAKE) -f windows.mk doit ARCH=64 HOST=x86_64-w64-mingw32 64=64 CHECK=check

upload:
	@if test ! -d "$(YUBICO_GITHUB_REPO)"; then \
		echo "yubico.github.com repo not found!"; \
		echo "Make sure that YUBICO_GITHUB_REPO is set"; \
		exit 1; \
		fi
	gpg --detach-sign --default-key $(PGPKEYID) \
		$(PACKAGE)-$(VERSION)-win$(ARCH).zip
	gpg --verify $(PACKAGE)-$(VERSION)-win$(ARCH).zip.sig
	$(YUBICO_GITHUB_REPO)/publish $(PACKAGE) $(VERSION) $(PACKAGE)-$(VERSION)-win${ARCH}.zip*

upload-32bit:
	$(MAKE) -f windows.mk upload ARCH=32

upload-64bit:
	$(MAKE) -f windows.mk upload ARCH=64
