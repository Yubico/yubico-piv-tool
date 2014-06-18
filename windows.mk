# Copyright (C) 2014 Yubico AB
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

PACKAGE=yubico-piv-tool
OPENSSLVERSION=1.0.1h

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
		wget --no-check-certificate "https://www.openssl.org/source/openssl-$(OPENSSLVERSION).tar.gz" && \
	tar xfa openssl-$(OPENSSLVERSION).tar.gz && \
	cd openssl-$(OPENSSLVERSION) && \
	CROSS_COMPILE="$(HOST)-" ./Configure mingw64 no-asm shared --prefix=$(PWD)/tmp$(ARCH)/root && \
	make all install_sw && \
	cp LICENSE $(PWD)/tmp$(ARCH)/root/licenses/openssl.txt && \
	cd .. && \
	cp ../$(PACKAGE)-$(VERSION).tar.gz . && \
	tar xfa $(PACKAGE)-$(VERSION).tar.gz && \
	cd $(PACKAGE)-$(VERSION)/ && \
	CC=$(HOST)-gcc PKG_CONFIG_PATH=$(PWD)/tmp$(ARCH)/root/lib/pkgconfig lt_cv_deplibs_check_method=pass_all ./configure --host=$(HOST) --build=x86_64-unknown-linux-gnu --prefix=$(PWD)/tmp$(ARCH)/root LDFLAGS=-L$(PWD)/tmp$(ARCH)/root/lib CPPFLAGS=-I$(PWD)/tmp$(ARCH)/root/include && \
	make install $(CHECK) && \
	cp COPYING $(PWD)/tmp$(ARCH)/root/licenses/$(PACKAGE).txt && \
	cd .. && \
	cd root && \
	zip -r ../../$(PACKAGE)-$(VERSION)-win$(ARCH).zip *

32bit:
	$(MAKE) -f windows.mk doit ARCH=32 HOST=i686-w64-mingw32 CHECK=check

64bit:
	$(MAKE) -f windows.mk doit ARCH=64 HOST=x86_64-w64-mingw32 CHECK=check

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
