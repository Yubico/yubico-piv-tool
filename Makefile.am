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

SUBDIRS = lib tool

ACLOCAL_AMFLAGS = -I m4

EXTRA_DIST = windows.mk mac.mk tool/tests/basic.sh tools/fasc.pl

EXTRA_DIST += doc/Certificate_Authority_with_NEO.adoc doc/OS_X_code_signing.adoc doc/SSH_with_PIV_and_PKCS11.adoc doc/Windows_certificate.adoc doc/YubiKey_NEO_PIV_introduction.adoc

if ENABLE_COV
cov-reset:
	rm -fr coverage
	find . -name "*.gcda" -exec rm {} \;
	lcov --directory . --zerocounters

cov-report:
	mkdir -p coverage
	lcov --compat-libtool --directory . --capture --output-file coverage/app.info
	lcov --extract coverage/app.info '*.c' --output-file coverage/app2.info
	genhtml -o coverage/ coverage/app2.info

cov:
	make cov-report

clean-local:
	make cov-reset

check:
	make cov
endif

if ENABLE_CPPCHECK
cppcheck:
	$(CPPCHECK) -q -v -f --enable=all -i tool/cmdline.c lib tool
endif

# Maintainer rules.

check-doc-dist:
	perl -pe "s,^EXTRA_DIST \+= .*,EXTRA_DIST += `cd $(srcdir) && ls doc/*.adoc | xargs echo`," < $(srcdir)/Makefile.am > check-doc-dist.tmp
	diff -ur $(srcdir)/Makefile.am check-doc-dist.tmp || \
		(rm -f check-doc-dist.tmp; echo 'error: please update $(srcdir)/Makefile.am to include all docs'; exit 1)
	rm -f check-doc-dist.tmp

ChangeLog:
	cd $(srcdir) && git2cl > ChangeLog

release:
	@if test -z "$(KEYID)"; then \
		echo "Try this instead:"; \
		echo "  make release KEYID=[PGPKEYID]"; \
		echo "For example:"; \
		echo "  make release KEYID=2117364A"; \
		exit 1; \
	fi
	head -3 $(srcdir)/NEWS | \
		grep -q "Version $(VERSION) .released `date -I`" || \
		(echo 'error: Update date/version in $(srcdir)/NEWS.'; exit 1)
	rm -f $(srcdir)/ChangeLog
	make check-doc-dist ChangeLog distcheck
	gpg --detach-sign --default-key $(KEYID) $(PACKAGE)-$(VERSION).tar.gz
	gpg --verify $(PACKAGE)-$(VERSION).tar.gz.sig
	git tag -sm "$(PACKAGE)-$(VERSION)" $(PACKAGE)-$(VERSION)
	git push
	git push --tags
	$(YUBICO_GITHUB_REPO)/publish $(PACKAGE) $(VERSION) $(PACKAGE)-$(VERSION).tar.gz*
