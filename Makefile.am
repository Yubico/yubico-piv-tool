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

SUBDIRS = lib tool ykcs11

ACLOCAL_AMFLAGS = -I m4

EXTRA_DIST = windows.mk mac.mk tool/tests/basic.sh tools/fasc.pl ykcs11/tests/reset.sh

EXTRA_DIST += doc/Attestation.adoc doc/YKCS11_release_notes.adoc doc/YubiKey_PIV_introduction.adoc

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
	$(CPPCHECK) -q -v -f --enable=all -i tool/cmdline.c lib tool ykcs11
endif

# Maintainer rules.

if DX_COND_html
doxygen:
	doxygen lib/Doxyfile
endif

hwcheck:
	@$(srcdir)/tools/confirm.sh && YKPIV_ENV_HWTESTS_CONFIRMED="1" $(MAKE) check

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
	$(HELP2ADOC) -e tool/yubico-piv-tool -n "Yubico PIV Tool" -i tool/yubico-piv-tool.h2m > yubico-piv-tool.1.txt
	$(YUBICO_GITHUB_REPO)/save-mans $(PACKAGE) yubico-piv-tool.1.txt
	$(YUBICO_GITHUB_REPO)/publish $(PACKAGE) $(VERSION) $(PACKAGE)-$(VERSION).tar.gz*
