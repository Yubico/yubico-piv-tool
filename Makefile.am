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
AM_CPPFLAGS = $(PCSC_CFLAGS)

bin_PROGRAMS = yubico-piv-tool
yubico_piv_tool_SOURCES = yubico-piv-tool.c
yubico_piv_tool_SOURCES += cmdline.ggo cmdline.c cmdline.h
yubico_piv_tool_LDADD = $(PCSC_LIBS)

cmdline.c cmdline.h: cmdline.ggo Makefile.am
	gengetopt --input $^

BUILT_SOURCES = cmdline.c cmdline.h
MAINTAINERCLEANFILES = $(BUILT_SOURCES)

# Doc.

dist_man_MANS = yubico-piv-tool.1
MAINTAINERCLEANFILES += $(dist_man_MANS)

yubico-piv-tool.1: $(yubico_piv_tool_SOURCES) \
		$(top_srcdir)/configure.ac
	$(HELP2MAN) --no-info \
		--name="Yubico PIV tool" \
		--output=$@ $(top_builddir)/yubico-piv-tool$(EXEEXT)

# Maintainer rules.

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
	make ChangeLog distcheck
	gpg --detach-sign --default-key $(KEYID) $(PACKAGE)-$(VERSION).tar.gz
	gpg --verify $(PACKAGE)-$(VERSION).tar.gz.sig
	git tag -sm "$(PACKAGE)-$(VERSION)" $(PACKAGE)-$(VERSION)
	git push
	git push --tags
	git add $(PACKAGE)-$(VERSION).tar.gz
	git add $(PACKAGE)-$(VERSION).tar.gz.sig
	git stash
	git checkout gh-pages
	git stash pop
	git mv $(PACKAGE)-$(VERSION).tar.gz releases/
	git mv $(PACKAGE)-$(VERSION).tar.gz.sig releases/
	x=$$(ls -1 releases/*.tar.gz | awk -F\- '{print $$4}' | sed 's/.tar.gz//' | paste -sd ',' -); sed -i -e "2s/\[.*\]/[$$x]/" releases.html
	git add releases.html
	git commit -m "Added tarball for release $(VERSION)."
	git push
	git checkout master
