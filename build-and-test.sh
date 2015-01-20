#!/bin/sh

set -e

autoreconf -i

if [ "x$ARCH" != "x" ]; then
    version=`cat NEWS  | grep unreleased | cut -d' ' -f3`
    set +e
    tar --exclude .git --transform="s/^\./yubico-piv-tool-${version}/" -czf yubico-piv-tool-${version}.tar.gz .
    set -e

    make -f windows.mk ${ARCH}bit VERSION=$version
else
    ./configure $COVERAGE
    make check
    if [ "x$COVERAGE" != "x" ]; then
        gem install coveralls-lcov
        coveralls-lcov --repo-token $COVERALLS_TOKEN coverage/app2.info
    fi
fi
