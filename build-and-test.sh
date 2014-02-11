#!/bin/sh

set -e
set -x

autoreconf -i

if [ "x$ARCH" != "x" ]; then
    version=`cat NEWS  | grep unreleased | cut -d' ' -f3`
    set +e
    tar --exclude .git --transform="s/^\./yubico-piv-tool-${version}/" -czf yubico-piv-tool-${version}.tar.gz .
    set -e

    make -f windows.mk ${ARCH}bit VERSION=$version
else
    ./configure
    make check
fi
