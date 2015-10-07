#!/bin/sh

set -e

autoreconf -i

if [ "x$TRAVIS_OS_NAME" != "xosx" ]; then
    sudo apt-get update -qq
    sudo apt-get remove -qq -y $REMOVE
    sudo apt-get autoremove -qq
    sudo apt-get install -qq -y gengetopt help2man $EXTRA
    TAR=tar
else
    ARCH=osx
    brew update
    brew install help2man
    brew install pkg-config
    brew install gengetopt
    brew install gnu-tar
    TAR=gtar
fi
if [ "x$ARCH" != "x" ]; then
    version=`cat NEWS  | grep unreleased | cut -d' ' -f3`
    set +e
    $TAR --exclude .git --transform="s/^\./yubico-piv-tool-${version}/" -czf yubico-piv-tool-${version}.tar.gz .
    set -e
    if [ "x$ARCH" != "xosx" ]; then
        make -f windows.mk ${ARCH}bit VERSION=$version
    else
        make -f mac.mk mac VERSION=$version
    fi
else
    ./configure $COVERAGE
    make check
    if [ "x$COVERAGE" != "x" ]; then
        gem install coveralls-lcov
        coveralls-lcov coverage/app2.info
    fi
fi
