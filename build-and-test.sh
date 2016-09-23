#!/bin/sh

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


if [ "x$TRAVIS_OS_NAME" != "xosx" ]; then
    sudo apt-get update -qq
    sudo apt-get remove -qq -y $REMOVE
    sudo apt-get autoremove -qq
    sudo apt-get install -qq -y gengetopt help2man $EXTRA
    TAR=tar
else
    ARCH=osx
    brew update
    brew uninstall libtool
    brew install libtool
    brew install help2man
    brew install pkg-config
    brew install gengetopt
    brew install gnu-tar
    TAR=gtar
fi

set -e

autoreconf -ifv

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
