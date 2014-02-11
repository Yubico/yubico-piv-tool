#!/bin/sh

set -e
set -x

autoreconf -i

if [ "x$ARCH" != "x" ]; then
    ./configure
    touch ChangeLog
    touch yubico-piv-tool.1
    make dist

    if [ "x$ARCH" = "x32" ]; then
        export CC=i686-w64-mingw32-gcc
    else
        export CC=x86_64-w64-mingw32-gcc
    fi
    make -f windows.mk ${ARCH}bit `grep ^VERSION Makefile|sed 's/ = /=/'`
else
    ./configure
    make check
fi
