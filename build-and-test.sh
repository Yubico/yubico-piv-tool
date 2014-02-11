#!/bin/sh

set -e
set -x

autoreconf -i

if [ "x$LIBUSB" = "xwindows" ]; then
    ./configure
    touch ChangeLog
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
