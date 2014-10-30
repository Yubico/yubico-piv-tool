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

AC_INIT([yubico-piv-tool], [0.1.1])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIR([m4])

# Library code modified:                              REVISION++
# Interfaces changed/added/removed:   CURRENT++       REVISION=0
# Interfaces added:                             AGE++
# Interfaces removed:                           AGE=0
AC_SUBST([LT_CURRENT], 0)
AC_SUBST([LT_REVISION], 1)
AC_SUBST([LT_AGE], 0)

AM_INIT_AUTOMAKE([-Wall -Werror foreign])
AM_SILENT_RULES([yes])
AC_PROG_CC
m4_ifdef([AM_PROG_AR], [AM_PROG_AR])

AC_LIBTOOL_WIN32_DLL
AC_PROG_LIBTOOL
AM_MISSING_PROG(HELP2MAN, help2man, $missing_dir)
AM_MISSING_PROG(GENGETOPT, gengetopt, $missing_dir)
PKG_PROG_PKG_CONFIG

PKG_CHECK_MODULES(OPENSSL, openssl)

gl_LD_VERSION_SCRIPT

AC_ARG_WITH([backend],
  [AS_HELP_STRING([--with-backend=ARG],
    [use specific backend/linkage; 'pcsc', 'macscard' or 'winscard'])],
    [],
    [with_backend=check])

case "$with_backend$host" in
  check*-darwin*)
    AC_MSG_NOTICE([Detected Mac: selecting macscard backend])
    AC_MSG_NOTICE([use --with-backend to override])
    with_backend=macscard ;;
  check*-mingw*)
    AC_MSG_NOTICE([Detected Windows: selecting winscard backend])
    AC_MSG_NOTICE([use --with-backend to override])
    with_backend=winscard ;;
esac

if test "x$with_backend" = xcheck || test "x$with_backend" = xpcsc; then
  PKG_CHECK_MODULES([PCSC], [libpcsclite],
                    [with_backend=pcsc], [:])
fi

if test "x$with_backend" = xcheck; then
  AC_CHECK_HEADERS([PCSC/winscard.h])
  AC_MSG_CHECKING([between Mac/Windows winscard])
  if test "x$ac_cv_header_PCSC_winscard_h" = xyes; then
    with_backend=macscard
    AC_MSG_RESULT([Mac])
  else
    with_backend=winscard
    AC_MSG_RESULT([Windows])
  fi
fi

if test "x$with_backend" = xwinscard; then
  AC_MSG_NOTICE([checking for winscard with Windows linkage])
  AC_CHECK_HEADERS([winscard.h])
  PCSC_WIN_LIBS="-lwinscard"
  save_LIBS="$LIBS"
  LIBS="$LIBS $PCSC_WIN_LIBS"
  AC_LINK_IFELSE([AC_LANG_PROGRAM([[#include <winscard.h>]],
          [[SCardBeginTransaction(0)]])],
                 [AC_SUBST([PCSC_WIN_LIBS])],
                 [AC_MSG_ERROR([cannot find Windows PCSC library/headers])])
  LIBS="$save_LIBS"
fi

if test "x$with_backend" = xmacscard; then
  AC_MSG_NOTICE([checking for PCSC with Mac linkage])
  AC_CHECK_HEADERS([PCSC/winscard.h])
  PCSC_MACOSX_LIBS="-Wl,-framework -Wl,PCSC"
  save_LIBS="$LIBS"
  LIBS="$LIBS $PCSC_MACOSX_LIBS"
  AC_LINK_IFELSE([AC_LANG_PROGRAM([[#include <PCSC/wintypes.h>
            #include <PCSC/winscard.h>]],
          [[SCardBeginTransaction(0)]])],
                 [AC_SUBST([PCSC_MACOSX_LIBS])],
                 [AC_MSG_ERROR([cannot find Mac PCSC library/headers])])
  LIBS="$save_LIBS"
fi

if test "x$with_backend" = xpcsc || test "x$with_backend" = xwinscard \
  || test "x$with_backend" = xmacscard; then
  AC_DEFINE([BACKEND_PCSC], 1, [Define to 1 if you the PCSC backend.])
else
  AC_MSG_ERROR([cannot find PCSC/winscard library/headers])
fi



AC_ARG_ENABLE([gcc-warnings],
  [AS_HELP_STRING([--enable-gcc-warnings],
      [turn on lots of GCC warnings (for developers)])],
  [case $enableval in
     yes|no) ;;
     *)      AC_MSG_ERROR([bad value $enableval for gcc-warnings option]) ;;
   esac
   gl_gcc_warnings=$enableval],
  [gl_gcc_warnings=no]
)

if test "$gl_gcc_warnings" = yes; then
  nw="$nw -Wsystem-headers"         # Don't let system headers trigger warnings
  nw="$nw -Wpadded"                 # Struct's arenot padded
  nw="$nw -Wc++-compat"             # We don't care strongly about C++ compilers
  nw="$nw -Wtraditional"            # Warns on #elif which we use often
  nw="$nw -Wtraditional-conversion" # Too many warnings for now
  nw="$nw -Wconversion"             # Too many warnings for now
  nw="$nw -Wsuggest-attribute=pure" # Is it worth using attributes?
  nw="$nw -Wsuggest-attribute=const" # Is it worth using attributes?

  gl_MANYWARN_ALL_GCC([ws])
  gl_MANYWARN_COMPLEMENT(ws, [$ws], [$nw])
  for w in $ws; do
    gl_WARN_ADD([$w])
  done

  gl_WARN_ADD([-fdiagnostics-show-option])
fi

AC_CONFIG_FILES([
  Makefile
  lib/Makefile
  lib/tests/Makefile
  tool/Makefile
  tool/tests/Makefile
  lib/ykpiv-version.h
  lib/ykpiv.pc
])
AC_OUTPUT

AC_MSG_NOTICE([summary of build options:

  Version:          ${VERSION}
  Host type:        ${host}
  Install prefix:   ${prefix}
  Compiler:         ${CC}
  CFLAGS:           ${CFLAGS}
  CPPFLAGS:         ${CPPFLAGS}
  Warnings:         ${WARN_CFLAGS}
  Backend:          ${with_backend}
  PCSC
          CFLAGS:   ${PCSC_CFLAGS}
            LIBS:   ${PCSC_LIBS}
  Winscard
            LIBS:   ${PCSC_WIN_LIBS}
  Mac PCSC
            LIBS:   ${PCSC_MACOSX_LIBS}
])
