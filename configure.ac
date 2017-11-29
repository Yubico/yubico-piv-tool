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

AC_INIT([yubico-piv-tool], [1.5.0])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIR([m4])

# Library code modified:                              REVISION++
# Interfaces changed/added/removed:   CURRENT++       REVISION=0
# Interfaces added:                             AGE++
# Interfaces removed:                           AGE=0
AC_SUBST([LT_CURRENT], 5)
AC_SUBST([LT_REVISION], 0)
AC_SUBST([LT_AGE], 4)

AM_INIT_AUTOMAKE([-Wall -Werror foreign])
AM_SILENT_RULES([yes])
AC_PROG_CC
m4_ifdef([AM_PROG_AR], [AM_PROG_AR])

AC_LIBTOOL_WIN32_DLL
AC_PROG_LIBTOOL
AM_MISSING_PROG(HELP2MAN, help2man, $missing_dir)
AM_MISSING_PROG(HELP2ADOC, help2adoc, $missing_dir)
AM_MISSING_PROG(GENGETOPT, gengetopt, $missing_dir)
PKG_PROG_PKG_CONFIG

PKG_CHECK_MODULES([OPENSSL], [libcrypto], [OPENSSL_VERSION=`$PKG_CONFIG --modversion libcrypto`])
PKG_CHECK_MODULES([CHECK], [check >= 0.9.6])

DX_HTML_FEATURE(ON)
DX_INIT_DOXYGEN(libykpiv,lib/Doxyfile)

gl_LD_VERSION_SCRIPT
gl_VALGRIND_TESTS

# Check for clang
AC_CACHE_CHECK([for clang],
	_cv_clang,[
	AC_TRY_COMPILE([], [
		#ifdef __clang__
		#else
		#error "NOT CLANG"
		#endif
		return 0;
	],
	[_cv_clang=yes],
	[_cv_clang=no],
	[])
])
AM_CONDITIONAL([COMPILER_CLANG], [test "$_cv_clang" = yes])

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
  AC_CHECK_HEADERS([winscard.h])
  AC_MSG_CHECKING([between Mac/Windows winscard])
  if test "x$ac_cv_header_PCSC_winscard_h" = xyes; then
    with_backend=macscard
    AC_MSG_RESULT([Mac])
  elif test "x$ac_cv_header_winscard_h" = xyes; then
    with_backend=winscard
    AC_MSG_RESULT([Windows])
  else
    AC_MSG_RESULT([no])
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
  AC_MSG_ERROR([cannot find PCSC library])
fi

AC_ARG_ENABLE([coverage],
              [AS_HELP_STRING([--enable-coverage],
                              [use Gcov to test the test suite])],
                              [],
                              [enable_cov=no])
AM_CONDITIONAL([ENABLE_COV],[test '!' "$enable_cov" = no])

AC_ARG_ENABLE([cppcheck],
              [AS_HELP_STRING([--enable-cppcheck],
                              [run cppcheck])],
                              [enable_cppcheck="$enableval"],
                              [enable_cppcheck="no"])

have_cppcheck=no
AS_IF([test "x$enable_cppcheck" != xno],
      [AC_PATH_PROG([CPPCHECK], [cppcheck], [NONE])
      AS_IF([test "x$enable_cppcheck" != xno],
            [have_cppcheck=yes
             AC_SUBST([CPPCHECK])],
             [have_cppcheck=no
              AS_IF([test "x$enable_cppcheck" != xauto],
                    [AC_MSG_ERROR([cannot find cppcheck])])])])
AM_CONDITIONAL([ENABLE_CPPCHECK],[test '!' "$have_cppcheck" = no])

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

AC_ARG_ENABLE([ykcs11-debug],
              [AS_HELP_STRING([--enable-ykcs11-debug],
                              [enables YKCS11 debug messages])],
                              [enable_ykcs11_debug="$enableval"],
                              [enable_ykcs11_debug="no"])

AS_IF([test "x$enable_ykcs11_debug" != xno],
            [AC_DEFINE([YKCS11_DBG], [1], [Regular debug flag])
             AC_DEFINE([YKCS11_DINOUT], [1], [Function accessed/left debug flag])
             ykcs11_debug="ENABLED"],
      [true],
            [AC_DEFINE([YKCS11_DBG], [0], [Regular debug flag])
            AC_DEFINE([YKCS11_DINOUT], [0], [Function accessed/left debug flag])
            ykcs11_debug="DISABLED"])

AC_ARG_ENABLE([hardware-tests],
              [AS_HELP_STRING([--enable-hardware-tests],
                              [enables tests that require a YubiKey to be plugged in])],
                              [enable_hardware_tests="$enableval"],
                              [enable_hardware_tests="no"])

AS_IF([test "x$enable_hardware_tests" != xno],
            [AC_DEFINE([HW_TESTS], [1], [Flag for hardware tests])
             hw_tests="ENABLED"],
      [true],
            [hw_tests="DISABLED"])

AC_SUBST(YKPIV_VERSION_MAJOR, `echo $PACKAGE_VERSION | sed 's/\(.*\)\..*\..*/\1/g'`)
AC_SUBST(YKPIV_VERSION_MINOR, `echo $PACKAGE_VERSION | sed 's/.*\.\(.*\)\..*/\1/g'`)
AC_SUBST(YKPIV_VERSION_PATCH, `echo $PACKAGE_VERSION | sed 's/.*\..*\.\(.*\)/\1/g'`)
AC_SUBST(YKPIV_VERSION_NUMBER, `printf "0x%02x%02x%02x" $YKPIV_VERSION_MAJOR $YKPIV_VERSION_MINOR $YKPIV_VERSION_PATCH`)

AC_SUBST(YKCS11_VERSION_MAJOR, `echo $PACKAGE_VERSION | sed 's/\(.*\)\..*\..*/\1/g'`)
AC_SUBST(YKCS11_VERSION_MINOR, `echo $PACKAGE_VERSION | sed 's/.*\.\(.*\)\..*/\1/g'`)
AC_SUBST(YKCS11_VERSION_PATCH, `echo $PACKAGE_VERSION | sed 's/.*\..*\.\(.*\)/\1/g'`)
AC_SUBST(YKCS11_VERSION_NUMBER, `printf "0x%02x%02x%02x" $YKCS11_VERSION_MAJOR $YKCS11_VERSION_MINOR $YKCS11_VERSION_PATCH`)

AC_CONFIG_FILES([
  Makefile
  lib/Makefile
  lib/tests/Makefile
  tool/Makefile
  tool/tests/Makefile
  lib/ykpiv-version.h
  lib/ykpiv.pc
  ykcs11/Makefile
  ykcs11/ykcs11-version.h
  ykcs11/ykcs11.pc
  ykcs11/tests/Makefile
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
  OpenSSL version:  ${OPENSSL_VERSION}
  PCSC
          CFLAGS:   ${PCSC_CFLAGS}
            LIBS:   ${PCSC_LIBS}
  Winscard
            LIBS:   ${PCSC_WIN_LIBS}
  Mac PCSC
            LIBS:   ${PCSC_MACOSX_LIBS}

  YKCS11 debug:    ${ykcs11_debug}
  Hardware tests:  ${hw_tests}
])
