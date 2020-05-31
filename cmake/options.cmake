# Copyright (c) 2020 Yubico AB
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

#These are the Variables that can be overridden with the command line arguments in the form:
# cmake -DVARIABLE1=VALUE1 -DVARIABLE2=VALUE2

option(BUILD_ONLY_LIB "Build only the library" OFF)
option(BUILD_STATIC_LIB "Buid static libraries" ON)
option(ENABLE_HARDWARE_TESTS "Enable/disable tests that require a YubiKey to be plugged in" OFF)
option(VERBOSE_CMAKE "Prints out trace messages when running the cmake script" OFF)
option(GENERATE_MAN_PAGES "Generate man pages for the command line tool" ON)
option(OPENSSL_STATIC_LINK "Statically link to OpenSSL" OFF)
option(ENABLE_COVERAGE "Enable/disable codecov evaluation" OFF)

set(YKCS11_DBG "0" CACHE STRING "Enable/disable YKCS11 debug messages. Possible values is 0 through 9")
set(BACKEND "check" CACHE STRING "use specific backend/linkage; 'pcsc', 'macscard' or'winscard'")
set(PCSC_LIB "" CACHE STRING "Name of custom PCSC lib")
set(PCSC_DIR "" CACHE STRING "Path to custom PCSC lib dir (use with PCSC_LIB")
set(GETOPT_LIB_DIR "" CACHE STRING "Path to look for getopt libraries")
set(GETOPT_INCLUDE_DIR "" CACHE STRING "Path to look for getopt.h file")
set(CHECK_PATH "" CACHE STRING "Path to look for 'check', the test framework for C. If 'check' is not found, tests are skipped")
set(OPENSSL_PKG_PATH "" CACHE STRING "Path to be prepended to 'PKG_CONFIG_PATH' evironment variable to look for libcrypto library")
set(PCSCLITE_PKG_PATH "" CACHE STRING "Path to be prepended to 'PKG_CONFIG_PATH' environment variable to look for pcsc-lite library")

# Set various install paths
if (NOT DEFINED YKPIV_INSTALL_LIB_DIR)
    set(YKPIV_INSTALL_LIB_DIR "${CMAKE_INSTALL_PREFIX}/lib${LIB_SUFFIX}" CACHE PATH "Installation directory for libraries")
endif ()

if (NOT DEFINED YKPIV_INSTALL_INC_DIR)
    set(YKPIV_INSTALL_INC_DIR "${CMAKE_INSTALL_PREFIX}/include" CACHE PATH "Installation directory for headers")
endif ()

if (NOT DEFINED YKPIV_INSTALL_BIN_DIR)
    set(YKPIV_INSTALL_BIN_DIR "${CMAKE_INSTALL_PREFIX}/bin" CACHE PATH "Installation directory for executables")
endif ()

if (NOT DEFINED YKPIV_INSTALL_MAN_DIR)
    set(YKPIV_INSTALL_MAN_DIR "${CMAKE_INSTALL_PREFIX}/share/man" CACHE PATH "Installation directory for manual pages")
endif ()

if (NOT DEFINED YKPIV_INSTALL_PKGCONFIG_DIR)
    set(YKPIV_INSTALL_PKGCONFIG_DIR "${CMAKE_INSTALL_PREFIX}/share/pkgconfig" CACHE PATH "Installation directory for pkgconfig (.pc) files")
endif ()
