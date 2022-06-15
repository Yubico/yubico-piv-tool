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

cmake_minimum_required (VERSION 3.5)
# policy CMP0025 is to get AppleClang identifier rather than Clang for both
# this matters since the apple compiler accepts different flags.
cmake_policy(SET CMP0025 NEW)
cmake_policy(SET CMP0042 NEW)
cmake_policy(SET CMP0054 NEW)

include(CheckFunctionExists)

set (CMAKE_C_STANDARD 11)

project (yubico-piv-tool)

set (yubico_piv_tool_VERSION_MAJOR 2)
set (yubico_piv_tool_VERSION_MINOR 3)
set (yubico_piv_tool_VERSION_PATCH 0)
set (VERSION "${yubico_piv_tool_VERSION_MAJOR}.${yubico_piv_tool_VERSION_MINOR}.${yubico_piv_tool_VERSION_PATCH}")
set (SO_VERSION 2)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_CURRENT_SOURCE_DIR}/cmake/")
include(${CMAKE_SOURCE_DIR}/cmake/options.cmake)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug)
endif()

include(CheckCCompilerFlag)

set(CMAKE_POSITION_INDEPENDENT_CODE ON)

add_definitions(-DOPENSSL_API_COMPAT=0x10000000L)

if(WIN32)
    add_definitions(-DWIN32_LEAN_AND_MEAN)
    set(_WIN32 ${WIN32})
endif()

if(MSVC)
    if((NOT GETOPT_LIB_DIR) OR (NOT GETOPT_INCLUDE_DIR))
        message(FATAL_ERROR "please provide definitions for "
                "GETOPT_LIB_DIR and GETOPT_INCLUDE_DIR when building "
                "under msvc")
    endif()
    if(SUPRESS_MSVC_WARNINGS)
        set(MSVC_DISABLED_WARNINGS_LIST
            "C4200" # nonstandard extension used: zero-sized array in struct/union;
            "C4204" # nonstandard extension used: non-constant aggregate initializer;
            "C4706" # assignment within conditional expression;
            "C4996" # The POSIX name for this item is deprecated. Instead, use the ISO C and C++ conformant name

            "C4473" # Not enough arguments passed for format string placeholders
            "C4244" # Conversion from 'int' to 'unsigned char', possible loss of data
            "C4152" # Nonstandard extension, function/data pointer conversion in expression (openssl/applink.c)
            "C4068" # Unknown pragma
            "C4701" # Potentially uninitialized local variable
            "C4703" # Potentially uninitialized local pointer
            "C4100" # 'param': unreferenced formal parameter (unsupported pkcs11 functions)
            "C4221" # Nonstandard extension used: 'pValue': cannot be initialized using address of automatic variable (ykcs11_tests_util)
            "C4057" # 'const char *' differs in indirection to slightly different base types from 'const CK_CHAR_PTR' (ykcs11 tests)
            "C4245" # Conversion from 'int' to 'CK_ULONG' (ykcs11 tests)
            "C4013" # '_getpid' undefined; assuming extern returning int (ykcs11/utils.c)
            "C4702" # Unreachable code (mechanisms.c:is_RSA_mechanism)
            "C4133" # Incompatible types: from 'ykpiv_rc' (enum) to 'int'
            "C4267" # Conversion from 'size_t' to 'CK_ULONG'
            "C4312" # Conversion from 'unsigned int' to 'void *' of greater size (ykcs11/utils.c:noop_create_mutex)
            )
        # The construction in the following 3 lines was taken from LibreSSL's
        # CMakeLists.txt.
        string(REPLACE "C" " -wd" MSVC_DISABLED_WARNINGS_STR ${MSVC_DISABLED_WARNINGS_LIST})
        string(REGEX REPLACE "[/-]W[1234][ ]?" "" CMAKE_C_FLAGS ${CMAKE_C_FLAGS})
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -MP -W4 ${MSVC_DISABLED_WARNINGS_STR}")
    endif(SUPRESS_MSVC_WARNINGS)

    set(BUILD_SHARED_LIBS ON)
    set(GENERATE_MAN_PAGES OFF)
    set(LIBCRYPTO_LIBRARIES ${LIBCRYPTO_LIBRARIES} bcrypt)
else()
    find_package (PkgConfig REQUIRED)

    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Werror")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-missing-braces")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wformat -Wformat-security")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wshadow -Wpointer-arith")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wmissing-prototypes")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wbad-function-cast")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fstack-protector-all")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-pointer-sign")
    set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -g2")
    set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -fno-omit-frame-pointer")
endif()

# Use -Wshorten-64-to-32 if available.
check_c_compiler_flag("-Wshorten-64-to-32" HAVE_SHORTEN_64_TO_32)
if(HAVE_SHORTEN_64_TO_32)
#    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wshorten-64-to-32")
endif()

# Avoid https://gcc.gnu.org/bugzilla/show_bug.cgi?id=66425
if(CMAKE_COMPILER_IS_GNUCC)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-unused-result")
endif()

include(${CMAKE_SOURCE_DIR}/cmake/openssl.cmake)
find_libcrypto()
include_directories(${LIBCRYPTO_INCLUDE_DIRS})

enable_testing()
find_package(codecov)

# explicit_bzero
check_function_exists(explicit_bzero HAVE_EXPLICIT_BZERO)
if(HAVE_EXPLICIT_BZERO)
	add_definitions(-DHAVE_EXPLICIT_BZERO)
endif()

add_subdirectory (lib)
if(NOT BUILD_ONLY_LIB)
    add_subdirectory(ykcs11)
    add_subdirectory(tool)
endif()

coverage_evaluate()

message("Build summary:")
message("")
message("        Project name:     ${CMAKE_PROJECT_NAME}")
message("        Version:          ${VERSION}")
message("        Host type:        ${CMAKE_SYSTEM_NAME}")
message("        Install prefix:   ${CMAKE_PREFIX_PATH}")
message("        Compiler:         ${CMAKE_C_COMPILER}")
message("        Compiler ID:      ${CMAKE_C_COMPILER_ID}")
message("        CFLAGS:           ${CMAKE_C_FLAGS}")
message("        CFLAGS_DEBUG:     ${CMAKE_C_FLAGS_DEBUG}")
message("        CPPFLAGS:         ${CMAKE_CXX_FLAGS}")
message("        Warnings:         ${WARN_FLAGS}")
message("        Build type:       ${CMAKE_BUILD_TYPE}")
message("        Backend:          ${BACKEND}")
message("        PCSC")
message("                CFLAGS:   ${PCSC_CFLAGS}")
message("                LIBS:     ${PCSC_LIBRARIES}")
message("        Winscard")
message("                LIBS:     ${PCSC_WIN_LIBS}")
message("        Mac PCSC")
message("                LIBS:     ${PCSC_MACOSX_LIBS}")
message("        Custom PCSC")
message("                LIBS:     ${PCSC_CUSTOM_LIBS}")
message("")
message("        Install prefix:    ${CMAKE_INSTALL_PREFIX}")
message("        Install targets")
message("                Libraries  ${YKPIV_INSTALL_LIB_DIR}")
message("                Includes   ${YKPIV_INSTALL_INC_DIR}")
message("                Binaries   ${YKPIV_INSTALL_BIN_DIR}")
message("                Manuals    ${YKPIV_INSTALL_MAN_DIR}")
message("                Pkg-config ${YKPIV_INSTALL_PKGCONFIG_DIR}")
message("")
message("        YKCS11 debug:     ${ENABLE_YKCS11_DBG}")
if(ENABLE_HARDWARE_TESTS)
    message("        Hardware tests:   Enabled. *** WARNING: RUNNING THE TESTS WILL ERASE ALL DATA ON CONNECTED YUBIKEYS *** ")
else(ENABLE_HARDWARE_TESTS)
    message("        Hardware tests:   Disabled")
endif(ENABLE_HARDWARE_TESTS)