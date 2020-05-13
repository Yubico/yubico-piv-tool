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

cmake_minimum_required (VERSION 3.10)
cmake_policy(SET CMP0025 NEW)
set (CMAKE_C_STANDARD 99)
#set (CMAKE_C_STANDARD 11)

project (yubico-piv-tool)

set (yubico_piv_tool_VERSION_MAJOR 2)
set (yubico_piv_tool_VERSION_MINOR 1)
set (yubico_piv_tool_VERSION_PATCH 0)
set (VERSION "${yubico_piv_tool_VERSION_MAJOR}.${yubico_piv_tool_VERSION_MINOR}.${yubico_piv_tool_VERSION_PATCH}")
include(${CMAKE_SOURCE_DIR}/cmake/options.cmake)
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_CURRENT_SOURCE_DIR}/cmake/")

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug)
endif()

if(${CMAKE_SYSTEM_NAME} STREQUAL "Darwin")
    if(NOT ${CMAKE_BUILD_TYPE} STREQUAL "Release")
        set(ENV{PKG_CONFIG_PATH} "/usr/local/opt/openssl@1.1/lib/pkgconfig:$ENV{PKG_CONFIG_PATH}")
    endif(NOT ${CMAKE_BUILD_TYPE} STREQUAL "Release")
    #set(ENV{PKG_CONFIG_PATH} "/usr/local/opt/pcsc-lite/lib/pkgconfig:$ENV{PKG_CONFIG_PATH}")
endif(${CMAKE_SYSTEM_NAME} STREQUAL "Darwin")

if(${CMAKE_SYSTEM_NAME} STREQUAL "Windows")
    set(_WIN32 ${WIN32})

    set (GENERATE_MAN_PAGES OFF)

    if (NOT LIBCRYPTO_LDFLAGS)
        set (LIBCRYPTO_LIBRARIES "bcrypt")
    endif()

else(${CMAKE_SYSTEM_NAME} STREQUAL "Windows")
    find_package (PkgConfig REQUIRED)

    set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -w") # -g -O2
    set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -Werror")
    if(ENABLE_GCC_WARN)
        set (WARN_FLAGS "")
        set (WARN_FLAGS "${WARN_FLAGS} -Wsystem-headers")
        set (WARN_FLAGS "${WARN_FLAGS} -Wpadded")
        set (WARN_FLAGS "${WARN_FLAGS} -Wc++-compat")
        set (WARN_FLAGS "${WARN_FLAGS} -Wtraditional")
        set (WARN_FLAGS "${WARN_FLAGS} -Wtraditional-conversion")
        set (WARN_FLAGS "${WARN_FLAGS} -Wconversion")
        set (WARN_FLAGS "${WARN_FLAGS} -Wsuggest-attribute=pure")
        set (WARN_FLAGS "${WARN_FLAGS} -Wsuggest-attribute=const")
        set (WARN_FLAGS "${WARN_FLAGS} -Waggregate-return")
        set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${WARN_FLAGS}")
    endif(ENABLE_GCC_WARN)
endif(${CMAKE_SYSTEM_NAME} STREQUAL "Windows")

if (NOT DISABLE_LTO)
    if (CMAKE_C_COMPILER_ID STREQUAL GNU)
        if (CMAKE_C_COMPILER_VERSION VERSION_GREATER 6.0)
            set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -flto")
        endif ()
    else ()
        if (CMAKE_C_COMPILER_VERSION VERSION_GREATER 7.0)
            set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -flto")
        endif ()
    endif ()
endif ()

enable_testing()
#find_package(codecov)

add_subdirectory (lib)
if(NOT BUILD_ONLY_LIB)
    add_subdirectory (ykcs11)
    add_subdirectory (tool)
endif()

add_custom_target (
        cppcheck
        COMMENT "Running cppcheck"
        COMMAND /usr/bin/cppcheck
        --enable=warning,style,unusedFunction,missingInclude
        --template="[{severity}][{id}] {message} {callstack} \(On {file}:{line}\)"
        -i ${CMAKE_SOURCE_DIR}/tool/cmdline.c
        --verbose
        --quiet
        ${CMAKE_SOURCE_DIR}/lib ${CMAKE_SOURCE_DIR}/tool ${CMAKE_SOURCE_DIR}/ykcs11
)

set(ARCHIVE_NAME ${CMAKE_PROJECT_NAME}-${yubico_piv_tool_VERSION_MAJOR}.${yubico_piv_tool_VERSION_MINOR}.${yubico_piv_tool_VERSION_PATCH})
add_custom_target (
        dist
        COMMAND git archive --prefix=${ARCHIVE_NAME}/ HEAD | gzip > ${CMAKE_BINARY_DIR}/${ARCHIVE_NAME}.tar.gz
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
)

#coverage_evaluate()

message("Summary of build options:")
message("")
message("        Version:          ${VERSION}")
message("        Host type:        ${CMAKE_SYSTEM_NAME}")
message("        Install prefix:   ${CMAKE_PREFIX_PATH}")
message("        Compiler ID:      ${CMAKE_C_COMPILER_ID}")
message("        CFLAGS:           ${CMAKE_C_FLAGS}")
message("        CPPFLAGS:         ${CMAKE_CXX_FLAGS}")
message("        Warnings:         ${WARN_FLAGS}")
message("        Build type:       ${CMAKE_BUILD_TYPE}")
message("        Backend:          ${BACKEND}")
message("        OpenSSL version:  ${OPENSSL_VERSION}")
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
message("        Install targets")
message("                Libraries  ${YKPIV_INSTALL_LIB_DIR}")
message("                Includes   ${YKPIV_INSTALL_INC_DIR}")
message("                Binaries   ${YKPIV_INSTALL_BIN_DIR}")
message("                Manuals    ${YKPIV_INSTALL_MAN_DIR}")
message("                Pkg-config ${YKPIV_INSTALL_PKGCONFIG_DIR}")
message("")
message("        YKCS11 debug:     ${ENABLE_YKCS11_DBG}")
message("        Hardware tests:   ${ENABLE_HARDWARE_TESTS}")