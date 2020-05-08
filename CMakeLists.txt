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
include(${CMAKE_SOURCE_DIR}/cmake/configOptions.cmake)

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
    set(_WINDOWS 1)
    set(_WIN32 ${WIN32})
#    if("${CMAKE_GENERATOR_PLATFORM}" STREQUAL "Win32")
#        message("win32")
#        set(_WIN32 1)
#    else("${CMAKE_GENERATOR_PLATFORM}" STREQUAL "Win32")
#        message("win64")
#    endif("${CMAKE_GENERATOR_PLATFORM}" STREQUAL "Win32")

    #[[set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fno-use-linker-plugin -static-libgcc")
    set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wl,--nxcompat")
    set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wl,--disable-auto-image-base -Wl,--dynamicbase")
    if ("${CMAKE_SIZEOF_VOID_P}" EQUAL "8")
        set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wl,--high-entropy-va")
        set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wl,--image-base -Wl,0x140000000")
        # mingw64 gcc with -pie puts the entry address in the wrong place, help it..
        set (CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,-emainCRTStartup")
    else()
        # mingw32 gcc with -pie puts the entry address in the wrong place, with a different symbol than mingw64, help it..
        set (CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,-e_mainCRTStartup")
    endif ()
    add_definitions (-D_POSIX_THREAD_SAFE_FUNCTIONS=1)
    add_definitions (-D__USE_MINGW_ANSI_STDIO=1)
    add_definitions (-DWIN32_LEAN_AND_MEAN=1)
    ]]
    set (GENERATE_MAN_PAGES OFF)
    #if (NOT WITHOUT_WIN32_BCRYPT)
    #    set (WIN32_BCRYPT 1)
    #endif()
    if (NOT LIBCRYPTO_LDFLAGS)
        set (LIBCRYPTO_LIBRARIES "bcrypt.lib")
    endif()
    if (NOT LIBCRYPTO_VERSION)
        # msys now installs openssl 1.1.1, hardcode to that until we come up with something cleverer
        set(LIBCRYPTO_VERSION "1.1.1")
    endif()
    if (NOT OPENSSL_VERSION)
        # msys now installs openssl 1.1.1, hardcode to that until we come up with something cleverer
        set(OPENSSL_VERSION "1.1.1")
    endif()
else(${CMAKE_SYSTEM_NAME} STREQUAL "Windows")

    find_package (PkgConfig REQUIRED)
    set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_CURRENT_SOURCE_DIR}/cmake/")

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

# fortify can only be used with -O2 and higher, so only enable for release builds
#[[if (NOT ${CMAKE_SYSTEM_NAME} MATCHES "Windows")
    set (CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -D_FORTIFY_SOURCE=2")
endif ()]]
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
endif(${CMAKE_SYSTEM_NAME} STREQUAL "Windows")
#if (CMAKE_C_COMPILER_ID STREQUAL AppleClang)
#    set (CMAKE_EXE_LINKER_FLAGS_RELEASE "${CMAKE_EXE_LINKER_FLAGS_RELEASE} -fPIE")
#else()
#    # -Wl,--strip-all is dependent on linker not compiler...
#    set (CMAKE_EXE_LINKER_FLAGS_RELEASE "${CMAKE_EXE_LINKER_FLAGS_RELEASE} -Wl,--strip-all -fPIE -pie")
#endif ()

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