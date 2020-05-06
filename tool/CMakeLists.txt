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

message("tool/CMakeList.txt")

include(${CMAKE_SOURCE_DIR}/cmake/openssl.cmake)
find_libcrypto()

include(${CMAKE_SOURCE_DIR}/cmake/pcscd.cmake)
find_pcscd()

set (
        SOURCE
        util.c
        yubico-piv-tool.c
)

if(WIN32)
    add_definitions (-DPACKAGE="yubico-piv-tool")
    add_definitions (-DVERSION="${yubico_piv_tool_VERSION_MAJOR}.${yubico_piv_tool_VERSION_MINOR}.${yubico_piv_tool_VERSION_PATCH}")
    set(SOURCE ${SOURCE} cmdline.c)
    find_library(GETOPT getopt PATHS ${GENGETOPT_PATH})
    set(LINK_LIBS ${GETOPT})
else(WIN32)
    include(${CMAKE_SOURCE_DIR}/cmake/gengetopt.cmake)
    find_gengetopt()
    add_gengetopt_files(cmdline)
    set(SOURCE ${SOURCE} ${GGO_C})
endif(WIN32)

if(${OPENSSL_VERSION} VERSION_LESS 1.1.0)
    set(SOURCE ${SOURCE} openssl-compat.c)
endif()

include_directories (
        ${CMAKE_CURRENT_SOURCE_DIR}/../lib
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${GETOPT_INCLUDE_DIR}
)

if (CMAKE_C_COMPILER_ID MATCHES Clang)
    set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIE")
else ()
    set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIE -pie")
endif ()

list(APPEND LCOV_REMOVE_PATTERNS "'${PROJECT_SOURCE_DIR}/tool/cmdline.c'")

set(CMAKE_LIBRARY_PATH ${CMAKE_LIBRARY_PATH} ${OPENSSL_LIB_PATH})
#find_package(OpenSSL)
#set (LIBCRYPTO_LDFLAGS OpenSSL::Crypto)

find_library(GETOPT getopt PATHS ${GENGETOPT_PATH})
message("getopt: ${GETOPT}")

add_executable (yubico-piv-tool ${SOURCE})
target_link_libraries (yubico-piv-tool ykpiv ${LIBCRYPTO_LDFLAGS} ${LINK_LIBS})
if (BUILD_STATIC_LIB)
    add_executable (yubico-piv-tool_static ${SOURCE})
    set_target_properties (yubico-piv-tool_static PROPERTIES COMPILE_FLAGS "-DSTATIC")
    target_link_libraries(yubico-piv-tool_static ykpiv_static ${LIBCRYPTO_LDFLAGS} ${LINK_LIBS})
#    add_coverage (yubicp-piv-tool_static)
endif (BUILD_STATIC_LIB)

# Set install RPATH
set_target_properties(yubico-piv-tool PROPERTIES INSTALL_RPATH "${YKPIV_INSTALL_LIB_DIR}")

#add_coverage (yubico-piv-tool)

install(
        TARGETS yubico-piv-tool
        ARCHIVE DESTINATION "${YKPIV_INSTALL_LIB_DIR}"
        LIBRARY DESTINATION "${YKPIV_INSTALL_LIB_DIR}"
        RUNTIME DESTINATION "${YKPIV_INSTALL_BIN_DIR}")

if (GENERATE_MAN_PAGES)
    include (${CMAKE_SOURCE_DIR}/cmake/help2man.cmake)
    add_help2man_manpage (yubico-piv-tool.1 yubico-piv-tool)

    add_custom_target (yubico-piv-tool-man ALL DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/yubico-piv-tool.1)

    install(FILES "${CMAKE_CURRENT_BINARY_DIR}/yubico-piv-tool.1" DESTINATION "${YKPIV_INSTALL_MAN_DIR}/man1")
endif(GENERATE_MAN_PAGES)

add_subdirectory(tests)
