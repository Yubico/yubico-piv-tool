# Copyright (c) 2015-2016 Yubico AB
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

message("ykcs11/CMakeList.txt")

link_directories(${PCSC_LIBRARY_DIRS})
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fvisibility=hidden")

set(
        SOURCE
        ykcs11.c
        token.c
        mechanisms.c
        utils.c
        openssl_utils.c
        objects.c
        ../tool/util.c
)

if(${LIBCRYPTO_VERSION} VERSION_LESS 1.1.0)
    set(SOURCE ${SOURCE} ../tool/openssl-compat.c)
endif()

include_directories(
        ${CMAKE_CURRENT_SOURCE_DIR}/../lib
        ${CMAKE_CURRENT_SOURCE_DIR}
)

set(YKCS11_VERSION_STRING "${yubico_piv_tool_VERSION_MAJOR}.${yubico_piv_tool_VERSION_MINOR}.${yubico_piv_tool_VERSION_PATCH}")
set(YKCS11_VERSION_NUMBER ${yubico_piv_tool_VERSION_MAJOR}.${yubico_piv_tool_VERSION_MINOR}.${yubico_piv_tool_VERSION_PATCH})
set(YKCS11_VERSION_MAJOR ${yubico_piv_tool_VERSION_MAJOR})
set(YKCS11_VERSION_MINOR  ${yubico_piv_tool_VERSION_MINOR})
set(YKCS11_VERSION_PATCH ${yubico_piv_tool_VERSION_PATCH})


if(NOT ${ENABLE_YKCS11_DBG})
    set(YKCS11_DBG 0)
else(NOT ${ENABLE_YKCS11_DBG})
    set(YKCS11_DBG ${ENABLE_YKCS11_DBG})
endif(NOT ${ENABLE_YKCS11_DBG})

if(NOT ${ENABLE_HARDWARE_TESTS})
    set(HW_TESTS 0)
else(NOT ${ENABLE_HARDWARE_TESTS})
    set(HW_TESTS 1)
endif(NOT ${ENABLE_HARDWARE_TESTS})


add_library(ykcs11 SHARED ${SOURCE})
target_link_libraries(ykcs11 ykpiv)
# Remove "lib" from the built target
set_target_properties(ykcs11 PROPERTIES PREFIX "")

#add_definitions(-DCRYPTOKI_EXPORTS)

if(${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
    # glibc provides the iconv functionality out of the box, this
    # will probably be required on other platforms besides macOS.
    set_target_properties(ykcs11 PROPERTIES LINK_FLAGS "-liconv")
endif()

#add_coverage (ykcs11)

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/ykcs11.pc.in ${CMAKE_CURRENT_BINARY_DIR}/ykcs11.pc @ONLY)
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/ykcs11-config.h.in ${CMAKE_CURRENT_SOURCE_DIR}/ykcs11-config.h @ONLY)

set_target_properties(ykcs11 PROPERTIES INSTALL_RPATH "${YKPIV_INSTALL_LIB_DIR}")
install(
        TARGETS ykcs11
        ARCHIVE DESTINATION "${YKPIV_INSTALL_LIB_DIR}/ykcs11"
        LIBRARY DESTINATION "${YKPIV_INSTALL_LIB_DIR}/ykcs11"
        RUNTIME DESTINATION "${YKPIV_INSTALL_BIN_DIR}/ykcs11")
install(FILES pkcs11.h DESTINATION "${YKPIV_INSTALL_INC_DIR}/ykcs11")
install(FILES pkcs11y.h DESTINATION "${YKPIV_INSTALL_INC_DIR}/ykcs11")

add_subdirectory (tests)
