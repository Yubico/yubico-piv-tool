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

message("lib/CMakeList.txt")

include(${CMAKE_SOURCE_DIR}/cmake/pcscd.cmake)
find_pcscd()

set(YKPIV_VERSION_STRING "${yubico_piv_tool_VERSION_MAJOR}.${yubico_piv_tool_VERSION_MINOR}.${yubico_piv_tool_VERSION_PATCH}")

set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS TRUE)

set(SOURCE
        ykpiv.c
        util.c
        version.c
        error.c
        internal.c
        ../common/openssl-compat.c
        ../common/util.c)

include_directories(
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_SOURCE_DIR}/common
)

# static library
if(BUILD_STATIC_LIB)
    add_library(ykpiv STATIC ${SOURCE})
    target_link_libraries(ykpiv ${LIBCRYPTO_LIBRARIES} ${PCSC_LIBRARIES} ${PCSC_WIN_LIBS} ${PCSC_MACOSX_LIBS} ${PCSC_CUSTOM_LIBS})
    set_target_properties (ykpiv PROPERTIES COMPILE_FLAGS "-DSTATIC ")
    if(WIN32)
        set_target_properties(ykpiv PROPERTIES OUTPUT_NAME ykpiv_static)
    endif()
    add_coverage(ykpiv)
endif(BUILD_STATIC_LIB)

# dynamic library
add_library(ykpiv_shared SHARED ${SOURCE})
target_link_libraries(ykpiv_shared ${LIBCRYPTO_LIBRARIES} ${PCSC_LIBRARIES} ${PCSC_WIN_LIBS} ${PCSC_MACOSX_LIBS} ${PCSC_CUSTOM_LIBS})
set_target_properties(ykpiv_shared PROPERTIES SOVERSION ${SO_VERSION} VERSION ${VERSION})
set_target_properties(ykpiv_shared PROPERTIES INSTALL_RPATH "${YKPIV_INSTALL_LIB_DIR}")
if(WIN32)
    set_target_properties(ykpiv_shared PROPERTIES OUTPUT_NAME libykpiv)
else(WIN32)
    set_target_properties(ykpiv_shared PROPERTIES OUTPUT_NAME ykpiv)
endif(WIN32)
add_coverage(ykpiv_shared)

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/ykpiv.pc.in ${CMAKE_CURRENT_SOURCE_DIR}/ykpiv.pc @ONLY)
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/ykpiv-config.h.in ${CMAKE_CURRENT_SOURCE_DIR}/ykpiv-config.h @ONLY)

install(
        TARGETS ykpiv_shared
        ARCHIVE DESTINATION ${YKPIV_INSTALL_LIB_DIR}
        LIBRARY DESTINATION ${YKPIV_INSTALL_LIB_DIR}
        RUNTIME DESTINATION ${YKPIV_INSTALL_BIN_DIR})
if(BUILD_STATIC_LIB)
    install(
        TARGETS ykpiv
        ARCHIVE DESTINATION ${YKPIV_INSTALL_LIB_DIR}
        LIBRARY DESTINATION ${YKPIV_INSTALL_LIB_DIR}
        RUNTIME DESTINATION ${YKPIV_INSTALL_BIN_DIR})
endif(BUILD_STATIC_LIB)

install(FILES ykpiv.h DESTINATION ${YKPIV_INSTALL_INC_DIR}/ykpiv)
install(FILES ykpiv-config.h DESTINATION ${YKPIV_INSTALL_INC_DIR}/ykpiv)

install(FILES ykpiv.pc DESTINATION ${YKPIV_INSTALL_PKGCONFIG_DIR})

add_subdirectory(tests)
