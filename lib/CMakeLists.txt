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

message("lib/CMakeList.txt")

include(${CMAKE_SOURCE_DIR}/cmake/openssl.cmake)
find_libcrypto()

include(${CMAKE_SOURCE_DIR}/cmake/pcscd.cmake)
find_pcscd()

set(YKPIV_VERSION_STRING "${yubico_piv_tool_VERSION_MAJOR}.${yubico_piv_tool_VERSION_MINOR}.${yubico_piv_tool_VERSION_PATCH}")

set(SOURCE ykpiv.c util.c version.c error.c internal.c)
set(STATIC_SOURCE ${SOURCE})

include_directories(${CMAKE_CURRENT_SOURCE_DIR})

add_library(ykpiv SHARED ${SOURCE})
set_target_properties(ykpiv PROPERTIES BUILD_RPATH "${CMAKE_BINARY_DIR}/lib")
set_target_properties(ykpiv PROPERTIES SOVERSION ${yubico_piv_tool_VERSION_MAJOR})
target_link_libraries (ykpiv ${LIBCRYPTO_LIBRARIES} ${PCSC_LIBRARIES} ${PCSC_WIN_LIBS} ${PCSC_MACOSX_LIBS} ${PCSC_CUSTOM_LIBS} ${ADDITIONAL_LIBRARY})
add_coverage (ykpiv)

if(BUILD_STATIC_LIB)
    add_library (ykpiv_static STATIC ${STATIC_SOURCE})
    set_target_properties (ykpiv_static PROPERTIES POSITION_INDEPENDENT_CODE on OUTPUT_NAME ykpiv)
    set_target_properties (ykpiv_static PROPERTIES COMPILE_FLAGS "-DSTATIC " )
    target_link_libraries (ykpiv_static ${LIBCRYPTO_LIBRARIES} ${PCSC_LIBRARIES} ${PCSC_WIN_LIBS} ${PCSC_MACOSX_LIBS} ${PCSC_CUSTOM_LIBS} ${ADDITIONAL_LIBRARY})
    add_coverage (ykpiv_static)
endif(BUILD_STATIC_LIB)

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/ykpiv.pc.in ${CMAKE_CURRENT_BINARY_DIR}/ykpiv.pc @ONLY)
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/ykpiv-config.h.in ${CMAKE_CURRENT_SOURCE_DIR}/ykpiv-config.h @ONLY)

install(
        TARGETS ykpiv
        ARCHIVE DESTINATION ${YKPIV_INSTALL_LIB_DIR}
        LIBRARY DESTINATION ${YKPIV_INSTALL_LIB_DIR}
        RUNTIME DESTINATION ${YKPIV_INSTALL_BIN_DIR})
if(BUILD_STATIC_LIB)
    install(
        TARGETS ykpiv_static
        ARCHIVE DESTINATION ${YKPIV_INSTALL_LIB_DIR}
        LIBRARY DESTINATION ${YKPIV_INSTALL_LIB_DIR}
        RUNTIME DESTINATION ${YKPIV_INSTALL_BIN_DIR})
endif(BUILD_STATIC_LIB)

install(FILES ykpiv.h DESTINATION ${YKPIV_INSTALL_INC_DIR}/ykpiv)
install(FILES ykpiv-config.h DESTINATION ${YKPIV_INSTALL_INC_DIR}/ykpiv)

add_subdirectory(tests)
