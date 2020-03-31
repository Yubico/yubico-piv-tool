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

include(pcscd)
find_pcscd()
link_directories(${PCSC_LIBRARY_DIRS})

set(YKPIV_VERSION_STRING "${yubico_piv_tool_VERSION_MAJOR}.${yubico_piv_tool_VERSION_MINOR}.${yubico_piv_tool_VERSION_PATCH}")

set(SOURCE ykpiv.c util.c internal.c version.c error.c)
set(STATIC_SOURCE ${SOURCE})

include_directories(${CMAKE_CURRENT_SOURCE_DIR})

add_library(ykpiv SHARED ${SOURCE})
set_target_properties(ykpiv PROPERTIES BUILD_RPATH "${CMAKE_BINARY_DIR}/lib")
#set_target_properties (ykpiv PROPERTIES VERSION "${yubico_piv_tool_VERSION_MAJOR}.${yubico_piv_tool_VERSION_MINOR}.${yubico_piv_tool_VERSION_PATCH}" SOVERSION ${yubico_piv_tool_VERSION_MAJOR})
set_target_properties (ykpiv PROPERTIES VERSION "${YKPIV_VERSION_STRING}" SOVERSION ${yubico_piv_tool_VERSION_MAJOR})

if(BUILD_STATIC_LIB)
    add_library (ykpiv_static STATIC ${STATIC_SOURCE})
    set_target_properties (ykpiv_static PROPERTIES POSITION_INDEPENDENT_CODE on OUTPUT_NAME ykpiv)
    set_target_properties (ykpiv_static PROPERTIES COMPILE_FLAGS "-DSTATIC " )
    #add_coverage (ykpiv_static)
endif(BUILD_STATIC_LIB)

#add_coverage (ykpiv)

target_link_libraries (ykpiv ${LIBCRYPTO_LIBRARIES} ${PCSC_LIBRARIES} ${PCSC_WIN_LIBS} ${PCSC_MACOSX_LIBS} ${PCSC_CUSTOM_LIBS})
if(BUILD_STATIC_LIB)
    target_link_libraries (ykpiv_static ${LIBCRYPTO_LIBRARIES} ${PCSC_LIBRARIES} ${PCSC_WIN_LIBS} ${PCSC_MACOSX_LIBS} ${PCSC_CUSTOM_LIBS})
endif(BUILD_STATIC_LIB)

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/ykpiv.pc.in ${CMAKE_CURRENT_BINARY_DIR}/ykpiv.pc @ONLY)
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/ykpiv-config.h.in ${CMAKE_CURRENT_SOURCE_DIR}/ykpiv-config.h @ONLY)

install(
        TARGETS ykpiv
        ARCHIVE DESTINATION ${YKPIV_INSTALL_LIB_DIR}
        LIBRARY DESTINATION ${YKPIV_INSTALL_LIB_DIR}
        RUNTIME DESTINATION ${YKPIV_INSTALL_BIN_DIR})
install(FILES ykpiv.h DESTINATION ${YKPIV_INSTALL_INC_DIR})
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/ykpiv.pc DESTINATION ${YKPIV_INSTALL_PKGCONFIG_DIR})

add_subdirectory (tests)