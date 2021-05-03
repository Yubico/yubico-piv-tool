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

message("tool/CMakeList.txt")

set (SOURCE
        yubico-piv-tool.c
        ../common/openssl-compat.c
        ../common/util.c)

if(WIN32)
    add_definitions (-DPACKAGE="yubico-piv-tool")
    add_definitions (-DVERSION="${yubico_piv_tool_VERSION_MAJOR}.${yubico_piv_tool_VERSION_MINOR}.${yubico_piv_tool_VERSION_PATCH}")

    set(SOURCE ${SOURCE} cmdline.c)

    find_library(GETOPT getopt PATHS ${GETOPT_LIB_DIR})
    set(LINK_LIBS_WIN ${GETOPT})
    include_directories(${GETOPT_INCLUDE_DIR})
else(WIN32)
    include(${CMAKE_SOURCE_DIR}/cmake/gengetopt.cmake)
    find_gengetopt()
    add_gengetopt_files(cmdline)
    set(SOURCE ${SOURCE} ${GGO_C})
endif(WIN32)

include_directories (
        ${CMAKE_SOURCE_DIR}/lib
        ${CMAKE_CURRENT_SOURCE_DIR}
)

add_executable (yubico-piv-tool ${SOURCE})
target_link_libraries(yubico-piv-tool ${LIBCRYPTO_LDFLAGS} ${LINK_LIBS_WIN} ykpiv_shared)
add_coverage(yubico-piv-tool)

if (${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
    set_target_properties(yubico-piv-tool PROPERTIES INSTALL_RPATH "${YKPIV_INSTALL_LIB_DIR}")
endif()

install(
        TARGETS yubico-piv-tool
        ARCHIVE DESTINATION "${YKPIV_INSTALL_LIB_DIR}"
        LIBRARY DESTINATION "${YKPIV_INSTALL_LIB_DIR}"
        RUNTIME DESTINATION "${YKPIV_INSTALL_BIN_DIR}")

if (GENERATE_MAN_PAGES)
    include (${CMAKE_SOURCE_DIR}/cmake/help2man.cmake)
    add_help2man_manpage (yubico-piv-tool.1 yubico-piv-tool "Tool for managing Personal Identity Verification credentials on Yubikeys")

    add_custom_target (yubico-piv-tool-man ALL DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/yubico-piv-tool.1)
    install(FILES "${CMAKE_CURRENT_SOURCE_DIR}/yubico-piv-tool.1" DESTINATION "${YKPIV_INSTALL_MAN_DIR}/man1")
endif(GENERATE_MAN_PAGES)

# If somehow a manpage was generated before configure started, install that too
find_file(MAN_PAGE yubico-piv-tool.1 PATHS ${CMAKE_CURRENT_SOURCE_DIR})
if(MAN_PAGE)
    install(FILES "${CMAKE_CURRENT_SOURCE_DIR}/yubico-piv-tool.1" DESTINATION "${YKPIV_INSTALL_MAN_DIR}/man1")
endif(MAN_PAGE)

add_subdirectory(tests)
