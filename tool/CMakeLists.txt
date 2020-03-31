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

link_directories(${PCSC_LIBRARY_DIRS})

include(gengetopt)
find_gengetopt()
add_gengetopt_files (cmdline)

set (
        SOURCE
        ${GGO_C}
        util.c
        yubico-piv-tool.c
        openssl-compat.c
)

include_directories (${CMAKE_CURRENT_SOURCE_DIR}/../lib ${CMAKE_CURRENT_SOURCE_DIR})

if (CMAKE_C_COMPILER_ID MATCHES Clang)
    set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIE")
else ()
    set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIE -pie")
endif ()

list(APPEND LCOV_REMOVE_PATTERNS "'${PROJECT_SOURCE_DIR}/tool/cmdline.c'")

add_executable (yubico-piv-tool ${SOURCE})
target_link_libraries (yubico-piv-tool ykpiv ${LIBCRYPTO_LDFLAGS})
if (BUILD_STATIC_LIB)
    add_executable (yubico-piv-tool_static ${SOURCE})
    set_target_properties (yubico-piv-tool_static PROPERTIES COMPILE_FLAGS "-DSTATIC")
    target_link_libraries(yubico-piv-tool_static ykpiv_static ${LIBCRYPTO_LDFLAGS})
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
    include (help2man)
    add_help2man_manpage (yubico-piv-tool.1 yubico-piv-tool)

    add_custom_target (yubico-piv-tool-man ALL DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/yubico-piv-tool.1)

    install(FILES "${CMAKE_CURRENT_BINARY_DIR}/yubico-piv-tool.1" DESTINATION "${YKPIV_INSTALL_MAN_DIR}/man1")
endif(GENERATE_MAN_PAGES)

add_subdirectory(tests)
