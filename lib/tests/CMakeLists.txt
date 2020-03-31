# Copyright (c) 2014-2016 Yubico AB
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are
# met:
#
#   * Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
#
#   * Redistributions in binary form must reproduce the above
#     copyright notice, this list of conditions and the following
#     disclaimer in the documentation and/or other materials provided
#     with the distribution.
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

if (CMAKE_C_COMPILER_ID MATCHES Clang)
    set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIE")
else ()
    set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIE -pie")
endif ()

include(check)
find_check()

set(SOURCE_BASIC basic.c)
set(SOURCE_API api.c)
set(SOURCE_PARSE_KEY parse_key.c)

add_executable (test_basic ${SOURCE_BASIC})
add_executable(test_api ${SOURCE_API})
add_executable(test_parse_key ${SOURCE_PARSE_KEY})

target_link_libraries(test_basic ykpiv ${LIBCRYPTO_LDFLAGS} ${LIBCHECK_LDFLAGS})
target_link_libraries(test_api ykpiv ${LIBCRYPTO_LDFLAGS} ${LIBCHECK_LDFLAGS})
target_link_libraries(test_parse_key ykpiv ${LIBCRYPTO_LDFLAGS} ${LIBCHECK_LDFLAGS})

add_test(
        NAME basic
        COMMAND test_basic
        WORKING_DIRECTORY ${CMAKE_BINARY_DIR}/lib/tests/
)

add_test(
        NAME api
        COMMAND test_api
        WORKING_DIRECTORY ${CMAKE_BINARY_DIR}/lib/tests/
)

add_test(
        NAME parse_key
        COMMAND test_parse_key
        WORKING_DIRECTORY ${CMAKE_BINARY_DIR}/lib/tests/
)