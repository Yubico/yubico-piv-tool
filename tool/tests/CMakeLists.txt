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

#set(LOG_COMPILER "${VALGRIND}")

include(check)
find_check()

find_program (BASH_PROGRAM bash)

configure_file (
        ${CMAKE_CURRENT_SOURCE_DIR}/cert.pem
        ${CMAKE_CURRENT_BINARY_DIR}/cert.pem
        COPYONLY)

configure_file (
        ${CMAKE_CURRENT_SOURCE_DIR}/private.pem
        ${CMAKE_CURRENT_BINARY_DIR}/private.pem
        COPYONLY)

configure_file (
        ${CMAKE_CURRENT_SOURCE_DIR}/public.pem
        ${CMAKE_CURRENT_BINARY_DIR}/public.pem
        COPYONLY)


set(SOURCE_PARSE_NAME parse_name.c ../util.c)
set(SOURCE_TEST_INOUT test_inout.c ../util.c)


add_executable(test_parse_name ${SOURCE_PARSE_NAME})
add_executable (test_inout ${SOURCE_TEST_INOUT})

target_link_libraries(test_parse_name crypto ${LIBCHECK_LDFLAGS} ykpiv)
target_link_libraries(test_inout crypto ${LIBCHECK_LDFLAGS} ykpiv)


add_test(
        NAME test_parse_name
        COMMAND test_parse_name
        WORKING_DIRECTORY ${CMAKE_BINARY_DIR}/tool/tests/
)

add_test(
        NAME test_inout
        COMMAND test_inout
        WORKING_DIRECTORY ${CMAKE_BINARY_DIR}/tool/tests/
)


add_test(
        NAME basic_tests
        COMMAND ${BASH_PROGRAM} ${CMAKE_CURRENT_SOURCE_DIR}/basic.sh
)
set_property(TEST basic_tests APPEND PROPERTY ENVIRONMENT "VERSION=${VERSION}")
set_property(TEST basic_tests APPEND PROPERTY ENVIRONMENT "EXEEXT=${CMAKE_EXECUTABLE_SUFFIX}")

