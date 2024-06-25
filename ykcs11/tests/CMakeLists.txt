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

message("ykcs11/tests/CMakeList.txt")

include(check)
find_check()

if(NOT DEFINED SKIP_TESTS)
    if(ENABLE_HARDWARE_TESTS)
        if(NOT WIN32)
            add_test(
                NAME reset_tests
                COMMAND ${BASH_PROGRAM} ${CMAKE_CURRENT_SOURCE_DIR}/reset.sh
            )
            set_property(TEST reset_tests APPEND PROPERTY ENVIRONMENT "EXEEXT=${CMAKE_EXECUTABLE_SUFFIX}")
            set_property(TEST reset_tests APPEND PROPERTY ENVIRONMENT "YKPIV_ENV_HWTESTS_CONFIRMED=${HW_TESTS}")
        else(NOT WIN32)
            message("Running on Windows. Skipping basic tests...")
        endif(NOT WIN32)
    endif(ENABLE_HARDWARE_TESTS)

    set(SOURCE_YKCS11_TESTS
            ykcs11_tests.c
            ykcs11_tests_util.c
    )
    add_executable(test_ykcs11 ${SOURCE_YKCS11_TESTS})
    target_link_libraries(test_ykcs11 ykcs11_shared ${LIBCRYPTO_LDFLAGS})
    add_test(
        NAME test_ykcs11
        COMMAND test_ykcs11
        WORKING_DIRECTORY ${CMAKE_BINARY_DIR}/ykcs11/tests/
    )
    set_property(TEST test_ykcs11 APPEND PROPERTY ENVIRONMENT "YKPIV_ENV_HWTESTS_CONFIRMED=${HW_TESTS}")

    set(SOURCE_YKCS11_INTERFACES_TESTS ykcs11_interfaces_tests.c)
    add_executable(test_ykcs11_interfaces ${SOURCE_YKCS11_INTERFACES_TESTS})
    target_link_libraries(test_ykcs11_interfaces ykcs11_shared ${LIBCRYPTO_LDFLAGS})
    add_test(
        NAME test_ykcs11_interfaces
        COMMAND test_ykcs11_interfaces
        WORKING_DIRECTORY ${CMAKE_BINARY_DIR}/ykcs11/tests/
    )
    set_property(TEST test_ykcs11_interfaces APPEND PROPERTY ENVIRONMENT "YKPIV_ENV_HWTESTS_CONFIRMED=${HW_TESTS}")
endif(NOT DEFINED SKIP_TESTS)