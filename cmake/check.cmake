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

macro (find_check)
    if(WIN32)

        if(NOT check_FOUND)
            find_package(check CONFIG PATHS ${CHECK_PATH})
            if(check_FOUND)
                set(LIBCHECK_LDFLAGS Check::check Check::checkShared)
                set(LIBCHECK_INCLUDE_DIRS ${CHECK_INCLUDE_DIR})
                set(LIBCHECK_VERSION ${CHECK_VERSION})
                set(LIBCHECK_LIBRARIES ${CHECK_LIBRARIES})

                if(VERBOSE_CMAKE)
                    message("check_FOUND: ${check_FOUND}")
                    message("LIBCHECK_LDFLAGS: ${LIBCHECK_LDFLAGS}")
                    message("LIBCHECK_INCLUDE_DIRS: ${LIBCHECK_INCLUDE_DIR}")
                    message("LIBCHECK_VERSION: ${LIBCHECK_VERSION}")
                    message("LIBCHECK_LIBRARIES: ${LIBCHECK_LIBRARIES}")
                endif(VERBOSE_CMAKE)
            else(check_FOUND)
                message(WARNING "'check' not found. Skipping testing...")
                set(SKIP_TESTS TRUE)
            endif(check_FOUND)
        endif(NOT check_FOUND)

    else(WIN32)

        if(NOT LIBCHECK_FOUND)
            pkg_check_modules(LIBCHECK REQUIRED check)
            if(LIBCHECK_FOUND)
                if(VERBOSE_CMAKE)
                    message("LIBCHECK_FOUND: ${LIBCHECK_FOUND}")
                    message("LIBCHECK_LIBRARIES: ${LIBCHECK_LIBRARIES}")
                    message("LIBCHECK_LIBRARY_DIRS: ${LIBCHECK_LIBRARY_DIRS}")
                    message("LIBCHECK_LDFLAGS: ${LIBCHECK_LDFLAGS}")
                    message("LIBCHECK_LDFLAGS_OTHER: ${LIBCHECK_LDFLAGS_OTHER}")
                    message("LIBCHECK_INCLUDE_DIRS: ${LIBCHECK_INCLUDE_DIRS}")
                    message("LIBCHECK_CFLAGS: ${LIBCHECK_CFLAGS}")
                    message("LIBCHECK_CFLAGS_OTHER: ${LIBCHECK_CFLAGS_OTHER}")
                    message("LIBCHECK_VERSION: ${LIBCHECK_VERSION}")
                    message("LIBCHECK_INCLUDEDIR: ${LIBCHECK_INCLUDEDIR}")
                    message("LIBCHECK_LIBDIR: ${LIBCHECK_LIBDIR}")
                endif(VERBOSE_CMAKE)
            else(LIBCHECK_FOUND)
                message (WARNING "'check' not found. Skipping testing...")
                set(SKIP_TESTS TRUE)
            endif(LIBCHECK_FOUND)
        endif(NOT LIBCHECK_FOUND)

    endif(WIN32)

    include_directories(${LIBCHECK_INCLUDE_DIRS})

endmacro()