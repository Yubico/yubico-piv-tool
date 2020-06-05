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

macro (find_libcrypto)
    if(WIN32 OR OPENSSL_STATIC_LINK)
        if(NOT OpenSSL_FOUND)

            if(OPENSSL_STATIC_LINK)
                set(OPENSSL_USE_STATIC_LIBS TRUE) #Need to be set so that find_package would find the static library
            endif(OPENSSL_STATIC_LINK)
            find_package(OpenSSL REQUIRED)

            if(OpenSSL_FOUND)
                set(LIBCRYPTO_LDFLAGS OpenSSL::Crypto)
                if(NOT WIN32)
                    set(LIBCRYPTO_LDFLAGS ${LIBCRYPTO_LDFLAGS} -ldl)
                endif(NOT WIN32)

                set(LIBCRYPTO_INCLUDE_DIRS ${OPENSSL_INCLUDE_DIR})
                set(LIBCRYPTO_VERSION ${OPENSSL_VERSION})
                set(LIBCRYPTO_LIBRARIES ${LIBCRYPTO_LIBRARIES} ${OPENSSL_LIBRARIES})

                if(VERBOSE_CMAKE)
                    message("OPENSSL_FOUND: ${OPENSSL_FOUND}")
                    message("LIBCRYPTO_LDFLAGS: ${LIBCRYPTO_LDFLAGS}")
                    message("LIBCRYPTO_INCLUDE_DIRS: ${LIBCRYPTO_INCLUDE_DIRS}")
                    message("LIBCRYPTO_VERSION: ${LIBCRYPTO_VERSION}")
                    message("LIBCRYPTO_LIBRARIES: ${LIBCRYPTO_LIBRARIES}")
                endif(VERBOSE_CMAKE)
            else(OpenSSL_FOUND)
                message (FATAL_ERROR "static libcrypto not found. Aborting...")
            endif(OpenSSL_FOUND)

        endif(NOT OpenSSL_FOUND)
    else(WIN32 OR OPENSSL_STATIC_LINK)
        if(NOT LIBCRYPTO_FOUND)

            set(ENV{PKG_CONFIG_PATH} "${OPENSSL_PKG_PATH}:$ENV{PKG_CONFIG_PATH}")
            pkg_check_modules(LIBCRYPTO REQUIRED libcrypto)
            if(LIBCRYPTO_FOUND)
                if(VERBOSE_CMAKE)
                    message("LIBCRYPTO_FOUND: ${LIBCRYPTO_FOUND}")
                    message("LIBCRYPTO_LIBRARIES: ${LIBCRYPTO_LIBRARIES}")
                    message("LIBCRYPTO_LIBRARY_DIRS: ${LIBCRYPTO_LIBRARY_DIRS}")
                    message("LIBCRYPTO_LDFLAGS: ${LIBCRYPTO_LDFLAGS}")
                    message("LIBCRYPTO_LDFLAGS_OTHER: ${LIBCRYPTO_LDFLAGS_OTHER}")
                    message("LIBCRYPTO_INCLUDE_DIRS: ${LIBCRYPTO_INCLUDE_DIRS}")
                    message("LIBCRYPTO_CFLAGS: ${LIBCRYPTO_CFLAGS}")
                    message("LIBCRYPTO_CFLAGS_OTHER: ${LIBCRYPTO_CFLAGS_OTHER}")
                    message("LIBCRYPTO_VERSION: ${LIBCRYPTO_VERSION}")
                    message("LIBCRYPTO_INCLUDEDIR: ${LIBCRYPTO_INCLUDEDIR}")
                    message("LIBCRYPTO_LIBDIR: ${LIBCRYPTO_LIBDIR}")
                endif(VERBOSE_CMAKE)
            else(LIBCRYPTO_FOUND)
                message (FATAL_ERROR "libcrypto not found. Aborting...")
            endif(LIBCRYPTO_FOUND)
            set(OPENSSL_VERSION ${LIBCRYPTO_VERSION})

        endif(NOT LIBCRYPTO_FOUND)
    endif(WIN32 OR OPENSSL_STATIC_LINK)
    
    message("        OpenSSL version:   ${OPENSSL_VERSION}")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${LIBCRYPTO_CFLAGS}")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${LIBCRYPTO_CFLAGS}")
    link_directories(${LIBCRYPTO_LIBRARY_DIRS})
    include_directories(${LIBCRYPTO_INCLUDE_DIRS})

endmacro()