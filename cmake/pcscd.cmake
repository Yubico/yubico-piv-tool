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

set(BACKEND_ARG_CHECK "check")
set(BACKEND_ARG_PCSC "pcsc")
set(BACKEND_ARG_MAC "macscard")
set(BACKEND_ARG_WIN "winscard")

macro (find_pcscd)
    if(VERBOSE_CMAKE)
        message("BACKEND: ${BACKEND}")
    endif(VERBOSE_CMAKE)

    if(${BACKEND} STREQUAL ${BACKEND_ARG_CHECK})
        if(${CMAKE_SYSTEM_NAME} MATCHES "(D|d)arwin")
            message("Detected Mac: selecting ${BACKEND_ARG_MAC} backend")
            set(BACKEND ${BACKEND_ARG_MAC})
        elseif(${CMAKE_SYSTEM_NAME} MATCHES "(W|w)in")
            message("Detected Windows: selecting ${BACKEND_ARG_WIN} backend")
            set(BACKEND ${BACKEND_ARG_WIN})
        else()
            message("Detected neither Mac nor Windows: selecting ${BACKEND_ARG_PCSC} backend")
            set(BACKEND ${BACKEND_ARG_PCSC})
        endif()
    endif(${BACKEND} STREQUAL ${BACKEND_ARG_CHECK})

    if(${BACKEND} STREQUAL ${BACKEND_ARG_MAC})
        message("Checking for PCSC with Mac linkage")
        find_file(PCSC_WINSCARD_H_FOUND PCSC/winscard.h)
        if(PCSC_WINSCARD_H_FOUND)
            set(HAVE_PCSC_WINSCARD_H ON)
            set(PCSC_MACOSX_LIBS "-Wl,-framework -Wl,PCSC")
            set(PCSC_LIBRARIES ${PCSC_MACOSX_LIBS})
            message("PCSC_WINSCARD_H_FOUND: ${PCSC_WINSCARD_H_FOUND}")
            message("HAVE_PCSC_WINSCARD_H: ${HAVE_PCSC_WINSCARD_H}")
            message("PCSC_MACOSX_LIBS: ${PCSC_MACOSX_LIBS}")
        else(PCSC_WINSCARD_H_FOUND)
            message(FATAL_ERROR "cannot find Mac PCSC library/headers")
        endif()
    endif(${BACKEND} STREQUAL ${BACKEND_ARG_MAC})

    if(${BACKEND} STREQUAL ${BACKEND_ARG_WIN})
        message("Checking for winscard with Windows linkage")
        set(PCSC_WIN_LIBS "winscard.lib")
        set(PCSC_LIBRARIES ${PCSC_WIN_LIBS})
        message("WINSCARD_H_FOUND: ${WINSCARD_H_FOUND}")
        message("PCSC_WIN_LIBS: ${PCSC_WIN_LIBS}")
    endif(${BACKEND} STREQUAL ${BACKEND_ARG_WIN})

    if(${BACKEND} STREQUAL ${BACKEND_ARG_PCSC})
        set(ENV{PKG_CONFIG_PATH} "${PCSCLITE_PKG_PATH}:$ENV{PKG_CONFIG_PATH}")
        pkg_check_modules(PCSC REQUIRED libpcsclite)
        if(PCSC_FOUND)
            set(PCSC_LIBRARIES ${PCSC_LDFLAGS})
            if(VERBOSE_CMAKE)
                message("PCSC_FOUND: ${PCSC_FOUND}")
                message("PCSC_LIBRARY_DIRS: ${PCSC_LIBRARY_DIRS}")
                message("PCSC_LDFLAGS: ${PCSC_LDFLAGS}")
                message("PCSC_LDFLAGS_OTHER: ${PCSC_LDFLAGS_OTHER}")
                message("PCSC_INCLUDE_DIRS: ${PCSC_INCLUDE_DIRS}")
                message("PCSC_CFLAGS_OTHER: ${PCSC_CFLAGS_OTHER}")
                message("PCSC_VERSION: ${PCSC_VERSION}")
                message("PCSC_INCLUDEDIR: ${PCSC_INCLUDEDIR}")
                message("PCSC_LIBDIR: ${PCSC_LIBDIR}")
            endif(VERBOSE_CMAKE)
        else(PCSC_FOUND)
            message (FATAL_ERROR "pcscd not found. Aborting...")
        endif(PCSC_FOUND)
    endif()

    if(${PCSC_LIB} NOT STREQUAL "")
        message("Checking for PCSC with custom lib")
        find_file(PCSC_WINSCARD_H_FOUND PCSC/winscard.h)
        if(${PCSC_DIR} NOT STREQUAL "")
            set(PCSC_CUSTOM_LIBS "-Wl,-L${PCSC_DIR} -Wl,-l${PCSC_LIB} -Wl,-rpath,${PCSC_DIR}")
        else(${PCSC_DIR} NOT STREQUAL "")
            set(PCSC_CUSTOM_LIBS "-Wl,-l${PCSC_LIB}")
        endif(${PCSC_DIR} NOT STREQUAL "")
        set(CMAKE_C_FLAGS ${PCSC_CFLAGS} ${CMAKE_C_FLAGS})
        set(PCSC_LIBRARIES ${PCSC_LIBRARIES} ${PCSC_CUSTOM_LIBS})
        unset(PCSC_MACOSX_LIBS)
        unset(PCSC_WIN_LIBS)
        unset(PCSC_LIBS)
    endif(${PCSC_LIB} NOT STREQUAL "")

    string(REPLACE ";" " " PCSC_CFLAGS "${PCSC_CFLAGS}")

    if(${BACKEND} STREQUAL ${BACKEND_ARG_PCSC} OR
            ${BACKEND} STREQUAL ${BACKEND_ARG_WIN} OR
            ${BACKEND} STREQUAL ${BACKEND_ARG_MAC}  OR
            ${PCSC_LIB} NOT STREQUAL "")
        set(BACKEND_PCSC ON)
    else()
        message (FATAL_ERROR "cannot find PCSC library")
    endif()

    message("PCSC_LIBRARIES: ${PCSC_LIBRARIES}")
    message("PCSC_CFLAGS: ${PCSC_CFLAGS}")
    message("BACKEND_PCSC: ${BACKEND_PCSC}")
    message("HAVE_PCSC_WINSCARD_H: ${HAVE_PCSC_WINSCARD_H}")

    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${PCSC_CFLAGS}")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${PCSC_CFLAGS}")
    link_directories(${PCSC_LIBRARY_DIRS})

endmacro()