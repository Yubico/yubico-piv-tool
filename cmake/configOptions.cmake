#These are the Variables that can be overridden with the command line arguments in the form:
# cmake -DVARIABLE1=VALUE1 -DVARIABLE2=VALUE2

option(BUILD_ONLY_LIB "Build only the library" OFF)
option(BUILD_STATIC_LIB "Buid static libraries" ON)
option(ENABLE_YKCS11_DBG "Enable/disable YKCS11 debug messages" OFF)
option(ENABLE_HARDWARE_TESTS "Enable/disable tests that require a YubiKey to be plugged in" OFF)
option(VERBOSE_CMAKE "Prints out trace messages when running the cmake script" OFF)
option(ENABLE_GCC_WARN "Turn on lots of GCC warnings (for developers)" OFF)
option(GENERATE_MAN_PAGES "Generate man pages for the command line tool" ON)
option(DISABLE_LTO "Disable/enable turning on Link Time Optimization" ON)

set(BACKEND "check" CACHE STRING "use specific backend/linkage; 'pcsc', 'macscard' or'winscard'")
set(PCSC_LIB "" CACHE STRING "Name of custom PCSC lib")
set(PCSC_DIR "" CACHE STRING "Path to custom PCSC lib dir (use with PCSC_LIB")

# Set various install paths
if (NOT DEFINED YKPIV_INSTALL_LIB_DIR)
    set(YKPIV_INSTALL_LIB_DIR "${CMAKE_INSTALL_PREFIX}/lib${LIB_SUFFIX}" CACHE PATH "Installation directory for libraries")
endif ()

if (NOT DEFINED YKPIV_INSTALL_INC_DIR)
    set(YKPIV_INSTALL_INC_DIR "${CMAKE_INSTALL_PREFIX}/include" CACHE PATH "Installation directory for headers")
endif ()

if (NOT DEFINED YKPIV_INSTALL_BIN_DIR)
    set(YKPIV_INSTALL_BIN_DIR "${CMAKE_INSTALL_PREFIX}/bin" CACHE PATH "Installation directory for executables")
endif ()

if (NOT DEFINED YKPIV_INSTALL_MAN_DIR)
    set(YKPIV_INSTALL_MAN_DIR "${CMAKE_INSTALL_PREFIX}/share/man" CACHE PATH "Installation directory for manual pages")
endif ()

if (NOT DEFINED YKPIV_INSTALL_PKGCONFIG_DIR)
    set(YKPIV_INSTALL_PKGCONFIG_DIR "${CMAKE_INSTALL_PREFIX}/share/pkgconfig" CACHE PATH "Installation directory for pkgconfig (.pc) files")
endif ()
