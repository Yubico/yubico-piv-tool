find_program (HELP2MAN_LOCATION help2man)
IF (NOT HELP2MAN_LOCATION)
    message (FATAL_ERROR "Cannot find help2man. Please install it.")
ENDIF ()

MACRO (add_help2man_manpage file command)
    add_custom_command (OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/${file}
            COMMAND  ${HELP2MAN_LOCATION} ARGS -s1 -N -o ${CMAKE_CURRENT_BINARY_DIR}/${file} ./${command}
            DEPENDS ${command}
            COMMENT "Building manpage for ${command}")
ENDMACRO ()