macro (find_gengetopt)
    if (NOT GENGETOPT_EXECUTABLE)
        find_program (GENGETOPT_EXECUTABLE gengetopt)
        if (NOT GENGETOPT_EXECUTABLE)
            message (FATAL_ERROR "gengetopt not found. Aborting...")
        endif ()
    endif ()
    add_definitions (-DPACKAGE="yubico-piv-tool")
    add_definitions (-DVERSION="${yubico_piv_tool_VERSION_MAJOR}.${yubico_piv_tool_VERSION_MINOR}.${yubico_piv_tool_VERSION_PATCH}")
endmacro ()

macro (add_gengetopt_files _basename)
    find_gengetopt ()
    set (_ggo_extra_input ${ARGV})

    set (_ggo_c ${CMAKE_CURRENT_SOURCE_DIR}/${_basename}.c)
    set (_ggo_h ${CMAKE_CURRENT_SOURCE_DIR}/${_basename}.h)
    set (_ggo_g ${CMAKE_CURRENT_SOURCE_DIR}/${_basename}.ggo)

    execute_process(
            COMMAND gengetopt --conf-parser -i ${_ggo_g} --output-dir ${CMAKE_CURRENT_SOURCE_DIR}
    )

    #add_custom_target(my_target
    #        ALL # Force target to be built with default build target.
    #        DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/utils.c)

    set (GGO_C ${_ggo_c})
    set (GGO_H ${_ggo_h})

endmacro (add_gengetopt_files)