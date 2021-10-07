cmake_minimum_required(VERSION 2.8)

project(tarantool-plugin C CXX)

find_program(GIT git)

#
# Set default build type to Debug. This is to ease a developer's
# life. Release binaries are built by BuildBot automatically anyway.
#
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug CACHE STRING
        "Choose the type of build, options are: None Debug Release RelWithDebInfo MinSizeRel."
        FORCE)
endif()

#
# Check submodules
#
function(update_submodules)
    message(STATUS "Updating submodules")
    execute_process(COMMAND ${GIT} submodule update --init --recursive
                    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})
endfunction()

if(NOT EXISTS ${CMAKE_SOURCE_DIR}/tarantool/CMakeLists.txt)
    if (EXISTS "${CMAKE_SOURCE_DIR}/.git" AND GIT)
        update_submodules()
    else()
        message(FATAL_ERROR "Failed to find submodules")
    endif()
endif()

add_subdirectory(tarantool)

# A helper function to compile *.lua source into *.lua.c sources
function(lua_source varname filename)
    if (IS_ABSOLUTE "${filename}")
        string (REPLACE "${PROJECT_SOURCE_DIR}" "${PROJECT_BINARY_DIR}"
            genname "${filename}")
        set (srcfile "${filename}")
        set (tmpfile "${genname}.new.c")
        set (dstfile "${genname}.c")
    else(IS_ABSOLUTE "${filename}")
        set (srcfile "${CMAKE_CURRENT_SOURCE_DIR}/${filename}")
        set (tmpfile "${CMAKE_CURRENT_BINARY_DIR}/${filename}.new.c")
        set (dstfile "${CMAKE_CURRENT_BINARY_DIR}/${filename}.c")
    endif(IS_ABSOLUTE "${filename}")
    get_filename_component(module ${filename} NAME_WE)
    get_filename_component(_name ${dstfile} NAME)
    string(REGEX REPLACE "${_name}$" "" dstdir ${dstfile})
    if (IS_DIRECTORY ${dstdir})
    else()
        file(MAKE_DIRECTORY ${dstdir})
    endif()

    ADD_CUSTOM_COMMAND(OUTPUT ${dstfile}
        COMMAND ${ECHO} 'const char ${module}_lua[] =' > ${tmpfile}
        COMMAND ${PROJECT_BINARY_DIR}/tarantool/extra/txt2c ${srcfile} >> ${tmpfile}
        COMMAND ${ECHO} '\;' >> ${tmpfile}
        COMMAND ${CMAKE_COMMAND} -E copy_if_different ${tmpfile} ${dstfile}
        COMMAND ${CMAKE_COMMAND} -E remove ${tmpfile}
        DEPENDS ${srcfile} txt2c libluajit)

    set(var ${${varname}})
    set(${varname} ${var} ${dstfile} PARENT_SCOPE)
endfunction()

set(lua_sources)
lua_source(lua_sources lua/normalize_uri_ee.lua)

add_custom_target(generate_plugin_lua_sources
    WORKING_DIRECTORY ${PROJECT_BINARY_DIR}/lua
    DEPENDS ${lua_sources})
set_property(DIRECTORY PROPERTY ADDITIONAL_MAKE_CLEAN_FILES ${lua_sources})

add_library(tarantool-plugin SHARED
    src/plugin.c
    ${lua_sources}
)
add_dependencies(tarantool-plugin tarantool)

include_directories(${PROJECT_SOURCE_DIR}/tarantool/src)
include_directories(${PROJECT_SOURCE_DIR}/tarantool/src/box)
include_directories(${PROJECT_SOURCE_DIR}/tarantool/src/lib)
include_directories(${PROJECT_SOURCE_DIR}/tarantool/src/lib/small/include)
include_directories(${PROJECT_SOURCE_DIR}/tarantool/src/lib/small/third_party)
include_directories(${PROJECT_SOURCE_DIR}/tarantool/src/lib/core)
include_directories(${PROJECT_SOURCE_DIR}/tarantool/third_party)
include_directories(${PROJECT_SOURCE_DIR}/tarantool/third_party/luajit/src)
