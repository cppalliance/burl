#
# Copyright (c) 2025 Vinnie Falco (vinnie dot falco at gmail dot com)
#
# Distributed under the Boost Software License, Version 1.0. (See accompanying
# file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
#
# Official repository: https://github.com/cppalliance/burl
#

#-------------------------------------------------
#
# Project
#
#-------------------------------------------------

cmake_minimum_required(VERSION 3.8...3.31)

set(BOOST_BURL_VERSION 1)
if (BOOST_SUPERPROJECT_VERSION)
    set(BOOST_BURL_VERSION ${BOOST_SUPERPROJECT_VERSION})
endif ()
project(boost_burl VERSION "${BOOST_BURL_VERSION}" LANGUAGES CXX)
set(BOOST_BURL_IS_ROOT OFF)
if (CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
    set(BOOST_BURL_IS_ROOT ON)
endif ()
set(__ignore__ ${CMAKE_C_COMPILER})

#-------------------------------------------------
#
# Options
#
#-------------------------------------------------
if (BOOST_BURL_IS_ROOT)
    include(CTest)
endif ()
option(BOOST_BURL_BUILD_TESTS "Build boost::burl tests" ${BUILD_TESTING})
option(BOOST_BURL_BUILD_EXAMPLES "Build boost::burl examples" ${BOOST_BURL_IS_ROOT})
option(BOOST_BURL_MRDOCS_BUILD "Build the target for MrDocs: see mrdocs.yml" OFF)

# Check if environment variable BOOST_SRC_DIR is set
if (NOT DEFINED BOOST_SRC_DIR AND DEFINED ENV{BOOST_SRC_DIR})
    set(DEFAULT_BOOST_SRC_DIR "$ENV{BOOST_SRC_DIR}")
else ()
    set(DEFAULT_BOOST_SRC_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../..")
endif ()
set(BOOST_SRC_DIR ${DEFAULT_BOOST_SRC_DIR} CACHE STRING "Boost source dir to use when running CMake from this directory.")

#-------------------------------------------------
#
# Boost modules
#
#-------------------------------------------------
# The boost super-project requires one explicit dependency per-line.
set(BOOST_BURL_DEPENDENCIES
    Boost::capy
    Boost::corosio
    Boost::config
    Boost::http
    Boost::json
    Boost::system
    Boost::url)

foreach (BOOST_BURL_DEPENDENCY ${BOOST_BURL_DEPENDENCIES})
    if (BOOST_BURL_DEPENDENCY MATCHES "^[ ]*Boost::([A-Za-z0-9_]+)[ ]*$")
        list(APPEND BOOST_BURL_INCLUDE_LIBRARIES ${CMAKE_MATCH_1})
    endif ()
endforeach ()
# Conditional dependencies
if (NOT BOOST_BURL_MRDOCS_BUILD)
    if (BOOST_BURL_BUILD_TESTS)
        set(BOOST_BURL_UNIT_TEST_LIBRARIES)
    endif ()
    if (BOOST_BURL_BUILD_EXAMPLES)
        set(BOOST_BURL_EXAMPLE_LIBRARIES hash2)
    endif ()
endif ()
# Complete dependency list (only set when burl is the root project)
# When built as part of the superproject, these are set by the superproject
if (BOOST_BURL_IS_ROOT)
    set(BOOST_INCLUDE_LIBRARIES ${BOOST_BURL_INCLUDE_LIBRARIES} ${BOOST_BURL_UNIT_TEST_LIBRARIES} ${BOOST_BURL_EXAMPLE_LIBRARIES})
    set(BOOST_EXCLUDE_LIBRARIES burl)
endif()

#-------------------------------------------------
#
# Add Boost Subdirectory
#
#-------------------------------------------------
if (BOOST_BURL_IS_ROOT)
    set(CMAKE_FOLDER Dependencies)
    # Find absolute BOOST_SRC_DIR
    if (NOT IS_ABSOLUTE ${BOOST_SRC_DIR})
        set(BOOST_SRC_DIR "${CMAKE_CURRENT_SOURCE_DIR}/${BOOST_SRC_DIR}")
    endif ()

    # Validate BOOST_SRC_DIR
    set(BOOST_SRC_DIR_IS_VALID ON)
    foreach (F "CMakeLists.txt" "Jamroot" "boost-build.jam" "bootstrap.sh" "libs")
        if (NOT EXISTS "${BOOST_SRC_DIR}/${F}")
            message(STATUS "${BOOST_SRC_DIR}/${F} does not exist. Fallback to find_package.")
            set(BOOST_SRC_DIR_IS_VALID OFF)
            break()
        endif ()
    endforeach ()

    # Create Boost interface targets
    if (BOOST_SRC_DIR_IS_VALID)
        # From BOOST_SRC_DIR
        if (BUILD_SHARED_LIBS)
            set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
        endif ()
        set(BOOST_EXCLUDE_LIBRARIES ${PROJECT_NAME})
        set(PREV_BUILD_TESTING ${BUILD_TESTING})
        set(BUILD_TESTING OFF CACHE BOOL "Build the tests." FORCE)
        add_subdirectory(${BOOST_SRC_DIR} Dependencies/boost EXCLUDE_FROM_ALL)
        set(BUILD_TESTING ${PREV_BUILD_TESTING} CACHE BOOL "Build the tests." FORCE)
        set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${BOOST_SRC_DIR}/tools/cmake/include")
    else ()
        # From Boost Package
        find_package(Boost REQUIRED COMPONENTS system url json)
        foreach (BOOST_INCLUDE_LIBRARY ${BOOST_INCLUDE_LIBRARIES})
            if (NOT TARGET Boost::${BOOST_INCLUDE_LIBRARY})
                add_library(Boost::${BOOST_INCLUDE_LIBRARY} ALIAS Boost::headers)
            endif ()
        endforeach ()
    endif ()
    unset(CMAKE_FOLDER)
endif ()

#-------------------------------------------------
#
# OpenSSL (optional)
#
#-------------------------------------------------

# OpenSSL is optional for burl. When available, TLS support is enabled via
# corosio_openssl. The code uses tls_stream (base class) to avoid requiring
# openssl_stream symbols when OpenSSL is not available.

#-------------------------------------------------
#
# Library
#
#-------------------------------------------------
set_property(GLOBAL PROPERTY USE_FOLDERS ON)

file(GLOB_RECURSE BOOST_BURL_HEADERS CONFIGURE_DEPENDS
    "${CMAKE_CURRENT_SOURCE_DIR}/include/boost/burl/*.hpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/include/boost/burl.hpp")
file(GLOB_RECURSE BOOST_BURL_SOURCES CONFIGURE_DEPENDS
    "${CMAKE_CURRENT_SOURCE_DIR}/src/*.hpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp")

source_group("" FILES "include/boost/burl.hpp")
source_group(TREE "${CMAKE_CURRENT_SOURCE_DIR}/include/boost/burl" PREFIX "include" FILES ${BOOST_BURL_HEADERS})
source_group(TREE "${CMAKE_CURRENT_SOURCE_DIR}/src" PREFIX "src" FILES ${BOOST_BURL_SOURCES})

function(boost_burl_setup_properties target)
    target_compile_features(${target} PUBLIC cxx_std_20)
    target_include_directories(${target} PUBLIC "${PROJECT_SOURCE_DIR}/include")
    target_include_directories(${target} PRIVATE "${PROJECT_SOURCE_DIR}")
    target_link_libraries(${target} PUBLIC ${BOOST_BURL_DEPENDENCIES})
    # Link corosio_openssl for TLS support when available.
    # In superproject builds, corosio is processed after burl (alphabetically),
    # so the target may not exist at configure time. Use $<TARGET_NAME_IF_EXISTS:...>
    # which evaluates at generation time when all targets exist.
    target_link_libraries(${target} PUBLIC $<TARGET_NAME_IF_EXISTS:Boost::corosio_openssl>)
    target_compile_definitions(${target} PUBLIC BOOST_BURL_NO_LIB)
    target_compile_definitions(${target} PRIVATE BOOST_BURL_SOURCE)
    if (BUILD_SHARED_LIBS)
        target_compile_definitions(${target} PUBLIC BOOST_BURL_DYN_LINK)
    else ()
        target_compile_definitions(${target} PUBLIC BOOST_BURL_STATIC_LINK)
    endif ()
endfunction()

if (BOOST_BURL_MRDOCS_BUILD)
    file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/mrdocs.cpp" "#include <boost/burl.hpp>\n")
    add_library(boost_burl_mrdocs "${CMAKE_CURRENT_BINARY_DIR}/mrdocs.cpp")
    boost_burl_setup_properties(boost_burl_mrdocs)
    target_compile_definitions(boost_burl_mrdocs PUBLIC BOOST_BURL_MRDOCS)
    set_target_properties(boost_burl_mrdocs PROPERTIES EXPORT_COMPILE_COMMANDS ON)
    return()
endif ()

add_library(boost_burl ${BOOST_BURL_HEADERS} ${BOOST_BURL_SOURCES})
add_library(Boost::burl ALIAS boost_burl)
boost_burl_setup_properties(boost_burl)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
find_package(Libpsl)
if (Libpsl_FOUND)
    target_link_libraries(boost_burl PRIVATE Libpsl::Libpsl)
    target_compile_definitions(boost_burl PRIVATE BURL_HAS_LIBPSL)
endif ()

#-------------------------------------------------
#
# Tests
#
#-------------------------------------------------
if (BOOST_BURL_BUILD_TESTS)
    add_subdirectory(test)
endif ()

#-------------------------------------------------
#
# Examples
#
#-------------------------------------------------
if (BOOST_BURL_BUILD_EXAMPLES)
    add_subdirectory(example)
endif ()
