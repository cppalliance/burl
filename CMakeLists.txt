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

# OpenSSL dependencies (added after find_package)
set(BOOST_BURL_OPENSSL_DEPENDENCIES
    Boost::corosio_openssl)

foreach (BOOST_BURL_DEPENDENCY ${BOOST_BURL_DEPENDENCIES})
    if (BOOST_BURL_DEPENDENCY MATCHES "^[ ]*Boost::([A-Za-z0-9_]+)[ ]*$")
        list(APPEND BOOST_BURL_INCLUDE_LIBRARIES ${CMAKE_MATCH_1})
    endif ()
endforeach ()
# Conditional dependencies
if (BOOST_BURL_BUILD_TESTS)
    set(BOOST_BURL_UNIT_TEST_LIBRARIES)
endif ()
if (BOOST_BURL_BUILD_EXAMPLES)
    set(BOOST_BURL_EXAMPLE_LIBRARIES)
endif ()
# Complete dependency list
set(BOOST_INCLUDE_LIBRARIES ${BOOST_BURL_INCLUDE_LIBRARIES} ${BOOST_BURL_UNIT_TEST_LIBRARIES} ${BOOST_BURL_EXAMPLE_LIBRARIES})
set(BOOST_EXCLUDE_LIBRARIES burl)

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
# OpenSSL
#
#-------------------------------------------------
find_package(OpenSSL)

#-------------------------------------------------
#
# Library
#
#-------------------------------------------------
set_property(GLOBAL PROPERTY USE_FOLDERS ON)

file(GLOB_RECURSE BOOST_BURL_HEADERS CONFIGURE_DEPENDS include/boost/*.hpp include/boost/*.natvis)
file(GLOB_RECURSE BOOST_BURL_SOURCES CONFIGURE_DEPENDS src/*.cpp src/*.hpp)

source_group(TREE ${CMAKE_CURRENT_SOURCE_DIR}/include/boost/burl PREFIX "include" FILES ${BOOST_BURL_HEADERS})
source_group(TREE ${CMAKE_CURRENT_SOURCE_DIR}/src PREFIX "src" FILES ${BOOST_BURL_SOURCES})

function(boost_burl_setup_properties target)
    target_compile_features(${target} PUBLIC cxx_std_20)
    target_include_directories(${target} PUBLIC "${PROJECT_SOURCE_DIR}/include")
    target_include_directories(${target} PRIVATE "${PROJECT_SOURCE_DIR}")
    target_link_libraries(${target} PUBLIC ${BOOST_BURL_DEPENDENCIES} ${BOOST_BURL_OPENSSL_DEPENDENCIES})
    target_compile_definitions(${target} PUBLIC BOOST_BURL_NO_LIB)
    target_compile_definitions(${target} PRIVATE BOOST_BURL_SOURCE)
    if (BUILD_SHARED_LIBS)
        target_compile_definitions(${target} PUBLIC BOOST_BURL_DYN_LINK)
    else ()
        target_compile_definitions(${target} PUBLIC BOOST_BURL_STATIC_LINK)
    endif ()
endfunction()

add_library(boost_burl ${BOOST_BURL_HEADERS} ${BOOST_BURL_SOURCES})
add_library(Boost::burl ALIAS boost_burl)
boost_burl_setup_properties(boost_burl)

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
