#
# Copyright (c) 2025 Vinnie Falco (vinnie dot falco at gmail dot com)
#
# Distributed under the Boost Software License, Version 1.0. (See accompanying
# file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
#
# Official repository: https://github.com/cppalliance/burl
#

if(NOT TARGET tests)
    add_custom_target(tests)
    set_property(TARGET tests PROPERTY FOLDER Dependencies)
endif()

# Create a test executable for each .cpp file
file(GLOB TEST_SOURCES CONFIGURE_DEPENDS *.cpp)

foreach(TEST_SOURCE ${TEST_SOURCES})
    get_filename_component(TEST_NAME ${TEST_SOURCE} NAME_WE)
    set(TEST_TARGET boost_burl_test_${TEST_NAME})
    
    add_executable(${TEST_TARGET} ${TEST_SOURCE})
    target_link_libraries(${TEST_TARGET} PRIVATE Boost::burl)
    target_include_directories(${TEST_TARGET} PRIVATE . ../)
    
    add_test(NAME burl_${TEST_NAME} COMMAND ${TEST_TARGET})
    add_dependencies(tests ${TEST_TARGET})
endforeach()
