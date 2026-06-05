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

# add_subdirectory(unit)

# Placeholder so CTest finds at least one test until the unit directory is
# enabled (it currently causes a target name collision; to be addressed later).
add_test(NAME boost_burl_dummy COMMAND ${CMAKE_COMMAND} -E true)
add_dependencies(tests boost_burl)
