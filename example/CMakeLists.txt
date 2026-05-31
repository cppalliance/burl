#
# Copyright (c) 2025 Vinnie Falco (vinnie dot falco at gmail dot com)
#
# Distributed under the Boost Software License, Version 1.0. (See accompanying
# file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
#
# Official repository: https://github.com/cppalliance/burl
#

add_executable(burl_example_usage usage.cpp)
target_link_libraries(burl_example_usage PRIVATE Boost::burl Boost::hash2)

if (TARGET Boost::http_zlib)
    target_link_libraries(burl_example_usage PRIVATE Boost::http_zlib)
endif()

if (TARGET Boost::http_brotli)
    target_link_libraries(burl_example_usage PRIVATE Boost::http_brotli)
endif()

find_package(nlohmann_json QUIET)
if (nlohmann_json_FOUND)
    add_executable(burl_example_nlohmann_json nlohmann_json.cpp)
    target_link_libraries(burl_example_nlohmann_json
        PRIVATE Boost::burl nlohmann_json::nlohmann_json)
endif()
