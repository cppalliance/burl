#
# Copyright (c) 2026 Mohammad Nejati
#
# Distributed under the Boost Software License, Version 1.0. (See accompanying
# file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
#
# Official repository: https://github.com/cppalliance/burl
#

# Provides imported targets:
#   Zstd::Zstd

find_path(Zstd_INCLUDE_DIR NAMES "zstd.h")
find_library(Zstd_LIBRARY NAMES zstd libzstd zstd_static)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(Zstd
    REQUIRED_VARS
    Zstd_INCLUDE_DIR
    Zstd_LIBRARY
)

if(Zstd_FOUND)
    add_library(Zstd::Zstd UNKNOWN IMPORTED)
    set_target_properties(Zstd::Zstd PROPERTIES
        IMPORTED_LOCATION "${Zstd_LIBRARY}"
        INTERFACE_INCLUDE_DIRECTORIES "${Zstd_INCLUDE_DIR}"
    )
endif()

mark_as_advanced(
    Zstd_INCLUDE_DIR
    Zstd_LIBRARY)
