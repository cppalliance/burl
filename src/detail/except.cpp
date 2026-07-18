//
// Copyright (c) 2026 Mohammad Nejati
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

#include "except.hpp"

#include <boost/throw_exception.hpp>

#include <stdexcept>

namespace boost
{
namespace burl
{
namespace detail
{

void
throw_invalid_argument(
    char const* what,
    source_location const& loc)
{
    throw_exception(
        std::invalid_argument(what), loc);
}

void
throw_length_error(
    char const* what,
    source_location const& loc)
{
    throw_exception(
        std::length_error(what), loc);
}

void
throw_out_of_range(
    char const* what,
    source_location const& loc)
{
    throw_exception(
        std::out_of_range(what), loc);
}

} // namespace detail
} // namespace burl
} // namespace boost
