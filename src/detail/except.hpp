//
// Copyright (c) 2026 Mohammad Nejati
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

#ifndef BOOST_BURL_SRC_DETAIL_EXCEPT_HPP
#define BOOST_BURL_SRC_DETAIL_EXCEPT_HPP

#include <boost/assert/source_location.hpp>

namespace boost
{
namespace burl
{
namespace detail
{

[[noreturn]] void
throw_invalid_argument(
    char const* what,
    source_location const& loc = BOOST_CURRENT_LOCATION);

[[noreturn]] void
throw_length_error(
    char const* what,
    source_location const& loc = BOOST_CURRENT_LOCATION);

[[noreturn]] void
throw_out_of_range(
    char const* what,
    source_location const& loc = BOOST_CURRENT_LOCATION);

} // namespace detail
} // namespace burl
} // namespace boost

#endif
