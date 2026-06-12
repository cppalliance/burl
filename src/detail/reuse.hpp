//
// Copyright (c) 2026 Mohammad Nejati
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

#ifndef BOOST_BURL_SRC_DETAIL_REUSE_HPP
#define BOOST_BURL_SRC_DETAIL_REUSE_HPP

#include <boost/http/response_parser.hpp>

namespace boost
{
namespace burl
{
namespace detail
{

bool
can_reuse_conn(http::response_parser& parser) noexcept;

} // namespace detail
} // namespace burl
} // namespace boost

#endif
