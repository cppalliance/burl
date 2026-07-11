//
// Copyright (c) 2026 Mohammad Nejati
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

#ifndef BOOST_BURL_SRC_DETAIL_DRAIN_BODY_HPP
#define BOOST_BURL_SRC_DETAIL_DRAIN_BODY_HPP

#include <boost/burl/detail/response_parser.hpp>
#include <boost/capy/io_task.hpp>

#include <cstdint>

namespace boost
{
namespace burl
{
namespace detail
{

capy::io_task<bool>
drain_body(
    response_parser& parser,
    std::size_t attempts);

} // namespace detail
} // namespace burl
} // namespace boost

#endif
