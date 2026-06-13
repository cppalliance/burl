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

#include <boost/capy/io/any_stream.hpp>
#include <boost/capy/io_task.hpp>
#include <boost/http/response_parser.hpp>

#include <cstdint>

namespace boost
{
namespace burl
{
namespace detail
{

/** Read and discard the remaining body.
*/
capy::io_task<>
drain_body(
    http::response_parser& parser,
    capy::any_stream conn,
    std::uint64_t limit);

} // namespace detail
} // namespace burl
} // namespace boost

#endif
