//
// Copyright (c) 2026 Mohammad Nejati
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

#ifndef BOOST_BURL_SRC_DETAIL_DRAIN_HPP
#define BOOST_BURL_SRC_DETAIL_DRAIN_HPP

#include <boost/capy/buffers.hpp>
#include <boost/capy/error.hpp>
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
template<capy::ReadStream Stream>
capy::io_task<>
drain_body(
    http::response_parser& parser,
    Stream& conn,
    std::uint64_t limit)
{
    auto source = parser.source_for(conn);
    for(;;)
    {
        capy::const_buffer arr[2];
        auto [ec, bufs] = co_await source.pull(arr);
        if(ec == capy::cond::eof)
            co_return {};
        if(ec)
            co_return { ec };

        auto n = capy::buffer_size(bufs);
        if(n > limit)
            co_return {};
        limit -= n;
        source.consume(n);
    }
}

} // namespace detail
} // namespace burl
} // namespace boost

#endif
