//
// Copyright (c) 2026 Mohammad Nejati
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

#include "drain_body.hpp"

#include <boost/capy/buffers.hpp>
#include <boost/capy/error.hpp>

namespace boost
{
namespace burl
{
namespace detail
{

capy::io_task<>
drain_body(
    http::response_parser& parser,
    capy::any_stream conn,
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
