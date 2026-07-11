//
// Copyright (c) 2026 Mohammad Nejati
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

#include "drain_body.hpp"

#include <boost/capy/error.hpp>

namespace boost
{
namespace burl
{
namespace detail
{

capy::io_task<bool>
drain_body(
    response_parser& parser,
    std::size_t attempts)
{
    while(!parser.got_body())
    {
        if(attempts-- == 0)
            co_return { {}, false };

        capy::const_buffer arr[8];
        auto [ec, bufs] = co_await parser.pull(arr);
        if(ec)
        {
            if(ec == capy::cond::eof)
                break;
            co_return { ec, false };
        }
        parser.consume(capy::buffer_size(bufs));
    }
    co_return { {}, true };
}

} // namespace detail
} // namespace burl
} // namespace boost
