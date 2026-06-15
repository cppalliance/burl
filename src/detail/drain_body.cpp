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
#include <boost/capy/buffers/buffer_slice.hpp>
#include <boost/capy/error.hpp>
#include <boost/http/error.hpp>

namespace boost
{
namespace burl
{
namespace detail
{

capy::io_task<bool>
drain_body(
    http::response_parser& parser,
    capy::any_stream conn,
    std::uint64_t limit)
{
    for(;;)
    {
        if(parser.is_complete())
            co_return { {}, true };

        parser.consume_body(
            (std::numeric_limits<std::uint64_t>::max)());

        system::error_code ec;
        parser.parse(ec);

        if(ec == http::condition::need_more_input)
        {
            if(limit == 0)
                co_return { {}, false };

            auto mbs = parser.prepare();
            auto [rec, n] = co_await conn.read_some(
                capy::buffer_slice(mbs, 0, limit).data());
            if(rec == capy::cond::eof)
            {
                parser.commit_eof();
            }
            else if(!rec)
            {
                parser.commit(n);
                limit -= n;
            }
            else
            {
                co_return { rec, false };
            }

            continue;
        }

        if(ec)
            co_return { std::error_code(ec), false };
    }
}

} // namespace detail
} // namespace burl
} // namespace boost
