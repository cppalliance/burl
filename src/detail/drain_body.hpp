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

#include <boost/burl/message_reader.hpp>
#include <boost/burl/response_parser.hpp>

#include <boost/capy/buffers.hpp>
#include <boost/capy/concept/read_stream.hpp>
#include <boost/capy/cond.hpp>
#include <boost/capy/io_task.hpp>

#include <cstddef>

namespace boost
{
namespace burl
{
namespace detail
{

template<capy::ReadStream S>
capy::io_task<bool>
drain_body(
    S& stream,
    response_parser& parser,
    std::size_t attempts)
{
    message_reader reader{ &stream, &parser };

    while(!parser.got_body())
    {
        if(attempts-- == 0)
            co_return { std::error_code(), false };

        capy::const_buffer arr[8];
        auto [ec, bufs] = co_await reader.pull(arr);
        if(ec)
        {
            if(ec == capy::cond::eof)
                break;
            co_return { ec, false };
        }
        parser.consume(capy::buffer_size(bufs));
    }
    co_return { std::error_code(), true };
}

} // namespace detail
} // namespace burl
} // namespace boost

#endif
