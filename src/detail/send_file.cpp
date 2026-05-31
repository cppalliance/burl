//
// Copyright (c) 2026 Mohammad Nejati
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

#include "send_file.hpp"

#include "util.hpp"

#include <boost/burl/error.hpp>
#include <boost/capy/cond.hpp>
#include <boost/capy/ex/this_coro.hpp>
#include <boost/capy/io/any_buffer_sink.hpp>
#include <boost/corosio/file_base.hpp>
#include <boost/corosio/stream_file.hpp>

#include <system_error>

namespace boost
{
namespace burl
{
namespace detail
{

capy::io_task<>
send_file(
    capy::any_buffer_sink& sink,
    std::filesystem::path const& path,
    std::uint64_t size)
{
    corosio::stream_file f(co_await capy::this_coro::executor);
    // TODO: switch to a non-throwing open() overload once available.
    try
    {
        f.open(path, corosio::file_base::read_only);
    }
    catch(std::system_error const& e)
    {
        co_return { e.code() };
    }

    auto remaining = size;
    while(remaining > 0)
    {
        capy::mutable_buffer arr[2];
        auto dst = sink.prepare(arr);
        if(dst.empty())
        {
            if(auto [ec] = co_await sink.commit(0); ec)
                co_return { ec };
            continue;
        }

        auto [rec, n] = co_await f.read_some(dst);

        auto take = clamp(remaining, n);
        if(take)
        {
            if(auto [ec] = co_await sink.commit(take); ec)
                co_return { ec };
            remaining -= take;
        }

        if(remaining == 0)
            break;
        if(rec == capy::cond::eof)
            co_return { error::file_changed };
        if(rec)
            co_return { rec };
    }

    co_return {};
}

} // namespace detail
} // namespace burl
} // namespace boost
