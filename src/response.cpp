//
// Copyright (c) 2026 Mohammad Nejati
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

#include <boost/burl/connection_pool.hpp>
#include <boost/burl/response.hpp>

#include "detail/reuse.hpp"

#include <boost/capy/error.hpp>
#include <boost/capy/timeout.hpp>

#include <chrono>
#include <utility>

namespace boost
{
namespace burl
{

response::response(
    urls::url url,
    connection_pool::pooled_connection conn,
    http::response_parser parser,
    std::optional<clock::time_point> deadline)
    : url_(std::move(url))
    , conn_(std::move(conn))
    , parser_(std::move(parser))
    , deadline_(deadline)
{
}

response::response(response&& other) noexcept
    : url_(std::move(other.url_))
    , conn_(std::move(other.conn_))
    , parser_(std::move(other.parser_))
    , deadline_(other.deadline_)
{
}

response&
response::operator=(response&& other) noexcept
{
    if(this != &other)
    {
        if(conn_ && detail::can_reuse_conn(parser_))
            conn_.return_to_pool();
        url_      = std::move(other.url_);
        conn_     = std::move(other.conn_);
        parser_   = std::move(other.parser_);
        deadline_ = other.deadline_;
    }
    return *this;
}

response::~response()
{
    if(conn_ && detail::can_reuse_conn(parser_))
        conn_.return_to_pool();
}

capy::io_task<std::string_view>
response::try_as_view() &
{
    if(parser_.is_complete())
        co_return { {}, parser_.body() };

    if(deadline_)
    {
        auto dur = *deadline_ - clock::now();
        if(dur <= clock::duration::zero())
            co_return { capy::error::timeout, {} };

        auto [rec] = co_await capy::timeout(parser_.read(conn_), dur);
        if(rec)
            co_return { rec, {} };
    }
    else if(auto [rec] = co_await parser_.read(conn_); rec)
    {
        co_return { rec, {} };
    }
    co_return { {}, parser_.body() };
}

capy::task<std::string_view>
response::as_view() &
{
    auto [ec, body] = co_await try_as_view();

    if(ec)
        throw std::system_error(ec);

    co_return std::move(body);
}

capy::any_buffer_source
response::as_buffer_source() &
{
    return parser_.source_for(conn_);
}

capy::any_read_source
response::as_read_source() &
{
    return as_buffer_source(); // TODO
}

} // namespace burl
} // namespace boost
