//
// Copyright (c) 2026 Mohammad Nejati
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

#include <boost/burl/response.hpp>

#include "detail/can_reuse_conn.hpp"

#include <boost/capy/error.hpp>
#include <boost/corosio/timeout.hpp>

#include <chrono>
#include <utility>

namespace boost
{
namespace burl
{

response::response(
    urls::url url,
    detail::pooled_connection conn,
    response_parser parser,
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
    if(deadline_)
        co_return co_await corosio::timeout(
            message_reader{ &conn_, &parser_ }.read_body(),
            *deadline_ - clock::now());
    co_return co_await message_reader{ &conn_, &parser_ }.read_body();
}

capy::task<std::string_view>
response::as_view() &
{
    auto [ec, body] = co_await try_as_view();

    if(ec)
        throw std::system_error(ec);

    co_return std::move(body);
}

http::any_buffer_source
response::as_buffer_source() &
{
    return http::any_buffer_source(
        message_reader{ &conn_, &parser_ });
}

http::any_read_source
response::as_read_source() &
{
    return http::any_read_source(
        message_reader{ &conn_, &parser_ });
}

} // namespace burl
} // namespace boost
