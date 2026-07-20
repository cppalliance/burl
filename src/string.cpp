//
// Copyright (c) 2026 Mohammad Nejati
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

#include <boost/burl/string.hpp>
#include "detail/util.hpp"

#include <boost/capy/buffers/make_buffer.hpp>
#include <boost/capy/read.hpp>

#include <algorithm>
#include <cstdint>
#include <string_view>
#include <utility>

namespace boost
{
namespace burl
{
namespace
{

class string_body
{
    std::string body_;

public:
    explicit string_body(std::string body)
        : body_(std::move(body))
    {
    }

    std::optional<std::string>
    content_type() const
    {
        return "text/plain; charset=utf-8";
    }

    std::optional<std::uint64_t>
    content_length() const noexcept
    {
        return body_.size();
    }

    capy::io_task<>
    write(http::any_buffer_sink& sink) const
    {
        auto [ec, n] =
            co_await sink.write_eof(
                capy::make_buffer(std::string_view(body_)));
        co_return { ec };
    }
};

class string_view_body
{
    std::string_view body_;

public:
    explicit string_view_body(std::string_view body)
        : body_(body)
    {
    }

    std::optional<std::string>
    content_type() const
    {
        return "text/plain; charset=utf-8";
    }

    std::optional<std::uint64_t>
    content_length() const noexcept
    {
        return body_.size();
    }

    capy::io_task<>
    write(http::any_buffer_sink& sink) const
    {
        auto [ec, n] = co_await sink.write_eof(
            capy::make_buffer(body_));
        co_return { ec };
    }
};

} // namespace

any_request_body
tag_invoke(body_from_tag<std::string>, std::string body)
{
    return string_body{ std::move(body) };
}

any_request_body
tag_invoke(body_from_tag<std::string_view>, std::string_view body)
{
    return string_view_body{ body };
}

capy::io_task<std::string>
tag_invoke(body_to_tag<std::string>, response& resp)
{
    std::string ret;
    auto source = resp.as_read_source();

    if(auto cl = resp.content_length())
    {
        ret.resize(detail::clamp(*cl));
        auto [ec, n] = co_await source.read(
            capy::mutable_buffer(ret.data(), ret.size()));
        ret.resize(n);
        if(ec == capy::cond::eof)
            ec.clear();
        co_return { ec, ret };
    }

    std::size_t chunk = 4096;
    ret.resize(chunk);
    std::size_t total = 0;
    for(;;)
    {
        auto [ec, n] = co_await source.read_some(
            capy::mutable_buffer(ret.data() + total, ret.size() - total));
        total += n;
        if(ec)
        {
            ret.resize(total);
            if(ec == capy::cond::eof)
                ec.clear();
            co_return { ec, ret };
        }
        if(total == ret.size())
        {
            chunk = std::min<std::size_t>(chunk * 2, 65536);
            ret.resize(ret.size() + chunk);
        }
    }
}

} // namespace burl
} // namespace boost
