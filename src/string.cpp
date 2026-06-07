//
// Copyright (c) 2026 Mohammad Nejati
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

#include <boost/burl/string.hpp>

#include <boost/capy/buffers/make_buffer.hpp>
#include <boost/capy/buffers/string_dynamic_buffer.hpp>
#include <boost/capy/read.hpp>

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
    write(capy::any_buffer_sink& sink) const
    {
        if(auto [ec, n] =
               co_await sink.write(capy::make_buffer(std::string_view(body_)));
           ec)
            co_return { ec };
        co_return {};
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
    write(capy::any_buffer_sink& sink) const
    {
        if(auto [ec, n] = co_await sink.write(capy::make_buffer(body_)); ec)
            co_return { ec };
        co_return {};
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

    if(auto cl = resp.content_length())
        ret.reserve(*cl);

    auto source = resp.as_read_source();
    auto [ec, n] =
        co_await capy::read(source, capy::string_dynamic_buffer(&ret));
    co_return { ec, ret };
}

} // namespace burl
} // namespace boost
