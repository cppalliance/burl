//
// Copyright (c) 2026 Mohammad Nejati
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

#include <boost/burl/client.hpp>

#include "detail/base64.hpp"

#include <string>
#include <string_view>

namespace boost
{
namespace burl
{

request_builder&&
request_builder::query(std::string_view key, std::string_view value) &&
{
    request_.url.params().append({ key, value });
    return std::move(*this);
}

request_builder&&
request_builder::header(http::field field, std::string_view value) &&
{
    request_.headers.set(field, value);
    return std::move(*this);
}

request_builder&&
request_builder::header(std::string_view name, std::string_view value) &&
{
    request_.headers.set(name, value);
    return std::move(*this);
}

request_builder&&
request_builder::basic_auth(std::string_view user, std::string_view pass) &&
{
    std::string credentials{ user };
    credentials += ':';
    credentials += pass;

    std::string value = "Basic ";
    detail::base64_encode(value, credentials);

    request_.headers.set(http::field::authorization, value);
    return std::move(*this);
}

request_builder&&
request_builder::bearer_auth(std::string_view token) &&
{
    std::string value = "Bearer ";
    value += token;

    request_.headers.set(http::field::authorization, value);
    return std::move(*this);
}

capy::io_task<response>
request_builder::send() &&
{
    return client_.execute(std::move(request_));
}

} // namespace burl
} // namespace boost
