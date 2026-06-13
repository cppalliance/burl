//
// Copyright (c) 2026 Mohammad Nejati
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

#include "socks5_tunnel.hpp"

#include <boost/burl/error.hpp>

#include <boost/capy/buffers/make_buffer.hpp>
#include <boost/capy/read.hpp>
#include <boost/capy/write.hpp>
#include <boost/url/grammar/string_token.hpp>

#include <cstddef>
#include <cstdint>
#include <string>

namespace boost
{
namespace burl
{
namespace detail
{

capy::io_task<>
open_socks5_tunnel(
    capy::any_stream stream,
    std::string_view target_host,
    std::string_view target_port,
    urls::url_view proxy)
{
    // Greeting: offer username/password auth only when credentials are present.
    if(proxy.has_userinfo())
    {
        std::uint8_t greeting[4] = { 0x05, 0x02, 0x00, 0x02 };
        auto [ec, n] =
            co_await capy::write(stream, capy::make_buffer(greeting));
        if(ec)
            co_return ec;
    }
    else
    {
        std::uint8_t greeting[3] = { 0x05, 0x01, 0x00 };
        auto [ec, n] =
            co_await capy::write(stream, capy::make_buffer(greeting));
        if(ec)
            co_return ec;
    }

    std::uint8_t greeting_resp[2];
    if(auto [ec, n] =
           co_await capy::read(stream, capy::make_buffer(greeting_resp));
       ec)
        co_return ec;

    if(greeting_resp[0] != 0x05)
        co_return { error::proxy_unsupported_version };

    switch(greeting_resp[1])
    {
    case 0x00: // no authentication required
        break;
    case 0x02: // username/password (RFC 1929)
    {
        std::string auth_req;
        auth_req.push_back(0x01); // sub-negotiation version

        auto user = proxy.encoded_user();
        auth_req.push_back(static_cast<char>(user.decoded_size()));
        user.decode({}, urls::string_token::append_to(auth_req));

        auto pass = proxy.encoded_password();
        auth_req.push_back(static_cast<char>(pass.decoded_size()));
        pass.decode({}, urls::string_token::append_to(auth_req));

        if(auto [ec, n] =
               co_await capy::write(stream, capy::make_buffer(auth_req));
           ec)
            co_return ec;

        std::uint8_t auth_resp[2];
        if(auto [ec, n] =
               co_await capy::read(stream, capy::make_buffer(auth_resp));
           ec)
            co_return ec;

        if(auth_resp[1] != 0x00)
            co_return { error::proxy_auth_failed };
        break;
    }
    default: // no acceptable method (0xFF) or anything unexpected
        co_return { error::proxy_auth_failed };
    }

    // connection request
    std::string conn_req = { 0x05, 0x01, 0x00, 0x03 };

    conn_req.push_back(static_cast<char>(target_host.size()));
    conn_req.append(target_host);

    auto port =
        static_cast<std::uint16_t>(std::stoul(std::string(target_port)));
    conn_req.push_back(static_cast<char>((port >> 8) & 0xFF));
    conn_req.push_back(static_cast<char>(port & 0xFF));

    if(auto [ec, n] = co_await capy::write(stream, capy::make_buffer(conn_req));
       ec)
        co_return ec;

    // connection response
    std::uint8_t reply_head[5];
    if(auto [ec, n] =
           co_await capy::read(stream, capy::make_buffer(reply_head));
       ec)
        co_return ec;

    if(reply_head[1] != 0x00)
        co_return { error::proxy_connect_failed };

    std::size_t tail = 0;
    switch(reply_head[3])
    {
    case 0x01:
        tail = 4 + 2 - 1; // ipv4 + port
        break;
    case 0x03:
        tail = reply_head[4] + 2u; // domain name + port
        break;
    case 0x04:
        tail = 16 + 2 - 1; // ipv6 + port
        break;
    default:
        co_return { error::proxy_connect_failed };
    }

    std::string reply_tail;
    reply_tail.resize(tail);
    if(auto [ec, n] =
           co_await capy::read(stream, capy::make_buffer(reply_tail));
       ec)
        co_return ec;

    co_return {};
}

} // namespace detail
} // namespace burl
} // namespace boost
