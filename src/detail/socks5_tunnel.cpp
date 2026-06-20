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

#include "effective_port.hpp"

#include <boost/capy/buffers/make_buffer.hpp>
#include <boost/capy/read.hpp>
#include <boost/capy/write.hpp>
#include <boost/url/grammar/string_token.hpp>

#include <charconv>
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
    urls::url_view target,
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

    // connection request: VER, CMD=connect, RSV
    std::string conn_req = { 0x05, 0x01, 0x00 };

    switch(target.host_type())
    {
    case urls::host_type::ipv4:
    {
        conn_req.push_back(0x01); // ATYP: IPv4 address
        auto bytes = target.host_ipv4_address().to_bytes();
        conn_req.append(
            reinterpret_cast<const char*>(bytes.data()), bytes.size());
        break;
    }
    case urls::host_type::ipv6:
    {
        conn_req.push_back(0x04); // ATYP: IPv6 address
        auto bytes = target.host_ipv6_address().to_bytes();
        conn_req.append(
            reinterpret_cast<const char*>(bytes.data()), bytes.size());
        break;
    }
    case urls::host_type::name:
    {
        auto host = target.host_address(); // decoded, without brackets
        if(host.empty() || host.size() > 255)
            co_return { error::proxy_connect_failed };
        conn_req.push_back(0x03); // ATYP: domain name
        conn_req.push_back(static_cast<char>(host.size()));
        conn_req.append(host);
        break;
    }
    default: // host_type::none or host_type::ipvfuture
        co_return { error::proxy_connect_failed };
    }

    std::uint16_t port = 0;
    auto port_str      = effective_port(target);
    std::from_chars(
        port_str.data(), port_str.data() + port_str.size(), port);
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
