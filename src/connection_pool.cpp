//
// Copyright (c) 2026 Mohammad Nejati
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

#include <boost/burl/connection_pool.hpp>
#include <boost/burl/error.hpp>

#include "detail/base64.hpp"

#include <boost/capy/buffers/make_buffer.hpp>
#include <boost/capy/io/any_stream.hpp>
#include <boost/capy/read.hpp>
#include <boost/capy/timeout.hpp>
#include <boost/capy/write.hpp>
#include <boost/corosio/connect.hpp>
#include <boost/corosio/openssl_stream.hpp>
#include <boost/corosio/resolver.hpp>
#include <boost/corosio/shutdown_type.hpp>
#include <boost/corosio/socket_option.hpp>
#include <boost/corosio/tcp_socket.hpp>
#include <boost/http/field.hpp>
#include <boost/http/method.hpp>
#include <boost/http/request.hpp>
#include <boost/http/response_parser.hpp>
#include <boost/http/status.hpp>
#include <boost/url/grammar/string_token.hpp>
#include <boost/url/scheme.hpp>
#include <boost/url/url_view.hpp>

#include <cstdint>
#include <memory>
#include <string>
#include <utility>

namespace boost
{
namespace burl
{

class connection_pool::tcp_connection final : public connection
{
    corosio::tcp_socket socket_;

public:
    explicit tcp_connection(corosio::tcp_socket socket)
        : socket_(std::move(socket))
    {
    }

    virtual capy::io_task<std::size_t>
    read_some(std::span<capy::mutable_buffer const> buffers) override
    {
        co_return co_await socket_.read_some(buffers);
    }

    virtual capy::io_task<std::size_t>
    write_some(std::span<capy::const_buffer const> buffers) override
    {
        co_return co_await socket_.write_some(buffers);
    }

    capy::io_task<>
    shutdown() override
    {
        socket_.shutdown(corosio::shutdown_both);
        co_return {};
    }

    bool
    is_open() override
    {
        return socket_.is_open();
    }
};

class connection_pool::tls_connection final : public connection
{
    corosio::tcp_socket socket_;
    corosio::openssl_stream stream_;

public:
    tls_connection(corosio::tcp_socket socket, const corosio::tls_context& ctx)
        : socket_(std::move(socket))
        , stream_(&socket_, ctx)
    {
    }

    virtual capy::io_task<std::size_t>
    read_some(std::span<capy::mutable_buffer const> buffers) override
    {
        return stream_.read_some(buffers);
    }

    virtual capy::io_task<std::size_t>
    write_some(std::span<capy::const_buffer const> buffers) override
    {
        return stream_.write_some(buffers);
    }

    capy::io_task<>
    handshake()
    {
        return stream_.handshake(corosio::openssl_stream::client);
    }

    capy::io_task<>
    shutdown() override
    {
        return stream_.shutdown();
    }

    bool
    is_open() override
    {
        return socket_.is_open();
    }
};

namespace
{

std::string_view
effective_port(const urls::url_view& url)
{
    if(url.has_port())
        return url.port();

    if(url.scheme() == "https")
        return "443";

    if(url.scheme() == "http")
        return "80";

    if(url.scheme() == "socks5" || url.scheme() == "socks5h")
        return "1080";

    return {};
}

std::string
origin(urls::url_view url)
{
    std::string key{ url.scheme() };
    key += "://";
    key += url.encoded_host_and_port();
    return key;
}

capy::io_task<>
connect_tcp(
    corosio::tcp_socket& socket,
    capy::executor_ref exec,
    const connection_pool::config& cfg,
    std::string_view host,
    std::string_view port)
{
    corosio::resolver resolver(exec);
    auto [rec, eps] = co_await resolver.resolve(host, port);
    if(rec)
        co_return rec;

    if(auto [cec, ep] = co_await corosio::connect(socket, eps); cec)
        co_return cec;

    if(cfg.tcp_nodelay)
        socket.set_option(corosio::socket_option::no_delay(true));

    co_return {};
}

capy::io_task<>
connect_http_proxy(
    corosio::tcp_socket& socket,
    std::string_view target_host,
    std::string_view target_port,
    urls::url_view proxy)
{
    std::string host_port(target_host);
    host_port += ':';
    host_port += target_port;

    http::request req(http::method::connect, host_port);
    req.set(http::field::host, host_port);
    req.set(http::field::proxy_connection, "keep-alive");

    if(proxy.has_userinfo())
    {
        std::string value = "Basic ";
        detail::base64_encode(value, proxy.encoded_userinfo().decode());
        req.set(http::field::proxy_authorization, value);
    }

    if(auto [ec, n] =
           co_await capy::write(socket, capy::make_buffer(req.buffer()));
       ec)
        co_return ec;

    auto parser_cfg = http::make_parser_config(http::parser_config{ false });
    http::response_parser parser(parser_cfg);
    parser.reset();
    parser.start();
    if(auto [ec] = co_await parser.read_header(socket); ec)
        co_return { error::proxy_connect_failed };

    auto status = parser.get().status();
    if(status == http::status::proxy_authentication_required)
        co_return { error::proxy_auth_failed };
    if(to_status_class(status) != http::status_class::successful)
        co_return { error::proxy_connect_failed };

    co_return {};
}

capy::io_task<>
connect_socks5_proxy(
    corosio::tcp_socket& socket,
    std::string_view target_host,
    std::string_view target_port,
    urls::url_view proxy)
{
    // Greeting: offer username/password auth only when credentials are present.
    if(proxy.has_userinfo())
    {
        std::uint8_t greeting[4] = { 0x05, 0x02, 0x00, 0x02 };
        auto [ec, n] =
            co_await capy::write(socket, capy::make_buffer(greeting));
        if(ec)
            co_return ec;
    }
    else
    {
        std::uint8_t greeting[3] = { 0x05, 0x01, 0x00 };
        auto [ec, n] =
            co_await capy::write(socket, capy::make_buffer(greeting));
        if(ec)
            co_return ec;
    }

    std::uint8_t greeting_resp[2];
    if(auto [ec, n] =
           co_await capy::read(socket, capy::make_buffer(greeting_resp));
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
               co_await capy::write(socket, capy::make_buffer(auth_req));
           ec)
            co_return ec;

        std::uint8_t auth_resp[2];
        if(auto [ec, n] =
               co_await capy::read(socket, capy::make_buffer(auth_resp));
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

    if(auto [ec, n] = co_await capy::write(socket, capy::make_buffer(conn_req));
       ec)
        co_return ec;

    // connection response
    std::uint8_t reply_head[5];
    if(auto [ec, n] =
           co_await capy::read(socket, capy::make_buffer(reply_head));
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
           co_await capy::read(socket, capy::make_buffer(reply_tail));
       ec)
        co_return ec;

    co_return {};
}

} // namespace

capy::io_task<std::unique_ptr<connection_pool::connection>>
connection_pool::connect(urls::url_view url) const
{
    auto target_port = effective_port(url);
    if(target_port.empty())
        co_return { error::invalid_url_scheme, {} };

    corosio::tcp_socket socket(exec_);

    if(config_.proxy)
    {
        auto const& proxy = *config_.proxy;
        auto proxy_port   = effective_port(proxy);
        if(proxy_port.empty())
            co_return { error::unsupported_proxy_scheme, {} };

        auto [ec] = co_await connect_tcp(
            socket, exec_, config_, proxy.encoded_host(), proxy_port);
        if(ec)
            co_return { ec, {} };

        if(proxy.scheme() == "http")
        {
            auto [ec] = co_await connect_http_proxy(
                socket, url.encoded_host(), target_port, proxy);
            if(ec)
                co_return { ec, {} };
        }
        else if(proxy.scheme() == "socks5" || proxy.scheme() == "socks5h")
        {
            auto [ec] = co_await connect_socks5_proxy(
                socket, url.encoded_host(), target_port, proxy);
            if(ec)
                co_return { ec, {} };
        }
        else
        {
            co_return { error::unsupported_proxy_scheme, {} };
        }
    }
    else
    {
        auto [ec] = co_await connect_tcp(
            socket, exec_, config_, url.encoded_host(), target_port);
        if(ec)
            co_return { ec, {} };
    }

    if(url.scheme_id() == urls::scheme::https)
    {
        auto tls_ctx = tls_ctx_;
        tls_ctx.set_hostname(url.encoded_host());

        auto conn =
            std::make_unique<tls_connection>(std::move(socket), tls_ctx);
        auto [hec] = co_await conn->handshake();
        if(hec)
            co_return { hec, {} };

        co_return { {}, std::move(conn) };
    }

    co_return { {}, std::make_unique<tcp_connection>(std::move(socket)) };
}

capy::io_task<connection_pool::pooled_connection>
connection_pool::acquire(urls::url_view url)
{
    auto const key = origin(url);
    auto const now = config::clock::now();

    auto [it, last] = idle_.equal_range(key);
    while(it != last)
    {
        auto entry = std::move(it->second);
        it         = idle_.erase(it);

        if(now - entry.idle_since >= config_.idle_timeout)
            continue;

        if(!entry.conn->is_open())
            continue;

        co_return { {}, { std::move(entry.conn), config_.io_timeout } };
    }

    auto [ec, conn] =
        co_await capy::timeout(connect(url), config_.connect_timeout);
    if(ec)
        co_return { ec, {} };

    co_return { {}, { std::move(conn), config_.io_timeout } };
}

void
connection_pool::release(
    urls::url_view url,
    connection_pool::pooled_connection pc,
    http::response_parser const& parser)
{
    if(!parser.is_complete())
        return;

    if(!parser.get().keep_alive())
        return;

    if(!pc.conn_ || !pc.conn_->is_open())
        return;

    auto const key = origin(url);
    if(idle_.count(key) >= config_.max_idle_per_host)
        return;

    idle_.emplace(
        key, idle_connection{ std::move(pc.conn_), config::clock::now() });
}

} // namespace burl
} // namespace boost
