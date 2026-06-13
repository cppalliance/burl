//
// Copyright (c) 2026 Mohammad Nejati
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

#include "connection_pool.hpp"

#include <boost/burl/error.hpp>

#include "http_tunnel.hpp"
#include "socks5_tunnel.hpp"

#include <boost/capy/io/any_stream.hpp>
#include <boost/capy/timeout.hpp>
#include <boost/corosio/connect.hpp>
#include <boost/corosio/openssl_stream.hpp>
#include <boost/corosio/resolver.hpp>
#include <boost/corosio/shutdown_type.hpp>
#include <boost/corosio/socket_option.hpp>
#include <boost/corosio/tcp_socket.hpp>
#include <boost/url/scheme.hpp>
#include <boost/url/url_view.hpp>

#include <memory>
#include <string>
#include <utility>

namespace boost
{
namespace burl
{
namespace detail
{

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
    const client::config& cfg,
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

class tcp_connection final : public connection
{
    corosio::tcp_socket socket_;

public:
    explicit tcp_connection(corosio::tcp_socket socket)
        : socket_(std::move(socket))
    {
    }

    bool
    is_open() const noexcept override
    {
        return socket_.is_open();
    }

    capy::io_task<>
    shutdown() override
    {
        socket_.shutdown(corosio::shutdown_both);
        co_return {};
    }

private:
    capy::io_task<std::size_t>
    do_read_some(std::span<capy::mutable_buffer const> buffers) override
    {
        co_return co_await socket_.read_some(buffers);
    }

    capy::io_task<std::size_t>
    do_write_some(std::span<capy::const_buffer const> buffers) override
    {
        co_return co_await socket_.write_some(buffers);
    }
};

class tls_connection final : public connection
{
    corosio::tcp_socket socket_;
    corosio::openssl_stream stream_;

public:
    tls_connection(corosio::tcp_socket socket, const corosio::tls_context& ctx)
        : socket_(std::move(socket))
        , stream_(&socket_, ctx)
    {
    }

    capy::io_task<>
    handshake()
    {
        return stream_.handshake(corosio::openssl_stream::client);
    }

    bool
    is_open() const noexcept override
    {
        return socket_.is_open();
    }

    capy::io_task<>
    shutdown() override
    {
        return stream_.shutdown();
    }

private:
    capy::io_task<std::size_t>
    do_read_some(std::span<capy::mutable_buffer const> buffers) override
    {
        return stream_.read_some(buffers);
    }

    capy::io_task<std::size_t>
    do_write_some(std::span<capy::const_buffer const> buffers) override
    {
        return stream_.write_some(buffers);
    }
};

} // namespace

connection_pool::connection_pool(
    capy::executor_ref exec,
    corosio::tls_context tls_ctx,
    config cfg)
    : exec_(exec)
    , tls_ctx_(std::move(tls_ctx))
    , config_(std::move(cfg))
{
}

capy::io_task<pooled_connection>
connection_pool::acquire(urls::url_view url)
{
    auto key = origin(url);
    auto [it, last] = idle_.equal_range(key);
    while(it != last)
    {
        auto entry = std::move(it->second);
        it = idle_.erase(it);

        if(config::clock::now() - entry.idle_since >= config_.pool_idle_timeout)
            continue;

        if(!entry.conn->is_open())
            continue;

        co_return {
            {},
            { std::move(entry.conn),
              weak_from_this(),
              std::move(key),
              config_.io_timeout }
        };
    }

    auto [ec, conn] =
        co_await capy::timeout(connect(url), config_.connect_timeout);
    if(ec)
        co_return { ec, {} };

    co_return {
        {},
        { std::move(conn),
          weak_from_this(),
          std::move(key),
          config_.io_timeout }
    };
}

void
connection_pool::release(pooled_connection pc)
{
    if(!pc.conn_ || !pc.conn_->is_open())
        return;

    if(idle_.count(pc.key_) >= config_.pool_max_idle_per_host)
        return;

    idle_.emplace(
        std::move(pc.key_),
        idle_connection{ std::move(pc.conn_), config::clock::now() });
}

capy::io_task<std::unique_ptr<connection>>
connection_pool::connect(urls::url_view url) const
{
    auto target_port = effective_port(url);
    if(target_port.empty())
        co_return { error::unsupported_url_scheme, {} };

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
            auto [ec] = co_await open_http_tunnel(
                capy::any_stream(&socket),
                url.encoded_host(),
                target_port,
                proxy);
            if(ec)
                co_return { ec, {} };
        }
        else if(proxy.scheme() == "socks5" || proxy.scheme() == "socks5h")
        {
            auto [ec] = co_await open_socks5_tunnel(
                capy::any_stream(&socket),
                url.encoded_host(),
                target_port,
                proxy);
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

void
pooled_connection::return_to_pool()
{
    if(auto pool = pool_.lock())
        pool->release(std::move(*this));
}

} // namespace detail
} // namespace burl
} // namespace boost
