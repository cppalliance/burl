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

#include "effective_port.hpp"
#include "http_tunnel.hpp"
#include "socks5_tunnel.hpp"

#include <boost/capy/io/any_stream.hpp>
#include <boost/corosio/connect.hpp>
#include <boost/corosio/openssl_stream.hpp>
#include <boost/corosio/resolver.hpp>
#include <boost/corosio/shutdown_type.hpp>
#include <boost/corosio/socket_option.hpp>
#include <boost/corosio/tcp_socket.hpp>
#include <boost/corosio/timeout.hpp>
#include <boost/corosio/tls_stream.hpp>
#include <boost/url/scheme.hpp>
#include <boost/url/url_view.hpp>

#include <memory>
#include <string>
#include <string_view>
#include <utility>

namespace boost
{
namespace burl
{
namespace detail
{

namespace
{

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
    urls::url_view url)
{
    corosio::resolver resolver(exec);
    auto [ec, eps] = co_await resolver.resolve(
        url.encoded_host_address(), effective_port(url));
    if(ec)
        co_return ec;

    std::tie(ec, std::ignore) = co_await corosio::connect(socket, eps);
    if(ec)
        co_return ec;

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

    // capy::io_task<>
    // shutdown() override
    // {
    //     socket_.shutdown(corosio::shutdown_both);
    //     co_return {};
    // }

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
        return stream_.handshake(corosio::tls_role::client);
    }

    void
    set_hostname(std::string_view hostname)
    {
        stream_.set_hostname(hostname);
    }

    bool
    is_open() const noexcept override
    {
        return socket_.is_open();
    }

    // capy::io_task<>
    // shutdown() override
    // {
    //     return stream_.shutdown();
    // }

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

class stream_connection final : public connection
{
    capy::any_stream stream_;
    bool open_ = true;

public:
    explicit stream_connection(capy::any_stream stream)
        : stream_(std::move(stream))
    {
    }

    bool
    is_open() const noexcept override
    {
        return open_;
    }

    // capy::io_task<>
    // shutdown() override
    // {
    //     open_ = false;
    //     co_return {};
    // }

private:
    capy::io_task<std::size_t>
    do_read_some(std::span<capy::mutable_buffer const> buffers) override
    {
        auto [ec, n] = co_await stream_.read_some(buffers);
        if(ec)
            open_ = false;
        co_return { ec, n };
    }

    capy::io_task<std::size_t>
    do_write_some(std::span<capy::const_buffer const> buffers) override
    {
        auto [ec, n] = co_await stream_.write_some(buffers);
        if(ec)
            open_ = false;
        co_return { ec, n };
    }
};

} // namespace

capy::io_task<std::size_t>
connection::
read_some_impl(capy::detail::mutable_buffer_array<8> rba)
{
    if(io_timeout_)
        co_return co_await corosio::timeout(
            do_read_some(rba), *io_timeout_);
    co_return co_await do_read_some(rba);
}

capy::io_task<std::size_t>
connection::
write_some_impl(capy::detail::const_buffer_array<8> wba)
{
    if(io_timeout_)
        co_return co_await corosio::timeout(
            do_write_some(wba), *io_timeout_);
    co_return co_await do_write_some(wba);
}

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

        entry.conn->set_io_timeout(config_.io_timeout);
        co_return {
            std::error_code(),
            pooled_connection{ std::move(entry.conn),
                weak_from_this(),
                std::move(key) }
        };
    }

    auto [ec, conn] =
        co_await corosio::timeout(
            connect(url), config_.connect_timeout);
    if(ec)
        co_return { ec, pooled_connection{} };

    conn->set_io_timeout(config_.io_timeout);
    co_return {
        std::error_code(),
        pooled_connection{ std::move(conn),
            weak_from_this(),
            std::move(key) }
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
    using urls::scheme;

    if(url.scheme_id() != scheme::http && url.scheme_id() != scheme::https)
        co_return { error::unsupported_url_scheme, nullptr };

    if(config_.connect_handler)
    {
        auto [ec, stream] = co_await config_.connect_handler(url);
        if(ec)
            co_return { ec, nullptr };
        co_return { std::error_code(),
            std::make_unique<stream_connection>(std::move(stream)) };
    }

    corosio::tcp_socket socket(exec_);

    if(config_.proxy)
    {
        auto const& proxy = *config_.proxy;
        if(effective_port(proxy).empty())
            co_return { error::unsupported_proxy_scheme, nullptr };

        if(auto [ec] = co_await connect_tcp(socket, exec_, config_, proxy); ec)
            co_return { ec, nullptr };

        if(proxy.scheme() == "http")
        {
            auto [ec] = co_await open_http_tunnel(
                capy::any_stream(&socket), url, proxy);
            if(ec)
                co_return { ec, nullptr };
        }
        else if(proxy.scheme() == "socks5")
        {
            urls::url resolved;

            corosio::resolver resolver(exec_);
            auto [ec, eps] = co_await resolver.resolve(
                url.encoded_host_address(), effective_port(url));
            if(ec)
                co_return { ec, nullptr };

            auto const& ep = eps.front().get_endpoint();
            resolved.set_port_number(ep.port());
            if(ep.is_v4())
                resolved.set_host_ipv4(
                    urls::ipv4_address(ep.v4_address().to_bytes()));
            else
                resolved.set_host_ipv6(
                    urls::ipv6_address(ep.v6_address().to_bytes()));

            std::tie(ec) = co_await open_socks5_tunnel(
                capy::any_stream(&socket), resolved, proxy);
            if(ec)
                co_return { ec, nullptr };
        }
        else if(proxy.scheme() == "socks5h")
        {
            auto [ec] = co_await open_socks5_tunnel(
                capy::any_stream(&socket), url, proxy);
            if(ec)
                co_return { ec, nullptr };
        }
        else
        {
            co_return { error::unsupported_proxy_scheme, nullptr };
        }
    }
    else
    {
        if(auto [ec] = co_await connect_tcp(socket, exec_, config_, url); ec)
            co_return { ec, nullptr };
    }

    if(url.scheme_id() == scheme::https)
    {
        auto conn =
            std::make_unique<tls_connection>(std::move(socket), tls_ctx_);
        conn->set_hostname(url.encoded_host());
        auto [ec] = co_await conn->handshake();
        if(ec)
            co_return { ec, nullptr };

        co_return { std::error_code(), std::move(conn) };
    }

    co_return { std::error_code(),
        std::make_unique<tcp_connection>(std::move(socket)) };
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
