//
// Copyright (c) 2026 Mohammad Nejati
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

#ifndef BOOST_BURL_CONNECTION_POOL_HPP
#define BOOST_BURL_CONNECTION_POOL_HPP

#include <boost/burl/detail/config.hpp>
#include <boost/capy/buffers.hpp>
#include <boost/capy/ex/executor_ref.hpp>
#include <boost/capy/io/any_stream.hpp>
#include <boost/capy/io_task.hpp>
#include <boost/capy/timeout.hpp>
#include <boost/corosio/endpoint.hpp>
#include <boost/corosio/tls_context.hpp>
#include <boost/http/response_parser.hpp>
#include <boost/url/url.hpp>
#include <boost/url/url_view.hpp>

#include <chrono>
#include <cstddef>
#include <memory>
#include <optional>
#include <string>
#include <unordered_map>
#include <utility>

namespace boost
{
namespace burl
{

class client;
class response;

/** A pool of reusable HTTP connections.

    This class establishes connections to origin
    servers, directly or through a proxy, and
    retains completed keep-alive connections for
    reuse. Connections are keyed by origin, that is,
    the scheme, host, and port of the URL. Idle
    connections are discarded after
    @ref config::idle_timeout, and at most
    @ref config::max_idle_per_host are retained per
    origin.

    Each @ref client owns a connection pool,
    configured through @ref client::config::pool.

    @see @ref client.
*/
class connection_pool
{
    friend class client;
    friend class response;

public:
    /** Configuration settings for a connection pool.
    */
    struct config
    {
        using clock = std::chrono::steady_clock;

        /** Timeout for establishing a connection.

            Covers name resolution, the TCP
            connection, proxy negotiation, and the
            TLS handshake.
        */
        clock::duration connect_timeout = std::chrono::seconds(60);

        /** Timeout for individual I/O operations.

            When set, applies to every read and
            write performed on a connection,
            bounding the time the peer may remain
            unresponsive regardless of the message
            size.
        */
        std::optional<clock::duration> io_timeout = std::nullopt;

        /** Time an idle connection remains usable.

            Pooled connections which have been idle
            for longer than this duration are
            discarded instead of being reused.
        */
        clock::duration idle_timeout = std::chrono::seconds(90);

        /** Maximum number of idle connections per origin.

            When the limit is reached, additional
            connections are closed instead of being
            returned to the pool.
        */
        std::size_t max_idle_per_host = 10;

        /** Set the `TCP_NODELAY` option on sockets.

            Disables Nagle's algorithm on newly
            established connections.
        */
        bool tcp_nodelay = true;

        /** The local endpoint to bind sockets to.
        */
        corosio::endpoint local_address;

        /** The proxy used for establishing connections.

            Supported proxy schemes are `http`,
            `socks5`, and `socks5h`. Credentials in
            the userinfo component of the URL are
            used for proxy authentication.

            @par Example
            @code
            cfg.pool.proxy = urls::url("socks5h://user:pass@localhost:8080");
            @endcode
        */
        std::optional<urls::url> proxy;
    };

    /** Constructor.

        Constructs a connection pool with a default
        configuration.

        @param exec The executor used to perform
        asynchronous operations.

        @param tls_ctx The TLS context used for
        `https` connections.
    */
    connection_pool(capy::executor_ref exec, corosio::tls_context tls_ctx)
        : connection_pool(exec, std::move(tls_ctx), config{})
    {
    }

    /** Constructor.

        Constructs a connection pool with the
        provided configuration.

        @param exec The executor used to perform
        asynchronous operations.

        @param tls_ctx The TLS context used for
        `https` connections.

        @param cfg The configuration settings.
    */
    connection_pool(
        capy::executor_ref exec,
        corosio::tls_context tls_ctx,
        config cfg)
        : exec_(exec)
        , tls_ctx_(std::move(tls_ctx))
        , config_(std::move(cfg))
    {
    }

private:
    class connection
    {
    public:
        virtual capy::io_task<std::size_t>
        read_some(std::span<capy::mutable_buffer const> buffers) = 0;

        virtual capy::io_task<std::size_t>
        write_some(std::span<capy::const_buffer const> buffers) = 0;

        virtual capy::io_task<>
        shutdown() = 0;

        virtual bool
        is_open() = 0;

        virtual ~connection() = default;
    };

    class tcp_connection;
    class tls_connection;

    class pooled_connection
    {
        friend class connection_pool;
        friend class response;

        std::unique_ptr<connection> conn_;
        std::optional<config::clock::duration> io_timeout_;
        capy::detail::buffer_array<8, false> rba_; // TODO
        capy::detail::buffer_array<8, true> wba_;  // TODO

        pooled_connection() = default;

        pooled_connection(
            std::unique_ptr<connection> conn,
            std::optional<config::clock::duration> io_timeout = std::nullopt)
            : conn_(std::move(conn))
            , io_timeout_(io_timeout)
        {
        }

    public:
        template<capy::MutableBufferSequence MB>
        capy::io_task<std::size_t>
        read_some(MB buffers)
        {
            rba_ = buffers;

            if(io_timeout_)
                return capy::timeout(conn_->read_some(rba_), *io_timeout_);
            return conn_->read_some(rba_);
        }

        template<capy::ConstBufferSequence CB>
        capy::io_task<std::size_t>
        write_some(CB buffers)
        {
            wba_ = buffers;

            if(io_timeout_)
                return capy::timeout(conn_->write_some(wba_), *io_timeout_);
            return conn_->write_some(wba_);
        }
    };

    struct idle_connection
    {
        std::unique_ptr<connection> conn;
        config::clock::time_point idle_since;
    };

    BOOST_BURL_DECL
    capy::io_task<pooled_connection>
    acquire(urls::url_view url);

    BOOST_BURL_DECL
    void
    release(
        urls::url_view url,
        pooled_connection pc,
        http::response_parser const& parser);

    BOOST_BURL_DECL
    capy::io_task<std::unique_ptr<connection>>
    connect(urls::url_view url) const;

    capy::executor_ref exec_;
    corosio::tls_context tls_ctx_;
    std::unordered_multimap<std::string, idle_connection> idle_;
    config config_;
};

} // namespace burl
} // namespace boost

#endif
