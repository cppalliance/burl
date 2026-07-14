//
// Copyright (c) 2026 Mohammad Nejati
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

#ifndef BOOST_BURL_CLIENT_HPP
#define BOOST_BURL_CLIENT_HPP

#include <boost/burl/cookie_jar.hpp>
#include <boost/burl/detail/config.hpp>
#include <boost/burl/detail/connection_pool.hpp>
#include <boost/burl/request.hpp>
#include <boost/burl/response.hpp>

#include <boost/capy/ex/executor_ref.hpp>
#include <boost/capy/io/any_stream.hpp>
#include <boost/capy/io_task.hpp>
#include <boost/corosio/endpoint.hpp>
#include <boost/corosio/tls_context.hpp>
#include <boost/http/field.hpp>
#include <boost/http/fields.hpp>
#include <boost/url/url.hpp>
#include <boost/url/url_view.hpp>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <limits>
#include <memory>
#include <optional>
#include <string_view>

namespace boost
{
namespace burl
{

class request_builder;

/** An HTTP client.

    This is the main interface for performing HTTP
    requests. A client owns the configuration, a
    connection pool, a set of default headers, and a
    cookie jar, which are shared by all requests
    performed through it. Connections to the same
    origin are reused across requests when possible.

    @par Example
    @code
    burl::client c(co_await capy::this_coro::executor, tls_ctx);

    auto r = co_await c.get("https://example.com")
        .as<std::string>();
    @endcode

    @see
        @ref request_builder,
        @ref response.
*/
class client
{
public:
    /** Configuration settings for a client.
     */
    struct config
    {
        using clock = std::chrono::steady_clock;

        /** Enable automatic cookie handling.

           When enabled, cookies received in
           `Set-Cookie` headers are stored in the
           cookie jar, and matching cookies are
           sent in the `Cookie` header of
           subsequent requests.

           @see @ref client::cookie_jar.
       */
        bool cookies = false;

        /** The HTTP version used for requests.
         */
        http::version version = http::version::http_1_1;

        /** Follow redirect responses automatically.

            When enabled, responses with status
            codes 301, 302, 303, 307, and 308 are
            followed transparently, up to
            @ref maxredirs times.
        */
        bool followlocation = true;

        /** Maximum number of redirects to follow.

            Exceeding the limit fails the request
            with @ref error::too_many_redirects.
        */
        std::uint32_t maxredirs = 10;

        /** Keep the request method on 301 responses.
         */
        bool post301 = false;

        /** Keep the request method on 302 responses.
         */
        bool post302 = false;

        /** Keep the request method on 303 responses.
         */
        bool post303 = false;

        /** Send credentials on cross-origin redirects.

            By default, the `Authorization` and
            `Proxy-Authorization` headers, along
            with any `Cookie` header set explicitly
            on the request, are dropped when a
            redirect leads to a different origin
            than the original request. Enable to
            keep sending them.
        */
        bool unrestricted_auth = false;

        /** Set the `Referer` header when following redirects.

            The header is set to the URL being left,
            with any userinfo component removed.
        */
        bool autoreferer = true;

        /** Advertise and decode the Brotli content coding.

            When enabled, `br` is included in the
            `Accept-Encoding` header and response
            bodies are decoded transparently.
            Effective only when the library was built
            with Brotli support
            (`BOOST_BURL_HAS_BROTLI`). Not applied
            when the request carries an explicit
            `Accept-Encoding` header.
        */
        bool brotli = true;

        /** Advertise and decode the deflate content coding.

            When enabled, `deflate` is included in
            the `Accept-Encoding` header and
            response bodies are decoded
            transparently. Effective only when the
            library was built with zlib support
            (`BOOST_BURL_HAS_ZLIB`). Not applied when
            the request carries an explicit
            `Accept-Encoding` header.
        */
        bool deflate = true;

        /** Advertise and decode the gzip content coding.

            When enabled, `gzip` is included in the
            `Accept-Encoding` header and response
            bodies are decoded transparently.
            Effective only when the library was built
            with zlib support
            (`BOOST_BURL_HAS_ZLIB`). Not applied when
            the request carries an explicit
            `Accept-Encoding` header.
        */
        bool gzip = true;

        /** Advertise and decode the zstd content coding.

            When enabled, `zstd` is included in the
            `Accept-Encoding` header and response
            bodies are decoded transparently.
            Effective only when the library was built
            with zstd support
            (`BOOST_BURL_HAS_ZSTD`). Not applied when
            the request carries an explicit
            `Accept-Encoding` header.
        */
        bool zstd = true;

        /** Maximum allowed size of a response body.

            Reading a body which exceeds the limit
            after decoding fails with
            `http::error::body_too_large`. The
            default is unlimited.
        */
        std::uint64_t response_body_limit =
            (std::numeric_limits<std::uint64_t>::max)();

        /** Size of the in-place response buffer.

            Bodies up to this size fit in the
            internal buffer of the parser and can be
            read without additional allocations
            using @ref response::try_as_view and
            @ref response::as_view. Reading a
            larger body in place fails with
            `http::error::in_place_overflow`.
        */
        std::size_t response_inplace_buffer = 1024 * 1024;

        /** Timeout for the entire operation.

            When set, each request must complete
            within this duration, from connection
            establishment through receipt of the
            response headers. The remaining time
            then bounds a whole-body read with
            @ref response::as or
            @ref response::as_view (and their
            `try_` forms), but not the streaming
            sources @ref response::as_buffer_source
            and @ref response::as_read_source. Can
            be overridden per request with
            @ref request_builder::timeout.
        */
        std::optional<clock::duration> timeout;

        /** Timeout for establishing a connection.

            Covers name resolution, the TCP
            connection, proxy negotiation, and the
            TLS handshake.
        */
        clock::duration connect_timeout = std::chrono::seconds(60);

        /** Timeout for individual I/O operations.

            When set, applies to every read and write
            performed on a connection, bounding the
            time the peer may remain unresponsive
            regardless of the message size.
        */
        std::optional<clock::duration> io_timeout = std::nullopt;

        /** Time an idle pooled connection remains usable.

            Pooled connections which have been idle for
            longer than this duration are discarded
            instead of being reused.
        */
        clock::duration pool_idle_timeout = std::chrono::seconds(90);

        /** Maximum number of idle pooled connections per origin.

            When the limit is reached, additional
            connections are closed instead of being
            returned to the pool.
        */
        std::size_t pool_max_idle_per_host = 10;

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
            `socks5`, and `socks5h`. Credentials in the
            userinfo component of the URL are used for
            proxy authentication.

            @par Example
            @code
            cfg.proxy = urls::url("socks5h://user:pass@localhost:8080");
            @endcode
        */
        std::optional<urls::url> proxy;

        /** Override connection establishment.

            When set, this function is invoked
            instead of the built-in name resolution,
            TCP connection, proxy negotiation, and
            TLS handshake whenever the pool needs a
            new connection. 

            Intended for testing and for advanced uses
            such as connecting over a pre-established
            tunnel or a Unix domain socket.

            @par Example
            @code
            cfg.connect_handler =
                [](urls::url_view) -> capy::io_task<capy::any_stream>
                {
                    auto [a, b] = capy::test::make_stream_pair();
                    // drive b from the test; hand a to the client
                    co_return { {}, capy::any_stream(std::move(a)) };
                };
            @endcode
        */
        std::function<
            capy::io_task<capy::any_stream>(urls::url_view url)>
                connect_handler;
    };

private:
    config config_;
    std::shared_ptr<detail::connection_pool> pool_;
    http::fields headers_;
    burl::cookie_jar cookie_jar_;

public:
    /** Constructor.

        Constructs a client with a default
        configuration.

        @param exec The executor used to perform
        asynchronous operations.

        @param tls_ctx The TLS context used for
        `https` connections.
    */
    BOOST_BURL_DECL
    client(capy::executor_ref exec, corosio::tls_context tls_ctx);

    /** Constructor.

        Constructs a client with the provided
        configuration. Content codings whose decode
        service is not installed in the system
        context are disabled, regardless of the
        configuration.

        @param exec The executor used to perform
        asynchronous operations.

        @param tls_ctx The TLS context used for
        `https` connections.

        @param cfg The configuration settings.
    */
    BOOST_BURL_DECL
    client(capy::executor_ref exec, corosio::tls_context tls_ctx, config cfg);

    /** Copy constructor (deleted).
    */
    client(client const&) = delete;

    /** Copy assignment (deleted).
    */
    client&
    operator=(client const&) = delete;

    /** Move constructor.

        @param other The client to move from.
    */
    client(client&& other) = default;

    /** Move assignment.

        @param other The client to move from.

        @return A reference to this client.
    */
    client&
    operator=(client&& other) = default;

    /** Return the default headers.

        These headers are sent with every request.
        Headers set on an individual request take
        precedence over default headers with the
        same name.

        @par Example
        @code
        c.headers().set(http::field::user_agent, "BoostBurl/1.0");
        @endcode
    */
    http::fields&
    headers() noexcept
    {
        return headers_;
    }

    /** Return the default headers.

        These headers are sent with every request.
        Headers set on an individual request take
        precedence over default headers with the
        same name.
    */
    const http::fields&
    headers() const noexcept
    {
        return headers_;
    }

    /** Return the cookie jar.

        The jar stores cookies received in responses
        and supplies them for subsequent requests
        when @ref config::cookies is enabled.
    */
    burl::cookie_jar&
    cookie_jar() noexcept
    {
        return cookie_jar_;
    }

    /** Return the cookie jar.

        The jar stores cookies received in responses
        and supplies them for subsequent requests
        when @ref config::cookies is enabled.
    */
    const burl::cookie_jar&
    cookie_jar() const noexcept
    {
        return cookie_jar_;
    }

    /** Set default credentials for HTTP Basic authentication.

        Sets the default `Authorization` header,
        sent with every request, to the Basic scheme
        with the provided credentials. Can be
        overridden per request with
        @ref request_builder::basic_auth.

        Credentials are not sent when a redirect
        leads to a different origin, unless
        @ref config::unrestricted_auth is enabled.

        @param user The username.

        @param pass The password.
    */
    BOOST_BURL_DECL
    void
    basic_auth(std::string_view user, std::string_view pass);

    /** Set a default token for HTTP Bearer authentication.

        Sets the default `Authorization` header,
        sent with every request, to the Bearer
        scheme with the provided token. Can be
        overridden per request with
        @ref request_builder::bearer_auth.

        The token is not sent when a redirect leads
        to a different origin, unless
        @ref config::unrestricted_auth is enabled.

        @param token The bearer token.
    */
    BOOST_BURL_DECL
    void
    bearer_auth(std::string_view token);

    /** Create a builder for a `GET` request.

        @par Example
        @code
        auto r = co_await c.get("https://example.com")
            .as<std::string>();
        @endcode

        @param url The URL of the request.

        @return A builder for configuring and
        sending the request.
    */
    BOOST_BURL_DECL
    request_builder
    get(urls::url_view url);

    /** Create a builder for a `HEAD` request.

        @param url The URL of the request.

        @return A builder for configuring and
        sending the request.
    */
    BOOST_BURL_DECL
    request_builder
    head(urls::url_view url);

    /** Create a builder for a `POST` request.

        @param url The URL of the request.

        @return A builder for configuring and
        sending the request.
    */
    BOOST_BURL_DECL
    request_builder
    post(urls::url_view url);

    /** Create a builder for a `PUT` request.

        @param url The URL of the request.

        @return A builder for configuring and
        sending the request.
    */
    BOOST_BURL_DECL
    request_builder
    put(urls::url_view url);

    /** Create a builder for a `PATCH` request.

        @param url The URL of the request.

        @return A builder for configuring and
        sending the request.
    */
    BOOST_BURL_DECL
    request_builder
    patch(urls::url_view url);

    /** Create a builder for a `DELETE` request.

        The trailing underscore in the function name
        avoids the `delete` keyword.

        @param url The URL of the request.

        @return A builder for configuring and
        sending the request.
    */
    BOOST_BURL_DECL
    request_builder
    delete_(urls::url_view url);

    /** Create a builder for a request.

        The verb functions are equivalent to calling
        this function with the corresponding method.

        @param method The method of the request.

        @param url The URL of the request.

        @return A builder for configuring and
        sending the request.
    */
    BOOST_BURL_DECL
    request_builder
    request(http::method method, urls::url_view url);

    /** Asynchronously execute a request.

        Sends the request and reads the response
        status line and headers; the body is left
        unread and can be consumed through the
        returned @ref response.

        @par Example
        @code
        burl::request req = c.get("https://example.com").build();

        auto [ec, r] = co_await c.execute(std::move(req));
        @endcode

        @param request The request to execute.

        @return An awaitable yielding
        `(error_code,response)`.

        @see @ref request_builder::send.
    */
    BOOST_BURL_DECL
    capy::io_task<response>
    execute(burl::request request);

private:
    BOOST_BURL_DECL
    capy::io_task<response>
    execute_impl(
        burl::request request,
        std::optional<config::clock::time_point> deadline);
};

} // namespace burl
} // namespace boost

#include <boost/burl/request_builder.hpp>

#endif
