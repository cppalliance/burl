//
// Copyright (c) 2026 Mohammad Nejati
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

#ifndef BOOST_BURL_RESPONSE_HPP
#define BOOST_BURL_RESPONSE_HPP

#include <boost/burl/connection_pool.hpp>
#include <boost/burl/conversion.hpp>
#include <boost/burl/detail/config.hpp>
#include <boost/burl/error.hpp>
#include <boost/capy/io/any_buffer_source.hpp>
#include <boost/capy/io/any_read_source.hpp>
#include <boost/capy/io_task.hpp>
#include <boost/http/fields_base.hpp>
#include <boost/http/metadata.hpp>
#include <boost/http/response_parser.hpp>
#include <boost/http/status.hpp>
#include <boost/http/version.hpp>
#include <boost/url/url.hpp>
#include <boost/url/url_view.hpp>

#include <chrono>
#include <cstddef>
#include <optional>
#include <string_view>
#include <system_error>
#include <utility>

namespace boost
{
namespace burl
{

/** The response to an HTTP request.

    Objects of this type provide access to the
    status, headers, and body of a response. The
    status line and headers have already been read
    when the response is obtained; the body remains
    unread on the connection and is consumed through
    the body functions.

    The response owns the connection it was received
    on. Upon destruction, the connection is returned
    to the pool for reuse when the body was read to
    completion and the connection can be kept alive;
    otherwise it is closed.

    @par Example
    @code
    auto [ec, r] = co_await c.get("https://example.com").send();

    if(ec)
        throw std::system_error(ec);

    std::cout << "status: " << r.status_int() << '\n';
    std::cout << "headers: " << r.headers() << '\n';
    std::cout << "body: " << co_await r.as<std::string>() << '\n';
    @endcode

    @see
        @ref client::execute,
        @ref request_builder::send.
*/
class response
{
    friend class client;

    urls::url url_;
    connection_pool::pooled_connection conn_;
    connection_pool* pool_ = nullptr;
    http::response_parser parser_;
    std::optional<std::chrono::steady_clock::time_point> deadline_;

    response(
        urls::url url,
        connection_pool::pooled_connection conn,
        connection_pool* pool,
        http::response_parser parser,
        std::optional<std::chrono::steady_clock::time_point> deadline);

public:
    /** Constructor.

        A default-constructed response is not
        associated with any request, and is intended
        only as a target for assignment.
    */
    response() = default;

    /** Constructor.

        Constructs a response by taking ownership of
        the contents of another response, including
        the underlying connection. The moved-from
        response no longer owns a connection.

        @param other The response to move from.
    */
    BOOST_BURL_DECL
    response(response&& other) noexcept;

    /** Assignment.

        Takes ownership of the contents of another
        response, including the underlying
        connection. The previously owned connection,
        if any, is returned to the pool or closed,
        as if by destruction. The moved-from
        response no longer owns a connection.

        @param other The response to move from.

        @return A reference to this object.
    */
    BOOST_BURL_DECL
    response&
    operator=(response&& other) noexcept;

    /** Destructor.

        Returns the connection to the pool for reuse
        when the body was read to completion and the
        connection can be kept alive; otherwise the
        connection is closed.
    */
    BOOST_BURL_DECL
    ~response();

    /** Return the status code.
    */
    http::status
    status() const noexcept
    {
        return parser_.get().status();
    }

    /** Return the status code as an integer.
    */
    unsigned short
    status_int() const noexcept
    {
        return parser_.get().status_int();
    }

    /** Return true if the status code indicates success.
    */
    bool
    ok() const noexcept
    {
        return http::to_status_class(status()) ==
            http::status_class::successful;
    }

    /** Return the reason phrase of the status code.
    */
    std::string_view
    reason() const noexcept
    {
        return parser_.get().reason();
    }

    /** Throw an exception for 4xx and 5xx status codes.

        If the status code is 400 or above, throws
        an exception whose code value is the status
        code and whose category is
        @ref burl_category. Otherwise, this function
        has no effect.

        @par Example
        @code
        r.raise_for_status(); // throws on 4XX and 5XX status codes
        @endcode

        @throw std::system_error
        The status code is 400 or above.

        @see @ref request_builder::error_for_status.
    */
    void
    raise_for_status() const
    {
        if(status_int() >= 400)
            throw std::system_error(
                std::error_code(status_int(), burl_category()));
    }

    /** Return the HTTP version of the response.
    */
    http::version
    version() const noexcept
    {
        return parser_.get().version();
    }

    /** Return the final URL of the response.
    */
    urls::url_view
    url() const noexcept
    {
        return url_;
    }

    /** Return the response headers.
    */
    const http::fields_base&
    headers() const noexcept
    {
        return parser_.get();
    }

    /** Return the payload size, if known.

        Returns the size of the message payload when
        it is determined by the message metadata.
        Otherwise returns an empty optional, such as
        for chunked messages.
    */
    std::optional<std::uint64_t>
    content_length() const noexcept
    {
        if(parser_.get().payload() == http::payload::size)
            return parser_.get().payload_size();
        return std::nullopt;
    }

    /** Asynchronously read the entire body in place.

        Reads the remainder of the body into the
        internal buffer of the parser and returns a
        view of the complete body. The buffer is
        sized by
        @ref client::config::response_inplace_buffer;
        a body which does not fit fails with
        `http::error::in_place_overflow`. If the
        body has already been read to completion,
        the body is returned without performing I/O.

        The returned view references memory owned by
        the response, and remains valid until the
        response is destroyed or moved from.

        The remaining time of the request timeout,
        when one was set, applies to this operation.

        @par Example
        @code
        auto [ec, body] = co_await r.try_as_view();
        @endcode

        @return An awaitable yielding
        `(error_code,std::string_view)`.

        @see @ref as_view.
    */
    BOOST_BURL_DECL
    capy::io_task<std::string_view>
    try_as_view() &;

    /** Asynchronously read the entire body in place.

        Equivalent to @ref try_as_view, except
        that an exception is thrown upon failure.

        @par Example
        @code
        std::cout << co_await r.as_view() << '\n';
        @endcode

        @throw std::system_error
        The operation failed.

        @return An awaitable yielding a view of the
        body.
    */
    BOOST_BURL_DECL
    capy::task<std::string_view>
    as_view() &;

    /** Asynchronously convert the body.

        Reads the body and converts it to `T` by
        calling `tag_invoke` with @ref body_to_tag.

        @par Example
        @code
        auto [ec, v] = co_await r.try_as<json::value>();
        @endcode

        @tparam T The type to convert the body to.

        @param args Additional arguments forwarded
        to the conversion.

        @return An awaitable yielding
        `(error_code,T)`.

        @see
            @ref as,
            @ref body_to_tag.
    */
    template<class T, class... Args>
        requires requires(response& resp, Args&&... args) {
            tag_invoke(body_to_tag<T>{}, resp, std::forward<Args>(args)...);
        }
    capy::io_task<T>
    try_as(Args&&... args) &
    {
        return tag_invoke(body_to_tag<T>{}, *this, std::forward<Args>(args)...);
    }

    /** Asynchronously convert the body.

        Equivalent to @ref try_as, except that an
        exception is thrown upon failure.

        @par Example
        @code
        auto v = co_await r.as<json::value>();
        @endcode

        @throw std::system_error
        The operation failed.

        @tparam T The type to convert the body to.

        @param args Additional arguments forwarded
        to the conversion.

        @return An awaitable yielding the converted
        body.

        @see
            @ref try_as,
            @ref body_to_tag.
    */
    template<class T, class... Args>
    capy::task<T>
    as(Args... args) &
    {
        auto [ec, body] = co_await try_as<T>(std::move(args)...);

        if(ec)
            throw std::system_error(ec);

        co_return std::move(body);
    }

    /** Return a buffer source for reading the body.

        The returned source pulls the body
        incrementally, exposing the internal buffers
        of the parser directly instead of buffering
        the whole body in memory. The response must
        remain valid until the source is no longer
        used.

        @par Example
        @code
        auto source = r.as_buffer_source();
        for(;;)
        {
            capy::const_buffer arr[8];
            auto [ec, bufs] = co_await source.pull(arr);
            if(ec == capy::cond::eof)
                break;
            if(ec)
                throw std::system_error(ec);
            for(auto const& buf : bufs)
            {
                consume_data(buf.data(), buf.size());
                source.consume(buf.size());
            }
        }
        @endcode

        @return A buffer source for the body.

        @see @ref as_read_source.
    */
    BOOST_BURL_DECL
    capy::any_buffer_source
    as_buffer_source() &;

    /** Return a read source for reading the body.

        The returned source reads the body
        incrementally into caller-provided buffers.
        The response must remain valid until the
        source is no longer used.

        @return A read source for the body.

        @see @ref as_buffer_source.
    */
    BOOST_BURL_DECL
    capy::any_read_source
    as_read_source() &;
};

} // namespace burl
} // namespace boost

#endif
