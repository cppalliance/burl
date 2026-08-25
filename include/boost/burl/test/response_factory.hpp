//
// Copyright (c) 2026 Mohammad Nejati
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

#ifndef BOOST_BURL_TEST_RESPONSE_FACTORY_HPP
#define BOOST_BURL_TEST_RESPONSE_FACTORY_HPP

#include <boost/burl/detail/connection_pool.hpp>
#include <boost/burl/message_reader.hpp>
#include <boost/burl/response_parser.hpp>
#include <boost/burl/response.hpp>
#include <boost/burl/response_head.hpp>
#include <boost/burl/test/detail/buffer_connection.hpp>

#include <boost/capy/task.hpp>
#include <boost/capy/test/run_blocking.hpp>
#include <boost/url/url.hpp>

#include <string>
namespace boost
{
namespace burl
{
namespace test
{

/** A factory for synthesizing a @ref response.

    This is test infrastructure for exercising code
    that consumes a @ref response, such as body
    conversions and status handling, without standing
    up a client or server. It produces a genuine
    @ref response: the status line and headers are
    parsed up front, and the body remains unread on a
    synthetic connection, to be consumed through the
    normal body functions.

    Member functions configure the factory and return
    a reference to it, allowing calls to be chained. A
    response is produced with @ref create, which
    leaves the factory unchanged and may be called
    repeatedly to obtain independent responses.

    The body is supplied as a vector of strings. Each
    element is delivered as a separate read, so the
    split controls how the body is fragmented on the
    wire. With @ref chunked, each element is framed as
    its own transfer-encoding chunk; otherwise the
    elements are concatenated under a single
    `Content-Length`.

    @par Example
    @code
    auto r = test::response_factory(http::status::ok)
        .header(http::field::content_type, "application/json")
        .body({ R"({"key":"value"})" })
        .create();

    auto body = co_await r.as<json::value>();
    @endcode

    @see @ref response.
*/
class response_factory
{
    using clock = std::chrono::steady_clock;

    response_head head_;
    std::vector<std::string> body_;
    urls::url url_;
    std::optional<clock::time_point> deadline_;

public:
    /** Constructor.

        Constructs a factory for a response with the
        provided status code and version. The reason
        phrase is set to the standard text for the
        status code.

        @param sc The status code of the response.

        @param v The HTTP version of the response.
    */
    explicit
    response_factory(
        http::status sc = http::status::ok,
        http::version v = http::version::http_1_1)
        : head_(sc, v)
    {
    }

    /** Append a response header.

        The value is added without removing any
        existing values for the same field. Use this
        to synthesize repeated fields such as
        `Set-Cookie`.

        @param field The field name constant.

        @param value The value of the field.

        @return The factory, for chaining.
    */
    response_factory&
    header(http::field field, core::string_view value)
    {
        head_.append(field, value);
        return *this;
    }

    /** Append a response header.

        The value is added without removing any
        existing values for the same field.

        @param name The name of the field.

        @param value The value of the field.

        @return The factory, for chaining.
    */
    response_factory&
    header(core::string_view name, core::string_view value)
    {
        head_.append(name, value);
        return *this;
    }

    /** Set the response body.

        Each element is delivered as a separate read.
        With @ref chunked, each element becomes its
        own chunk; otherwise the elements are
        concatenated and framed with a
        `Content-Length`.

        @param body The body fragments.

        @return The factory, for chaining.
    */
    response_factory&
    body(std::vector<std::string> body)
    {
        body_ = std::move(body);
        return *this;
    }

    /** Override the `Content-Length` header.

        By default a non-chunked response is framed
        with a `Content-Length` equal to the total
        size of the body fragments. This forces a
        specific value instead, which may differ from
        the actual body size to exercise
        mismatched-length handling. It has no effect
        when @ref chunked is enabled.

        @param value The content length to advertise.

        @return The factory, for chaining.
    */
    response_factory&
    content_length(std::uint64_t value)
    {
        head_.set_content_length(value);
        return *this;
    }

    /** Frame the body with chunked transfer encoding.

        When enabled, the body is sent using chunked
        transfer encoding instead of a
        `Content-Length`, and each body fragment is
        framed as a separate chunk.

        @param value Whether to use chunked transfer
        encoding.

        @return The factory, for chaining.
    */
    response_factory&
    chunked(bool value)
    {
        head_.set_chunked(value);
        return *this;
    }

    /** Set the final URL of the response.

        @param url The URL.

        @return The factory, for chaining.
    */
    response_factory&
    url(urls::url url)
    {
        url_ = std::move(url);
        return *this;
    }

    /** Set a timeout for reading the body.

        Sets a deadline measured from the time of this
        call. The remaining time applies to body
        reads, exactly as for a client-produced
        response.

        @param dur The timeout duration.

        @return The factory, for chaining.
    */
    response_factory&
    timeout(clock::duration dur)
    {
        deadline_ = clock::now() + dur;
        return *this;
    }

    /** Create a response.

        Produces a new @ref response from the current
        configuration. The factory is left unchanged,
        so this may be called repeatedly to obtain
        independent responses.

        @param fuse A fuse consulted before each
        data-bearing body read. Under
        @ref capy::test::fuse::armed it injects read
        failures at successive points; the default
        fuse never injects.

        @return A @ref response equivalent to one
        obtained from a client.
    */
    response
    create(capy::test::fuse fuse = {}) const
    {
        auto head = head_;
        std::vector<std::string> chunks;
        if(head.chunked())
        {
            for(auto const& piece : body_)
                chunks.push_back(frame_chunk(piece));
            chunks.emplace_back("0\r\n\r\n");
        }
        else
        {
            if(head.payload() != http::payload::size)
            {
                std::uint64_t content_length = 0;
                for(auto const& piece : body_)
                    content_length += piece.size();
                head.set_content_length(content_length);
            }
            chunks = body_;
        }

        burl::detail::pooled_connection conn(
            std::make_unique<detail::buffer_connection>(
                std::move(chunks),
                std::move(fuse),
                std::string{ head.buffer() }),
            {},
            {});

        response_parser parser(response_parser::config{});
        parser.start();
        capy::test::run_blocking()([&]() -> capy::task<>
        {
            if(auto [ec] = co_await message_reader{
                &conn, &parser }.read_header(); ec)
                throw system::system_error(ec);
        }());

        return response{
            url_, std::move(conn), std::move(parser), deadline_ };
    }

private:
    static std::string
    frame_chunk(std::string const& data)
    {
        char hex[2 * sizeof(std::size_t)];
        auto const r =
            std::to_chars(hex, hex + sizeof(hex), data.size(), 16);
        std::string out(hex, r.ptr);
        out += "\r\n";
        out += data;
        out += "\r\n";
        return out;
    }
};

} // namespace test
} // namespace burl
} // namespace boost

#endif
