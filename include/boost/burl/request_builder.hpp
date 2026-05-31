//
// Copyright (c) 2026 Mohammad Nejati
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

#ifndef BOOST_BURL_REQUEST_BUILDER_HPP
#define BOOST_BURL_REQUEST_BUILDER_HPP

#include <boost/burl/conversion.hpp>
#include <boost/burl/detail/config.hpp>
#include <boost/burl/request.hpp>
#include <boost/burl/response.hpp>

#include <boost/capy/io_task.hpp>
#include <boost/http/field.hpp>
#include <boost/http/method.hpp>
#include <boost/url/url.hpp>

#include <chrono>
#include <string_view>
#include <type_traits>
#include <utility>

namespace boost
{
namespace burl
{

class client;

/** A builder for configuring and sending a request.

    Objects of this type are created by the verb
    functions of @ref client, such as
    @ref client::get and @ref client::post. Member
    functions configure the request and return the
    builder by rvalue reference, allowing calls to
    be chained. The chain is finished with
    @ref send, @ref as, or @ref build, which
    consume the builder.

    @par Example
    @code
    auto r = co_await c.get("https://example.com/get")
        .query("category", "shoes")
        .header(http::field::accept_language, "en")
        .as<json::value>();
    @endcode

    @see
        @ref client,
        @ref request,
        @ref response.
*/
class request_builder
{
    client& client_;
    request request_;

public:
    /** Constructor.

        Constructs a builder for a request with the
        provided method and URL. Ownership of the
        client is not transferred; it must remain
        valid until the request has been sent.

        @param client The client used to send the
        request.

        @param method The method of the request.

        @param url The URL of the request.
    */
    request_builder(client& client, http::method method, urls::url url)
        : client_(client)
        , request_{ method, std::move(url), {}, {} }
    {
    }

    /** Append a parameter to the URL query.

        The key and value are percent-encoded.

        @par Example
        @code
        auto r = co_await c.get("https://example.com/get")
            .query("category", "shoes")
            .query("color", "blue")
            .send();
        @endcode

        @param key The key of the parameter.

        @param value The value of the parameter.

        @return The builder, for chaining.
    */
    BOOST_BURL_DECL
    request_builder&&
    query(std::string_view key, std::string_view value) &&;

    /** Set a request header.

        Any existing values for the same field are
        replaced. Headers set on the request take
        precedence over the default headers of the
        client with the same name.

        @param field The field name constant.

        @param value The value of the field.

        @return The builder, for chaining.
    */
    BOOST_BURL_DECL
    request_builder&&
    header(http::field field, std::string_view value) &&;

    /** Set a request header.

        Any existing values for the same field are
        replaced. Headers set on the request take
        precedence over the default headers of the
        client with the same name.

        @param name The name of the field.

        @param value The value of the field.

        @return The builder, for chaining.
    */
    BOOST_BURL_DECL
    request_builder&&
    header(std::string_view name, std::string_view value) &&;

    /** Set credentials for HTTP Basic authentication.

        Sets the `Authorization` header of this
        request to the Basic scheme with the
        provided credentials, overriding any default
        set on the client.

        Credentials are not sent when a redirect
        leads to a different origin, unless
        @ref client::config::unrestricted_auth is
        enabled.

        @param user The username.

        @param pass The password.

        @return The builder, for chaining.
    */
    BOOST_BURL_DECL
    request_builder&&
    basic_auth(std::string_view user, std::string_view pass) &&;

    /** Set a token for HTTP Bearer authentication.

        Sets the `Authorization` header of this
        request to the Bearer scheme with the
        provided token, overriding any default set
        on the client.

        The token is not sent when a redirect leads
        to a different origin, unless
        @ref client::config::unrestricted_auth is
        enabled.

        @param token The bearer token.

        @return The builder, for chaining.
    */
    BOOST_BURL_DECL
    request_builder&&
    bearer_auth(std::string_view token) &&;

    /** Treat 4xx and 5xx status codes as errors.

        When enabled, a response with a status code
        of 400 or above causes @ref send to yield an
        error code whose value is the status code
        and whose category is @ref burl_category,
        alongside the response. Such codes compare
        equal to @ref condition::client_error or
        @ref condition::server_error. @ref as throws
        instead.

        @par Example
        @code
        auto [ec, r] = co_await c.get("https://example.com/not-found")
            .error_for_status()
            .send();

        if(ec == burl::condition::client_error)
            std::cerr << ec.message() << '\n'; // HTTP 404 Not Found
        @endcode

        @param enable `true` to treat 4xx and 5xx
        status codes as errors.

        @return The builder, for chaining.

        @see @ref response::raise_for_status.
    */
    request_builder&&
    error_for_status(bool enable = true) &&
    {
        request_.options.error_for_status = enable;
        return std::move(*this);
    }

    /** Set a timeout for the entire operation.

        Overrides @ref client::config::timeout for
        this request.

        @param dur The timeout duration.

        @return The builder, for chaining.
    */
    request_builder&&
    timeout(request::options::clock::duration dur) &&
    {
        request_.options.timeout = dur;
        return std::move(*this);
    }

    /** Set the request body.

        The value is converted to a request body by
        calling `tag_invoke` with
        @ref body_from_tag.

        The `Content-Type` of the body is used
        unless the header is set explicitly on the
        request. The `Content-Length`, or chunked
        transfer encoding, is always derived from
        the body.

        @par Example
        @code
        auto r = co_await c.post("https://example.com/post")
            .body(json::value({ "key", "value" }))
            .send();
        @endcode

        @param value The value to convert into the
        body.

        @param args Additional arguments forwarded
        to the conversion.

        @return The builder, for chaining.

        @see
            @ref body_from_tag,
            @ref RequestBody.
    */
    template<class T, class... Args>
        requires requires(T&& value, Args&&... args) {
            tag_invoke(
                body_from_tag<std::remove_cvref_t<T>>{},
                std::forward<T>(value),
                std::forward<Args>(args)...);
        }
    request_builder&&
    body(T&& value, Args&&... args) &&
    {
        request_.body = tag_invoke(
            body_from_tag<std::remove_cvref_t<T>>{},
            std::forward<T>(value),
            std::forward<Args>(args)...);
        return std::move(*this);
    }

    /** Set the request body.

        @param body The body to set.

        @return The builder, for chaining.
    */
    request_builder&&
    body(any_request_body body) &&
    {
        request_.body = std::move(body);
        return std::move(*this);
    }

    /** Return the configured request.

        The returned request can be stored and
        executed later with @ref client::execute.

        @par Example
        @code
        burl::request req = c.post("https://example.com/post")
            .header("X-Debug", "1")
            .body("payload")
            .build();

        auto [ec, r] = co_await c.execute(std::move(req));
        @endcode

        @return The configured request.
    */
    request
    build() &&
    {
        return std::move(request_);
    }

    /** Asynchronously send the request.

        Sends the request and reads the response
        status line and headers; the body is left
        unread and can be consumed through the
        returned @ref response. Equivalent to
        passing the built request to
        @ref client::execute.

        @par Example
        @code
        auto [ec, r] = co_await c.get("https://example.com").send();
        @endcode

        @return An awaitable yielding
        `(error_code,response)`.
    */
    BOOST_BURL_DECL
    capy::io_task<response>
    send() &&;

    /** Asynchronously send the request and convert the body.

        Sends the request and converts the response
        body to `T` by calling `tag_invoke` with
        @ref body_to_tag.

        @par Example
        @code
        auto r = co_await c.get("https://example.com")
            .as<std::string>();
        @endcode

        @throw std::system_error
        The request or the conversion failed.

        @tparam T The type to convert the body to.

        @param args Additional arguments forwarded
        to the conversion.

        @return An awaitable yielding the converted
        body.

        @see
            @ref body_to_tag,
            @ref response::as.
    */
    template<class T, class... Args>
    capy::task<T>
    as(Args... args) &&
    {
        auto [ec, r] = co_await std::move(*this).send();
        if(ec)
            throw std::system_error(ec);

        auto [bec, b] = co_await r.template try_as<T>(std::move(args)...);
        if(bec)
            throw std::system_error(bec);

        co_return std::move(b);
    }
};

} // namespace burl
} // namespace boost

#endif
