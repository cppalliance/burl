//
// Copyright (c) 2026 Mohammad Nejati
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

#ifndef BOOST_BURL_JSON_HPP
#define BOOST_BURL_JSON_HPP

#include <boost/burl/any_request_body.hpp>
#include <boost/burl/conversion.hpp>
#include <boost/burl/detail/config.hpp>
#include <boost/burl/response.hpp>

#include <boost/capy/io_task.hpp>
#include <boost/json/value.hpp>

namespace boost
{
namespace burl
{

/** Create a request body from a JSON value.

    The value is serialized incrementally while the
    request is being sent. The `Content-Type` is
    `application/json`. The serialized size is not
    known ahead of time, so the body is sent with
    chunked transfer encoding.

    @par Example
    @code
    auto r = co_await c.post("https://example.com/post")
        .body(json::value({ "key", "value" }))
        .as<json::value>();
    @endcode

    @param value The JSON value to send.

    @return The request body.
*/
BOOST_BURL_DECL
any_request_body
tag_invoke(body_from_tag<json::value>, json::value value);

/** Asynchronously parse a response body as JSON.

    This overload enables `resp.as<json::value>()`
    and related functions, which parse the body
    incrementally into a `json::value`.

    @par Example
    @code
    auto r = co_await c.get("https://example.com/get")
        .as<json::value>();
    @endcode

    @param resp The response to read from.

    @return An awaitable yielding
    `(error_code,json::value)`.
*/
BOOST_BURL_DECL
capy::io_task<json::value>
tag_invoke(body_to_tag<json::value>, response& resp);

/** Create a request body from a JSON object.

    The object is serialized incrementally while the
    request is being sent. The `Content-Type` is
    `application/json`. The serialized size is not
    known ahead of time, so the body is sent with
    chunked transfer encoding.

    @par Example
    @code
    auto r = co_await c.post("https://example.com/post")
        .body(json::object({ { "key", "value" } }))
        .as<json::object>();
    @endcode

    @param value The JSON object to send.

    @return The request body.
*/
BOOST_BURL_DECL
any_request_body
tag_invoke(body_from_tag<json::object>, json::object value);

/** Asynchronously parse a response body as a JSON object.

    This overload enables `resp.as<json::object>()`
    and related functions, which parse the body
    incrementally as a `json::value`. If the parsed
    value is not an object, the awaitable yields an
    error.

    @par Example
    @code
    auto r = co_await c.get("https://example.com/get")
        .as<json::object>();
    @endcode

    @param resp The response to read from.

    @return An awaitable yielding
    `(error_code,json::object)`.
*/
BOOST_BURL_DECL
capy::io_task<json::object>
tag_invoke(body_to_tag<json::object>, response& resp);

/** Create a request body from a JSON array.

    The array is serialized incrementally while the
    request is being sent. The `Content-Type` is
    `application/json`. The serialized size is not
    known ahead of time, so the body is sent with
    chunked transfer encoding.

    @par Example
    @code
    auto r = co_await c.post("https://example.com/post")
        .body(json::array({ 1, 2, 3 }))
        .as<json::array>();
    @endcode

    @param value The JSON array to send.

    @return The request body.
*/
BOOST_BURL_DECL
any_request_body
tag_invoke(body_from_tag<json::array>, json::array value);

/** Asynchronously parse a response body as a JSON array.

    This overload enables `resp.as<json::array>()`
    and related functions, which parse the body
    incrementally as a `json::value`. If the parsed
    value is not an array, the awaitable yields an
    error.

    @par Example
    @code
    auto r = co_await c.get("https://example.com/get")
        .as<json::array>();
    @endcode

    @param resp The response to read from.

    @return An awaitable yielding
    `(error_code,json::array)`.
*/
BOOST_BURL_DECL
capy::io_task<json::array>
tag_invoke(body_to_tag<json::array>, response& resp);

/** Create a request body from a JSON string.

    The string is serialized incrementally while the
    request is being sent. The `Content-Type` is
    `application/json`. The serialized size is not
    known ahead of time, so the body is sent with
    chunked transfer encoding.

    @par Example
    @code
    auto r = co_await c.post("https://example.com/post")
        .body(json::string("value"))
        .as<json::string>();
    @endcode

    @param value The JSON string to send.

    @return The request body.
*/
BOOST_BURL_DECL
any_request_body
tag_invoke(body_from_tag<json::string>, json::string value);

/** Asynchronously parse a response body as a JSON string.

    This overload enables `resp.as<json::string>()`
    and related functions, which parse the body
    incrementally as a `json::value`. If the parsed
    value is not a string, the awaitable yields an
    error.

    @par Example
    @code
    auto r = co_await c.get("https://example.com/get")
        .as<json::string>();
    @endcode

    @param resp The response to read from.

    @return An awaitable yielding
    `(error_code,json::string)`.
*/
BOOST_BURL_DECL
capy::io_task<json::string>
tag_invoke(body_to_tag<json::string>, response& resp);

} // namespace burl
} // namespace boost

#endif
