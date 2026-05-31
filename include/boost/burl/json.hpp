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

} // namespace burl
} // namespace boost

#endif
