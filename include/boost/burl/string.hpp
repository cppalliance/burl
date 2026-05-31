//
// Copyright (c) 2026 Mohammad Nejati
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

#ifndef BOOST_BURL_STRING_HPP
#define BOOST_BURL_STRING_HPP

#include <boost/burl/any_request_body.hpp>
#include <boost/burl/conversion.hpp>
#include <boost/burl/detail/config.hpp>
#include <boost/burl/response.hpp>

#include <boost/capy/io_task.hpp>

#include <cstddef>
#include <string>
#include <string_view>

namespace boost
{
namespace burl
{

/** Create a request body from a string.

    The body takes ownership of the string. The
    `Content-Type` is `text/plain; charset=utf-8`,
    and the `Content-Length` is the size of the
    string.

    @par Example
    @code
    auto r = co_await c.post(url)
        .body(std::string("payload"))
        .send();
    @endcode

    @param body The string to send.

    @return The request body.
*/
BOOST_BURL_DECL
any_request_body
tag_invoke(body_from_tag<std::string>, std::string body);

/** Create a request body from a string view.

    The body refers to the passed characters;
    ownership is not transferred. The caller is
    responsible for ensuring that the lifetime of
    the underlying character buffer extends until
    the request has been sent. The `Content-Type`
    is `text/plain; charset=utf-8`, and the
    `Content-Length` is the size of the view.

    @param body The string view to send.

    @return The request body.
*/
BOOST_BURL_DECL
any_request_body
tag_invoke(body_from_tag<std::string_view>, std::string_view body);

/** Create a request body from a character array.

    The array is treated as a string literal; the
    terminating null character is excluded. The
    body refers to the passed characters; ownership
    is not transferred. The caller is responsible
    for ensuring that the lifetime of the array
    extends until the request has been sent.

    @par Example
    @code
    auto r = co_await c.post(url)
        .body("payload")
        .send();
    @endcode

    @param body The character array to send.

    @return The request body.
*/
template<std::size_t N>
any_request_body
tag_invoke(body_from_tag<char[N]>, const char (&body)[N])
{
    return tag_invoke(body_from_tag<std::string_view>{}, { body, N - 1 });
}

/** Asynchronously read a response body into a string.

    This overload enables `resp.as<std::string>()`
    and related functions, which read the entire
    body into a `std::string`.

    @par Example
    @code
    auto r = co_await c.get("https://example.com")
        .as<std::string>();
    @endcode

    @param resp The response to read from.

    @return An awaitable yielding
    `(error_code,std::string)`.
*/
BOOST_BURL_DECL
capy::io_task<std::string>
tag_invoke(body_to_tag<std::string>, response& resp);

} // namespace burl
} // namespace boost

#endif
