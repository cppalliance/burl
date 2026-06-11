//
// Copyright (c) 2026 Mohammad Nejati
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

#ifndef BOOST_BURL_REQUEST_HPP
#define BOOST_BURL_REQUEST_HPP

#include <boost/burl/any_request_body.hpp>
#include <boost/burl/detail/config.hpp>

#include <boost/http/fields.hpp>
#include <boost/http/method.hpp>
#include <boost/url/url.hpp>

#include <chrono>
#include <optional>

namespace boost
{
namespace burl
{

/** An HTTP request prepared for execution.

    Objects of this type hold everything needed to
    perform a request. They are usually produced by
    @ref request_builder::build and consumed by
    @ref client::execute, which allows a request to
    be constructed once, stored, and executed later.

    @par Example
    @code
    burl::request req = c.post("https://example.com/post")
        .header("X-Debug", "1")
        .body("payload")
        .build();

    auto [ec, r] = co_await c.execute(std::move(req));
    @endcode

    @see
        @ref client::execute,
        @ref request_builder.
*/
struct request
{
    /** Per-request options.
    */
    struct options
    {
        using clock = std::chrono::steady_clock;

        /** Timeout for the entire operation.

            When set, overrides
            @ref client::config::timeout for this
            request.

            @see @ref request_builder::timeout.
        */
        std::optional<clock::duration> timeout;
    };

    /** The request method.
    */
    http::method method;

    /** The request URL.
    */
    urls::url url;

    /** The request headers.

        Headers set here take precedence over the
        default headers of the @ref client with the
        same name.
    */
    http::fields headers;

    /** The request body.

        An empty wrapper indicates a request without
        a body.
    */
    any_request_body body;

    /** The per-request options.
    */
    options options;
};

} // namespace burl
} // namespace boost

#endif
