//
// Copyright (c) 2025 Vinnie Falco (vinnie dot falco at gmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

#ifndef BOOST_BURL_RESPONSE_HPP
#define BOOST_BURL_RESPONSE_HPP

#include <boost/burl/fwd.hpp>
#include <boost/burl/error.hpp>
#include <boost/http/response.hpp>
#include <boost/http/status.hpp>
#include <boost/url/url.hpp>
#include <string_view>
#include <boost/capy/io/any_buffer_source.hpp>

#include <chrono>
#include <concepts>
#include <string>
#include <vector>

namespace boost {
namespace burl {

//----------------------------------------------------------

/** HTTP response with buffered body.

    Contains the HTTP response headers, status, body content,
    and metadata about the request.

    @tparam Body The type to store the response body.
        Defaults to std::string.

    The response exposes Boost.HTTP and Boost.URL types directly:
    - `message` is a `http::response` containing headers and status
    - `url` is a `urls::url` containing the final URL after redirects

    @par Example
    @code
    auto [ec, r] = co_await session.get("https://example.com/api");
    
    // Access status
    if (r.ok()) {
        std::cout << r.text() << "\n";
    }
    
    // Access headers via http::response
    if (r.message.exists(http::field::content_type))
        std::cout << r.message.at(http::field::content_type) << "\n";
    
    // Access URL via urls::url
    std::cout << "Host: " << r.url.host() << "\n";
    @endcode
*/
template<class Body>
struct response
{
    /// HTTP response headers and status (boost::http::response)
    http::response message;

    /// Response body in the requested container type
    Body body;

    /// Final URL after following redirects (boost::urls::url)
    urls::url url;

    /// Time elapsed for the complete request
    std::chrono::milliseconds elapsed{0};

    /// Redirect history (empty if no redirects followed)
    std::vector<response<Body>> history;

    //------------------------------------------------------
    // Convenience accessors (delegate to message)
    //------------------------------------------------------

    /** Get the HTTP status code enum.
    */
    http::status
    status() const noexcept
    {
        return message.status();
    }

    /** Get the HTTP status code as an integer.
    */
    unsigned short
    status_int() const noexcept
    {
        return message.status_int();
    }

    /** Get the HTTP reason phrase.
    */
    std::string_view
    reason() const noexcept
    {
        return message.reason();
    }

    /** Check if the response indicates success (status < 400).
    */
    bool
    ok() const noexcept
    {
        return message.status_int() < 400;
    }

    /** Get the body as a string_view.

        Only available when Body is convertible to string_view.
    */
    std::string_view
    text() const noexcept
        requires std::convertible_to<Body const&, std::string_view>
    {
        return body;
    }

    /** Check if this is a redirect response.

        @return true if status is 301, 302, 303, 307, or 308
    */
    bool
    is_redirect() const noexcept
    {
        auto s = status_int();
        return s == 301 || s == 302 || s == 303 || s == 307 || s == 308;
    }

    /** Throw http_error if status indicates an error.

        Throws http_error if the status code is >= 400.
        Does nothing if the response indicates success.

        @throws http_error if status >= 400
    */
    void
    raise_for_status() const
    {
        if (status_int() >= 400)
        {
            throw http_error(
                status_int(),
                std::string(reason()),
                url.buffer());
        }
    }
};

//----------------------------------------------------------

/// Alias for response with string body (most common case)
using string_response = response<std::string>;

//----------------------------------------------------------

/** HTTP response with streaming body.

    For large responses that should not be buffered in memory.
    The body is accessed via a capy::any_buffer_source which
    allows incremental reading.

    @par Example
    @code
    auto [ec, r] = co_await session.get_streamed("https://example.com/large-file");
    
    capy::const_buffer arr[16];
    while (true) {
        auto [err, count] = co_await r.body.pull(arr, 16);
        if (err || count == 0)
            break;
        
        // Process buffers arr[0..count)
        
        r.body.consume(total_bytes_processed);
    }
    @endcode
*/
struct streamed_response
{
    /// HTTP response headers and status
    http::response message;

    /// Streaming body source
    capy::any_buffer_source body;

    /// Final URL after following redirects
    urls::url url;

    //------------------------------------------------------
    // Convenience accessors (delegate to message)
    //------------------------------------------------------

    http::status status() const noexcept { return message.status(); }
    unsigned short status_int() const noexcept { return message.status_int(); }
    std::string_view reason() const noexcept { return message.reason(); }
    bool ok() const noexcept { return message.status_int() < 400; }
    bool is_redirect() const noexcept
    {
        auto s = status_int();
        return s == 301 || s == 302 || s == 303 || s == 307 || s == 308;
    }
};

//----------------------------------------------------------

/** HTTP request with streaming body.

    For large request bodies that should not be buffered in memory.
    The body is written via a capy::any_buffer_sink.
*/
struct streamed_request
{
    /// HTTP request headers and method
    http::request message;

    /// Streaming body sink
    capy::any_buffer_sink body;
};

} // namespace burl
} // namespace boost

#endif
