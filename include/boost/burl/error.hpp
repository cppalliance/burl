//
// Copyright (c) 2025 Vinnie Falco (vinnie dot falco at gmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

#ifndef BOOST_BURL_ERROR_HPP
#define BOOST_BURL_ERROR_HPP

#include <boost/burl/fwd.hpp>
#include <system_error>

#include <exception>
#include <string>

namespace boost {
namespace burl {

//----------------------------------------------------------

/** Error codes for burl operations.
*/
enum class error
{
    /// Operation succeeded
    success = 0,

    /// URL is malformed or missing required components
    invalid_url,

    /// URL scheme is not http or https
    invalid_scheme,

    /// Failed to resolve hostname
    resolve_failed,

    /// Failed to establish TCP connection
    connection_failed,

    /// TLS handshake failed
    tls_handshake_failed,

    /// Operation timed out
    timeout,

    /// Too many redirects followed
    too_many_redirects,

    /// Response body exceeds size limit
    body_too_large,

    /// Invalid HTTP response received
    invalid_response,

    /// Connection was closed unexpectedly
    connection_closed,

    /// Operation cancelled
    cancelled,

    /// Operation not yet implemented
    not_implemented
};

//----------------------------------------------------------

/** Error category for burl errors.
*/
class error_category : public std::error_category
{
public:
    /** Return the name of the category.
    */
    char const*
    name() const noexcept override
    {
        return "boost.burl";
    }

    /** Return the message for an error code.
    */
    std::string
    message(int ev) const override;

    /** Return the error condition for an error code.
    */
    std::error_condition
    default_error_condition(int ev) const noexcept override;
};

//----------------------------------------------------------

/** Return the error category for burl errors.
*/
BOOST_BURL_DECL
std::error_category const&
burl_category() noexcept;

/** Create an error_code from a burl error.
*/
inline std::error_code
make_error_code(error e) noexcept
{
    return std::error_code(
        static_cast<int>(e),
        burl_category());
}

//----------------------------------------------------------

/** Exception thrown when raise_for_status() is called on an error response.

    This exception is thrown by response::raise_for_status() when
    the HTTP status code indicates an error (>= 400).
*/
class http_error : public std::exception
{
    unsigned short status_code_;
    std::string reason_;
    std::string url_;
    std::string what_;

public:
    /** Constructor.

        @param status_code The HTTP status code (e.g., 404, 500)
        @param reason The HTTP reason phrase
        @param url The URL that returned the error
    */
    http_error(
        unsigned short status_code,
        std::string reason,
        std::string url);

    /** Return a description of the error.
    */
    char const*
    what() const noexcept override
    {
        return what_.c_str();
    }

    /** Return the HTTP status code.
    */
    unsigned short
    status_code() const noexcept
    {
        return status_code_;
    }

    /** Return the HTTP reason phrase.
    */
    std::string const&
    reason() const noexcept
    {
        return reason_;
    }

    /** Return the URL that returned the error.
    */
    std::string const&
    url() const noexcept
    {
        return url_;
    }
};

} // namespace burl
} // namespace boost

//----------------------------------------------------------

template<>
struct std::is_error_code_enum<boost::burl::error> : std::true_type {};

//----------------------------------------------------------

namespace boost {
namespace burl {

BOOST_BURL_DECL
std::string
error_category::message(int ev) const
{
    switch(static_cast<error>(ev))
    {
    case error::success:            return "success";
    case error::invalid_url:        return "invalid URL";
    case error::invalid_scheme:     return "invalid URL scheme";
    case error::resolve_failed:     return "DNS resolution failed";
    case error::connection_failed:  return "connection failed";
    case error::tls_handshake_failed: return "TLS handshake failed";
    case error::timeout:            return "operation timed out";
    case error::too_many_redirects: return "too many redirects";
    case error::body_too_large:     return "response body too large";
    case error::invalid_response:   return "invalid HTTP response";
    case error::connection_closed:  return "connection closed";
    case error::cancelled:          return "operation cancelled";
    case error::not_implemented:    return "not implemented";
    default:                        return "unknown error";
    }
}

BOOST_BURL_DECL
std::error_condition
error_category::default_error_condition(int ev) const noexcept
{
    return std::error_condition(ev, *this);
}

BOOST_BURL_DECL
std::error_category const&
burl_category() noexcept
{
    static error_category const cat{};
    return cat;
}

BOOST_BURL_DECL
http_error::http_error(
    unsigned short status_code,
    std::string reason,
    std::string url)
    : status_code_(status_code)
    , reason_(std::move(reason))
    , url_(std::move(url))
{
    what_ = std::to_string(status_code_) + " " + reason_ + ": " + url_;
}

} // namespace burl
} // namespace boost

#endif
