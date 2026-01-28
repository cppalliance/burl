//
// Copyright (c) 2025 Vinnie Falco (vinnie dot falco at gmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

#ifndef BOOST_BURL_AUTH_HPP
#define BOOST_BURL_AUTH_HPP

#include <boost/burl/fwd.hpp>

#include <memory>
#include <string>

namespace boost {
namespace http {
    class request;
}
}

namespace boost {
namespace burl {

//----------------------------------------------------------

/** Base class for HTTP authentication schemes.

    Derive from this class to implement custom authentication
    schemes. The apply() method is called before each request
    to add authentication headers.
*/
class auth_base
{
public:
    /** Virtual destructor.
    */
    virtual ~auth_base() = default;

    /** Apply authentication to a request.

        This method is called before sending each request.
        Implementations should add appropriate authentication
        headers to the request.

        @param req The request to authenticate
    */
    virtual void
    apply(http::request& req) const = 0;

    /** Clone this authentication object.

        @return A new instance with the same credentials
    */
    virtual std::unique_ptr<auth_base>
    clone() const = 0;
};

//----------------------------------------------------------

/** HTTP Basic authentication.

    Implements RFC 7617 HTTP Basic authentication scheme.
    Credentials are base64-encoded and sent in the
    Authorization header.

    @par Example
    @code
    burl::session s;
    s.set_auth(std::make_shared<burl::http_basic_auth>("user", "pass"));
    @endcode
*/
class http_basic_auth : public auth_base
{
    std::string username_;
    std::string password_;
    mutable std::string encoded_;

public:
    /** Constructor.

        @param username The username
        @param password The password
    */
    http_basic_auth(
        std::string username,
        std::string password);

    /** Apply Basic authentication to a request.

        Adds the Authorization header with base64-encoded
        credentials.

        @param req The request to authenticate
    */
    void
    apply(http::request& req) const override;

    /** Clone this authentication object.
    */
    std::unique_ptr<auth_base>
    clone() const override;
};

//----------------------------------------------------------

/** HTTP Digest authentication.

    Implements RFC 7616 HTTP Digest authentication scheme.
    This provides better security than Basic auth as the
    password is never sent over the wire.

    @note Digest auth requires a challenge from the server,
    so the first request may receive a 401 response.

    @par Example
    @code
    burl::session s;
    s.set_auth(std::make_shared<burl::http_digest_auth>("user", "pass"));
    @endcode
*/
class http_digest_auth : public auth_base
{
    std::string username_;
    std::string password_;

    // Server challenge parameters (set after 401 response)
    mutable std::string realm_;
    mutable std::string nonce_;
    mutable std::string opaque_;
    mutable std::string qop_;
    mutable std::string algorithm_;
    mutable unsigned nc_ = 0;

public:
    /** Constructor.

        @param username The username
        @param password The password
    */
    http_digest_auth(
        std::string username,
        std::string password);

    /** Apply Digest authentication to a request.

        If a challenge has been received, adds the Authorization
        header with the digest response. Otherwise, the first
        request will likely receive a 401 with a challenge.

        @param req The request to authenticate
    */
    void
    apply(http::request& req) const override;

    /** Clone this authentication object.
    */
    std::unique_ptr<auth_base>
    clone() const override;

    /** Process a 401 challenge response.

        Extracts the server's challenge parameters from the
        WWW-Authenticate header.

        @param www_authenticate The WWW-Authenticate header value
    */
    void
    process_challenge(std::string_view www_authenticate) const;
};

//----------------------------------------------------------

/** HTTP Bearer token authentication.

    Implements RFC 6750 Bearer Token authentication.
    Commonly used with OAuth 2.0.

    @par Example
    @code
    burl::session s;
    s.set_auth(std::make_shared<burl::http_bearer_auth>("your-token-here"));
    @endcode
*/
class http_bearer_auth : public auth_base
{
    std::string token_;

public:
    /** Constructor.

        @param token The bearer token
    */
    explicit
    http_bearer_auth(std::string token);

    /** Apply Bearer authentication to a request.

        Adds the Authorization header with the bearer token.

        @param req The request to authenticate
    */
    void
    apply(http::request& req) const override;

    /** Clone this authentication object.
    */
    std::unique_ptr<auth_base>
    clone() const override;
};

} // namespace burl
} // namespace boost

#endif
