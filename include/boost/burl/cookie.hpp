//
// Copyright (c) 2026 Mohammad Nejati
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/beast2
//

#ifndef BOOST_BURL_COOKIE_HPP
#define BOOST_BURL_COOKIE_HPP

#include <boost/burl/detail/config.hpp>

#include <boost/url/url_view.hpp>

#include <chrono>
#include <optional>
#include <string>

namespace boost
{
namespace burl
{

/** An HTTP cookie.

    Objects of this type represent a cookie as
    defined in RFC 6265, with members corresponding
    to the attributes of a `Set-Cookie` header.
    They are produced by @ref parse_cookie and
    stored in a @ref cookie_jar.

    @par Specification
    @li <a href="https://datatracker.ietf.org/doc/html/rfc6265"
        >HTTP State Management Mechanism (rfc6265)</a>

    @see
        @ref parse_cookie,
        @ref cookie_jar.
*/
struct cookie
{
    /** Values for the `SameSite` attribute.
     */
    enum same_site_t
    {
        /// The cookie is only sent for same-site requests.
        strict,

        /// The cookie is also sent when navigating to the origin site.
        lax,

        /// The cookie is sent for both same-site and cross-site requests.
        none
    };

    /** The name of the cookie.
     */
    std::string name;

    /** The value of the cookie, if present.
     */
    std::optional<std::string> value;

    /** The expiry time of the cookie, if present.

        Derived from the `Expires` or `Max-Age`
        attribute. An empty optional indicates a
        session cookie.
    */
    std::optional<std::chrono::system_clock::time_point> expires;

    /** The value of the `Domain` attribute, if present.

        @ref cookie_jar::add normalizes this value,
        and fills it in from the request URL when
        the attribute is absent.
    */
    std::optional<std::string> domain;

    /** The value of the `Path` attribute, if present.

        @ref cookie_jar::add computes the default
        path from the request URL when the attribute
        is absent.
    */
    std::optional<std::string> path;

    /** The value of the `SameSite` attribute, if present.
     */
    std::optional<same_site_t> same_site;

    /** Whether the `Partitioned` attribute is present.
     */
    bool partitioned = false;

    /** Whether the `Secure` attribute is present.

        Secure cookies are only stored for, and sent
        over, secure contexts: `https`, or `localhost`
        and loopback addresses.
    */
    bool secure = false;

    /** Whether the `HttpOnly` attribute is present.
     */
    bool http_only = false;

    /** Whether domain matching uses suffix matching.

        Set by @ref cookie_jar::add when the cookie
        carried a `Domain` attribute; such cookies
        match the domain and its subdomains. Cookies
        without a `Domain` attribute match the
        request host exactly.
    */
    bool tailmatch = false;
};

/** Parse a `Set-Cookie` field value.

    This function parses a string in the
    set-cookie-string grammar and returns a cookie
    upon success, otherwise an error. The recognized
    attributes are `Expires`, `Max-Age`, `Domain`,
    `Path`, `SameSite`, `Partitioned`, `Secure`, and
    `HttpOnly`; unknown attributes are ignored.
    Cookies violating the `__Secure-` or `__Host-`
    name prefix requirements are rejected.

    @par Example
    @code
    system::result<cookie> rc =
        parse_cookie( "id=a3fWa; Max-Age=2592000; Secure" );
    @endcode

    @par BNF
    @code
    set-cookie-string = cookie-pair *( ";" SP cookie-av )

    cookie-pair       = cookie-name "=" cookie-value
    @endcode

    @par Specification
    @li <a href="https://datatracker.ietf.org/doc/html/rfc6265#section-5.2"
        >5.2. The Set-Cookie Header (rfc6265)</a>

    @param sv The string to parse.

    @return The parsed cookie upon success,
    otherwise an error.
*/
BOOST_BURL_DECL
system::result<cookie>
parse_cookie(std::string_view sv);

} // namespace burl
} // namespace boost

#endif
