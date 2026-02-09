//
// Copyright (c) 2025 Vinnie Falco (vinnie dot falco at gmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

#ifndef BOOST_BURL_COOKIES_HPP
#define BOOST_BURL_COOKIES_HPP

#include <boost/burl/fwd.hpp>
#include <boost/url/url_view.hpp>

#include <chrono>
#include <map>
#include <optional>
#include <string>
#include <vector>

namespace boost {
namespace burl {

//----------------------------------------------------------

/** An HTTP cookie.

    Represents a single cookie with all its attributes as
    defined in RFC 6265.
*/
struct cookie
{
    /// Cookie name
    std::string name;

    /// Cookie value
    std::string value;

    /// Domain the cookie is valid for
    std::string domain;

    /// Path the cookie is valid for
    std::string path = "/";

    /// Expiration time (nullopt = session cookie)
    std::optional<std::chrono::system_clock::time_point> expires;

    /// Whether cookie should only be sent over HTTPS
    bool secure = false;

    /// Whether cookie should not be accessible via JavaScript
    bool http_only = false;

    /// SameSite attribute
    enum class same_site_t { none, lax, strict };
    same_site_t same_site = same_site_t::lax;

    /** Check if the cookie has expired.

        @return true if the cookie has expired
    */
    BOOST_BURL_DECL
    bool
    is_expired() const noexcept;

    /** Check if the cookie matches a URL.

        @param url The URL to check against
        @return true if this cookie should be sent to the URL
    */
    BOOST_BURL_DECL
    bool
    matches(urls::url_view url) const;
};

//----------------------------------------------------------

/** A container for managing HTTP cookies.

    Implements cookie storage and retrieval as defined in
    RFC 6265. Automatically handles domain matching, path
    matching, expiration, and secure/http-only flags.

    @par Thread Safety
    Not thread-safe. Access must be externally synchronized.

    @par Example
    @code
    burl::session s;
    auto& jar = s.cookies();
    
    // Add a cookie manually
    jar.set(burl::cookie{
        .name = "session_id",
        .value = "abc123",
        .domain = "example.com"
    });
    
    // Get all cookies for a URL
    auto cookies = jar.get_cookies(url);
    @endcode
*/
class BOOST_BURL_DECL cookie_jar
{
    std::vector<cookie> cookies_;

public:
    /** Default constructor.

        Creates an empty cookie jar.
    */
    cookie_jar() = default;

    /** Add or update a cookie.

        If a cookie with the same name, domain, and path exists,
        it is replaced. Otherwise, the cookie is added.

        @param c The cookie to set
    */
    void
    set(cookie c);

    /** Add cookies from a Set-Cookie header.

        Parses the Set-Cookie header value and adds the cookie
        to the jar.

        @param set_cookie_header The Set-Cookie header value
        @param request_url The URL the response came from
    */
    void
    set_from_header(
        std::string_view set_cookie_header,
        urls::url_view request_url);

    /** Get cookies that should be sent to a URL.

        Returns all non-expired cookies that match the given URL
        based on domain, path, secure, and same-site rules.

        @param url The URL to get cookies for
        @return Vector of matching cookies
    */
    std::vector<cookie>
    get_cookies(urls::url_view url) const;

    /** Get the Cookie header value for a URL.

        Returns a formatted Cookie header value containing all
        cookies that should be sent to the URL.

        @param url The URL to get the header for
        @return The Cookie header value, or empty string if no cookies
    */
    std::string
    get_cookie_header(urls::url_view url) const;

    /** Remove a specific cookie.

        @param name Cookie name
        @param domain Cookie domain
        @param path Cookie path
    */
    void
    remove(
        std::string_view name,
        std::string_view domain,
        std::string_view path = "/");

    /** Remove all expired cookies.
    */
    void
    remove_expired();

    /** Remove all cookies.
    */
    void
    clear();

    /** Get the number of cookies.
    */
    std::size_t
    size() const noexcept
    {
        return cookies_.size();
    }

    /** Check if the jar is empty.
    */
    bool
    empty() const noexcept
    {
        return cookies_.empty();
    }

    /** Iterator access.
    */
    auto begin() const noexcept { return cookies_.begin(); }
    auto end() const noexcept { return cookies_.end(); }
};

} // namespace burl
} // namespace boost

#endif
