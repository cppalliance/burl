//
// Copyright (c) 2026 Mohammad Nejati
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/beast2
//

#ifndef BOOST_BURL_COOKIE_JAR_HPP
#define BOOST_BURL_COOKIE_JAR_HPP

#include <boost/burl/cookie.hpp>
#include <boost/burl/detail/config.hpp>

#include <boost/url/url_view.hpp>

#include <list>
#include <string>

namespace boost
{
namespace burl
{

/** A container of HTTP cookies.

    This container stores cookies received in
    responses and produces the `Cookie` header
    value for requests, applying the storage and
    matching rules of RFC 6265. A @ref client with
    @ref client::config::cookies enabled maintains
    its cookie jar automatically.

    The @ref to_netscape and @ref from_netscape
    members serialize cookies in the Netscape cookie
    file format, allowing the jar to be persisted
    between sessions.

    @par Example
    @code
    burl::client::config cfg;
    cfg.cookies = true;

    burl::client c(co_await capy::this_coro::executor, tls_ctx, cfg);

    auto r = co_await c.get("https://example.com/login").send();

    // Print the stored cookies in Netscape format
    std::cout << c.cookie_jar().to_netscape();
    @endcode

    @see
        @ref client::cookie_jar,
        @ref cookie,
        @ref parse_cookie.
*/
class cookie_jar
{
    std::list<cookie> cookies_;

public:
    /** Return whether public suffix checking is supported.

        When supported, @ref add rejects cookies set
        for a public suffix (e.g. `"com"`, `"co.uk"`)
        using the Public Suffix List. Otherwise a weak
        fallback is used that only rejects cookies set
        on bare top-level domains.

        This is a compile-time property of the library
        determined by whether it was built with libpsl.

        @return `true` if public suffix checking is
        supported.
    */
    BOOST_BURL_DECL
    static bool
    public_suffix_supported() noexcept;

    /** Add a cookie received from a URL.

        This function performs the storage checks of
        RFC 6265 against the URL the cookie was
        received from:

        @li When the cookie carries a `Domain`
            attribute, the attribute is normalized
            and the request host must domain-match
            it, otherwise the cookie is ignored.
            When the attribute is absent, the domain
            is set to the request host and matching
            is exact.
        @li When the cookie carries no `Path`
            attribute, the default path is computed
            from the URL.
        @li Secure cookies received outside a secure
            context are ignored. As well as `https`,
            `localhost` and loopback addresses are
            treated as secure contexts.
        @li A cookie received outside a secure context
            is ignored when it would evict or overwrite
            an existing `Secure` cookie of the same
            name whose domain and path overlap ("Leave
            Secure Cookies Alone").

        An existing cookie with the same name,
        domain, and path is replaced. A cookie which
        is already expired removes the existing one
        without being stored, which allows servers
        to delete cookies.

        @param url The URL the cookie was received
        from.

        @param c The cookie to add.
    */
    BOOST_BURL_DECL
    void
    add(const urls::url_view& url, cookie c);

    /** Return the `Cookie` field value for a request.

        Stored cookies are matched against the URL
        by domain, path, and the `Secure` attribute,
        and returned as `name=value` pairs separated
        by `"; "`, ordered with longer paths first
        (RFC 6265 5.4). Expired cookies encountered
        during matching are removed from the jar.

        @param url The URL of the request.

        @return The field value, or an empty string
        when no cookies match.
    */
    BOOST_BURL_DECL
    std::string
    cookie_header(const urls::url_view& url);

    /** Remove all cookies.
     */
    BOOST_BURL_DECL
    void
    clear();

    /** Remove all session cookies.

        Session cookies are those without an expiry
        time.
    */
    BOOST_BURL_DECL
    void
    clear_session_cookies();

    /** Return the jar in the Netscape cookie file format.

        @return The serialized cookies.
    */
    BOOST_BURL_DECL
    std::string
    to_netscape() const;

    /** Add cookies from the Netscape cookie file format.

        The cookies are read from `sv` and added to
        the jar. Empty lines and comment lines are
        skipped, except those carrying the
        `#HttpOnly_` prefix.

        @param sv The serialized cookies to parse.

        @return Nothing on success, otherwise an
        error if the input contains a malformed line.
    */
    BOOST_BURL_DECL
    system::result<void>
    from_netscape(std::string_view sv);
};

} // namespace burl
} // namespace boost

#endif
