//
// Copyright (c) 2026 Mohammad Nejati
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

// Test that header file is self-contained.
#include <boost/burl/cookie_jar.hpp>

#include "test_suite.hpp"

#include <boost/url/url.hpp>

namespace boost
{
namespace burl
{

struct cookie_jar_test
{
    //
    // Adding, replacing, and header ordering
    //

    void
    testAddAndHeader()
    {
        cookie_jar jar;
        urls::url url("https://example.com/path");

        jar.add(url, parse_cookie("id=42").value());
        jar.add(url, parse_cookie("theme=dark").value());

        BOOST_TEST_EQ(jar.cookie_header(url), "id=42; theme=dark");
    }

    void
    testReplace()
    {
        cookie_jar jar;
        urls::url url("https://example.com/");

        jar.add(url, parse_cookie("k=old").value());
        jar.add(url, parse_cookie("k=new").value());
        BOOST_TEST_EQ(jar.cookie_header(url), "k=new");

        // A leading dot names the same cookie as the dotless form.
        jar.add(url, parse_cookie("d=old; Domain=.example.com").value());
        jar.add(url, parse_cookie("d=new; Domain=example.com").value());
        BOOST_TEST_EQ(
            jar.cookie_header(urls::url("https://example.com/")),
            "k=new; d=new");
    }

    void
    testOrdering()
    {
        // RFC 6265bis 5.8: cookies with longer paths come first.
        {
            cookie_jar jar;
            jar.add(
                urls::url("https://example.com/"),
                parse_cookie("a=1; Path=/").value());
            jar.add(
                urls::url("https://example.com/app/x"),
                parse_cookie("b=2; Path=/app").value());
            jar.add(
                urls::url("https://example.com/app/x"),
                parse_cookie("c=3; Path=/app/x").value());

            BOOST_TEST_EQ(
                jar.cookie_header(urls::url("https://example.com/app/x")),
                "c=3; b=2; a=1");
        }

        // Equal-length paths keep insertion (creation) order.
        {
            cookie_jar jar;
            urls::url url("https://example.com/");
            jar.add(url, parse_cookie("a=1").value());
            jar.add(url, parse_cookie("b=2").value());
            jar.add(url, parse_cookie("c=3").value());
            BOOST_TEST_EQ(jar.cookie_header(url), "a=1; b=2; c=3");
        }

        // RFC 6265bis 5.7: an updated cookie keeps its original position.
        {
            cookie_jar jar;
            urls::url url("https://example.com/");
            jar.add(url, parse_cookie("a=1").value());
            jar.add(url, parse_cookie("b=2").value());
            jar.add(url, parse_cookie("a=updated").value());
            BOOST_TEST_EQ(jar.cookie_header(url), "a=updated; b=2");
        }
    }

    //
    // Domain matching
    //

    void
    testDomainMismatch()
    {
        cookie_jar jar;
        urls::url url("https://example.com/");

        jar.add(url, parse_cookie("x=1; Domain=other.com").value());
        BOOST_TEST_EQ(jar.cookie_header(url), "");
    }

    void
    testTrailingDot()
    {
        // A trailing dot on the request host is normalized: a cookie set on
        // "example.com." is sent to "example.com" and vice versa.
        {
            cookie_jar jar;
            jar.add(
                urls::url("https://example.com./"),
                parse_cookie("a=1").value());
            BOOST_TEST_EQ(
                jar.cookie_header(urls::url("https://example.com/")), "a=1");
        }

        // The reverse direction normalizes too.
        {
            cookie_jar jar;
            jar.add(
                urls::url("https://example.com/"),
                parse_cookie("a=1").value());
            BOOST_TEST_EQ(
                jar.cookie_header(urls::url("https://example.com./")), "a=1");
        }

        // A Domain attribute with a trailing dot domain-matches the host.
        {
            cookie_jar jar;
            urls::url url("https://www.example.com/");
            jar.add(url, parse_cookie("a=1; Domain=example.com.").value());
            BOOST_TEST_EQ(jar.cookie_header(url), "a=1");
        }

        // CVE-2022-27779: a trailing dot must not let a cookie be set on a
        // bare TLD, with or without libpsl.
        {
            cookie_jar jar;
            urls::url url("https://example.com./");
            jar.add(url, parse_cookie("a=1; Domain=com.").value());
            BOOST_TEST_EQ(
                jar.cookie_header(urls::url("https://example.com/")), "");
        }
    }

    void
    testIPHost()
    {
        // A host-only cookie on an IPv4 literal is sent back to the same
        // address.
        {
            cookie_jar jar;
            urls::url url("http://192.168.0.1/");
            jar.add(url, parse_cookie("a=1").value());
            BOOST_TEST_EQ(jar.cookie_header(url), "a=1");
        }

        // RFC 6265bis 5.1.3: suffix matching does not apply to IP hosts, so a
        // cookie set on one address is not sent to a different address that
        // shares a textual suffix.
        {
            cookie_jar jar;
            jar.add(
                urls::url("http://1.2.3.4/"), parse_cookie("a=1").value());
            BOOST_TEST_EQ(
                jar.cookie_header(urls::url("http://9.9.3.4/")), "");
        }

        // A Domain attribute that is a textual suffix of the IP host must be
        // rejected rather than accepted as a tailmatch cookie.
        {
            cookie_jar jar;
            urls::url url("http://1.2.3.4/");
            jar.add(url, parse_cookie("a=1; Domain=3.4").value());
            BOOST_TEST_EQ(jar.cookie_header(url), "");
            // and it must never leak to a sibling address.
            BOOST_TEST_EQ(
                jar.cookie_header(urls::url("http://9.9.3.4/")), "");
        }

        // A Domain attribute equal to the IP host is accepted but treated as
        // host-only: sent to that exact address, never to a suffix sibling.
        {
            cookie_jar jar;
            urls::url url("http://1.2.3.4/");
            jar.add(url, parse_cookie("a=1; Domain=1.2.3.4").value());
            BOOST_TEST_EQ(jar.cookie_header(url), "a=1");
            BOOST_TEST_EQ(
                jar.cookie_header(urls::url("http://9.1.2.3.4/")), "");
        }

        // Defense in depth: a Netscape file that keys a tailmatch cookie to an
        // IP suffix must not match a longer IP address.
        {
            cookie_jar jar;
            BOOST_TEST(
                jar.from_netscape(
                    "# Netscape HTTP Cookie File\n\n"
                    "0.1\tTRUE\t/\tFALSE\t0\ta\t1\n").has_value());
            BOOST_TEST_EQ(
                jar.cookie_header(urls::url("http://127.0.0.1/")), "");
        }
    }

    void
    testIPv6()
    {
        // An IPv6 literal host is keyed without its brackets.
        {
            cookie_jar jar;
            jar.add(
                urls::url("http://[::1]/"), parse_cookie("a=1").value());
            BOOST_TEST_EQ(
                jar.cookie_header(urls::url("http://[::1]/")), "a=1");
        }

        // The exported jar uses the bracket-free address and re-imports
        // to the same key.
        {
            cookie_jar jar;
            jar.add(
                urls::url("http://[::1]/"), parse_cookie("a=1").value());

            const auto s = jar.to_netscape();
            BOOST_TEST(s.find("[") == std::string::npos);
            BOOST_TEST(s.find("::1\t") != std::string::npos);

            cookie_jar in;
            BOOST_TEST(in.from_netscape(s).has_value());
            BOOST_TEST_EQ(
                in.cookie_header(urls::url("http://[::1]/")), "a=1");
        }
    }

    //
    // Public suffix
    //

    void
    testPublicSuffix()
    {
        // A registrable domain is accepted.
        {
            cookie_jar jar;
            urls::url url("https://www.example.com/");
            jar.add(url, parse_cookie("a=1; Domain=example.com").value());
            BOOST_TEST_EQ(jar.cookie_header(url), "a=1");
        }

        // A bare TLD is rejected, by libpsl and the no-dot fallback alike.
        {
            cookie_jar jar;
            urls::url url("https://example.com/");
            jar.add(url, parse_cookie("a=1; Domain=com").value());
            BOOST_TEST_EQ(jar.cookie_header(url), "");
        }

        // RFC 6265bis 5.6.3: a leading dot is ignored — accepted on a domain,
        // rejected on a bare TLD.
        {
            cookie_jar jar;
            urls::url url("https://www.example.com/");
            jar.add(url, parse_cookie("a=1; Domain=.example.com").value());
            BOOST_TEST_EQ(jar.cookie_header(url), "a=1");
        }
        {
            cookie_jar jar;
            urls::url url("https://example.com/");
            jar.add(url, parse_cookie("a=1; Domain=.com").value());
            BOOST_TEST_EQ(jar.cookie_header(url), "");
        }

        // A multi-label public suffix is rejected only with libpsl; the
        // no-dot fallback can't tell and accepts it.
        {
            cookie_jar jar;
            urls::url url("https://example.co.uk/");
            jar.add(url, parse_cookie("a=1; Domain=co.uk").value());
            if(cookie_jar::public_suffix_supported())
                BOOST_TEST_EQ(jar.cookie_header(url), "");
            else
                BOOST_TEST_EQ(jar.cookie_header(url), "a=1");
        }

        // The no-dot fallback special-cases "localhost" as a non-public-suffix
        // so a Domain=localhost cookie tailmatches subdomains during local dev.
        if(!cookie_jar::public_suffix_supported())
        {
            cookie_jar jar;
            urls::url url("http://localhost/");
            jar.add(url, parse_cookie("a=1; Domain=localhost").value());
            BOOST_TEST_EQ(
                jar.cookie_header(urls::url("http://sub.localhost/")), "a=1");
        }
    }

    void
    testPublicSuffixHostOnly()
    {
        // RFC 6265bis 5.7 step 9: a public-suffix Domain equal to the host is
        // accepted as host-only (a bare label is a public suffix either way).
        {
            cookie_jar jar;
            urls::url url("http://intranet/");
            jar.add(url, parse_cookie("a=1; Domain=intranet").value());
            BOOST_TEST_EQ(jar.cookie_header(url), "a=1");

            // host-only: it must not leak to a subdomain.
            BOOST_TEST_EQ(
                jar.cookie_header(urls::url("http://host.intranet/")), "");
        }

        // A public-suffix Domain that differs from the host is still rejected.
        {
            cookie_jar jar;
            urls::url url("https://example.com/");
            jar.add(url, parse_cookie("a=1; Domain=com").value());
            BOOST_TEST_EQ(jar.cookie_header(url), "");
        }
    }

    //
    // Path matching
    //

    void
    testPathMatch()
    {
        cookie_jar jar;
        jar.add(
            urls::url("https://example.com/app"),
            parse_cookie("k=1; Path=/app").value());

        // RFC 6265bis 5.1.4: the cookie path is a prefix ending on a boundary.
        BOOST_TEST_EQ(jar.cookie_header(urls::url("https://example.com/app")), "k=1");
        BOOST_TEST_EQ(
            jar.cookie_header(urls::url("https://example.com/app/x")), "k=1");

        // A prefix that is not on a path boundary does not match.
        BOOST_TEST_EQ(
            jar.cookie_header(urls::url("https://example.com/application")), "");

        // RFC 6265bis 5.1.4: a no-path request defaults to "/", not matching /app.
        BOOST_TEST_EQ(
            jar.cookie_header(urls::url("https://example.com")), "");

        // RFC 6265bis 5.1.4: the defaulted "/" does match a root cookie.
        cookie_jar root;
        root.add(
            urls::url("https://example.com/"), parse_cookie("a=1").value());
        BOOST_TEST_EQ(
            root.cookie_header(urls::url("https://example.com")), "a=1");
    }

    void
    testDefaultPath()
    {
        // RFC 6265bis 5.1.4: with no Path attribute, the default path is the
        // request's directory (everything up to the last '/').
        cookie_jar jar;
        jar.add("https://example.com/app/x", parse_cookie("a=1").value());
        BOOST_TEST_EQ(jar.cookie_header("https://example.com/app/x"), "a=1");
        BOOST_TEST_EQ(jar.cookie_header("https://example.com/app/y"), "a=1");
        BOOST_TEST_EQ(jar.cookie_header("https://example.com/app"), "a=1");
        BOOST_TEST_EQ(jar.cookie_header("https://example.com/"), "");
    }

    //
    // Secure context
    //

    void
    testSecure()
    {
        cookie_jar jar;
        urls::url https("https://example.com/");
        jar.add(https, parse_cookie("s=1; Secure").value());

        BOOST_TEST_EQ(jar.cookie_header(https), "s=1");

        urls::url http("http://example.com/");
        BOOST_TEST_EQ(jar.cookie_header(http), "");
    }

    void
    testLocalhostSecure()
    {
        // localhost is a secure context, so Secure cookies are accepted and
        // sent over plain http (matches curl/browsers).
        {
            cookie_jar jar;
            urls::url url("http://localhost/");
            jar.add(url, parse_cookie("s=1; Secure").value());
            BOOST_TEST_EQ(jar.cookie_header(url), "s=1");
        }

        // The same holds for loopback addresses.
        {
            cookie_jar jar;
            urls::url url("http://127.0.0.1/");
            jar.add(url, parse_cookie("s=1; Secure").value());
            BOOST_TEST_EQ(jar.cookie_header(url), "s=1");
        }
        {
            cookie_jar jar;
            urls::url url("http://127.0.0.255/");
            jar.add(url, parse_cookie("s=1; Secure").value());
            BOOST_TEST_EQ(jar.cookie_header(url), "s=1");
        }
        {
            cookie_jar jar;
            urls::url url("http://[::1]/");
            jar.add(url, parse_cookie("s=1; Secure").value());
            BOOST_TEST_EQ(jar.cookie_header(url), "s=1");
        }

        // "localhost." is not a secure context: fail closed rather than
        // normalize the trailing dot (matches curl's literal check).
        {
            cookie_jar jar;
            urls::url url("http://localhost./");
            jar.add(url, parse_cookie("s=1; Secure").value());
            BOOST_TEST_EQ(jar.cookie_header(url), "");
        }

        // A non-loopback host over http is not secure, so the cookie is
        // rejected.
        {
            cookie_jar jar;
            urls::url url("http://example.com/");
            jar.add(url, parse_cookie("s=1; Secure").value());
            BOOST_TEST_EQ(jar.cookie_header(url), "");
        }

        // An ipvfuture host over http is not a recognized secure context, so
        // the cookie is rejected (fail closed).
        {
            cookie_jar jar;
            urls::url url("http://[v1.fe80::a]/");
            jar.add(url, parse_cookie("s=1; Secure").value());
            BOOST_TEST_EQ(jar.cookie_header(url), "");
        }

        // A host-less url over http is likewise not secure.
        {
            cookie_jar jar;
            urls::url url("http:/path");
            jar.add(url, parse_cookie("s=1; Secure").value());
            BOOST_TEST_EQ(jar.cookie_header(url), "");
        }
    }

    void
    testLeaveSecureAlone()
    {
        // RFC 6265bis: a cookie received over http must not evict or
        // overwrite an existing Secure cookie of the same name.
        {
            cookie_jar jar;
            jar.add(
                urls::url("https://example.com/"),
                parse_cookie("k=secure; Secure").value());

            jar.add(
                urls::url("http://example.com/"),
                parse_cookie("k=evil").value());
            BOOST_TEST_EQ(
                jar.cookie_header(urls::url("https://example.com/")), "k=secure");
        }

        // The protection covers overlapping domains and paths, not just an
        // exact name/domain/path triple.
        {
            cookie_jar jar;
            jar.add(
                urls::url("https://example.com/"),
                parse_cookie("k=secure; Secure; Domain=example.com; Path=/")
                    .value());
            jar.add(
                urls::url("http://www.example.com/app"),
                parse_cookie("k=evil").value());
            BOOST_TEST_EQ(
                jar.cookie_header(urls::url("https://example.com/")), "k=secure");
        }

        // An https response may still overwrite a Secure cookie.
        {
            cookie_jar jar;
            jar.add(
                urls::url("https://example.com/"),
                parse_cookie("k=old; Secure").value());
            jar.add(
                urls::url("https://example.com/"),
                parse_cookie("k=new; Secure").value());
            BOOST_TEST_EQ(
                jar.cookie_header(urls::url("https://example.com/")), "k=new");
        }

        // A non-Secure cookie is not protected and may be replaced over http.
        {
            cookie_jar jar;
            jar.add(
                urls::url("http://example.com/"),
                parse_cookie("k=old").value());
            jar.add(
                urls::url("http://example.com/"),
                parse_cookie("k=new").value());
            BOOST_TEST_EQ(
                jar.cookie_header(urls::url("http://example.com/")), "k=new");
        }
    }

    //
    // Expiry and clearing
    //

    void
    testExpiry()
    {
        urls::url url("https://example.com/");

        // An already-expired cookie with no stored counterpart is dropped.
        {
            cookie_jar jar;
            jar.add(url, parse_cookie("a=1; Max-Age=0").value());
            BOOST_TEST_EQ(jar.cookie_header(url), "");
        }

        // RFC 6265bis: a server deletes a stored cookie by re-sending it
        // already expired, which erases the existing entry.
        {
            cookie_jar jar;
            jar.add(url, parse_cookie("a=1").value());
            BOOST_TEST_EQ(jar.cookie_header(url), "a=1");
            jar.add(url, parse_cookie("a=2; Max-Age=0").value());
            BOOST_TEST_EQ(jar.cookie_header(url), "");
        }
    }

    void
    testLazyExpiry()
    {
        // epoch 1 is 1970 — already past. from_netscape stores it directly,
        // bypassing add()'s expiry check, so a stale entry lands in the jar.
        cookie_jar jar;
        BOOST_TEST(
            jar.from_netscape(
                "# Netscape HTTP Cookie File\n\n"
                "example.com\tFALSE\t/\tFALSE\t1\ta\t1\n").has_value());

        // Querying the jar purges the expired entry and returns nothing.
        BOOST_TEST_EQ(
            jar.cookie_header(urls::url("http://example.com/")), "");

        // It was erased, not merely filtered: it no longer appears in an
        // export.
        BOOST_TEST(jar.to_netscape().find("example.com") == std::string::npos);
    }

    void
    testClearSessionCookies()
    {
        cookie_jar jar;
        urls::url url("https://example.com/");

        // A session cookie has no expiry; a persistent one does.
        jar.add(url, parse_cookie("s=1").value());
        jar.add(url, parse_cookie("p=2; Max-Age=3600").value());

        jar.clear_session_cookies();

        BOOST_TEST_EQ(jar.cookie_header(url), "p=2");
    }

    void
    testClear()
    {
        cookie_jar jar;
        urls::url url("https://example.com/");
        jar.add(url, parse_cookie("a=1").value());
        jar.add(url, parse_cookie("b=2").value());

        jar.clear();
        BOOST_TEST_EQ(jar.cookie_header(url), "");
    }

    //
    // Netscape import/export
    //

    void
    testNetscapeRoundTrip()
    {
        cookie_jar jar;
        urls::url url("https://example.com/path");
        jar.add(url, parse_cookie("id=42; Max-Age=3600; HttpOnly").value());
        jar.add(url, parse_cookie("theme=dark; Max-Age=3600").value());

        // An HttpOnly cookie serializes with the "#HttpOnly_" line prefix.
        const auto netscape = jar.to_netscape();
        BOOST_TEST(netscape.find("#HttpOnly_") != std::string::npos);

        cookie_jar jar2;
        BOOST_TEST(jar2.from_netscape(netscape).has_value());

        BOOST_TEST_EQ(jar2.cookie_header(url), jar.cookie_header(url));
        // A second export must reproduce the original, proving the HttpOnly
        // flag (which the cookie header omits) survived the round-trip.
        BOOST_TEST_EQ(jar2.to_netscape(), netscape);
    }

    void
    testNetscapeValueless()
    {
        // A value-less cookie exports with an empty value field and must
        // re-import without error.
        cookie_jar jar;
        jar.add(
            urls::url("http://example.com/"), parse_cookie("flag=").value());

        cookie_jar in;
        BOOST_TEST(in.from_netscape(jar.to_netscape()).has_value());
        BOOST_TEST_EQ(
            in.cookie_header(urls::url("http://example.com/")), "flag=");
    }

    void
    testNetscapeLeadingDot()
    {
        // A leading-dot domain imported from a file must still match the
        // host and its subdomains.
        cookie_jar jar;
        BOOST_TEST(
            jar.from_netscape(
                "# Netscape HTTP Cookie File\n\n"
                ".example.com\tTRUE\t/\tFALSE\t0\ta\t1\n").has_value());
        BOOST_TEST_EQ(
            jar.cookie_header(urls::url("http://www.example.com/")), "a=1");
        BOOST_TEST_EQ(
            jar.cookie_header(urls::url("http://example.com/")), "a=1");

        // The leading dot marks tailmatch even when the flag column is FALSE,
        // and is stripped so it survives an export round-trip.
        cookie_jar dotted;
        BOOST_TEST(
            dotted.from_netscape(
                "# Netscape HTTP Cookie File\n\n"
                ".example.com\tFALSE\t/\tFALSE\t0\tb\t2\n").has_value());
        BOOST_TEST_EQ(
            dotted.cookie_header(urls::url("http://sub.example.com/")), "b=2");

        cookie_jar in;
        BOOST_TEST(in.from_netscape(dotted.to_netscape()).has_value());
        BOOST_TEST_EQ(
            in.cookie_header(urls::url("http://sub.example.com/")), "b=2");
    }

    void
    testNetscapeCRLF()
    {
        // CRLF line endings are tolerated: the trailing '\r' is stripped so
        // the value field parses as "1", not "1\r".
        cookie_jar jar;
        BOOST_TEST(
            jar.from_netscape(
                "# Netscape HTTP Cookie File\r\n\r\n"
                "example.com\tFALSE\t/\tFALSE\t0\ta\t1\r\n").has_value());
        BOOST_TEST_EQ(
            jar.cookie_header(urls::url("http://example.com/")), "a=1");
    }

    void
    testNetscapeMalformed()
    {
        // A line that does not match the fixed tab-delimited shape fails to
        // parse and the error is propagated out of from_netscape.
        cookie_jar jar;
        BOOST_TEST(
            jar.from_netscape(
                "# Netscape HTTP Cookie File\n\n"
                "example.com\tTRUE\t/\n").has_error());
    }

    void
    run()
    {
        // Adding, replacing, and header ordering
        testAddAndHeader();
        testReplace();
        testOrdering();

        // Domain matching
        testDomainMismatch();
        testTrailingDot();
        testIPHost();
        testIPv6();

        // Public suffix
        testPublicSuffix();
        testPublicSuffixHostOnly();

        // Path matching
        testPathMatch();
        testDefaultPath();

        // Secure context
        testSecure();
        testLocalhostSecure();
        testLeaveSecureAlone();

        // Expiry and clearing
        testExpiry();
        testLazyExpiry();
        testClearSessionCookies();
        testClear();

        // Netscape import/export
        testNetscapeRoundTrip();
        testNetscapeValueless();
        testNetscapeLeadingDot();
        testNetscapeCRLF();
        testNetscapeMalformed();
    }
};

TEST_SUITE(cookie_jar_test, "boost.burl.cookie_jar");

} // namespace burl
} // namespace boost
