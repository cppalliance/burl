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

#include <string>

namespace boost
{
namespace burl
{

struct cookie_jar_test
{
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
    testDomainMismatch()
    {
        cookie_jar jar;
        urls::url url("https://example.com/");

        jar.add(url, parse_cookie("x=1; Domain=other.com").value());
        BOOST_TEST_EQ(jar.cookie_header(url), "");
    }

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

        // RFC 6265 5.2.3: a leading dot is ignored — accepted on a domain,
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
    testPathMatch()
    {
        cookie_jar jar;
        jar.add(
            urls::url("https://example.com/app"),
            parse_cookie("k=1; Path=/app").value());

        // RFC 6265 5.1.4: the cookie path is a prefix ending on a boundary.
        BOOST_TEST_EQ(jar.cookie_header(urls::url("https://example.com/app")), "k=1");
        BOOST_TEST_EQ(
            jar.cookie_header(urls::url("https://example.com/app/x")), "k=1");

        // A prefix that is not on a path boundary does not match.
        BOOST_TEST_EQ(
            jar.cookie_header(urls::url("https://example.com/application")), "");

        // RFC 6265 5.1.4: a no-path request defaults to "/", not matching /app.
        BOOST_TEST_EQ(
            jar.cookie_header(urls::url("https://example.com")), "");

        // RFC 6265 5.1.4: the defaulted "/" does match a root cookie.
        cookie_jar root;
        root.add(
            urls::url("https://example.com/"), parse_cookie("a=1").value());
        BOOST_TEST_EQ(
            root.cookie_header(urls::url("https://example.com")), "a=1");
    }

    void
    testOrdering()
    {
        // RFC 6265 5.4: cookies with longer paths come first.
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

        // RFC 6265 5.3: an updated cookie keeps its original position.
        {
            cookie_jar jar;
            urls::url url("https://example.com/");
            jar.add(url, parse_cookie("a=1").value());
            jar.add(url, parse_cookie("b=2").value());
            jar.add(url, parse_cookie("a=updated").value());
            BOOST_TEST_EQ(jar.cookie_header(url), "a=updated; b=2");
        }
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

        // RFC 6265 5.1.3: suffix matching does not apply to IP hosts, so a
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
    }

    void
    testPublicSuffixHostOnly()
    {
        // RFC 6265 5.3 step 5: a public-suffix Domain equal to the host is
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
    testNetscapeRoundTrip()
    {
        cookie_jar jar;
        urls::url url("https://example.com/path");
        jar.add(url, parse_cookie("id=42; Max-Age=3600").value());
        jar.add(url, parse_cookie("theme=dark; Max-Age=3600").value());

        cookie_jar jar2;
        BOOST_TEST(jar2.from_netscape(jar.to_netscape()).has_value());

        BOOST_TEST_EQ(jar2.cookie_header(url), jar.cookie_header(url));
    }

    void
    run()
    {
        testAddAndHeader();
        testSecure();
        testDomainMismatch();
        testPublicSuffix();
        testPublicSuffixHostOnly();
        testReplace();
        testPathMatch();
        testOrdering();
        testLocalhostSecure();
        testTrailingDot();
        testIPv6();
        testIPHost();
        testNetscapeValueless();
        testNetscapeLeadingDot();
        testLeaveSecureAlone();
        testClear();
        testClearSessionCookies();
        testNetscapeRoundTrip();
    }
};

TEST_SUITE(cookie_jar_test, "boost.burl.cookie_jar");

} // namespace burl
} // namespace boost
