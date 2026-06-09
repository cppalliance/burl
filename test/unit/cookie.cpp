//
// Copyright (c) 2026 Mohammad Nejati
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

// Test that header file is self-contained.
#include <boost/burl/cookie.hpp>

#include "test_suite.hpp"

#include <boost/url/url.hpp>

#include <sstream>
#include <string>

namespace boost
{
namespace burl
{

struct cookie_test
{
    //----------------------------------------------------------
    // parse_cookie
    //----------------------------------------------------------

    void
    testParseBasic()
    {
        auto rc = parse_cookie("id=a3fWa");
        BOOST_TEST(rc.has_value());
        BOOST_TEST_EQ(rc->name, "id");
        BOOST_TEST(rc->value.has_value());
        BOOST_TEST_EQ(rc->value.value(), "a3fWa");
        BOOST_TEST(!rc->secure);
        BOOST_TEST(!rc->http_only);
        BOOST_TEST(!rc->expires.has_value());
        BOOST_TEST(!rc->domain.has_value());
        BOOST_TEST(!rc->path.has_value());
    }

    void
    testParseAttributes()
    {
        auto rc = parse_cookie(
            "sid=xyz; Domain=Example.com; Path=/app; Secure; HttpOnly");
        BOOST_TEST(rc.has_value());
        BOOST_TEST_EQ(rc->name, "sid");
        BOOST_TEST_EQ(rc->value.value(), "xyz");
        BOOST_TEST(rc->domain.has_value());
        BOOST_TEST_EQ(rc->domain.value(), "Example.com");
        BOOST_TEST(rc->path.has_value());
        BOOST_TEST_EQ(rc->path.value(), "/app");
        BOOST_TEST(rc->secure);
        BOOST_TEST(rc->http_only);
    }

    void
    testParseMaxAge()
    {
        // Max-Age yields an expiry time.
        auto rc = parse_cookie("a=b; Max-Age=3600");
        BOOST_TEST(rc.has_value());
        BOOST_TEST(rc->expires.has_value());
    }

    void
    testParseSameSite()
    {
        BOOST_TEST(
            parse_cookie("a=b; SameSite=Strict")->same_site ==
            cookie::same_site_t::strict);
        BOOST_TEST(
            parse_cookie("a=b; SameSite=Lax")->same_site ==
            cookie::same_site_t::lax);
        BOOST_TEST(
            parse_cookie("a=b; SameSite=None")->same_site ==
            cookie::same_site_t::none);

        // An unrecognized SameSite value is rejected.
        BOOST_TEST(parse_cookie("a=b; SameSite=Bogus").has_error());
    }

    void
    testParseValueless()
    {
        // A cookie with an empty value parses with no value.
        auto rc = parse_cookie("flag=");
        BOOST_TEST(rc.has_value());
        BOOST_TEST_EQ(rc->name, "flag");
        BOOST_TEST(!rc->value.has_value());
    }

    void
    testParseInvalid()
    {
        BOOST_TEST(parse_cookie("").has_error());
        BOOST_TEST(parse_cookie("noequalsign").has_error());
    }

    void
    testNamePrefixes()
    {
        // "__Secure-" requires the Secure attribute.
        BOOST_TEST(parse_cookie("__Secure-x=1").has_error());
        BOOST_TEST(parse_cookie("__Secure-x=1; Secure").has_value());

        // "__Host-" requires Secure, Path=/, and no Domain.
        BOOST_TEST(parse_cookie("__Host-x=1; Secure; Path=/").has_value());
        BOOST_TEST(parse_cookie("__Host-x=1; Secure").has_error());
        BOOST_TEST(parse_cookie("__Host-x=1; Secure; Path=/app").has_error());
        BOOST_TEST(
            parse_cookie("__Host-x=1; Secure; Path=/; Domain=example.com")
                .has_error());
    }

    //----------------------------------------------------------
    // cookie_jar
    //----------------------------------------------------------

    void
    testJarAddAndHeader()
    {
        cookie_jar jar;
        urls::url url("https://example.com/path");

        jar.add(url, parse_cookie("id=42").value());
        jar.add(url, parse_cookie("theme=dark").value());

        // Both cookies match the request URL; they are returned in insertion
        // order, separated by "; ".
        BOOST_TEST_EQ(jar.cookie_header(url), "id=42; theme=dark");
    }

    void
    testJarSecure()
    {
        cookie_jar jar;
        urls::url https("https://example.com/");
        jar.add(https, parse_cookie("s=1; Secure").value());

        // A Secure cookie is sent over https...
        BOOST_TEST_EQ(jar.cookie_header(https), "s=1");

        // ...but not over http.
        urls::url http("http://example.com/");
        BOOST_TEST_EQ(jar.cookie_header(http), "");
    }

    void
    testJarDomainMismatch()
    {
        cookie_jar jar;
        urls::url url("https://example.com/");

        // A Domain attribute the request host does not domain-match is
        // rejected, so nothing is stored.
        jar.add(url, parse_cookie("x=1; Domain=other.com").value());
        BOOST_TEST_EQ(jar.cookie_header(url), "");
    }

    void
    testJarPublicSuffix()
    {
        // A cookie set on a registrable domain is accepted regardless of
        // whether public suffix checking is supported.
        {
            cookie_jar jar;
            urls::url url("https://www.example.com/");
            jar.add(url, parse_cookie("a=1; Domain=example.com").value());
            BOOST_TEST_EQ(jar.cookie_header(url), "a=1");
        }

        // A cookie set on a bare top-level domain is always rejected: libpsl
        // knows "com" is a public suffix, and the weak fallback rejects it for
        // having no dot.
        {
            cookie_jar jar;
            urls::url url("https://example.com/");
            jar.add(url, parse_cookie("a=1; Domain=com").value());
            BOOST_TEST_EQ(jar.cookie_header(url), "");
        }

        // A cookie set on a multi-label public suffix (e.g. "co.uk") is only
        // rejected when public suffix checking is supported. The weak fallback
        // accepts it because it contains a non-trailing dot.
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
    testJarReplace()
    {
        cookie_jar jar;
        urls::url url("https://example.com/");

        // A cookie with the same name/domain/path replaces the existing one.
        jar.add(url, parse_cookie("k=old").value());
        jar.add(url, parse_cookie("k=new").value());
        BOOST_TEST_EQ(jar.cookie_header(url), "k=new");
    }

    void
    testJarClear()
    {
        cookie_jar jar;
        urls::url url("https://example.com/");
        jar.add(url, parse_cookie("a=1").value());
        jar.add(url, parse_cookie("b=2").value());

        jar.clear();
        BOOST_TEST_EQ(jar.cookie_header(url), "");
    }

    void
    testNetscapeRoundTrip()
    {
        cookie_jar jar;
        urls::url url("https://example.com/path");
        jar.add(url, parse_cookie("id=42; Max-Age=3600").value());
        jar.add(url, parse_cookie("theme=dark; Max-Age=3600").value());

        // Serialize to the Netscape format and read it back into a fresh jar.
        std::ostringstream os;
        os << jar;

        cookie_jar jar2;
        std::istringstream is(os.str());
        is >> jar2;

        BOOST_TEST_EQ(jar2.cookie_header(url), jar.cookie_header(url));
    }

    void
    run()
    {
        testParseBasic();
        testParseAttributes();
        testParseMaxAge();
        testParseSameSite();
        testParseValueless();
        testParseInvalid();
        testNamePrefixes();
        testJarAddAndHeader();
        testJarSecure();
        testJarDomainMismatch();
        testJarPublicSuffix();
        testJarReplace();
        testJarClear();
        testNetscapeRoundTrip();
    }
};

TEST_SUITE(cookie_test, "boost.burl.cookie");

} // namespace burl
} // namespace boost
