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

namespace boost
{
namespace burl
{

struct cookie_test
{
    void
    testBasic()
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
    testAttributes()
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
    testMaxAge()
    {
        auto rc = parse_cookie("a=b; Max-Age=3600");
        BOOST_TEST(rc.has_value());
        BOOST_TEST(rc->expires.has_value());
    }

    void
    testSameSite()
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

        BOOST_TEST(parse_cookie("a=b; SameSite=Bogus").has_error());
    }

    void
    testValueless()
    {
        // An empty value parses as no value, not an empty string.
        auto rc = parse_cookie("flag=");
        BOOST_TEST(rc.has_value());
        BOOST_TEST_EQ(rc->name, "flag");
        BOOST_TEST(!rc->value.has_value());
    }

    void
    testInvalid()
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

        // The prefixes are matched case-insensitively (RFC 6265bis).
        BOOST_TEST(parse_cookie("__secure-x=1").has_error());
        BOOST_TEST(parse_cookie("__SECURE-x=1; Secure").has_value());
        BOOST_TEST(parse_cookie("__host-x=1; Secure").has_error());
        BOOST_TEST(parse_cookie("__HOST-x=1; Secure; Path=/").has_value());
    }

    void
    run()
    {
        testBasic();
        testAttributes();
        testMaxAge();
        testSameSite();
        testValueless();
        testInvalid();
        testNamePrefixes();
    }
};

TEST_SUITE(cookie_test, "boost.burl.cookie");

} // namespace burl
} // namespace boost
