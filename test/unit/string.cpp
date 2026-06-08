//
// Copyright (c) 2026 Mohammad Nejati
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

// Test that header file is self-contained.
#include <boost/burl/string.hpp>

#include <boost/burl/any_request_body.hpp>
#include <boost/burl/conversion.hpp>

#include "body_test.hpp"
#include "test_suite.hpp"

#include <string>
#include <string_view>
#include <utility>

namespace boost
{
namespace burl
{

struct string_test
{
    static void
    check_text(any_request_body const& body, std::string_view expected)
    {
        BOOST_TEST(body.has_value());

        auto ct = body.content_type();
        BOOST_TEST(ct.has_value());
        BOOST_TEST_EQ(ct.value(), "text/plain; charset=utf-8");

        auto cl = body.content_length();
        BOOST_TEST(cl.has_value());
        BOOST_TEST_EQ(cl.value(), expected.size());

        check_body(body, expected);
    }

    void
    testString()
    {
        auto body =
            tag_invoke(body_from_tag<std::string>{}, std::string("payload"));
        check_text(body, "payload");
    }

    void
    testEmptyString()
    {
        auto body = tag_invoke(body_from_tag<std::string>{}, std::string());
        check_text(body, "");
    }

    void
    testStringView()
    {
        std::string_view sv = "view payload";
        auto body = tag_invoke(body_from_tag<std::string_view>{}, sv);
        check_text(body, sv);
    }

    void
    testCharArray()
    {
        // The char[N] overload treats the array as a literal and drops the
        // terminating null.
        const char lit[] = "literal";
        auto body = tag_invoke(body_from_tag<char[sizeof(lit)]>{}, lit);
        check_text(body, "literal");
    }

    void
    run()
    {
        testString();
        testEmptyString();
        testStringView();
        testCharArray();
    }
};

TEST_SUITE(string_test, "boost.burl.string");

} // namespace burl
} // namespace boost
