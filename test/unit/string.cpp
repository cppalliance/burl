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

#include <boost/burl/test/response_factory.hpp>

#include <boost/capy/test/run_blocking.hpp>

#include "body_test.hpp"
#include "test_suite.hpp"


namespace boost
{
namespace burl
{

class string_test
{
    static void
    check(any_request_body const& body, std::string_view expected)
    {
        BOOST_TEST(body.has_value());
        BOOST_TEST_EQ(body.content_type().value_or(""), "text/plain; charset=utf-8");
        BOOST_TEST_EQ(body.content_length().value(), expected.size());
        check_body(body, expected);
    }

public:
    void
    testFromString()
    {
        std::string v = "payload";
        check(tag_invoke(body_from_tag<std::string>{}, v), v);
    }

    void
    testFromEmptyString()
    {
        std::string v = "";
        check(tag_invoke(body_from_tag<std::string>{}, v), v);
    }

    void
    testFromStringView()
    {
        std::string_view v = "payload";
        check(tag_invoke(body_from_tag<std::string_view>{}, v), v);
    }

    void
    testFromCharArray()
    {
        const char v[] = "payload";
        check(tag_invoke(body_from_tag<char[sizeof(v)]>{}, v), v);
    }

    void
    testToString()
    {
        capy::test::run_blocking()([&]() -> capy::task<>
        {
            auto r = test::response_factory()
                .body({ "frag1", "frag2", "frag3" })
                .create();
            auto [ec, v] = co_await r.try_as<std::string>();
            BOOST_TEST(!ec);
            BOOST_TEST_EQ(v, "frag1frag2frag3");
        }());
    }

    void
    testToStringTruncated()
    {
        capy::test::run_blocking()([&]() -> capy::task<>
        {
            auto r = test::response_factory()
                .content_length(11)
                .body({ "payl" })
                .create();
            auto [ec, v] = co_await r.try_as<std::string>();
            BOOST_TEST_EQ(ec, http::error::incomplete);
            BOOST_TEST_EQ(v, "payl");
        }());
    }

    void
    testTransportErrorInjection()
    {
        capy::test::fuse f;
        test::response_factory factory;
        factory.body({ "pay", "load" });

        auto r = f.armed([&](capy::test::fuse&) -> capy::task<>
        {
            auto r = factory.create(f);

            auto [ec, v] = co_await r.try_as<std::string>();
            if(ec)
                co_return;

            BOOST_TEST_EQ(v, "payload");
        });
        BOOST_TEST(r.success);
    }

    void
    run()
    {
        testFromString();
        testFromEmptyString();
        testFromStringView();
        testFromCharArray();
        testToString();
        testToStringTruncated();
        testTransportErrorInjection();
    }
};

TEST_SUITE(string_test, "boost.burl.string");

} // namespace burl
} // namespace boost
