//
// Copyright (c) 2026 Mohammad Nejati
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

// Test that header file is self-contained.
#include <boost/burl/test/response_factory.hpp>

#include <boost/burl/string.hpp>

#include <boost/capy/test/run_blocking.hpp>

#include "test_suite.hpp"


namespace boost
{
namespace burl
{
namespace test
{

struct response_factory_test
{
    void
    testBasic()
    {
        capy::test::run_blocking()([]() -> capy::task<>
        {
            auto r = response_factory()
                .header(http::field::content_type, "text/plain")
                .body({ "hello ", "world" })
                .create();

            BOOST_TEST_EQ(r.status_int(), 200);
            BOOST_TEST_EQ(r.reason(), "OK");
            BOOST_TEST(r.ok());
            BOOST_TEST(r.version() == http::version::http_1_1);
            BOOST_TEST_EQ(r.content_length().value_or(0), 11u);
            BOOST_TEST_EQ(
                r.headers().value_or(http::field::content_type, ""),
                "text/plain");

            auto body = co_await r.as<std::string>();
            BOOST_TEST_EQ(body, "hello world");
        }());
    }

    void
    testEmptyBody()
    {
        capy::test::run_blocking()([&]() -> capy::task<>
        {
            auto r = response_factory().create();

            BOOST_TEST_EQ(r.status_int(), 200);
            BOOST_TEST(r.ok());

            auto body = co_await r.as_view();
            BOOST_TEST_EQ(body, "");
        }());
    }

    void
    testMultiValueHeaders()
    {
        capy::test::run_blocking()([&]() -> capy::task<>
        {
            auto r = response_factory()
                .header("X-Custom", "1")
                .header(http::field::cookie, "a=1")
                .header(http::field::cookie, "b=2")
                .body({ "x" })
                .create();

            BOOST_TEST_EQ(r.headers().value_or("X-Custom", ""), "1");

            core::string_view const expected[] = { "a=1", "b=2" };
            std::size_t i = 0;
            for(auto sv : r.headers().find_all(http::field::cookie))
            {
                if(BOOST_TEST(i < 2u))
                    BOOST_TEST_EQ(sv, expected[i]);
                ++i;
            }
            BOOST_TEST_EQ(i, 2u);

            auto body = co_await r.as_view();
            BOOST_TEST_EQ(body, "x");
        }());
    }

    void
    testChunkedBody()
    {
        capy::test::run_blocking()([&]() -> capy::task<>
        {
            auto r = response_factory()
                .header(http::field::content_type, "application/json")
                .chunked(true)
                .body({ "Hello, ", "World" })
                .create();

            BOOST_TEST(!r.content_length().has_value());
            BOOST_TEST_EQ(
                r.headers().value_or(http::field::transfer_encoding, ""),
                "chunked");
            BOOST_TEST_EQ(
                r.headers().value_or(http::field::content_type, ""),
                "application/json");

            auto body = co_await r.as<std::string>();
            BOOST_TEST_EQ(body, "Hello, World");
        }());
    }

    void
    testReadError()
    {
        capy::test::fuse f;
        response_factory factory;
        factory.body({ "hello ", "world" });

        auto r = f.armed([&](capy::test::fuse&) -> capy::task<>
        {
            auto r = factory.create(f);

            auto [ec, body] = co_await r.try_as_view();
            if(ec)
                co_return;
            BOOST_TEST_EQ(body, "hello world");
        });
        BOOST_TEST(r.success);
    }

    void
    run()
    {
        testBasic();
        testEmptyBody();
        testMultiValueHeaders();
        testChunkedBody();
        testReadError();
    }
};

TEST_SUITE(response_factory_test, "boost.burl.response_factory");

} // namespace test
} // namespace burl
} // namespace boost
