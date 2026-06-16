//
// Copyright (c) 2026 Mohammad Nejati
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

// Test that header file is self-contained.
#include <boost/burl/test/detail/buffer_connection.hpp>

#include <boost/capy/test/run_blocking.hpp>

#include "test_suite.hpp"

namespace boost
{
namespace burl
{
namespace test
{
namespace detail
{

struct buffer_connection_test
{
    void
    testReadsFragments()
    {
        capy::test::run_blocking()([]() -> capy::task<>
        {
            buffer_connection conn({ "hello", "world" }, capy::test::fuse{});
            char buf[64];

            // Each fragment is delivered by its own read, even when the
            // buffer is large enough to hold more than one.
            auto [ec1, n1] = co_await conn.read_some(capy::make_buffer(buf));
            BOOST_TEST(!ec1);
            BOOST_TEST_EQ(std::string_view(buf, n1), "hello");

            auto [ec2, n2] = co_await conn.read_some(capy::make_buffer(buf));
            BOOST_TEST(!ec2);
            BOOST_TEST_EQ(std::string_view(buf, n2), "world");

            // The fragments are exhausted; the next read reports eof.
            auto [ec3, n3] = co_await conn.read_some(capy::make_buffer(buf));
            BOOST_TEST(ec3 == capy::error::eof);
            BOOST_TEST_EQ(n3, 0u);

            // eof is sticky.
            auto [ec4, n4] = co_await conn.read_some(capy::make_buffer(buf));
            BOOST_TEST(ec4 == capy::error::eof);
            BOOST_TEST_EQ(n4, 0u);
        }());
    }

    void
    testPartialReads()
    {
        capy::test::run_blocking()([]() -> capy::task<>
        {
            buffer_connection conn({ "hello" }, capy::test::fuse{});
            char buf[64];

            // A buffer smaller than the fragment yields the fragment across
            // successive reads.
            auto [ec1, n1] = co_await conn.read_some(capy::make_buffer(buf, 2));
            BOOST_TEST(!ec1);
            BOOST_TEST_EQ(std::string_view(buf, n1), "he");

            auto [ec2, n2] = co_await conn.read_some(capy::make_buffer(buf, 2));
            BOOST_TEST(!ec2);
            BOOST_TEST_EQ(std::string_view(buf, n2), "ll");

            auto [ec3, n3] = co_await conn.read_some(capy::make_buffer(buf, 2));
            BOOST_TEST(!ec3);
            BOOST_TEST_EQ(std::string_view(buf, n3), "o");

            auto [ec4, n4] = co_await conn.read_some(capy::make_buffer(buf, 2));
            BOOST_TEST(ec4 == capy::error::eof);
            BOOST_TEST_EQ(n4, 0u);
        }());
    }

    void
    testEmptyFragment()
    {
        capy::test::run_blocking()([]() -> capy::task<>
        {
            buffer_connection conn({ "" }, capy::test::fuse{});
            char buf[64];

            // An empty fragment is a successful zero-byte read, not eof.
            auto [ec1, n1] = co_await conn.read_some(capy::make_buffer(buf));
            BOOST_TEST(!ec1);
            BOOST_TEST_EQ(n1, 0u);

            auto [ec2, n2] = co_await conn.read_some(capy::make_buffer(buf));
            BOOST_TEST(ec2 == capy::error::eof);
            BOOST_TEST_EQ(n2, 0u);
        }());
    }

    void
    testNoFragments()
    {
        capy::test::run_blocking()([]() -> capy::task<>
        {
            buffer_connection conn({}, capy::test::fuse{});
            char buf[64];

            auto [ec, n] = co_await conn.read_some(capy::make_buffer(buf));
            BOOST_TEST(ec == capy::error::eof);
            BOOST_TEST_EQ(n, 0u);
        }());
    }

    void
    testWriteFails()
    {
        capy::test::run_blocking()([]() -> capy::task<>
        {
            buffer_connection conn({ "hello" }, capy::test::fuse{});

            // The connection is read-only; writes always report eof.
            auto [ec, n] = co_await conn.write_some(
                capy::make_buffer(std::string_view("data")));
            BOOST_TEST(ec == capy::error::eof);
            BOOST_TEST_EQ(n, 0u);
        }());
    }

    void
    testIsOpenAndShutdown()
    {
        capy::test::run_blocking()([]() -> capy::task<>
        {
            buffer_connection conn({ "hello" }, capy::test::fuse{});
            BOOST_TEST(conn.is_open());

            // Draining the data does not close the connection.
            char buf[64];
            auto [rec, rn] = co_await conn.read_some(capy::make_buffer(buf));
            BOOST_TEST(!rec);
            BOOST_TEST_EQ(std::string_view(buf, rn), "hello");

            auto [ec, n] = co_await conn.read_some(capy::make_buffer(buf));
            BOOST_TEST(ec == capy::error::eof);
            BOOST_TEST_EQ(n, 0u);
            BOOST_TEST(conn.is_open());

            // shutdown completes without error and is a no-op.
            auto [sec] = co_await conn.shutdown();
            BOOST_TEST(!sec);
            BOOST_TEST(conn.is_open());
        }());
    }

    void
    testReadError()
    {
        capy::test::fuse f;
        auto r = f.armed([&](capy::test::fuse&) -> capy::task<>
        {
            buffer_connection conn({ "hello", "world" }, f);
            char buf[64];
            for(;;)
            {
                auto [ec, n] = co_await conn.read_some(capy::make_buffer(buf));
                if(ec)
                    co_return;
                BOOST_TEST(n > 0u);
            }
        });
        BOOST_TEST(r.success);
    }

    void
    run()
    {
        testReadsFragments();
        testPartialReads();
        testEmptyFragment();
        testNoFragments();
        testWriteFails();
        testIsOpenAndShutdown();
        testReadError();
    }
};

TEST_SUITE(buffer_connection_test, "boost.burl.detail.buffer_connection");

} // namespace detail
} // namespace test
} // namespace burl
} // namespace boost
