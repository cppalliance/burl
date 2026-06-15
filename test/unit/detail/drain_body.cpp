//
// Copyright (c) 2026 Mohammad Nejati
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

// Test that header file is self-contained.
#include "src/detail/drain_body.hpp"

#include "test_suite.hpp"

#include <boost/capy/test/fuse.hpp>
#include <boost/capy/test/stream.hpp>

namespace boost
{
namespace burl
{
namespace detail
{

class drain_body_test
{
    void
    check(
        std::string_view msg,
        std::uint64_t limit,
        bool expected)
    {
        http::response_parser pr(
            http::make_parser_config(http::parser_config{ false }));
        capy::test::fuse f;
        auto r = f.armed([&](capy::test::fuse&) -> capy::task<>
        {
            auto [client, server] = capy::test::make_stream_pair(f);
            client.set_max_read_size(1);
            server.provide(msg);
            server.close();

            pr.reset();
            pr.start();

            if(auto [rec] = co_await pr.read_header(client); rec)
                co_return;

            BOOST_TEST(pr.got_header());

            auto [dec, drained] =
                co_await drain_body(
                    pr, capy::any_stream(&client), limit);

            if(dec)
            {
                BOOST_TEST(!drained);
                co_return;
            }

            BOOST_TEST_EQ(drained, expected);
        });
        BOOST_TEST(r.success);
    }

public:
    void
    testEmptyBody()
    {
        auto msg =
            "HTTP/1.1 200 OK\r\n"
            "Content-Length: 0\r\n"
            "\r\n";

        check(msg, 1, true);
        check(msg, 0, true);
    }

    void
    testPartialBody()
    {
        auto msg =
            "HTTP/1.1 200 OK\r\n"
            "Content-Length: 11\r\n"
            "\r\n"
            "hello wo";

        check(msg, 256, false);
    }

    void
    testContentLength()
    {
        auto msg =
            "HTTP/1.1 200 OK\r\n"
            "Content-Length: 5\r\n"
            "\r\n"
            "hello";

        check(msg, 5, true);
        check(msg, 5 - 1, false);
    }

    void
    testChunked()
    {
        auto msg =
            "HTTP/1.1 200 OK\r\n"
            "Transfer-Encoding: chunked\r\n"
            "\r\n"
            "5\r\n"
            "hello"
            "0\r\n\r\n";

        check(msg, 3 + 5 + 5, true);
        check(msg, 3 + 5 + 5 - 1, false);
    }

    void
    run()
    {
        testEmptyBody();
        testPartialBody();
        testContentLength();
        testChunked();
    }
};

TEST_SUITE(drain_body_test, "boost.burl.detail.drain_body");

} // namespace detail
} // namespace burl
} // namespace boost
