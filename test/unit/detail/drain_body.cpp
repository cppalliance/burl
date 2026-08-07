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

#include <boost/burl/message_reader.hpp>

#include "test_suite.hpp"

#include <boost/capy/test/fuse.hpp>
#include <boost/capy/test/stream.hpp>
#include <boost/http/error.hpp>

namespace boost
{
namespace burl
{
namespace detail
{

class drain_body_test
{
    struct result
    {
        std::error_code ec;
        bool drained  = false;
        bool complete = false;
    };

    result
    check(
        std::string_view msg,
        std::size_t attempts,
        std::size_t max_read_size = std::size_t(-1))
    {
        result rs;
        response_parser pr(response_parser::config{});
        capy::test::fuse f;
        auto r = f.armed([&](capy::test::fuse&) -> capy::task<>
        {
            auto [client, server] = capy::test::make_stream_pair(f);
            client.set_max_read_size(max_read_size);
            server.provide(msg);
            server.close();

            pr.reset();
            pr.start();

            if(auto [rec] = co_await message_reader{
                   &client, &pr }.read_header(); rec)
                co_return;

            BOOST_TEST(pr.got_header());

            auto [dec, drained] = co_await drain_body(client, pr, attempts);
            if(dec)
                BOOST_TEST(!drained);
            rs = { dec, drained, pr.got_body() };
        });
        BOOST_TEST(r.success);
        return rs;
    }

public:
    void
    testEmptyBody()
    {
        auto msg =
            "HTTP/1.1 200 OK\r\n"
            "Content-Length: 0\r\n"
            "\r\n";

        // Complete after the header; no attempts needed
        auto rs = check(msg, 0);
        BOOST_TEST(!rs.ec);
        BOOST_TEST(rs.drained);
        BOOST_TEST(rs.complete);
    }

    void
    testContentLength()
    {
        auto msg =
            "HTTP/1.1 200 OK\r\n"
            "Content-Length: 5\r\n"
            "\r\n"
            "hello";

        // One byte per read; each attempt drains one byte
        auto rs = check(msg, 5, 1);
        BOOST_TEST(!rs.ec);
        BOOST_TEST(rs.drained);
        BOOST_TEST(rs.complete);
    }

    void
    testChunked()
    {
        auto msg =
            "HTTP/1.1 200 OK\r\n"
            "Transfer-Encoding: chunked\r\n"
            "\r\n"
            "5\r\n"
            "hello\r\n"
            "0\r\n"
            "\r\n";

        auto rs = check(msg, 1);
        BOOST_TEST(!rs.ec);
        BOOST_TEST(rs.drained);
        BOOST_TEST(rs.complete);

        // One byte per read; the final chunk arrives after the
        // last data byte and is reported as eof, which also
        // means the body is drained
        rs = check(msg, 64, 1);
        BOOST_TEST(!rs.ec);
        BOOST_TEST(rs.drained);
    }

    void
    testAttemptsExhausted()
    {
        auto msg =
            "HTTP/1.1 200 OK\r\n"
            "Content-Length: 5\r\n"
            "\r\n"
            "hello";

        // One byte per read; runs out of attempts before
        // the body is fully drained
        auto rs = check(msg, 4, 1);
        BOOST_TEST(!rs.ec);
        BOOST_TEST(!rs.drained);
        BOOST_TEST(!rs.complete);
    }

    void
    testIncompleteBody()
    {
        auto msg1 =
            "HTTP/1.1 200 OK\r\n"
            "Content-Length: 11\r\n"
            "\r\n"
            "hello wo";

        auto rs = check(msg1, 64, 1);
        BOOST_TEST(rs.ec == http::error::incomplete);
        BOOST_TEST(!rs.drained);
        BOOST_TEST(!rs.complete);

        auto msg2 =
            "HTTP/1.1 200 OK\r\n"
            "Transfer-Encoding: chunked\r\n"
            "\r\n"
            "5\r\n"
            "hel";

        rs = check(msg2, 64, 1);
        BOOST_TEST(rs.ec == http::error::incomplete);
        BOOST_TEST(!rs.drained);
        BOOST_TEST(!rs.complete);
    }

    void
    run()
    {
        testEmptyBody();
        testContentLength();
        testChunked();
        testAttemptsExhausted();
        testIncompleteBody();
    }
};

TEST_SUITE(drain_body_test, "boost.burl.detail.drain_body");

} // namespace detail
} // namespace burl
} // namespace boost
