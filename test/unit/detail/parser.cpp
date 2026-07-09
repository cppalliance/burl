//
// Copyright (c) 2026 Mohammad Nejati
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

// Test that header file is self-contained.
#include "src/detail/parser.hpp"

#include <boost/burl/error.hpp>

#include <boost/capy/test/read_stream.hpp>

#include "test_suite.hpp"

namespace boost
{
namespace burl
{
namespace detail
{

// parser has protected members (it is a base for the request/response
// parsers); this shim exposes them so the base can be exercised directly.
struct test_parser : parser
{
    test_parser(
        config const& cfg,
        capy::any_read_stream* stream = nullptr)
        : parser(cfg, http::detail::kind::response, stream)
    {
    }

    void
    start(bool head = false)
    {
        parser::start(head);
    }
};

class parser_test
{
public:
    void
    test1()
    {
        capy::test::read_stream server;
        capy::any_read_stream stream(&server);
        test_parser pr({}, &stream);

        capy::test::run_blocking()([&]() -> capy::task<>
        {
            std::string_view sv =
                "HTTP/1.1 200 OK\r\n"
                "Content-Length: 5\r\n"
                "\r\n"
                "hello";

            server.provide(sv);

            pr.start();
            auto [ec] = co_await pr.read_header();
            BOOST_TEST(!ec);
            BOOST_TEST(pr.got_header());
            BOOST_TEST(!pr.is_complete());

            char buf[3];
            {
                auto [ec, n] = co_await pr.read_some(capy::make_buffer(buf));
                BOOST_TEST(!ec);
                BOOST_TEST_EQ(n, 3);
            }
            {
                auto [ec, n] = co_await pr.read_some(capy::make_buffer(buf));
                BOOST_TEST(ec == capy::cond::eof);
                BOOST_TEST_EQ(n, 2);
            }
            {
                auto [ec, n] = co_await pr.read(capy::make_buffer(buf));
                BOOST_TEST(ec == capy::cond::eof);
                BOOST_TEST_EQ(n, 0);
            }
        }());
    }

    void
    test2()
    {
        capy::test::read_stream server;
        capy::any_read_stream stream(&server);
        test_parser pr({}, &stream);

        capy::test::run_blocking()([&]() -> capy::task<>
        {
            std::string_view sv =
                "HTTP/1.1 200 OK\r\n"
                "Content-Length: 5\r\n"
                "\r\n"
                "hello";

            server.provide(sv);

            pr.start();
            auto [ec] = co_await pr.read_header();
            BOOST_TEST(!ec);
            BOOST_TEST(pr.got_header());
            BOOST_TEST(!pr.is_complete());

            capy::const_buffer arr[2];
            {
                auto [ec, bufs] = co_await pr.pull(arr);
                BOOST_TEST(!ec);
                BOOST_TEST_EQ(bufs.size(), 1);
                BOOST_TEST_EQ(bufs[0].size(), 5);
            }
            pr.consume(3);
            {
                auto [ec, bufs] = co_await pr.pull(arr);
                BOOST_TEST(!ec);
                BOOST_TEST_EQ(bufs.size(), 1);
                BOOST_TEST_EQ(bufs[0].size(), 2);
            }
            pr.consume(2);
            {
                auto [ec, bufs] = co_await pr.pull(arr);
                BOOST_TEST(ec == capy::cond::eof);
                BOOST_TEST_EQ(bufs.size(), 0);
            }
        }());
    }

    void
    test3()
    {
        capy::test::read_stream server;
        capy::any_read_stream stream(&server);
        test_parser pr({}, &stream);

        capy::test::run_blocking()([&]() -> capy::task<>
        {
            std::string_view sv =
                "HTTP/1.1 200 OK\r\n"
                "Transfer-Encoding: chunked\r\n"
                "\r\n"
                "5\r\n"
                "hello"
                "\r\n"
                "0\r\n\r\n";

            server.provide(sv);

            pr.start();
            auto [ec] = co_await pr.read_header();
            BOOST_TEST(!ec);
            BOOST_TEST(pr.got_header());
            BOOST_TEST(!pr.is_complete());

            char buf[3];
            {
                auto [ec, n] = co_await pr.read_some(capy::make_buffer(buf));
                BOOST_TEST(!ec);
                BOOST_TEST_EQ(n, 3);
            }
            {
                auto [ec, n] = co_await pr.read_some(capy::make_buffer(buf));
                BOOST_TEST(ec == capy::cond::eof);
                BOOST_TEST_EQ(n, 2);
            }
            {
                auto [ec, n] = co_await pr.read(capy::make_buffer(buf));
                BOOST_TEST(ec == capy::cond::eof);
                BOOST_TEST_EQ(n, 0);
            }
        }());
    }

    void
    test4()
    {
        capy::test::read_stream server;
        capy::any_read_stream stream(&server);
        test_parser pr({}, &stream);

        capy::test::run_blocking()([&]() -> capy::task<>
        {
            std::string_view sv =
                "HTTP/1.1 200 OK\r\n"
                "Transfer-Encoding: chunked\r\n"
                "\r\n"
                "5\r\n"
                "hello"
                "\r\n"
                "8\r\n"
                "universe"
                "\r\n"
                "0\r\n\r\n";

            server.provide(sv);

            pr.start();
            auto [ec] = co_await pr.read_header();
            BOOST_TEST(!ec);
            BOOST_TEST(pr.got_header());
            BOOST_TEST(!pr.is_complete());

            capy::const_buffer arr[2];
            {
                auto [ec, bufs] = co_await pr.pull(arr);
                BOOST_TEST(!ec);
                BOOST_TEST_EQ(bufs.size(), 2);
                BOOST_TEST_EQ(bufs[0].size(), 5);
                BOOST_TEST_EQ(bufs[1].size(), 8);
            }
            pr.consume(3);
            {
                auto [ec, bufs] = co_await pr.pull(arr);
                BOOST_TEST(!ec);
                BOOST_TEST_EQ(bufs.size(), 2);
                BOOST_TEST_EQ(bufs[0].size(), 2);
                BOOST_TEST_EQ(bufs[1].size(), 8);
            }
            pr.consume(2);
            {
                auto [ec, bufs] = co_await pr.pull(arr);
                BOOST_TEST(!ec);
                BOOST_TEST_EQ(bufs.size(), 1);
                BOOST_TEST_EQ(bufs[0].size(), 8);
            }
            pr.consume(2);
            {
                auto [ec, bufs] = co_await pr.pull(arr);
                BOOST_TEST(!ec);
                BOOST_TEST_EQ(bufs.size(), 1);
                BOOST_TEST_EQ(bufs[0].size(), 6);
            }
            pr.consume(6);
            {
                auto [ec, bufs] = co_await pr.pull(arr);
                BOOST_TEST(ec == capy::cond::eof);
                BOOST_TEST_EQ(bufs.size(), 0);
            }
        }());
    }

    void
    test_move_ctor()
    {
        capy::test::read_stream server;
        capy::any_read_stream stream(&server);
        test_parser pr({}, &stream);

        capy::test::run_blocking()([&]() -> capy::task<>
        {
            server.provide(
                "HTTP/1.1 200 OK\r\n"
                "Content-Length: 5\r\n"
                "\r\n"
                "hello");

            pr.start();
            auto [ec] = co_await pr.read_header();
            BOOST_TEST(!ec);

            char buf[3];
            {
                auto [ec, n] = co_await pr.read_some(capy::make_buffer(buf));
                BOOST_TEST(!ec);
                BOOST_TEST_EQ(n, 3);
            }

            // move-construct mid-body: pr2 must adopt the in-progress state
            // (and the static_response the buffer points to), and the
            // moved-from pr must remain safely destructible.
            test_parser pr2(std::move(pr));
            BOOST_TEST(pr2.got_header());
            BOOST_TEST(!pr2.is_complete());
            {
                auto [ec, n] = co_await pr2.read_some(capy::make_buffer(buf));
                BOOST_TEST(ec == capy::cond::eof);
                BOOST_TEST_EQ(n, 2);
            }
        }());
    }

    void
    test_move_assign()
    {
        capy::test::read_stream server;
        capy::any_read_stream stream(&server);
        test_parser pr({}, &stream);
        test_parser pr2({}, &stream); // owns its own allocation

        capy::test::run_blocking()([&]() -> capy::task<>
        {
            server.provide(
                "HTTP/1.1 200 OK\r\n"
                "Content-Length: 5\r\n"
                "\r\n"
                "hello");

            pr.start();
            auto [ec] = co_await pr.read_header();
            BOOST_TEST(!ec);

            char buf[3];
            {
                auto [ec, n] = co_await pr.read_some(capy::make_buffer(buf));
                BOOST_TEST(!ec);
                BOOST_TEST_EQ(n, 3);
            }

            // move-assign: pr2's original allocation must be released (no
            // leak, no double free) and pr2 adopts pr's in-progress state.
            pr2 = std::move(pr);
            BOOST_TEST(pr2.got_header());
            {
                auto [ec, n] = co_await pr2.read_some(capy::make_buffer(buf));
                BOOST_TEST(ec == capy::cond::eof);
                BOOST_TEST_EQ(n, 2);
            }
        }());
    }

    void
    test_reset()
    {
        capy::test::read_stream server1;
        capy::any_read_stream stream1(&server1);
        test_parser pr({}, &stream1);

        capy::test::run_blocking()([&]() -> capy::task<>
        {
            server1.provide(
                "HTTP/1.1 200 OK\r\n"
                "Content-Length: 5\r\n"
                "\r\n"
                "hello");

            pr.start();
            {
                auto [ec] = co_await pr.read_header();
                BOOST_TEST(!ec);
                BOOST_TEST(pr.got_header());
            }
            char buf[8];
            {
                auto [ec, n] = co_await pr.read(capy::make_buffer(buf));
                BOOST_TEST(ec == capy::cond::eof);
                BOOST_TEST_EQ(n, 5);
                BOOST_TEST(std::string_view(buf, n) == "hello");
            }

            // reset onto a fresh stream must return the parser to a
            // construction-like state: buffers restored, flags cleared, and a
            // second, differently-framed message parses correctly.
            capy::test::read_stream server2;
            capy::any_read_stream stream2(&server2);
            pr.reset(&stream2);
            BOOST_TEST(!pr.got_header());

            server2.provide(
                "HTTP/1.1 404 Not Found\r\n"
                "Content-Length: 3\r\n"
                "\r\n"
                "bye");

            pr.start();
            {
                auto [ec] = co_await pr.read_header();
                BOOST_TEST(!ec);
                BOOST_TEST(pr.got_header());
                BOOST_TEST(!pr.is_complete());
            }
            {
                auto [ec, n] = co_await pr.read(capy::make_buffer(buf));
                BOOST_TEST(ec == capy::cond::eof);
                BOOST_TEST_EQ(n, 3);
                BOOST_TEST(std::string_view(buf, n) == "bye");
            }
        }());
    }

    void
    run()
    {
        test1();
        test2();
        test3();
        test4();
        test_move_ctor();
        test_move_assign();
        test_reset();
    }
};

TEST_SUITE(parser_test, "boost.burl.detail.parser");

} // namespace detail
} // namespace burl
} // namespace boost
