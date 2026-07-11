//
// Copyright (c) 2026 Mohammad Nejati
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

// Test that header file is self-contained.
#include <boost/burl/detail/response_parser.hpp>

#include <boost/burl/error.hpp>

#include <boost/capy/test/read_stream.hpp>

#include "test_suite.hpp"

#include <string_view>

namespace boost
{
namespace burl
{
namespace detail
{

class response_parser_test
{
public:
    void
    test_header()
    {
        capy::test::read_stream server;
        capy::any_read_stream stream(&server);
        response_parser pr({}, &stream);

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
            BOOST_TEST(pr.got_header());
            // the whole body arrived with the header, so the message
            // is already complete (arrival semantics)
            BOOST_TEST(pr.got_body());

            BOOST_TEST(pr.get().status() == http::status::ok);
            BOOST_TEST_EQ(pr.get().status_int(), 200);
            BOOST_TEST(pr.get().reason() == "OK");

            char buf[8];
            auto [bec, n] = co_await pr.read(capy::make_buffer(buf));
            BOOST_TEST(bec == capy::cond::eof);
            BOOST_TEST_EQ(n, 5);
            BOOST_TEST(std::string_view(buf, n) == "hello");
        }());
    }

    void
    test_head_response()
    {
        capy::test::read_stream server;
        capy::any_read_stream stream(&server);
        response_parser pr({}, &stream);

        capy::test::run_blocking()([&]() -> capy::task<>
        {
            // Response to a HEAD request: framing fields are present but no
            // body follows. start(true) tells the parser not to read one.
            server.provide(
                "HTTP/1.1 200 OK\r\n"
                "Content-Length: 5\r\n"
                "\r\n");

            pr.start(true);
            auto [ec] = co_await pr.read_header();
            BOOST_TEST(!ec);
            BOOST_TEST(pr.got_header());
            BOOST_TEST(pr.got_body());
            BOOST_TEST_EQ(pr.get().status_int(), 200);
        }());
    }

    void
    run()
    {
        test_header();
        test_head_response();
    }
};

TEST_SUITE(response_parser_test, "boost.burl.detail.response_parser");

} // namespace detail
} // namespace burl
} // namespace boost
