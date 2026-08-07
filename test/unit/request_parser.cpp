//
// Copyright (c) 2026 Mohammad Nejati
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

// Test that header file is self-contained.
#include <boost/burl/request_parser.hpp>

#include <boost/burl/error.hpp>
#include <boost/burl/message_reader.hpp>

#include <boost/capy/io/any_read_stream.hpp>
#include <boost/capy/test/read_stream.hpp>

#include "test_suite.hpp"

#include <string_view>

namespace boost
{
namespace burl
{
class request_parser_test
{
public:
    void
    test_header()
    {
        capy::test::read_stream server;
        capy::any_read_stream stream(&server);
        request_parser pr(request_parser::config{});

        capy::test::run_blocking()([&]() -> capy::task<>
        {
            server.provide(
                "GET /index.html HTTP/1.1\r\n"
                "Host: example.com\r\n"
                "Content-Length: 5\r\n"
                "\r\n"
                "hello");

            pr.start();
            auto [ec] = co_await message_reader{ &stream, &pr }.read_header();
            BOOST_TEST(!ec);
            BOOST_TEST(pr.got_header());

            BOOST_TEST(pr.get().method() == http::method::get);
            BOOST_TEST(pr.get().target() == "/index.html");

            char buf[8];
            auto [bec, n] = co_await message_reader{ &stream, &pr }
                .read(capy::make_buffer(buf));
            BOOST_TEST(bec == capy::cond::eof);
            BOOST_TEST_EQ(n, 5);
            BOOST_TEST(std::string_view(buf, n) == "hello");
        }());
    }

    void
    run()
    {
        test_header();
    }
};

TEST_SUITE(request_parser_test, "boost.burl.request_parser");
} // namespace burl
} // namespace boost
