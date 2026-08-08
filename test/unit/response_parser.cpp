//
// Copyright (c) 2026 Mohammad Nejati
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

// Test that header file is self-contained.
#include <boost/burl/response_parser.hpp>

#include <boost/burl/error.hpp>

#include <boost/capy/buffers/buffer_copy.hpp>
#include <boost/capy/cond.hpp>

#include "test_suite.hpp"

#include <span>
#include <string_view>

namespace boost
{
namespace burl
{
class response_parser_test
{
    // The parser does no I/O: octets go in through prepare()/commit().
    static
    void
    feed(parser& pr, std::string_view s)
    {
        auto const n = capy::buffer_copy(
            pr.prepare(),
            capy::const_buffer(s.data(), s.size()));
        BOOST_TEST_EQ(n, s.size());
        pr.commit(n);
    }

public:
    void
    test_header()
    {
        response_parser pr(response_parser::config{});

        pr.start();
        feed(pr,
            "HTTP/1.1 200 OK\r\n"
            "Content-Length: 5\r\n"
            "\r\n"
            "hello");

        system::error_code ec;
        pr.parse_header(ec);
        BOOST_TEST(!ec);
        BOOST_TEST(pr.got_header());
        // the whole body arrived with the header, so the message
        // is already complete (arrival semantics)
        BOOST_TEST(pr.got_body());

        BOOST_TEST(pr.get().status() == http::status::ok);
        BOOST_TEST_EQ(pr.get().status_int(), 200);
        BOOST_TEST(pr.get().reason() == "OK");

        char buf[8];
        capy::mutable_buffer mb(buf, sizeof(buf));
        auto n = pr.read_some({ &mb, 1 }, ec);
        BOOST_TEST(!ec);
        BOOST_TEST_EQ(n, 5);
        BOOST_TEST(std::string_view(buf, n) == "hello");

        n = pr.read_some({ &mb, 1 }, ec);
        BOOST_TEST(ec == capy::cond::eof);
        BOOST_TEST_EQ(n, 0);
    }

    void
    test_head_response()
    {
        response_parser pr(response_parser::config{});

        // Response to a HEAD request: framing fields are present but no
        // body follows. start(true) tells the parser not to read one.
        pr.start(true);
        feed(pr,
            "HTTP/1.1 200 OK\r\n"
            "Content-Length: 5\r\n"
            "\r\n");

        system::error_code ec;
        pr.parse_header(ec);
        BOOST_TEST(!ec);
        BOOST_TEST(pr.got_header());
        BOOST_TEST(pr.got_body());
        BOOST_TEST_EQ(pr.get().status_int(), 200);
    }

    void
    run()
    {
        test_header();
        test_head_response();
    }
};

TEST_SUITE(response_parser_test, "boost.burl.response_parser");
} // namespace burl
} // namespace boost
