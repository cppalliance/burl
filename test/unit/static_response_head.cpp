//
// Copyright (c) 2026 Mohammad Nejati
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

// Test that header file is self-contained.
#include <boost/burl/static_response_head.hpp>

#include <boost/burl/response_head.hpp>

#include "test_suite.hpp"

#include <stdexcept>
#include <string>
#include <type_traits>
#include <utility>

namespace boost
{
namespace burl
{

// The container behavior shared with the owning heads is
// covered by the response_head and fields tests, and the
// fixed-storage mechanics by the static_request_head
// tests. These tests cover the response-specific surface.

static_assert(std::is_nothrow_move_constructible_v<static_response_head>);
static_assert(! std::is_copy_constructible_v<static_response_head>);

class static_response_head_test
{
public:
    void
    testDefault()
    {
        alignas(4) char buf[64];
        static_response_head h(buf, sizeof(buf));
        BOOST_TEST_EQ(h.buffer(), "HTTP/1.1 200 OK\r\n\r\n");
        BOOST_TEST(h.status() == http::status::ok);
        BOOST_TEST_EQ(h.status_int(), 200u);
        BOOST_TEST_EQ(h.reason(), "OK");
        BOOST_TEST(h.version() == http::version::http_1_1);
        BOOST_TEST(h.empty());
        BOOST_TEST_EQ(h.capacity_in_bytes(), 64u);
        BOOST_TEST_EQ(h.buffer().data(), &buf[0]);
    }

    void
    testTooSmall()
    {
        alignas(4) char buf[20];
        // the storage must hold at least the default head
        BOOST_TEST_THROWS(
            static_response_head(buf, 18),
            std::length_error);
        // an exact fit leaves no field capacity
        {
            static_response_head h(buf + 1, 19);
            BOOST_TEST_EQ(h.buffer(), "HTTP/1.1 200 OK\r\n\r\n");
            BOOST_TEST_EQ(h.capacity_in_bytes(), 19u);
        }
        static_response_head h(buf, sizeof(buf));
        BOOST_TEST_EQ(h.buffer(), "HTTP/1.1 200 OK\r\n\r\n");
        BOOST_TEST_THROWS(
            h.append("X", "*"),
            std::length_error);
    }

    void
    testCapacity()
    {
        // the storage is fixed: the start line and fields
        // grow within it, and throw when it is exhausted
        alignas(4) char buf[64];
        static_response_head h(buf, sizeof(buf));
        h.set_start_line(http::status::not_found);
        h.set(http::field::content_type, "text/html");
        BOOST_TEST_EQ(
            h.buffer(),
            "HTTP/1.1 404 Not Found\r\n"
            "Content-Type: text/html\r\n"
            "\r\n");
        BOOST_TEST_THROWS(
            h.append("X", std::string(40, '*')),
            std::length_error);
        BOOST_TEST_THROWS(
            h.set_start_line(
                http::status::internal_server_error,
                http::version::http_1_0),
            std::length_error);
        BOOST_TEST_EQ(
            h.buffer(),
            "HTTP/1.1 404 Not Found\r\n"
            "Content-Type: text/html\r\n"
            "\r\n");
    }

    void
    testCopyAssign()
    {
        response_head src(http::status::no_content);
        src.set(http::field::server, "boost");

        alignas(4) char buf[128];
        static_response_head h(buf, sizeof(buf));
        h = src;
        BOOST_TEST_EQ(h.buffer(), src.buffer());
        BOOST_TEST(h.buffer().data() != src.buffer().data());
        BOOST_TEST(h.status() == http::status::no_content);
        BOOST_TEST(h.payload() == http::payload::none);

        // self-assignment
        auto const& hr = h;
        h = hr;
        BOOST_TEST_EQ(h.buffer(), src.buffer());

        response_head big;
        big.set(http::field::server, std::string(200, 'x'));
        BOOST_TEST_THROWS(h = big, std::length_error);
        BOOST_TEST_EQ(h.buffer(), src.buffer());
    }

    void
    testMove()
    {
        alignas(4) char buf[64];
        static_response_head h1(buf, sizeof(buf));
        h1.set_status(http::status::accepted);
        auto const* p = h1.buffer().data();
        static_response_head h2(std::move(h1));
        BOOST_TEST_EQ(h2.buffer(), "HTTP/1.1 202 Accepted\r\n\r\n");
        BOOST_TEST_EQ(h2.buffer().data(), p);
        BOOST_TEST_EQ(h1.capacity_in_bytes(), 0u);
        BOOST_TEST_THROWS(
            h1.append("X", "*"),
            std::length_error);
        BOOST_TEST_THROWS(h1 = h2, std::length_error);
        // a source whose start line is shorter than the
        // default one would fit the reported capacity of
        // the shared default buffer
        response_head h3;
        h3.set_start_line(200, "");
        BOOST_TEST_THROWS(h1 = h3, std::length_error);
        BOOST_TEST_EQ(
            response_head().buffer(), "HTTP/1.1 200 OK\r\n\r\n");
    }

    void
    run()
    {
        testDefault();
        testTooSmall();
        testCapacity();
        testCopyAssign();
        testMove();
    }
};

TEST_SUITE(static_response_head_test, "boost.burl.static_response_head");

} // namespace burl
} // namespace boost
