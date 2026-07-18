//
// Copyright (c) 2026 Mohammad Nejati
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

// Test that header file is self-contained.
#include <boost/burl/static_request_head.hpp>

#include <boost/burl/request_head.hpp>

#include "test_suite.hpp"

#include <stdexcept>
#include <string>
#include <type_traits>
#include <utility>

namespace boost
{
namespace burl
{

// The container behavior shared with the owning heads —
// fields, start line, framing — is covered by the
// request_head and fields tests. These tests focus on
// the fixed-storage semantics.

static_assert(std::is_nothrow_move_constructible_v<static_request_head>);
static_assert(! std::is_copy_constructible_v<static_request_head>);

class static_request_head_test
{
public:
    void
    testDefault()
    {
        alignas(4) char buf[64];
        static_request_head h(buf, sizeof(buf));
        BOOST_TEST_EQ(h.buffer(), "GET / HTTP/1.1\r\n\r\n");
        BOOST_TEST(h.method() == http::method::get);
        BOOST_TEST_EQ(h.target(), "/");
        BOOST_TEST(h.version() == http::version::http_1_1);
        BOOST_TEST(h.empty());
        BOOST_TEST_EQ(h.capacity_in_bytes(), 64u);
        BOOST_TEST_EQ(h.buffer().data(), &buf[0]);
    }

    void
    testAlignment()
    {
        // an unaligned buffer end is aligned down
        alignas(4) char buf[64];
        static_request_head h(buf + 1, 62);
        BOOST_TEST_EQ(h.capacity_in_bytes(), 59u);
        BOOST_TEST_EQ(h.buffer(), "GET / HTTP/1.1\r\n\r\n");
    }

    void
    testTooSmall()
    {
        alignas(4) char buf[20];
        // the storage must hold at least the default head
        BOOST_TEST_THROWS(
            static_request_head(buf, 17),
            std::length_error);
        // an exact fit leaves no field capacity
        {
            static_request_head h(buf + 2, 18);
            BOOST_TEST_EQ(h.buffer(), "GET / HTTP/1.1\r\n\r\n");
            BOOST_TEST_EQ(h.capacity_in_bytes(), 18u);
            BOOST_TEST_THROWS(
                h.append("X", "*"),
                std::length_error);
        }
        static_request_head h(buf, sizeof(buf));
        BOOST_TEST_EQ(h.buffer(), "GET / HTTP/1.1\r\n\r\n");
        BOOST_TEST_THROWS(
            h.append("X", "*"),
            std::length_error);
        h.set_target("/x");
        BOOST_TEST_EQ(h.buffer(), "GET /x HTTP/1.1\r\n\r\n");
    }

    void
    testFieldCapacity()
    {
        // the capacity is fixed: appends beyond it throw
        // and leave the contents unchanged
        alignas(4) char buf[96];
        static_request_head h(buf, sizeof(buf));
        for(int i = 0; i < 4; ++i)
            h.append("T", "*");
        auto const before = std::string(h.buffer());
        BOOST_TEST_THROWS(
            h.append("T", "*"),
            std::length_error);
        BOOST_TEST_EQ(h.buffer(), before);
        // free space released by an erase is reusable
        h.erase(h.begin());
        h.append("T", "*");
        BOOST_TEST_EQ(h.buffer(), before);
    }

    void
    testStartLine()
    {
        // the start line grows into the free field
        // capacity, and throws when the storage is
        // exhausted
        alignas(4) char buf[32];
        static_request_head h(buf, sizeof(buf));
        h.set_target("/abc");
        BOOST_TEST_EQ(h.buffer(), "GET /abc HTTP/1.1\r\n\r\n");
        BOOST_TEST_THROWS(
            h.set_target("/" + std::string(40, 'a')),
            std::length_error);
        BOOST_TEST_EQ(h.buffer(), "GET /abc HTTP/1.1\r\n\r\n");
    }

    void
    testStartLineExactFitEmpty()
    {
        // a start-line grow may fill the storage exactly,
        // leaving no free field capacity
        alignas(4) char buf[32];
        static_request_head h(buf, sizeof(buf));
        h.set_target("/23456789012345");
        BOOST_TEST_EQ(
            h.buffer(), "GET /23456789012345 HTTP/1.1\r\n\r\n");
        BOOST_TEST_THROWS(
            h.append("T", "*"),
            std::length_error);
        BOOST_TEST_EQ(
            h.buffer(), "GET /23456789012345 HTTP/1.1\r\n\r\n");
    }

    void
    testStartLineExactFit()
    {
        // with fields present, an exact-fit start-line
        // grow succeeds in place
        alignas(4) char buf[48];
        static_request_head h(buf, sizeof(buf));
        h.append("T", "*");
        h.set_target("/234567890123");
        BOOST_TEST_EQ(
            h.buffer(),
            "GET /234567890123 HTTP/1.1\r\n"
            "T: *\r\n"
            "\r\n");
        BOOST_TEST_THROWS(
            h.append("T", "*"),
            std::length_error);
    }

    void
    testCopyAssign()
    {
        // a copy whose start line is longer than the
        // reserved headroom repositions the split within
        // the fixed storage
        request_head src(http::method::post, "/x");
        src.set(http::field::content_length, "42");
        src.set(http::field::user_agent, "boost");

        alignas(4) char buf[128];
        static_request_head h(buf, sizeof(buf));
        h = src;
        BOOST_TEST_EQ(h.buffer(), src.buffer());
        BOOST_TEST(h.buffer().data() != src.buffer().data());
        BOOST_TEST(
            h.buffer().data() >= buf &&
            h.buffer().data() < buf + sizeof(buf));
        BOOST_TEST(h.method() == http::method::post);
        BOOST_TEST(h.content_length() == 42u);

        // assigning a default-constructed head copies
        // into the fixed storage instead of adopting the
        // shared read-only buffer
        h = request_head();
        BOOST_TEST_EQ(h.buffer(), "GET / HTTP/1.1\r\n\r\n");
        BOOST_TEST(
            h.buffer().data() >= buf &&
            h.buffer().data() < buf + sizeof(buf));
        h.append("T", "*");
        BOOST_TEST_EQ(h.buffer(), "GET / HTTP/1.1\r\nT: *\r\n\r\n");

        // static to static
        alignas(4) char buf2[64];
        static_request_head h2(buf2, sizeof(buf2));
        h2 = h;
        BOOST_TEST_EQ(h2.buffer(), h.buffer());
        BOOST_TEST(h2.buffer().data() != h.buffer().data());

        // self-assignment
        auto const& hr = h2;
        h2 = hr;
        BOOST_TEST_EQ(h2.buffer(), h.buffer());
    }

    void
    testCopyAssignOverflow()
    {
        // a copy that does not fit throws and leaves the
        // contents unchanged
        request_head big;
        big.set_target("/" + std::string(200, 'p'));

        alignas(4) char buf[64];
        static_request_head h(buf, sizeof(buf));
        h.append("T", "*");
        BOOST_TEST_THROWS(h = big, std::length_error);
        BOOST_TEST_EQ(h.buffer(), "GET / HTTP/1.1\r\nT: *\r\n\r\n");

        // a copy may fill the storage exactly, with the
        // repositioned start line consuming the free
        // field capacity
        request_head src(http::method::get, "/23456789012345");
        alignas(4) char buf2[32];
        static_request_head h2(buf2, sizeof(buf2));
        h2 = src;
        BOOST_TEST_EQ(h2.buffer(), src.buffer());
        BOOST_TEST_THROWS(
            h2.append("T", "*"),
            std::length_error);
    }

    void
    testMove()
    {
        alignas(4) char buf[64];
        static_request_head h1(buf, sizeof(buf));
        h1.set_target("/x");
        auto const* p = h1.buffer().data();
        static_request_head h2(std::move(h1));
        BOOST_TEST_EQ(h2.buffer(), "GET /x HTTP/1.1\r\n\r\n");
        BOOST_TEST_EQ(h2.buffer().data(), p);
        BOOST_TEST_EQ(h2.capacity_in_bytes(), 64u);
        // the moved-from object no longer refers to the
        // storage; modifiers and assignment throw
        BOOST_TEST(h1.buffer().data() != p);
        BOOST_TEST_EQ(h1.capacity_in_bytes(), 0u);
        BOOST_TEST_THROWS(
            h1.append("T", "*"),
            std::length_error);
        BOOST_TEST_THROWS(
            h1.set_target("/other"),
            std::length_error);
        BOOST_TEST_THROWS(h1 = h2, std::length_error);
        // a source whose start line is shorter than the
        // default one would fit the reported capacity of
        // the shared default buffer
        request_head h3;
        h3.set_start_line("A", "/");
        BOOST_TEST_THROWS(h1 = h3, std::length_error);
        BOOST_TEST_EQ(
            request_head().buffer(), "GET / HTTP/1.1\r\n\r\n");
    }

    void
    run()
    {
        testDefault();
        testAlignment();
        testTooSmall();
        testFieldCapacity();
        testStartLine();
        testStartLineExactFitEmpty();
        testStartLineExactFit();
        testCopyAssign();
        testCopyAssignOverflow();
        testMove();
    }
};

TEST_SUITE(static_request_head_test, "boost.burl.static_request_head");

} // namespace burl
} // namespace boost
