//
// Copyright (c) 2026 Mohammad Nejati
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

// Test that header file is self-contained.
#include <boost/burl/response_head.hpp>

#include <boost/burl/head_parser.hpp>

#include "test_suite.hpp"

#include <cstring>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <utility>

namespace boost
{
namespace burl
{

static_assert(std::is_nothrow_swappable_v<response_head>);

class response_head_test
{
public:
    void
    testDefault()
    {
        response_head h;
        BOOST_TEST_EQ(h.buffer(), "HTTP/1.1 200 OK\r\n\r\n");
        BOOST_TEST(h.status() == http::status::ok);
        BOOST_TEST_EQ(h.status_int(), 200);
        BOOST_TEST_EQ(h.reason(), "OK");
        BOOST_TEST(h.empty());
    }

    void
    testGrow()
    {
        response_head h;
        std::string expected = "HTTP/1.1 200 OK\r\n";
        for(int i = 0; i < 64; ++i)
        {
            auto const name  = "X-Field-" + std::to_string(i);
            auto const value = std::string(20, 'a' + (i % 26));
            h.append(name, value);
            expected += name + ": " + value + "\r\n";
        }
        expected += "\r\n";
        BOOST_TEST_EQ(h.size(), 64u);
        BOOST_TEST_EQ(h.buffer(), expected);
        BOOST_TEST_EQ(h.at("X-Field-0"), std::string(20, 'a'));
    }

    void
    testStartLineGrow()
    {
        // a long reason phrase forces the status line to
        // grow via realloc
        response_head h;
        h.append(http::field::server, "burl");
        auto const reason = std::string(4000, 'z');
        h.set_start_line(200, reason);
        BOOST_TEST_EQ(h.reason(), reason);
        BOOST_TEST_EQ(h.at(http::field::server), "burl");
        BOOST_TEST_EQ(
            h.buffer(),
            "HTTP/1.1 200 " + reason + "\r\n"
            "Server: burl\r\n"
            "\r\n");
    }

    // A default-constructed head views shared immutable
    // storage, so a status-line change must copy out of it
    // before writing. Every path leaves the shared bytes
    // pristine, and a rejected change does not allocate.
    void
    testStartLineDefaultStorage()
    {
        // a shorter status line shrinks in place
        {
            response_head h;
            BOOST_TEST_EQ(h.capacity_in_bytes(), 0u);
            h.set_start_line(404, "");
            BOOST_TEST_EQ(h.buffer(), "HTTP/1.1 404 \r\n\r\n");
        }
        // a longer one reallocates
        {
            response_head h;
            auto const reason = std::string(4000, 'z');
            h.set_start_line(500, reason);
            BOOST_TEST_EQ(
                h.buffer(),
                "HTTP/1.1 500 " + reason + "\r\n"
                "\r\n");
        }
        // a rejected change keeps the head on the shared
        // storage instead of leaving a detached buffer
        response_head g;
        BOOST_TEST_THROWS(
            g.set_start_line(200, std::string(70000, 'z')),
            std::length_error);
        BOOST_TEST_EQ(g.capacity_in_bytes(), 0u);
        // the shared storage was never written through
        BOOST_TEST_EQ(g.buffer(), "HTTP/1.1 200 OK\r\n\r\n");
    }

    // The status line has its own 16-bit size limit,
    // independent of the buffer limit; exceeding it
    // throws and leaves the head unchanged.
    void
    testStartLineLimits()
    {
        response_head h;
        h.append(http::field::server, "burl");
        BOOST_TEST_THROWS(
            h.set_start_line(
                404,
                std::string(
                    response_head::max_start_line_size, 'z')),
            std::length_error);
        // the failed operation leaves the head unchanged
        BOOST_TEST_EQ(h.status_int(), 200);
        BOOST_TEST_EQ(
            h.buffer(),
            "HTTP/1.1 200 OK\r\n"
            "Server: burl\r\n"
            "\r\n");

        // the limit covers the whole line, not the reason
        // alone: "HTTP/1.1 200 " + reason + "\r\n" spends
        // 15 bytes on everything but the reason
        auto const room = response_head::max_start_line_size -
            std::strlen("HTTP/1.1 200 \r\n");
        response_head g;
        g.set_start_line(404, std::string(room, 'z'));
        BOOST_TEST_EQ(g.reason().size(), room);
        // one byte more does not fit
        BOOST_TEST_THROWS(
            g.set_start_line(200, std::string(room + 1, 'z')),
            std::length_error);
        BOOST_TEST_EQ(g.status_int(), 404);
        BOOST_TEST_EQ(g.reason().size(), room);
        // a shrink is never refused
        g.set_start_line(200, "OK");
        BOOST_TEST_EQ(
            g.buffer(), "HTTP/1.1 200 OK\r\n\r\n");

        // a status code outside [100, 999] is refused
        // and leaves the head unchanged
        response_head r;
        r.append(http::field::server, "burl");
        BOOST_TEST_THROWS(
            r.set_start_line(99, "Low"), std::invalid_argument);
        BOOST_TEST_THROWS(
            r.set_start_line(1000, "High"), std::invalid_argument);
        BOOST_TEST_EQ(r.status_int(), 200);
        BOOST_TEST_EQ(
            r.buffer(),
            "HTTP/1.1 200 OK\r\n"
            "Server: burl\r\n"
            "\r\n");
    }

    // Start-line setters accept arguments viewing the
    // start line itself.
    void
    testStartLineSelfReference()
    {
        response_head h;
        h.append(http::field::server, "burl");
        h.set_start_line(200, "Everything Is Fine");
        h.set_start_line(500, h.reason());
        BOOST_TEST_EQ(h.status_int(), 500);
        BOOST_TEST_EQ(h.reason(), "Everything Is Fine");

        // shrink to a prefix of the old reason
        h.set_start_line(404, h.reason().substr(0, 10));
        BOOST_TEST_EQ(h.reason(), "Everything");
        BOOST_TEST_EQ(
            h.buffer(),
            "HTTP/1.1 404 Everything\r\n"
            "Server: burl\r\n"
            "\r\n");
    }

    void
    testMove()
    {
        response_head h1;
        h1.set_status(http::status::not_found);
        h1.append(http::field::server, "burl");
        auto const before = std::string(h1.buffer());

        response_head h2(std::move(h1));
        BOOST_TEST_EQ(h2.buffer(), before);
        BOOST_TEST_EQ(h2.status_int(), 404);

        response_head h3;
        h3.append(http::field::server, "other");
        h1 = std::move(h3);
        BOOST_TEST_EQ(h1.at(http::field::server), "other");
    }

    void
    testSwap()
    {
        {
            response_head h1;
            h1.set_status(http::status::not_found);
            h1.append(http::field::server, "a");
            h1.set_content_length(7);
            response_head h2;
            h2.append(http::field::server, "b");
            h2.set_chunked(true);
            auto const cap1 = h1.capacity_in_bytes();
            auto const cap2 = h2.capacity_in_bytes();
            // a view follows the contents into the
            // other header
            auto const v1 = h1.at(http::field::server);

            h1.swap(h2);

            // the status line, the fields, and the cached
            // metadata all move together
            BOOST_TEST_EQ(h1.status_int(), 200);
            BOOST_TEST_EQ(h1.at(http::field::server), "b");
            BOOST_TEST(h1.chunked());
            BOOST_TEST(! h1.content_length().has_value());
            BOOST_TEST_EQ(h1.capacity_in_bytes(), cap2);

            BOOST_TEST_EQ(h2.status_int(), 404);
            BOOST_TEST(h2.status() == http::status::not_found);
            BOOST_TEST_EQ(h2.at(http::field::server), "a");
            BOOST_TEST(! h2.chunked());
            BOOST_TEST_EQ(h2.content_length().value(), 7u);
            BOOST_TEST_EQ(h2.capacity_in_bytes(), cap1);

            BOOST_TEST_EQ(v1, "a");

            // both headers remain usable
            h1.set_status(http::status::accepted);
            h2.append(http::field::date, "now");
            BOOST_TEST_EQ(h1.status_int(), 202);
            BOOST_TEST_EQ(h2.at(http::field::date), "now");
        }

        // ADL and std::swap find the hidden friend
        {
            response_head h1(http::status::not_found);
            response_head h2;
            swap(h1, h2);
            BOOST_TEST_EQ(h1.buffer(), "HTTP/1.1 200 OK\r\n\r\n");
            BOOST_TEST_EQ(
                h2.buffer(), "HTTP/1.1 404 Not Found\r\n\r\n");
            std::swap(h1, h2);
            BOOST_TEST_EQ(
                h1.buffer(), "HTTP/1.1 404 Not Found\r\n\r\n");
        }

        // swapping with a default header transfers the
        // allocation and the shared static buffer
        {
            response_head h1(http::status::not_found);
            response_head h2;
            auto const cap1 = h1.capacity_in_bytes();
            h1.swap(h2);
            BOOST_TEST_EQ(h1.buffer(), "HTTP/1.1 200 OK\r\n\r\n");
            BOOST_TEST_EQ(h1.capacity_in_bytes(), 0u);
            BOOST_TEST_EQ(
                h2.buffer(), "HTTP/1.1 404 Not Found\r\n\r\n");
            BOOST_TEST_EQ(h2.capacity_in_bytes(), cap1);

            // the header which received the static buffer
            // allocates on its next modification, and the
            // start-line headroom moves with it
            h1.set_status(http::status::service_unavailable);
            BOOST_TEST_EQ(
                h1.buffer(),
                "HTTP/1.1 503 Service Unavailable\r\n\r\n");
        }

        // two default headers
        {
            response_head h1;
            response_head h2;
            h1.swap(h2);
            BOOST_TEST_EQ(h1.buffer(), "HTTP/1.1 200 OK\r\n\r\n");
            BOOST_TEST_EQ(h1.capacity_in_bytes(), 0u);
            BOOST_TEST_EQ(h2.buffer(), "HTTP/1.1 200 OK\r\n\r\n");
            BOOST_TEST_EQ(h2.capacity_in_bytes(), 0u);
        }

        // self-swap has no effect
        {
            response_head h(http::status::not_found);
            h.append(http::field::server, "a");
            auto& hr = h;
            h.swap(hr);
            BOOST_TEST_EQ(
                h.buffer(),
                "HTTP/1.1 404 Not Found\r\n"
                "Server: a\r\n"
                "\r\n");
        }
    }

    void
    testCopy()
    {
        response_head h1;
        h1.set_status(http::status::not_found);
        h1.append(http::field::server, "burl");

        response_head h2(h1);
        BOOST_TEST_EQ(h2.buffer(), h1.buffer());
        BOOST_TEST(h2.buffer().data() != h1.buffer().data());

        h1.set_status(http::status::ok);
        BOOST_TEST_EQ(h2.status_int(), 404);
        BOOST_TEST_EQ(
            h2.buffer(),
            "HTTP/1.1 404 Not Found\r\n"
            "Server: burl\r\n"
            "\r\n");
    }

    void
    testAssign()
    {
        response_head h1;
        h1.append(http::field::server, "a");
        response_head h2;
        h2.set_status(http::status::accepted);
        h2.append(http::field::server, "b");

        h1 = h2; // copy
        BOOST_TEST_EQ(h1.buffer(), h2.buffer());
        BOOST_TEST(h1.buffer().data() != h2.buffer().data());

        // self copy-assignment is a no-op
        auto const& hr = h1;
        h1 = hr;
        BOOST_TEST_EQ(h1.buffer(), h2.buffer());

        response_head h3;
        h3.set_status(http::status::no_content);
        h1 = std::move(h3); // move
        BOOST_TEST_EQ(h1.status_int(), 204);

        // self move-assignment is a no-op
        auto& hm = h1;
        h1       = std::move(hm);
        BOOST_TEST_EQ(h1.status_int(), 204);
    }

    void
    testReserveShrink()
    {
        response_head h;
        h.reserve(4096, 32);
        BOOST_TEST(h.capacity_in_bytes() >= 4096u);
        h.append(http::field::server, "burl");
        h.shrink_to_fit();
        BOOST_TEST(h.capacity_in_bytes() < 4096u);
        BOOST_TEST_EQ(h.at(http::field::server), "burl");

        // the fit is exact: reserving room for what the
        // head already holds lands on the same allocation
        response_head g;
        auto const prefix = g.buffer().size() - 2;
        g.reserve(h.buffer().size() - prefix, h.size());
        BOOST_TEST_EQ(
            h.capacity_in_bytes(), g.capacity_in_bytes());

        // a second call has nothing left to do
        auto const* data = h.buffer().data();
        h.shrink_to_fit();
        BOOST_TEST(h.buffer().data() == data);
        BOOST_TEST_EQ(
            h.buffer(),
            "HTTP/1.1 200 OK\r\n"
            "Server: burl\r\n"
            "\r\n");
    }

    void
    testSetVersion()
    {
        // the version is written in place; nothing
        // else moves
        response_head h;
        h.set_start_line(404, "Not Found");
        h.append(http::field::server, "burl");
        h.set_version(http::version::http_1_0);
        BOOST_TEST(h.version() == http::version::http_1_0);
        BOOST_TEST_EQ(
            h.buffer(),
            "HTTP/1.0 404 Not Found\r\n"
            "Server: burl\r\n"
            "\r\n");
        h.set_version(http::version::http_1_1);
        BOOST_TEST_EQ(
            h.buffer(),
            "HTTP/1.1 404 Not Found\r\n"
            "Server: burl\r\n"
            "\r\n");

        // a default-constructed head detaches from the
        // shared storage before writing
        response_head g;
        BOOST_TEST_EQ(g.capacity_in_bytes(), 0u);
        g.set_version(http::version::http_1_0);
        BOOST_TEST_EQ(g.buffer(), "HTTP/1.0 200 OK\r\n\r\n");
        BOOST_TEST(g.capacity_in_bytes() > 0u);
        // the shared storage was never written through
        response_head fresh;
        BOOST_TEST_EQ(fresh.buffer(), "HTTP/1.1 200 OK\r\n\r\n");

        // with a framed payload, keep-alive follows
        // the version
        g.set_content_length(0);
        BOOST_TEST(! g.keep_alive());
        g.set_version(http::version::http_1_1);
        BOOST_TEST(g.keep_alive());
    }

    void
    testClear()
    {
        // the status line survives; the fields and
        // the state derived from them do not
        response_head h;
        h.set_start_line(
            404, "Not Found", http::version::http_1_0);
        h.set_content_length(5);
        h.set_keep_alive(true);
        BOOST_TEST(h.keep_alive());
        auto const cap = h.capacity_in_bytes();

        h.clear();
        BOOST_TEST(h.empty());
        BOOST_TEST_EQ(h.buffer(), "HTTP/1.0 404 Not Found\r\n\r\n");
        BOOST_TEST_EQ(h.status_int(), 404);
        BOOST_TEST(h.version() == http::version::http_1_0);
        BOOST_TEST_EQ(h.capacity_in_bytes(), cap);
        BOOST_TEST(! h.content_length().has_value());
        BOOST_TEST(h.payload() == http::payload::to_eof);
        BOOST_TEST(! h.keep_alive());
    }

    // Snapshot a non-owning response_head_base (as produced by
    // head_parser over an external buffer) into an owner.
    void
    testFromBase()
    {
        static_assert(std::is_convertible_v<
            response_head_base const&, response_head>);

        alignas(4) char buf[4096];
        std::string_view const msg =
            "HTTP/1.1 404 Not Found\r\n"
            "Server: burl\r\n"
            "Content-Length: 0\r\n"
            "\r\n";
        auto const parse =
            [&](head_parser& pr)
            {
                std::memcpy(buf, msg.data(), msg.size());
                system::error_code ec;
                pr.parse(msg.size(), ec);
                BOOST_TEST(!ec);
            };

        head_parser pr(false, buf, sizeof(buf));
        parse(pr);
        response_head_base const& base = pr.response_head();

        // lossless, implicit construction from the base
        response_head h = base;
        BOOST_TEST_EQ(h.buffer(), msg);
        BOOST_TEST(h.status() == http::status::not_found);
        BOOST_TEST_EQ(h.status_int(), 404);
        BOOST_TEST_EQ(h.reason(), "Not Found");
        BOOST_TEST_EQ(h.at(http::field::server), "burl");
        // independent storage
        BOOST_TEST(h.buffer().data() != base.buffer().data());

        // clobbering the parse buffer leaves the snapshot intact
        std::memset(buf, 'Z', msg.size());
        BOOST_TEST_EQ(h.reason(), "Not Found");
        BOOST_TEST_EQ(h.at(http::field::server), "burl");

        // assignment from a base replaces prior contents
        response_head g;
        g.append(http::field::server, "old");
        head_parser pr2(false, buf, sizeof(buf));
        parse(pr2);
        g = pr2.response_head();
        BOOST_TEST_EQ(g.buffer(), msg);
        BOOST_TEST(g.buffer().data() != buf);
        BOOST_TEST_EQ(g.count(http::field::server), 1u);
    }

    // Framing metadata cached in the header must follow the
    // content through assignment from a parsed base, on both
    // the reallocating and the in-place path.
    void
    testFromBaseFraming()
    {
        alignas(4) char buf[4096];
        std::string_view const msg =
            "HTTP/1.1 200 Fine and Dandy\r\n"
            "Connection: close\r\n"
            "Transfer-Encoding: chunked\r\n"
            "\r\n";
        head_parser pr(false, buf, sizeof(buf));
        std::memcpy(buf, msg.data(), msg.size());
        system::error_code ec;
        pr.parse(msg.size(), ec);
        BOOST_TEST(!ec);
        response_head_base const& base = pr.response_head();

        // small target: the assignment reallocates
        response_head h1;
        h1 = base;
        BOOST_TEST_EQ(h1.buffer(), msg);
        BOOST_TEST(h1.status() == http::status::ok);
        BOOST_TEST_EQ(h1.status_int(), 200);
        BOOST_TEST_EQ(h1.reason(), "Fine and Dandy");
        BOOST_TEST(h1.chunked());
        BOOST_TEST(! h1.keep_alive());
        BOOST_TEST(h1.version() == http::version::http_1_1);

        // large target: the allocation is reused, and the
        // cached metadata is replaced all the same
        response_head h2;
        h2.reserve(512, 16);
        h2.set_content_length(42);
        BOOST_TEST(h2.content_length().has_value());
        h2 = base;
        BOOST_TEST_EQ(h2.buffer(), msg);
        BOOST_TEST(h2.capacity_in_bytes() > 400u);
        BOOST_TEST(h2.chunked());
        BOOST_TEST(! h2.content_length().has_value());
        BOOST_TEST(! h2.keep_alive());
        BOOST_TEST_EQ(h2.status_int(), 200);
        BOOST_TEST_EQ(h2.reason(), "Fine and Dandy");
    }

    // Growing the start line in place must never leave the
    // remaining field capacity equal to the internal
    // non-owning marker, which would silently leak the
    // allocation.
    void
    testStartLineOwnership()
    {
        response_head h;
        // 17 -> 22 bytes over the minimal allocation
        h.set_start_line(http::status::created);
        BOOST_TEST_EQ(h.buffer(), "HTTP/1.1 201 Created\r\n\r\n");
        BOOST_TEST(h.capacity_in_bytes() != 0u);
        h.append(http::field::age, "1");
        BOOST_TEST_EQ(h.at(http::field::age), "1");

        // ownership transfers on move
        response_head g(std::move(h));
        BOOST_TEST_EQ(g.at(http::field::age), "1");
        BOOST_TEST_EQ(g.status_int(), 201);
        BOOST_TEST_EQ(h.buffer(), "HTTP/1.1 200 OK\r\n\r\n");
    }

    void
    run()
    {
        testDefault();
        testGrow();
        testStartLineGrow();
        testStartLineDefaultStorage();
        testStartLineLimits();
        testStartLineOwnership();
        testStartLineSelfReference();
        testMove();
        testSwap();
        testCopy();
        testAssign();
        testReserveShrink();
        testSetVersion();
        testClear();
        testFromBase();
        testFromBaseFraming();
    }
};

TEST_SUITE(response_head_test, "boost.burl.response_head");

} // namespace burl
} // namespace boost
