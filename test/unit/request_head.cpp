//
// Copyright (c) 2026 Mohammad Nejati
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

// Test that header file is self-contained.
#include <boost/burl/request_head.hpp>

#include <boost/burl/head_parser.hpp>

#include "test_suite.hpp"

#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <utility>

namespace boost
{
namespace burl
{

static_assert(std::is_nothrow_swappable_v<request_head>);

class request_head_test
{
public:
    void
    testDefault()
    {
        request_head h;
        BOOST_TEST_EQ(h.buffer(), "GET / HTTP/1.1\r\n\r\n");
        BOOST_TEST(h.method() == http::method::get);
        BOOST_TEST(h.version() == http::version::http_1_1);
        BOOST_TEST(h.empty());

        // shrink_to_fit on the shared storage is a
        // no-op
        h.shrink_to_fit();
        BOOST_TEST_EQ(h.capacity_in_bytes(), 0u);
        BOOST_TEST_EQ(h.target(), "/");
    }

    void
    testGrow()
    {
        // append far more than the initial allocation
        // can hold, forcing several reallocations
        request_head h;
        std::string expected = "GET / HTTP/1.1\r\n";
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
        // a value survives the reallocations intact
        BOOST_TEST_EQ(
            h.at("X-Field-0"), std::string(20, 'a'));
        BOOST_TEST_EQ(
            h.at("X-Field-63"), std::string(20, 'a' + (63 % 26)));
    }

    void
    testStartLineGrow()
    {
        // a target far larger than the initial buffer
        // forces the start line to grow via realloc
        request_head h;
        h.append(http::field::host, "example.com");
        auto const target = "/" + std::string(4000, 'p');
        h.set_target(target);
        BOOST_TEST_EQ(h.target(), target);
        BOOST_TEST_EQ(h.at(http::field::host), "example.com");
        BOOST_TEST_EQ(
            h.buffer(),
            "GET " + target + " HTTP/1.1\r\n"
            "Host: example.com\r\n"
            "\r\n");
    }

    // Growing the start line of a head with no fields
    // must not land the field capacity exactly on the
    // internal non-owning marker: the buffer would be
    // disowned and silently leak.
    void
    testStartLineGrowEmpty()
    {
        request_head h;
        h.set_target("/some/self-contained-target");
        BOOST_TEST(h.capacity_in_bytes() > 0u);
        h.append(http::field::host, "example.com");
        BOOST_TEST_EQ(
            h.buffer(),
            "GET /some/self-contained-target HTTP/1.1\r\n"
            "Host: example.com\r\n"
            "\r\n");
    }

    // A start-line grow far beyond the current allocation
    // reallocates and carries the field section with it,
    // and the following shrink slides it back.
    void
    testStartLineLargeGrow()
    {
        request_head h;
        h.reserve(64, 1);
        h.append(http::field::host, "example.com");
        auto const target = "/" + std::string(45000, 'p');
        h.set_target(target);
        BOOST_TEST_EQ(h.target(), target);
        BOOST_TEST_EQ(h.at(http::field::host), "example.com");
        h.set_target("/short");
        BOOST_TEST_EQ(h.target(), "/short");
        BOOST_TEST_EQ(
            h.buffer(),
            "GET /short HTTP/1.1\r\n"
            "Host: example.com\r\n"
            "\r\n");
    }

    // A default-constructed head views shared immutable
    // storage, so a start-line change must copy out of it
    // before writing. Every path leaves the shared bytes
    // pristine, and a rejected change does not allocate.
    void
    testStartLineDefaultStorage()
    {
        // a same-size replacement takes the in-place path
        {
            request_head h;
            BOOST_TEST_EQ(h.capacity_in_bytes(), 0u);
            h.set_method("PUT");
            BOOST_TEST_EQ(h.buffer(), "PUT / HTTP/1.1\r\n\r\n");
        }
        // a shorter start line shrinks in place
        {
            request_head h;
            h.set_start_line("A", "/");
            BOOST_TEST_EQ(h.buffer(), "A / HTTP/1.1\r\n\r\n");
        }
        // a longer one reallocates
        {
            request_head h;
            auto const target = "/" + std::string(4000, 'q');
            h.set_target(target);
            BOOST_TEST_EQ(
                h.buffer(),
                "GET " + target + " HTTP/1.1\r\n"
                "\r\n");
        }
        // a rejected change keeps the head on the shared
        // storage instead of leaving a detached buffer
        request_head g;
        BOOST_TEST_THROWS(
            g.set_target(std::string(70000, 'q')),
            std::length_error);
        BOOST_TEST_EQ(g.capacity_in_bytes(), 0u);
        // the shared storage was never written through
        BOOST_TEST_EQ(g.buffer(), "GET / HTTP/1.1\r\n\r\n");
    }

    // The start line has its own 16-bit size limit,
    // independent of the buffer limit; exceeding it
    // throws and leaves the head unchanged.
    void
    testStartLineLimits()
    {
        std::string const big(
            request_head::max_start_line_size + 1, 'p');

        request_head h;
        h.append(http::field::host, "example.com");
        BOOST_TEST_THROWS(h.set_target(big), std::length_error);
        BOOST_TEST_THROWS(h.set_method(big), std::length_error);
        BOOST_TEST_THROWS(
            h.set_start_line(http::method::get, big),
            std::length_error);
        BOOST_TEST_THROWS(
            h.set_start_line(big, "/"), std::length_error);
        // failed operations leave the head unchanged
        BOOST_TEST_EQ(
            h.buffer(),
            "GET / HTTP/1.1\r\n"
            "Host: example.com\r\n"
            "\r\n");

        // the limit covers the whole line, not the target
        // alone: "GET " + target + " HTTP/1.1\r\n" spends
        // 15 bytes on everything but the target
        auto const room = request_head::max_start_line_size -
            std::strlen("GET  HTTP/1.1\r\n");
        request_head g;
        g.set_target("/" + std::string(room - 1, 'p'));
        BOOST_TEST_EQ(g.target().size(), room);
        // one byte more does not fit
        BOOST_TEST_THROWS(
            g.set_target("/" + std::string(room, 'p')),
            std::length_error);
        BOOST_TEST_EQ(g.target().size(), room);
        // a shrink is never refused
        g.set_target("/");
        BOOST_TEST_EQ(
            g.buffer(), "GET / HTTP/1.1\r\n\r\n");
    }

    // Arguments viewing the start line remain valid to
    // pass to append and set, including when the call
    // reallocates the buffer.
    void
    testSelfReference()
    {
        request_head h;
        h.append(http::field::host, "example.com");
        h.set_target("/self-referenced-target");
        h.shrink_to_fit();
        // the append reallocates while the value
        // views the start line
        h.append("X-Original-Uri", h.target());
        BOOST_TEST_EQ(
            h.at("X-Original-Uri"), "/self-referenced-target");

        // from the method text
        h.append("X-Method", h.method_text());
        BOOST_TEST_EQ(h.at("X-Method"), "GET");

        // the replacement reallocates while the new
        // value views the start line
        h.set(http::field::host, "h");
        h.shrink_to_fit();
        h.set(http::field::host, h.target());
        BOOST_TEST_EQ(
            h.at(http::field::host), "/self-referenced-target");
    }

    // Start-line setters accept arguments viewing the
    // start line itself, in every splice path.
    void
    testStartLineSelfReference()
    {
        // in place, same size
        request_head h;
        h.append(http::field::host, "example.com");
        h.set_target("/self-aliased-target");
        h.set_target(h.target());
        BOOST_TEST_EQ(h.target(), "/self-aliased-target");

        // shrink to a suffix of the old target
        h.set_target(h.target().substr(6));
        BOOST_TEST_EQ(h.target(), "aliased-target");

        // the start line grows in place while the argument
        // views the old target
        h.reserve(1024, 8);
        h.set_start_line(
            "LONGER-METHOD",
            h.target(),
            http::version::http_1_1);
        BOOST_TEST_EQ(h.method_text(), "LONGER-METHOD");
        BOOST_TEST_EQ(h.target(), "aliased-target");

        // the head before the splice point stays put while
        // the argument views it
        request_head h2;
        h2.reserve(64, 1);
        h2.set_target(h2.method_text());
        BOOST_TEST_EQ(h2.buffer(), "GET GET HTTP/1.1\r\n\r\n");

        // the start line grows into the free space beyond
        // the field section, shifting it along
        request_head h3;
        h3.reserve(1024, 8);
        h3.append(http::field::host, "example.com");
        h3.set_target("/mid-path-target");
        h3.set_start_line(
            "LONGER-METHOD",
            h3.target(),
            http::version::http_1_1);
        BOOST_TEST_EQ(h3.target(), "/mid-path-target");
        BOOST_TEST_EQ(
            h3.buffer(),
            "LONGER-METHOD /mid-path-target HTTP/1.1\r\n"
            "Host: example.com\r\n"
            "\r\n");

        // the method argument sources from inside the
        // target's destination: it must be copied first
        request_head h5;
        h5.reserve(64, 1);
        h5.set_target("/old");
        h5.set_start_line(
            h5.method_text(),
            "/considerably-longer-target",
            http::version::http_1_1);
        BOOST_TEST_EQ(
            h5.buffer(),
            "GET /considerably-longer-target HTTP/1.1\r\n"
            "\r\n");

        // likewise through a reallocation
        request_head h6;
        h6.set_target("/old");
        h6.shrink_to_fit();
        h6.set_start_line(
            h6.method_text(),
            "/considerably-longer-target",
            http::version::http_1_1);
        BOOST_TEST_EQ(
            h6.buffer(),
            "GET /considerably-longer-target HTTP/1.1\r\n"
            "\r\n");

        // the mirrored direction: the target argument
        // shrinks while the method grows
        h6.set_start_line(
            "DELETE",
            h6.target().substr(0, 13),
            http::version::http_1_1);
        BOOST_TEST_EQ(
            h6.buffer(),
            "DELETE /considerably HTTP/1.1\r\n"
            "\r\n");

        // shrink to a leading substring of the old target:
        // the head move lands on the argument's bytes,
        // which are salvaged first
        request_head h7;
        h7.append(http::field::host, "example.com");
        h7.set_target("/salvaged-target");
        h7.set_target(h7.target().substr(0, 9));
        BOOST_TEST_EQ(h7.target(), "/salvaged");
        // and to an interior substring
        h7.set_target(h7.target().substr(1, 4));
        BOOST_TEST_EQ(h7.target(), "salv");
        BOOST_TEST_EQ(
            h7.buffer(),
            "GET salv HTTP/1.1\r\n"
            "Host: example.com\r\n"
            "\r\n");

        // the grow reallocates while the argument views
        // the old buffer
        request_head h4;
        h4.append(http::field::host, "example.com");
        h4.set_target("/slow-path-target");
        h4.shrink_to_fit();
        h4.set_start_line(
            "A-MUCH-LONGER-CUSTOM-METHOD",
            h4.target(),
            http::version::http_1_0);
        BOOST_TEST_EQ(h4.target(), "/slow-path-target");
        BOOST_TEST_EQ(h4.at(http::field::host), "example.com");
        BOOST_TEST_EQ(
            h4.buffer(),
            "A-MUCH-LONGER-CUSTOM-METHOD /slow-path-target HTTP/1.0\r\n"
            "Host: example.com\r\n"
            "\r\n");
    }

    void
    testMove()
    {
        request_head h1;
        h1.set_target("/x");
        h1.append(http::field::host, "example.com");
        auto const before = std::string(h1.buffer());

        request_head h2(std::move(h1));
        BOOST_TEST_EQ(h2.buffer(), before);
        BOOST_TEST_EQ(h2.at(http::field::host), "example.com");
        BOOST_TEST_EQ(h2.method_text(), "GET");
        BOOST_TEST_EQ(h2.target(), "/x");

        // the moved-from object is left default-constructed
        BOOST_TEST_EQ(h1.buffer(), "GET / HTTP/1.1\r\n\r\n");
        BOOST_TEST_EQ(h1.method_text(), "GET");
        BOOST_TEST_EQ(h1.target(), "/");

        // the moved-from object is destructible and can
        // be reassigned
        request_head h3;
        h3.append(http::field::host, "other");
        h1 = std::move(h3);
        BOOST_TEST_EQ(h1.at(http::field::host), "other");
    }

    void
    testMoveAssign()
    {
        request_head h1;
        h1.append(http::field::host, "a");
        request_head h2;
        h2.append(http::field::host, "b");
        h2.append(http::field::accept, "*/*");

        h1 = std::move(h2);
        BOOST_TEST_EQ(
            h1.buffer(),
            "GET / HTTP/1.1\r\n"
            "Host: b\r\n"
            "Accept: */*\r\n"
            "\r\n");

        // self move-assignment is a no-op
        auto& hr = h1;
        h1       = std::move(hr);
        BOOST_TEST_EQ(h1.at(http::field::host), "b");
    }

    void
    testSwap()
    {
        {
            request_head h1(http::method::post, "/a");
            h1.append(http::field::host, "a.example");
            h1.set_content_length(7);
            request_head h2;
            h2.append(http::field::host, "b.example");
            h2.set_chunked(true);
            auto const cap1 = h1.capacity_in_bytes();
            auto const cap2 = h2.capacity_in_bytes();
            // a view follows the contents into the
            // other header
            auto const v1 = h1.at(http::field::host);

            h1.swap(h2);

            // the start line, the fields, and the cached
            // metadata all move together
            BOOST_TEST_EQ(h1.method_text(), "GET");
            BOOST_TEST_EQ(h1.target(), "/");
            BOOST_TEST_EQ(h1.at(http::field::host), "b.example");
            BOOST_TEST(h1.chunked());
            BOOST_TEST(! h1.content_length().has_value());
            BOOST_TEST_EQ(h1.capacity_in_bytes(), cap2);

            BOOST_TEST(h2.method() == http::method::post);
            BOOST_TEST_EQ(h2.target(), "/a");
            BOOST_TEST_EQ(h2.at(http::field::host), "a.example");
            BOOST_TEST(! h2.chunked());
            BOOST_TEST_EQ(h2.content_length().value(), 7u);
            BOOST_TEST_EQ(h2.capacity_in_bytes(), cap1);

            BOOST_TEST_EQ(v1, "a.example");

            // both headers remain usable
            h1.set_target("/b");
            h2.append(http::field::accept, "*/*");
            BOOST_TEST_EQ(h1.target(), "/b");
            BOOST_TEST_EQ(h2.at(http::field::accept), "*/*");
        }

        // ADL and std::swap find the hidden friend
        {
            request_head h1(http::method::put, "/x");
            request_head h2;
            swap(h1, h2);
            BOOST_TEST_EQ(h1.buffer(), "GET / HTTP/1.1\r\n\r\n");
            BOOST_TEST_EQ(h2.buffer(), "PUT /x HTTP/1.1\r\n\r\n");
            std::swap(h1, h2);
            BOOST_TEST_EQ(h1.buffer(), "PUT /x HTTP/1.1\r\n\r\n");
        }

        // swapping with a default header transfers the
        // allocation and the shared static buffer
        {
            request_head h1(http::method::post, "/a");
            request_head h2;
            auto const cap1 = h1.capacity_in_bytes();
            h1.swap(h2);
            BOOST_TEST_EQ(h1.buffer(), "GET / HTTP/1.1\r\n\r\n");
            BOOST_TEST_EQ(h1.capacity_in_bytes(), 0u);
            BOOST_TEST_EQ(h2.buffer(), "POST /a HTTP/1.1\r\n\r\n");
            BOOST_TEST_EQ(h2.capacity_in_bytes(), cap1);

            // the header which received the static buffer
            // allocates on its next modification, and the
            // start-line headroom moves with it
            h1.set_target("/longer-target");
            BOOST_TEST_EQ(
                h1.buffer(), "GET /longer-target HTTP/1.1\r\n\r\n");
        }

        // two default headers
        {
            request_head h1;
            request_head h2;
            h1.swap(h2);
            BOOST_TEST_EQ(h1.buffer(), "GET / HTTP/1.1\r\n\r\n");
            BOOST_TEST_EQ(h1.capacity_in_bytes(), 0u);
            BOOST_TEST_EQ(h2.buffer(), "GET / HTTP/1.1\r\n\r\n");
            BOOST_TEST_EQ(h2.capacity_in_bytes(), 0u);
        }

        // self-swap has no effect
        {
            request_head h(http::method::post, "/a");
            h.append(http::field::host, "a.example");
            auto& hr = h;
            h.swap(hr);
            BOOST_TEST_EQ(
                h.buffer(),
                "POST /a HTTP/1.1\r\n"
                "Host: a.example\r\n"
                "\r\n");
        }
    }

    void
    testCopy()
    {
        request_head h1;
        h1.set_target("/orig");
        h1.append(http::field::host, "example.com");

        request_head h2(h1);
        BOOST_TEST_EQ(h2.buffer(), h1.buffer());
        // independent storage
        BOOST_TEST(h2.buffer().data() != h1.buffer().data());

        // mutating the original leaves the copy intact
        h1.set_target("/changed");
        h1.append(http::field::accept, "*/*");
        BOOST_TEST_EQ(h2.target(), "/orig");
        BOOST_TEST_EQ(
            h2.buffer(),
            "GET /orig HTTP/1.1\r\n"
            "Host: example.com\r\n"
            "\r\n");

        // framing metadata is preserved on the copy, and
        // mutating the copy's framing leaves the original
        // untouched
        request_head h3(http::method::post, "/u");
        h3.set_content_length(7);
        h3.set_keep_alive(false);
        h3.set_expect_100_continue(true);
        request_head h4(h3);
        BOOST_TEST(h4.content_length().has_value());
        BOOST_TEST_EQ(*h4.content_length(), 7u);
        BOOST_TEST(! h4.keep_alive());
        BOOST_TEST(h4.expect_100_continue());
        BOOST_TEST_EQ(h4.buffer(), h3.buffer());
        h4.set_chunked(true);
        BOOST_TEST(h4.chunked());
        BOOST_TEST(! h3.chunked());
        BOOST_TEST(h3.content_length().has_value());
    }

    void
    testCopyAssign()
    {
        request_head h1;
        h1.append(http::field::host, "a");
        request_head h2;
        h2.set_target("/y");
        h2.append(http::field::accept, "*/*");

        h1 = h2;
        BOOST_TEST_EQ(h1.buffer(), h2.buffer());
        BOOST_TEST(h1.buffer().data() != h2.buffer().data());

        // self copy-assignment is a no-op
        auto const& hr = h1;
        h1 = hr;
        BOOST_TEST_EQ(h1.target(), "/y");

        // an assignment never releases the storage: from a
        // default-constructed head it reallocates only when
        // the start-line headroom shrank below the default
        // request line
        request_head h3;
        h3.set_start_line("A", "/", http::version::http_1_0);
        h3.append(http::field::host, std::string(100, 'x'));
        h3.erase(http::field::host);
        h3.shrink_to_fit();
        request_head h4;
        h3 = h4;
        BOOST_TEST_EQ(h3.buffer(), "GET / HTTP/1.1\r\n\r\n");
        BOOST_TEST(h3.method() == http::method::get);
        BOOST_TEST(h3.capacity_in_bytes() > 0);
        h3.append(http::field::accept, "*/*");
        BOOST_TEST_EQ(h3.at(http::field::accept), "*/*");

        // otherwise the capacity is kept
        request_head h5(http::method::post, "/some/target");
        h5.append(http::field::host, "example.com");
        auto const h5cap = h5.capacity_in_bytes();
        h5 = h4;
        BOOST_TEST_EQ(h5.buffer(), "GET / HTTP/1.1\r\n\r\n");
        BOOST_TEST(h5.method() == http::method::get);
        BOOST_TEST_EQ(h5.capacity_in_bytes(), h5cap);

        // two default heads share the default buffer
        request_head h6;
        h6 = h4;
        BOOST_TEST_EQ(h6.buffer(), "GET / HTTP/1.1\r\n\r\n");
        BOOST_TEST_EQ(h6.capacity_in_bytes(), 0u);
    }

    void
    testSetChunked()
    {
        // enabling chunked when a Content-Length exists and
        // no Transfer-Encoding is present: the erase must not
        // leave a stale iterator dereferenced
        request_head h1(http::method::post, "/u");
        h1.set_content_length(7);
        h1.set_chunked(true);
        BOOST_TEST(! h1.contains(http::field::content_length));
        BOOST_TEST_EQ(h1.count(http::field::transfer_encoding), 1u);
        BOOST_TEST_EQ(h1.at(http::field::transfer_encoding), "chunked");
        BOOST_TEST(h1.chunked());

        // a Content-Length preceding an already-chunked
        // Transfer-Encoding: the erase shifts positions, and
        // a duplicate "chunked" must not be appended
        request_head h2(http::method::post, "/u");
        h2.append(http::field::content_length, "7");
        h2.append(http::field::transfer_encoding, "chunked");
        h2.set_chunked(true);
        BOOST_TEST(! h2.contains(http::field::content_length));
        BOOST_TEST_EQ(h2.count(http::field::transfer_encoding), 1u);
        BOOST_TEST(h2.chunked());

        // with a non-final coding, "chunked" is appended
        // exactly once
        request_head h3(http::method::post, "/u");
        h3.append(http::field::content_length, "7");
        h3.append(http::field::transfer_encoding, "gzip");
        h3.set_chunked(true);
        BOOST_TEST(! h3.contains(http::field::content_length));
        BOOST_TEST_EQ(h3.count(http::field::transfer_encoding), 2u);
        BOOST_TEST(h3.chunked());

        // disabling removes a final "chunked" coding
        h1.set_chunked(false);
        BOOST_TEST(! h1.contains(http::field::transfer_encoding));
        BOOST_TEST(! h1.chunked());
        request_head h5(http::method::post, "/u");
        h5.append(http::field::transfer_encoding, "gzip, chunked");
        h5.set_chunked(false);
        BOOST_TEST_EQ(h5.at(http::field::transfer_encoding), "gzip");

        // whitespace before the removed coding goes
        // with it
        request_head h6(http::method::post, "/u");
        h6.append(http::field::transfer_encoding, "gzip \t, chunked");
        h6.set_chunked(false);
        BOOST_TEST_EQ(h6.at(http::field::transfer_encoding), "gzip");

        // disabling leaves a non-chunked final coding
        // alone, and is a no-op with no
        // Transfer-Encoding at all
        request_head h7(http::method::post, "/u");
        h7.append(http::field::transfer_encoding, "gzip");
        h7.set_chunked(false);
        BOOST_TEST_EQ(h7.at(http::field::transfer_encoding), "gzip");
        h7.erase(http::field::transfer_encoding);
        h7.set_chunked(false);
        BOOST_TEST(! h7.contains(http::field::transfer_encoding));
    }

    void
    testSetKeepAlive()
    {
        // HTTP/1.1 defaults to keep-alive; requesting
        // close adds the token, and requesting
        // keep-alive removes the field again
        request_head h;
        BOOST_TEST(h.keep_alive());
        h.set_keep_alive(false);
        BOOST_TEST_EQ(h.at(http::field::connection), "close");
        BOOST_TEST(! h.keep_alive());
        h.set_keep_alive(true);
        BOOST_TEST(! h.contains(http::field::connection));
        BOOST_TEST(h.keep_alive());

        // unrelated tokens survive the rewrite
        h.append(http::field::connection, "upgrade");
        h.set_keep_alive(false);
        BOOST_TEST_EQ(
            h.at(http::field::connection), "upgrade, close");
        h.set_keep_alive(true);
        BOOST_TEST_EQ(h.at(http::field::connection), "upgrade");

        // multiple fields and tokens collapse into one
        // field, keeping the unrelated tokens in order
        request_head h2;
        h2.append(http::field::connection, "keep-alive, x-a");
        h2.append(http::field::connection, "x-b");
        h2.set_keep_alive(false);
        BOOST_TEST_EQ(h2.count(http::field::connection), 1u);
        BOOST_TEST_EQ(
            h2.at(http::field::connection), "x-a, x-b, close");

        // a value which is not a token list
        // contributes nothing
        request_head h3;
        h3.append(http::field::connection, "@@@");
        h3.set_keep_alive(false);
        BOOST_TEST_EQ(h3.at(http::field::connection), "close");

        // HTTP/1.0 defaults to close; keep-alive must
        // be asked for explicitly
        request_head h4;
        h4.set_version(http::version::http_1_0);
        BOOST_TEST(! h4.keep_alive());
        h4.set_keep_alive(true);
        BOOST_TEST_EQ(
            h4.at(http::field::connection), "keep-alive");
        BOOST_TEST(h4.keep_alive());
        h4.set_keep_alive(false);
        BOOST_TEST(! h4.contains(http::field::connection));
        BOOST_TEST(! h4.keep_alive());
    }

    void
    testSetVersion()
    {
        // the version is written in place; nothing
        // else moves
        request_head h;
        h.append(http::field::host, "example.com");
        h.set_version(http::version::http_1_0);
        BOOST_TEST(h.version() == http::version::http_1_0);
        BOOST_TEST_EQ(
            h.buffer(),
            "GET / HTTP/1.0\r\n"
            "Host: example.com\r\n"
            "\r\n");
        h.set_version(http::version::http_1_1);
        BOOST_TEST_EQ(
            h.buffer(),
            "GET / HTTP/1.1\r\n"
            "Host: example.com\r\n"
            "\r\n");

        // a default-constructed head detaches from the
        // shared storage before writing
        request_head g;
        BOOST_TEST_EQ(g.capacity_in_bytes(), 0u);
        g.set_version(http::version::http_1_0);
        BOOST_TEST_EQ(g.buffer(), "GET / HTTP/1.0\r\n\r\n");
        BOOST_TEST(g.capacity_in_bytes() > 0u);
        // the shared storage was never written through
        request_head fresh;
        BOOST_TEST_EQ(fresh.buffer(), "GET / HTTP/1.1\r\n\r\n");

        // keep-alive follows the version
        BOOST_TEST(! g.keep_alive());
        g.set_version(http::version::http_1_1);
        BOOST_TEST(g.keep_alive());
    }

    void
    testExpect100Continue()
    {
        request_head h(http::method::post, "/u");
        BOOST_TEST(! h.expect_100_continue());
        h.set_expect_100_continue(true);
        BOOST_TEST(h.expect_100_continue());
        BOOST_TEST_EQ(h.at(http::field::expect), "100-continue");
        // setting again does not duplicate the field
        h.set_expect_100_continue(true);
        BOOST_TEST_EQ(h.count(http::field::expect), 1u);
        // disabling removes the field; again is a no-op
        h.set_expect_100_continue(false);
        BOOST_TEST(! h.expect_100_continue());
        BOOST_TEST(! h.contains(http::field::expect));
        h.set_expect_100_continue(false);
        BOOST_TEST(! h.contains(http::field::expect));

        // the observer tracks the field however it is
        // written; other expectations do not count
        h.append(http::field::expect, "nope");
        BOOST_TEST(! h.expect_100_continue());
        h.set(http::field::expect, "NOPE, 100-CONTINUE");
        BOOST_TEST(h.expect_100_continue());
        h.erase(http::field::expect);
        BOOST_TEST(! h.expect_100_continue());
    }

    void
    testUpgrade()
    {
        // the proposal needs both the Upgrade field
        // and the "upgrade" Connection token
        request_head h;
        BOOST_TEST(! h.upgrade());
        h.append(http::field::upgrade, "h2c");
        BOOST_TEST(! h.upgrade());
        h.append(http::field::connection, "upgrade");
        BOOST_TEST(h.upgrade());

        // removing either side withdraws it
        h.erase(http::field::upgrade);
        BOOST_TEST(! h.upgrade());
        h.append(http::field::upgrade, "h2c");
        BOOST_TEST(h.upgrade());
        h.set(http::field::connection, "close");
        BOOST_TEST(! h.upgrade());
    }

    void
    testClear()
    {
        // the request line survives; the fields and
        // the state derived from them do not
        request_head h(http::method::post, "/upload");
        h.set_content_length(5);
        h.set_keep_alive(false);
        h.set_expect_100_continue(true);
        BOOST_TEST(! h.keep_alive());
        auto const cap = h.capacity_in_bytes();

        h.clear();
        BOOST_TEST(h.empty());
        BOOST_TEST_EQ(h.buffer(), "POST /upload HTTP/1.1\r\n\r\n");
        BOOST_TEST(h.method() == http::method::post);
        BOOST_TEST_EQ(h.capacity_in_bytes(), cap);
        BOOST_TEST(! h.content_length().has_value());
        BOOST_TEST(h.payload() == http::payload::none);
        BOOST_TEST(h.keep_alive());
        BOOST_TEST(! h.expect_100_continue());

        // the version bit survives with the request line
        request_head g;
        g.set_version(http::version::http_1_0);
        g.append(http::field::connection, "keep-alive");
        BOOST_TEST(g.keep_alive());
        g.clear();
        BOOST_TEST(g.version() == http::version::http_1_0);
        BOOST_TEST(! g.keep_alive());
    }

    // A header built by hand is not checked: the
    // framing observers describe whatever the fields
    // say, and say so consistently.
    void
    testFramingByHand()
    {
        // a Content-Length which is not a single decimal
        // number reads as if absent, and is stored as given
        {
            request_head h(http::method::put, "/u");
            h.append(http::field::content_length, "abc");
            BOOST_TEST(! h.content_length().has_value());
            BOOST_TEST(h.payload() == http::payload::none);
            BOOST_TEST_EQ(h.at(http::field::content_length), "abc");
        }

        // a value one past the largest representable
        // length reads as if absent; the largest itself
        // parses
        {
            request_head h(http::method::put, "/u");
            h.set(http::field::content_length,
                "18446744073709551616");
            BOOST_TEST(! h.content_length().has_value());
            h.set(http::field::content_length,
                "18446744073709551615");
            BOOST_TEST_EQ(
                h.content_length().value(), std::uint64_t(-1));
        }

        // values which are not token lists: the
        // Expect tokens contribute nothing, an empty
        // Content-Length reads as if absent, and a
        // Transfer-Encoding still counts as one, so
        // the request cannot be framed
        {
            request_head h(http::method::put, "/u");
            h.set(http::field::expect, "@@");
            BOOST_TEST(! h.expect_100_continue());
            h.set(http::field::content_length, "");
            BOOST_TEST(! h.content_length().has_value());
            h.erase(http::field::content_length);
            h.append(http::field::transfer_encoding, "@@");
            BOOST_TEST(! h.chunked());
            BOOST_TEST(h.payload() == http::payload::error);
        }

        // field lines join into a list, so a duplicate
        // leaves no usable length even when the values
        // agree; removing it restores one
        {
            request_head h(http::method::put, "/u");
            h.append(http::field::content_length, "5");
            BOOST_TEST_EQ(h.content_length().value_or(0), 5u);
            h.append(http::field::content_length, "5");
            BOOST_TEST(! h.content_length().has_value());
            h.erase(--h.end());
            BOOST_TEST_EQ(h.content_length().value_or(0), 5u);
        }

        // Content-Length together with Transfer-Encoding
        {
            request_head h(http::method::put, "/u");
            h.append(http::field::transfer_encoding, "chunked");
            h.append(http::field::content_length, "5");
            BOOST_TEST(h.payload() == http::payload::error);
            BOOST_TEST(! h.chunked());
            h.erase(http::field::content_length);
            BOOST_TEST(h.chunked());
        }

        // a request whose final coding is not "chunked"
        // cannot be framed
        {
            request_head h(http::method::put, "/u");
            h.append(http::field::transfer_encoding, "gzip");
            BOOST_TEST(h.payload() == http::payload::error);
        }

        // the cached state is a function of the field
        // section, not of the mutations which produced
        // it: `a` reaches these fields by appending, `b`
        // by erasing back down to them
        {
            request_head a(http::method::put, "/u");
            a.append(http::field::content_length, "5");
            a.append(http::field::content_length, "9");

            request_head b(http::method::put, "/u");
            b.append(http::field::content_length, "5");
            b.append(http::field::content_length, "9");
            b.append(http::field::content_length, "7");
            b.erase(--b.end());

            BOOST_TEST_EQ(a.buffer(), b.buffer());
            BOOST_TEST(a.content_length() == b.content_length());
            BOOST_TEST(a.payload() == b.payload());
        }
        {
            request_head a(http::method::put, "/u");
            a.append(http::field::transfer_encoding, "chunked");
            a.append(http::field::transfer_encoding, "gzip");

            request_head b(http::method::put, "/u");
            b.append(http::field::transfer_encoding, "chunked");
            b.append(http::field::transfer_encoding, "gzip");
            b.append(http::field::transfer_encoding, "gzip");
            b.erase(--b.end());

            BOOST_TEST_EQ(a.buffer(), b.buffer());
            BOOST_TEST(a.chunked() == b.chunked());
            BOOST_TEST(a.payload() == b.payload());
        }
    }

    void
    testReserveShrink()
    {
        request_head h;
        h.reserve(4096, 32);
        auto const cap = h.capacity_in_bytes();
        BOOST_TEST(cap >= 4096u);
        // reserving within the capacity does not shrink
        h.reserve(10, 1);
        BOOST_TEST_EQ(h.capacity_in_bytes(), cap);

        h.append(http::field::host, "example.com");
        h.shrink_to_fit();
        // after shrinking, the allocation is small
        BOOST_TEST(h.capacity_in_bytes() < 4096u);
        BOOST_TEST_EQ(h.at(http::field::host), "example.com");
        BOOST_TEST_EQ(
            h.buffer(),
            "GET / HTTP/1.1\r\n"
            "Host: example.com\r\n"
            "\r\n");
    }

    // A later reserve must not give back the capacity an
    // earlier one obtained.
    void
    testReserveStartLineLater()
    {
        request_head h;
        h.reserve(4096, 32);
        h.append(http::field::host, "example.com");
        auto const cap = h.capacity_in_bytes();
        h.reserve(0, 0);
        BOOST_TEST_EQ(h.capacity_in_bytes(), cap);
        BOOST_TEST_EQ(h.at(http::field::host), "example.com");

        h.set_start_line(
            http::method::post,
            "/some/longer/target",
            http::version::http_1_1);
        BOOST_TEST_EQ(h.capacity_in_bytes(), cap);
        BOOST_TEST_EQ(
            h.buffer(),
            "POST /some/longer/target HTTP/1.1\r\n"
            "Host: example.com\r\n"
            "\r\n");

        // the field section still holds what the first
        // reserve obtained: filling it does not reallocate
        h.append(http::field::accept, std::string(3000, 'a'));
        BOOST_TEST_EQ(h.capacity_in_bytes(), cap);
    }

    // The request line shares the allocation with the field
    // section, so a longer one slides the fields along
    // rather than reallocating, as long as the reserve
    // covers both.
    void
    testReserveStartLine()
    {
        request_head h;
        h.reserve(1024, 8);
        h.append(http::field::host, "example.com");
        auto const cap = h.capacity_in_bytes();

        // a longer request line (35 bytes incl CRLF) still
        // fits the reserved capacity
        h.set_start_line(
            http::method::post,
            "/some/longer/target",
            http::version::http_1_1);

        // the field section moved but the allocation did not
        // change, and the entry offsets followed it
        BOOST_TEST_EQ(h.capacity_in_bytes(), cap);
        BOOST_TEST_EQ(h.at(http::field::host), "example.com");
        BOOST_TEST_EQ(
            h.buffer(),
            "POST /some/longer/target HTTP/1.1\r\n"
            "Host: example.com\r\n"
            "\r\n");
    }

    // Snapshot a non-owning request_head_base (as produced by
    // head_parser over an external buffer) into an owner.
    void
    testFromBase()
    {
        static_assert(std::is_convertible_v<
            request_head_base const&, request_head>);

        alignas(4) char buf[4096];
        std::string_view const msg =
            "POST /submit HTTP/1.1\r\n"
            "Host: example.com\r\n"
            "X-A: 1\r\n"
            "\r\n";
        auto const parse =
            [&](head_parser& pr)
            {
                std::memcpy(buf, msg.data(), msg.size());
                std::error_code ec;
                pr.parse(msg.size(), ec);
                BOOST_TEST(!ec);
            };

        head_parser pr(true, buf, sizeof(buf));
        parse(pr);
        request_head_base const& base = pr.request_head();

        // lossless, implicit construction from the base
        request_head h = base;
        BOOST_TEST_EQ(h.buffer(), msg);
        BOOST_TEST(h.method() == http::method::post);
        BOOST_TEST_EQ(h.target(), "/submit");
        BOOST_TEST_EQ(h.at(http::field::host), "example.com");
        // independent storage
        BOOST_TEST(h.buffer().data() != base.buffer().data());

        // clobbering the parse buffer leaves the snapshot intact
        std::memset(buf, 'Z', msg.size());
        BOOST_TEST_EQ(h.target(), "/submit");
        BOOST_TEST_EQ(h.at(http::field::host), "example.com");

        // assignment from a base replaces prior contents
        request_head g;
        g.append(http::field::host, "old");
        head_parser pr2(true, buf, sizeof(buf));
        parse(pr2);
        g = pr2.request_head();
        BOOST_TEST_EQ(g.buffer(), msg);
        BOOST_TEST(g.buffer().data() != buf);
        BOOST_TEST_EQ(g.count(http::field::host), 1u);
    }

    void
    run()
    {
        testDefault();
        testGrow();
        testStartLineGrow();
        testStartLineGrowEmpty();
        testStartLineLargeGrow();
        testStartLineDefaultStorage();
        testStartLineLimits();
        testSelfReference();
        testStartLineSelfReference();
        testMove();
        testMoveAssign();
        testSwap();
        testCopy();
        testCopyAssign();
        testSetChunked();
        testSetKeepAlive();
        testSetVersion();
        testExpect100Continue();
        testUpgrade();
        testClear();
        testFramingByHand();
        testReserveShrink();
        testReserveStartLineLater();
        testReserveStartLine();
        testFromBase();
    }
};

TEST_SUITE(request_head_test, "boost.burl.request_head");

} // namespace burl
} // namespace boost
