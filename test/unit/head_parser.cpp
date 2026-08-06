//
// Copyright (c) 2026 Mohammad Nejati
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

// Test that header file is self-contained.
#include <boost/burl/head_parser.hpp>

#include <boost/burl/request_head.hpp>
#include <boost/burl/static_fields.hpp>

#include <boost/assert.hpp>

#include "test_suite.hpp"

#include <cstdint>
#include <cstring>
#include <memory>
#include <sstream>
#include <string>

namespace boost
{
namespace burl
{

class head_parser_test
{
    alignas(4) char buf_[4096];

    // the space the lookup table takes for `count`
    // fields, which is exposed only as part of a
    // whole buffer size
    static
    std::size_t
    table_space(std::size_t count) noexcept
    {
        return static_fields::bytes_needed(0, count) -
            static_fields::bytes_needed(0, 0);
    }

    // the alignment the end of the buffer is rounded
    // down to, which is exposed only through the
    // sizes it rounds
    static constexpr std::size_t align =
        head_parser::bytes_needed(
            { .max_size = 1, .max_fields = 0 });

    // the parse base, which the parser exposes as
    // the start of the header it is building
    static
    char*
    base_of(head_parser const& pr) noexcept
    {
        return const_cast<char*>(
            pr.message_head().buffer().data());
    }

    // the bytes past the header, which the caller
    // locates from the header and its own total
    static
    std::string_view
    leftovers(
        head_parser const& pr,
        std::size_t size) noexcept
    {
        auto const h = pr.message_head().buffer();
        return { h.data() + h.size(), size - h.size() };
    }

    // place s at the parse base past the `size`
    // bytes already there, then parse the new total
    static
    system::error_code
    feed(
        head_parser& pr,
        std::size_t& size,
        std::string_view s)
    {
        auto* const base = base_of(pr);
        BOOST_ASSERT(base + size + s.size() <= pr.ceiling());
        std::memcpy(base + size, s.data(), s.size());
        size += s.size();
        system::error_code ec;
        pr.parse(size, ec);
        return ec;
    }

    // one shot into a parser with nothing in it yet
    static
    system::error_code
    feed(
        head_parser& pr,
        std::string_view s)
    {
        std::size_t size = 0;
        return feed(pr, size, s);
    }

public:
    void
    testRequest()
    {
        std::string_view const msg =
            "GET /index.html HTTP/1.1\r\n"
            "Host: example.com\r\n"
            "User-Agent:  burl  \r\n"
            "X-Empty:\r\n"
            "X-Ows: \t \r\n"
            "Set-Cookie: a=1\r\n"
            "Set-Cookie: b=2\r\n"
            "\r\n";
        std::string const body = "BODYBYTES";

        head_parser pr(true, buf_, sizeof(buf_));
        BOOST_TEST(base_of(pr) == buf_);
        std::memcpy(buf_, msg.data(), msg.size());
        std::memcpy(buf_ + msg.size(), body.data(), body.size());
        auto const fed = msg.size() + body.size();
        system::error_code ec;
        pr.parse(fed, ec);
        BOOST_TEST(!ec);

        auto const& h = pr.request_head();
        BOOST_TEST(h.method() == http::method::get);
        BOOST_TEST_EQ(h.method_text(), "GET");
        BOOST_TEST_EQ(h.target(), "/index.html");
        BOOST_TEST(h.version() == http::version::http_1_1);

        // the header is returned in its original place
        BOOST_TEST_EQ(h.buffer(), msg);
        BOOST_TEST(h.buffer().data() == buf_);
        BOOST_TEST_EQ(h.size(), 6u);

        BOOST_TEST_EQ(h.at(http::field::host), "example.com");
        BOOST_TEST(h.at(http::field::host).data() > buf_);
        BOOST_TEST(h.at(http::field::host).data() < buf_ + msg.size());

        // surrounding whitespace is excluded from values
        BOOST_TEST_EQ(h.at(http::field::user_agent), "burl");
        BOOST_TEST_EQ(h.at("X-Empty"), "");
        BOOST_TEST_EQ(h.at("X-Ows"), "");

        // names as received; lookups case-insensitive
        BOOST_TEST_EQ(h.begin()[0].name, "Host");
        BOOST_TEST(h.begin()[0].id == http::field::host);
        BOOST_TEST(h.contains("x-empty"));

        std::string all;
        for(auto v : h.find_all(http::field::set_cookie))
        {
            all.append(v);
            all.push_back(';');
        }
        BOOST_TEST_EQ(all, "a=1;b=2;");

        // payload bytes after the header are
        // untouched and reported as leftovers
        BOOST_TEST_EQ(
            std::string_view(buf_ + msg.size(), body.size()), body);
        BOOST_TEST_EQ(leftovers(pr, fed), body);

        // the table reserve is withheld from the
        // writable region, before and after
        // completion alike
        auto const reserve = table_space(
            pr.limits().max_fields);
        BOOST_TEST(pr.ceiling() == buf_ + sizeof(buf_) - reserve);

        // parsing again is a no-op success
        pr.parse(fed, ec);
        BOOST_TEST(!ec);
    }

    void
    testIncremental()
    {
        std::string_view const msg =
            "POST /submit HTTP/1.0\r\n"
            "Content-Length: 11\r\n"
            "Connection: keep-alive\r\n"
            "\r\n";

        head_parser pr(true, buf_, sizeof(buf_));
        system::error_code ec;
        std::size_t n = 0;
        for(char const c : msg)
        {
            pr.parse(n, ec);
            BOOST_TEST(ec == http::error::need_data);
            buf_[n++] = c;
        }
        pr.parse(n, ec);
        BOOST_TEST(!ec);

        auto const& h = pr.request_head();
        BOOST_TEST(h.method() == http::method::post);
        BOOST_TEST_EQ(h.target(), "/submit");
        BOOST_TEST(h.version() == http::version::http_1_0);
        BOOST_TEST(h.payload() == http::payload::size);
        BOOST_TEST_EQ(h.content_length(), 11u);
        BOOST_TEST(h.keep_alive());
    }

    void
    testResponse()
    {
        std::string_view const msg =
            "HTTP/1.0 404 Not Found\r\n"
            "Content-Length: 5\r\n"
            "\r\n";

        head_parser pr(false, buf_, sizeof(buf_));
        BOOST_TEST(! feed(pr, msg));

        auto const& h = pr.response_head();
        BOOST_TEST(h.status() == http::status::not_found);
        BOOST_TEST_EQ(h.status_int(), 404);
        BOOST_TEST_EQ(h.reason(), "Not Found");
        BOOST_TEST(h.version() == http::version::http_1_0);
        BOOST_TEST(h.payload() == http::payload::size);
        BOOST_TEST_EQ(*h.content_length(), 5u);
        BOOST_TEST_EQ(h.buffer(), msg);

        // HTTP/1.0 without keep-alive closes
        BOOST_TEST(!h.keep_alive());
    }

    void
    testResponseVariants()
    {
        // no reason-phrase, no space
        {
            head_parser pr(false, buf_, sizeof(buf_));
            std::string_view const msg = "HTTP/1.1 204\r\n\r\n";
            BOOST_TEST(! feed(pr, msg));
            auto const& h = pr.response_head();
            BOOST_TEST_EQ(h.status_int(), 204);
            BOOST_TEST_EQ(h.reason(), "");
            BOOST_TEST(h.payload() == http::payload::none);
        }

        // no reason-phrase, trailing space
        {
            head_parser pr(false, buf_, sizeof(buf_));
            std::string_view const msg = "HTTP/1.1 200 \r\n\r\n";
            BOOST_TEST(! feed(pr, msg));
            auto const& h = pr.response_head();
            BOOST_TEST_EQ(h.status_int(), 200);
            BOOST_TEST_EQ(h.reason(), "");
            BOOST_TEST(h.payload() == http::payload::to_eof);
            BOOST_TEST(!h.keep_alive());
        }

        // unknown status code
        {
            head_parser pr(false, buf_, sizeof(buf_));
            std::string_view const msg = "HTTP/1.1 599 Whatever\r\n\r\n";
            BOOST_TEST(! feed(pr, msg));
            BOOST_TEST(
                pr.response_head().status() == http::status::unknown);
            BOOST_TEST_EQ(pr.response_head().status_int(), 599);
        }

        // protocol switch
        {
            head_parser pr(false, buf_, sizeof(buf_));
            std::string_view const msg =
                "HTTP/1.1 101 Switching Protocols\r\n"
                "Connection: upgrade\r\n"
                "Upgrade: websocket\r\n"
                "\r\n";
            BOOST_TEST(! feed(pr, msg));
            auto const& h = pr.response_head();
            BOOST_TEST(h.upgrade());
            BOOST_TEST(h.payload() == http::payload::none);
        }
    }

    void
    testFraming()
    {
        // Content-Length
        {
            head_parser pr(true, buf_, sizeof(buf_));
            auto const ec = feed(
                pr,
                "PUT / HTTP/1.1\r\n"
                "Content-Length: 5\r\n"
                "\r\n");
            BOOST_TEST(!ec);
            BOOST_TEST(
                pr.request_head().payload() == http::payload::size);
            BOOST_TEST_EQ(
                pr.request_head().content_length().value_or(0), 5);
        }

        // a coding other than chunked in a response is
        // read to EOF
        {
            head_parser pr(false, buf_, sizeof(buf_));
            auto const ec = feed(
                pr,
                "HTTP/1.1 200 OK\r\n"
                "Transfer-Encoding: gzip\r\n"
                "\r\n");
            BOOST_TEST(!ec);
            BOOST_TEST(
                pr.response_head().payload() == http::payload::to_eof);
        }

        // chunked framing
        {
            head_parser pr(true, buf_, sizeof(buf_));
            auto const ec = feed(
                pr,
                "PUT / HTTP/1.1\r\n"
                "Transfer-Encoding: gzip, chunked\r\n"
                "\r\n");
            BOOST_TEST(!ec);
            BOOST_TEST(
                pr.request_head().payload() == http::payload::chunked);
        }

        // connection close
        {
            head_parser pr(true, buf_, sizeof(buf_));
            auto const ec = feed(
                pr,
                "GET / HTTP/1.1\r\n"
                "Connection: close\r\n"
                "\r\n");
            BOOST_TEST(!ec);
            BOOST_TEST(!pr.request_head().keep_alive());
        }

        // an Expect field counts only when its token
        // list contains 100-continue
        {
            head_parser pr(true, buf_, sizeof(buf_));
            auto const ec = feed(
                pr,
                "PUT / HTTP/1.1\r\n"
                "Content-Length: 5\r\n"
                "Expect: 100-continue\r\n"
                "\r\n");
            BOOST_TEST(!ec);
            BOOST_TEST(pr.request_head().expect_100_continue());
        }
        {
            head_parser pr(true, buf_, sizeof(buf_));
            auto const ec = feed(
                pr,
                "PUT / HTTP/1.1\r\n"
                "Content-Length: 5\r\n"
                "Expect: nope\r\n"
                "\r\n");
            BOOST_TEST(!ec);
            BOOST_TEST(!pr.request_head().expect_100_continue());
        }
    }

    void
    testObsFold()
    {
        // each obs-fold is resolved in place: the CRLF
        // is overwritten with spaces, leaving the value
        // contiguous and the field on one logical line
        {
            std::string_view const msg =
                "GET / HTTP/1.1\r\n"
                "X: 1\r\n continued\r\n"
                "Y: a\r\n\tb\r\n\tc\r\n"
                "Host: example.com\r\n"
                "\r\n";

            head_parser pr(true, buf_, sizeof(buf_));
            BOOST_TEST(! feed(pr, msg));
            auto const& h = pr.request_head();
            BOOST_TEST_EQ(h.size(), 3u);
            BOOST_TEST_EQ(h.at("X"), "1   continued");
            BOOST_TEST_EQ(h.at("Y"), "a  \tb  \tc");
            BOOST_TEST_EQ(h.at(http::field::host), "example.com");
            // the buffer holds the resolved header
            BOOST_TEST_EQ(
                h.buffer(),
                "GET / HTTP/1.1\r\n"
                "X: 1   continued\r\n"
                "Y: a  \tb  \tc\r\n"
                "Host: example.com\r\n"
                "\r\n");
        }

        // a fold is invisible to the cached state
        {
            std::string_view const msg =
                "PUT /u HTTP/1.1\r\n"
                "Transfer-Encoding: gzip,\r\n chunked\r\n"
                "\r\n";

            head_parser pr(true, buf_, sizeof(buf_));
            BOOST_TEST(! feed(pr, msg));
            BOOST_TEST(pr.request_head().chunked());
        }

        // the continuation is awaited: a field line is
        // complete only once the byte which follows its
        // CRLF has arrived
        {
            std::string_view const msg =
                "GET / HTTP/1.1\r\n"
                "X: 1\r\n continued\r\n"
                "\r\n";

            head_parser pr(true, buf_, sizeof(buf_));
            system::error_code ec;
            // bytes are appended one at a time;
            // those already parsed are resolved in
            // place and never rewritten
            std::size_t n = 0;
            for(char const c : msg)
            {
                pr.parse(n, ec);
                BOOST_TEST(ec == http::error::need_data);
                buf_[n++] = c;
            }
            pr.parse(n, ec);
            BOOST_TEST(!ec);
            BOOST_TEST_EQ(pr.request_head().at("X"), "1   continued");
        }

        // a fold may arrive before any field content;
        // the ws it bares is not part of the value
        {
            std::string_view const msg =
                "GET / HTTP/1.1\r\n"
                "X:\r\n foo\r\n"
                "\r\n";

            head_parser pr(true, buf_, sizeof(buf_));
            BOOST_TEST(! feed(pr, msg));
            BOOST_TEST_EQ(pr.request_head().at("X"), "foo");
        }

        // a fold which bares only whitespace yields
        // an empty value
        {
            std::string_view const msg =
                "GET / HTTP/1.1\r\n"
                "X:\r\n \r\n"
                "Host: example.com\r\n"
                "\r\n";

            head_parser pr(true, buf_, sizeof(buf_));
            BOOST_TEST(! feed(pr, msg));
            BOOST_TEST_EQ(pr.request_head().at("X"), "");
        }

        // a payload which begins with whitespace does
        // not continue the final empty line
        {
            std::string_view const msg =
                "PUT /u HTTP/1.1\r\n"
                "Content-Length: 6\r\n"
                "\r\n"
                " body ";

            head_parser pr(true, buf_, sizeof(buf_));
            BOOST_TEST(! feed(pr, msg));
            auto const& h = pr.request_head();
            BOOST_TEST_EQ(h.size(), 1u);
            BOOST_TEST_EQ(
                std::string_view(buf_ + h.buffer().size(), 6), " body ");
        }
    }

    // The parser folds each field into the cached
    // state as it arrives, while a header built by
    // hand recomputes it from the whole field
    // section. For fields the parser accepts, the two
    // must arrive at the same state.
    void
    testFoldMatchesRescan()
    {
        auto const check = [&](
            std::initializer_list<
                std::pair<http::field, std::string_view>> fields)
        {
            std::string msg = "PUT /u HTTP/1.1\r\n";
            request_head h(http::method::put, "/u");
            for(auto const& f : fields)
            {
                msg += http::to_string(f.first);
                msg += ": ";
                msg += f.second;
                msg += "\r\n";
                h.append(f.first, f.second);
            }
            msg += "\r\n";

            head_parser pr(true, buf_, sizeof(buf_));
            if(! BOOST_TEST(! feed(pr, msg)))
                return;
            auto const& p = pr.request_head();
            // every framing contradiction is rejected,
            // so a parsed header never reports one
            BOOST_TEST(p.payload() != http::payload::error);
            BOOST_TEST_EQ(p.buffer(), h.buffer());
            BOOST_TEST(p.payload() == h.payload());
            BOOST_TEST(p.content_length() == h.content_length());
            BOOST_TEST_EQ(p.chunked(), h.chunked());
            BOOST_TEST_EQ(p.keep_alive(), h.keep_alive());
            BOOST_TEST_EQ(p.upgrade(), h.upgrade());
            BOOST_TEST_EQ(
                p.expect_100_continue(), h.expect_100_continue());
        };

        check({ { http::field::content_length, "0" } });
        check({ { http::field::content_length, "5" } });
        check({ { http::field::transfer_encoding, "chunked" } });
        check({ { http::field::transfer_encoding, "gzip, chunked" } });
        check({ { http::field::transfer_encoding, "gzip" },
                { http::field::transfer_encoding, "chunked" } });
        check({ { http::field::transfer_encoding, "chunked" },
                { http::field::connection, "close" } });
        check({ { http::field::connection, "close" } });
        check({ { http::field::expect, "100-continue" },
                { http::field::content_length, "3" } });
        check({ { http::field::connection, "keep-alive" },
                { http::field::connection, "upgrade" },
                { http::field::upgrade, "websocket" } });
        check({ { http::field::expect, "100-continue" } });
        check({ { http::field::host, "example.com" },
                { http::field::content_length, "12" } });
    }

    void
    testRejectedHeader()
    {
        // a header rejected by the final framing rule is
        // whole, so the caller can inspect it
        {
            head_parser pr(true, buf_, sizeof(buf_));
            auto const ec = feed(
                pr,
                "PUT /u HTTP/1.1\r\n"
                "Host: example.com\r\n"
                "Transfer-Encoding: gzip\r\n"
                "\r\n");
            BOOST_TEST(ec == http::error::bad_transfer_encoding);
            auto const& h = pr.request_head();
            BOOST_TEST_EQ(
                h.buffer(),
                "PUT /u HTTP/1.1\r\n"
                "Host: example.com\r\n"
                "Transfer-Encoding: gzip\r\n"
                "\r\n");
            BOOST_TEST_EQ(h.target(), "/u");
            BOOST_TEST_EQ(h.at(http::field::host), "example.com");
        }

        // a field rejected as it arrives is not part of
        // the header at all: the cached state describes
        // the fields which preceded it
        {
            head_parser pr(true, buf_, sizeof(buf_));
            auto const ec = feed(
                pr,
                "PUT /u HTTP/1.1\r\n"
                "Content-Length: 5\r\n"
                "Transfer-Encoding: chunked\r\n"
                "\r\n");
            BOOST_TEST(ec == http::error::bad_payload);
            auto const& h = pr.request_head();
            BOOST_TEST_EQ(h.size(), 1u);
            BOOST_TEST(! h.contains(http::field::transfer_encoding));
            BOOST_TEST_EQ(h.content_length().value_or(0), 5u);
        }
    }

    void
    testErrors()
    {
        auto const check = [&](
            bool is_request,
            std::string_view msg,
            http::error e,
            header_limits const& limits = {})
        {
            head_parser pr(is_request, buf_, sizeof(buf_), limits);
            std::size_t n = 0;
            system::error_code ec = feed(pr, n, msg);
            BOOST_TEST(ec == e);
            // errors are sticky
            pr.parse(n, ec);
            BOOST_TEST(ec == e);
        };

        // bare LF
        check(
            true,
            "GET / HTTP/1.1\nHost: x\r\n\r\n",
            http::error::bad_line_ending);

        // malformed methods
        check(true, " / HTTP/1.1\r\n\r\n", http::error::bad_method);
        check(true, "GE\x01T / HTTP/1.1\r\n\r\n", http::error::bad_method);

        // malformed targets
        check(true, "GET HTTP/1.1\r\n\r\n", http::error::bad_request_target);
        check(
            true,
            "GET /a\x7F" "b HTTP/1.1\r\n\r\n",
            http::error::bad_request_target);

        // malformed versions
        check(true, "GET / HTTP/2.0\r\n\r\n", http::error::bad_version);
        check(true, "GET / HTP/1.1\r\n\r\n", http::error::bad_version);
        check(false, "HTP/1.1 200 OK\r\n\r\n", http::error::bad_version);

        // the request line must end in CRLF right
        // after the version
        check(true, "GET / HTTP/1.1X\r\n\r\n", http::error::bad_line_ending);
        check(true, "GET / HTTP/1.1\rX\r\n", http::error::bad_line_ending);

        // an empty target
        check(true, "GET  HTTP/1.1\r\n\r\n", http::error::bad_request_target);

        // malformed status lines
        check(false, "HTTP/1.1 200\r\n", http::error::need_data);
        check(false, "HTTP/1.1 x00 OK\r\n\r\n", http::error::bad_status_code);
        check(false, "HTTP/1.1 2x0 OK\r\n\r\n", http::error::bad_status_code);
        check(false, "HTTP/1.1 2000 OK\r\n\r\n", http::error::bad_status_code);
        check(false, "HTTP/1.1 20\r\n\r\n", http::error::bad_status_code);
        check(false, "HTTP/1.1200 OK\r\n\r\n", http::error::bad_version);

        // malformed reason phrases
        check(false, "HTTP/1.1 200 O\x01K\r\n\r\n", http::error::bad_reason);
        check(false, "HTTP/1.1 200 OK\rX\r\n\r\n", http::error::bad_line_ending);

        // malformed fields
        check(
            true,
            "GET / HTTP/1.1\r\nHost : x\r\n\r\n",
            http::error::bad_field_name);
        check(
            true,
            "GET / HTTP/1.1\r\n: x\r\n\r\n",
            http::error::bad_field_name);
        check(
            true,
            "GET / HTTP/1.1\r\nNoColon\r\n\r\n",
            http::error::bad_field_name);
        check(
            true,
            "GET / HTTP/1.1\r\nX: a\x01z\r\n\r\n",
            http::error::bad_field_value);
        check(
            true,
            "GET / HTTP/1.1\r\nX: a\x7Fz\r\n\r\n",
            http::error::bad_field_value);

        // an obs-fold with no field line to continue
        check(
            true,
            "GET / HTTP/1.1\r\n continued\r\n\r\n",
            http::error::bad_field_name);

        // a bare LF ending the continuation of a fold
        check(
            true,
            "GET / HTTP/1.1\r\nX: 1\r\n continued\n\r\n",
            http::error::bad_line_ending);

        // a field-section terminator whose CR is not
        // followed by LF
        check(
            true,
            "GET / HTTP/1.1\r\nHost: x\r\n\rZ\r\n",
            http::error::bad_line_ending);

        // a folded field line is measured whole
        check(
            true,
            "GET / HTTP/1.1\r\nX: 1\r\n continued\r\n\r\n",
            http::error::field_size_limit,
            { .max_field = 12 });

        // framing which cannot be trusted is rejected
        // as the field which introduces it is parsed,
        // in either order
        check(
            true,
            "PUT / HTTP/1.1\r\n"
            "Content-Length: 5\r\n"
            "Transfer-Encoding: chunked\r\n\r\n",
            http::error::bad_payload);
        check(
            false,
            "HTTP/1.1 200 OK\r\n"
            "Transfer-Encoding: chunked\r\n"
            "Content-Length: 5\r\n\r\n",
            http::error::bad_payload);
        // a no-payload status does not excuse it
        check(
            false,
            "HTTP/1.1 204 No Content\r\n"
            "Content-Length: 5\r\n"
            "Transfer-Encoding: chunked\r\n\r\n",
            http::error::bad_payload);

        // a Content-Length which is not a single
        // decimal number
        check(
            true,
            "PUT / HTTP/1.1\r\nContent-Length: abc\r\n\r\n",
            http::error::bad_content_length);
        check(
            true,
            "PUT / HTTP/1.1\r\nContent-Length:\r\n\r\n",
            http::error::bad_content_length);
        check(
            true,
            "PUT / HTTP/1.1\r\nContent-Length: 5, 5\r\n\r\n",
            http::error::bad_content_length);
        // one past the largest representable value
        check(
            true,
            "PUT / HTTP/1.1\r\n"
            "Content-Length: 18446744073709551616\r\n\r\n",
            http::error::bad_content_length);
        // the largest representable value parses
        {
            head_parser pr(true, buf_, sizeof(buf_));
            BOOST_TEST(! feed(
                pr,
                "PUT / HTTP/1.1\r\n"
                "Content-Length: 18446744073709551615\r\n\r\n"));
            BOOST_TEST_EQ(
                pr.request_head().content_length().value(),
                std::uint64_t(-1));
        }

        // field lines join into a list, so any
        // duplicate Content-Length is an error, even
        // when the values agree
        check(
            true,
            "PUT / HTTP/1.1\r\n"
            "Content-Length: 5\r\nContent-Length: 6\r\n\r\n",
            http::error::multiple_content_length);
        check(
            true,
            "PUT / HTTP/1.1\r\n"
            "Content-Length: 5\r\nContent-Length: 5\r\n\r\n",
            http::error::multiple_content_length);

        // a Transfer-Encoding which is not a token list
        check(
            true,
            "PUT / HTTP/1.1\r\nTransfer-Encoding: @\r\n\r\n",
            http::error::bad_transfer_encoding);

        // "chunked" must be applied exactly once, as
        // the final coding of the joined value
        check(
            true,
            "PUT / HTTP/1.1\r\n"
            "Transfer-Encoding: chunked, chunked\r\n\r\n",
            http::error::bad_transfer_encoding);
        check(
            true,
            "PUT / HTTP/1.1\r\n"
            "Transfer-Encoding: chunked\r\n"
            "Transfer-Encoding: chunked\r\n\r\n",
            http::error::bad_transfer_encoding);
        check(
            true,
            "PUT / HTTP/1.1\r\n"
            "Transfer-Encoding: chunked\r\n"
            "Transfer-Encoding: gzip\r\n\r\n",
            http::error::bad_transfer_encoding);
        check(
            false,
            "HTTP/1.1 200 OK\r\n"
            "Transfer-Encoding: chunked, gzip\r\n\r\n",
            http::error::bad_transfer_encoding);

        // the length of a request framed by a coding
        // other than chunked cannot be determined.
        // Whether a later field appends "chunked" is
        // unknown until the field section ends, so this
        // is rejected there rather than as the field
        // arrives
        check(
            true,
            "PUT / HTTP/1.1\r\n"
            "Transfer-Encoding: gzip\r\n\r\n",
            http::error::bad_transfer_encoding);
        check(
            true,
            "PUT / HTTP/1.1\r\n"
            "Transfer-Encoding: gzip\r\n"
            "Transfer-Encoding: deflate\r\n\r\n",
            http::error::bad_transfer_encoding);

        // HTTP/1.0 has no transfer codings
        check(
            true,
            "PUT / HTTP/1.0\r\nTransfer-Encoding: chunked\r\n\r\n",
            http::error::bad_transfer_encoding);
        check(
            false,
            "HTTP/1.0 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n",
            http::error::bad_transfer_encoding);

        // limits
        check(
            true,
            "GET /averyveryverylongtarget HTTP/1.1\r\n\r\n",
            http::error::start_line_limit,
            { .max_start_line = 16 });
        check(
            true,
            "GET / HTTP/1.1\r\nX-Long: a-value-beyond-the-limit\r\n\r\n",
            http::error::field_size_limit,
            { .max_field = 16 });
        check(
            true,
            "GET / HTTP/1.1\r\nA: 1\r\nB: 2\r\n\r\n",
            http::error::fields_limit,
            { .max_fields = 1 });
        check(
            true,
            "GET / HTTP/1.1\r\nA: 1\r\nB: 2\r\n\r\n",
            http::error::headers_limit,
            { .max_size = 20 });
    }

    void
    testLimits()
    {
        // A request whose start line is `sl` bytes and
        // which carries `nf` field lines of `fl` bytes
        // each, counting delimiters.
        auto const msg = [](
            std::size_t sl,
            std::size_t nf,
            std::size_t fl)
        {
            std::string s =
                "GET /" + std::string(sl - 16, 'a') +
                    " HTTP/1.1\r\n";
            for(std::size_t i = 0; i < nf; ++i)
            {
                auto const name = "X" + std::to_string(i);
                s += name + ": " +
                    std::string(fl - name.size() - 4, 'v') +
                    "\r\n";
            }
            return s + "\r\n";
        };

        // Every limit is a maximum, so a header which
        // reaches it exactly must be accepted. Each case
        // is parsed twice: in one call, and one byte at a
        // time. Both must reach the same verdict, which
        // is what proves a limit cannot be reported
        // before the bytes which violate it have arrived.
        auto const check = [&](
            std::string_view s,
            http::error e,
            header_limits const& limits = {})
        {
            {
                head_parser pr(
                    true, buf_, sizeof(buf_), limits);
                auto const ec = feed(pr, s);
                if(e == http::error::success)
                    BOOST_TEST(! ec);
                else
                    BOOST_TEST(ec == e);
            }
            {
                head_parser pr(
                    true, buf_, sizeof(buf_), limits);
                system::error_code ec;
                for(std::size_t n = 0;; ++n)
                {
                    pr.parse(n, ec);
                    if(ec != http::error::need_data ||
                        n == s.size())
                        break;
                    buf_[n] = s[n];
                }
                if(e == http::error::success)
                    BOOST_TEST(! ec);
                else
                    BOOST_TEST(ec == e);
            }
        };

        // max_size, on a 52-byte header
        auto const h52 = msg(20, 3, 10);
        BOOST_TEST_EQ(h52.size(), 52u);
        check(h52, http::error::headers_limit, { .max_size = 51 });
        check(h52, http::error::success, { .max_size = 52 });
        check(h52, http::error::success, { .max_size = 53 });

        // max_size also bounds the start line, and the
        // remaining budget cannot wrap once it does
        auto const h100 = msg(100, 1, 10);
        check(h100, http::error::start_line_limit,
            { .max_size = 50, .max_start_line = 4096 });
        check(h100, http::error::start_line_limit,
            { .max_size = 99, .max_start_line = 4096 });
        // the start line fits exactly, leaving nothing
        // for the field section
        check(h100, http::error::headers_limit,
            { .max_size = 100, .max_start_line = 4096 });

        // max_start_line binds when it is the smaller of
        // the two, and admits a start line which reaches
        // it exactly
        auto const h40 = msg(40, 1, 10);
        check(h40, http::error::start_line_limit,
            { .max_start_line = 39 });
        check(h40, http::error::success, { .max_start_line = 40 });

        // max_field, on 40-byte field lines. A field line
        // is complete only once the byte after its CRLF
        // has arrived, so the window given to the field
        // parser is one byte wider than the limit
        auto const f40 = msg(20, 2, 40);
        check(f40, http::error::field_size_limit, { .max_field = 39 });
        check(f40, http::error::success, { .max_field = 40 });
        check(f40, http::error::success, { .max_field = 41 });

        // max_fields, with four present
        auto const n4 = msg(20, 4, 10);
        check(n4, http::error::fields_limit, { .max_fields = 3 });
        check(n4, http::error::success, { .max_fields = 4 });

        // a limit still fires when the bytes which
        // violate it are followed by unrelated ones
        check(h52 + std::string(200, 'Z'),
            http::error::headers_limit, { .max_size = 40 });

        // the same boundary at the default max_field,
        // which needs a buffer of its own
        {
            alignas(4) char big[8192];
            auto const field = [](std::size_t n)
            {
                return "GET / HTTP/1.1\r\nX: " +
                    std::string(n - 5, 'v') + "\r\n\r\n";
            };
            auto const at = field(4096);
            head_parser pr(true, big, sizeof(big));
            BOOST_TEST(! feed(pr, at));
            BOOST_TEST_EQ(
                pr.request_head().at("X").size(), 4096u - 5u);

            auto const over = field(4097);
            head_parser pr2(true, big, sizeof(big));
            BOOST_TEST(
                feed(pr2, over) == http::error::field_size_limit);
        }
    }

    void
    testTableSpace()
    {
        // the table reserve leaves no room to
        // receive anything: the parser reports
        // that it cannot proceed in place
        alignas(4) char tiny[64];

        head_parser pr(true, tiny, sizeof(tiny));
        BOOST_TEST(pr.ceiling() == tiny); // default max_fields = 100
        system::error_code ec;
        pr.parse(0, ec);
        BOOST_TEST(ec == http::error::in_place_overflow);
        // the error is derived again on request
        pr.parse(0, ec);
        BOOST_TEST(ec == http::error::in_place_overflow);

        // with fitting limits the same buffer works
        head_parser pr2(true, tiny, sizeof(tiny), { .max_fields = 3 });
        std::string_view const msg2 = "GET / HTTP/1.1\r\nHost: x\r\n\r\n";
        BOOST_TEST(! feed(pr2, msg2));
        BOOST_TEST_EQ(pr2.request_head().at(http::field::host), "x");
    }

    void
    testOstream()
    {
        head_parser pr(true, buf_, sizeof(buf_));
        BOOST_TEST(!feed(pr,
            "GET / HTTP/1.1\r\n"
            "Host: example.com\r\n"
            "User-Agent:  burl  \r\n"
            "\r\n"));

        std::ostringstream os;
        os << pr.request_head();
        BOOST_TEST_EQ(os.str(),
            "GET / HTTP/1.1\n"
            "Host: example.com\n"
            "User-Agent: burl\n");

        // through a fields_base lens only the
        // field section is written
        os.str({});
        os << static_cast<fields_base const&>(pr.message_head());
        BOOST_TEST_EQ(os.str(),
            "Host: example.com\n"
            "User-Agent: burl\n");

        head_parser ps(false, buf_, sizeof(buf_));
        BOOST_TEST(!feed(ps,
            "HTTP/1.1 200 OK\r\n"
            "Content-Length: 0\r\n"
            "\r\n"));

        os.str({});
        os << ps.response_head();
        BOOST_TEST_EQ(os.str(),
            "HTTP/1.1 200 OK\n"
            "Content-Length: 0\n");

        // streamable before parse succeeds; no
        // start line has been parsed yet
        head_parser pe(true, buf_, sizeof(buf_));
        os.str({});
        os << pe.message_head();
        BOOST_TEST_EQ(os.str(), "");
    }

    void
    testMove()
    {
        alignas(4) char buf[256];
        std::string_view const msg =
            "GET /index HTTP/1.1\r\n"
            "Host: example.com\r\n"
            "\r\n";

        // move mid-parse: the new object resumes
        // where the source stopped, carrying the
        // limits with it
        header_limits const lim{ .max_fields = 4 };
        head_parser pr(true, buf, sizeof(buf), lim);
        system::error_code ec;
        std::size_t n = 0;
        std::memcpy(buf, msg.data(), 21);
        n = 21;
        pr.parse(n, ec);
        BOOST_TEST(ec == http::error::need_data);

        // the new object continues over the same
        // bytes
        head_parser pr2(std::move(pr));
        BOOST_TEST(base_of(pr2) == buf);
        BOOST_TEST(! feed(pr2, n, msg.substr(21)));
        auto const& h = pr2.request_head();
        BOOST_TEST_EQ(h.target(), "/index");
        BOOST_TEST_EQ(h.at(http::field::host), "example.com");
        BOOST_TEST_EQ(pr2.message_head().buffer(), msg);

        // move assignment from a fresh parser
        // re-arms over the same buffer
        pr2 = head_parser(true, buf, sizeof(buf), lim);
        std::string_view const msg2 =
            "POST /submit HTTP/1.1\r\n\r\n";
        BOOST_TEST(! feed(pr2, msg2));
        BOOST_TEST_EQ(
            pr2.request_head().method(), http::method::post);

        // self move-assignment is a no-op
        auto& pr2r = pr2;
        pr2 = std::move(pr2r);
        BOOST_TEST_EQ(pr2.request_head().target(), "/submit");

        // default construction: zero-size buffer,
        // no room to receive anything
        head_parser pr3;
        BOOST_TEST(pr3.ceiling() == base_of(pr3));
        pr3.parse(0, ec);
        BOOST_TEST(ec == http::error::in_place_overflow);
    }

    void
    testReset()
    {
        alignas(4) char buf[256];

        // parse to completion, then re-arm in place
        // and parse a different header over the same
        // buffer
        head_parser pr(true, buf, sizeof(buf), { .max_fields = 4 });
        std::string_view const msg1 =
            "GET /a HTTP/1.1\r\nHost: a\r\n\r\n";
        BOOST_TEST(! feed(pr, msg1));
        BOOST_TEST_EQ(pr.request_head().target(), "/a");

        pr.reset(buf);
        BOOST_TEST(base_of(pr) == buf);
        BOOST_TEST_EQ(pr.message_head().buffer().size(), 0u);
        std::string_view const msg2 =
            "POST /bb HTTP/1.1\r\nHost: b\r\nX: y\r\n\r\n";
        BOOST_TEST(! feed(pr, msg2));
        BOOST_TEST(pr.request_head().method() == http::method::post);
        BOOST_TEST_EQ(pr.request_head().target(), "/bb");
        BOOST_TEST_EQ(pr.request_head().at(http::field::host), "b");

        // the limits configured at construction
        // survive the reset
        BOOST_TEST_EQ(pr.limits().max_fields, 4u);
    }

    void
    testPipelined()
    {
        // a second message follows the first into
        // the buffer. Between messages a connection
        // re-arms the parser, moves the leftovers
        // down, and commits them back; they always
        // fit within the fresh window
        alignas(4) char buf[256];
        std::string_view const msg1 =
            "GET /a HTTP/1.1\r\nHost: a\r\n\r\n";
        std::string_view const msg2 =
            "POST /b HTTP/1.1\r\n\r\n";

        head_parser pr(true, buf, sizeof(buf), { .max_fields = 4 });
        auto const both =
            std::string(msg1) + std::string(msg2);
        std::size_t n = 0;
        BOOST_TEST(! feed(pr, n, both));
        auto const lo = leftovers(pr, n);
        BOOST_TEST(lo.data() == buf + msg1.size());
        BOOST_TEST_EQ(lo, msg2);

        std::memmove(buf, lo.data(), lo.size());
        pr.reset(buf);
        n = lo.size();
        system::error_code ec;
        pr.parse(n, ec);
        BOOST_TEST(! ec);
        BOOST_TEST_EQ(pr.request_head().target(), "/b");
        BOOST_TEST_EQ(leftovers(pr, n).size(), 0u);
    }

    void
    testBufferGeometry()
    {
        std::string_view const msg =
            "GET / HTTP/1.1\r\nHost: x\r\n\r\n";
        header_limits const lim{ .max_fields = 1 };

        // any buffer address and size is accepted;
        // the end is aligned down for the table
        {
            alignas(4) char raw[64];
            head_parser pr(true, raw + 1, 41, lim);
            // raw + 42 aligns down to raw + 40:
            // 39 usable bytes, 12 reserved
            BOOST_TEST(base_of(pr) == raw + 1);
            BOOST_TEST_EQ(pr.ceiling() - (raw + 1), 27);
            BOOST_TEST(! feed(pr, msg));
            BOOST_TEST_EQ(
                pr.request_head().at(http::field::host), "x");
        }

        // sizes too small for any storage leave the
        // parser empty
        {
            alignas(4) char raw[16];
            for(std::size_t n = 0; n <= 12; ++n)
            {
                head_parser pr(true, raw, n, lim);
                BOOST_TEST(pr.ceiling() == raw);
                system::error_code ec;
                pr.parse(0, ec);
                BOOST_TEST(ec == http::error::in_place_overflow);
            }
        }

        // the header needs more bytes than the
        // window can ever receive
        {
            alignas(4) char raw[36];
            head_parser pr(true, raw, sizeof(raw), lim);
            BOOST_TEST_EQ(pr.ceiling() - raw, 24);
            std::size_t n = 0;
            auto ec = feed(pr, n, msg.substr(0, 24));
            BOOST_TEST(ec == http::error::in_place_overflow);
            // and stays so
            pr.parse(n, ec);
            BOOST_TEST(ec == http::error::in_place_overflow);
        }
    }

    // Feed `s` to the parse base in chunks of at most
    // `chunk` bytes (0 for as much as fits below the
    // table), stopping once the parser stops asking for
    // bytes or the caller has none left to give. Reports
    // how much was placed.
    static
    system::error_code
    drive(
        head_parser& pr,
        std::string_view s,
        std::size_t chunk,
        std::size_t& fed)
    {
        auto* const base = base_of(pr);
        system::error_code ec;
        fed = 0;
        for(;;)
        {
            pr.parse(fed, ec);
            if(ec != http::error::need_data)
                break;
            auto const room = static_cast<std::size_t>(
                pr.ceiling() - (base + fed));
            if(room == 0 || fed == s.size())
                break;
            auto n = s.size() - fed;
            if(chunk != 0 && n > chunk)
                n = chunk;
            if(n > room)
                n = room;
            std::memcpy(base + fed, s.data() + fed, n);
            fed += n;
        }
        return ec;
    }

    // A request whose `nf` field lines are `fl` bytes
    // each, counting delimiters.
    static
    std::string
    fieldsHeader(
        std::size_t nf,
        std::size_t fl)
    {
        std::string s = "GET /x HTTP/1.1\r\n";
        for(std::size_t i = 0; i < nf; ++i)
        {
            auto const name = "X" + std::to_string(i);
            s += name + ": " +
                std::string(fl - name.size() - 4, 'v') + "\r\n";
        }
        return s + "\r\n";
    }

    void
    testBufferSweep()
    {
        // The field table grows down from the end of the
        // buffer while received bytes fill it from the
        // front, and prepare() withholds the room the
        // table needs. The two therefore cannot meet: for
        // any buffer address and size, any number of
        // fields and any chunking of the input, a header
        // which parses must read back byte for byte and
        // must leave the payload behind it untouched. A
        // failure to hold the reserve shows up here as a
        // field that reads back wrong, or as payload
        // bytes replaced by a table entry.
        alignas(4) char raw[1024];
        std::string const pay(40, 'P');

        for(std::size_t nf : { 0u, 1u, 3u, 8u })
        for(std::size_t mf : { 0u, 1u, 3u, 8u, 100u })
        for(std::size_t off : { 0u, 1u, 2u, 3u })
        {
            auto const h    = fieldsHeader(nf, 12);
            auto const wire = h + pay;
            auto const rsv  = table_space(mf);

            // buffer sizes bracketing the exact fit, so
            // the boundary between "completes" and
            // "cannot proceed in place" is crossed
            for(std::size_t d = 0; d <= 6; ++d)
            {
                auto const n = rsv + h.size() + d;
                if(off + n > sizeof(raw))
                    continue;

                system::error_code first;
                for(std::size_t chunk : { 0u, 1u, 7u })
                {
                    std::memset(raw, 0xCD, sizeof(raw));
                    head_parser pr(
                        true, raw + off, n, { .max_fields =
                            static_cast<std::uint16_t>(mf) });

                    // the region offered is always inside
                    // the buffer
                    BOOST_TEST(base_of(pr) == raw + off);
                    BOOST_TEST(pr.ceiling() >= raw + off);
                    BOOST_TEST(pr.ceiling() <= raw + off + n);

                    std::size_t fed = 0;
                    auto const ec = drive(pr, wire, chunk, fed);

                    // how the input is chunked cannot
                    // change the verdict
                    if(chunk == 0)
                        first = ec;
                    else
                        BOOST_TEST(ec == first);

                    if(ec)
                    {
                        BOOST_TEST(
                            ec == http::error::in_place_overflow ||
                            ec == http::error::fields_limit ||
                            ec == http::error::need_data);
                        continue;
                    }

                    // the header is exactly the bytes sent
                    auto const& hd = pr.message_head();
                    BOOST_TEST_EQ(hd.buffer(), h);
                    BOOST_TEST_EQ(hd.size(), nf);
                    for(std::size_t i = 0; i < nf; ++i)
                    {
                        auto const name = "X" + std::to_string(i);
                        BOOST_TEST_EQ(hd.begin()[i].name, name);
                        BOOST_TEST_EQ(
                            hd.begin()[i].value,
                            std::string(12 - name.size() - 4, 'v'));
                    }

                    // and the payload which followed it in
                    // is byte for byte where it landed
                    auto const got = fed - h.size();
                    auto const lo = leftovers(pr, fed);
                    BOOST_TEST_EQ(lo.size(), got);
                    BOOST_TEST(lo.data() == raw + off + h.size());
                    BOOST_TEST_EQ(
                        lo, std::string_view(pay).substr(0, got));

                    // leftovers and the still-writable
                    // region together stay in the buffer
                    BOOST_TEST(
                        lo.data() + lo.size() <= pr.ceiling());
                }
            }
        }
    }

    void
    testBufferSize()
    {
        // bytes_needed() is the contract between the
        // caller's allocation and the limits: a buffer of
        // that size must accept the largest header the
        // limits permit -- max_size bytes of text *and*
        // max_fields entries at the same time, which are
        // the two things that compete for the buffer.
        auto const maximal = [](
            std::size_t ms,
            std::size_t nf)
        {
            // with no field to pad, the target carries
            // the length instead
            if(nf == 0)
                return "GET /" + std::string(ms - 18, 'a') +
                    " HTTP/1.1\r\n\r\n";

            // "GET / HTTP/1.1\r\n" + nf fields + "\r\n"
            std::string s = "GET / HTTP/1.1\r\n";
            auto rem = ms - 18;
            for(std::size_t i = 0; i < nf; ++i)
            {
                auto const name = "X" + std::to_string(i);
                auto len = rem / (nf - i);
                if(i + 1 == nf)
                    len = rem;
                s += name + ": " +
                    std::string(len - name.size() - 4, 'v') + "\r\n";
                rem -= len;
            }
            return s + "\r\n";
        };

        for(std::uint16_t mf : { 0u, 1u, 3u, 8u, 100u })
        {
            // the smallest max_size which can carry
            // mf fields, and a couple of larger ones
            auto const least =
                static_cast<std::uint32_t>((18 + 8 * mf + 3) & ~3u);
            for(std::uint32_t ms :
                { least, least + 64u, least + 256u })
            {
                header_limits const lim{
                    .max_size = ms, .max_fields = mf };
                auto const h = maximal(ms, mf);
                BOOST_TEST_EQ(h.size(), ms);

                auto const cap = head_parser::bytes_needed(lim);
                auto owned = std::unique_ptr<char[]>(
                    new char[cap]);
                head_parser pr(true, owned.get(), cap, lim);
                std::size_t fed = 0;
                BOOST_TEST(! drive(pr, h, 0, fed));
                BOOST_TEST_EQ(pr.message_head().buffer(), h);
                BOOST_TEST_EQ(pr.message_head().size(), mf);

                // one alignment unit less is not enough:
                // the shortfall is reported, not absorbed
                // by eating into the table's room
                head_parser pr2(true, owned.get(), cap - 4, lim);
                std::size_t fed2 = 0;
                BOOST_TEST(
                    drive(pr2, h, 0, fed2) ==
                        http::error::in_place_overflow);
            }
        }
    }

    void
    testBufferSizeCap()
    {
        // the head is bounded by
        // fields_base::max_buffer_size, all the field
        // storage can hold, and the table by the field
        // count; the bytes which follow the head are not
        // stored as fields and are bounded only by
        // size_t. Limits which call for more must cap
        // through arithmetic which cannot wrap even where
        // size_t is 32 bits.
        constexpr std::size_t cap =
            fields_base::max_buffer_size;
        auto const table = table_space(100);
        auto const slack = align - 1;

        auto const most = std::uint32_t(-1);
        auto const huge = std::size_t(-1);

        // the head caps, and the table is added on top
        BOOST_TEST_EQ(head_parser::bytes_needed(
            { .max_size = most }), cap + slack + table);

        // extra is added in full, past that cap
        BOOST_TEST_EQ(head_parser::bytes_needed(
            { .max_size = most }, 4096),
            cap + 4096 + slack + table);

        // it caps only at what size_t can address, and
        // there the table gets what is left, which is
        // nothing
        BOOST_TEST_EQ(head_parser::bytes_needed({}, huge), huge);
        BOOST_TEST_EQ(head_parser::bytes_needed(
            { .max_size = most }, huge), huge);

        // the largest field count the limits can express
        // is small enough that the table never competes
        // with the cap
        auto const all =
            std::uint16_t(fields_base::max_field_count);
        BOOST_TEST_EQ(head_parser::bytes_needed(
            { .max_fields = all }),
            8192 + slack + table_space(all));
        BOOST_TEST_EQ(head_parser::bytes_needed(
            { .max_size = most, .max_fields = all },
            huge), huge);

        // an uncapped result is exactly what the
        // components add up to
        header_limits const lim{
            .max_size = 8192, .max_fields = 100 };
        BOOST_TEST_EQ(head_parser::bytes_needed(lim, 13),
            8192 + 13 + slack + table_space(100));
    }

    void
    testLimitSweep()
    {
        // max_size is spent by the start line first and
        // the field section gets what is left, as an
        // unsigned difference. Should that difference ever
        // wrap, the window becomes enormous, the limit
        // stops being applied, and the only visible
        // symptom is a header longer than max_size being
        // accepted -- no error, no crash. Sweep the whole
        // small-limit space against headers of several
        // shapes and assert the limit is never lost, and
        // that a header is accepted only in full.
        std::string const hs[] = {
            fieldsHeader(0, 0),    // 19
            fieldsHeader(1, 10),   // 29
            fieldsHeader(3, 10),   // 49
            fieldsHeader(2, 40),   // 99
            fieldsHeader(8, 8),    // 83
        };

        // generous, so in_place_overflow never stands in
        // for a limit verdict
        auto const cap = head_parser::bytes_needed(
            { .max_size = 4096 }, 256);
        auto owned = std::unique_ptr<char[]>(new char[cap]);

        for(auto const& h : hs)
        for(std::uint32_t ms = 0; ms <= 120; ++ms)
        for(std::uint16_t msl : { 0, 17, 64, 4096 })
        for(std::uint16_t mfd : { 0, 9, 40, 4096 })
        for(std::uint16_t mfl : { 0, 1, 3, 100 })
        {
            header_limits const lim{
                .max_size       = ms,
                .max_fields     = mfl,
                .max_start_line = msl,
                .max_field      = mfd };

            head_parser pr(true, owned.get(), cap, lim);
            std::size_t fed = 0;
            auto const ec = drive(pr, h, 0, fed);
            if(ec)
                continue;
            // a success must fit the limit it was given,
            // and must be the whole header
            BOOST_TEST(pr.message_head().buffer().size() <= ms);
            BOOST_TEST_EQ(pr.message_head().buffer(), h);
        }
    }

    void
    testFieldLineAtUint16Max()
    {
        // Field lengths reach the header through a
        // uint16_t, which is safe only because max_field
        // is one too. The per-field window is max_field+1
        // -- one byte wider than the limit, for the
        // obs-fold lookahead -- so this is the case where
        // a consumed length could reach 65536 and truncate
        // to zero. It must not: the extra byte is looked
        // at, never consumed.
        header_limits const lim{
            .max_size   = 200000,
            .max_fields = 8,
            .max_field  = 65535 };
        auto const cap = head_parser::bytes_needed(lim, 16);
        auto owned = std::unique_ptr<char[]>(new char[cap]);

        auto const with = [](std::size_t line)
        {
            // a field line of exactly `line` bytes
            return "GET / HTTP/1.1\r\nX: " +
                std::string(line - 5, 'v') + "\r\n\r\n";
        };

        auto const at = with(65535);
        head_parser pr(true, owned.get(), cap, lim);
        std::size_t fed = 0;
        BOOST_TEST(! drive(pr, at, 0, fed));
        BOOST_TEST_EQ(pr.message_head().buffer().size(), at.size());
        BOOST_TEST_EQ(
            pr.request_head().at("X").size(), 65535u - 5u);

        head_parser pr2(true, owned.get(), cap, lim);
        std::size_t fed2 = 0;
        BOOST_TEST(
            drive(pr2, with(65536), 0, fed2) ==
                http::error::field_size_limit);
    }

    void
    testResetFullBuffer()
    {
        // A message and the bytes behind it exactly fill
        // the writable region. The leftovers are bounded
        // by the region reset() re-arms, not by what is
        // left of the one it retires -- which is nothing.
        std::string const one =
            "GET / HTTP/1.1\r\nHost: x\r\n\r\n";

        header_limits const lim{ .max_fields = 2 };
        auto const table =
            table_space(lim.max_fields);
        auto const cap =
            (table + one.size() + 10 + align - 1) &
                ~(align - 1);
        // as many bytes as the region has past the header
        auto const carry = cap - table - one.size();
        auto const wire = one + std::string(carry, 'x');
        auto owned = std::unique_ptr<char[]>(new char[cap]);

        head_parser pr(true, owned.get(), cap, lim);
        std::size_t fed = 0;
        BOOST_TEST(! drive(pr, wire, 0, fed));
        BOOST_TEST(base_of(pr) + fed == pr.ceiling());

        auto const lo = leftovers(pr, fed);
        BOOST_TEST_EQ(lo.size(), carry);
        std::memmove(owned.get(), lo.data(), lo.size());
        pr.reset(owned.get());
        BOOST_TEST_EQ(
            pr.ceiling() - (owned.get() + lo.size()), one.size());
    }

    void
    testRebase()
    {
        std::string_view const msg =
            "GET /a HTTP/1.1\r\nHost: x\r\n\r\n";
        std::string_view const carry = "GET /b";

        // a header built away from the front, moved down
        // once it is complete
        head_parser pr(true, buf_, sizeof(buf_));
        pr.reset(buf_ + 64);
        std::size_t n = 0;
        BOOST_TEST(
            ! feed(pr, n, std::string(msg) + std::string(carry)));
        BOOST_TEST(pr.message_head().buffer().data() == buf_ + 64);

        std::memmove(buf_, buf_ + 64, n);
        pr.rebase(buf_);
        BOOST_TEST(pr.message_head().buffer().data() == buf_);
        BOOST_TEST_EQ(pr.message_head().buffer(), msg);
        BOOST_TEST_EQ(pr.request_head().target(), "/a");
        BOOST_TEST_EQ(pr.request_head().at(http::field::host), "x");
        BOOST_TEST_EQ(leftovers(pr, n), carry);

        // rebasing where it already is is harmless
        pr.rebase(buf_);
        BOOST_TEST_EQ(pr.request_head().target(), "/a");

        // a rebase in the middle of a parse keeps the
        // progress made so far
        head_parser pr2(true, buf_, sizeof(buf_));
        pr2.reset(buf_ + 64);
        std::size_t n2 = 0;
        BOOST_TEST(
            feed(pr2, n2, "GET /c HTTP/1.1\r\nHo") ==
                http::error::need_data);
        std::memmove(buf_, buf_ + 64, n2);
        pr2.rebase(buf_);
        BOOST_TEST(! feed(pr2, n2, "st: y\r\n\r\n"));
        BOOST_TEST_EQ(pr2.request_head().target(), "/c");
        BOOST_TEST_EQ(pr2.request_head().at(http::field::host), "y");
    }

    void
    testPipelineRounds()
    {
        // Several messages arrive back to back into a
        // buffer which holds barely more than one header,
        // so every round has leftovers to carry and the
        // window that receives them is the one reset()
        // just re-armed.
        std::string const one =
            "GET /a HTTP/1.1\r\nHost: x\r\n\r\n";
        auto const wire = one + one + one + one;

        header_limits const lim{ .max_fields = 2 };
        auto const cap =
            head_parser::bytes_needed(lim, one.size() / 2);
        auto owned = std::unique_ptr<char[]>(new char[cap]);

        head_parser pr(true, owned.get(), cap, lim);
        // bytes taken off the wire, and how many of
        // them are sitting at the parse base
        std::size_t sent = 0;
        std::size_t held = 0;
        int done = 0;
        for(int round = 0; round < 4; ++round)
        {
            system::error_code ec;
            for(;;)
            {
                pr.parse(held, ec);
                if(ec != http::error::need_data)
                    break;
                auto* const at = base_of(pr) + held;
                auto const room = static_cast<std::size_t>(
                    pr.ceiling() - at);
                if(room == 0 || sent == wire.size())
                    break;
                auto n = wire.size() - sent;
                if(n > room)
                    n = room;
                std::memcpy(at, wire.data() + sent, n);
                sent += n;
                held += n;
            }
            if(! BOOST_TEST(! ec))
                break;
            BOOST_TEST_EQ(pr.message_head().buffer(), one);
            BOOST_TEST_EQ(pr.request_head().at(http::field::host), "x");
            ++done;

            auto const lo = leftovers(pr, held);
            std::memmove(owned.get(), lo.data(), lo.size());
            pr.reset(owned.get());
            held = lo.size();
        }
        BOOST_TEST_EQ(done, 4);
    }

    void
    run()
    {
        testRequest();
        testIncremental();
        testResponse();
        testResponseVariants();
        testFraming();
        testObsFold();
        testFoldMatchesRescan();
        testRejectedHeader();
        testErrors();
        testLimits();
        testTableSpace();
        testOstream();
        testMove();
        testReset();
        testPipelined();
        testBufferGeometry();
        testBufferSweep();
        testBufferSize();
        testBufferSizeCap();
        testLimitSweep();
        testFieldLineAtUint16Max();
        testResetFullBuffer();
        testRebase();
        testPipelineRounds();
    }
};

TEST_SUITE(head_parser_test, "boost.burl.head_parser");

} // namespace burl
} // namespace boost
