//
// Copyright (c) 2026 Mohammad Nejati
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

// Test that header file is self-contained.
#include <boost/burl/parser.hpp>

#include <boost/burl/error.hpp>
#include <boost/burl/fields.hpp>
#include <boost/burl/static_fields.hpp>

#include <boost/capy/buffers.hpp>
#include <boost/capy/buffers/buffer_copy.hpp>
#include <boost/capy/buffers/buffer_param.hpp>
#include <boost/capy/buffers/buffer_slice.hpp>
#include <boost/capy/buffers/consuming_buffers.hpp>
#include <boost/capy/buffers/make_buffer.hpp>
#include <boost/capy/cond.hpp>
#include <boost/capy/error.hpp>
#include <boost/http/error.hpp>

#include <algorithm>
#include <array>
#include <cstring>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>

#include "test_suite.hpp"

namespace boost
{
namespace burl
{

// parser has protected members (it is a base for the request/response
// parsers) and performs no I/O: octets go in through prepare()/commit()
// and come back out through the sans-io operations. This shim exposes
// the protected members and adds a scripted wire, so that a test can say
// exactly what arrives and when, with no stream and no coroutine.
//
// The read_* members are the synchronous equivalents of what a @ref
// message_reader does over a socket: drive the parser, and whenever it
// asks for input hand it the next slice of the wire. An exhausted wire
// is a closed connection.
struct test_parser : parser
{
    test_parser(
        config const& cfg = {},
        bool is_request = false)
        : parser(cfg, is_request)
    {
    }

    //--------------------------------------------
    //
    // the wire
    //
    //--------------------------------------------

    // Append octets for later refills.
    void
    provide(std::string_view s)
    {
        wire_.append(s);
    }

    // Cap what a single refill delivers, the way a transport's read
    // size does.
    void
    max_read(std::size_t n) noexcept
    {
        max_read_ = n;
    }

    // Report the close together with the last octets rather than on a
    // following empty refill. Real transports do this.
    void
    eager_eof() noexcept
    {
        eager_eof_ = true;
    }

    // Hand the parser the next slice of the wire, or close.
    void
    refill()
    {
        if(pos_ == wire_.size())
            return commit_eof();
        auto const n = capy::buffer_copy(prepare(), next_());
        pos_ += n;
        commit(n);
        if(eager_eof_ && pos_ == wire_.size())
            commit_eof();
    }

    //--------------------------------------------
    //
    // protected surface
    //
    //--------------------------------------------

    void
    start(bool head = false)
    {
        parser::start(head);
    }

    response_head_base const&
    get() const
    {
        return get_response();
    }

    // Discard the parsing state and the scripted wire alike.
    void
    reset() noexcept
    {
        parser::reset();
        wire_.clear();
        pos_ = 0;
    }

    using parser::consume;

    //--------------------------------------------
    //
    // driving
    //
    //--------------------------------------------

    std::error_code
    read_header()
    {
        for(;;)
        {
            system::error_code ec;
            parse_header(ec);
            if(ec != http::error::need_data)
                return ec;
            refill();
        }
    }

    std::pair<std::error_code, std::string_view>
    read_body()
    {
        if(! got_header())
            if(auto ec = read_header(); ec)
                return { ec, {} };

        for(;;)
        {
            system::error_code ec;
            auto const sv = flatten_body(ec);
            if(ec != http::error::need_data)
                return { ec, sv };
            refill();
        }
    }

    template<capy::MutableBufferSequence MB>
    std::pair<std::error_code, std::size_t>
    read_some(MB buffers)
    {
        if(! got_header())
            if(auto ec = read_header(); ec)
                return { ec, 0 };

        capy::buffer_param bp(buffers);

        for(;;)
        {
            system::error_code ec;
            auto const n = parser::read_some(bp.data(), ec);
            if(ec != http::error::need_data)
                return { ec, n };

            if(auto const lim = direct_capacity(); lim != 0)
            {
                auto const mbs = bp.data();
                auto const rn = direct_read(
                    capy::buffer_slice(mbs, 0, lim));
                if(rn != 0)
                    return { std::error_code(), rn };
                continue;
            }

            refill();
        }
    }

    // hand the parser the span exactly as given, with no
    // buffer_param in between to drop the empty buffers
    std::pair<std::error_code, std::size_t>
    read_some_raw(std::span<capy::mutable_buffer const> buffers)
    {
        if(! got_header())
            if(auto ec = read_header(); ec)
                return { ec, 0 };

        for(;;)
        {
            system::error_code ec;
            auto const n = parser::read_some(buffers, ec);
            if(ec != http::error::need_data)
                return { ec, n };
            refill();
        }
    }

    template<capy::MutableBufferSequence MB>
    std::pair<std::error_code, std::size_t>
    read(MB buffers)
    {
        auto const total_size = capy::buffer_size(buffers);
        capy::consuming_buffers dest(buffers);
        std::size_t total = 0;

        while(total < total_size)
        {
            auto [ec, n] = read_some(dest.data());
            dest.consume(n);
            total += n;
            if(ec && total < total_size)
                return { ec, total };
        }

        return { std::error_code(), total };
    }

    std::pair<std::error_code, std::span<capy::const_buffer>>
    pull(std::span<capy::const_buffer> dest)
    {
        if(! got_header())
            if(auto ec = read_header(); ec)
                return { ec, {} };

        for(;;)
        {
            system::error_code ec;
            auto const bufs = parser::pull(dest, ec);
            if(ec != http::error::need_data)
                return { ec, bufs };
            refill();
        }
    }

private:
    // The pass-through read: octets travel from the wire straight into
    // the caller's memory, never entering the parser's buffer.
    template<capy::MutableBufferSequence MB>
    std::size_t
    direct_read(MB buffers)
    {
        if(pos_ == wire_.size())
        {
            commit_eof();
            return 0;
        }
        auto const n = capy::buffer_copy(buffers, next_());
        pos_ += n;
        commit_direct(n);
        if(eager_eof_ && pos_ == wire_.size())
            commit_eof();
        return n;
    }

    capy::const_buffer
    next_() const noexcept
    {
        return { wire_.data() + pos_,
            (std::min)(wire_.size() - pos_, max_read_) };
    }

    std::string wire_;
    std::size_t pos_ = 0;
    std::size_t max_read_ = std::size_t(-1);
    bool eager_eof_ = false;
};

class parser_test
{
    // A decoder that increments every body byte by one, so decoded
    // output is distinguishable from identity output. Its end-of-
    // stream behavior is scriptable to cover every decoder-side
    // contract: finishing on the eof kick (optionally emitting a
    // trailer first), finishing exactly at `eof_at` consumed octets
    // (zlib-style, or early), failing at `fail_at` alongside partial
    // output, or never finishing at all (a truncated stream).
    struct test_decoder : parser::decoder
    {
        std::string trailer;
        std::error_code fail_ec;
        std::uint64_t fail_at = std::uint64_t(-1);
        std::uint64_t eof_at  = std::uint64_t(-1);
        bool ignore_eof = false;
        std::size_t max_step = std::size_t(-1);
        std::uint64_t consumed_total = 0;
        bool finished = false;

        result
        process(
            capy::mutable_buffer out,
            capy::const_buffer in,
            bool more) override
        {
            if(fail_ec && consumed_total >= fail_at)
                return { 0, 0, fail_ec };
            if(consumed_total >= eof_at)
            {
                finished = true;
                return { 0, 0, capy::error::eof };
            }

            auto* dst = static_cast<unsigned char*>(out.data());
            auto* src = static_cast<unsigned char const*>(in.data());
            auto n = (std::min)(out.size(), in.size());
            n = (std::min)(n, max_step);
            if(fail_ec)
                n = (std::min<std::uint64_t>)(
                    n, fail_at - consumed_total);
            n = (std::min<std::uint64_t>)(n, eof_at - consumed_total);
            for(std::size_t i = 0; i != n; ++i)
                dst[i] = static_cast<unsigned char>(src[i] + 1);
            consumed_total += n;

            result r{ n, n, {} };
            if(fail_ec && consumed_total >= fail_at)
            {
                r.ec = fail_ec;
                return r;
            }
            if(consumed_total >= eof_at)
            {
                finished = true;
                r.ec = capy::error::eof;
                return r;
            }
            if(!more && n == in.size() && !ignore_eof)
            {
                auto const t = (std::min)(
                    out.size() - n, trailer.size() - trailer_pos_);
                std::memcpy(
                    dst + n, trailer.data() + trailer_pos_, t);
                trailer_pos_ += t;
                r.produced += t;
                if(trailer_pos_ == trailer.size())
                {
                    finished = true;
                    r.ec = capy::error::eof;
                }
            }
            return r;
        }

    private:
        std::size_t trailer_pos_ = 0;
    };

    static
    std::string
    make_body(std::size_t n)
    {
        std::string s(n, '\0');
        for(std::size_t i = 0; i != n; ++i)
            s[i] = static_cast<char>('0' + i % 64);
        return s;
    }

    // The mock-decoded form of `s`.
    static
    std::string
    decoded(std::string_view s)
    {
        std::string r(s);
        for(auto& c : r)
            c = static_cast<char>(c + 1);
        return r;
    }

public:
    //--------------------------------------------
    //
    // header
    //
    //--------------------------------------------

    void
    testHeader()
    {
        test_parser pr;
        pr.provide(
            "HTTP/1.1 200 OK\r\n"
            "Content-Length: 5\r\n"
            "\r\n");

        pr.start();
        auto ec = pr.read_header();
        BOOST_TEST(!ec);
        BOOST_TEST(pr.got_header());
        BOOST_TEST_EQ(pr.get().status_int(), 200);

        // no body octet has arrived yet
        BOOST_TEST(!pr.got_body());

        // repeated calls are no-ops
        auto ec2 = pr.read_header();
        BOOST_TEST(!ec2);
    }

    void
    testHeaderEagerComplete()
    {
        test_parser pr;
        pr.provide(
            "HTTP/1.1 200 OK\r\n"
            "Content-Length: 5\r\n"
            "\r\n"
            "hello");

        pr.start();
        auto ec = pr.read_header();
        BOOST_TEST(!ec);

        // the whole body arrived with the header: complete
        // (arrival) but not drained (undelivered)
        BOOST_TEST(pr.got_body());
        BOOST_TEST(!pr.has_buffered_data());
    }

    void
    testHeaderSyntaxError()
    {
        test_parser pr;
        pr.provide("BOGUS NONSENSE\r\n\r\n");

        pr.start();
        auto ec = pr.read_header();
        BOOST_TEST(ec);
        BOOST_TEST(!pr.got_header());
        BOOST_TEST(!pr.got_body());

        // terminal: the same error repeats deterministically
        auto ec2 = pr.read_header();
        BOOST_TEST(ec2 == ec);
        char buf[4];
        auto [ec3, n] = pr.read_some(capy::make_buffer(buf));
        BOOST_TEST(ec3 == ec);
        BOOST_TEST_EQ(n, 0);
    }

    void
    testHeaderPayloadError()
    {
        test_parser pr;

        // Content-Length together with Transfer-Encoding
        // makes the payload undefined; the header parser
        // rejects it as the second of the two is parsed,
        // so the header never completes
        pr.provide(
            "HTTP/1.1 200 OK\r\n"
            "Content-Length: 5\r\n"
            "Transfer-Encoding: chunked\r\n"
            "\r\n"
            "hello");

        pr.start();
        auto ec = pr.read_header();
        BOOST_TEST(ec == http::error::bad_payload);
        BOOST_TEST(!pr.got_header());
        BOOST_TEST(!pr.got_body());
    }

    void
    testRequestBadTransferEncoding()
    {
        test_parser pr({}, true);

        // a request whose Transfer-Encoding does not end in
        // chunked has no defined length; unlike a response it
        // has no to-eof fallback, so the header is rejected
        pr.provide(
            "PUT / HTTP/1.1\r\n"
            "Transfer-Encoding: gzip\r\n"
            "\r\n");

        pr.start();
        auto ec = pr.read_header();
        BOOST_TEST(ec == http::error::bad_transfer_encoding);
        BOOST_TEST(!pr.got_header());
        BOOST_TEST(!pr.got_body());
    }

    void
    testEndOfStream()
    {
        // a clean close before any octet of the message: the
        // retryable stale-connection signal
        test_parser pr;

        pr.start();
        auto ec = pr.read_header();
        BOOST_TEST(ec == http::error::end_of_stream);
        BOOST_TEST(!pr.got_header());

        auto ec2 = pr.read_header();
        BOOST_TEST(ec2 == http::error::end_of_stream);
    }

    void
    testIncompleteHeader()
    {
        test_parser pr;
        pr.provide("HTTP/1.1 200 OK\r\nContent-");

        pr.start();
        auto ec = pr.read_header();
        BOOST_TEST(ec == http::error::incomplete);
        BOOST_TEST(!pr.got_header());

        auto ec2 = pr.read_header();
        BOOST_TEST(ec2 == http::error::incomplete);
    }

    void
    testHeaderResumes()
    {
        // a header split across refills is resumed, not restarted:
        // each partial arrival asks for more input and leaves the
        // parser usable. The start line is 17 octets, so five
        // refills of four deliver it without reaching the close.
        test_parser pr;
        pr.provide("HTTP/1.1 200 OK\r\n");
        pr.max_read(4);

        pr.start();
        for(int i = 0; i != 5; ++i)
        {
            system::error_code ec;
            pr.parse_header(ec);
            BOOST_TEST(ec == http::error::need_data);
            BOOST_TEST(!pr.got_header());
            pr.refill();
        }

        pr.provide(
            "Content-Length: 5\r\n"
            "\r\n"
            "hello");
        auto [ec, body] = pr.read_body();
        BOOST_TEST(!ec);
        BOOST_TEST(body == "hello");
    }

    void
    testHeaderLargerThanBuffer()
    {
        // the fill window always covers max_size, so a header can
        // never starve the buffer; the parser's own limit fires
        parser::config cfg;
        cfg.hdr_limits.max_fields = 1;
        cfg.hdr_limits.max_size = 64;
        test_parser pr(cfg);

        pr.provide(
            "HTTP/1.1 200 OK\r\n"
            "X-Filler: " + std::string(100, 'x') + "\r\n"
            "\r\n");

        pr.start();
        auto ec = pr.read_header();
        BOOST_TEST(ec == http::error::headers_limit);

        // exceeding a header limit is terminal
        auto ec2 = pr.read_header();
        BOOST_TEST(ec2 == http::error::headers_limit);
    }

    //--------------------------------------------
    //
    // payload::size
    //
    //--------------------------------------------

    void
    testSizedReadSome()
    {
        test_parser pr;
        pr.provide(
            "HTTP/1.1 200 OK\r\n"
            "Content-Length: 5\r\n"
            "\r\n"
            "hello");

        pr.start();
        auto ec = pr.read_header();
        BOOST_TEST(!ec);

        char buf[3];
        {
            auto [ec, n] = pr.read_some(capy::make_buffer(buf));
            BOOST_TEST(!ec);
            BOOST_TEST_EQ(n, 3);
            BOOST_TEST(std::string_view(buf, n) == "hel");
        }
        {
            auto [ec, n] = pr.read_some(capy::make_buffer(buf));
            BOOST_TEST(!ec);
            BOOST_TEST_EQ(n, 2);
            BOOST_TEST(std::string_view(buf, n) == "lo");
        }
        BOOST_TEST(pr.got_body());
        BOOST_TEST(!pr.has_buffered_data());
        // terminal success repeats deterministically
        {
            auto [ec, n] = pr.read_some(capy::make_buffer(buf));
            BOOST_TEST(ec == capy::cond::eof);
            BOOST_TEST_EQ(n, 0);
        }
        {
            auto [ec, n] = pr.read(capy::make_buffer(buf));
            BOOST_TEST(ec == capy::cond::eof);
            BOOST_TEST_EQ(n, 0);
        }
    }

    void
    testSizedPullConsume()
    {
        test_parser pr;
        pr.provide(
            "HTTP/1.1 200 OK\r\n"
            "Content-Length: 5\r\n"
            "\r\n"
            "hello");

        pr.start();
        auto ec = pr.read_header();
        BOOST_TEST(!ec);

        capy::const_buffer arr[2];
        {
            auto [ec, bufs] = pr.pull(arr);
            BOOST_TEST(!ec);
            BOOST_TEST_EQ(bufs.size(), 1);
            BOOST_TEST_EQ(bufs[0].size(), 5);
        }
        pr.consume(3);
        {
            // unconsumed data is re-returned
            auto [ec, bufs] = pr.pull(arr);
            BOOST_TEST(!ec);
            BOOST_TEST_EQ(bufs.size(), 1);
            BOOST_TEST_EQ(bufs[0].size(), 2);
        }
        pr.consume(2);
        BOOST_TEST(pr.got_body());
        {
            auto [ec, bufs] = pr.pull(arr);
            BOOST_TEST(ec == capy::cond::eof);
            BOOST_TEST_EQ(bufs.size(), 0);
        }
        {
            auto [ec, bufs] = pr.pull(arr);
            BOOST_TEST(ec == capy::cond::eof);
            BOOST_TEST_EQ(bufs.size(), 0);
        }
    }

    void
    testSizedReadBody()
    {
        test_parser pr;
        pr.provide(
            "HTTP/1.1 200 OK\r\n"
            "Content-Length: 5\r\n"
            "\r\n"
            "hello");

        pr.start();
        {
            auto [ec, body] = pr.read_body();
            BOOST_TEST(!ec);
            BOOST_TEST(body == "hello");
        }
        BOOST_TEST(pr.got_body());
        BOOST_TEST(!pr.has_buffered_data());

        // read_body is non-destructive: the view is stable and
        // the parser is not drained
        {
            auto [ec, body] = pr.read_body();
            BOOST_TEST(!ec);
            BOOST_TEST(body == "hello");
        }

        // a streaming read serves the same bytes
        char buf[8];
        auto [ec, n] = pr.read_some(capy::make_buffer(buf));
        BOOST_TEST(!ec);
        BOOST_TEST_EQ(n, 5);
        BOOST_TEST(std::string_view(buf, n) == "hello");
        auto [ec2, n2] = pr.read_some(capy::make_buffer(buf));
        BOOST_TEST(ec2 == capy::cond::eof);
        BOOST_TEST_EQ(n2, 0);
    }

    void
    testSizedTrailingJunk()
    {
        test_parser pr;
        pr.provide(
            "HTTP/1.1 200 OK\r\n"
            "Content-Length: 5\r\n"
            "\r\n"
            "helloJUNK");

        pr.start();
        char buf[16];
        auto [ec, n] = pr.read_some(capy::make_buffer(buf));
        BOOST_TEST(!ec);
        BOOST_TEST_EQ(n, 5);
        BOOST_TEST(std::string_view(buf, n) == "hello");
        auto [ec2, n2] = pr.read_some(capy::make_buffer(buf));
        BOOST_TEST(ec2 == capy::cond::eof);
        BOOST_TEST_EQ(n2, 0);
        BOOST_TEST(pr.got_body());
        BOOST_TEST(pr.has_buffered_data());
    }

    void
    testSizedZeroLength()
    {
        test_parser pr;
        pr.provide(
            "HTTP/1.1 200 OK\r\n"
            "Content-Length: 0\r\n"
            "\r\n");

        pr.start();
        auto ec = pr.read_header();
        BOOST_TEST(!ec);
        BOOST_TEST(pr.got_body());
        {
            auto [ec, body] = pr.read_body();
            BOOST_TEST(!ec);
            BOOST_TEST(body.empty());
        }
        char buf[4];
        {
            auto [ec, n] = pr.read_some(capy::make_buffer(buf));
            BOOST_TEST(ec == capy::cond::eof);
            BOOST_TEST_EQ(n, 0);
        }
        capy::const_buffer arr[2];
        {
            auto [ec, bufs] = pr.pull(arr);
            BOOST_TEST(ec == capy::cond::eof);
            BOOST_TEST_EQ(bufs.size(), 0);
        }
    }

    void
    testSizedIncomplete()
    {
        test_parser pr;
        pr.provide(
            "HTTP/1.1 200 OK\r\n"
            "Content-Length: 5\r\n"
            "\r\n"
            "hel");

        pr.start();
        char buf[8];
        {
            auto [ec, n] = pr.read_some(capy::make_buffer(buf));
            BOOST_TEST(!ec);
            BOOST_TEST_EQ(n, 3);
        }
        {
            auto [ec, n] = pr.read_some(capy::make_buffer(buf));
            BOOST_TEST(ec == http::error::incomplete);
            BOOST_TEST_EQ(n, 0);
        }
        BOOST_TEST(!pr.got_body());
        {
            auto [ec, n] = pr.read_some(capy::make_buffer(buf));
            BOOST_TEST(ec == http::error::incomplete);
            BOOST_TEST_EQ(n, 0);
        }
    }

    void
    testSizedReadBodyIncomplete()
    {
        test_parser pr;
        pr.provide(
            "HTTP/1.1 200 OK\r\n"
            "Content-Length: 5\r\n"
            "\r\n"
            "hel");

        pr.start();
        // the octets which did arrive are still flattened and
        // viewable; the error says the body is not all there
        auto [ec, body] = pr.read_body();
        BOOST_TEST(ec == http::error::incomplete);
        BOOST_TEST(body == "hel");

        auto [ec2, body2] = pr.read_body();
        BOOST_TEST(ec2 == http::error::incomplete);
        BOOST_TEST(body2 == "hel");
    }

    void
    testSizedBodyLimit()
    {
        parser::config cfg;
        cfg.body_limit = 4;
        test_parser pr(cfg);
        pr.provide(
            "HTTP/1.1 200 OK\r\n"
            "Content-Length: 5\r\n"
            "\r\n"
            "hello");

        pr.start();
        auto ec = pr.read_header();
        BOOST_TEST(!ec);
        BOOST_TEST(pr.got_header());

        char buf[16];
        // the declared length alone settles it: no
        // octet is delivered
        auto [ec2, n] = pr.read_some(capy::make_buffer(buf));
        BOOST_TEST(ec2 == http::error::body_too_large);
        BOOST_TEST_EQ(n, 0);
    }

    void
    testSizedBodyLimitViaReadBody()
    {
        parser::config cfg;
        cfg.body_limit = 4;
        test_parser pr(cfg);
        pr.provide(
            "HTTP/1.1 200 OK\r\n"
            "Content-Length: 5\r\n"
            "\r\n"
            "hello");

        pr.start();
        // the declared length alone settles it: the body can never
        // be returned whole, and no refill will change that
        auto [ec, body] = pr.read_body();
        BOOST_TEST(ec == http::error::body_too_large);
    }

    void
    testSizedPullBodyLimitZero()
    {
        // a zero budget fails the pull before any delivery
        parser::config cfg;
        cfg.body_limit = 0;
        test_parser pr(cfg);
        pr.provide(
            "HTTP/1.1 200 OK\r\n"
            "Content-Length: 5\r\n"
            "\r\n"
            "hello");

        pr.start();
        capy::const_buffer arr[2];
        auto [ec, bufs] = pr.pull(arr);
        BOOST_TEST(ec == http::error::body_too_large);
        BOOST_TEST_EQ(bufs.size(), 0);
    }

    void
    testSizedMixedStreamThenView()
    {
        test_parser pr;
        pr.provide(
            "HTTP/1.1 200 OK\r\n"
            "Content-Length: 5\r\n"
            "\r\n"
            "hello");

        pr.start();
        char buf[2];
        {
            auto [ec, n] = pr.read_some(capy::make_buffer(buf));
            BOOST_TEST(!ec);
            BOOST_TEST_EQ(n, 2);
        }
        // the octets already streamed out are gone, so flattening
        // what is left yields the remainder rather than the whole
        // body
        auto [ec, body] = pr.read_body();
        BOOST_TEST(!ec);
        BOOST_TEST(body == "llo");
        BOOST_TEST(pr.got_body());
    }

    void
    testSizedReadBodyOverflow()
    {
        constexpr std::string_view hdr =
            "HTTP/1.1 200 OK\r\n"
            "Content-Length: 40\r\n"
            "\r\n";

        // in_ is sized so the header fits but the body does not:
        // an exact header window leaves 25 octets for the body
        parser::config cfg;
        cfg.hdr_limits.max_fields = 1;
        cfg.hdr_limits.max_size = hdr.size();
        cfg.in_buffer = 25;
        test_parser pr(cfg);

        auto const body = make_body(40);
        pr.provide(std::string(hdr) + body);

        pr.start();
        {
            // the buffer cannot hold the whole body; what fits is
            // still flattened and viewable
            auto [ec, part] = pr.read_body();
            BOOST_TEST(ec == http::error::in_place_overflow);
            BOOST_TEST(part == std::string_view(body).substr(0, 25));
        }
        // delivery-side overflow is transient: streaming reads
        // drain the whole message (read_body did not consume)
        std::string got;
        for(;;)
        {
            char buf[16];
            auto [ec, n] = pr.read_some(capy::make_buffer(buf));
            got.append(buf, n);
            if(ec)
            {
                BOOST_TEST(ec == capy::cond::eof);
                break;
            }
        }
        BOOST_TEST(got == body);
        BOOST_TEST(pr.got_body());
    }

    //--------------------------------------------
    //
    // payload::chunked
    //
    //--------------------------------------------

    void
    testChunkedReadSome()
    {
        test_parser pr;
        pr.provide(
            "HTTP/1.1 200 OK\r\n"
            "Transfer-Encoding: chunked\r\n"
            "\r\n"
            "5\r\nhello\r\n"
            "0\r\n\r\n");

        pr.start();
        char buf[3];
        {
            auto [ec, n] = pr.read_some(capy::make_buffer(buf));
            BOOST_TEST(!ec);
            BOOST_TEST_EQ(n, 3);
            BOOST_TEST(std::string_view(buf, n) == "hel");
        }
        {
            auto [ec, n] = pr.read_some(capy::make_buffer(buf));
            BOOST_TEST(!ec);
            BOOST_TEST_EQ(n, 2);
            BOOST_TEST(std::string_view(buf, n) == "lo");
        }
        BOOST_TEST(pr.got_body());

        // the terminal framing was consumed: the connection
        // holds nothing beyond the message
        BOOST_TEST(!pr.has_buffered_data());
        {
            auto [ec, n] = pr.read_some(capy::make_buffer(buf));
            BOOST_TEST(ec == capy::cond::eof);
            BOOST_TEST_EQ(n, 0);
        }
    }

    void
    testChunkedPullConsume()
    {
        test_parser pr;
        pr.provide(
            "HTTP/1.1 200 OK\r\n"
            "Transfer-Encoding: chunked\r\n"
            "\r\n"
            "5\r\nhello\r\n"
            "8\r\nuniverse\r\n"
            "0\r\n\r\n");

        pr.start();
        capy::const_buffer arr[2];
        {
            auto [ec, bufs] = pr.pull(arr);
            BOOST_TEST(!ec);
            BOOST_TEST_EQ(bufs.size(), 2);
            BOOST_TEST_EQ(bufs[0].size(), 5);
            BOOST_TEST_EQ(bufs[1].size(), 8);
        }
        pr.consume(3);
        {
            auto [ec, bufs] = pr.pull(arr);
            BOOST_TEST(!ec);
            BOOST_TEST_EQ(bufs.size(), 2);
            BOOST_TEST_EQ(bufs[0].size(), 2);
            BOOST_TEST_EQ(bufs[1].size(), 8);
        }
        pr.consume(10);
        BOOST_TEST(pr.got_body());
        BOOST_TEST(!pr.has_buffered_data());
        {
            auto [ec, bufs] = pr.pull(arr);
            BOOST_TEST(ec == capy::cond::eof);
            BOOST_TEST_EQ(bufs.size(), 0);
        }
    }

    void
    testChunkedReadBody()
    {
        test_parser pr;
        pr.provide(
            "HTTP/1.1 200 OK\r\n"
            "Transfer-Encoding: chunked\r\n"
            "\r\n"
            "5\r\nhello\r\n"
            "6\r\n world\r\n"
            "0\r\n\r\n");

        pr.start();
        {
            auto [ec, body] = pr.read_body();
            BOOST_TEST(!ec);
            BOOST_TEST(body == "hello world");
        }
        BOOST_TEST(pr.got_body());
        BOOST_TEST(!pr.has_buffered_data());
        {
            // stable repeated view
            auto [ec, body] = pr.read_body();
            BOOST_TEST(!ec);
            BOOST_TEST(body == "hello world");
        }
        // a streaming switch drains the parked dechunked bytes
        char buf[16];
        auto [ec, n] = pr.read_some(capy::make_buffer(buf));
        BOOST_TEST(!ec);
        BOOST_TEST_EQ(n, 11);
        BOOST_TEST(std::string_view(buf, n) == "hello world");
        auto [ec2, n2] = pr.read_some(capy::make_buffer(buf));
        BOOST_TEST(ec2 == capy::cond::eof);
        BOOST_TEST_EQ(n2, 0);
    }

    void
    testChunkedReadBodyByteByByte()
    {
        // one octet per refill exercises every resume point of the
        // in-place flattening walk: split chunk-size line, split
        // extension, split chunk data, split closing CRLF, and
        // split trailers
        test_parser pr;
        pr.max_read(1);
        pr.provide(
            "HTTP/1.1 200 OK\r\n"
            "Transfer-Encoding: chunked\r\n"
            "\r\n"
            "5;ext=1\r\nhello\r\n"
            "6\r\n world\r\n"
            "0\r\n"
            "X-Trailer: v\r\n"
            "\r\n");

        pr.start();
        auto [ec, body] = pr.read_body();
        BOOST_TEST(!ec);
        BOOST_TEST(body == "hello world");
        BOOST_TEST(pr.got_body());
        BOOST_TEST(!pr.has_buffered_data());
    }

    void
    testChunkedReadBodySplitMidChunk()
    {
        // a chunk larger than a single refill needs several of
        // them; the missing bytes must land in position without
        // corrupting the already-flattened prefix
        test_parser pr;
        pr.max_read(4);
        pr.provide(
            "HTTP/1.1 200 OK\r\n"
            "Transfer-Encoding: chunked\r\n"
            "\r\n"
            "1a\r\nabcdefghijklmnopqrstuvwxyz\r\n"
            "0\r\n\r\n");

        pr.start();
        auto [ec, body] = pr.read_body();
        BOOST_TEST(!ec);
        BOOST_TEST(body == "abcdefghijklmnopqrstuvwxyz");
        BOOST_TEST(pr.got_body());
        BOOST_TEST(!pr.has_buffered_data());
    }

    void
    testChunkedReadBodyPipelined()
    {
        test_parser pr;
        pr.provide(
            "HTTP/1.1 200 OK\r\n"
            "Transfer-Encoding: chunked\r\n"
            "\r\n"
            "5\r\nhello\r\n"
            "6\r\n world\r\n"
            "0\r\n\r\n"
            "NEXT");

        pr.start();
        auto [ec, body] = pr.read_body();
        BOOST_TEST(!ec);
        BOOST_TEST(body == "hello world");
        BOOST_TEST(pr.got_body());

        // the pipelined octets survive the compaction and sit
        // right past the body view
        BOOST_TEST(pr.has_buffered_data());
    }

    void
    testChunkedTrailersAndExtensions()
    {
        test_parser pr;
        pr.provide(
            "HTTP/1.1 200 OK\r\n"
            "Transfer-Encoding: chunked\r\n"
            "\r\n"
            "5;ext=value\r\nhello\r\n"
            "0\r\n"
            "X-Trailer: yes\r\n"
            "X-More: sure\r\n"
            "\r\n"
            "NEXT");

        pr.start();
        char buf[16];
        auto [ec, n] = pr.read_some(capy::make_buffer(buf));
        BOOST_TEST(!ec);
        BOOST_TEST_EQ(n, 5);
        auto [ec2, n2] = pr.read_some(capy::make_buffer(buf));
        BOOST_TEST(ec2 == capy::cond::eof);
        BOOST_TEST_EQ(n2, 0);
        BOOST_TEST(pr.got_body());

        // trailers consumed with the message; the pipelined
        // octets past it are detected
        BOOST_TEST(pr.has_buffered_data());
    }

    void
    testTrailerReadSome()
    {
        test_parser pr;
        pr.provide(
            "HTTP/1.1 200 OK\r\n"
            "Transfer-Encoding: chunked\r\n"
            "\r\n"
            "5\r\nhello\r\n"
            "0\r\n"
            "Expires: never\r\n"
            "X-Dup: 1\r\n"
            "X-Dup: 2\r\n"
            "\r\n"
            "NEXT");

        pr.start();
        char buf[16];
        auto [ec, n] = pr.read_some(capy::make_buffer(buf));
        BOOST_TEST(!ec);
        BOOST_TEST_EQ(n, 5);
        auto [ec2, n2] = pr.read_some(capy::make_buffer(buf));
        BOOST_TEST(ec2 == capy::cond::eof);
        BOOST_TEST_EQ(n2, 0);
        BOOST_TEST(pr.got_body());

        // the retained trailer does not count as data
        // beyond the message; the pipelined octets do
        BOOST_TEST(pr.has_buffered_data());

        fields f;
        system::error_code tec;
        pr.parse_trailer(f, tec);
        BOOST_TEST(!tec);
        BOOST_TEST_EQ(f.size(), 3u);

        // insertion order, known-field resolution, and
        // duplicates are preserved
        BOOST_TEST((*f.begin()).name == "Expires");
        BOOST_TEST(f.at(http::field::expires) == "never");
        auto r  = f.find_all("X-Dup");
        auto it = r.begin();
        BOOST_TEST(*it == "1");
        BOOST_TEST(*++it == "2");

        // each call appends again
        pr.parse_trailer(f, tec);
        BOOST_TEST(!tec);
        BOOST_TEST_EQ(f.size(), 6u);
    }

    void
    testTrailerReadBody()
    {
        test_parser pr;
        pr.provide(
            "HTTP/1.1 200 OK\r\n"
            "Transfer-Encoding: chunked\r\n"
            "\r\n"
            "5\r\nhello\r\n"
            "6\r\n world\r\n"
            "0\r\n"
            "X-Trailer: v\r\n"
            "\r\n"
            "HTTP/1.1 200 OK\r\n"
            "Content-Length: 3\r\n"
            "\r\n"
            "bye");

        pr.start();
        auto [ec, body] = pr.read_body();
        BOOST_TEST(!ec);
        BOOST_TEST(body == "hello world");

        fields f;
        system::error_code tec;
        pr.parse_trailer(f, tec);
        BOOST_TEST(!tec);
        BOOST_TEST_EQ(f.size(), 1u);
        BOOST_TEST(f.at("X-Trailer") == "v");

        // a flattened trailer is extracted in place: the
        // view returned by read_body survives
        BOOST_TEST(body == "hello world");
        BOOST_TEST(pr.has_buffered_data());

        // the undelivered view and the trailer are both
        // skipped by the restart
        pr.start();
        auto [ec2, body2] = pr.read_body();
        BOOST_TEST(!ec2);
        BOOST_TEST(body2 == "bye");
        BOOST_TEST(!pr.has_buffered_data());
    }

    void
    testTrailerPullConsume()
    {
        test_parser pr;
        pr.provide(
            "HTTP/1.1 200 OK\r\n"
            "Transfer-Encoding: chunked\r\n"
            "\r\n"
            "3\r\nabc\r\n"
            "0\r\n"
            "X-T: v\r\n"
            "\r\n");

        pr.start();

        {
            // the dry window: pull has described the whole
            // message, but until it reports eof the framing
            // is not finalized and the trailer is unavailable
            capy::const_buffer arr[2];
            auto [ec, bufs] = pr.pull(arr);
            BOOST_TEST(!ec);
            BOOST_TEST(pr.got_body());
            fields f;
            system::error_code tec;
            pr.parse_trailer(f, tec);
            BOOST_TEST(tec == http::error::incomplete);
            BOOST_TEST_EQ(f.size(), 0u);
        }

        std::string got;
        for(;;)
        {
            capy::const_buffer arr[2];
            auto [ec, bufs] = pr.pull(arr);
            if(ec)
            {
                BOOST_TEST(ec == capy::cond::eof);
                break;
            }
            for(auto b : bufs)
                got.append(
                    static_cast<char const*>(b.data()), b.size());
            pr.consume(capy::buffer_size(bufs));
        }
        BOOST_TEST(got == "abc");

        fields f;
        system::error_code tec;
        pr.parse_trailer(f, tec);
        BOOST_TEST(!tec);
        BOOST_TEST_EQ(f.size(), 1u);
        BOOST_TEST(f.at("X-T") == "v");
    }

    void
    testTrailerEmptyAndNonChunked()
    {
        {
            // an empty trailer section appends nothing
            test_parser pr;
            pr.provide(
                "HTTP/1.1 200 OK\r\n"
                "Transfer-Encoding: chunked\r\n"
                "\r\n"
                "0\r\n\r\n");

            pr.start();
            auto [ec, body] = pr.read_body();
            BOOST_TEST(!ec);
            BOOST_TEST(body == "");
            BOOST_TEST(!pr.has_buffered_data());

            fields f;
            system::error_code tec;
            pr.parse_trailer(f, tec);
            BOOST_TEST(!tec);
            BOOST_TEST(f.empty());
        }
        {
            // non-chunked messages have no trailer
            test_parser pr;
            pr.provide(
                "HTTP/1.1 200 OK\r\n"
                "Content-Length: 5\r\n"
                "\r\n"
                "hello");

            pr.start();
            auto [ec, body] = pr.read_body();
            BOOST_TEST(!ec);
            BOOST_TEST(body == "hello");

            fields f;
            system::error_code tec;
            pr.parse_trailer(f, tec);
            BOOST_TEST(!tec);
            BOOST_TEST(f.empty());
        }
    }

    void
    testTrailerObsFold()
    {
        test_parser pr;
        pr.provide(
            "HTTP/1.1 200 OK\r\n"
            "Transfer-Encoding: chunked\r\n"
            "\r\n"
            "0\r\n"
            "X-A: 1\r\n"
            " fold\r\n"
            "X-B: 2\r\n"
            "\r\n");

        pr.start();
        auto [ec, body] = pr.read_body();
        BOOST_TEST(!ec);

        fields f;
        system::error_code tec;
        pr.parse_trailer(f, tec);
        BOOST_TEST(!tec);
        BOOST_TEST_EQ(f.size(), 2u);
        BOOST_TEST(f.at("X-A") == "1   fold");
        BOOST_TEST(f.at("X-B") == "2");

        // the in-place unfolding is stable under re-parsing
        pr.parse_trailer(f, tec);
        BOOST_TEST(!tec);
        BOOST_TEST_EQ(f.size(), 4u);
        BOOST_TEST(f.at("X-A") == "1   fold");
    }

    void
    testTrailerByteByByte()
    {
        // one octet per refill exercises the rescan of a partially
        // received trailer; completion must not double-append
        test_parser pr;
        pr.max_read(1);
        pr.provide(
            "HTTP/1.1 200 OK\r\n"
            "Transfer-Encoding: chunked\r\n"
            "\r\n"
            "5\r\nhello\r\n"
            "0\r\n"
            "X-A: 1\r\n"
            "X-B: 2\r\n"
            "\r\n");

        pr.start();
        auto [ec, body] = pr.read_body();
        BOOST_TEST(!ec);
        BOOST_TEST(body == "hello");

        fields f;
        system::error_code tec;
        pr.parse_trailer(f, tec);
        BOOST_TEST(!tec);
        BOOST_TEST_EQ(f.size(), 2u);
        BOOST_TEST(f.at("X-A") == "1");
        BOOST_TEST(f.at("X-B") == "2");
    }

    void
    testTrailerLimit()
    {
        // a field line of exactly max_field octets is accepted;
        // one more is rejected
        for(bool over : { false, true })
        {
            parser::config cfg;
            cfg.hdr_limits.max_field = 32;
            test_parser pr(cfg);

            // "X-Name: " + value + CRLF == 32 octets
            std::string const value(over ? 23 : 22, 'a');
            pr.provide(
                "HTTP/1.1 200 OK\r\n"
                "Transfer-Encoding: chunked\r\n"
                "\r\n"
                "0\r\n"
                "X-Name: " + value + "\r\n"
                "\r\n");

            pr.start();
            auto [ec, body] = pr.read_body();
            BOOST_TEST(!ec);

            fields f;
            system::error_code tec;
            pr.parse_trailer(f, tec);
            if(over)
            {
                BOOST_TEST(tec == http::error::field_size_limit);
                BOOST_TEST(f.empty());
            }
            else
            {
                BOOST_TEST(!tec);
                BOOST_TEST(f.at("X-Name") == value);
            }
        }
    }

    void
    testTrailerBadField()
    {
        {
            // a line which is structurally a trailer but not a
            // field completes the message; only extraction fails,
            // and fields parsed before the error remain
            test_parser pr;
            pr.provide(
                "HTTP/1.1 200 OK\r\n"
                "Transfer-Encoding: chunked\r\n"
                "\r\n"
                "0\r\n"
                "X-A: v\r\n"
                "junk\r\n"
                "\r\n"
                "HTTP/1.1 204 No Content\r\n"
                "\r\n");

            pr.start();
            auto [ec, body] = pr.read_body();
            BOOST_TEST(!ec);
            BOOST_TEST(pr.got_body());

            fields f;
            system::error_code tec;
            pr.parse_trailer(f, tec);
            BOOST_TEST(tec == http::error::bad_field_name);
            BOOST_TEST_EQ(f.size(), 1u);
            BOOST_TEST(f.at("X-A") == "v");

            // the failure does not poison the stream
            pr.start();
            auto hec = pr.read_header();
            BOOST_TEST(!hec);
            BOOST_TEST_EQ(pr.get().status_int(), 204);
        }
        {
            // a bare LF inside a trailer field survives completion
            // and is rejected at extraction
            test_parser pr;
            pr.provide(
                "HTTP/1.1 200 OK\r\n"
                "Transfer-Encoding: chunked\r\n"
                "\r\n"
                "0\r\n"
                "X-B: v\n\r\n"
                "\r\n");

            pr.start();
            auto [ec, body] = pr.read_body();
            BOOST_TEST(!ec);

            fields f;
            system::error_code tec;
            pr.parse_trailer(f, tec);
            BOOST_TEST(tec == http::error::bad_line_ending);
            BOOST_TEST(f.empty());
        }
    }

    void
    testTrailerStaticFields()
    {
        test_parser pr;
        pr.provide(
            "HTTP/1.1 200 OK\r\n"
            "Transfer-Encoding: chunked\r\n"
            "\r\n"
            "0\r\n"
            "X-Trailer: value\r\n"
            "\r\n");

        pr.start();
        auto [ec, body] = pr.read_body();
        BOOST_TEST(!ec);

        // a container too small throws in the caller's frame;
        // the trailer remains available for a retry
        char small[8];
        static_fields sf(small, sizeof(small));
        system::error_code tec;
        BOOST_TEST_THROWS(
            pr.parse_trailer(sf, tec), std::length_error);

        fields f;
        pr.parse_trailer(f, tec);
        BOOST_TEST(!tec);
        BOOST_TEST_EQ(f.size(), 1u);
        BOOST_TEST(f.at("X-Trailer") == "value");
    }

    void
    testTrailerStraddleWrap()
    {
        // streaming leaves the retained trailer wherever the final
        // chunk landed in the circular buffer. Sweeping the trailer
        // length walks the section across the wrap point, so some
        // iterations straddle it at every position: mid-name,
        // mid-value, at the CRLF, and at the terminal empty line.
        // Filling the buffer afterwards makes extraction rearrange
        // a completely full buffer in some iterations.
        for(std::size_t len = 0; len <= 48; ++len)
        {
            parser::config cfg;
            cfg.hdr_limits.max_size = 96;
            cfg.in_buffer = 64;
            test_parser pr(cfg);
            pr.max_read(1);

            std::string const value(len, 'a');
            std::string const chunk(16, 'b');
            std::string wire =
                "HTTP/1.1 200 OK\r\n"
                "Transfer-Encoding: chunked\r\n"
                "\r\n";
            for(int i = 0; i != 4; ++i)
                wire += "10\r\n" + chunk + "\r\n";
            wire += "0\r\n"
                "X-T: " + value + "\r\n"
                "\r\n";
            pr.provide(wire);

            pr.start();
            auto hec = pr.read_header();
            BOOST_TEST(!hec);

            // consume the body as it arrives so the write
            // position advances and later octets wrap
            std::size_t total = 0;
            for(;;)
            {
                char buf[16];
                auto [ec, n] = pr.read_some(
                    capy::make_buffer(buf));
                total += n;
                if(ec)
                {
                    BOOST_TEST(ec == capy::cond::eof);
                    break;
                }
            }
            BOOST_TEST_EQ(total, 64);

            // pipelined octets can refill the buffer to the
            // brim before extraction; alternate so both a
            // full and a partially filled buffer are
            // rearranged
            if(len % 2 == 0)
            {
                for(;;)
                {
                    auto const pb = pr.prepare();
                    auto const n = capy::buffer_size(pb);
                    if(n == 0)
                        break;
                    for(auto b : pb)
                        std::memset(b.data(), 'Z', b.size());
                    pr.commit(n);
                }
            }

            fields f;
            system::error_code tec;
            pr.parse_trailer(f, tec);
            BOOST_TEST(!tec);
            BOOST_TEST_EQ(f.size(), 1u);
            BOOST_TEST(f.at("X-T") == value);

            // the rearrangement preserves the section
            pr.parse_trailer(f, tec);
            BOOST_TEST(!tec);
            BOOST_TEST_EQ(f.size(), 2u);

            BOOST_TEST(pr.has_buffered_data() ==
                (len % 2 == 0));
        }
    }

    void
    testChunkedPullSmallDest()
    {
        test_parser pr;
        pr.provide(
            "HTTP/1.1 200 OK\r\n"
            "Transfer-Encoding: chunked\r\n"
            "\r\n"
            "3\r\nabc\r\n"
            "3\r\ndef\r\n"
            "0\r\n\r\n");

        pr.start();
        // a single descriptor cannot span chunks: delivery
        // stops at the boundary and resumes on the next pull
        capy::const_buffer arr[1];
        {
            auto [ec, bufs] = pr.pull(arr);
            BOOST_TEST(!ec);
            BOOST_TEST_EQ(bufs.size(), 1);
            BOOST_TEST_EQ(bufs[0].size(), 3);
        }
        pr.consume(3);
        {
            auto [ec, bufs] = pr.pull(arr);
            BOOST_TEST(!ec);
            BOOST_TEST_EQ(bufs.size(), 1);
            BOOST_TEST_EQ(bufs[0].size(), 3);
        }
        pr.consume(3);
        {
            auto [ec, bufs] = pr.pull(arr);
            BOOST_TEST(ec == capy::cond::eof);
            BOOST_TEST_EQ(bufs.size(), 0);
        }
        BOOST_TEST(pr.got_body());
    }

    void
    testChunkedBadFraming()
    {
        test_parser pr;
        pr.provide(
            "HTTP/1.1 200 OK\r\n"
            "Transfer-Encoding: chunked\r\n"
            "\r\n"
            "ZZZ\r\nhello\r\n");

        pr.start();
        char buf[16];
        {
            auto [ec, n] = pr.read_some(capy::make_buffer(buf));
            BOOST_TEST(ec == http::error::bad_payload);
            BOOST_TEST_EQ(n, 0);
        }
        BOOST_TEST(!pr.got_body());
        {
            auto [ec, n] = pr.read_some(capy::make_buffer(buf));
            BOOST_TEST(ec == http::error::bad_payload);
            BOOST_TEST_EQ(n, 0);
        }
    }

    void
    testChunkedBadFramingWithData()
    {
        test_parser pr;
        pr.provide(
            "HTTP/1.1 200 OK\r\n"
            "Transfer-Encoding: chunked\r\n"
            "\r\n"
            "5\r\nhello\r\n"
            "ZZZ");

        pr.start();
        char buf[16];
        // the bytes that decoded cleanly before the error are
        // delivered first; the error reports on the next call
        auto [ec, n] = pr.read_some(capy::make_buffer(buf));
        BOOST_TEST(!ec);
        BOOST_TEST_EQ(n, 5);
        BOOST_TEST(std::string_view(buf, n) == "hello");
        auto [ec2, n2] = pr.read_some(capy::make_buffer(buf));
        BOOST_TEST(ec2 == http::error::bad_payload);
        BOOST_TEST_EQ(n2, 0);
    }

    void
    testChunkedBadChunkExtension()
    {
        test_parser pr;
        // a lone CR inside a chunk extension
        pr.provide(
            "HTTP/1.1 200 OK\r\n"
            "Transfer-Encoding: chunked\r\n"
            "\r\n"
            "5;ext\rZ\r\nhello\r\n"
            "0\r\n\r\n");

        pr.start();
        char buf[16];
        auto [ec, n] = pr.read_some(capy::make_buffer(buf));
        BOOST_TEST(ec == http::error::bad_payload);
        BOOST_TEST_EQ(n, 0);
    }

    void
    testChunkedSizeOverflow()
    {
        test_parser pr;
        // a chunk size that does not fit in 64 bits
        pr.provide(
            "HTTP/1.1 200 OK\r\n"
            "Transfer-Encoding: chunked\r\n"
            "\r\n"
            "FFFFFFFFFFFFFFFFF\r\nhello\r\n"
            "0\r\n\r\n");

        pr.start();
        char buf[16];
        auto [ec, n] = pr.read_some(capy::make_buffer(buf));
        BOOST_TEST(ec == http::error::bad_payload);
        BOOST_TEST_EQ(n, 0);
    }

    void
    testChunkedBadChunkTerminator()
    {
        // the CRLF closing the chunk data is malformed in two
        // ways: no CR at all, and a CR followed by the wrong octet
        for(std::string_view tail : { "XY", "\rX" })
        {
            test_parser pr;
            pr.provide(
                "HTTP/1.1 200 OK\r\n"
                "Transfer-Encoding: chunked\r\n"
                "\r\n"
                "5\r\nhello" + std::string(tail));

            pr.start();
            char buf[16];
            // the valid chunk data is delivered first
            auto [ec, n] = pr.read_some(capy::make_buffer(buf));
            BOOST_TEST(!ec);
            BOOST_TEST_EQ(n, 5);

            auto [ec2, n2] = pr.read_some(capy::make_buffer(buf));
            BOOST_TEST(ec2 == http::error::bad_payload);
            BOOST_TEST_EQ(n2, 0);
        }
    }

    void
    testChunkedBadTrailer()
    {
        test_parser pr;
        // a lone CR inside the trailer section
        pr.provide(
            "HTTP/1.1 200 OK\r\n"
            "Transfer-Encoding: chunked\r\n"
            "\r\n"
            "0\r\n\rX");

        pr.start();
        char buf[16];
        auto [ec, n] = pr.read_some(capy::make_buffer(buf));
        BOOST_TEST(ec == http::error::bad_payload);
        BOOST_TEST_EQ(n, 0);
        BOOST_TEST(!pr.got_body());
    }

    void
    testChunkedPullDrainThenError()
    {
        test_parser pr;
        pr.provide(
            "HTTP/1.1 200 OK\r\n"
            "Transfer-Encoding: chunked\r\n"
            "\r\n"
            "5\r\nhello\r\n"
            "ZZZ");

        pr.start();
        capy::const_buffer arr[4];
        {
            // pull returns error XOR data: the valid chunk is
            // delivered with no error...
            auto [ec, bufs] = pr.pull(arr);
            BOOST_TEST(!ec);
            BOOST_TEST_EQ(bufs.size(), 1);
            BOOST_TEST_EQ(bufs[0].size(), 5);
        }
        pr.consume(5);
        {
            // ...and the sticky error surfaces once drained
            auto [ec, bufs] = pr.pull(arr);
            BOOST_TEST(ec == http::error::bad_payload);
            BOOST_TEST_EQ(bufs.size(), 0);
        }
        {
            auto [ec, bufs] = pr.pull(arr);
            BOOST_TEST(ec == http::error::bad_payload);
            BOOST_TEST_EQ(bufs.size(), 0);
        }
    }

    void
    testChunkedIncomplete()
    {
        test_parser pr;
        pr.provide(
            "HTTP/1.1 200 OK\r\n"
            "Transfer-Encoding: chunked\r\n"
            "\r\n"
            "5\r\nhel");

        pr.start();
        char buf[16];
        {
            auto [ec, n] = pr.read_some(capy::make_buffer(buf));
            BOOST_TEST(!ec);
            BOOST_TEST_EQ(n, 3);
        }
        {
            auto [ec, n] = pr.read_some(capy::make_buffer(buf));
            BOOST_TEST(ec == http::error::incomplete);
            BOOST_TEST_EQ(n, 0);
        }
        {
            auto [ec, n] = pr.read_some(capy::make_buffer(buf));
            BOOST_TEST(ec == http::error::incomplete);
            BOOST_TEST_EQ(n, 0);
        }
    }

    void
    testChunkedFramingLargerThanBuffer()
    {
        constexpr std::string_view hdr =
            "HTTP/1.1 200 OK\r\n"
            "Transfer-Encoding: chunked\r\n"
            "\r\n";

        parser::config cfg;
        cfg.hdr_limits.max_fields = 1;
        cfg.hdr_limits.max_size = hdr.size();
        cfg.in_buffer = 49;
        test_parser pr(cfg);

        // a chunk extension longer than what remains of in_
        pr.provide(std::string(hdr) +
            "5;e=" + std::string(80, 'x') + "\r\nhello\r\n0\r\n\r\n");

        pr.start();
        char buf[16];
        {
            auto [ec, n] = pr.read_some(capy::make_buffer(buf));
            BOOST_TEST(ec == http::error::in_place_overflow);
            BOOST_TEST_EQ(n, 0);
        }
        // framing overflow is terminal, unlike delivery overflow
        {
            auto [ec, n] = pr.read_some(capy::make_buffer(buf));
            BOOST_TEST(ec == http::error::in_place_overflow);
            BOOST_TEST_EQ(n, 0);
        }
    }

    void
    testChunkedReadBodyChunkLargerThanBuffer()
    {
        test_parser pr;
        // the chunk declares more octets than in_ can ever
        // hold: assembling a contiguous body cannot succeed
        pr.provide(
            "HTTP/1.1 200 OK\r\n"
            "Transfer-Encoding: chunked\r\n"
            "\r\n"
            "FFFFFF\r\nhello");

        pr.start();
        auto [ec, body] = pr.read_body();
        BOOST_TEST(ec == http::error::in_place_overflow);

        // the walk never cleared the chunk header, so not one
        // octet of the chunk was flattened
        BOOST_TEST(body.empty());
    }

    void
    testChunkedBodyLimit()
    {
        parser::config cfg;
        cfg.body_limit = 4;
        test_parser pr(cfg);
        pr.provide(
            "HTTP/1.1 200 OK\r\n"
            "Transfer-Encoding: chunked\r\n"
            "\r\n"
            "a\r\n0123456789\r\n"
            "0\r\n\r\n");

        pr.start();
        char buf[16];
        // the in-limit prefix is delivered first
        auto [ec, n] = pr.read_some(capy::make_buffer(buf));
        BOOST_TEST(!ec);
        BOOST_TEST_EQ(n, 4);

        auto [ec2, n2] = pr.read_some(capy::make_buffer(buf));
        BOOST_TEST(ec2 == http::error::body_too_large);
        BOOST_TEST_EQ(n2, 0);
    }

    void
    testChunkedBodyLimitViaReadBody()
    {
        parser::config cfg;
        cfg.body_limit = 4;
        test_parser pr(cfg);
        pr.provide(
            "HTTP/1.1 200 OK\r\n"
            "Transfer-Encoding: chunked\r\n"
            "\r\n"
            "a\r\n0123456789\r\n"
            "0\r\n\r\n");

        pr.start();
        // the flattened body outgrows the budget: it can never be
        // returned whole
        auto [ec, body] = pr.read_body();
        BOOST_TEST(ec == http::error::body_too_large);
    }

    void
    testChunkedBodyLimitViaConsume()
    {
        parser::config cfg;
        cfg.body_limit = 4;
        test_parser pr(cfg);
        pr.provide(
            "HTTP/1.1 200 OK\r\n"
            "Transfer-Encoding: chunked\r\n"
            "\r\n"
            "a\r\n0123456789\r\n"
            "0\r\n\r\n");

        pr.start();
        capy::const_buffer arr[2];
        // delivery is clamped at the limit: the caller never
        // observes body octets past it
        auto [ec, bufs] = pr.pull(arr);
        BOOST_TEST(!ec);
        BOOST_TEST_EQ(capy::buffer_size(bufs), 4);

        pr.consume(4);
        auto [ec2, bufs2] = pr.pull(arr);
        BOOST_TEST(ec2 == http::error::body_too_large);
        BOOST_TEST_EQ(bufs2.size(), 0);

        // the walk can never reach the terminal framing: the
        // message stays incomplete and the failure is sticky
        pr.consume(0);
        BOOST_TEST(!pr.got_body());
        auto [ec3, bufs3] = pr.pull(arr);
        BOOST_TEST(ec3 == http::error::body_too_large);
    }

    void
    testChunkedExactLimitPull()
    {
        // a body that ends exactly on the budget: the walk must
        // still reach the terminal chunk. only body octets past the
        // budget make the payload too large
        parser::config cfg;
        cfg.body_limit = 5;
        test_parser pr(cfg);
        pr.provide(
            "HTTP/1.1 200 OK\r\n"
            "Transfer-Encoding: chunked\r\n"
            "\r\n"
            "5\r\nhello\r\n"
            "0\r\n\r\n");

        pr.start();
        capy::const_buffer arr[2];
        {
            auto [ec, bufs] = pr.pull(arr);
            BOOST_TEST(!ec);
            BOOST_TEST_EQ(capy::buffer_size(bufs), 5);
            pr.consume(5);
        }
        {
            auto [ec, bufs] = pr.pull(arr);
            BOOST_TEST(ec == capy::cond::eof);
            BOOST_TEST_EQ(bufs.size(), 0);
        }
        BOOST_TEST(pr.got_body());
    }

    void
    testChunkedExactLimitDecoder()
    {
        parser::config cfg;
        cfg.body_limit = 5;
        test_parser pr(cfg);
        test_decoder dec;

        pr.provide(
            "HTTP/1.1 200 OK\r\n"
            "Transfer-Encoding: chunked\r\n"
            "\r\n"
            "5\r\nhello\r\n"
            "0\r\n\r\n");

        pr.start();
        auto hec = pr.read_header();
        BOOST_TEST(!hec);
        pr.set_decoder(&dec);

        char buf[16];
        {
            auto [ec, n] = pr.read_some(capy::make_buffer(buf));
            BOOST_TEST(!ec);
            BOOST_TEST_EQ(n, 5);
            BOOST_TEST(std::string_view(buf, n) == decoded("hello"));
        }
        {
            auto [ec, n] = pr.read_some(capy::make_buffer(buf));
            BOOST_TEST(ec == capy::cond::eof);
            BOOST_TEST_EQ(n, 0);
        }
        BOOST_TEST(pr.got_body());
    }

    void
    testChunkedExactLimitDecoderViaReadBody()
    {
        parser::config cfg;
        cfg.body_limit = 5;
        test_parser pr(cfg);
        test_decoder dec;

        pr.provide(
            "HTTP/1.1 200 OK\r\n"
            "Transfer-Encoding: chunked\r\n"
            "\r\n"
            "5\r\nhello\r\n"
            "0\r\n\r\n");

        pr.start();
        auto hec = pr.read_header();
        BOOST_TEST(!hec);
        pr.set_decoder(&dec);

        auto [ec, body] = pr.read_body();
        BOOST_TEST(!ec);
        BOOST_TEST(body == decoded("hello"));
        BOOST_TEST(pr.got_body());
    }

    void
    testChunkedEmptyBodyZeroLimit()
    {
        // no body octets, so nothing can exceed the budget
        parser::config cfg;
        cfg.body_limit = 0;
        test_parser pr(cfg);
        pr.provide(
            "HTTP/1.1 200 OK\r\n"
            "Transfer-Encoding: chunked\r\n"
            "\r\n"
            "0\r\n\r\n");

        pr.start();
        capy::const_buffer arr[2];
        auto [ec, bufs] = pr.pull(arr);
        BOOST_TEST(ec == capy::cond::eof);
        BOOST_TEST_EQ(bufs.size(), 0);
        BOOST_TEST(pr.got_body());
    }

    void
    testChunkedBodyLimitDecoder()
    {
        // the budget still bites on the decode path: the decoder
        // has output left to give and no room to give it in
        parser::config cfg;
        cfg.body_limit = 4;
        test_parser pr(cfg);
        test_decoder dec;

        pr.provide(
            "HTTP/1.1 200 OK\r\n"
            "Transfer-Encoding: chunked\r\n"
            "\r\n"
            "a\r\n0123456789\r\n"
            "0\r\n\r\n");

        pr.start();
        auto hec = pr.read_header();
        BOOST_TEST(!hec);
        pr.set_decoder(&dec);

        char buf[16];
        {
            auto [ec, n] = pr.read_some(capy::make_buffer(buf));
            BOOST_TEST(!ec);
            BOOST_TEST_EQ(n, 4);
            BOOST_TEST(std::string_view(buf, n) == decoded("0123"));
        }
        {
            auto [ec, n] = pr.read_some(capy::make_buffer(buf));
            BOOST_TEST(ec == http::error::body_too_large);
            BOOST_TEST_EQ(n, 0);
        }
        BOOST_TEST(!pr.got_body());
    }

    void
    testChunkedByteByByte()
    {
        test_parser pr;
        pr.max_read(1);
        pr.provide(
            "HTTP/1.1 200 OK\r\n"
            "Transfer-Encoding: chunked\r\n"
            "\r\n"
            "5;ext=1\r\nhello\r\n"
            "6\r\n world\r\n"
            "0\r\n"
            "X-Trailer: v\r\n"
            "\r\n");

        pr.start();
        std::string got;
        for(;;)
        {
            char buf[4];
            auto [ec, n] = pr.read_some(capy::make_buffer(buf));
            got.append(buf, n);
            if(ec)
            {
                BOOST_TEST(ec == capy::cond::eof);
                break;
            }
        }
        BOOST_TEST(got == "hello world");
        BOOST_TEST(pr.got_body());
        BOOST_TEST(!pr.has_buffered_data());
    }

    void
    testChunkedReadBodyOverflowThenStream()
    {
        constexpr std::string_view hdr =
            "HTTP/1.1 200 OK\r\n"
            "Transfer-Encoding: chunked\r\n"
            "\r\n";

        // the input region holds the first chunk's data
        // but not the whole dechunked body, so the second
        // chunk overflows the in-place decode and falls
        // back to streaming; max_fields leaves no table
        // reserve to reclaim
        parser::config cfg;
        cfg.hdr_limits.max_size = hdr.size();
        cfg.hdr_limits.max_fields = 1;
        cfg.in_buffer = 9;
        test_parser pr(cfg);

        pr.provide(hdr);
        pr.provide(
            "5\r\nhello\r\n"
            "6\r\n world\r\n"
            "0\r\n\r\n");

        pr.start();
        std::string got;
        {
            // the chunks flattened before the overflow are
            // viewable; the rest of the body is not
            auto [ec, part] = pr.read_body();
            BOOST_TEST(ec == http::error::in_place_overflow);
            BOOST_TEST(part == "hello");
        }
        // the switch to streaming first drains the bytes parked
        // in the decode buffer (the same bytes the partial view
        // exposed — read_body does not consume), then continues
        // with the wire
        for(;;)
        {
            char buf[4];
            auto [ec, n] = pr.read_some(capy::make_buffer(buf));
            got.append(buf, n);
            if(ec)
            {
                BOOST_TEST(ec == capy::cond::eof);
                break;
            }
        }
        BOOST_TEST(got == "hello world");
        BOOST_TEST(pr.got_body());
        BOOST_TEST(!pr.has_buffered_data());
    }

    //--------------------------------------------
    //
    // payload::to_eof
    //
    //--------------------------------------------

    void
    testToEofReadSome()
    {
        test_parser pr;
        pr.provide(
            "HTTP/1.1 200 OK\r\n"
            "\r\n"
            "hello");

        pr.start();
        auto ec = pr.read_header();
        BOOST_TEST(!ec);
        BOOST_TEST(pr.get().payload() ==
            http::payload::to_eof);
        BOOST_TEST(!pr.got_body());

        char buf[16];
        {
            auto [ec, n] = pr.read_some(capy::make_buffer(buf));
            BOOST_TEST(!ec);
            BOOST_TEST_EQ(n, 5);
            BOOST_TEST(std::string_view(buf, n) == "hello");
        }
        BOOST_TEST(!pr.got_body());
        {
            // stream EOF completes the message; it is not an error
            auto [ec, n] = pr.read_some(capy::make_buffer(buf));
            BOOST_TEST(ec == capy::cond::eof);
            BOOST_TEST_EQ(n, 0);
        }
        BOOST_TEST(pr.got_body());
        BOOST_TEST(!pr.has_buffered_data());
    }

    void
    testToEofReadBody()
    {
        test_parser pr;
        pr.provide(
            "HTTP/1.1 200 OK\r\n"
            "\r\n"
            "hello world");

        pr.start();
        auto [ec, body] = pr.read_body();
        BOOST_TEST(!ec);
        BOOST_TEST(body == "hello world");
        BOOST_TEST(pr.got_body());

        auto [ec2, body2] = pr.read_body();
        BOOST_TEST(!ec2);
        BOOST_TEST(body2 == "hello world");
    }

    void
    testToEofPull()
    {
        test_parser pr;
        pr.provide(
            "HTTP/1.1 200 OK\r\n"
            "\r\n"
            "hello");

        pr.start();
        capy::const_buffer arr[2];
        {
            auto [ec, bufs] = pr.pull(arr);
            BOOST_TEST(!ec);
            BOOST_TEST_EQ(capy::buffer_size(bufs), 5);
        }
        pr.consume(5);
        {
            auto [ec, bufs] = pr.pull(arr);
            BOOST_TEST(ec == capy::cond::eof);
            BOOST_TEST_EQ(bufs.size(), 0);
        }
        BOOST_TEST(pr.got_body());
    }

    void
    testToEofEmptyBody()
    {
        test_parser pr;
        pr.provide(
            "HTTP/1.1 200 OK\r\n"
            "\r\n");

        pr.start();
        auto [ec, body] = pr.read_body();
        BOOST_TEST(!ec);
        BOOST_TEST(body.empty());
        BOOST_TEST(pr.got_body());
    }

    void
    testToEofBodyLimit()
    {
        parser::config cfg;
        cfg.body_limit = 4;
        test_parser pr(cfg);
        pr.provide(
            "HTTP/1.1 200 OK\r\n"
            "\r\n"
            "0123456789");

        pr.start();
        char buf[16];
        // the in-limit prefix is delivered first
        auto [ec, n] = pr.read_some(capy::make_buffer(buf));
        BOOST_TEST(!ec);
        BOOST_TEST_EQ(n, 4);

        auto [ec2, n2] = pr.read_some(capy::make_buffer(buf));
        BOOST_TEST(ec2 == http::error::body_too_large);
        BOOST_TEST_EQ(n2, 0);
    }


    void
    testToEofBodyLimitViaReadBody()
    {
        parser::config cfg;
        cfg.body_limit = 4;
        test_parser pr(cfg);
        pr.provide(
            "HTTP/1.1 200 OK\r\n"
            "\r\n"
            "hello");

        pr.start();
        // a close-delimited body has no declared length, so the
        // budget is tested against what has arrived
        auto [ec, body] = pr.read_body();
        BOOST_TEST(ec == http::error::body_too_large);
    }

    void
    testToEofPullBodyLimitZero()
    {
        // a zero budget fails the pull before any delivery
        parser::config cfg;
        cfg.body_limit = 0;
        test_parser pr(cfg);
        pr.provide(
            "HTTP/1.1 200 OK\r\n"
            "\r\n"
            "hello");

        pr.start();
        capy::const_buffer arr[2];
        auto [ec, bufs] = pr.pull(arr);
        BOOST_TEST(ec == http::error::body_too_large);
        BOOST_TEST_EQ(bufs.size(), 0);
    }

    void
    testToEofExactLimit()
    {
        // a close-delimited body has no declared length, so a spent
        // budget alone proves nothing: the body is too large only
        // once an octet past it arrives. here none does, and the
        // close lands on a refill of its own
        parser::config cfg;
        cfg.body_limit = 5;
        test_parser pr(cfg);
        pr.provide(
            "HTTP/1.1 200 OK\r\n"
            "\r\n"
            "hello");

        pr.start();
        char buf[16];
        {
            auto [ec, n] = pr.read_some(capy::make_buffer(buf));
            BOOST_TEST(!ec);
            BOOST_TEST_EQ(n, 5);
            BOOST_TEST(std::string_view(buf, n) == "hello");
        }
        {
            auto [ec, n] = pr.read_some(capy::make_buffer(buf));
            BOOST_TEST(ec == capy::cond::eof);
            BOOST_TEST_EQ(n, 0);
        }
        BOOST_TEST(pr.got_body());
    }

    void
    testToEofExactLimitEagerEof()
    {
        // the same body, with the close reported together with the
        // last octets: the framing is already complete when the
        // budget runs out
        parser::config cfg;
        cfg.body_limit = 5;
        test_parser pr(cfg);
        pr.eager_eof();
        pr.provide(
            "HTTP/1.1 200 OK\r\n"
            "\r\n"
            "hello");

        pr.start();
        char buf[16];
        {
            auto [ec, n] = pr.read_some(capy::make_buffer(buf));
            BOOST_TEST(!ec);
            BOOST_TEST_EQ(n, 5);
        }
        {
            auto [ec, n] = pr.read_some(capy::make_buffer(buf));
            BOOST_TEST(ec == capy::cond::eof);
            BOOST_TEST_EQ(n, 0);
        }
        BOOST_TEST(pr.got_body());
    }

    void
    testToEofExactLimitPull()
    {
        parser::config cfg;
        cfg.body_limit = 5;
        test_parser pr(cfg);
        pr.provide(
            "HTTP/1.1 200 OK\r\n"
            "\r\n"
            "hello");

        pr.start();
        capy::const_buffer arr[2];
        {
            auto [ec, bufs] = pr.pull(arr);
            BOOST_TEST(!ec);
            BOOST_TEST_EQ(capy::buffer_size(bufs), 5);
            pr.consume(5);
        }
        {
            auto [ec, bufs] = pr.pull(arr);
            BOOST_TEST(ec == capy::cond::eof);
            BOOST_TEST_EQ(bufs.size(), 0);
        }
        BOOST_TEST(pr.got_body());
    }

    void
    testToEofExactLimitDecoder()
    {
        // the decoder announces its end of stream on a final call
        // that produces nothing. a spent budget must not stop that
        // call from happening
        parser::config cfg;
        cfg.body_limit = 5;
        test_parser pr(cfg);
        test_decoder dec;

        pr.provide(
            "HTTP/1.1 200 OK\r\n"
            "\r\n"
            "hello");

        pr.start();
        auto hec = pr.read_header();
        BOOST_TEST(!hec);
        pr.set_decoder(&dec);

        char buf[16];
        {
            auto [ec, n] = pr.read_some(capy::make_buffer(buf));
            BOOST_TEST(!ec);
            BOOST_TEST_EQ(n, 5);
            BOOST_TEST(std::string_view(buf, n) == decoded("hello"));
        }
        {
            auto [ec, n] = pr.read_some(capy::make_buffer(buf));
            BOOST_TEST(ec == capy::cond::eof);
            BOOST_TEST_EQ(n, 0);
        }
        BOOST_TEST(pr.got_body());
    }

    void
    testToEofExactLimitDecoderViaReadBody()
    {
        parser::config cfg;
        cfg.body_limit = 5;
        test_parser pr(cfg);
        test_decoder dec;

        pr.provide(
            "HTTP/1.1 200 OK\r\n"
            "\r\n"
            "hello");

        pr.start();
        auto hec = pr.read_header();
        BOOST_TEST(!hec);
        pr.set_decoder(&dec);

        auto [ec, body] = pr.read_body();
        BOOST_TEST(!ec);
        BOOST_TEST(body == decoded("hello"));
        BOOST_TEST(pr.got_body());
    }

    void
    testToEofEmptyBodyZeroLimit()
    {
        // an empty close-delimited body is not too large, whatever
        // the budget
        parser::config cfg;
        cfg.body_limit = 0;
        test_parser pr(cfg);
        pr.provide("HTTP/1.1 200 OK\r\n\r\n");

        pr.start();
        char buf[16];
        auto [ec, n] = pr.read_some(capy::make_buffer(buf));
        BOOST_TEST(ec == capy::cond::eof);
        BOOST_TEST_EQ(n, 0);
        BOOST_TEST(pr.got_body());
    }

    //--------------------------------------------
    //
    // set_body_limit
    //
    //--------------------------------------------

    void
    testSetBodyLimitEnforced()
    {
        // a limit installed via the setter (not the config) is
        // enforced on the next read
        test_parser pr; // default config: no limit
        pr.provide(
            "HTTP/1.1 200 OK\r\n"
            "Content-Length: 5\r\n"
            "\r\n"
            "hello");

        pr.start();
        auto ec = pr.read_header();
        BOOST_TEST(!ec);

        pr.set_body_limit(4);

        char buf[16];
        // the declared length alone settles it: no
        // octet is delivered
        auto [ec2, n] = pr.read_some(capy::make_buffer(buf));
        BOOST_TEST(ec2 == http::error::body_too_large);
        BOOST_TEST_EQ(n, 0);
    }

    void
    testSetBodyLimitRaiseUnblocks()
    {
        // body_too_large is not terminal: raising the limit
        // resumes delivery without re-reading
        parser::config cfg;
        cfg.body_limit = 4;
        test_parser pr(cfg);
        pr.provide(
            "HTTP/1.1 200 OK\r\n"
            "Content-Length: 10\r\n"
            "\r\n"
            "0123456789");

        pr.start();
        auto ec = pr.read_header();
        BOOST_TEST(!ec);

        char buf[16];
        {
            auto [ec, n] = pr.read_some(capy::make_buffer(buf));
            BOOST_TEST(ec == http::error::body_too_large);
            BOOST_TEST_EQ(n, 0);
        }
        pr.set_body_limit(10);
        {
            auto [ec, n] = pr.read_some(capy::make_buffer(buf));
            BOOST_TEST(!ec);
            BOOST_TEST_EQ(n, 10);
            BOOST_TEST(std::string_view(buf, n) == "0123456789");
        }
        {
            auto [ec, n] = pr.read_some(capy::make_buffer(buf));
            BOOST_TEST(ec == capy::cond::eof);
            BOOST_TEST_EQ(n, 0);
        }
        BOOST_TEST(pr.got_body());
    }

    void
    testSetBodyLimitBelowTransferred()
    {
        // lowering the limit below what has already been transferred
        // must clamp the remaining budget to zero (no unsigned
        // underflow), so the next read fails as too large
        test_parser pr;
        pr.provide(
            "HTTP/1.1 200 OK\r\n"
            "Content-Length: 10\r\n"
            "\r\n"
            "0123456789");

        pr.start();
        auto ec = pr.read_header();
        BOOST_TEST(!ec);

        char buf[3];
        {
            auto [ec, n] = pr.read_some(capy::make_buffer(buf));
            BOOST_TEST(!ec);
            BOOST_TEST_EQ(n, 3); // transferred == 3
        }
        pr.set_body_limit(2); // below the 3 already delivered
        {
            auto [ec, n] = pr.read_some(capy::make_buffer(buf));
            BOOST_TEST(ec == http::error::body_too_large);
            BOOST_TEST_EQ(n, 0);
        }
    }

    void
    testSetBodyLimitDecoder()
    {
        // the limit tracks decoded output: it clamps the decode path
        // and a raise unblocks it just as it does the raw path
        parser::config cfg;
        cfg.body_limit = 2;
        test_parser pr(cfg);
        test_decoder dec; // finishes on the eof kick

        pr.provide(
            "HTTP/1.1 200 OK\r\n"
            "Content-Length: 5\r\n"
            "\r\n"
            "hello");

        pr.start();
        auto hec = pr.read_header();
        BOOST_TEST(!hec);
        pr.set_decoder(&dec);

        char buf[16];
        {
            auto [ec, n] = pr.read_some(capy::make_buffer(buf));
            BOOST_TEST(!ec);
            BOOST_TEST_EQ(n, 2); // decoded output clamped to the limit
            BOOST_TEST(std::string_view(buf, n) == decoded("he"));
        }
        pr.set_body_limit(100);
        {
            auto [ec, n] = pr.read_some(capy::make_buffer(buf));
            BOOST_TEST(!ec);
            BOOST_TEST_EQ(n, 3);
            BOOST_TEST(std::string_view(buf, n) == decoded("llo"));
        }
        {
            auto [ec, n] = pr.read_some(capy::make_buffer(buf));
            BOOST_TEST(ec == capy::cond::eof);
            BOOST_TEST_EQ(n, 0);
        }
        BOOST_TEST(pr.got_body());
    }

    //--------------------------------------------
    //
    // HEAD responses
    //
    //--------------------------------------------

    void
    testHeadResponse()
    {
        test_parser pr;
        // framing fields are present but no body follows
        pr.provide(
            "HTTP/1.1 200 OK\r\n"
            "Content-Length: 100\r\n"
            "\r\n");

        pr.start(true);
        auto ec = pr.read_header();
        BOOST_TEST(!ec);
        BOOST_TEST(pr.got_body());
        BOOST_TEST(!pr.has_buffered_data());

        // streaming reads must not touch the wire
        char buf[8];
        {
            auto [ec, n] = pr.read_some(capy::make_buffer(buf));
            BOOST_TEST(ec == capy::cond::eof);
            BOOST_TEST_EQ(n, 0);
        }
        {
            auto [ec, body] = pr.read_body();
            BOOST_TEST(!ec);
            BOOST_TEST(body.empty());
        }
        capy::const_buffer arr[2];
        {
            auto [ec, bufs] = pr.pull(arr);
            BOOST_TEST(ec == capy::cond::eof);
            BOOST_TEST_EQ(bufs.size(), 0);
        }
    }

    void
    testHeadResponseWithJunk()
    {
        test_parser pr;
        pr.provide(
            "HTTP/1.1 200 OK\r\n"
            "Content-Length: 100\r\n"
            "\r\n"
            "JUNK");

        pr.start(true);
        auto ec = pr.read_header();
        BOOST_TEST(!ec);
        BOOST_TEST(pr.got_body());
        BOOST_TEST(pr.has_buffered_data());
    }

    //--------------------------------------------
    //
    // decoder
    //
    //--------------------------------------------

    void
    testDecoderSized()
    {
        test_parser pr;
        test_decoder dec;
        dec.eof_at = 5; // ends exactly with the last consumed octet

        pr.provide(
            "HTTP/1.1 200 OK\r\n"
            "Content-Length: 5\r\n"
            "\r\n"
            "hello");

        pr.start();
        auto hec = pr.read_header();
        BOOST_TEST(!hec);
        pr.set_decoder(&dec);

        char buf[16];
        {
            auto [ec, n] = pr.read_some(capy::make_buffer(buf));
            BOOST_TEST(!ec);
            BOOST_TEST_EQ(n, 5);
            BOOST_TEST(std::string_view(buf, n) == decoded("hello"));
        }
        {
            auto [ec, n] = pr.read_some(capy::make_buffer(buf));
            BOOST_TEST(ec == capy::cond::eof);
            BOOST_TEST_EQ(n, 0);
        }
        BOOST_TEST(pr.got_body());
        BOOST_TEST(!pr.has_buffered_data());
    }

    void
    testDecoderSizedFinishOnKick()
    {
        test_parser pr;
        test_decoder dec; // finishes only when told the input ended

        pr.provide(
            "HTTP/1.1 200 OK\r\n"
            "Content-Length: 5\r\n"
            "\r\n"
            "hello");

        pr.start();
        auto hec = pr.read_header();
        BOOST_TEST(!hec);
        pr.set_decoder(&dec);

        char buf[16];
        {
            auto [ec, n] = pr.read_some(capy::make_buffer(buf));
            BOOST_TEST(!ec);
            BOOST_TEST_EQ(n, 5);
        }
        {
            auto [ec, n] = pr.read_some(capy::make_buffer(buf));
            BOOST_TEST(ec == capy::cond::eof);
            BOOST_TEST_EQ(n, 0);
        }
        BOOST_TEST(dec.finished);
    }

    void
    testDecoderTrailer()
    {
        test_parser pr;
        test_decoder dec;
        dec.trailer = "XY"; // flush output produced by the eof kick

        pr.provide(
            "HTTP/1.1 200 OK\r\n"
            "Content-Length: 5\r\n"
            "\r\n"
            "hello");

        pr.start();
        auto hec = pr.read_header();
        BOOST_TEST(!hec);
        pr.set_decoder(&dec);

        std::string got;
        for(;;)
        {
            char buf[4];
            auto [ec, n] = pr.read_some(capy::make_buffer(buf));
            got.append(buf, n);
            if(ec)
            {
                BOOST_TEST(ec == capy::cond::eof);
                break;
            }
        }
        BOOST_TEST(got == decoded("hello") + "XY");
    }

    void
    testDecoderTruncatedStream()
    {
        test_parser pr;
        test_decoder dec;
        dec.ignore_eof = true; // never finishes: a truncated stream

        pr.provide(
            "HTTP/1.1 200 OK\r\n"
            "Content-Length: 5\r\n"
            "\r\n"
            "hello");

        pr.start();
        auto hec = pr.read_header();
        BOOST_TEST(!hec);
        pr.set_decoder(&dec);

        char buf[16];
        {
            auto [ec, n] = pr.read_some(capy::make_buffer(buf));
            BOOST_TEST(!ec);
            BOOST_TEST_EQ(n, 5);
        }
        {
            // the raw side ended and the decoder stalls: this
            // must be an error, not a wait for more input
            auto [ec, n] = pr.read_some(capy::make_buffer(buf));
            BOOST_TEST(ec == error::decode_error);
            BOOST_TEST_EQ(n, 0);
        }
        {
            auto [ec, n] = pr.read_some(capy::make_buffer(buf));
            BOOST_TEST(ec == error::decode_error);
            BOOST_TEST_EQ(n, 0);
        }
    }

    void
    testDecoderEarlyEof()
    {
        test_parser pr;
        test_decoder dec;
        dec.eof_at = 3; // ends inside the declared payload

        pr.provide(
            "HTTP/1.1 200 OK\r\n"
            "Content-Length: 5\r\n"
            "\r\n"
            "hello");

        pr.start();
        auto hec = pr.read_header();
        BOOST_TEST(!hec);
        pr.set_decoder(&dec);

        char buf[16];
        // the cleanly decoded bytes are delivered first
        auto [ec, n] = pr.read_some(capy::make_buffer(buf));
        BOOST_TEST(!ec);
        BOOST_TEST_EQ(n, 3);

        auto [ec2, n2] = pr.read_some(capy::make_buffer(buf));
        BOOST_TEST(ec2 == http::error::bad_payload);
        BOOST_TEST_EQ(n2, 0);
    }

    void
    testDecoderHardError()
    {
        test_parser pr;
        test_decoder dec;
        dec.fail_ec = capy::error::test_failure;
        dec.fail_at = 3;

        pr.provide(
            "HTTP/1.1 200 OK\r\n"
            "Content-Length: 5\r\n"
            "\r\n"
            "hello");

        pr.start();
        auto hec = pr.read_header();
        BOOST_TEST(!hec);
        pr.set_decoder(&dec);

        char buf[16];
        // the bytes decoded before the failure are delivered first
        auto [ec, n] = pr.read_some(capy::make_buffer(buf));
        BOOST_TEST(!ec);
        BOOST_TEST_EQ(n, 3);

        auto [ec2, n2] = pr.read_some(capy::make_buffer(buf));
        BOOST_TEST(ec2 == capy::error::test_failure);
        BOOST_TEST_EQ(n2, 0);
    }

    void
    testDecoderPullServesDataBeforeError()
    {
        test_parser pr;
        test_decoder dec;
        dec.fail_ec = capy::error::test_failure;
        dec.fail_at = 3;

        pr.provide(
            "HTTP/1.1 200 OK\r\n"
            "Content-Length: 5\r\n"
            "\r\n"
            "hello");

        pr.start();
        auto hec = pr.read_header();
        BOOST_TEST(!hec);
        pr.set_decoder(&dec);

        capy::const_buffer arr[2];
        {
            // decoded bytes produced before the failure are
            // served with no error (error XOR data)...
            auto [ec, bufs] = pr.pull(arr);
            BOOST_TEST(!ec);
            BOOST_TEST_EQ(capy::buffer_size(bufs), 3);
        }
        pr.consume(3);
        {
            // ...and the stored failure surfaces once drained
            auto [ec, bufs] = pr.pull(arr);
            BOOST_TEST(ec == capy::error::test_failure);
            BOOST_TEST_EQ(bufs.size(), 0);
        }
    }

    void
    testDecoderNoPayload()
    {
        test_parser pr;
        test_decoder dec;

        pr.provide(
            "HTTP/1.1 200 OK\r\n"
            "Content-Length: 0\r\n"
            "\r\n");

        pr.start();
        auto hec = pr.read_header();
        BOOST_TEST(!hec);
        pr.set_decoder(&dec);

        // a bodiless message ends the decode path without
        // ever invoking the decoder
        char buf[8];
        auto [ec, n] = pr.read_some(capy::make_buffer(buf));
        BOOST_TEST(ec == capy::cond::eof);
        BOOST_TEST_EQ(n, 0);
        BOOST_TEST(!dec.finished);
    }

    void
    testDecoderReadSomeEmptyBuffer()
    {
        test_parser pr;
        test_decoder dec;

        pr.provide(
            "HTTP/1.1 200 OK\r\n"
            "Content-Length: 5\r\n"
            "\r\n"
            "hello");

        pr.start();
        auto hec = pr.read_header();
        BOOST_TEST(!hec);
        pr.set_decoder(&dec);

        // an empty destination transfers nothing and is
        // not an error
        {
            auto [ec, n] = pr.read_some(capy::mutable_buffer{});
            BOOST_TEST(!ec);
            BOOST_TEST_EQ(n, 0);
        }
        char buf[16];
        {
            auto [ec, n] = pr.read_some(capy::make_buffer(buf));
            BOOST_TEST(!ec);
            BOOST_TEST_EQ(n, 5);
            BOOST_TEST(std::string_view(buf, n) == decoded("hello"));
        }
    }

    void
    testDecoderReadSomeLeadingEmptyBuffer()
    {
        // a destination whose first buffer is empty still has
        // room in it: the decoder must skip to the buffer that
        // does, rather than read the empty front as "full"
        char buf[16];
        auto dest = [&]
        {
            return std::array<capy::mutable_buffer, 2>{
                capy::mutable_buffer{},
                capy::mutable_buffer{ buf, sizeof(buf) } };
        };
        {
            test_parser pr;
            test_decoder dec;

            pr.provide(
                "HTTP/1.1 200 OK\r\n"
                "Content-Length: 5\r\n"
                "\r\n"
                "hello");

            pr.start();
            auto hec = pr.read_header();
            BOOST_TEST(!hec);
            pr.set_decoder(&dec);

            auto [ec, n] = pr.read_some_raw(dest());
            BOOST_TEST(!ec);
            BOOST_TEST_EQ(n, 5);
            BOOST_TEST(std::string_view(buf, n) == decoded("hello"));
        }
        {
            test_parser pr;
            test_decoder dec;

            pr.provide(
                "HTTP/1.1 200 OK\r\n"
                "Transfer-Encoding: chunked\r\n"
                "\r\n"
                "5\r\nhello\r\n"
                "0\r\n\r\n");

            pr.start();
            auto hec = pr.read_header();
            BOOST_TEST(!hec);
            pr.set_decoder(&dec);

            auto [ec, n] = pr.read_some_raw(dest());
            BOOST_TEST(!ec);
            BOOST_TEST_EQ(n, 5);
            BOOST_TEST(std::string_view(buf, n) == decoded("hello"));
        }
    }

    void
    testDecoderBodyAfterStreaming()
    {
        test_parser pr;
        test_decoder dec;

        pr.provide(
            "HTTP/1.1 200 OK\r\n"
            "Content-Length: 5\r\n"
            "\r\n"
            "hello");

        pr.start();
        auto hec = pr.read_header();
        BOOST_TEST(!hec);
        pr.set_decoder(&dec);

        char buf[3];
        {
            auto [ec, n] = pr.read_some(capy::make_buffer(buf));
            BOOST_TEST(!ec);
            BOOST_TEST_EQ(n, 3);
        }
        // the decoded octets already streamed out are gone, so
        // what is flattened is the remainder of the output
        auto [ec, body] = pr.read_body();
        BOOST_TEST(!ec);
        BOOST_TEST(body == decoded("lo"));
    }

    void
    testDecoderReadBodyHardError()
    {
        test_parser pr;
        test_decoder dec;
        dec.fail_ec = capy::error::test_failure;
        dec.fail_at = 3;

        pr.provide(
            "HTTP/1.1 200 OK\r\n"
            "Content-Length: 5\r\n"
            "\r\n"
            "hello");

        pr.start();
        auto hec = pr.read_header();
        BOOST_TEST(!hec);
        pr.set_decoder(&dec);

        // the in-place body cannot be completed; the output
        // produced before the failure is still viewable
        auto [ec, body] = pr.read_body();
        BOOST_TEST(ec == capy::error::test_failure);
        BOOST_TEST(body == decoded("hel"));
    }

    void
    testDecoderPullTwiceWithoutConsume()
    {
        test_parser pr;
        test_decoder dec;

        pr.provide(
            "HTTP/1.1 200 OK\r\n"
            "Content-Length: 5\r\n"
            "\r\n"
            "hello");

        pr.start();
        auto hec = pr.read_header();
        BOOST_TEST(!hec);
        pr.set_decoder(&dec);

        capy::const_buffer arr[2];
        {
            auto [ec, bufs] = pr.pull(arr);
            BOOST_TEST(!ec);
            BOOST_TEST_EQ(capy::buffer_size(bufs), 5);
        }
        // without a consume the same octets are served again,
        // straight from the decoded buffer
        {
            auto [ec, bufs] = pr.pull(arr);
            BOOST_TEST(!ec);
            BOOST_TEST_EQ(capy::buffer_size(bufs), 5);
        }
        pr.consume(5);
        {
            auto [ec, bufs] = pr.pull(arr);
            BOOST_TEST(ec == capy::cond::eof);
            BOOST_TEST_EQ(bufs.size(), 0);
        }
    }

    void
    testDecoderChunked()
    {
        test_parser pr;
        test_decoder dec;
        dec.trailer = "!";

        pr.provide(
            "HTTP/1.1 200 OK\r\n"
            "Transfer-Encoding: chunked\r\n"
            "\r\n"
            "5\r\nhello\r\n"
            "6\r\n world\r\n"
            "0\r\n\r\n");

        pr.start();
        auto hec = pr.read_header();
        BOOST_TEST(!hec);
        pr.set_decoder(&dec);

        std::string got;
        for(;;)
        {
            char buf[8];
            auto [ec, n] = pr.read_some(capy::make_buffer(buf));
            got.append(buf, n);
            if(ec)
            {
                BOOST_TEST(ec == capy::cond::eof);
                break;
            }
        }
        BOOST_TEST(got == decoded("hello world") + "!");
        BOOST_TEST(pr.got_body());
        BOOST_TEST(!pr.has_buffered_data());
    }

    void
    testDecoderChunkedTrailer()
    {
        // the trailer is outside the coded content: extraction
        // works alongside an installed decoder
        test_parser pr;
        test_decoder dec;

        pr.provide(
            "HTTP/1.1 200 OK\r\n"
            "Transfer-Encoding: chunked\r\n"
            "\r\n"
            "3\r\nabc\r\n"
            "0\r\n"
            "X-T: v\r\n"
            "\r\n");

        pr.start();
        auto hec = pr.read_header();
        BOOST_TEST(!hec);
        pr.set_decoder(&dec);

        std::string got;
        for(;;)
        {
            char buf[8];
            auto [ec, n] = pr.read_some(capy::make_buffer(buf));
            got.append(buf, n);
            if(ec)
            {
                BOOST_TEST(ec == capy::cond::eof);
                break;
            }
        }
        BOOST_TEST(got == decoded("abc"));
        BOOST_TEST(pr.got_body());

        fields f;
        system::error_code tec;
        pr.parse_trailer(f, tec);
        BOOST_TEST(!tec);
        BOOST_TEST_EQ(f.size(), 1u);
        BOOST_TEST(f.at("X-T") == "v");
    }

    void
    testDecoderChunkedEarlyEof()
    {
        test_parser pr;
        test_decoder dec;
        dec.eof_at = 3; // ends before the final chunk

        pr.provide(
            "HTTP/1.1 200 OK\r\n"
            "Transfer-Encoding: chunked\r\n"
            "\r\n"
            "5\r\nhello\r\n"
            "0\r\n\r\n");

        pr.start();
        auto hec = pr.read_header();
        BOOST_TEST(!hec);
        pr.set_decoder(&dec);

        char buf[16];
        // the cleanly decoded bytes are delivered first
        auto [ec, n] = pr.read_some(capy::make_buffer(buf));
        BOOST_TEST(!ec);
        BOOST_TEST_EQ(n, 3);

        auto [ec2, n2] = pr.read_some(capy::make_buffer(buf));
        BOOST_TEST(ec2 == http::error::bad_payload);
        BOOST_TEST_EQ(n2, 0);
    }

    void
    testDecoderChunkedIncomplete()
    {
        test_parser pr;
        test_decoder dec;

        // the stream ends mid-chunk
        pr.provide(
            "HTTP/1.1 200 OK\r\n"
            "Transfer-Encoding: chunked\r\n"
            "\r\n"
            "5\r\nab");

        pr.start();
        auto hec = pr.read_header();
        BOOST_TEST(!hec);
        pr.set_decoder(&dec);

        char buf[16];
        // the cleanly decoded bytes are delivered first
        auto [ec, n] = pr.read_some(capy::make_buffer(buf));
        BOOST_TEST(!ec);
        BOOST_TEST_EQ(n, 2);
        BOOST_TEST(std::string_view(buf, n) == decoded("ab"));

        auto [ec2, n2] = pr.read_some(capy::make_buffer(buf));
        BOOST_TEST(ec2 == http::error::incomplete);
        BOOST_TEST_EQ(n2, 0);
    }

    void
    testDecoderToEof()
    {
        test_parser pr;
        test_decoder dec;
        dec.eof_at = 5;

        // a close-delimited (to_eof) body whose decoder reaches
        // its own end-of-stream while octets remain unconsumed and
        // before the peer closes: the parser ends the body at the
        // decoder's eof and rejects the trailing octets
        pr.provide(
            "HTTP/1.1 200 OK\r\n"
            "\r\n"
            "helloJUNK");

        pr.start();
        auto hec = pr.read_header();
        BOOST_TEST(!hec);
        pr.set_decoder(&dec);

        char buf[16];
        {
            auto [ec, n] = pr.read_some(capy::make_buffer(buf));
            BOOST_TEST(!ec);
            BOOST_TEST_EQ(n, 5);
            BOOST_TEST(std::string_view(buf, n) == decoded("hello"));
        }
        {
            // the decoder is done but octets remain and the
            // connection has not closed, so the payload is rejected
            auto [ec, n] = pr.read_some(capy::make_buffer(buf));
            BOOST_TEST(ec == http::error::bad_payload);
            BOOST_TEST_EQ(n, 0);
        }
        // the message never completes: to_eof completion requires
        // an observed stream EOF, which never arrives
        BOOST_TEST(!pr.got_body());
    }

    // decoder that echoes 5 body bytes (+1), then treats any further
    // input as a trailer it consumes WITHOUT producing output, and
    // finishes (like a gzip CRC/ISIZE trailer)
    struct trailer_consuming_decoder : parser::decoder
    {
        std::uint64_t consumed_total = 0;
        bool finished = false;
        result
        process(capy::mutable_buffer out, capy::const_buffer in, bool) override
        {
            BOOST_TEST(!finished);
            if(consumed_total >= 5)
            {
                finished = true;
                return { in.size(), 0, capy::error::eof };
            }
            auto* dst = static_cast<unsigned char*>(out.data());
            auto* src = static_cast<unsigned char const*>(in.data());
            auto n = (std::min)(out.size(), in.size());
            n = (std::min<std::uint64_t>)(n, 5 - consumed_total);
            for(std::size_t i = 0; i != n; ++i)
                dst[i] = static_cast<unsigned char>(src[i] + 1);
            consumed_total += n;
            return { n, n, {} };
        }
    };

    void
    testDecoderToEofTrailerSeparateRead()
    {
        test_parser pr;
        trailer_consuming_decoder dec;

        // a to_eof body whose decoder finishes by consuming a
        // trailer that produces no output; the trailer arrives in a
        // refill separate from the body. the decoder consumes it
        // cleanly, leaving nothing buffered, and the subsequent
        // refill observes the peer's close, so the message completes
        pr.provide("HTTP/1.1 200 OK\r\n\r\nhello");
        pr.start();
        auto hec = pr.read_header();
        BOOST_TEST(!hec);
        pr.set_decoder(&dec);

        char buf[16];
        {
            auto [ec, n] = pr.read_some(capy::make_buffer(buf));
            BOOST_TEST(!ec);
            BOOST_TEST_EQ(n, 5);
            BOOST_TEST(std::string_view(buf, n) == decoded("hello"));
        }
        // the non-producing trailer arrives on its own
        pr.provide("TRL");
        {
            auto [ec, n] = pr.read_some(capy::make_buffer(buf));
            BOOST_TEST(ec == capy::cond::eof);
            BOOST_TEST_EQ(n, 0);
        }
        // the trailing refill reached the peer's close, so to_eof
        // framing is complete
        BOOST_TEST(pr.got_body());
    }

    void
    testDecoderReadBody()
    {
        test_parser pr;
        test_decoder dec;
        dec.eof_at = 5;

        pr.provide(
            "HTTP/1.1 200 OK\r\n"
            "Content-Length: 5\r\n"
            "\r\n"
            "hello");

        pr.start();
        auto hec = pr.read_header();
        BOOST_TEST(!hec);
        pr.set_decoder(&dec);

        auto [ec, body] = pr.read_body();
        BOOST_TEST(!ec);
        BOOST_TEST(body == decoded("hello"));

        auto [ec2, body2] = pr.read_body();
        BOOST_TEST(!ec2);
        BOOST_TEST(body2 == decoded("hello"));
    }

    void
    testDecoderReadBodyOverflowThenStream()
    {
        parser::config cfg;
        cfg.dec_buffer = 4; // decoded output exceeds the buffer
        test_parser pr(cfg);
        test_decoder dec;
        dec.eof_at = 5;

        pr.provide(
            "HTTP/1.1 200 OK\r\n"
            "Content-Length: 5\r\n"
            "\r\n"
            "hello");

        pr.start();
        auto hec = pr.read_header();
        BOOST_TEST(!hec);
        pr.set_decoder(&dec);

        std::string got;
        {
            // what the decode buffer holds is viewable; the rest
            // of the output has nowhere to go
            auto [ec, part] = pr.read_body();
            BOOST_TEST(ec == http::error::in_place_overflow);
            BOOST_TEST(part == decoded("hell"));
        }
        for(;;)
        {
            char buf[4];
            auto [ec, n] = pr.read_some(capy::make_buffer(buf));
            got.append(buf, n);
            if(ec)
            {
                BOOST_TEST(ec == capy::cond::eof);
                break;
            }
        }
        BOOST_TEST(got == decoded("hello"));
    }

    //--------------------------------------------
    //
    // lifecycle
    //
    //--------------------------------------------

    void
    testResetAfterFailure()
    {
        test_parser pr;
        pr.provide(
            "HTTP/1.1 200 OK\r\n"
            "Transfer-Encoding: chunked\r\n"
            "\r\n"
            "ZZZ");

        pr.start();
        char buf[8];
        {
            auto [ec, n] = pr.read_some(capy::make_buffer(buf));
            BOOST_TEST(ec == http::error::bad_payload);
        }

        // reset is the universal escape: failure is per-message
        pr.reset();
        BOOST_TEST(!pr.got_header());

        pr.provide(
            "HTTP/1.1 404 Not Found\r\n"
            "Content-Length: 3\r\n"
            "\r\n"
            "bye");

        pr.start();
        {
            auto [ec, body] = pr.read_body();
            BOOST_TEST(!ec);
            BOOST_TEST(body == "bye");
        }
        BOOST_TEST_EQ(pr.get().status_int(), 404);
    }

    void
    testPullEmptyDest()
    {
        test_parser pr;
        pr.provide(
            "HTTP/1.1 200 OK\r\n"
            "Transfer-Encoding: chunked\r\n"
            "\r\n"
            "5\r\nhello\r\n"
            "0\r\n\r\n");

        pr.start();
        auto [ec, bufs] = pr.pull({});
        BOOST_TEST(!ec);
        BOOST_TEST_EQ(bufs.size(), 0);
    }

    void
    testMoveCtor()
    {
        test_parser pr;
        pr.provide(
            "HTTP/1.1 200 OK\r\n"
            "Content-Length: 5\r\n"
            "\r\n"
            "hello");

        pr.start();
        auto ec = pr.read_header();
        BOOST_TEST(!ec);

        char buf[3];
        {
            auto [ec, n] = pr.read_some(capy::make_buffer(buf));
            BOOST_TEST(!ec);
            BOOST_TEST_EQ(n, 3);
        }

        // move-construct mid-body: pr2 must adopt the in-progress state
        // (and the parsed header the buffer points to), and the
        // moved-from pr must remain safely destructible.
        test_parser pr2(std::move(pr));
        BOOST_TEST(pr2.got_header());
        {
            auto [ec, n] = pr2.read_some(capy::make_buffer(buf));
            BOOST_TEST(!ec);
            BOOST_TEST_EQ(n, 2);
        }
        {
            auto [ec, n] = pr2.read_some(capy::make_buffer(buf));
            BOOST_TEST(ec == capy::cond::eof);
            BOOST_TEST_EQ(n, 0);
        }
    }

    void
    testMoveAssign()
    {
        test_parser pr;
        test_parser pr2; // owns its own allocation

        pr.provide(
            "HTTP/1.1 200 OK\r\n"
            "Content-Length: 5\r\n"
            "\r\n"
            "hello");

        pr.start();
        auto ec = pr.read_header();
        BOOST_TEST(!ec);

        char buf[3];
        {
            auto [ec, n] = pr.read_some(capy::make_buffer(buf));
            BOOST_TEST(!ec);
            BOOST_TEST_EQ(n, 3);
        }

        // move-assign: pr2's original allocation must be released (no
        // leak, no double free) and pr2 adopts pr's in-progress state.
        pr2 = std::move(pr);
        BOOST_TEST(pr2.got_header());
        {
            auto [ec, n] = pr2.read_some(capy::make_buffer(buf));
            BOOST_TEST(!ec);
            BOOST_TEST_EQ(n, 2);
        }
        {
            auto [ec, n] = pr2.read_some(capy::make_buffer(buf));
            BOOST_TEST(ec == capy::cond::eof);
            BOOST_TEST_EQ(n, 0);
        }
    }

    void
    testReset()
    {
        test_parser pr;
        pr.provide(
            "HTTP/1.1 200 OK\r\n"
            "Content-Length: 5\r\n"
            "\r\n"
            "hello");

        pr.start();
        {
            auto ec = pr.read_header();
            BOOST_TEST(!ec);
            BOOST_TEST(pr.got_header());
        }
        char buf[8];
        {
            auto [ec, n] = pr.read(capy::make_buffer(buf));
            BOOST_TEST(ec == capy::cond::eof);
            BOOST_TEST_EQ(n, 5);
            BOOST_TEST(std::string_view(buf, n) == "hello");
        }

        // reset must return the parser to a construction-like state:
        // buffers restored, flags cleared, and a second, differently
        // framed message parses correctly.
        pr.reset();
        BOOST_TEST(!pr.got_header());

        pr.provide(
            "HTTP/1.1 404 Not Found\r\n"
            "Transfer-Encoding: chunked\r\n"
            "\r\n"
            "3\r\nbye\r\n"
            "0\r\n\r\n");

        pr.start();
        {
            auto ec = pr.read_header();
            BOOST_TEST(!ec);
            BOOST_TEST(pr.got_header());
        }
        {
            auto [ec, n] = pr.read(capy::make_buffer(buf));
            BOOST_TEST(ec == capy::cond::eof);
            BOOST_TEST_EQ(n, 3);
            BOOST_TEST(std::string_view(buf, n) == "bye");
        }
        BOOST_TEST(!pr.has_buffered_data());
    }

    void
    testStartPipelined()
    {
        test_parser pr;
        pr.provide(
            "HTTP/1.1 200 OK\r\n"
            "Content-Length: 5\r\n"
            "\r\n"
            "hello"
            "HTTP/1.1 200 OK\r\n"
            "Content-Length: 3\r\n"
            "\r\n"
            "bye");

        pr.start();
        {
            auto [ec, body] = pr.read_body();
            BOOST_TEST(!ec);
            BOOST_TEST(body == "hello");
        }
        BOOST_TEST(pr.got_body());
        BOOST_TEST(pr.has_buffered_data());
        pr.consume(5);

        // start() re-arms for the next message on the same
        // stream, carrying the pipelined octets over
        pr.start();
        BOOST_TEST(!pr.got_header());
        {
            auto [ec, body] = pr.read_body();
            BOOST_TEST(!ec);
            BOOST_TEST(body == "bye");
        }
        BOOST_TEST(pr.got_body());
        BOOST_TEST(!pr.has_buffered_data());

        // nothing follows the second message; the undelivered
        // "bye" view is skipped by the restart
        pr.start();
        auto ec = pr.read_header();
        BOOST_TEST(ec == http::error::end_of_stream);
    }

    void
    testStartParksCompleteMessage()
    {
        test_parser pr;
        pr.provide(
            "HTTP/1.1 200 OK\r\n"
            "Content-Length: 5\r\n"
            "\r\n"
            "hello"
            "HTTP/1.1 200 OK\r\n"
            "Content-Length: 3\r\n"
            "\r\n"
            "bye");

        pr.start();
        char const* first = nullptr;
        {
            auto [ec, body] = pr.read_body();
            BOOST_TEST(!ec);
            BOOST_TEST(body == "hello");
            first = body.data();
        }
        pr.consume(5);

        pr.start();

        // the octets carried over are reported even though
        // the header has not completed yet
        BOOST_TEST(pr.has_buffered_data());
        {
            auto [ec, body] = pr.read_body();
            BOOST_TEST(!ec);
            BOOST_TEST(body == "bye");

            // the whole message was already buffered, so the
            // header was parsed where its octets lay; nothing
            // was moved back to the front of the buffer
            BOOST_TEST(body.data() > first + 5);
        }
    }

    void
    testStartCompactsIncompleteMessage()
    {
        test_parser pr;
        pr.provide(
            "HTTP/1.1 200 OK\r\n"
            "Content-Length: 5\r\n"
            "\r\n"
            "hello"
            "HTTP/1.1 200 OK\r\n"
            "Content-Length: 3\r\n"
            "\r\n");

        pr.start();
        char const* first = nullptr;
        {
            auto [ec, body] = pr.read_body();
            BOOST_TEST(!ec);
            BOOST_TEST(body == "hello");
            first = body.data();
        }
        pr.consume(5);

        pr.start();
        {
            auto ec = pr.read_header();
            BOOST_TEST(!ec);
        }
        pr.provide("bye");
        {
            auto [ec, body] = pr.read_body();
            BOOST_TEST(!ec);
            BOOST_TEST(body == "bye");

            // the body had not arrived, so the header was
            // moved back to the front to recover the window;
            // both headers are the same length
            BOOST_TEST(body.data() == first);
        }
    }

    void
    testStartRetriesOverflowAtParkedBase()
    {
        // sized so that once the first message is parked, the run
        // above the parked base is too short for the second
        // header. Parsing must fall back to the front of the
        // buffer rather than fail with in_place_overflow.
        parser::config cfg;
        cfg.hdr_limits.max_fields = 1;
        cfg.hdr_limits.max_size = 39;
        cfg.in_buffer = 36;
        test_parser pr(cfg);

        pr.provide(
            "HTTP/1.1 200 OK\r\n"       // 39 octets
            "Content-Length: 20\r\n"
            "\r\n"
            "01234567890123456789"      // 20 octets
            "HTTP/1.1 200 OK\r\n"       // 38 octets
            "Content-Length: 3\r\n"
            "\r\n"
            "bye");

        pr.start();
        {
            auto [ec, body] = pr.read_body();
            BOOST_TEST(!ec);
            BOOST_TEST(body == "01234567890123456789");
        }
        pr.consume(20);

        pr.start();
        {
            auto [ec, body] = pr.read_body();
            BOOST_TEST(!ec);
            BOOST_TEST(body == "bye");
        }
    }

    void
    testStartSkipsUndeliveredRemainder()
    {
        test_parser pr;
        pr.provide(
            "HTTP/1.1 200 OK\r\n"
            "Content-Length: 5\r\n"
            "\r\n"
            "hello"
            "HTTP/1.1 204 No Content\r\n"
            "\r\n");

        pr.start();
        {
            auto ec = pr.read_header();
            BOOST_TEST(!ec);
        }
        // the whole sized body arrived with the header; the
        // caller moves on without ever delivering it
        BOOST_TEST(pr.got_body());
        pr.start();
        {
            auto ec = pr.read_header();
            BOOST_TEST(!ec);
            BOOST_TEST_EQ(pr.get().status_int(), 204);
        }
        BOOST_TEST(pr.got_body());
        BOOST_TEST(!pr.has_buffered_data());
    }

    //--------------------------------------------
    //
    // sans-io surface
    //
    //--------------------------------------------

    void
    testDirectCapacity()
    {
        // The pass-through budget is what lets a body be received straight
        // into caller memory. It must be offered exactly when that is safe.
        {
            test_parser pr;
            pr.provide(
                "HTTP/1.1 200 OK\r\n"
                "Content-Length: 5\r\n"
                "\r\n");

            pr.start();
            auto ec = pr.read_header();
            BOOST_TEST(!ec);
            // nothing buffered, so the whole payload may go direct
            BOOST_TEST_EQ(pr.direct_capacity(), 5u);

            // a limit below the declared size withholds
            // the budget: the message can never complete
            pr.set_body_limit(3);
            BOOST_TEST_EQ(pr.direct_capacity(), 0u);
        }
        {
            // octets which arrived with the header must be drained first
            test_parser pr;
            pr.provide(
                "HTTP/1.1 200 OK\r\n"
                "Content-Length: 5\r\n"
                "\r\n"
                "he");

            pr.start();
            auto ec = pr.read_header();
            BOOST_TEST(!ec);
            BOOST_TEST_EQ(pr.direct_capacity(), 0u);

            char buf[8];
            auto [rec, n] = pr.read_some(capy::make_buffer(buf));
            BOOST_TEST(!rec);
            BOOST_TEST_EQ(n, 2);

            // buffer drained: the remainder may go direct
            BOOST_TEST_EQ(pr.direct_capacity(), 3u);
        }
        {
            // a decoder has to see the octets, so nothing may bypass it
            test_parser pr;
            test_decoder dec;
            pr.provide(
                "HTTP/1.1 200 OK\r\n"
                "Content-Length: 5\r\n"
                "\r\n");

            pr.start();
            auto ec = pr.read_header();
            BOOST_TEST(!ec);
            pr.set_decoder(&dec);
            BOOST_TEST_EQ(pr.direct_capacity(), 0u);
        }
        {
            // chunked framing has to be walked, so it cannot go direct
            test_parser pr;
            pr.provide(
                "HTTP/1.1 200 OK\r\n"
                "Transfer-Encoding: chunked\r\n"
                "\r\n");

            pr.start();
            auto ec = pr.read_header();
            BOOST_TEST(!ec);
            BOOST_TEST_EQ(pr.direct_capacity(), 0u);
        }
    }

    void
    testDirectReadBypassesBuffer()
    {
        // With a buffer far smaller than the body, a single read_some can
        // only deliver more than the buffer holds by reading straight into
        // the caller's memory.
        auto const body = make_body(4096);
        test_parser pr(
            {
                .hdr_limits = { .max_size = 128, .max_fields = 4 },
                .in_buffer  = 64
            });

        pr.provide(
            "HTTP/1.1 200 OK\r\n"
            "Content-Length: 4096\r\n"
            "\r\n");

        pr.start();
        auto ec = pr.read_header();
        BOOST_TEST(!ec);

        // the body arrives only after the header, so none of it is
        // buffered and all of it is eligible for the direct path
        pr.provide(body);

        std::string dest(4096, '\0');
        auto [rec, n] = pr.read_some(
            capy::mutable_buffer(dest.data(), dest.size()));
        BOOST_TEST(!rec);
        BOOST_TEST_EQ(n, 4096);
        BOOST_TEST(std::string_view(dest.data(), n) == body);
        BOOST_TEST(pr.got_body());
    }

    void
    testBufferedData()
    {
        {
            // pipelined: the next message is visible once this one is done
            test_parser pr;
            pr.provide(
                "HTTP/1.1 200 OK\r\n"
                "Content-Length: 5\r\n"
                "\r\n"
                "hello"
                "HTTP/1.1 204 No Content\r\n"
                "\r\n");

            pr.start();
            auto ec = pr.read_header();
            BOOST_TEST(!ec);

            char buf[8];
            auto [rec, n] = pr.read_some(capy::make_buffer(buf));
            BOOST_TEST(!rec);
            BOOST_TEST_EQ(n, 5);

            BOOST_TEST(pr.has_buffered_data());
            auto const bufs = pr.buffered_data();
            BOOST_TEST_EQ(capy::buffer_size(bufs), 27u);
            BOOST_TEST(std::string_view(
                static_cast<char const*>(bufs[0].data()),
                bufs[0].size()).starts_with("HTTP/1.1 204"));
        }
        {
            // A response whose framing runs to the end of the stream hides
            // its leftovers from has_buffered_data. This is the shape of a
            // 200 answer to CONNECT: the caller knows there is no body even
            // though the response alone cannot say so, and buffered_data is
            // the only way to recover the octets which follow.
            test_parser pr;
            pr.provide(
                "HTTP/1.1 200 Connection Established\r\n"
                "\r\n"
                "\x16\x03\x01");

            pr.start();
            auto ec = pr.read_header();
            BOOST_TEST(!ec);
            BOOST_TEST(pr.get().payload() ==
                http::payload::to_eof);

            BOOST_TEST(!pr.has_buffered_data());
            auto const bufs = pr.buffered_data();
            BOOST_TEST_EQ(capy::buffer_size(bufs), 3u);
            BOOST_TEST(std::string_view(
                static_cast<char const*>(bufs[0].data()),
                bufs[0].size()) == "\x16\x03\x01");
        }
    }

    void
    testEofWithOctets()
    {
        // A refill which delivers the last octets together with the close
        // must not lose them: they are committed before the contingency is
        // acted on, and reported before eof is.
        {
            test_parser pr;
            pr.eager_eof();
            pr.provide(
                "HTTP/1.1 200 OK\r\n"
                "\r\n"
                "hello");

            pr.start();
            auto ec = pr.read_header();
            BOOST_TEST(!ec);

            std::string got;
            char buf[16];
            for(;;)
            {
                auto [rec, n] = pr.read_some(capy::make_buffer(buf));
                got.append(buf, n);
                if(rec)
                {
                    // any contingency ends the read; only eof is
                    // expected here
                    BOOST_TEST(rec == capy::cond::eof);
                    break;
                }
            }
            BOOST_TEST(got == "hello");
            BOOST_TEST(pr.got_body());
        }
        {
            // same, through a decoder, which forces every octet to travel
            // via the parser's buffer rather than the pass-through path
            test_parser pr;
            test_decoder dec;
            pr.eager_eof();
            pr.provide(
                "HTTP/1.1 200 OK\r\n"
                "Content-Length: 5\r\n"
                "\r\n"
                "hello");

            pr.start();
            auto ec = pr.read_header();
            BOOST_TEST(!ec);
            pr.set_decoder(&dec);

            auto [bec, body] = pr.read_body();
            BOOST_TEST(!bec);
            BOOST_TEST(body == decoded("hello"));
        }
    }

    void
    run()
    {
        testHeader();
        testHeaderEagerComplete();
        testHeaderSyntaxError();
        testHeaderPayloadError();
        testRequestBadTransferEncoding();
        testEndOfStream();
        testIncompleteHeader();
        testHeaderResumes();
        testHeaderLargerThanBuffer();

        testSizedReadSome();
        testSizedPullConsume();
        testSizedReadBody();
        testSizedTrailingJunk();
        testSizedZeroLength();
        testSizedIncomplete();
        testSizedReadBodyIncomplete();
        testSizedBodyLimit();
        testSizedBodyLimitViaReadBody();
        testSizedPullBodyLimitZero();
        testSizedMixedStreamThenView();
        testSizedReadBodyOverflow();

        testChunkedReadSome();
        testChunkedPullConsume();
        testChunkedReadBody();
        testChunkedReadBodyByteByByte();
        testChunkedReadBodySplitMidChunk();
        testChunkedReadBodyPipelined();
        testChunkedTrailersAndExtensions();
        testTrailerReadSome();
        testTrailerReadBody();
        testTrailerPullConsume();
        testTrailerEmptyAndNonChunked();
        testTrailerObsFold();
        testTrailerByteByByte();
        testTrailerLimit();
        testTrailerBadField();
        testTrailerStaticFields();
        testTrailerStraddleWrap();
        testChunkedPullSmallDest();
        testChunkedBadFraming();
        testChunkedBadFramingWithData();
        testChunkedBadChunkExtension();
        testChunkedSizeOverflow();
        testChunkedBadChunkTerminator();
        testChunkedBadTrailer();
        testChunkedPullDrainThenError();
        testChunkedIncomplete();
        testChunkedFramingLargerThanBuffer();
        testChunkedReadBodyChunkLargerThanBuffer();
        testChunkedBodyLimit();
        testChunkedBodyLimitViaReadBody();
        testChunkedBodyLimitViaConsume();
        testChunkedBodyLimitDecoder();
        testChunkedExactLimitPull();
        testChunkedExactLimitDecoder();
        testChunkedExactLimitDecoderViaReadBody();
        testChunkedEmptyBodyZeroLimit();
        testChunkedByteByByte();
        testChunkedReadBodyOverflowThenStream();

        testToEofReadSome();
        testToEofReadBody();
        testToEofPull();
        testToEofEmptyBody();
        testToEofBodyLimit();
        testToEofBodyLimitViaReadBody();
        testToEofPullBodyLimitZero();
        testToEofExactLimit();
        testToEofExactLimitEagerEof();
        testToEofExactLimitPull();
        testToEofExactLimitDecoder();
        testToEofExactLimitDecoderViaReadBody();
        testToEofEmptyBodyZeroLimit();

        testSetBodyLimitEnforced();
        testSetBodyLimitRaiseUnblocks();
        testSetBodyLimitBelowTransferred();
        testSetBodyLimitDecoder();

        testHeadResponse();
        testHeadResponseWithJunk();

        testDecoderSized();
        testDecoderSizedFinishOnKick();
        testDecoderTrailer();
        testDecoderTruncatedStream();
        testDecoderEarlyEof();
        testDecoderHardError();
        testDecoderPullServesDataBeforeError();
        testDecoderNoPayload();
        testDecoderReadSomeEmptyBuffer();
        testDecoderReadSomeLeadingEmptyBuffer();
        testDecoderBodyAfterStreaming();
        testDecoderReadBodyHardError();
        testDecoderPullTwiceWithoutConsume();
        testDecoderChunked();
        testDecoderChunkedTrailer();
        testDecoderChunkedEarlyEof();
        testDecoderChunkedIncomplete();
        testDecoderToEof();
        testDecoderToEofTrailerSeparateRead();
        testDecoderReadBody();
        testDecoderReadBodyOverflowThenStream();

        testResetAfterFailure();
        testPullEmptyDest();
        testMoveCtor();
        testMoveAssign();
        testReset();
        testStartPipelined();
        testStartParksCompleteMessage();
        testStartCompactsIncompleteMessage();
        testStartRetriesOverflowAtParkedBase();
        testStartSkipsUndeliveredRemainder();

        testDirectCapacity();
        testDirectReadBypassesBuffer();
        testBufferedData();
        testEofWithOctets();
    }
};

TEST_SUITE(parser_test, "boost.burl.parser");
} // namespace burl
} // namespace boost
