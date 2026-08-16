//
// Copyright (c) 2026 Mohammad Nejati
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

// Test that header file is self-contained.
#include <boost/burl/serializer.hpp>

#include <boost/burl/error.hpp>
#include <boost/burl/fields.hpp>
#include <boost/burl/request_head.hpp>
#include <boost/burl/response_head.hpp>

#include <boost/capy/buffers/buffer_copy.hpp>
#include <boost/capy/buffers/make_buffer.hpp>
#include <boost/capy/error.hpp>

#include <cstring>
#include <string>

#include "test_suite.hpp"

namespace boost
{
namespace burl
{

// The serializer performs no I/O: every test below supplies the
// body to frame() as a buffer sequence and drains the returned
// descriptors through consume() into a std::string, trimming
// the body by what consume() returns. No streams are involved.
class serializer_test
{
    // A scaled-down config so that framing and encoder
    // thresholds (staged vs. direct writes, commit-triggered
    // flushes, encoder drop) are crossed with tiny bodies, and
    // so tests keep exercising the same paths if the default
    // config values change.
    static constexpr serializer::config cfg{
        .stage_buffer  = 64,
        .min_prepare   = 32,
        .min_direct    = 16,
        .enc_buffer    = 32,
        .enc_threshold = 8 };

    // header + merged prefix/run + a few body descriptors +
    // epilogue + trailer
    static constexpr std::size_t dest_n = 24;

    static request_head
    make_request()
    {
        request_head req;
        req.set_chunked(true);
        return req;
    }

    static request_head
    make_request(std::size_t cl)
    {
        request_head req;
        req.set_content_length(cl);
        return req;
    }

    // An encoder that increments every body byte by one, so
    // encoded output is distinguishable from identity output,
    // and appends an optional footer once the input ends. It
    // consumes and produces as much as the given buffers allow,
    // or at most `out_limit` octets per call when set.
    struct test_encoder : serializer::encoder
    {
        std::string footer;
        std::error_code fail;
        std::size_t out_limit = 0;
        std::size_t calls = 0;
        bool finished = false;

        explicit test_encoder(std::string f = {})
            : footer(std::move(f))
        {
        }

        result
        process(
            capy::mutable_buffer out,
            capy::const_buffer in,
            bool more) override
        {
            ++calls;
            if(fail)
                return { 0, 0, fail };
            if(out_limit != 0 && out.size() > out_limit)
                out = { out.data(), out_limit };

            auto* dst = static_cast<unsigned char*>(out.data());
            auto* src = static_cast<unsigned char const*>(in.data());
            auto const n = (std::min)(out.size(), in.size());
            for(std::size_t i = 0; i != n; ++i)
                dst[i] = static_cast<unsigned char>(src[i] + 1);

            result r{ n, n, {} };
            if(!more && n == in.size())
            {
                auto const t = (std::min)(
                    out.size() - n, footer.size() - footer_pos_);
                std::memcpy(
                    dst + n, footer.data() + footer_pos_, t);
                footer_pos_ += t;
                r.produced += t;
                if(footer_pos_ == footer.size())
                {
                    finished = true;
                    r.ec = capy::error::eof;
                }
            }
            return r;
        }

    private:
        std::size_t footer_pos_ = 0;
    };

    // Returns a body with a varied byte pattern so reordered
    // or duplicated regions cannot go unnoticed.
    static std::string
    make_body(std::size_t n)
    {
        std::string s(n, '\0');
        for(std::size_t i = 0; i != n; ++i)
            s[i] = static_cast<char>('0' + i % 64);
        return s;
    }

    // Returns the mock-encoded form of `s`.
    static std::string
    encoded(std::string_view s)
    {
        std::string r(s);
        for(auto& c : r)
            c = static_cast<char>(c + 1);
        return r;
    }

    // One drive pass: supplies `body`, trimming it by whatever
    // consume() reports, and drains the framed output into
    // `wire`, consuming at most `step` octets per lap so every
    // cursor split point is exercised when `step` is small.
    // Returns when frame() has no work for this input.
    static system::error_code
    drive(
        serializer& sr,
        std::string& wire,
        std::string_view& body,
        bool more,
        std::size_t step = std::size_t(-1))
    {
        for(;;)
        {
            capy::const_buffer const b{
                body.data(), body.size() };
            system::error_code ec;
            capy::const_buffer dest[dest_n];
            auto const bufs = sr.frame(dest, b, more, ec);
            if(bufs.empty())
            {
                body.remove_prefix(sr.consume(0));
                return ec;
            }
            std::size_t n = 0;
            for(auto cb : bufs)
            {
                auto const k = (std::min)(step - n, cb.size());
                wire.append(
                    static_cast<char const*>(cb.data()), k);
                if((n += k) == step)
                    break;
            }
            body.remove_prefix(sr.consume(n));
        }
    }

    // Writes the whole of `body` without ending the message;
    // the sans-I/O equivalent of the awaitable write().
    static system::error_code
    write(
        serializer& sr,
        std::string& wire,
        std::string_view body,
        std::size_t step = std::size_t(-1))
    {
        do
        {
            if(auto ec = drive(sr, wire, body, true, step))
                return ec;
        }
        while(!body.empty());
        return {};
    }

    // Ends the body with `body`; the sans-I/O equivalent of the
    // awaitable write_eof().
    static system::error_code
    write_eof(
        serializer& sr,
        std::string& wire,
        std::string_view body = {},
        std::size_t step = std::size_t(-1))
    {
        for(;;)
        {
            if(auto ec = drive(sr, wire, body, false, step))
                return ec;
            if(sr.is_done())
                return {};
        }
    }

    // Flushes outstanding output (and the header) without
    // supplying anything; the sans-I/O drain().
    static system::error_code
    drain(
        serializer& sr,
        std::string& wire,
        std::size_t step = std::size_t(-1))
    {
        std::string_view none;
        return drive(sr, wire, none, true, step);
    }

    // The same, through the frame() overload that takes no
    // buffer sequence at all.
    static system::error_code
    drain_bufferless(
        serializer& sr,
        std::string& wire,
        bool more = true)
    {
        for(;;)
        {
            system::error_code ec;
            capy::const_buffer dest[dest_n];
            auto const bufs = sr.frame(dest, more, ec);
            if(bufs.empty())
            {
                BOOST_TEST_EQ(sr.consume(0), 0u);
                return ec;
            }
            std::size_t n = 0;
            for(auto cb : bufs)
            {
                wire.append(
                    static_cast<char const*>(cb.data()),
                    cb.size());
                n += cb.size();
            }
            BOOST_TEST_EQ(sr.consume(n), 0u);
        }
    }

public:
    void
    testContentLengthSmallBody()
    {
        auto req = make_request(5);
        serializer sr(cfg);
        sr.start(&req);
        BOOST_TEST(!sr.is_done());

        std::string wire;
        BOOST_TEST(!write(sr, wire, "hello"));
        BOOST_TEST(wire.empty()); // coalesced, header held back
        BOOST_TEST(!sr.is_done());

        BOOST_TEST(!write_eof(sr, wire));
        BOOST_TEST(sr.is_done());

        BOOST_TEST_EQ(
            wire, std::string(req.buffer()) + "hello");
    }

    void
    testContentLengthLargeBody()
    {
        // A body at the direct-write threshold bypasses staging.
        std::string const body(cfg.min_direct, 'x');
        auto req = make_request(body.size());
        serializer sr(cfg);
        sr.start(&req);

        std::string wire;
        BOOST_TEST(!write(sr, wire, body));
        BOOST_TEST(!write_eof(sr, wire));

        BOOST_TEST_EQ(
            wire, std::string(req.buffer()) + body);
    }

    void
    testContentLengthMultipleBuffers()
    {
        std::string const b1(4, 'a');
        std::string const b2(4, 'b');
        auto req = make_request(b1.size() + b2.size());
        serializer sr(cfg);
        sr.start(&req);

        capy::const_buffer const bufs[2] = {
            capy::make_buffer(b1),
            capy::make_buffer(b2) };

        std::string wire;
        system::error_code ec;
        capy::const_buffer dest[dest_n];
        auto const out = sr.frame(dest, bufs, false, ec);
        BOOST_TEST(!ec);
        BOOST_TEST(!out.empty());

        std::size_t n = 0;
        for(auto cb : out)
        {
            wire.append(
                static_cast<char const*>(cb.data()), cb.size());
            n += cb.size();
        }
        BOOST_TEST_EQ(sr.consume(n), 8u);
        BOOST_TEST(sr.is_done());

        BOOST_TEST_EQ(
            wire, std::string(req.buffer()) + b1 + b2);
    }

    void
    testBodySizeMismatch()
    {
        // fewer bytes than Content-Length
        {
            auto req = make_request(5);
            serializer sr(cfg);
            sr.start(&req);

            std::string wire;
            BOOST_TEST(!write(sr, wire, "hell"));
            BOOST_TEST_EQ(
                write_eof(sr, wire),
                error::body_size_mismatch);
            BOOST_TEST(!sr.is_done());
        }

        // more bytes than Content-Length: caught at the
        // supplying call, before any octet is handed out
        {
            auto req = make_request(5);
            serializer sr(cfg);
            sr.start(&req);

            std::string wire;
            BOOST_TEST_EQ(
                write(sr, wire, "helloo"),
                error::body_size_mismatch);
            BOOST_TEST(wire.empty());
        }

        // same on the direct path
        std::string const body(cfg.min_direct, 'x');
        {
            auto req = make_request(5);
            serializer sr(cfg);
            sr.start(&req);

            std::string wire;
            BOOST_TEST_EQ(
                write(sr, wire, body),
                error::body_size_mismatch);
            BOOST_TEST(wire.empty());
        }

        // errors preserve state: the failed call repeats, and a
        // corrected input proceeds
        {
            auto req = make_request(5);
            serializer sr(cfg);
            sr.start(&req);

            std::string wire;
            BOOST_TEST_EQ(
                write(sr, wire, "helloo"),
                error::body_size_mismatch);
            BOOST_TEST_EQ(
                write(sr, wire, "helloo"),
                error::body_size_mismatch);
            BOOST_TEST(!write_eof(sr, wire, "hello"));
            BOOST_TEST(sr.is_done());
            BOOST_TEST_EQ(
                wire, std::string(req.buffer()) + "hello");
        }
    }

    void
    testChunkedSmallBodyConvertsToContentLength()
    {
        auto req = make_request();
        serializer sr(cfg);
        sr.start(&req);

        // The body stays below min_direct, so it is fully
        // buffered before the header goes out.
        std::string wire;
        BOOST_TEST(!write(sr, wire, "hello world"));
        BOOST_TEST(!write_eof(sr, wire));

        // The entire body was buffered before the header was
        // flushed, so chunked encoding is replaced with
        // Content-Length and the body is sent unframed.
        BOOST_TEST(!req.chunked());
        BOOST_TEST_EQ(req.content_length().value(), 11u);
        BOOST_TEST(
            wire.find("Transfer-Encoding") ==
            std::string::npos);
        BOOST_TEST_EQ(
            wire, std::string(req.buffer()) + "hello world");
    }

    void
    testChunkedWriteEofWithBody()
    {
        auto req = make_request();
        serializer sr(cfg);
        sr.start(&req);

        std::string wire;
        BOOST_TEST(!write_eof(sr, wire, "hello"));
        BOOST_TEST(sr.is_done());

        BOOST_TEST(!req.chunked());
        BOOST_TEST_EQ(req.content_length().value(), 5u);
        BOOST_TEST_EQ(
            wire, std::string(req.buffer()) + "hello");
    }

    void
    testChunkedLargeBody()
    {
        std::string const body(cfg.min_direct, 'x');
        auto req = make_request();
        serializer sr(cfg);
        sr.start(&req);

        std::string wire;
        BOOST_TEST(!write(sr, wire, body));
        BOOST_TEST(!write(sr, wire, "hello"));
        BOOST_TEST(!sr.is_done());
        BOOST_TEST(!write_eof(sr, wire));
        BOOST_TEST(sr.is_done());

        // The large write is gathered with the header and sent
        // as its own chunk; the small write is buffered and
        // flushed at eof as a chunk. Chunk sizes are always
        // minimal-width; 16 == 0x10.
        std::string expected(req.buffer());
        expected += "10\r\n" + body + "\r\n";
        expected += "5\r\nhello\r\n";
        expected += "0\r\n\r\n";
        BOOST_TEST(req.chunked());
        BOOST_TEST_EQ(wire, expected);
    }

    void
    testChunkedWriteEofWithTail()
    {
        // Once the header is on the wire, the final input must
        // frame the staged bytes and the caller's bytes as the
        // final chunk and terminate the body with the last-chunk
        // in the same vector.
        std::string const body(cfg.min_direct, 'x');
        auto req = make_request();
        serializer sr(cfg);
        sr.start(&req);

        std::string wire;
        BOOST_TEST(!write(sr, wire, body));
        BOOST_TEST(!write(sr, wire, "abc"));
        BOOST_TEST(!write_eof(sr, wire, "hello"));

        std::string expected(req.buffer());
        expected += "10\r\n" + body + "\r\n";
        expected += "8\r\nabchello\r\n";
        expected += "0\r\n\r\n";
        BOOST_TEST(req.chunked());
        BOOST_TEST_EQ(wire, expected);
    }

    void
    testChunkedWriteEofTailOnly()
    {
        std::string const body(cfg.min_direct, 'x');
        auto req = make_request();
        serializer sr(cfg);
        sr.start(&req);

        std::string wire;
        BOOST_TEST(!write(sr, wire, body));
        BOOST_TEST(!write_eof(sr, wire, "hello"));

        std::string expected(req.buffer());
        expected += "10\r\n" + body + "\r\n";
        expected += "5\r\nhello\r\n";
        expected += "0\r\n\r\n";
        BOOST_TEST(req.chunked());
        BOOST_TEST_EQ(wire, expected);
    }

    void
    testChunkedEmptyBody()
    {
        auto req = make_request();
        serializer sr(serializer::config{});
        sr.start(&req);
        BOOST_TEST(!sr.is_done());

        std::string wire;
        BOOST_TEST(!write_eof(sr, wire));
        BOOST_TEST(sr.is_done());

        BOOST_TEST(!req.chunked());
        BOOST_TEST(
            wire.find("Content-Length: 0\r\n") !=
            std::string::npos);
        BOOST_TEST_EQ(wire, std::string(req.buffer()));
    }

    void
    testPrepareCommitContentLength()
    {
        auto req = make_request(5);
        serializer sr(cfg);
        sr.start(&req);

        capy::mutable_buffer tmp[2];
        auto const dest = sr.prepare(tmp);
        BOOST_TEST_EQ(
            capy::buffer_size(dest), cfg.stage_buffer);
        auto const n = capy::buffer_copy(
            dest, capy::const_buffer("hello", 5));
        BOOST_TEST_EQ(n, 5u);
        sr.commit(n);

        std::string wire;
        BOOST_TEST(!write_eof(sr, wire));
        BOOST_TEST(sr.is_done());
        BOOST_TEST_EQ(
            wire, std::string(req.buffer()) + "hello");
    }

    void
    testPrepareCommitPartialFlush()
    {
        // A commit that leaves at least min_prepare capacity
        // raises no drain pressure and a drain pass moves no
        // body; one that does flushes the whole staged run as
        // one chunk.
        auto req = make_request();
        serializer sr(cfg);
        sr.start(&req);

        std::string const b1 = make_body(30);
        std::string const b2 = make_body(4);

        capy::mutable_buffer tmp[2];
        capy::buffer_copy(
            sr.prepare(tmp), capy::make_buffer(b1));
        sr.commit(b1.size());
        BOOST_TEST(!sr.should_drain());

        // a drain pass flushes the header, but not the run
        std::string wire;
        BOOST_TEST(!drain(sr, wire));
        BOOST_TEST_EQ(wire, std::string(req.buffer()));

        capy::buffer_copy(
            sr.prepare(tmp), capy::make_buffer(b2));
        sr.commit(b2.size());
        BOOST_TEST(sr.should_drain());

        BOOST_TEST(!drain(sr, wire));

        // 34 == 0x22
        std::string expected(req.buffer());
        expected += "22\r\n" + b1 + b2;
        BOOST_TEST_EQ(wire, expected);

        BOOST_TEST(!write_eof(sr, wire));
        expected += "\r\n0\r\n\r\n";
        BOOST_TEST_EQ(wire, expected);
    }

    void
    testPrepareCommitChunked()
    {
        // The staging buffer holds raw body bytes only, so the
        // full capacity is stageable as one chunk; 64 == 0x40.
        std::string const body(cfg.stage_buffer, 'z');
        auto req = make_request();
        serializer sr(cfg);
        sr.start(&req);

        capy::mutable_buffer tmp[2];
        auto const n = capy::buffer_copy(
            sr.prepare(tmp), capy::make_buffer(body));
        BOOST_TEST_EQ(n, body.size());
        sr.commit(n);
        BOOST_TEST(sr.should_drain());

        std::string wire;
        BOOST_TEST(!drain(sr, wire));

        // the chunk's closing CRLF is deferred to the next unit
        BOOST_TEST_EQ(
            wire,
            std::string(req.buffer()) + "40\r\n" + body);

        BOOST_TEST(!write(sr, wire, "hello"));
        BOOST_TEST(!write_eof(sr, wire));

        std::string expected(req.buffer());
        expected += "40\r\n" + body + "\r\n";
        expected += "5\r\nhello\r\n";
        expected += "0\r\n\r\n";
        BOOST_TEST(req.chunked());
        BOOST_TEST_EQ(wire, expected);
    }

    void
    testPrepareCommitNoFlush()
    {
        // Nothing is drained before eof, so the staged body
        // converts to Content-Length.
        auto req = make_request();
        serializer sr(cfg);
        sr.start(&req);

        capy::mutable_buffer tmp[2];
        capy::buffer_copy(
            sr.prepare(tmp), capy::const_buffer("hello", 5));
        sr.commit(5);
        BOOST_TEST(!sr.should_drain());

        std::string wire;
        BOOST_TEST(!write_eof(sr, wire));
        BOOST_TEST(sr.is_done());

        BOOST_TEST(!req.chunked());
        BOOST_TEST_EQ(req.content_length().value(), 5u);
        BOOST_TEST_EQ(
            wire, std::string(req.buffer()) + "hello");
    }

    void
    testPrepareEmptyDest()
    {
        auto req = make_request();
        serializer sr(cfg);
        sr.start(&req);

        auto const dest = sr.prepare({});
        BOOST_TEST(dest.empty());
    }

    void
    testPrepareFullBuffer()
    {
        // A full staging buffer yields an empty prepare(); a
        // drain pass flushes it and restores the full window.
        std::string const body(cfg.stage_buffer, 'z');
        auto req = make_request();
        serializer sr(cfg);
        sr.start(&req);

        capy::mutable_buffer tmp[2];
        auto const n = capy::buffer_copy(
            sr.prepare(tmp), capy::make_buffer(body));
        BOOST_TEST_EQ(n, body.size());
        sr.commit(n);
        BOOST_TEST(sr.prepare(tmp).empty());

        std::string wire;
        BOOST_TEST(!drain(sr, wire));

        BOOST_TEST_EQ(
            capy::buffer_size(sr.prepare(tmp)),
            cfg.stage_buffer);

        BOOST_TEST(!write_eof(sr, wire));
        BOOST_TEST(sr.is_done());
    }

    void
    testPartialConsume()
    {
        // The same multi-chunk message drained one octet at a
        // time, and at various other split widths, must produce
        // identical wire bytes: frame re-materializes remainders
        // from the cursors, including a partially consumed chunk
        // prefix, with the body supplied again every call.
        std::string const body(cfg.min_direct, 'x');

        std::string expected;
        {
            auto req = make_request();
            serializer sr(cfg);
            sr.start(&req);
            BOOST_TEST(!write(sr, expected, body));
            BOOST_TEST(!write(sr, expected, "abc"));
            BOOST_TEST(!write_eof(sr, expected, "hello"));
        }

        for(std::size_t step = 1; step != 24; ++step)
        {
            auto req = make_request();
            serializer sr(cfg);
            sr.start(&req);

            std::string wire;
            BOOST_TEST(!write(sr, wire, body, step));
            BOOST_TEST(!write(sr, wire, "abc", step));
            BOOST_TEST(!write_eof(sr, wire, "hello", step));
            BOOST_TEST(sr.is_done());
            BOOST_TEST_EQ(wire, expected);
        }
    }

    void
    testRemainderCoalesces()
    {
        // What is left of a directly framed input after a short
        // write is judged on its own size: once under the
        // threshold it coalesces, rather than costing a write of
        // its own. The end of the body is the exception — there
        // is nothing left to batch with, so a final input goes
        // out as it stands.
        std::string const body(cfg.min_direct + 8, 'x');
        auto req = make_request(body.size());
        serializer sr(cfg);
        sr.start(&req);

        std::string_view rem(body);
        capy::const_buffer const b{
            rem.data(), rem.size() };
        system::error_code ec;
        capy::const_buffer dest[dest_n];

        auto out = sr.frame(dest, b, true, ec);
        BOOST_TEST(!ec);
        BOOST_TEST_EQ(out.size(), 2u); // header + body, no copy

        // the wire takes the header and all but 4 octets
        std::string wire;
        for(auto cb : out)
            wire.append(
                static_cast<char const*>(cb.data()), cb.size());
        auto const k = req.buffer().size() + body.size() - 4;
        wire.resize(k);
        rem.remove_prefix(sr.consume(k));
        BOOST_TEST_EQ(rem.size(), 4u);

        // the 4-octet remainder is absorbed, not re-framed
        capy::const_buffer const b2{
            rem.data(), rem.size() };
        out = sr.frame(dest, b2, true, ec);
        BOOST_TEST(!ec);
        BOOST_TEST(out.empty());
        BOOST_TEST_EQ(sr.consume(0), rem.size());

        BOOST_TEST(!write_eof(sr, wire));
        BOOST_TEST(sr.is_done());
        BOOST_TEST_EQ(
            wire, std::string(req.buffer()) + body);
    }

    void
    testFrameIdempotent()
    {
        // Two frames without an intervening mutation return the
        // same octets, before and after a partial consume.
        std::string const body(cfg.min_direct, 'x');
        auto req = make_request();
        serializer sr(cfg);
        sr.start(&req);

        capy::const_buffer const b{
            body.data(), body.size() };
        auto const flatten = [&]
        {
            system::error_code ec;
            capy::const_buffer dest[dest_n];
            auto const bufs = sr.frame(dest, b, true, ec);
            BOOST_TEST(!ec);
            std::string s;
            for(auto cb : bufs)
                s.append(
                    static_cast<char const*>(cb.data()),
                    cb.size());
            return s;
        };

        auto const s1 = flatten();
        auto const s2 = flatten();
        BOOST_TEST_EQ(s1, s2);
        BOOST_TEST(!s1.empty());

        BOOST_TEST_EQ(sr.consume(7), 0u); // mid-header
        auto const s3 = flatten();
        BOOST_TEST_EQ(s3, s1.substr(7));

        BOOST_TEST_EQ(sr.consume(s3.size()), body.size());
    }

    void
    testCancelAndResume()
    {
        // An interrupted drive leaves the accounting true to the
        // wire; supplying the unconsumed remainder resumes it,
        // and the serializer can even be moved mid-flight.
        std::string const body(cfg.min_direct, 'x');
        auto req = make_request();
        serializer sr(cfg);
        sr.start(&req);

        std::string_view rem(body);
        std::string wire;
        {
            capy::const_buffer const b{
                rem.data(), rem.size() };
            system::error_code ec;
            capy::const_buffer dest[dest_n];
            auto const bufs = sr.frame(dest, b, true, ec);
            BOOST_TEST(!ec);
            BOOST_TEST(!bufs.empty());

            // take the header and half the chunk, then stop, as
            // a cancelled write would
            auto const k =
                req.buffer().size() + 4 + body.size() / 2;
            std::string flat;
            for(auto cb : bufs)
                flat.append(
                    static_cast<char const*>(cb.data()),
                    cb.size());
            wire.append(flat.substr(0, k));
            rem.remove_prefix(sr.consume(k));
        }
        BOOST_TEST_EQ(rem.size(), body.size() / 2);

        // resume on a moved-to serializer: the wire is resumable
        // from the counters alone
        serializer sr2(std::move(sr));
        BOOST_TEST(!write(sr2, wire, rem));
        BOOST_TEST(!write_eof(sr2, wire));

        std::string expected(req.buffer());
        expected += "10\r\n" + body + "\r\n";
        expected += "0\r\n\r\n";
        BOOST_TEST_EQ(wire, expected);
    }

    void
    testCancelResumeByCommit()
    {
        // The other resume path: after a cancelled flight is
        // consumed up to the wire's true position, the caller
        // may supply the remainder through prepare/commit — an
        // open chunk's owed count is indifferent to which region
        // pays it.
        std::string const body(cfg.min_direct, 'x');
        auto req = make_request();
        serializer sr(cfg);
        sr.start(&req);

        std::string_view rem(body);
        std::string wire;
        {
            capy::const_buffer const b{
                rem.data(), rem.size() };
            system::error_code ec;
            capy::const_buffer dest[dest_n];
            auto const bufs = sr.frame(dest, b, true, ec);
            BOOST_TEST(!ec);

            auto const k =
                req.buffer().size() + 4 + body.size() / 2;
            std::string flat;
            for(auto cb : bufs)
                flat.append(
                    static_cast<char const*>(cb.data()),
                    cb.size());
            wire.append(flat.substr(0, k));
            rem.remove_prefix(sr.consume(k));
        }

        // commit the unconsumed remainder and drain
        capy::mutable_buffer tmp[2];
        capy::buffer_copy(
            sr.prepare(tmp),
            capy::const_buffer(rem.data(), rem.size()));
        sr.commit(rem.size());
        BOOST_TEST(!drain(sr, wire));
        BOOST_TEST(!write_eof(sr, wire));

        std::string expected(req.buffer());
        expected += "10\r\n" + body + "\r\n";
        expected += "0\r\n\r\n";
        BOOST_TEST_EQ(wire, expected);
    }

    void
    testAbandonedChunkErrors()
    {
        // Declaring the end while an open chunk still owes
        // octets that only caller memory can supply is the
        // mismatch error: nothing can be handed out, and the
        // wire is already committed to the chunk.
        std::string const body(cfg.min_direct, 'x');
        auto req = make_request();
        serializer sr(cfg);
        sr.start(&req);

        std::string wire;
        {
            capy::const_buffer const b{
                body.data(), body.size() };
            system::error_code ec;
            capy::const_buffer dest[dest_n];
            auto const bufs = sr.frame(dest, b, true, ec);
            BOOST_TEST(!ec);

            // the header and the chunk prefix, no body octet
            auto const k = req.buffer().size() + 4;
            std::string flat;
            for(auto cb : bufs)
                flat.append(
                    static_cast<char const*>(cb.data()),
                    cb.size());
            wire.append(flat.substr(0, k));
            BOOST_TEST_EQ(sr.consume(k), 0u);
        }

        // a drain pass is harmless and moves nothing
        std::string before = wire;
        BOOST_TEST(!drain(sr, wire));
        BOOST_TEST_EQ(wire, before);

        // ending the message without the owed octets fails, and
        // keeps failing on repeat; the open chunk carries no
        // declared size of the caller's, so it is the contract
        // error, not the size mismatch
        BOOST_TEST_EQ(
            write_eof(sr, wire),
            std::make_error_code(
                std::errc::invalid_argument));
        BOOST_TEST_EQ(
            write_eof(sr, wire),
            std::make_error_code(
                std::errc::invalid_argument));

        // supplying the remainder again still resumes
        BOOST_TEST(!write(sr, wire, body));
        BOOST_TEST(!write_eof(sr, wire));
        BOOST_TEST(sr.is_done());

        std::string expected(req.buffer());
        expected += "10\r\n" + body + "\r\n";
        expected += "0\r\n\r\n";
        BOOST_TEST_EQ(wire, expected);
    }

    void
    testContentLengthCancelResume()
    {
        // A content-length flight interrupted mid-body resumes
        // by supplying the remainder again; consumption
        // reports are the caller's cursor.
        std::string const body(cfg.min_direct, 'x');
        auto req = make_request(body.size());
        serializer sr(cfg);
        sr.start(&req);

        std::string_view rem(body);
        std::string wire;
        {
            capy::const_buffer const b{
                rem.data(), rem.size() };
            system::error_code ec;
            capy::const_buffer dest[dest_n];
            auto const bufs = sr.frame(dest, b, true, ec);
            BOOST_TEST(!ec);

            // header plus one body octet
            auto const k = req.buffer().size() + 1;
            std::string flat;
            for(auto cb : bufs)
                flat.append(
                    static_cast<char const*>(cb.data()),
                    cb.size());
            wire.append(flat.substr(0, k));
            rem.remove_prefix(sr.consume(k));
        }
        BOOST_TEST_EQ(rem.size(), body.size() - 1);

        BOOST_TEST(!write(sr, wire, rem));
        BOOST_TEST(!write_eof(sr, wire));
        BOOST_TEST_EQ(
            wire, std::string(req.buffer()) + body);
    }

    void
    testManyDescriptors()
    {
        // No registration cap: a span of many descriptors is
        // framed in one call when dest is large enough.
        std::string const piece(4, 'x');
        capy::const_buffer bufs[24];
        for(auto& b : bufs)
            b = capy::make_buffer(piece);
        std::string const body(
            std::size(bufs) * piece.size(), 'x');

        auto req = make_request(body.size());
        serializer sr(cfg);
        sr.start(&req);

        std::string wire;
        system::error_code ec;
        capy::const_buffer dest[32];
        auto const out = sr.frame(dest, bufs, false, ec);
        BOOST_TEST(!ec);
        BOOST_TEST_EQ(
            out.size(), std::size(bufs) + 1); // + header

        std::size_t n = 0;
        for(auto cb : out)
        {
            wire.append(
                static_cast<char const*>(cb.data()), cb.size());
            n += cb.size();
        }
        BOOST_TEST_EQ(sr.consume(n), body.size());
        BOOST_TEST(sr.is_done());
        BOOST_TEST_EQ(wire, std::string(req.buffer()) + body);
    }

    void
    testOneSlotDest()
    {
        // A one-slot dest can always make progress: each debt
        // item is representable alone, and the unplaced
        // remainder is re-materialized next call.
        std::string const body(cfg.min_direct, 'x');
        auto req = make_request();
        serializer sr(cfg);
        sr.start(&req);

        fields trailer;
        trailer.set("x-a", "1");
        sr.set_trailer(&trailer);

        std::string_view rem(body);
        std::string wire;
        bool more = true;
        for(;;)
        {
            capy::const_buffer const b{
                rem.data(), rem.size() };
            system::error_code ec;
            capy::const_buffer dest[1];
            auto const bufs = sr.frame(dest, b, more, ec);
            more = false;
            BOOST_TEST(!ec);
            if(bufs.empty())
            {
                rem.remove_prefix(sr.consume(0));
                if(sr.is_done())
                    break;
                continue;
            }
            std::string flat;
            for(auto cb : bufs)
                flat.append(
                    static_cast<char const*>(cb.data()),
                    cb.size());
            wire.append(flat);
            rem.remove_prefix(sr.consume(flat.size()));
        }

        std::string expected(req.buffer());
        expected += "10\r\n" + body + "\r\n";
        expected += "0\r\n";
        expected += std::string(trailer.buffer());
        BOOST_TEST_EQ(wire, expected);

        // With the header already on the wire, the final input
        // both ends the body and opens its chunk: the epilogue
        // waits until the slot-starved body has been placed.
        {
            auto req2 = make_request();
            serializer sr2(cfg);
            sr2.start(&req2);

            std::string wire2;
            BOOST_TEST(!drain(sr2, wire2));
            BOOST_TEST_EQ(wire2, std::string(req2.buffer()));

            std::string_view rem2(body);
            for(;;)
            {
                capy::const_buffer const b{
                    rem2.data(), rem2.size() };
                system::error_code ec;
                capy::const_buffer dest[1];
                auto const bufs = sr2.frame(dest, b, false, ec);
                BOOST_TEST(!ec);
                if(bufs.empty())
                {
                    rem2.remove_prefix(sr2.consume(0));
                    if(sr2.is_done())
                        break;
                    continue;
                }
                std::size_t n = 0;
                for(auto cb : bufs)
                {
                    wire2.append(
                        static_cast<char const*>(cb.data()),
                        cb.size());
                    n += cb.size();
                }
                rem2.remove_prefix(sr2.consume(n));
            }

            std::string expected2(req2.buffer());
            expected2 += "10\r\n" + body + "\r\n0\r\n\r\n";
            BOOST_TEST_EQ(wire2, expected2);
        }
    }

    void
    testStagedBeyondOpenChunk()
    {
        // Octets staged after a chunk was opened are no part of
        // its debt: they wait behind it, and the call that ends
        // the body — which sees them buffered with nothing owed
        // — gives them a chunk of their own before the
        // last-chunk. 40 == 0x28, 10 == 0xa.
        std::string const b1(40, 'x');
        std::string const b2(10, 'y');
        auto req = make_request();
        serializer sr(cfg);
        sr.start(&req);

        capy::mutable_buffer tmp[2];
        capy::buffer_copy(
            sr.prepare(tmp), capy::make_buffer(b1));
        sr.commit(b1.size());
        BOOST_TEST(sr.should_drain());

        // the wire takes the header, the prefix, and ten octets
        std::string wire;
        {
            system::error_code ec;
            capy::const_buffer dest[dest_n];
            auto const out = sr.frame(dest, true, ec);
            BOOST_TEST(!ec);
            BOOST_TEST_EQ(out.size(), 2u);

            std::size_t const n = req.buffer().size() + 4 + 10;
            std::size_t taken = 0;
            for(auto cb : out)
            {
                auto const k = (std::min)(n - taken, cb.size());
                wire.append(
                    static_cast<char const*>(cb.data()), k);
                if((taken += k) == n)
                    break;
            }
            BOOST_TEST_EQ(taken, n);
            BOOST_TEST_EQ(sr.consume(n), 0u);
        }

        // these belong to no chunk yet
        capy::buffer_copy(
            sr.prepare(tmp), capy::make_buffer(b2));
        sr.commit(b2.size());

        // the open chunk is paid off first, then the leftovers
        // are framed and the body ends
        BOOST_TEST(!write_eof(sr, wire));
        BOOST_TEST(sr.is_done());

        std::string expected(req.buffer());
        expected += "28\r\n" + b1;
        expected += "\r\na\r\n" + b2;
        expected += "\r\n0\r\n\r\n";
        BOOST_TEST(req.chunked());
        BOOST_TEST_EQ(wire, expected);
    }

    void
    testChunkedNarrowResumeWindow()
    {
        // The chunk is opened for the whole final input, then
        // resumed in windows narrower than what it still owes:
        // the last-chunk must wait until the debt is paid.
        // 40 == 0x28.
        std::string const body = make_body(40);
        auto req = make_request();
        serializer sr(cfg);
        sr.start(&req);

        // the header first, so the framing stays chunked
        std::string wire;
        BOOST_TEST(!drain(sr, wire));
        BOOST_TEST_EQ(wire, std::string(req.buffer()));

        std::string_view rem(body);

        // the whole body is offered once, so the chunk is opened
        // for all forty octets; the wire takes the prefix and
        // ten of them
        {
            system::error_code ec;
            capy::const_buffer dest[dest_n];
            capy::const_buffer const b{
                rem.data(), rem.size() };
            auto const out = sr.frame(dest, b, false, ec);
            BOOST_TEST(!ec);
            // prefix + body + last-chunk
            BOOST_TEST_EQ(out.size(), 3u);

            std::size_t const n = 4 + 10;
            std::size_t taken = 0;
            for(auto cb : out)
            {
                auto const k = (std::min)(n - taken, cb.size());
                wire.append(
                    static_cast<char const*>(cb.data()), k);
                if((taken += k) == n)
                    break;
            }
            BOOST_TEST_EQ(taken, n);
            rem.remove_prefix(sr.consume(n));
            BOOST_TEST_EQ(rem.size(), 30u);
        }

        // from here on only ten octets are offered per call,
        // fewer than the chunk still owes
        while(!sr.is_done())
        {
            system::error_code ec;
            capy::const_buffer dest[dest_n];
            capy::const_buffer const b{ rem.data(),
                (std::min)(std::size_t(10), rem.size()) };
            auto const out = sr.frame(dest, b, false, ec);
            BOOST_TEST(!ec);
            std::size_t n = 0;
            for(auto cb : out)
            {
                wire.append(
                    static_cast<char const*>(cb.data()),
                    cb.size());
                n += cb.size();
            }
            rem.remove_prefix(sr.consume(n));
        }

        BOOST_TEST(rem.empty());
        std::string expected(req.buffer());
        expected += "28\r\n" + body + "\r\n0\r\n\r\n";
        BOOST_TEST_EQ(wire, expected);
    }

    void
    testEmptyDescriptorsDoNotCount()
    {
        // Empty descriptors are dropped rather than framed, so a
        // padded span still fits in one call.
        std::string const piece(4, 'y');
        capy::const_buffer bufs[32];
        for(std::size_t i = 0; i != std::size(bufs); ++i)
            bufs[i] = i % 2
                ? capy::const_buffer()
                : capy::make_buffer(piece);
        std::string const body(
            std::size(bufs) / 2 * piece.size(), 'y');

        auto req = make_request(body.size());
        serializer sr(cfg);
        sr.start(&req);

        std::string wire;
        system::error_code ec;
        capy::const_buffer dest[32];
        auto const out = sr.frame(dest, bufs, false, ec);
        BOOST_TEST(!ec);

        std::size_t n = 0;
        for(auto cb : out)
        {
            BOOST_TEST(cb.size() != 0);
            wire.append(
                static_cast<char const*>(cb.data()), cb.size());
            n += cb.size();
        }
        BOOST_TEST_EQ(sr.consume(n), body.size());
        BOOST_TEST(sr.is_done());
        BOOST_TEST_EQ(wire, std::string(req.buffer()) + body);
    }

    void
    testConsumption()
    {
        // Consumption lands at two moments — octets absorbed
        // into the staging buffer are consumed by the frame that
        // absorbs them, and octets framed over caller memory are
        // consumed when the wire takes them — but both are
        // reported by the consume answering that frame.
        auto req = make_request();
        serializer sr(cfg);
        sr.start(&req);

        // absorbed, no debt: nothing to write, and the input is
        // spent all the same
        std::string wire;
        std::string_view sv("abc");
        BOOST_TEST(!drive(sr, wire, sv, true));
        BOOST_TEST(sv.empty());
        BOOST_TEST(wire.empty());

        // raise drain pressure, then absorb: the same call
        // returns the flush and reports the absorption
        capy::mutable_buffer tmp[2];
        auto const stage = make_body(40);
        capy::buffer_copy(
            sr.prepare(tmp), capy::make_buffer(stage));
        sr.commit(stage.size());
        BOOST_TEST(sr.should_drain());

        capy::const_buffer const b{ "def", 3 };
        system::error_code ec;
        capy::const_buffer dest[dest_n];
        auto const bufs = sr.frame(dest, b, true, ec);
        BOOST_TEST(!ec);
        BOOST_TEST(!bufs.empty());

        std::size_t n = 0;
        for(auto cb : bufs)
        {
            wire.append(
                static_cast<char const*>(cb.data()), cb.size());
            n += cb.size();
        }
        // framing and staged octets report nothing; the
        // absorbed input does
        BOOST_TEST_EQ(sr.consume(n), 3u);

        BOOST_TEST(!write_eof(sr, wire));
        BOOST_TEST(sr.is_done());

        // 46 == 0x2e
        std::string expected(req.buffer());
        expected += "2e\r\nabc" + stage + "def\r\n";
        expected += "0\r\n\r\n";
        BOOST_TEST_EQ(wire, expected);
    }

    void
    testFrameWithoutBuffers()
    {
        // The overload that supplies nothing flushes the header
        // on its own, and ends the body from the staged octets.
        auto req = make_request();
        serializer sr(cfg);
        sr.start(&req);

        capy::mutable_buffer tmp[2];
        capy::buffer_copy(
            sr.prepare(tmp), capy::const_buffer("hello", 5));
        sr.commit(5);
        BOOST_TEST(!sr.should_drain());

        std::string wire;
        BOOST_TEST(!drain_bufferless(sr, wire));
        BOOST_TEST(sr.is_header_done());
        BOOST_TEST_EQ(wire, std::string(req.buffer()));

        BOOST_TEST(!drain_bufferless(sr, wire, false));
        BOOST_TEST(sr.is_done());

        // the header was already out, so the staged run goes
        // out as a chunk rather than converting
        BOOST_TEST(req.chunked());
        BOOST_TEST_EQ(
            wire, std::string(req.buffer()) +
                "5\r\nhello\r\n0\r\n\r\n");

        // the same overload on a declared body still owing every
        // octet: the header goes out and the debt waits for a
        // supplying call
        {
            auto req2 = make_request(5);
            serializer sr2(cfg);
            sr2.start(&req2);

            std::string wire2;
            BOOST_TEST(!drain_bufferless(sr2, wire2));
            BOOST_TEST(sr2.is_header_done());
            BOOST_TEST(!sr2.is_done());
            BOOST_TEST_EQ(wire2, std::string(req2.buffer()));

            BOOST_TEST(!write_eof(sr2, wire2, "hello"));
            BOOST_TEST(sr2.is_done());
            BOOST_TEST_EQ(
                wire2, std::string(req2.buffer()) + "hello");
        }
    }

    void
    testChunkedOctetsAfterEof()
    {
        // Once the body has ended there is no chunk left to
        // frame octets with, and the last-chunk is already on
        // the wire: supplying more violates the call contract.
        auto req = make_request();
        serializer sr(cfg);
        sr.start(&req);

        std::string wire;
        BOOST_TEST(!drain(sr, wire));
        BOOST_TEST(!write_eof(sr, wire));
        BOOST_TEST(sr.is_done());
        BOOST_TEST_EQ(
            wire, std::string(req.buffer()) + "0\r\n\r\n");

        // a drain pass over a finished message moves nothing
        BOOST_TEST(!drain(sr, wire));
        BOOST_TEST_EQ(
            wire, std::string(req.buffer()) + "0\r\n\r\n");

        std::string_view rem("hello");
        BOOST_TEST_EQ(
            drive(sr, wire, rem, true),
            std::make_error_code(
                std::errc::invalid_argument));
        BOOST_TEST_EQ(rem.size(), 5u);
        BOOST_TEST_EQ(
            wire, std::string(req.buffer()) + "0\r\n\r\n");
    }

    void
    testStagedRemainderDrain()
    {
        // A staged run the wire took only half of stays owed
        // even though the window it left raises no drain
        // pressure; a drain pass flushes the remainder, ahead of
        // the caller's octets, which are supplied again.
        std::string const staged = make_body(16);
        std::string const body = make_body(16);
        auto req = make_request(staged.size() + body.size());
        serializer sr(cfg);
        sr.start(&req);

        capy::mutable_buffer tmp[2];
        capy::buffer_copy(
            sr.prepare(tmp), capy::make_buffer(staged));
        sr.commit(staged.size());
        BOOST_TEST(!sr.should_drain());

        std::string wire;
        std::string_view rem(body);
        {
            system::error_code ec;
            capy::const_buffer dest[dest_n];
            capy::const_buffer const b{
                rem.data(), rem.size() };
            auto const out = sr.frame(dest, b, true, ec);
            BOOST_TEST(!ec);
            // header + staged run + caller's octets
            BOOST_TEST_EQ(out.size(), 3u);

            auto const n = req.buffer().size() + 8;
            std::size_t taken = 0;
            for(auto cb : out)
            {
                auto const k = (std::min)(n - taken, cb.size());
                wire.append(
                    static_cast<char const*>(cb.data()), k);
                if((taken += k) == n)
                    break;
            }
            BOOST_TEST_EQ(taken, n);
            rem.remove_prefix(sr.consume(n));
            BOOST_TEST_EQ(rem.size(), body.size());
        }

        BOOST_TEST(!sr.should_drain());
        BOOST_TEST(!drain(sr, wire));
        BOOST_TEST_EQ(
            wire, std::string(req.buffer()) + staged);

        BOOST_TEST(!write_eof(sr, wire, rem));
        BOOST_TEST(sr.is_done());
        BOOST_TEST_EQ(
            wire, std::string(req.buffer()) + staged + body);
    }

    void
    testToEof()
    {
        // close-delimited response: no prefix, no epilogue, no
        // size check; the final input completes the message and
        // closing the connection is the caller's act
        std::string const body(cfg.min_direct, 'x');
        {
            response_head res;
            serializer sr(cfg);
            sr.start(&res);

            std::string wire;
            BOOST_TEST(!write(sr, wire, body));
            BOOST_TEST(!write_eof(sr, wire, "hello"));
            BOOST_TEST(sr.is_done());

            BOOST_TEST(!res.content_length().has_value());
            BOOST_TEST_EQ(
                wire,
                std::string(res.buffer()) + body + "hello");
        }

        // fully staged before the header goes out: late framing
        // converts to Content-Length, saving the connection
        {
            response_head res;
            serializer sr(cfg);
            sr.start(&res);

            std::string wire;
            BOOST_TEST(!write_eof(sr, wire, "hello"));

            BOOST_TEST_EQ(res.content_length().value(), 5u);
            BOOST_TEST_EQ(
                wire, std::string(res.buffer()) + "hello");
        }

        // the header on the wire pins close-delimited framing;
        // ending the body with nothing left to hand out
        // completes the message all the same
        {
            response_head res;
            serializer sr(cfg);
            sr.start(&res);

            std::string wire;
            BOOST_TEST(!drain(sr, wire));
            BOOST_TEST(sr.is_header_done());
            BOOST_TEST_EQ(wire, std::string(res.buffer()));

            BOOST_TEST(!write_eof(sr, wire));
            BOOST_TEST(sr.is_done());
            BOOST_TEST(!res.content_length().has_value());
            BOOST_TEST_EQ(wire, std::string(res.buffer()));
        }

        // a request without framing headers has no body by
        // definition; body bytes are rejected when supplied
        {
            request_head req;
            serializer sr(cfg);
            sr.start(&req);

            std::string wire;
            BOOST_TEST_EQ(
                write(sr, wire, body),
                error::body_size_mismatch);
            BOOST_TEST(wire.empty());
        }
    }

    void
    testToEofPartialWrites()
    {
        // close-delimited framing across partial writes: every
        // split still hands out the whole body, and is_done()
        // never fires early
        std::string const body = make_body(20);
        for(std::size_t step : { 1u, 3u, 7u })
        {
            response_head res;
            serializer sr(cfg);
            sr.start(&res);

            std::string wire;
            BOOST_TEST(!write(sr, wire, "abc", step));
            BOOST_TEST(!write(sr, wire, body, step));
            BOOST_TEST(!sr.is_done());
            BOOST_TEST(!write_eof(sr, wire, "hello", step));
            BOOST_TEST(sr.is_done());
            BOOST_TEST(!res.content_length().has_value());
            BOOST_TEST_EQ(
                wire,
                std::string(res.buffer()) +
                    "abc" + body + "hello");
        }
    }

    void
    testToEofBodyContract()
    {
        // close-delimited framing declares no size; the first
        // more=false call fixes the body instead, and deviating
        // from it afterwards is the call-contract error, not
        // the size mismatch
        std::string const body(cfg.min_direct, 'x');

        // octets after the end: rejected, nothing framed
        {
            response_head res;
            serializer sr(cfg);
            sr.start(&res);

            std::string wire;
            BOOST_TEST(!write(sr, wire, body));
            BOOST_TEST(!write_eof(sr, wire));
            BOOST_TEST(sr.is_done());

            std::string_view rem("hello");
            BOOST_TEST_EQ(
                drive(sr, wire, rem, true),
                std::make_error_code(
                    std::errc::invalid_argument));
            BOOST_TEST_EQ(rem.size(), 5u);
            BOOST_TEST(sr.is_done());
            BOOST_TEST_EQ(
                wire, std::string(res.buffer()) + body);
        }

        // a shorted re-supply after eof: the leftover debt is
        // an error rather than a truncated completion, and the
        // corrected remainder still resumes
        {
            response_head res;
            serializer sr(cfg);
            sr.start(&res);

            std::string wire;
            BOOST_TEST(!drain(sr, wire));

            std::string const b = make_body(10);
            {
                // declare eof; the wire takes nothing
                system::error_code ec;
                capy::const_buffer dest[dest_n];
                capy::const_buffer const cb{
                    b.data(), b.size() };
                BOOST_TEST(
                    !sr.frame(dest, cb, false, ec).empty());
                BOOST_TEST(!ec);
                BOOST_TEST_EQ(sr.consume(0), 0u);
            }

            // only a prefix of the remainder comes back
            std::string_view rem(b.data(), 4);
            BOOST_TEST_EQ(
                drive(sr, wire, rem, false),
                std::make_error_code(
                    std::errc::invalid_argument));
            BOOST_TEST(rem.empty());
            BOOST_TEST(!sr.is_done());

            // supplying the rest recovers
            BOOST_TEST(!write_eof(
                sr, wire, std::string_view(b.data() + 4, 6)));
            BOOST_TEST(sr.is_done());
            BOOST_TEST_EQ(
                wire, std::string(res.buffer()) + b);
        }
    }

    void
    testToEofDestExhaustion()
    {
        // a fully conforming caller: short header write, then
        // the whole body offered with a single descriptor slot,
        // which the header remainder takes up. Settling here
        // would truncate a body whose framing gives the peer no
        // way to notice.
        response_head res;
        serializer sr(cfg);
        sr.start(&res);

        std::string wire;
        system::error_code ec;

        // the wire takes half the header
        {
            capy::const_buffer dest[dest_n];
            auto const out = sr.frame(dest, true, ec);
            BOOST_TEST(!ec);
            auto const half = res.buffer().size() / 2;
            std::size_t n = 0;
            for(auto cb : out)
            {
                auto const k = (std::min)(half - n, cb.size());
                wire.append(
                    static_cast<char const*>(cb.data()), k);
                if((n += k) == half)
                    break;
            }
            BOOST_TEST_EQ(sr.consume(half), 0u);
        }

        // one slot: the header remainder claims it, no body
        // octet is placed, and the message must not settle
        std::string_view body("hello");
        {
            capy::const_buffer one[1];
            capy::const_buffer const cb{
                body.data(), body.size() };
            auto const out = sr.frame({ one, 1 }, cb, false, ec);
            BOOST_TEST(!ec);
            BOOST_TEST_EQ(out.size(), 1u);
            std::string flat;
            for(auto b : out)
                flat.append(
                    static_cast<char const*>(b.data()),
                    b.size());
            wire.append(flat);
            body.remove_prefix(sr.consume(flat.size()));
        }
        BOOST_TEST_EQ(body.size(), 5u);
        BOOST_TEST(!sr.is_done());
        BOOST_TEST_EQ(wire, std::string(res.buffer()));

        // the conforming loop continues and completes
        BOOST_TEST(!write_eof(sr, wire, body));
        BOOST_TEST(sr.is_done());
        BOOST_TEST_EQ(
            wire, std::string(res.buffer()) + "hello");
    }

    void
    testEmptyDest()
    {
        // A zero-slot dest places nothing, which is not a
        // statement about the body: the call must neither fail
        // the message nor settle it, and the loop must complete
        // once a slot is offered.

        // content-length, whole body declared at once
        {
            auto req = make_request(5);
            serializer sr(cfg);
            sr.start(&req);

            std::string_view body("hello");
            {
                system::error_code ec;
                capy::const_buffer const cb{
                    body.data(), body.size() };
                BOOST_TEST(
                    sr.frame({}, cb, false, ec).empty());
                BOOST_TEST(!ec);
                // nothing was placed, so nothing is released
                body.remove_prefix(sr.consume(0));
            }
            BOOST_TEST_EQ(body.size(), 5u);
            BOOST_TEST(!sr.is_done());

            std::string wire;
            BOOST_TEST(!write_eof(sr, wire, body));
            BOOST_TEST(sr.is_done());
            BOOST_TEST_EQ(
                wire, std::string(req.buffer()) + "hello");
        }

        // chunked, with a trailer and an open chunk's debt
        {
            auto req = make_request();
            fields trailer;
            trailer.set("x", "1");
            serializer sr(cfg);
            sr.start(&req);
            sr.set_trailer(&trailer);

            std::string wire;
            std::string_view body("hello");
            // small enough to stage: no chunk is opened yet
            BOOST_TEST(!write(sr, wire, body.substr(0, 2)));
            // the empty-dest call opens the chunk covering the
            // staged and the supplied octets
            {
                system::error_code ec;
                capy::const_buffer const cb{
                    body.data() + 2, 3 };
                BOOST_TEST(
                    sr.frame({}, cb, false, ec).empty());
                BOOST_TEST(!ec);
                BOOST_TEST_EQ(sr.consume(0), 0u);
            }
            BOOST_TEST(!sr.is_done());
            BOOST_TEST(!write_eof(sr, wire, body.substr(2)));
            BOOST_TEST(sr.is_done());
            BOOST_TEST_EQ(
                wire,
                std::string(req.buffer()) +
                    "5\r\nhello\r\n0\r\nx: 1\r\n\r\n");
        }

        // the bufferless overload, declaring an empty body
        {
            response_head res;
            serializer sr(cfg);
            sr.start(&res);

            {
                system::error_code ec;
                BOOST_TEST(sr.frame({}, false, ec).empty());
                BOOST_TEST(!ec);
                BOOST_TEST_EQ(sr.consume(0), 0u);
            }
            BOOST_TEST(!sr.is_done());

            std::string wire;
            BOOST_TEST(!drain_bufferless(sr, wire, false));
            BOOST_TEST(sr.is_done());
            BOOST_TEST_EQ(wire, std::string(res.buffer()));
        }

        // a genuinely short body is still diagnosed
        {
            auto req = make_request(5);
            serializer sr(cfg);
            sr.start(&req);

            std::string wire;
            std::string_view body("hel");
            BOOST_TEST_EQ(
                drive(sr, wire, body, false),
                error::body_size_mismatch);
        }
    }

    void
    testChunkedOctetsAfterEofDeferred()
    {
        // while an open chunk's debt stands, a re-supply of the
        // owed octets is indistinguishable from new data, so the
        // post-eof check waits for the debt to clear and rejects
        // only the surplus, one call later
        auto req = make_request();
        fields trailer;
        trailer.set("x", "1");
        serializer sr(cfg);
        sr.start(&req);
        sr.set_trailer(&trailer);

        std::string wire;
        // end the body; the wire takes nothing, so the whole
        // chunk stands as debt
        std::string_view body("hello");
        {
            system::error_code ec;
            capy::const_buffer dest[dest_n];
            capy::const_buffer const cb{
                body.data(), body.size() };
            BOOST_TEST(!sr.frame(dest, cb, false, ec).empty());
            BOOST_TEST(!ec);
            BOOST_TEST_EQ(sr.consume(0), 0u);
        }
        // a longer re-supply while the debt stands: the owed
        // prefix is accepted, the surplus is not — and no error
        // yet
        {
            system::error_code ec;
            capy::const_buffer dest[dest_n];
            std::string_view rem("helloworld");
            capy::const_buffer const cb{
                rem.data(), rem.size() };
            auto const out = sr.frame(dest, cb, false, ec);
            BOOST_TEST(!ec);
            std::string flat;
            for(auto b : out)
                flat.append(
                    static_cast<char const*>(b.data()),
                    b.size());
            wire.append(flat);
            BOOST_TEST_EQ(sr.consume(flat.size()), 5u);
        }
        // with the debt cleared, the surplus is rejected
        {
            std::string_view rem("world");
            BOOST_TEST_EQ(
                drive(sr, wire, rem, false),
                std::make_error_code(
                    std::errc::invalid_argument));
            BOOST_TEST_EQ(rem.size(), 5u);
        }
        // dropping the surplus recovers
        BOOST_TEST(!write_eof(sr, wire));
        BOOST_TEST(sr.is_done());
        BOOST_TEST_EQ(
            wire,
            std::string(req.buffer()) +
                "5\r\nhello\r\n0\r\nx: 1\r\n\r\n");
    }

    void
    testTrailer()
    {
        std::string const body(cfg.min_direct, 'x');

        // basic: the trailer section replaces the bare CRLF
        // after the last chunk
        {
            auto req = make_request();
            serializer sr(cfg);
            sr.start(&req);

            fields trailer;
            sr.set_trailer(&trailer);

            std::string wire;
            BOOST_TEST(!write(sr, wire, body));

            // fill-late: values computed from the body land
            // just before the final input
            trailer.set("x-checksum", "abc123");

            BOOST_TEST(!write_eof(sr, wire));
            BOOST_TEST(sr.is_done());

            std::string expected(req.buffer());
            expected += "10\r\n" + body + "\r\n";
            expected += "0\r\n";
            expected += "x-checksum: abc123\r\n\r\n";
            BOOST_TEST_EQ(wire, expected);
        }

        // a set trailer suppresses the small-body conversion
        // to Content-Length
        {
            auto req = make_request();
            serializer sr(cfg);
            sr.start(&req);

            fields trailer;
            trailer.set("x-a", "1");
            trailer.set("x-b", "2");
            sr.set_trailer(&trailer);

            std::string wire;
            BOOST_TEST(!write_eof(sr, wire, "hello"));

            BOOST_TEST(req.chunked());
            std::string expected(req.buffer());
            expected += "5\r\nhello\r\n";
            expected += "0\r\n";
            expected += std::string(trailer.buffer());
            BOOST_TEST_EQ(wire, expected);
        }

        // an empty container and no trailer are byte-identical
        {
            fields const empty;
            BOOST_TEST_EQ(
                std::string(empty.buffer()), "\r\n");

            auto req1 = make_request();
            auto req2 = make_request();
            serializer sr1(cfg);
            serializer sr2(cfg);
            sr1.start(&req1);
            sr2.start(&req2);
            sr2.set_trailer(&empty);

            std::string w1, w2;
            BOOST_TEST(!write(sr1, w1, body));
            BOOST_TEST(!write(sr2, w2, body));
            BOOST_TEST(!write_eof(sr1, w1));
            BOOST_TEST(!write_eof(sr2, w2));
            BOOST_TEST_EQ(w1, w2);
        }

        // set_trailer(nullptr) clears
        {
            auto req = make_request(5);
            serializer sr(cfg);
            sr.start(&req);

            fields trailer;
            sr.set_trailer(&trailer);
            sr.set_trailer(nullptr);

            std::string wire;
            BOOST_TEST(!write_eof(sr, wire, "hello"));
            BOOST_TEST(sr.is_done());
        }
    }

    void
    testTrailerIgnoredWhenNotChunked()
    {
        fields trailer;
        trailer.set("x-a", "1");

        // explicit Content-Length: the trailer is
        // silently discarded
        {
            auto req = make_request(5);
            serializer sr(cfg);
            sr.start(&req);
            sr.set_trailer(&trailer);

            std::string wire;
            BOOST_TEST(!write_eof(sr, wire, "hello"));
            BOOST_TEST(sr.is_done());
            BOOST_TEST_EQ(
                wire, std::string(req.buffer()) + "hello");
        }

        // close-delimited framing cannot carry
        // trailers either
        {
            response_head res;
            serializer sr(cfg);
            sr.start(&res);
            sr.set_trailer(&trailer);

            std::string wire;
            BOOST_TEST(!write_eof(sr, wire, "hello"));
            BOOST_TEST(sr.is_done());
            BOOST_TEST_EQ(
                wire, std::string(res.buffer()) + "hello");
        }

        // head mode suppresses the body and its framing
        {
            auto req = make_request();
            serializer sr(cfg);
            sr.start(&req, nullptr, true);
            sr.set_trailer(&trailer);

            std::string wire;
            BOOST_TEST(!write_eof(sr, wire));
            BOOST_TEST(sr.is_done());
            BOOST_TEST_EQ(wire, std::string(req.buffer()));
        }
    }

    void
    testTrailerWithEncoder()
    {
        // encoder footer and HTTP trailer section compose: the
        // footer is payload of the last data chunk, the trailer
        // section follows the last-chunk
        std::string const body = make_body(8);
        auto req = make_request();
        req.set(http::field::content_encoding, "test");
        test_encoder enc("eof!");
        serializer sr(cfg);
        sr.start(&req, &enc);

        fields trailer;
        trailer.set("x-digest", "42");
        sr.set_trailer(&trailer);

        std::string wire;
        BOOST_TEST(!write_eof(sr, wire, body));
        BOOST_TEST(sr.is_done());
        BOOST_TEST(enc.finished);

        // the trailer suppressed the conversion, so the encoded
        // bytes and footer went out chunked; 12 == 0xc
        BOOST_TEST(req.chunked());
        std::string expected(req.buffer());
        expected += "c\r\n" + encoded(body) + "eof!";
        expected += "\r\n0\r\n";
        expected += std::string(trailer.buffer());
        BOOST_TEST_EQ(wire, expected);
    }

    void
    testEncoderSmallBodyDropsEncoder()
    {
        // A body that stays below the encoder threshold skips
        // encoding entirely: the encoder is dropped at eof, the
        // Content-Encoding header is removed, and the identity
        // body is sent with a Content-Length.
        auto req = make_request();
        req.set(http::field::content_encoding, "test");
        test_encoder enc;
        serializer sr(cfg);
        sr.start(&req, &enc);

        std::string wire;
        BOOST_TEST(!write(sr, wire, "hello"));
        BOOST_TEST_EQ(enc.calls, 0u);
        BOOST_TEST(wire.empty());

        BOOST_TEST(!write_eof(sr, wire));
        BOOST_TEST(sr.is_done());

        BOOST_TEST_EQ(enc.calls, 0u);
        BOOST_TEST(!req.chunked());
        BOOST_TEST_EQ(req.content_length().value(), 5u);
        BOOST_TEST(
            wire.find("Content-Encoding") ==
            std::string::npos);
        BOOST_TEST_EQ(
            wire, std::string(req.buffer()) + "hello");
    }

    void
    testEncoderKeptAfterHeaderFlush()
    {
        // Once the header is on the wire its Content-Encoding
        // is a promise: a small body no longer drops the
        // encoder, and the framing stays as declared.
        auto req = make_request();
        req.set(http::field::content_encoding, "test");
        test_encoder enc;
        serializer sr(cfg);
        sr.start(&req, &enc);

        std::string wire;
        BOOST_TEST(!sr.is_header_done());
        BOOST_TEST(!drain(sr, wire));
        BOOST_TEST_EQ(wire, std::string(req.buffer()));
        BOOST_TEST(sr.is_header_done());

        BOOST_TEST(!write_eof(sr, wire, "hello"));
        BOOST_TEST(sr.is_done());
        BOOST_TEST(enc.finished);
        BOOST_TEST(req.chunked());
        BOOST_TEST_EQ(
            wire, std::string(req.buffer()) +
                "5\r\nifmmp\r\n0\r\n\r\n");
    }

    void
    testEncoderEmptyBody()
    {
        auto req = make_request();
        req.set(http::field::content_encoding, "test");
        test_encoder enc;
        serializer sr(cfg);
        sr.start(&req, &enc);

        std::string wire;
        BOOST_TEST(!write_eof(sr, wire));
        BOOST_TEST(sr.is_done());

        // an empty body is below any threshold: the encoder is
        // dropped and the request converts to Content-Length: 0
        BOOST_TEST_EQ(enc.calls, 0u);
        BOOST_TEST(!req.chunked());
        BOOST_TEST(
            wire.find("Content-Length: 0\r\n") !=
            std::string::npos);
        BOOST_TEST(
            wire.find("Content-Encoding") ==
            std::string::npos);
        BOOST_TEST_EQ(wire, std::string(req.buffer()));
    }

    void
    testTrailerWithDroppedEncoder()
    {
        // A trailer suppresses the conversion to Content-Length,
        // so a dropped encoder leaves the message chunked with
        // its octets still staged in the encoder's region: the
        // chunk prefix is written backwards below them, into the
        // output buffer the encoder never touched.
        auto req = make_request();
        req.set(http::field::content_encoding, "test");
        test_encoder enc;
        serializer sr(cfg);
        sr.start(&req, &enc);

        fields trailer;
        trailer.set("x-digest", "42");
        sr.set_trailer(&trailer);

        capy::mutable_buffer tmp[2];
        auto const n = capy::buffer_copy(
            sr.prepare(tmp), capy::const_buffer("hello", 5));
        BOOST_TEST_EQ(n, 5u);
        sr.commit(n);

        std::string wire;
        BOOST_TEST(!write_eof(sr, wire));
        BOOST_TEST(sr.is_done());

        BOOST_TEST_EQ(enc.calls, 0u);
        BOOST_TEST(req.chunked());
        BOOST_TEST(
            wire.find("Content-Encoding") ==
            std::string::npos);
        BOOST_TEST_EQ(
            wire,
            std::string(req.buffer()) + "5\r\nhello\r\n0\r\n" +
                std::string(trailer.buffer()));
    }

    void
    testEncoderPrepareCommitEof()
    {
        // With an encoder, prepare() exposes the encoder's
        // staging buffer rather than the output buffer.
        auto req = make_request();
        req.set(http::field::content_encoding, "test");
        test_encoder enc;
        serializer sr(cfg);
        sr.start(&req, &enc);

        capy::mutable_buffer tmp[2];
        auto const dest = sr.prepare(tmp);
        BOOST_TEST_EQ(
            capy::buffer_size(dest), cfg.enc_buffer);

        auto const n = capy::buffer_copy(
            dest, capy::const_buffer("hello", 5));
        BOOST_TEST_EQ(n, 5u);
        sr.commit(n);

        // below the threshold at eof: the encoder is dropped
        // and the staged bytes are sent as-is
        std::string wire;
        BOOST_TEST(!write_eof(sr, wire));
        BOOST_TEST(sr.is_done());

        BOOST_TEST_EQ(enc.calls, 0u);
        BOOST_TEST(!req.chunked());
        BOOST_TEST_EQ(req.content_length().value(), 5u);
        BOOST_TEST_EQ(
            wire, std::string(req.buffer()) + "hello");
    }

    void
    testEncoderThreshold()
    {
        // exactly at the threshold: the encoder is kept
        {
            std::string const body = make_body(8);
            auto req = make_request();
            req.set(http::field::content_encoding, "test");
            test_encoder enc;
            serializer sr(cfg);
            sr.start(&req, &enc);

            std::string wire;
            BOOST_TEST(!write_eof(sr, wire, body));
            BOOST_TEST(sr.is_done());

            // the whole encoded output was buffered before the
            // header went out, so chunked is replaced with the
            // encoded length while Content-Encoding is kept
            BOOST_TEST(enc.finished);
            BOOST_TEST(!req.chunked());
            BOOST_TEST_EQ(req.content_length().value(), 8u);
            BOOST_TEST(
                wire.find("Content-Encoding: test\r\n") !=
                std::string::npos);
            BOOST_TEST_EQ(
                wire,
                std::string(req.buffer()) + encoded(body));
        }

        // one byte below the threshold: the encoder is dropped
        {
            std::string const body = make_body(7);
            auto req = make_request();
            req.set(http::field::content_encoding, "test");
            test_encoder enc;
            serializer sr(cfg);
            sr.start(&req, &enc);

            std::string wire;
            BOOST_TEST(!write_eof(sr, wire, body));

            BOOST_TEST_EQ(enc.calls, 0u);
            BOOST_TEST_EQ(req.content_length().value(), 7u);
            BOOST_TEST(
                wire.find("Content-Encoding") ==
                std::string::npos);
            BOOST_TEST_EQ(
                wire, std::string(req.buffer()) + body);
        }
    }

    void
    testEncoderStagedAndTail()
    {
        // Staged bytes and the caller's final input together
        // reach the threshold at eof, so the encoder is kept; it
        // consumes the staged bytes first, then the input, whose
        // intake is reported through consume's return.
        auto req = make_request();
        req.set(http::field::content_encoding, "test");
        test_encoder enc;
        serializer sr(cfg);
        sr.start(&req, &enc);

        std::string wire;
        BOOST_TEST(!write(sr, wire, "abc"));
        BOOST_TEST_EQ(enc.calls, 0u);

        BOOST_TEST(!write_eof(sr, wire, "defgh"));
        BOOST_TEST(sr.is_done());

        BOOST_TEST(enc.finished);
        BOOST_TEST_EQ(req.content_length().value(), 8u);
        BOOST_TEST_EQ(
            wire,
            std::string(req.buffer()) + encoded("abcdefgh"));
    }

    void
    testEncoderLargeBodyChunked()
    {
        // A body larger than the output buffer forces the
        // header out early and streams encoded chunks; once the
        // encoder has started, even small writes are encoded
        // rather than coalesced. Chunk payloads hold encoded
        // bytes; 64 == 0x40.
        std::string const body = make_body(200);
        auto req = make_request();
        req.set(http::field::content_encoding, "test");
        test_encoder enc;
        serializer sr(cfg);
        sr.start(&req, &enc);

        std::string wire;
        BOOST_TEST(!write(sr, wire, body));
        BOOST_TEST(!sr.is_done());
        BOOST_TEST(!write_eof(sr, wire));
        BOOST_TEST(sr.is_done());

        auto const enc_body = encoded(body);
        std::string expected(req.buffer());
        expected += "40\r\n" + enc_body.substr(0, 64);
        expected += "\r\n40\r\n" + enc_body.substr(64, 64);
        expected += "\r\n40\r\n" + enc_body.substr(128, 64);
        expected += "\r\n8\r\n" + enc_body.substr(192, 8);
        expected += "\r\n0\r\n\r\n";
        BOOST_TEST(enc.finished);
        BOOST_TEST(req.chunked());
        BOOST_TEST(
            wire.find("Content-Encoding: test\r\n") !=
            std::string::npos);
        BOOST_TEST_EQ(wire, expected);
    }

    void
    testEncoderLargeBodyChunkedEof()
    {
        // the same oversized body arrives whole on the
        // declaring call: the encoder leaves a tail undigested
        // each time the output buffer fills, and the
        // re-supplied remainder must not trip the
        // octets-after-eof check
        std::string const body = make_body(200);
        auto req = make_request();
        req.set(http::field::content_encoding, "test");
        test_encoder enc;
        serializer sr(cfg);
        sr.start(&req, &enc);

        std::string wire;
        BOOST_TEST(!write_eof(sr, wire, body));
        BOOST_TEST(sr.is_done());
        BOOST_TEST(enc.finished);

        auto const enc_body = encoded(body);
        std::string expected(req.buffer());
        expected += "40\r\n" + enc_body.substr(0, 64);
        expected += "\r\n40\r\n" + enc_body.substr(64, 64);
        expected += "\r\n40\r\n" + enc_body.substr(128, 64);
        expected += "\r\n8\r\n" + enc_body.substr(192, 8);
        expected += "\r\n0\r\n\r\n";
        BOOST_TEST_EQ(wire, expected);
    }

    void
    testEncoderCommit()
    {
        // commit() stages input for the encoder; encoded bytes
        // stay buffered until the output buffer fills, and the
        // final flush carries the remainder.
        auto req = make_request();
        req.set(http::field::content_encoding, "test");
        test_encoder enc;
        serializer sr(cfg);
        sr.start(&req, &enc);

        std::string wire;
        capy::mutable_buffer tmp[2];

        // 4 commits of 20 raw bytes; the encoder's output
        // crosses stage_buffer on the last one
        std::string fed;
        for(int i = 0; i != 4; ++i)
        {
            auto const piece = make_body(20);
            capy::buffer_copy(
                sr.prepare(tmp), capy::make_buffer(piece));
            sr.commit(piece.size());
            fed += piece;
            BOOST_TEST(!drain(sr, wire));
        }
        BOOST_TEST(enc.calls != 0);

        // only the first full output unit went out; 64 == 0x40
        auto const enc_body = encoded(fed);
        std::string expected(req.buffer());
        expected += "40\r\n" + enc_body.substr(0, 64);
        BOOST_TEST_EQ(wire, expected);

        BOOST_TEST(!write_eof(sr, wire));
        BOOST_TEST(sr.is_done());

        expected += "\r\n10\r\n" + enc_body.substr(64, 16);
        expected += "\r\n0\r\n\r\n";
        BOOST_TEST_EQ(wire, expected);
    }

    void
    testEncoderFooterSpansFlush()
    {
        // The encoder's footer does not fit the output buffer
        // in one pass; it spans a flush and lands in a second
        // chunk. 64 == 0x40.
        std::string const body = make_body(60);
        auto req = make_request();
        req.set(http::field::content_encoding, "test");
        test_encoder enc("0123456789");
        serializer sr(cfg);
        sr.start(&req, &enc);

        std::string wire;
        BOOST_TEST(!write_eof(sr, wire, body));
        BOOST_TEST(sr.is_done());
        BOOST_TEST(enc.finished);

        auto const enc_body = encoded(body);
        std::string expected(req.buffer());
        expected += "40\r\n" + enc_body + "0123";
        expected += "\r\n6\r\n456789";
        expected += "\r\n0\r\n\r\n";
        BOOST_TEST(req.chunked());
        BOOST_TEST_EQ(wire, expected);
    }

    void
    testEncoderContentLength()
    {
        // an explicitly sized message is encoded without any
        // chunked framing; the declared size covers the encoded
        // output plus the footer
        std::string const body = make_body(8);
        auto req = make_request(12);
        req.set(http::field::content_encoding, "test");
        test_encoder enc("eof!");
        serializer sr(cfg);
        sr.start(&req, &enc);

        std::string wire;
        BOOST_TEST(!write_eof(sr, wire, body));
        BOOST_TEST(sr.is_done());
        BOOST_TEST(enc.finished);
        BOOST_TEST_EQ(req.content_length().value(), 12u);
        BOOST_TEST_EQ(
            wire,
            std::string(req.buffer()) +
                encoded(body) + "eof!");
    }

    void
    testEncoderContentLengthMismatch()
    {
        // encoded output larger than declared
        {
            std::string const body = make_body(8);
            auto req = make_request(5);
            req.set(http::field::content_encoding, "test");
            test_encoder enc("eof!");
            serializer sr(cfg);
            sr.start(&req, &enc);

            std::string wire;
            BOOST_TEST_EQ(
                write_eof(sr, wire, body),
                error::body_size_mismatch);
            BOOST_TEST(wire.empty());

            // the error latches: is_done() reports the message
            // over, and a retry — even without an intervening
            // consume — eats nothing and fails
            BOOST_TEST(sr.is_done());
            auto const calls = enc.calls;
            std::string_view rem = "xyz";
            BOOST_TEST_EQ(
                drive(sr, wire, rem, false),
                std::make_error_code(
                    std::errc::state_not_recoverable));
            BOOST_TEST_EQ(rem, "xyz");
            BOOST_TEST(wire.empty());
            BOOST_TEST_EQ(enc.calls, calls);
        }

        // encoded output smaller than declared
        {
            std::string const body = make_body(8);
            auto req = make_request(100);
            req.set(http::field::content_encoding, "test");
            test_encoder enc("eof!");
            serializer sr(cfg);
            sr.start(&req, &enc);

            std::string wire;
            BOOST_TEST_EQ(
                write_eof(sr, wire, body),
                error::body_size_mismatch);
            BOOST_TEST(sr.is_done());

            // supplying the exact shortfall raw would satisfy
            // the quota arithmetic; the latch keeps it from
            // completing a half-encoded body silently
            std::string const shortfall(88, 'x');
            std::string_view rem = shortfall;
            BOOST_TEST_EQ(
                drive(sr, wire, rem, false),
                std::make_error_code(
                    std::errc::state_not_recoverable));
            BOOST_TEST_EQ(rem.size(), shortfall.size());
            BOOST_TEST(wire.empty());
        }
    }

    void
    testEncoderErrorRetryNoConsume()
    {
        // the encoder digests input before the size check
        // fires; a retry without an intervening consume must
        // reach the latch, not the digested-input assert, and
        // the failing call's accounting stays intact
        std::string const body = make_body(8);
        auto req = make_request(5);
        req.set(http::field::content_encoding, "test");
        test_encoder enc("eof!");
        serializer sr(cfg);
        sr.start(&req, &enc);

        system::error_code ec;
        capy::const_buffer dest[dest_n];
        capy::const_buffer const b{
            body.data(), body.size() };
        auto out = sr.frame(dest, b, false, ec);
        BOOST_TEST_EQ(ec, error::body_size_mismatch);
        BOOST_TEST(out.empty());

        out = sr.frame(dest, b, false, ec);
        BOOST_TEST_EQ(
            ec,
            std::make_error_code(
                std::errc::state_not_recoverable));
        BOOST_TEST(out.empty());

        BOOST_TEST_EQ(sr.consume(0), body.size());
    }

    void
    testEncoderFailure()
    {
        // an encoder error surfaces from frame and poisons the
        // message
        std::string const body = make_body(20);
        auto req = make_request();
        req.set(http::field::content_encoding, "test");
        test_encoder enc;
        enc.fail = std::make_error_code(
            std::errc::invalid_argument);
        serializer sr(cfg);
        sr.start(&req, &enc);

        std::string wire;
        BOOST_TEST_EQ(
            write_eof(sr, wire, body), enc.fail);
        BOOST_TEST(wire.empty());

        // terminal: the encoder is never called again, and
        // retries fail
        BOOST_TEST(sr.is_done());
        auto const calls = enc.calls;
        std::string_view rem = body;
        BOOST_TEST_EQ(
            drive(sr, wire, rem, false),
            std::make_error_code(
                std::errc::state_not_recoverable));
        BOOST_TEST(wire.empty());
        BOOST_TEST_EQ(enc.calls, calls);
    }

    void
    testEncoderStagedFailure()
    {
        // the same error, raised while the staging buffer — not
        // the caller's memory — is what the encoder is draining
        auto req = make_request();
        req.set(http::field::content_encoding, "test");
        test_encoder enc;
        enc.fail = std::make_error_code(
            std::errc::invalid_argument);
        serializer sr(cfg);
        sr.start(&req, &enc);

        capy::mutable_buffer tmp[2];
        auto const dest = sr.prepare(tmp);
        // an installed encoder takes the staging buffer over for
        // its output, leaving enc_buffer for its input
        BOOST_TEST_EQ(
            capy::buffer_size(dest), cfg.enc_buffer);
        std::string const staged = make_body(20);
        capy::buffer_copy(dest, capy::make_buffer(staged));
        sr.commit(staged.size());

        std::string wire;
        BOOST_TEST_EQ(write_eof(sr, wire), enc.fail);
        BOOST_TEST(wire.empty());
        BOOST_TEST(sr.is_done());
    }

    void
    testEncoderFailureAtEof()
    {
        // the encoder accepts the body and then fails while
        // finishing the stream
        std::string const body = make_body(20);
        auto req = make_request();
        req.set(http::field::content_encoding, "test");
        test_encoder enc;
        serializer sr(cfg);
        sr.start(&req, &enc);

        std::string wire;
        BOOST_TEST(!write(sr, wire, body));

        enc.fail = std::make_error_code(
            std::errc::invalid_argument);
        BOOST_TEST_EQ(write_eof(sr, wire), enc.fail);
        BOOST_TEST(sr.is_done());
    }

    void
    testEncoderToEof()
    {
        // close-delimited framing, pinned by the flushed header:
        // encoded output goes out as it is produced, against no
        // declared size at all
        std::string const body = make_body(20);
        response_head res;
        res.set(http::field::content_encoding, "test");
        test_encoder enc("eof!");
        serializer sr(cfg);
        sr.start(&res, &enc);

        std::string wire;
        BOOST_TEST(!drain(sr, wire));
        BOOST_TEST_EQ(wire, std::string(res.buffer()));

        BOOST_TEST(!write_eof(sr, wire, body));
        BOOST_TEST(sr.is_done());
        BOOST_TEST(enc.finished);
        BOOST_TEST(!res.content_length().has_value());
        BOOST_TEST(!res.chunked());
        BOOST_TEST_EQ(
            wire,
            std::string(res.buffer()) + encoded(body) + "eof!");
    }

    void
    testEncoderToEofOctetsAfterEof()
    {
        // a finished encoder must not let post-eof octets ride
        // the close-delimited framing unencoded; the framed
        // output stays exactly the encoded stream
        std::string const body = make_body(20);
        response_head res;
        res.set(http::field::content_encoding, "test");
        test_encoder enc("eof!");
        serializer sr(cfg);
        sr.start(&res, &enc);

        std::string wire;
        BOOST_TEST(!drain(sr, wire));
        BOOST_TEST(!write_eof(sr, wire, body, 3));
        BOOST_TEST(sr.is_done());
        BOOST_TEST(enc.finished);

        std::string_view rem("hello");
        BOOST_TEST_EQ(
            drive(sr, wire, rem, true),
            std::make_error_code(
                std::errc::invalid_argument));
        BOOST_TEST_EQ(rem.size(), 5u);
        BOOST_TEST_EQ(
            wire,
            std::string(res.buffer()) + encoded(body) + "eof!");
    }

    void
    testEncoderToEofEmptyBody()
    {
        // a pinned close-delimited stream whose encoder receives
        // no input at all still completes; the empty case must
        // not read as leftover debt
        response_head res;
        res.set(http::field::content_encoding, "test");
        test_encoder enc;
        serializer sr(cfg);
        sr.start(&res, &enc);

        std::string wire;
        BOOST_TEST(!drain(sr, wire));
        BOOST_TEST(!write_eof(sr, wire));
        BOOST_TEST(sr.is_done());
        BOOST_TEST(enc.finished);
        BOOST_TEST_EQ(wire, std::string(res.buffer()));
    }

    void
    testEncoderContentLengthPartialConsume()
    {
        // An encoded content-length flight drained one octet at
        // a time: the encoder refills its output buffer as the
        // wire frees it, across a partially consumed run, and
        // the declared size still comes out exact.
        std::string const body = make_body(70);
        auto req = make_request(74);
        req.set(http::field::content_encoding, "test");
        test_encoder enc("eof!");
        serializer sr(cfg);
        sr.start(&req, &enc);

        std::string wire;
        BOOST_TEST(!write_eof(sr, wire, body, 1));
        BOOST_TEST(sr.is_done());
        BOOST_TEST(enc.finished);
        BOOST_TEST_EQ(req.content_length().value(), 74u);
        BOOST_TEST_EQ(
            wire,
            std::string(req.buffer()) + encoded(body) + "eof!");
    }

    void
    testEncoderChunkedEmptyFinalFlush()
    {
        // The wire emptied the encoder's output buffer before
        // the body ended, so the finishing pass produces nothing
        // and opens no chunk of its own; 64 == 0x40.
        std::string const body = make_body(cfg.stage_buffer);
        auto req = make_request();
        req.set(http::field::content_encoding, "test");
        test_encoder enc;
        serializer sr(cfg);
        sr.start(&req, &enc);

        std::string wire;
        BOOST_TEST(!drain(sr, wire));
        BOOST_TEST_EQ(wire, std::string(req.buffer()));

        BOOST_TEST(!write(sr, wire, body));
        std::string expected(req.buffer());
        expected += "40\r\n" + encoded(body);
        BOOST_TEST_EQ(wire, expected);

        BOOST_TEST(!write_eof(sr, wire));
        BOOST_TEST(sr.is_done());
        BOOST_TEST(enc.finished);
        BOOST_TEST(req.chunked());
        expected += "\r\n0\r\n\r\n";
        BOOST_TEST_EQ(wire, expected);
    }

    void
    testEncoderDribbles()
    {
        // An encoder is free to produce less than the room it
        // was given, footer included: the finishing pass is
        // re-entered until the stream ends rather than being
        // taken as finished. 14 == 0xe.
        std::string const body = make_body(10);
        auto req = make_request();
        req.set(http::field::content_encoding, "test");
        test_encoder enc("abcd");
        enc.out_limit = 1;
        serializer sr(cfg);
        sr.start(&req, &enc);

        std::string wire;
        BOOST_TEST(!drain(sr, wire));
        BOOST_TEST_EQ(wire, std::string(req.buffer()));

        BOOST_TEST(!write_eof(sr, wire, body));
        BOOST_TEST(sr.is_done());
        BOOST_TEST(enc.finished);
        BOOST_TEST(req.chunked());

        std::string expected(req.buffer());
        expected += "e\r\n" + encoded(body) + "abcd";
        expected += "\r\n0\r\n\r\n";
        BOOST_TEST_EQ(wire, expected);
    }

    void
    testEncoderMultipleBuffers()
    {
        auto req = make_request();
        req.set(http::field::content_encoding, "test");
        test_encoder enc;
        serializer sr(cfg);
        sr.start(&req, &enc);

        std::string const b1 = make_body(6);
        std::string const b2 = make_body(6);
        capy::const_buffer const bufs[2] = {
            capy::make_buffer(b1),
            capy::make_buffer(b2) };

        std::string wire;
        system::error_code ec;
        capy::const_buffer dest[dest_n];
        auto const out = sr.frame(dest, bufs, false, ec);
        BOOST_TEST(!ec);

        std::size_t n = 0;
        for(auto cb : out)
        {
            wire.append(
                static_cast<char const*>(cb.data()), cb.size());
            n += cb.size();
        }
        // the encoder ate the whole input as it ran
        BOOST_TEST_EQ(sr.consume(n), 12u);
        BOOST_TEST(sr.is_done());
        BOOST_TEST(enc.finished);
        BOOST_TEST_EQ(req.content_length().value(), 12u);
        BOOST_TEST_EQ(
            wire,
            std::string(req.buffer()) + encoded(b1 + b2));
    }

    void
    testEncoderOutputFillFlushes()
    {
        // A single large input pumps until the output buffer
        // fills, flushes it as one chunk, and leaves the
        // unconsumed input with the caller; 64 == 0x40.
        std::string const body = make_body(200);
        auto req = make_request();
        req.set(http::field::content_encoding, "test");
        test_encoder enc;
        serializer sr(cfg);
        sr.start(&req, &enc);

        capy::const_buffer const b{
            body.data(), body.size() };
        std::string wire;
        system::error_code ec;
        capy::const_buffer dest[dest_n];
        auto const out = sr.frame(dest, b, true, ec);
        BOOST_TEST(!ec);
        BOOST_TEST(!out.empty());

        std::size_t n = 0;
        for(auto cb : out)
        {
            wire.append(
                static_cast<char const*>(cb.data()), cb.size());
            n += cb.size();
        }
        BOOST_TEST_EQ(sr.consume(n), cfg.stage_buffer);

        auto const enc_body = encoded(body);
        BOOST_TEST_EQ(
            wire,
            std::string(req.buffer()) + "40\r\n" +
                enc_body.substr(0, 64));
    }

    void
    testEncoderRegionSeam()
    {
        // The encoder's input staging sits directly above its
        // output region in one allocation. Fill both to capacity
        // while the last output octet is still unconsumed, so a
        // misplaced boundary either corrupts that octet (wire
        // mismatch) or writes past the allocation.
        std::string const body1 = make_body(cfg.stage_buffer);
        std::string const body2 = make_body(cfg.enc_buffer);
        auto req = make_request();
        req.set(http::field::content_encoding, "test");
        test_encoder enc;
        serializer sr(cfg);
        sr.start(&req, &enc);

        // fill the encoder's output; 64 == 0x40
        capy::const_buffer const b{
            body1.data(), body1.size() };
        system::error_code ec;
        capy::const_buffer dest[dest_n];
        auto const out = sr.frame(dest, b, true, ec);
        BOOST_TEST(!ec);
        BOOST_TEST(!out.empty());

        // take the header and part of the chunk, keeping the
        // tail of the output region live
        std::string wire;
        auto const partial = req.buffer().size() + 14;
        std::size_t n = 0;
        for(auto cb : out)
        {
            auto const k = (std::min)(partial - n, cb.size());
            wire.append(
                static_cast<char const*>(cb.data()), k);
            if((n += k) == partial)
                break;
        }
        // the encoder ate the whole input as it ran
        BOOST_TEST_EQ(sr.consume(n), body1.size());

        // fill the staging window to its last byte while the
        // output tail still awaits the wire
        capy::mutable_buffer tmp[2];
        auto const m = capy::buffer_copy(
            sr.prepare(tmp), capy::make_buffer(body2));
        BOOST_TEST_EQ(m, cfg.enc_buffer);
        sr.commit(m);

        BOOST_TEST(!write_eof(sr, wire));
        BOOST_TEST(sr.is_done());

        std::string expected(req.buffer());
        expected += "40\r\n" + encoded(body1);
        expected += "\r\n20\r\n" + encoded(body2);
        expected += "\r\n0\r\n\r\n";
        BOOST_TEST_EQ(wire, expected);
    }

    void
    testStart()
    {
        // start() rebinds the serializer to a new message and
        // encoder for reuse. The first request drops its
        // encoder; the second must encode with full capacity.
        auto req1 = make_request();
        req1.set(http::field::content_encoding, "test");
        auto req2 = make_request();
        req2.set(http::field::content_encoding, "test");
        std::string const body = make_body(200);
        test_encoder enc1;
        test_encoder enc2;

        serializer sr(cfg);
        // no message yet, so nothing of a header is out
        BOOST_TEST(!sr.is_header_done());
        BOOST_TEST(!sr.is_done());
        sr.start(&req1, &enc1);

        // the small body drops the encoder
        std::string wire1;
        BOOST_TEST(!write_eof(sr, wire1, "hello"));
        BOOST_TEST(sr.is_done());
        BOOST_TEST_EQ(enc1.calls, 0u);
        BOOST_TEST_EQ(
            wire1, std::string(req1.buffer()) + "hello");

        sr.start(&req2, &enc2);
        BOOST_TEST(!sr.is_done());

        std::string wire2;
        BOOST_TEST(!write(sr, wire2, body));
        BOOST_TEST(!write_eof(sr, wire2));
        BOOST_TEST(sr.is_done());

        auto const enc_body = encoded(body);
        std::string expected(req2.buffer());
        expected += "40\r\n" + enc_body.substr(0, 64);
        expected += "\r\n40\r\n" + enc_body.substr(64, 64);
        expected += "\r\n40\r\n" + enc_body.substr(128, 64);
        expected += "\r\n8\r\n" + enc_body.substr(192, 8);
        expected += "\r\n0\r\n\r\n";
        BOOST_TEST(enc2.finished);
        BOOST_TEST(req2.chunked());
        BOOST_TEST_EQ(wire2, expected);
    }

    void
    testStartAfterEncoderKept()
    {
        // A following plain message must send its own staged
        // body, not stale encoder output, and re-adding an
        // encoder afterwards must keep full capacity.
        auto req1 = make_request();
        req1.set(http::field::content_encoding, "test");
        auto req2 = make_request(5);
        auto req3 = make_request();
        req3.set(http::field::content_encoding, "test");
        std::string const body1 = make_body(20);
        std::string const body3 = make_body(200);
        test_encoder enc1;
        test_encoder enc3;

        serializer sr(cfg);
        sr.start(&req1, &enc1);

        // the body crosses the threshold: the encoder is kept
        std::string wire1;
        BOOST_TEST(!write_eof(sr, wire1, body1));
        BOOST_TEST(sr.is_done());
        BOOST_TEST_EQ(
            wire1,
            std::string(req1.buffer()) + encoded(body1));

        sr.start(&req2);
        std::string wire2;
        BOOST_TEST(!write(sr, wire2, "hello"));
        BOOST_TEST(!write_eof(sr, wire2));
        BOOST_TEST(sr.is_done());
        BOOST_TEST_EQ(
            wire2, std::string(req2.buffer()) + "hello");

        sr.start(&req3, &enc3);
        std::string wire3;
        BOOST_TEST(!write(sr, wire3, body3));
        BOOST_TEST(!write_eof(sr, wire3));
        BOOST_TEST(sr.is_done());

        auto const enc_body = encoded(body3);
        std::string expected(req3.buffer());
        expected += "40\r\n" + enc_body.substr(0, 64);
        expected += "\r\n40\r\n" + enc_body.substr(64, 64);
        expected += "\r\n40\r\n" + enc_body.substr(128, 64);
        expected += "\r\n8\r\n" + enc_body.substr(192, 8);
        expected += "\r\n0\r\n\r\n";
        BOOST_TEST(req3.chunked());
        BOOST_TEST_EQ(wire3, expected);
    }

    void
    testStartAbandons()
    {
        // start() abandons outstanding debt; the next message
        // is unaffected
        std::string const body(cfg.min_direct, 'x');
        auto req1 = make_request();
        auto req2 = make_request(5);
        serializer sr(cfg);
        sr.start(&req1);

        capy::const_buffer const b{
            body.data(), body.size() };
        system::error_code ec;
        capy::const_buffer dest[dest_n];
        auto const out = sr.frame(dest, b, true, ec);
        BOOST_TEST(!out.empty());
        sr.consume(3); // part of the header, then abandon

        sr.start(&req2);
        std::string wire;
        BOOST_TEST(!write_eof(sr, wire, "hello"));
        BOOST_TEST_EQ(
            wire, std::string(req2.buffer()) + "hello");
    }

    void
    testHeadContentLength()
    {
        // A head message sends only the header; the declared
        // Content-Length describes the body a non-head message
        // would have carried, and stays untouched.
        auto req = make_request(5);
        serializer sr(cfg);
        sr.start(&req, nullptr, true);
        BOOST_TEST(!sr.is_done());

        std::string wire;
        BOOST_TEST(!write_eof(sr, wire));
        BOOST_TEST(sr.is_done());

        BOOST_TEST_EQ(req.content_length().value(), 5u);
        BOOST_TEST_EQ(wire, std::string(req.buffer()));

        // the head flag does not stick across start()
        auto req2 = make_request(5);
        sr.start(&req2);
        std::string wire2;
        BOOST_TEST(!write(sr, wire2, "hello"));
        BOOST_TEST(!write_eof(sr, wire2));
        BOOST_TEST_EQ(
            wire2, std::string(req2.buffer()) + "hello");
    }

    void
    testHeadChunked()
    {
        // A chunked head message keeps Transfer-Encoding in the
        // header to describe the framing a non-head message
        // would have used; no framing bytes reach the wire.
        auto req = make_request();
        serializer sr(cfg);
        sr.start(&req, nullptr, true);

        std::string wire;
        BOOST_TEST(!write_eof(sr, wire));
        BOOST_TEST(sr.is_done());

        BOOST_TEST(req.chunked());
        BOOST_TEST(
            wire.find("Content-Length") == std::string::npos);
        BOOST_TEST_EQ(wire, std::string(req.buffer()));
    }

    void
    testHeadBodyMismatch()
    {
        // body bytes are rejected when supplied, even when they
        // match the declared Content-Length
        {
            auto req = make_request(5);
            serializer sr(cfg);
            sr.start(&req, nullptr, true);

            std::string wire;
            BOOST_TEST_EQ(
                write(sr, wire, "hello"),
                error::body_size_mismatch);
            BOOST_TEST(wire.empty());
        }

        // same on the direct path
        {
            std::string const body(cfg.min_direct, 'x');
            auto req = make_request(body.size());
            serializer sr(cfg);
            sr.start(&req, nullptr, true);

            std::string wire;
            BOOST_TEST_EQ(
                write(sr, wire, body),
                error::body_size_mismatch);
            BOOST_TEST(wire.empty());
        }
    }

    void
    testHeadEncoder()
    {
        // an encoder passed alongside head is ignored entirely
        auto req = make_request(5);
        req.set(http::field::content_encoding, "test");
        test_encoder enc;
        serializer sr(cfg);
        sr.start(&req, &enc, true);

        std::string wire;
        BOOST_TEST(!write_eof(sr, wire));
        BOOST_TEST(sr.is_done());

        BOOST_TEST_EQ(enc.calls, 0u);
        BOOST_TEST(
            wire.find("Content-Encoding: test\r\n") !=
            std::string::npos);
        BOOST_TEST_EQ(wire, std::string(req.buffer()));
    }

    void
    run()
    {
        testContentLengthSmallBody();
        testContentLengthLargeBody();
        testContentLengthMultipleBuffers();
        testBodySizeMismatch();
        testChunkedSmallBodyConvertsToContentLength();
        testChunkedWriteEofWithBody();
        testChunkedLargeBody();
        testChunkedWriteEofWithTail();
        testChunkedWriteEofTailOnly();
        testChunkedEmptyBody();
        testPrepareCommitContentLength();
        testPrepareCommitPartialFlush();
        testPrepareCommitChunked();
        testPrepareCommitNoFlush();
        testPrepareEmptyDest();
        testPrepareFullBuffer();
        testPartialConsume();
        testRemainderCoalesces();
        testFrameIdempotent();
        testCancelAndResume();
        testCancelResumeByCommit();
        testAbandonedChunkErrors();
        testContentLengthCancelResume();
        testManyDescriptors();
        testOneSlotDest();
        testStagedBeyondOpenChunk();
        testChunkedNarrowResumeWindow();
        testEmptyDescriptorsDoNotCount();
        testConsumption();
        testFrameWithoutBuffers();
        testChunkedOctetsAfterEof();
        testStagedRemainderDrain();
        testToEof();
        testToEofPartialWrites();
        testToEofBodyContract();
        testToEofDestExhaustion();
        testEmptyDest();
        testChunkedOctetsAfterEofDeferred();
        testTrailer();
        testTrailerIgnoredWhenNotChunked();
        testTrailerWithEncoder();
        testTrailerWithDroppedEncoder();
        testEncoderSmallBodyDropsEncoder();
        testEncoderKeptAfterHeaderFlush();
        testEncoderEmptyBody();
        testEncoderPrepareCommitEof();
        testEncoderThreshold();
        testEncoderStagedAndTail();
        testEncoderLargeBodyChunked();
        testEncoderLargeBodyChunkedEof();
        testEncoderCommit();
        testEncoderFooterSpansFlush();
        testEncoderContentLength();
        testEncoderContentLengthMismatch();
        testEncoderErrorRetryNoConsume();
        testEncoderFailure();
        testEncoderStagedFailure();
        testEncoderFailureAtEof();
        testEncoderToEof();
        testEncoderToEofOctetsAfterEof();
        testEncoderToEofEmptyBody();
        testEncoderContentLengthPartialConsume();
        testEncoderChunkedEmptyFinalFlush();
        testEncoderDribbles();
        testEncoderMultipleBuffers();
        testEncoderOutputFillFlushes();
        testEncoderRegionSeam();
        testStart();
        testStartAfterEncoderKept();
        testStartAbandons();
        testHeadContentLength();
        testHeadChunked();
        testHeadBodyMismatch();
        testHeadEncoder();
    }
};

TEST_SUITE(serializer_test, "boost.burl.serializer");

} // namespace burl
} // namespace boost
