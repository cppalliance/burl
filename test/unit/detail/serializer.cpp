//
// Copyright (c) 2026 Mohammad Nejati
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

// Test that header file is self-contained.
#include "src/detail/serializer.hpp"

#include <boost/burl/error.hpp>
#include <boost/burl/request_head.hpp>

#include <boost/capy/error.hpp>
#include <boost/capy/test/fuse.hpp>
#include <boost/capy/test/run_blocking.hpp>
#include <boost/capy/test/stream.hpp>
#include <boost/capy/test/write_stream.hpp>

#include <cstring>

#include "test_suite.hpp"

namespace boost
{
namespace burl
{
namespace detail
{

class serializer_test
{
    // A scaled-down config so that framing and encoder
    // thresholds (staged vs. direct writes, commit-triggered
    // flushes, encoder drop) are crossed with tiny bodies, and
    // so tests keep exercising the same paths if the default
    // config values change.
    static constexpr serializer::config cfg{
        .out_buffer  = 64,
        .min_prepare = 32,
        .direct_thr  = 16,
        .enc_buffer  = 32,
        .enc_thr     = 8 };

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
    // and appends an optional trailer once the input ends. It
    // consumes and produces as much as the given buffers allow.
    struct test_encoder : serializer::encoder
    {
        std::string trailer;
        std::error_code fail;
        std::size_t calls = 0;
        bool finished = false;

        explicit test_encoder(std::string trl = {})
            : trailer(std::move(trl))
        {
        }

        result
        process(
            capy::mutable_buffer out,
            capy::const_buffer in,
            bool eof) override
        {
            ++calls;
            if(fail)
                return { 0, 0, fail };

            auto* dst = static_cast<unsigned char*>(out.data());
            auto* src = static_cast<unsigned char const*>(in.data());
            auto const n = (std::min)(out.size(), in.size());
            for(std::size_t i = 0; i != n; ++i)
                dst[i] = static_cast<unsigned char>(src[i] + 1);

            result r{ n, n, {} };
            if(eof && n == in.size())
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

public:
    void
    testContentLengthSmallBody()
    {
        auto req = make_request(5);
        auto [client, server] = capy::test::make_stream_pair();

        capy::test::run_blocking()([&]() -> capy::task<>
        {
            capy::any_write_stream ws(&client);
            serializer sr(cfg, &ws);
            sr.reset(&req);
            BOOST_TEST(!sr.is_done());

            auto [ec1, n] = co_await sr.write(
                capy::const_buffer("hello", 5));
            BOOST_TEST(!ec1);
            BOOST_TEST_EQ(n, 5u);
            BOOST_TEST(!sr.is_done());

            auto [ec2] = co_await sr.write_eof();
            BOOST_TEST(!ec2);
            BOOST_TEST(sr.is_done());
        }());

        BOOST_TEST_EQ(
            server.data(),
            std::string(req.buffer()) + "hello");
    }

    void
    testContentLengthLargeBody()
    {
        // A body at the direct-write threshold bypasses staging.
        std::string const body(cfg.direct_thr, 'x');

        auto req = make_request(body.size());
        auto [client, server] = capy::test::make_stream_pair();

        capy::test::run_blocking()([&]() -> capy::task<>
        {
            capy::any_write_stream ws(&client);
            serializer sr(cfg, &ws);
            sr.reset(&req);

            auto [ec1, n] = co_await sr.write(
                capy::make_buffer(body));
            BOOST_TEST(!ec1);
            BOOST_TEST_EQ(n, body.size());

            auto [ec2] = co_await sr.write_eof();
            BOOST_TEST(!ec2);
        }());

        BOOST_TEST_EQ(
            server.data(),
            std::string(req.buffer()) + body);
    }

    void
    testContentLengthMultipleBuffers()
    {
        std::string const b1(4, 'a');
        std::string const b2(4, 'b');

        auto req = make_request(b1.size() + b2.size());
        auto [client, server] = capy::test::make_stream_pair();

        capy::test::run_blocking()([&]() -> capy::task<>
        {
            capy::any_write_stream ws(&client);
            serializer sr(cfg, &ws);
            sr.reset(&req);

            std::array<capy::const_buffer, 2> bufs{
                capy::make_buffer(b1),
                capy::make_buffer(b2) };

            auto [ec, n] = co_await sr.write_eof(bufs);
            BOOST_TEST(!ec);
            BOOST_TEST_EQ(n, b1.size() + b2.size());
            BOOST_TEST(sr.is_done());
        }());

        BOOST_TEST_EQ(
            server.data(),
            std::string(req.buffer()) + b1 + b2);
    }

    void
    testBodySizeMismatch()
    {
        // fewer bytes than Content-Length
        {
            auto req = make_request(10);
            auto [client, server] = capy::test::make_stream_pair();

            capy::test::run_blocking()([&]() -> capy::task<>
            {
                capy::any_write_stream ws(&client);
                serializer sr(cfg, &ws);
                sr.reset(&req);

                auto [ec1, n] = co_await sr.write(
                    capy::const_buffer("hello", 5));
                BOOST_TEST(!ec1);
                BOOST_TEST_EQ(n, 5u);

                auto [ec2] = co_await sr.write_eof();
                BOOST_TEST(ec2 == error::body_size_mismatch);
                BOOST_TEST(!sr.is_done());
            }());

            // Nothing reaches the wire when the mismatch is
            // detected before the header is flushed.
            BOOST_TEST(server.data().empty());
        }

        // more bytes than Content-Length
        {
            auto req = make_request(3);
            auto [client, server] = capy::test::make_stream_pair();

            capy::test::run_blocking()([&]() -> capy::task<>
            {
                capy::any_write_stream ws(&client);
                serializer sr(cfg, &ws);
                sr.reset(&req);

                auto [ec, n] = co_await sr.write_eof(
                    capy::const_buffer("hello", 5));
                BOOST_TEST(ec == error::body_size_mismatch);
                BOOST_TEST(!sr.is_done());
            }());

            BOOST_TEST(server.data().empty());
        }
    }

    void
    testChunkedSmallBodyConvertsToContentLength()
    {
        auto req = make_request();
        auto [client, server] = capy::test::make_stream_pair();

        capy::test::run_blocking()([&]() -> capy::task<>
        {
            capy::any_write_stream ws(&client);
            serializer sr(cfg, &ws);
            sr.reset(&req);

            // The body stays below direct_thr, so it is fully
            // buffered before the header goes out.
            auto [ec1, n] = co_await sr.write(
                capy::const_buffer("hello world", 11));
            BOOST_TEST(!ec1);
            BOOST_TEST_EQ(n, 11u);

            auto [ec2] = co_await sr.write_eof();
            BOOST_TEST(!ec2);
        }());

        // The entire body was buffered before the header was
        // flushed, so chunked encoding is replaced with
        // Content-Length and the body is sent unframed.
        BOOST_TEST(!req.chunked());
        BOOST_TEST_EQ(req.content_length().value(), 11u);
        BOOST_TEST(
            server.data().find("Transfer-Encoding") ==
            std::string_view::npos);
        BOOST_TEST_EQ(
            server.data(),
            std::string(req.buffer()) + "hello world");
    }

    void
    testChunkedWriteEofWithBody()
    {
        auto req = make_request();
        auto [client, server] = capy::test::make_stream_pair();

        capy::test::run_blocking()([&]() -> capy::task<>
        {
            capy::any_write_stream ws(&client);
            serializer sr(cfg, &ws);
            sr.reset(&req);

            auto [ec, n] = co_await sr.write_eof(
                capy::const_buffer("hello", 5));
            BOOST_TEST(!ec);
            BOOST_TEST_EQ(n, 5u);
        }());

        BOOST_TEST(!req.chunked());
        BOOST_TEST_EQ(req.content_length().value(), 5u);
        BOOST_TEST_EQ(
            server.data(),
            std::string(req.buffer()) + "hello");
    }

    void
    testChunkedLargeBody()
    {
        std::string const body(cfg.direct_thr, 'x');

        auto req = make_request();
        auto [client, server] = capy::test::make_stream_pair();

        capy::test::run_blocking()([&]() -> capy::task<>
        {
            capy::any_write_stream ws(&client);
            serializer sr(cfg, &ws);
            sr.reset(&req);

            auto [ec1, n1] = co_await sr.write(
                capy::make_buffer(body));
            BOOST_TEST(!ec1);
            BOOST_TEST_EQ(n1, body.size());

            auto [ec2, n2] = co_await sr.write(
                capy::const_buffer("hello", 5));
            BOOST_TEST(!ec2);
            BOOST_TEST_EQ(n2, 5u);
            BOOST_TEST(!sr.is_done());

            auto [ec3] = co_await sr.write_eof();
            BOOST_TEST(!ec3);
            BOOST_TEST(sr.is_done());
        }());

        // The large write is gathered with the header and sent
        // as its own chunk; the small write is buffered and
        // flushed at eof as a chunk. Chunk sizes are always
        // minimal-width; 16 == 0x10.
        std::string expected(req.buffer());
        expected += "10\r\n" + body + "\r\n";
        expected += "5\r\nhello\r\n";
        expected += "0\r\n\r\n";
        BOOST_TEST(req.chunked());
        BOOST_TEST_EQ(server.data(), expected);
    }

    void
    testChunkedWriteEofWithTail()
    {
        // Once the header is on the wire, write_eof() with
        // caller buffers must frame the staged bytes and the
        // caller's bytes as the final chunk and terminate the
        // body with the last-chunk in the same gather.
        std::string const body(cfg.direct_thr, 'x');

        auto req = make_request();
        auto [client, server] = capy::test::make_stream_pair();

        capy::test::run_blocking()([&]() -> capy::task<>
        {
            capy::any_write_stream ws(&client);
            serializer sr(cfg, &ws);
            sr.reset(&req);

            auto [ec1, n1] = co_await sr.write(
                capy::make_buffer(body));
            BOOST_TEST(!ec1);
            BOOST_TEST_EQ(n1, body.size());

            auto [ec2, n2] = co_await sr.write(
                capy::const_buffer("abc", 3));
            BOOST_TEST(!ec2);
            BOOST_TEST_EQ(n2, 3u);

            auto [ec3, n3] = co_await sr.write_eof(
                capy::const_buffer("hello", 5));
            BOOST_TEST(!ec3);
            BOOST_TEST_EQ(n3, 5u);
        }());

        std::string expected(req.buffer());
        expected += "10\r\n" + body + "\r\n";
        expected += "8\r\nabchello\r\n";
        expected += "0\r\n\r\n";
        BOOST_TEST(req.chunked());
        BOOST_TEST_EQ(server.data(), expected);
    }

    void
    testChunkedWriteEofTailOnly()
    {
        // write_eof() with caller buffers while no bytes are
        // staged must still terminate the body with the
        // last-chunk after the final chunk.
        std::string const body(cfg.direct_thr, 'x');

        auto req = make_request();
        auto [client, server] = capy::test::make_stream_pair();

        capy::test::run_blocking()([&]() -> capy::task<>
        {
            capy::any_write_stream ws(&client);
            serializer sr(cfg, &ws);
            sr.reset(&req);

            auto [ec1, n1] = co_await sr.write(
                capy::make_buffer(body));
            BOOST_TEST(!ec1);
            BOOST_TEST_EQ(n1, body.size());

            auto [ec2, n2] = co_await sr.write_eof(
                capy::const_buffer("hello", 5));
            BOOST_TEST(!ec2);
            BOOST_TEST_EQ(n2, 5u);
        }());

        std::string expected(req.buffer());
        expected += "10\r\n" + body + "\r\n";
        expected += "5\r\nhello\r\n";
        expected += "0\r\n\r\n";
        BOOST_TEST(req.chunked());
        BOOST_TEST_EQ(server.data(), expected);
    }

    void
    testChunkedEmptyBody()
    {
        auto req = make_request();
        auto [client, server] = capy::test::make_stream_pair();

        capy::test::run_blocking()([&]() -> capy::task<>
        {
            capy::any_write_stream ws(&client);
            serializer sr({}, &ws);
            sr.reset(&req);
            BOOST_TEST(!sr.is_done());

            auto [ec] = co_await sr.write_eof();
            BOOST_TEST(!ec);
            BOOST_TEST(sr.is_done());
        }());

        BOOST_TEST(!req.chunked());
        BOOST_TEST(
            server.data().find("Content-Length: 0\r\n") !=
            std::string_view::npos);
        BOOST_TEST_EQ(server.data(), req.buffer());
    }

    void
    testPrepareCommitContentLength()
    {
        auto req = make_request(5);
        auto [client, server] = capy::test::make_stream_pair();

        capy::test::run_blocking()([&]() -> capy::task<>
        {
            capy::any_write_stream ws(&client);
            serializer sr(cfg, &ws);
            sr.reset(&req);

            capy::mutable_buffer tmp[2];
            auto n = capy::buffer_copy(
                sr.prepare(tmp),
                capy::const_buffer("hello", 5));
            BOOST_TEST_EQ(n, 5u);

            auto [ec] = co_await sr.commit_eof(n);
            BOOST_TEST(!ec);
            BOOST_TEST(sr.is_done());
        }());

        BOOST_TEST_EQ(
            server.data(),
            std::string(req.buffer()) + "hello");
    }

    void
    testPrepareCommitPartialFlush()
    {
        // Committing enough data to drop the remaining capacity
        // below min_prepare triggers a partial flush.
        std::string const body(60, 'z');

        auto req = make_request(body.size());
        auto [client, server] = capy::test::make_stream_pair();

        capy::test::run_blocking()([&]() -> capy::task<>
        {
            capy::any_write_stream ws(&client);
            serializer sr(cfg, &ws);
            sr.reset(&req);

            capy::mutable_buffer tmp[2];
            auto n = capy::buffer_copy(
                sr.prepare(tmp), capy::make_buffer(body));
            BOOST_TEST_EQ(n, body.size());

            auto [ec1] = co_await sr.commit(n);
            BOOST_TEST(!ec1);
            BOOST_TEST(!sr.is_done());

            auto [ec2] = co_await sr.write_eof();
            BOOST_TEST(!ec2);
            BOOST_TEST(sr.is_done());
        }());

        BOOST_TEST_EQ(
            server.data(),
            std::string(req.buffer()) + body);
    }

    void
    testPrepareCommitChunked()
    {
        // A drain while chunked emits the buffered bytes as a
        // single chunk with a minimal-width size; 60 == 0x3C.
        std::string const body(60, 'z');

        auto req = make_request();
        auto [client, server] = capy::test::make_stream_pair();

        capy::test::run_blocking()([&]() -> capy::task<>
        {
            capy::any_write_stream ws(&client);
            serializer sr(cfg, &ws);
            sr.reset(&req);

            capy::mutable_buffer tmp[2];
            auto n = capy::buffer_copy(
                sr.prepare(tmp), capy::make_buffer(body));
            BOOST_TEST_EQ(n, body.size());

            auto [ec1] = co_await sr.commit(n);
            BOOST_TEST(!ec1);

            auto [ec2] = co_await sr.write_eof();
            BOOST_TEST(!ec2);
        }());

        std::string expected(req.buffer());
        expected += "3c\r\n" + body + "\r\n";
        expected += "0\r\n\r\n";
        BOOST_TEST(req.chunked());
        BOOST_TEST_EQ(server.data(), expected);
    }

    void
    testPrepareCommitNoFlush()
    {
        // Committing a small amount keeps the remaining
        // capacity above min_prepare, so commit() completes
        // without flushing anything to the stream.
        auto req = make_request(5);
        auto [client, server] = capy::test::make_stream_pair();

        capy::test::run_blocking()([&]() -> capy::task<>
        {
            capy::any_write_stream ws(&client);
            serializer sr(cfg, &ws);
            sr.reset(&req);

            capy::mutable_buffer tmp[2];
            auto n = capy::buffer_copy(
                sr.prepare(tmp),
                capy::const_buffer("hello", 5));
            BOOST_TEST_EQ(n, 5u);

            auto [ec1] = co_await sr.commit(n);
            BOOST_TEST(!ec1);
            BOOST_TEST(server.data().empty());

            auto [ec2] = co_await sr.write_eof();
            BOOST_TEST(!ec2);
        }());

        BOOST_TEST_EQ(
            server.data(),
            std::string(req.buffer()) + "hello");
    }

    void
    testPrepareEmptyDest()
    {
        // prepare() with no destination buffers reports no
        // writable space.
        auto req = make_request(5);
        auto [client, server] = capy::test::make_stream_pair();

        capy::any_write_stream ws(&client);
        serializer sr(cfg, &ws);
        sr.reset(&req);

        BOOST_TEST(sr.prepare({}).empty());

        // The staging buffer is untouched and remains fully
        // available.
        capy::mutable_buffer tmp[2];
        auto dest = sr.prepare(tmp);
        BOOST_TEST_EQ(dest.size(), 1u);
        BOOST_TEST_EQ(capy::buffer_size(dest), cfg.out_buffer);
    }

    void
    testPrepareFullBuffer()
    {
        // A commit that fills the staging buffer triggers a
        // drain. When the drain fails, the buffered bytes are
        // kept; prepare() must report no writable space rather
        // than hand out a zero-sized buffer.
        capy::test::fuse f;
        auto r = f.armed([&](capy::test::fuse&) -> capy::task<>
        {
            std::string const body(cfg.out_buffer, 'z');

            auto req = make_request(body.size());
            capy::test::write_stream ws_impl(f);

            capy::any_write_stream ws(&ws_impl);
            serializer sr(cfg, &ws);
            sr.reset(&req);

            capy::mutable_buffer tmp[2];
            auto n = capy::buffer_copy(
                sr.prepare(tmp), capy::make_buffer(body));
            BOOST_TEST_EQ(n, body.size());

            if(auto [ec] = co_await sr.commit(n); ec)
            {
                BOOST_TEST(sr.prepare(tmp).empty());
                co_return;
            }

            // The successful drain empties the staging buffer,
            // so the full capacity is writable again.
            auto dest = sr.prepare(tmp);
            BOOST_TEST_EQ(dest.size(), 1u);
            BOOST_TEST_EQ(
                capy::buffer_size(dest), cfg.out_buffer);
        });
        BOOST_TEST(r.success);
    }

    void
    testChunkedShortWrites()
    {
        // The staging buffer holds raw body bytes only, so the
        // full capacity is stageable as one chunk; 64 == 0x40.
        std::string const body(cfg.out_buffer, 'z');

        auto req = make_request();
        capy::test::write_stream ws_impl({}, 1);

        capy::test::run_blocking()([&]() -> capy::task<>
        {
            capy::any_write_stream ws(&ws_impl);
            serializer sr(cfg, &ws);
            sr.reset(&req);

            capy::mutable_buffer tmp[2];
            auto n = capy::buffer_copy(
                sr.prepare(tmp), capy::make_buffer(body));
            BOOST_TEST_EQ(n, body.size());

            auto [ec1] = co_await sr.commit(n);
            BOOST_TEST(!ec1);

            // The drain writes the header and the staged chunk
            // to completion, even over a stream that transfers
            // one byte per write; the chunk's closing CRLF is
            // deferred to the next write.
            BOOST_TEST_EQ(ws_impl.data(),
                std::string(req.buffer()) +
                    "40\r\n" + body);

            auto [ec2, m] = co_await sr.write(
                capy::const_buffer("hello", 5));
            BOOST_TEST(!ec2);
            BOOST_TEST_EQ(m, 5u);

            auto [ec3] = co_await sr.write_eof();
            BOOST_TEST(!ec3);
        }());

        std::string expected(req.buffer());
        expected += "40\r\n" + body + "\r\n";
        expected += "5\r\nhello\r\n";
        expected += "0\r\n\r\n";
        BOOST_TEST(req.chunked());
        BOOST_TEST_EQ(ws_impl.data(), expected);
    }

    void
    testContentLengthShortWrites()
    {
        // A sized body streamed through the direct path must
        // arrive intact over a stream that transfers one byte
        // per write: bytes already on the wire may not be sent
        // again, and every call must consume at least one byte
        // of the caller's buffer.
        std::string const b1(cfg.direct_thr, 'x');
        std::string const b2(cfg.direct_thr, 'y');

        auto req = make_request(b1.size() + b2.size());
        capy::test::write_stream ws_impl({}, 1);

        capy::test::run_blocking()([&]() -> capy::task<>
        {
            capy::any_write_stream ws(&ws_impl);
            serializer sr(cfg, &ws);
            sr.reset(&req);

            // The first drain writes the header in full and
            // exactly one body byte.
            auto [ec1, n1] = co_await sr.write_some(
                capy::make_buffer(b1));
            BOOST_TEST(!ec1);
            BOOST_TEST_EQ(n1, 1u);
            BOOST_TEST_EQ(
                ws_impl.data(),
                std::string(req.buffer()) + "x");

            // The rest of the first buffer is below direct_thr
            // and is staged without touching the wire.
            auto [ec2, n2] = co_await sr.write(
                capy::const_buffer(b1.data() + 1, b1.size() - 1));
            BOOST_TEST(!ec2);
            BOOST_TEST_EQ(n2, b1.size() - 1);
            BOOST_TEST_EQ(
                ws_impl.data().size(),
                req.buffer().size() + 1);

            // Even when a full staged prefix must be flushed
            // first, at least one byte of the caller's buffer
            // is consumed.
            auto [ec3, n3] = co_await sr.write_some(
                capy::make_buffer(b2));
            BOOST_TEST(!ec3);
            BOOST_TEST_EQ(n3, 1u);
            BOOST_TEST_EQ(
                ws_impl.data(),
                std::string(req.buffer()) + b1 + "y");

            auto [ec4, n4] = co_await sr.write(
                capy::const_buffer(b2.data() + 1, b2.size() - 1));
            BOOST_TEST(!ec4);
            BOOST_TEST_EQ(n4, b2.size() - 1);

            auto [ec5] = co_await sr.write_eof();
            BOOST_TEST(!ec5);
        }());

        BOOST_TEST_EQ(
            ws_impl.data(),
            std::string(req.buffer()) + b1 + b2);
    }

    void
    testPrepareCommitShortWrites()
    {
        // A commit-triggered drain has no caller buffers; the
        // header and staged bytes are written to completion
        // over a stream that transfers one byte per write.
        std::string const body(60, 'z');

        auto req = make_request(body.size());
        capy::test::write_stream ws_impl({}, 1);

        capy::test::run_blocking()([&]() -> capy::task<>
        {
            capy::any_write_stream ws(&ws_impl);
            serializer sr(cfg, &ws);
            sr.reset(&req);

            capy::mutable_buffer tmp[2];
            auto n = capy::buffer_copy(
                sr.prepare(tmp), capy::make_buffer(body));
            BOOST_TEST_EQ(n, body.size());

            auto [ec1] = co_await sr.commit(n);
            BOOST_TEST(!ec1);
            BOOST_TEST_EQ(
                ws_impl.data(),
                std::string(req.buffer()) + body);

            auto [ec2] = co_await sr.write_eof();
            BOOST_TEST(!ec2);
        }());

        BOOST_TEST_EQ(
            ws_impl.data(),
            std::string(req.buffer()) + body);
    }

    void
    testShortWriteEofDoesNotTruncate()
    {
        // Everything due at eof is written to completion, even
        // over a stream that transfers one byte per write; the
        // body must not be silently dropped after the header.
        auto req = make_request();
        capy::test::write_stream ws_impl({}, 1);

        capy::test::run_blocking()([&]() -> capy::task<>
        {
            capy::any_write_stream ws(&ws_impl);
            serializer sr(cfg, &ws);
            sr.reset(&req);

            auto [ec1, n] = co_await sr.write(
                capy::const_buffer("hello", 5));
            BOOST_TEST(!ec1);
            BOOST_TEST_EQ(n, 5u);

            auto [ec2] = co_await sr.write_eof();
            BOOST_TEST(!ec2);
        }());

        // The body was fully buffered before the header went
        // out, so the request converts to Content-Length.
        BOOST_TEST(!req.chunked());
        BOOST_TEST_EQ(
            ws_impl.data(),
            std::string(req.buffer()) + "hello");
    }

    void
    testChunkedPreservesWriteOrder()
    {
        // A large write arriving while a small write is still
        // staged must not overtake it: both leave in a single
        // gather as one chunk with the staged bytes first, even
        // when the stream accepts one byte at a time;
        // 3 + 16 == 0x13.
        std::string const body(cfg.direct_thr, 'x');

        auto req = make_request();
        capy::test::write_stream ws_impl({}, 1);

        capy::test::run_blocking()([&]() -> capy::task<>
        {
            capy::any_write_stream ws(&ws_impl);
            serializer sr(cfg, &ws);
            sr.reset(&req);

            auto [ec1, n1] = co_await sr.write(
                capy::const_buffer("abc", 3));
            BOOST_TEST(!ec1);
            BOOST_TEST_EQ(n1, 3u);

            auto [ec2, n2] = co_await sr.write(
                capy::make_buffer(body));
            BOOST_TEST(!ec2);
            BOOST_TEST_EQ(n2, body.size());

            auto [ec3] = co_await sr.write_eof();
            BOOST_TEST(!ec3);
        }());

        std::string expected(req.buffer());
        expected += "13\r\nabc" + body + "\r\n";
        expected += "0\r\n\r\n";
        BOOST_TEST(req.chunked());
        BOOST_TEST_EQ(ws_impl.data(), expected);
    }

    void
    testErrorInjection()
    {
        capy::test::fuse f;
        auto r = f.armed([&](capy::test::fuse&) -> capy::task<>
        {
            std::string const body(cfg.direct_thr, 'x');

            auto req = make_request();

            auto [client, server] =
                capy::test::make_stream_pair(f);

            capy::any_write_stream ws(&client);
            serializer sr(cfg, &ws);
            sr.reset(&req);

            if(auto [ec, n] = co_await sr.write(
                capy::make_buffer(body)); ec)
            {
                BOOST_TEST(!sr.is_done());
                co_return;
            }

            if(auto [ec, n] = co_await sr.write(
                capy::const_buffer("hello", 5)); ec)
            {
                BOOST_TEST(!sr.is_done());
                co_return;
            }

            if(auto [ec] = co_await sr.write_eof(); ec)
            {
                BOOST_TEST(!sr.is_done());
                co_return;
            }

            BOOST_TEST(sr.is_done());

            std::string expected(req.buffer());
            expected += "10\r\n" + body + "\r\n";
            expected += "5\r\nhello\r\n";
            expected += "0\r\n\r\n";
            BOOST_TEST_EQ(server.data(), expected);
        });
        BOOST_TEST(r.success);
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
        auto [client, server] = capy::test::make_stream_pair();
        test_encoder enc;

        capy::test::run_blocking()([&]() -> capy::task<>
        {
            capy::any_write_stream ws(&client);
            serializer sr(cfg, &ws);
            sr.reset(&req, &enc);

            // below the threshold: coalesced into the encoder's
            // staging buffer without invoking the encoder
            auto [ec1, n] = co_await sr.write(
                capy::const_buffer("hello", 5));
            BOOST_TEST(!ec1);
            BOOST_TEST_EQ(n, 5u);
            BOOST_TEST_EQ(enc.calls, 0u);
            BOOST_TEST(server.data().empty());

            auto [ec2] = co_await sr.write_eof();
            BOOST_TEST(!ec2);
            BOOST_TEST(sr.is_done());
        }());

        BOOST_TEST_EQ(enc.calls, 0u);
        BOOST_TEST(!req.chunked());
        BOOST_TEST_EQ(req.content_length().value(), 5u);
        BOOST_TEST(
            server.data().find("Content-Encoding") ==
            std::string_view::npos);
        BOOST_TEST_EQ(
            server.data(),
            std::string(req.buffer()) + "hello");
    }

    void
    testEncoderEmptyBody()
    {
        auto req = make_request();
        req.set(http::field::content_encoding, "test");
        auto [client, server] = capy::test::make_stream_pair();
        test_encoder enc;

        capy::test::run_blocking()([&]() -> capy::task<>
        {
            capy::any_write_stream ws(&client);
            serializer sr(cfg, &ws);
            sr.reset(&req, &enc);

            auto [ec] = co_await sr.write_eof();
            BOOST_TEST(!ec);
            BOOST_TEST(sr.is_done());
        }());

        // an empty body is below any threshold: the encoder is
        // dropped and the request converts to Content-Length: 0
        BOOST_TEST_EQ(enc.calls, 0u);
        BOOST_TEST(!req.chunked());
        BOOST_TEST(
            server.data().find("Content-Length: 0\r\n") !=
            std::string_view::npos);
        BOOST_TEST(
            server.data().find("Content-Encoding") ==
            std::string_view::npos);
        BOOST_TEST_EQ(server.data(), req.buffer());
    }

    void
    testEncoderPrepareCommitEof()
    {
        // With an encoder, prepare() exposes the encoder's
        // staging buffer rather than the output buffer.
        auto req = make_request();
        req.set(http::field::content_encoding, "test");
        auto [client, server] = capy::test::make_stream_pair();
        test_encoder enc;

        capy::test::run_blocking()([&]() -> capy::task<>
        {
            capy::any_write_stream ws(&client);
            serializer sr(cfg, &ws);
            sr.reset(&req, &enc);

            capy::mutable_buffer tmp[2];
            auto dest = sr.prepare(tmp);
            BOOST_TEST_EQ(
                capy::buffer_size(dest), cfg.enc_buffer);

            auto n = capy::buffer_copy(
                dest, capy::const_buffer("hello", 5));
            BOOST_TEST_EQ(n, 5u);

            // below the threshold at eof: the encoder is
            // dropped and the staged bytes are sent as-is
            auto [ec] = co_await sr.commit_eof(n);
            BOOST_TEST(!ec);
            BOOST_TEST(sr.is_done());
        }());

        BOOST_TEST_EQ(enc.calls, 0u);
        BOOST_TEST(!req.chunked());
        BOOST_TEST_EQ(req.content_length().value(), 5u);
        BOOST_TEST_EQ(
            server.data(),
            std::string(req.buffer()) + "hello");
    }

    void
    testEncoderThreshold()
    {
        // exactly at the threshold: the encoder is kept
        {
            std::string const body = make_body(8);

            auto req = make_request();
            req.set(http::field::content_encoding, "test");
            auto [client, server] = capy::test::make_stream_pair();
            test_encoder enc;

            capy::test::run_blocking()([&]() -> capy::task<>
            {
                capy::any_write_stream ws(&client);
                serializer sr(cfg, &ws);
            sr.reset(&req, &enc);

                auto [ec, n] = co_await sr.write_eof(
                    capy::make_buffer(body));
                BOOST_TEST(!ec);
                BOOST_TEST_EQ(n, body.size());
                BOOST_TEST(sr.is_done());
            }());

            // the whole encoded output was buffered before the
            // header went out, so chunked is replaced with the
            // encoded length while Content-Encoding is kept
            BOOST_TEST(enc.finished);
            BOOST_TEST(!req.chunked());
            BOOST_TEST_EQ(req.content_length().value(), 8u);
            BOOST_TEST(
                server.data().find("Content-Encoding: test\r\n") !=
                std::string_view::npos);
            BOOST_TEST_EQ(
                server.data(),
                std::string(req.buffer()) + encoded(body));
        }

        // one byte below the threshold: the encoder is dropped
        {
            std::string const body = make_body(7);

            auto req = make_request();
            req.set(http::field::content_encoding, "test");
            auto [client, server] = capy::test::make_stream_pair();
            test_encoder enc;

            capy::test::run_blocking()([&]() -> capy::task<>
            {
                capy::any_write_stream ws(&client);
                serializer sr(cfg, &ws);
            sr.reset(&req, &enc);

                auto [ec, n] = co_await sr.write_eof(
                    capy::make_buffer(body));
                BOOST_TEST(!ec);
                BOOST_TEST_EQ(n, body.size());
            }());

            BOOST_TEST_EQ(enc.calls, 0u);
            BOOST_TEST_EQ(req.content_length().value(), 7u);
            BOOST_TEST(
                server.data().find("Content-Encoding") ==
                std::string_view::npos);
            BOOST_TEST_EQ(
                server.data(),
                std::string(req.buffer()) + body);
        }
    }

    void
    testEncoderStagedAndTail()
    {
        // Staged bytes and the caller's tail together reach the
        // threshold at eof, so the encoder is kept; it consumes
        // the staged bytes first, then the tail, and the count
        // returned to the caller covers only the tail.
        auto req = make_request();
        req.set(http::field::content_encoding, "test");
        auto [client, server] = capy::test::make_stream_pair();
        test_encoder enc;

        capy::test::run_blocking()([&]() -> capy::task<>
        {
            capy::any_write_stream ws(&client);
            serializer sr(cfg, &ws);
            sr.reset(&req, &enc);

            auto [ec1, n1] = co_await sr.write(
                capy::const_buffer("abc", 3));
            BOOST_TEST(!ec1);
            BOOST_TEST_EQ(n1, 3u);
            BOOST_TEST_EQ(enc.calls, 0u);

            auto [ec2, n2] = co_await sr.write_eof(
                capy::const_buffer("defgh", 5));
            BOOST_TEST(!ec2);
            BOOST_TEST_EQ(n2, 5u);
            BOOST_TEST(sr.is_done());
        }());

        BOOST_TEST(enc.finished);
        BOOST_TEST_EQ(req.content_length().value(), 8u);
        BOOST_TEST_EQ(
            server.data(),
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
        auto [client, server] = capy::test::make_stream_pair();
        test_encoder enc;

        capy::test::run_blocking()([&]() -> capy::task<>
        {
            capy::any_write_stream ws(&client);
            serializer sr(cfg, &ws);
            sr.reset(&req, &enc);

            auto [ec1, n] = co_await sr.write(
                capy::make_buffer(body));
            BOOST_TEST(!ec1);
            BOOST_TEST_EQ(n, body.size());
            BOOST_TEST(!sr.is_done());

            auto [ec2] = co_await sr.write_eof();
            BOOST_TEST(!ec2);
            BOOST_TEST(sr.is_done());
        }());

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
            server.data().find("Content-Encoding: test\r\n") !=
            std::string_view::npos);
        BOOST_TEST_EQ(server.data(), expected);
    }

    void
    testEncoderCommit()
    {
        // commit() stages input for the encoder; a drain is
        // deferred until the remaining capacity drops below
        // min_prepare, and encoded bytes stay buffered until
        // the output buffer needs room.
        std::string const body = make_body(54);

        auto req = make_request();
        req.set(http::field::content_encoding, "test");
        auto [client, server] = capy::test::make_stream_pair();
        test_encoder enc;

        // a staging buffer large enough to hold all commits
        auto ecfg = cfg;
        ecfg.enc_buffer = 64;

        capy::test::run_blocking()([&]() -> capy::task<>
        {
            capy::any_write_stream ws(&client);
            serializer sr(ecfg, &ws);
            sr.reset(&req, &enc);

            capy::mutable_buffer tmp[2];

            // capacity stays >= min_prepare: no drain
            auto n1 = capy::buffer_copy(
                sr.prepare(tmp),
                capy::const_buffer(body.data(), 20));
            BOOST_TEST_EQ(n1, 20u);
            auto [ec1] = co_await sr.commit(n1);
            BOOST_TEST(!ec1);
            BOOST_TEST_EQ(enc.calls, 0u);

            // capacity drops below min_prepare: the staged
            // bytes are encoded, but the encoded output still
            // fits and nothing reaches the wire
            auto n2 = capy::buffer_copy(
                sr.prepare(tmp),
                capy::const_buffer(body.data() + 20, 24));
            BOOST_TEST_EQ(n2, 24u);
            auto [ec2] = co_await sr.commit(n2);
            BOOST_TEST(!ec2);
            BOOST_TEST_EQ(enc.calls, 1u);
            BOOST_TEST(server.data().empty());

            // staged bytes present at commit_eof() are encoded
            // before the encoder is finished
            auto n3 = capy::buffer_copy(
                sr.prepare(tmp),
                capy::const_buffer(body.data() + 44, 10));
            BOOST_TEST_EQ(n3, 10u);
            auto [ec3] = co_await sr.commit_eof(n3);
            BOOST_TEST(!ec3);
            BOOST_TEST(sr.is_done());
        }());

        // everything fit before the header went out: chunked
        // is replaced with the encoded length
        BOOST_TEST_EQ(enc.calls, 2u);
        BOOST_TEST(enc.finished);
        BOOST_TEST(!req.chunked());
        BOOST_TEST_EQ(req.content_length().value(), 54u);
        BOOST_TEST_EQ(
            server.data(),
            std::string(req.buffer()) + encoded(body));
    }

    void
    testEncoderCommitTriggersFlush()
    {
        // A commit-triggered drain that overflows the output
        // buffer sends the header and a full chunk mid-commit;
        // the remainder stays buffered for the final flush;
        // 64 == 0x40, 32 == 0x20.
        std::string const body = make_body(96);

        auto req = make_request();
        req.set(http::field::content_encoding, "test");
        auto [client, server] = capy::test::make_stream_pair();
        test_encoder enc;

        // a staging buffer larger than the output buffer, so a
        // single commit overflows it
        auto ecfg = cfg;
        ecfg.enc_buffer = 96;

        capy::test::run_blocking()([&]() -> capy::task<>
        {
            capy::any_write_stream ws(&client);
            serializer sr(ecfg, &ws);
            sr.reset(&req, &enc);

            capy::mutable_buffer tmp[2];
            auto n = capy::buffer_copy(
                sr.prepare(tmp), capy::make_buffer(body));
            BOOST_TEST_EQ(n, body.size());

            auto [ec1] = co_await sr.commit(n);
            BOOST_TEST(!ec1);
            BOOST_TEST_EQ(
                server.data(),
                std::string(req.buffer()) +
                    "40\r\n" + encoded(body).substr(0, 64));

            auto [ec2] = co_await sr.write_eof();
            BOOST_TEST(!ec2);
        }());

        std::string expected(req.buffer());
        expected += "40\r\n" + encoded(body).substr(0, 64);
        expected += "\r\n20\r\n" + encoded(body).substr(64, 32);
        expected += "\r\n0\r\n\r\n";
        BOOST_TEST(req.chunked());
        BOOST_TEST_EQ(server.data(), expected);
    }

    void
    testEncoderTrailerSpansFlush()
    {
        // The encoder finishes over multiple eof calls when its
        // trailer does not fit in the remaining output space; a
        // flush runs between the calls; 64 == 0x40.
        std::string const body = make_body(60);

        auto req = make_request();
        req.set(http::field::content_encoding, "test");
        auto [client, server] = capy::test::make_stream_pair();
        test_encoder enc("0123456789");

        capy::test::run_blocking()([&]() -> capy::task<>
        {
            capy::any_write_stream ws(&client);
            serializer sr(cfg, &ws);
            sr.reset(&req, &enc);

            auto [ec, n] = co_await sr.write_eof(
                capy::make_buffer(body));
            BOOST_TEST(!ec);
            BOOST_TEST_EQ(n, body.size());
            BOOST_TEST(sr.is_done());
        }());

        std::string expected(req.buffer());
        expected += "40\r\n" + encoded(body) + "0123";
        expected += "\r\n6\r\n456789";
        expected += "\r\n0\r\n\r\n";
        BOOST_TEST_EQ(enc.calls, 2u);
        BOOST_TEST(enc.finished);
        BOOST_TEST(req.chunked());
        BOOST_TEST_EQ(server.data(), expected);
    }

    void
    testEncoderContentLength()
    {
        // A sized request works with an encoder when the
        // declared length matches the encoded output (body
        // plus trailer).
        std::string const body = make_body(30);

        auto req = make_request(34);
        req.set(http::field::content_encoding, "test");
        auto [client, server] = capy::test::make_stream_pair();
        test_encoder enc("eof!");

        capy::test::run_blocking()([&]() -> capy::task<>
        {
            capy::any_write_stream ws(&client);
            serializer sr(cfg, &ws);
            sr.reset(&req, &enc);

            auto [ec, n] = co_await sr.write_eof(
                capy::make_buffer(body));
            BOOST_TEST(!ec);
            BOOST_TEST_EQ(n, body.size());
            BOOST_TEST(sr.is_done());
        }());

        BOOST_TEST(enc.finished);
        BOOST_TEST_EQ(
            server.data(),
            std::string(req.buffer()) +
                encoded(body) + "eof!");
    }

    void
    testEncoderContentLengthMismatch()
    {
        // encoded output exceeds the declared length
        {
            std::string const body = make_body(30);

            auto req = make_request(30);
            req.set(http::field::content_encoding, "test");
            auto [client, server] = capy::test::make_stream_pair();
            test_encoder enc("eof!");

            capy::test::run_blocking()([&]() -> capy::task<>
            {
                capy::any_write_stream ws(&client);
                serializer sr(cfg, &ws);
            sr.reset(&req, &enc);

                auto [ec, n] = co_await sr.write_eof(
                    capy::make_buffer(body));
                BOOST_TEST(ec == error::body_size_mismatch);
                BOOST_TEST(!sr.is_done());
            }());

            BOOST_TEST(server.data().empty());
        }

        // encoded output falls short of the declared length
        {
            std::string const body = make_body(30);

            auto req = make_request(40);
            req.set(http::field::content_encoding, "test");
            auto [client, server] = capy::test::make_stream_pair();
            test_encoder enc("eof!");

            capy::test::run_blocking()([&]() -> capy::task<>
            {
                capy::any_write_stream ws(&client);
                serializer sr(cfg, &ws);
            sr.reset(&req, &enc);

                auto [ec, n] = co_await sr.write_eof(
                    capy::make_buffer(body));
                BOOST_TEST(ec == error::body_size_mismatch);
                BOOST_TEST(!sr.is_done());
            }());

            BOOST_TEST(server.data().empty());
        }
    }

    void
    testEncoderFailure()
    {
        // the encoder fails before anything is flushed
        {
            std::string const body = make_body(20);

            auto req = make_request();
            req.set(http::field::content_encoding, "test");
            auto [client, server] = capy::test::make_stream_pair();
            test_encoder enc;
            enc.fail = make_error_code(std::errc::io_error);

            capy::test::run_blocking()([&]() -> capy::task<>
            {
                capy::any_write_stream ws(&client);
                serializer sr(cfg, &ws);
            sr.reset(&req, &enc);

                auto [ec, n] = co_await sr.write_eof(
                    capy::make_buffer(body));
                BOOST_TEST(ec == std::errc::io_error);
                BOOST_TEST_EQ(n, 0u);
                BOOST_TEST(!sr.is_done());
            }());

            BOOST_TEST_EQ(enc.calls, 1u);
            BOOST_TEST(server.data().empty());
        }

        // the encoder fails mid-stream, after encoded output
        // has already been buffered
        {
            std::string const body = make_body(64);

            auto req = make_request();
            req.set(http::field::content_encoding, "test");
            auto [client, server] = capy::test::make_stream_pair();
            test_encoder enc;

            capy::test::run_blocking()([&]() -> capy::task<>
            {
                capy::any_write_stream ws(&client);
                serializer sr(cfg, &ws);
            sr.reset(&req, &enc);

                auto [ec1, n1] = co_await sr.write(
                    capy::make_buffer(body));
                BOOST_TEST(!ec1);
                BOOST_TEST_EQ(n1, body.size());
                BOOST_TEST(server.data().empty());

                enc.fail = make_error_code(std::errc::io_error);
                auto [ec2, n2] = co_await sr.write(
                    capy::const_buffer("more", 4));
                BOOST_TEST(ec2 == std::errc::io_error);
                BOOST_TEST_EQ(n2, 0u);
                BOOST_TEST(!sr.is_done());
            }());

            // the bytes encoded before the failure were flushed
            // while making room for more output; 64 == 0x40
            BOOST_TEST_EQ(
                server.data(),
                std::string(req.buffer()) +
                    "40\r\n" + encoded(body));
        }
    }

    void
    testEncoderMultipleBuffers()
    {
        // the encoder walks every caller buffer in order,
        // including empty ones
        std::string const b1 = make_body(6);
        std::string const b2 = make_body(6);

        auto req = make_request();
        req.set(http::field::content_encoding, "test");
        auto [client, server] = capy::test::make_stream_pair();
        test_encoder enc;

        capy::test::run_blocking()([&]() -> capy::task<>
        {
            capy::any_write_stream ws(&client);
            serializer sr(cfg, &ws);
            sr.reset(&req, &enc);

            std::array<capy::const_buffer, 3> bufs{
                capy::make_buffer(b1),
                capy::const_buffer{},
                capy::make_buffer(b2) };

            auto [ec, n] = co_await sr.write_eof(bufs);
            BOOST_TEST(!ec);
            BOOST_TEST_EQ(n, b1.size() + b2.size());
            BOOST_TEST(sr.is_done());
        }());

        BOOST_TEST(enc.finished);
        BOOST_TEST_EQ(req.content_length().value(), 12u);
        BOOST_TEST_EQ(
            server.data(),
            std::string(req.buffer()) +
                encoded(b1) + encoded(b2));
    }

    void
    testEncoderWriteEofManyBuffers()
    {
        // More caller buffers than fit in one gather window:
        // write_eof() feeds the encoder window by window, with
        // eof deferred until the last window.
        std::string const body = make_body(24);

        auto req = make_request();
        req.set(http::field::content_encoding, "test");
        auto [client, server] = capy::test::make_stream_pair();
        test_encoder enc;

        capy::test::run_blocking()([&]() -> capy::task<>
        {
            capy::any_write_stream ws(&client);
            serializer sr(cfg, &ws);
            sr.reset(&req, &enc);

            std::array<
                capy::const_buffer, 24> bufs;
            for(std::size_t i = 0; i != bufs.size(); ++i)
                bufs[i] = { body.data() + i, 1 };

            auto [ec, n] = co_await sr.write_eof(bufs);
            BOOST_TEST(!ec);
            BOOST_TEST_EQ(n, body.size());
            BOOST_TEST(sr.is_done());
        }());

        BOOST_TEST(enc.finished);
        BOOST_TEST(!req.chunked());
        BOOST_TEST_EQ(req.content_length().value(), 24u);
        BOOST_TEST_EQ(
            server.data(),
            std::string(req.buffer()) + encoded(body));
    }

    void
    testEncoderWriteSome()
    {
        // A write_some() that would cross the encoder threshold
        // is not coalesced: the staged bytes are encoded first,
        // then the caller's bytes, and the returned count covers
        // only the caller's bytes.
        auto req = make_request();
        req.set(http::field::content_encoding, "test");
        auto [client, server] = capy::test::make_stream_pair();
        test_encoder enc;

        capy::test::run_blocking()([&]() -> capy::task<>
        {
            capy::any_write_stream ws(&client);
            serializer sr(cfg, &ws);
            sr.reset(&req, &enc);

            // stays below the threshold: staged, encoder not
            // started
            auto [ec1, n1] = co_await sr.write_some(
                capy::const_buffer("abcd", 4));
            BOOST_TEST(!ec1);
            BOOST_TEST_EQ(n1, 4u);
            BOOST_TEST_EQ(enc.calls, 0u);

            // reaches the threshold: everything goes through
            // the encoder, and the encoded bytes stay buffered
            auto [ec2, n2] = co_await sr.write_some(
                capy::const_buffer("efgh", 4));
            BOOST_TEST(!ec2);
            BOOST_TEST_EQ(n2, 4u);
            BOOST_TEST_EQ(enc.calls, 2u);
            BOOST_TEST(server.data().empty());

            auto [ec3] = co_await sr.write_eof();
            BOOST_TEST(!ec3);
        }());

        BOOST_TEST(enc.finished);
        BOOST_TEST_EQ(req.content_length().value(), 8u);
        BOOST_TEST_EQ(
            server.data(),
            std::string(req.buffer()) + encoded("abcdefgh"));
    }

    void
    testEncoderMove()
    {
        // moving mid-stream transfers staged input and encoder
        // state
        {
            auto req = make_request();
            req.set(http::field::content_encoding, "test");
            auto [client, server] = capy::test::make_stream_pair();
            test_encoder enc;

            capy::test::run_blocking()([&]() -> capy::task<>
            {
                capy::any_write_stream ws(&client);
                serializer sr1(cfg);
                sr1.reset(&ws, &req, &enc);

                auto [ec1, n1] = co_await sr1.write(
                    capy::const_buffer("abc", 3));
                BOOST_TEST(!ec1);
                BOOST_TEST_EQ(n1, 3u);

                serializer sr2(std::move(sr1));
                auto [ec2, n2] = co_await sr2.write_eof(
                    capy::const_buffer("defgh", 5));
                BOOST_TEST(!ec2);
                BOOST_TEST_EQ(n2, 5u);
                BOOST_TEST(sr2.is_done());

                // move-assignment into the moved-from shell
                sr1 = std::move(sr2);
                BOOST_TEST(sr1.is_done());
            }());

            BOOST_TEST_EQ(
                server.data(),
                std::string(req.buffer()) +
                    encoded("abcdefgh"));
        }

        // moving a serializer whose encoder was dropped must
        // transfer ownership of the shifted staging buffer;
        // deallocating at the wrong offset corrupts the heap
        {
            auto req = make_request();
            req.set(http::field::content_encoding, "test");
            auto [client, server] = capy::test::make_stream_pair();
            test_encoder enc;

            capy::test::run_blocking()([&]() -> capy::task<>
            {
                capy::any_write_stream ws(&client);
                serializer sr1(cfg);
                sr1.reset(&ws, &req, &enc);

                auto [ec1, n1] = co_await sr1.write(
                    capy::const_buffer("hello", 5));
                BOOST_TEST(!ec1);

                // dropping the encoder shifts the internal
                // buffer
                auto [ec2] = co_await sr1.write_eof();
                BOOST_TEST(!ec2);

                serializer sr2(std::move(sr1));
                BOOST_TEST(sr2.is_done());

                sr1 = std::move(sr2);
                BOOST_TEST(sr1.is_done());

                // self-move is a no-op
                auto* self = &sr1;
                sr1 = std::move(*self);
                BOOST_TEST(sr1.is_done());
            }());

            BOOST_TEST_EQ(
                server.data(),
                std::string(req.buffer()) + "hello");
        }
    }

    void
    testReset()
    {
        // reset() rebinds the serializer to a new stream,
        // message, and encoder for reuse. The first request
        // drops its encoder, which swaps the internal buffers;
        // reset() must restore the original layout so the
        // second request encodes with full capacity.
        auto req1 = make_request();
        req1.set(http::field::content_encoding, "test");
        auto req2 = make_request();
        req2.set(http::field::content_encoding, "test");
        std::string const body = make_body(200);

        auto [client1, server1] = capy::test::make_stream_pair();
        auto [client2, server2] = capy::test::make_stream_pair();
        test_encoder enc1;
        test_encoder enc2;

        capy::test::run_blocking()([&]() -> capy::task<>
        {
            capy::any_write_stream ws1(&client1);
            capy::any_write_stream ws2(&client2);

            serializer sr(cfg, &ws1);
            sr.reset(&req1, &enc1);
            BOOST_TEST(sr.stream() == &ws1);
            BOOST_TEST(sr.message() == &req1);

            // the small body drops the encoder
            auto [ec1, n1] = co_await sr.write_eof(
                capy::const_buffer("hello", 5));
            BOOST_TEST(!ec1);
            BOOST_TEST_EQ(n1, 5u);
            BOOST_TEST(sr.is_done());

            sr.reset(&ws2, &req2, &enc2);
            BOOST_TEST(sr.stream() == &ws2);
            BOOST_TEST(sr.message() == &req2);
            BOOST_TEST(!sr.is_done());

            auto [ec2, n2] = co_await sr.write(
                capy::make_buffer(body));
            BOOST_TEST(!ec2);
            BOOST_TEST_EQ(n2, body.size());

            auto [ec3] = co_await sr.write_eof();
            BOOST_TEST(!ec3);
            BOOST_TEST(sr.is_done());
        }());

        BOOST_TEST_EQ(enc1.calls, 0u);
        BOOST_TEST(
            server1.data().find("Content-Encoding") ==
            std::string_view::npos);
        BOOST_TEST_EQ(
            server1.data(),
            std::string(req1.buffer()) + "hello");

        // the second request streams encoded chunks sized by
        // the restored output buffer; 64 == 0x40
        auto const enc_body = encoded(body);
        std::string expected(req2.buffer());
        expected += "40\r\n" + enc_body.substr(0, 64);
        expected += "\r\n40\r\n" + enc_body.substr(64, 64);
        expected += "\r\n40\r\n" + enc_body.substr(128, 64);
        expected += "\r\n8\r\n" + enc_body.substr(192, 8);
        expected += "\r\n0\r\n\r\n";
        BOOST_TEST(enc2.finished);
        BOOST_TEST(req2.chunked());
        BOOST_TEST_EQ(server2.data(), expected);
    }

    void
    testResetAfterEncoderKept()
    {
        // reset() must also restore the layout when the
        // previous message kept its encoder: a following plain
        // message must send its own staged body, not the stale
        // contents of the encoder's output buffer, and
        // re-adding an encoder afterwards must not shift the
        // staging buffer out of the allocation.
        auto req1 = make_request();
        req1.set(http::field::content_encoding, "test");
        auto req2 = make_request(5);
        auto req3 = make_request();
        req3.set(http::field::content_encoding, "test");
        std::string const body1 = make_body(20);
        std::string const body3 = make_body(200);

        auto [client1, server1] = capy::test::make_stream_pair();
        auto [client2, server2] = capy::test::make_stream_pair();
        auto [client3, server3] = capy::test::make_stream_pair();
        test_encoder enc1;
        test_encoder enc3;

        capy::test::run_blocking()([&]() -> capy::task<>
        {
            capy::any_write_stream ws1(&client1);
            capy::any_write_stream ws2(&client2);
            capy::any_write_stream ws3(&client3);

            serializer sr(cfg, &ws1);
            sr.reset(&req1, &enc1);

            // the body crosses the threshold: the encoder is
            // kept
            auto [ec1, n1] = co_await sr.write_eof(
                capy::make_buffer(body1));
            BOOST_TEST(!ec1);
            BOOST_TEST_EQ(n1, body1.size());
            BOOST_TEST(sr.is_done());

            sr.reset(&ws2, &req2);
            auto [ec2, n2] = co_await sr.write(
                capy::const_buffer("hello", 5));
            BOOST_TEST(!ec2);
            auto [ec3] = co_await sr.write_eof();
            BOOST_TEST(!ec3);
            BOOST_TEST(sr.is_done());

            sr.reset(&ws3, &req3, &enc3);
            auto [ec4, n4] = co_await sr.write(
                capy::make_buffer(body3));
            BOOST_TEST(!ec4);
            BOOST_TEST_EQ(n4, body3.size());
            auto [ec5] = co_await sr.write_eof();
            BOOST_TEST(!ec5);
            BOOST_TEST(sr.is_done());
        }());

        BOOST_TEST_EQ(
            server1.data(),
            std::string(req1.buffer()) + encoded(body1));

        BOOST_TEST_EQ(
            server2.data(),
            std::string(req2.buffer()) + "hello");

        // the third request streams encoded chunks sized by the
        // restored output buffer; 64 == 0x40
        auto const enc_body = encoded(body3);
        std::string expected(req3.buffer());
        expected += "40\r\n" + enc_body.substr(0, 64);
        expected += "\r\n40\r\n" + enc_body.substr(64, 64);
        expected += "\r\n40\r\n" + enc_body.substr(128, 64);
        expected += "\r\n8\r\n" + enc_body.substr(192, 8);
        expected += "\r\n0\r\n\r\n";
        BOOST_TEST(req3.chunked());
        BOOST_TEST_EQ(server3.data(), expected);
    }

    void
    testHeadContentLength()
    {
        // A head message sends only the header; the declared
        // Content-Length describes the body a non-head message
        // would have carried, and stays untouched.
        auto req = make_request(5);
        auto req2 = make_request(5);

        auto [client1, server1] = capy::test::make_stream_pair();
        auto [client2, server2] = capy::test::make_stream_pair();

        capy::test::run_blocking()([&]() -> capy::task<>
        {
            capy::any_write_stream ws1(&client1);
            capy::any_write_stream ws2(&client2);

            serializer sr(cfg, &ws1);
            sr.reset(&req, nullptr, true);
            BOOST_TEST(!sr.is_done());

            auto [ec1] = co_await sr.write_eof();
            BOOST_TEST(!ec1);
            BOOST_TEST(sr.is_done());

            // the head flag does not stick across reset()
            sr.reset(&ws2, &req2);
            auto [ec2, n] = co_await sr.write(
                capy::const_buffer("hello", 5));
            BOOST_TEST(!ec2);
            auto [ec3] = co_await sr.write_eof();
            BOOST_TEST(!ec3);
        }());

        BOOST_TEST_EQ(req.content_length().value(), 5u);
        BOOST_TEST_EQ(server1.data(), std::string(req.buffer()));
        BOOST_TEST_EQ(
            server2.data(),
            std::string(req2.buffer()) + "hello");
    }

    void
    testHeadChunked()
    {
        // A chunked head message keeps Transfer-Encoding in the
        // header to describe the framing a non-head message
        // would have used; no framing bytes reach the wire.
        auto req = make_request();
        auto [client, server] = capy::test::make_stream_pair();

        capy::test::run_blocking()([&]() -> capy::task<>
        {
            capy::any_write_stream ws(&client);
            serializer sr(cfg, &ws);
            sr.reset(&req, nullptr, true);

            auto [ec] = co_await sr.write_eof();
            BOOST_TEST(!ec);
            BOOST_TEST(sr.is_done());
        }());

        BOOST_TEST(req.chunked());
        BOOST_TEST(
            server.data().find("Content-Length") ==
            std::string_view::npos);
        BOOST_TEST_EQ(server.data(), std::string(req.buffer()));
    }

    void
    testHeadBodyMismatch()
    {
        // buffered body bytes are rejected at eof, even when
        // they match the declared Content-Length
        {
            auto req = make_request(5);
            auto [client, server] = capy::test::make_stream_pair();

            capy::test::run_blocking()([&]() -> capy::task<>
            {
                capy::any_write_stream ws(&client);
                serializer sr(cfg, &ws);
                sr.reset(&req, nullptr, true);

                auto [ec1, n] = co_await sr.write(
                    capy::const_buffer("hello", 5));
                BOOST_TEST(!ec1);
                BOOST_TEST_EQ(n, 5u);

                auto [ec2] = co_await sr.write_eof();
                BOOST_TEST(ec2 == error::body_size_mismatch);
                BOOST_TEST(!sr.is_done());
            }());

            BOOST_TEST(server.data().empty());
        }

        // a direct write is rejected before the header goes out
        {
            std::string const body(cfg.direct_thr, 'x');

            auto req = make_request();
            auto [client, server] = capy::test::make_stream_pair();

            capy::test::run_blocking()([&]() -> capy::task<>
            {
                capy::any_write_stream ws(&client);
                serializer sr(cfg, &ws);
                sr.reset(&req, nullptr, true);

                auto [ec, n] = co_await sr.write(
                    capy::make_buffer(body));
                BOOST_TEST(ec == error::body_size_mismatch);
                BOOST_TEST(!sr.is_done());
            }());

            BOOST_TEST(server.data().empty());
        }

        // write_eof() with caller buffers
        {
            auto req = make_request();
            auto [client, server] = capy::test::make_stream_pair();

            capy::test::run_blocking()([&]() -> capy::task<>
            {
                capy::any_write_stream ws(&client);
                serializer sr(cfg, &ws);
                sr.reset(&req, nullptr, true);

                auto [ec, n] = co_await sr.write_eof(
                    capy::const_buffer("hello", 5));
                BOOST_TEST(ec == error::body_size_mismatch);
                BOOST_TEST(!sr.is_done());
            }());

            BOOST_TEST(server.data().empty());
        }

        // prepare()/commit_eof()
        {
            auto req = make_request(5);
            auto [client, server] = capy::test::make_stream_pair();

            capy::test::run_blocking()([&]() -> capy::task<>
            {
                capy::any_write_stream ws(&client);
                serializer sr(cfg, &ws);
                sr.reset(&req, nullptr, true);

                capy::mutable_buffer tmp[2];
                auto n = capy::buffer_copy(
                    sr.prepare(tmp),
                    capy::const_buffer("hello", 5));
                BOOST_TEST_EQ(n, 5u);

                auto [ec] = co_await sr.commit_eof(n);
                BOOST_TEST(ec == error::body_size_mismatch);
                BOOST_TEST(!sr.is_done());
            }());

            BOOST_TEST(server.data().empty());
        }
    }

    void
    testHeadEncoder()
    {
        // A head message never invokes its encoder: the header
        // goes out as-is, with Content-Encoding intact, and the
        // serializer remains reusable for a plain message.
        {
            auto req = make_request();
            req.set(http::field::content_encoding, "test");
            auto req2 = make_request(5);

            auto [client1, server1] = capy::test::make_stream_pair();
            auto [client2, server2] = capy::test::make_stream_pair();
            test_encoder enc;

            capy::test::run_blocking()([&]() -> capy::task<>
            {
                capy::any_write_stream ws1(&client1);
                capy::any_write_stream ws2(&client2);

                serializer sr(cfg, &ws1);
                sr.reset(&req, &enc, true);

                auto [ec1] = co_await sr.write_eof();
                BOOST_TEST(!ec1);
                BOOST_TEST(sr.is_done());

                sr.reset(&ws2, &req2);
                auto [ec2, n] = co_await sr.write(
                    capy::const_buffer("hello", 5));
                BOOST_TEST(!ec2);
                auto [ec3] = co_await sr.write_eof();
                BOOST_TEST(!ec3);
            }());

            BOOST_TEST_EQ(enc.calls, 0u);
            BOOST_TEST(req.chunked());
            BOOST_TEST(
                server1.data().find("Content-Encoding: test") !=
                std::string_view::npos);
            BOOST_TEST_EQ(
                server1.data(), std::string(req.buffer()));
            BOOST_TEST_EQ(
                server2.data(),
                std::string(req2.buffer()) + "hello");
        }

        // body bytes staged for the encoder are rejected, and
        // the encoder is never invoked
        {
            auto req = make_request();
            req.set(http::field::content_encoding, "test");
            auto [client, server] = capy::test::make_stream_pair();
            test_encoder enc;

            capy::test::run_blocking()([&]() -> capy::task<>
            {
                capy::any_write_stream ws(&client);
                serializer sr(cfg, &ws);
                sr.reset(&req, &enc, true);

                // below enc_thr: staged without invoking the
                // encoder
                auto [ec1, n] = co_await sr.write(
                    capy::const_buffer("hello", 5));
                BOOST_TEST(!ec1);
                BOOST_TEST_EQ(n, 5u);

                auto [ec2] = co_await sr.write_eof();
                BOOST_TEST(ec2 == error::body_size_mismatch);
                BOOST_TEST(!sr.is_done());
            }());

            BOOST_TEST_EQ(enc.calls, 0u);
            BOOST_TEST(server.data().empty());
        }

        // commit() surfaces the mismatch when it triggers a
        // flush
        {
            auto req = make_request();
            req.set(http::field::content_encoding, "test");
            auto [client, server] = capy::test::make_stream_pair();
            test_encoder enc;

            capy::test::run_blocking()([&]() -> capy::task<>
            {
                capy::any_write_stream ws(&client);
                serializer sr(cfg, &ws);
                sr.reset(&req, &enc, true);

                capy::mutable_buffer tmp[2];
                auto n = capy::buffer_copy(
                    sr.prepare(tmp),
                    capy::const_buffer("x", 1));
                BOOST_TEST_EQ(n, 1u);

                auto [ec] = co_await sr.commit_eof(n);
                BOOST_TEST(ec == error::body_size_mismatch);
                BOOST_TEST(!sr.is_done());
            }());

            BOOST_TEST_EQ(enc.calls, 0u);
            BOOST_TEST(server.data().empty());
        }
    }

    void
    testEncoderErrorInjection()
    {
        capy::test::fuse f;
        auto r = f.armed([&](capy::test::fuse&) -> capy::task<>
        {
            std::string const body = make_body(100);

            auto req = make_request();
            req.set(http::field::content_encoding, "test");
            test_encoder enc;

            auto [client, server] =
                capy::test::make_stream_pair(f);

            capy::any_write_stream ws(&client);
            serializer sr(cfg, &ws);
            sr.reset(&req, &enc);

            if(auto [ec, n] = co_await sr.write(
                capy::make_buffer(body)); ec)
            {
                BOOST_TEST(!sr.is_done());
                co_return;
            }

            if(auto [ec] = co_await sr.write_eof(); ec)
            {
                BOOST_TEST(!sr.is_done());
                co_return;
            }

            BOOST_TEST(sr.is_done());
            BOOST_TEST(enc.finished);

            auto const enc_body = encoded(body);
            std::string expected(req.buffer());
            expected += "40\r\n" + enc_body.substr(0, 64);
            expected += "\r\n24\r\n" + enc_body.substr(64, 36);
            expected += "\r\n0\r\n\r\n";
            BOOST_TEST_EQ(server.data(), expected);
        });
        BOOST_TEST(r.success);
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
        testChunkedShortWrites();
        testContentLengthShortWrites();
        testPrepareCommitShortWrites();
        testShortWriteEofDoesNotTruncate();
        testChunkedPreservesWriteOrder();
        testErrorInjection();
        testEncoderSmallBodyDropsEncoder();
        testEncoderEmptyBody();
        testEncoderPrepareCommitEof();
        testEncoderThreshold();
        testEncoderStagedAndTail();
        testEncoderLargeBodyChunked();
        testEncoderCommit();
        testEncoderCommitTriggersFlush();
        testEncoderTrailerSpansFlush();
        testEncoderContentLength();
        testEncoderContentLengthMismatch();
        testEncoderFailure();
        testEncoderMultipleBuffers();
        testEncoderWriteEofManyBuffers();
        testEncoderWriteSome();
        testEncoderMove();
        testReset();
        testResetAfterEncoderKept();
        testHeadContentLength();
        testHeadChunked();
        testHeadBodyMismatch();
        testHeadEncoder();
        testEncoderErrorInjection();
    }
};

TEST_SUITE(serializer_test, "boost.burl.detail.serializer");

} // namespace detail
} // namespace burl
} // namespace boost
