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

#include <boost/capy/test/fuse.hpp>
#include <boost/capy/test/run_blocking.hpp>
#include <boost/capy/test/stream.hpp>
#include <boost/capy/test/write_stream.hpp>
#include <boost/http/request.hpp>

#include "test_suite.hpp"

namespace boost
{
namespace burl
{
namespace detail
{

class serializer_test
{
    // A scaled-down config so that framing thresholds (staged
    // vs. direct writes, commit-triggered flushes) are crossed
    // with tiny bodies, and so tests keep exercising the same
    // paths if the default config values change.
    static constexpr serializer::config cfg{
        .buffer_size = 64,
        .min_prepare = 32,
        .min_direct  = 16 };

    static http::request
    make_request()
    {
        http::request req;
        req.set_chunked(true);
        return req;
    }

    static http::request
    make_request(std::size_t cl)
    {
        http::request req;
        req.set_content_length(cl);
        return req;
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
            serializer sr(ws, req, cfg);
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
        std::string const body(cfg.min_direct, 'x');

        auto req = make_request(body.size());
        auto [client, server] = capy::test::make_stream_pair();

        capy::test::run_blocking()([&]() -> capy::task<>
        {
            capy::any_write_stream ws(&client);
            serializer sr(ws, req, cfg);

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
            serializer sr(ws, req, cfg);

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
                serializer sr(ws, req, cfg);

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
                serializer sr(ws, req, cfg);

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
            serializer sr(ws, req, cfg);

            // The body stays below min_direct, so it is fully
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
        BOOST_TEST_EQ(req.payload_size(), 11u);
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
            serializer sr(ws, req, cfg);

            auto [ec, n] = co_await sr.write_eof(
                capy::const_buffer("hello", 5));
            BOOST_TEST(!ec);
            BOOST_TEST_EQ(n, 5u);
        }());

        BOOST_TEST(!req.chunked());
        BOOST_TEST_EQ(req.payload_size(), 5u);
        BOOST_TEST_EQ(
            server.data(),
            std::string(req.buffer()) + "hello");
    }

    void
    testChunkedLargeBody()
    {
        std::string const body(cfg.min_direct, 'x');

        auto req = make_request();
        auto [client, server] = capy::test::make_stream_pair();

        capy::test::run_blocking()([&]() -> capy::task<>
        {
            capy::any_write_stream ws(&client);
            serializer sr(ws, req, cfg);

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
        std::string const body(cfg.min_direct, 'x');

        auto req = make_request();
        auto [client, server] = capy::test::make_stream_pair();

        capy::test::run_blocking()([&]() -> capy::task<>
        {
            capy::any_write_stream ws(&client);
            serializer sr(ws, req, cfg);

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
        std::string const body(cfg.min_direct, 'x');

        auto req = make_request();
        auto [client, server] = capy::test::make_stream_pair();

        capy::test::run_blocking()([&]() -> capy::task<>
        {
            capy::any_write_stream ws(&client);
            serializer sr(ws, req, cfg);

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
            serializer sr(ws, req);
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
            serializer sr(ws, req, cfg);

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
            serializer sr(ws, req, cfg);

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
            serializer sr(ws, req, cfg);

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
        expected += "3C\r\n" + body + "\r\n";
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
            serializer sr(ws, req, cfg);

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
        serializer sr(ws, req, cfg);

        BOOST_TEST(sr.prepare({}).empty());

        // The staging buffer is untouched and remains fully
        // available.
        capy::mutable_buffer tmp[2];
        auto dest = sr.prepare(tmp);
        BOOST_TEST_EQ(dest.size(), 1u);
        BOOST_TEST_EQ(capy::buffer_size(dest), cfg.buffer_size);
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
            std::string const body(cfg.buffer_size, 'z');

            auto req = make_request(body.size());
            capy::test::write_stream ws_impl(f);

            capy::any_write_stream ws(&ws_impl);
            serializer sr(ws, req, cfg);

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
                capy::buffer_size(dest), cfg.buffer_size);
        });
        BOOST_TEST(r.success);
    }

    void
    testChunkedShortWrites()
    {
        // The staging buffer holds raw body bytes only, so the
        // full capacity is stageable as one chunk; 64 == 0x40.
        std::string const body(cfg.buffer_size, 'z');

        auto req = make_request();
        capy::test::write_stream ws_impl({}, 1);

        capy::test::run_blocking()([&]() -> capy::task<>
        {
            capy::any_write_stream ws(&ws_impl);
            serializer sr(ws, req, cfg);

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
        std::string const b1(cfg.min_direct, 'x');
        std::string const b2(cfg.min_direct, 'y');

        auto req = make_request(b1.size() + b2.size());
        capy::test::write_stream ws_impl({}, 1);

        capy::test::run_blocking()([&]() -> capy::task<>
        {
            capy::any_write_stream ws(&ws_impl);
            serializer sr(ws, req, cfg);

            // The first drain writes the header in full and
            // exactly one body byte.
            auto [ec1, n1] = co_await sr.write_some(
                capy::make_buffer(b1));
            BOOST_TEST(!ec1);
            BOOST_TEST_EQ(n1, 1u);
            BOOST_TEST_EQ(
                ws_impl.data(),
                std::string(req.buffer()) + "x");

            // The rest of the first buffer is below min_direct
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
            serializer sr(ws, req, cfg);

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
            serializer sr(ws, req, cfg);

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
        std::string const body(cfg.min_direct, 'x');

        auto req = make_request();
        capy::test::write_stream ws_impl({}, 1);

        capy::test::run_blocking()([&]() -> capy::task<>
        {
            capy::any_write_stream ws(&ws_impl);
            serializer sr(ws, req, cfg);

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
            std::string const body(cfg.min_direct, 'x');

            auto req = make_request();

            auto [client, server] =
                capy::test::make_stream_pair(f);

            capy::any_write_stream ws(&client);
            serializer sr(ws, req, cfg);

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
    }
};

TEST_SUITE(serializer_test, "boost.burl.detail.serializer");

} // namespace detail
} // namespace burl
} // namespace boost
