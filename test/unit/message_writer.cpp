//
// Copyright (c) 2026 Mohammad Nejati
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

// Test that header file is self-contained.
#include <boost/burl/message_writer.hpp>

#include <boost/burl/error.hpp>
#include <boost/burl/fields.hpp>
#include <boost/burl/request_head.hpp>
#include <boost/burl/serializer.hpp>

#include <boost/capy/error.hpp>
#include <boost/capy/test/fuse.hpp>
#include <boost/capy/test/run_blocking.hpp>
#include <boost/capy/test/stream.hpp>
#include <boost/capy/test/write_stream.hpp>
#include <boost/http/concept/buffer_sink.hpp>
#include <boost/http/concept/write_sink.hpp>
#include <boost/http/io/any_buffer_sink.hpp>

#include <string>

#include "test_suite.hpp"

namespace boost
{
namespace burl
{

// One type serves all three body-writing concepts.
static_assert(
    capy::WriteStream<message_writer<capy::test::write_stream>>);
static_assert(
    http::WriteSink<message_writer<capy::test::write_stream>>);
static_assert(
    http::BufferSink<message_writer<capy::test::write_stream>>);

class message_writer_test
{
    static inline serializer::config const cfg{
        .stage_buffer  = 64,
        .min_prepare   = 32,
        .min_direct    = 16,
        .enc_buffer    = 32,
        .enc_threshold = 8 };

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

    static std::string
    make_body(std::size_t n)
    {
        std::string s(n, '\0');
        for(std::size_t i = 0; i != n; ++i)
            s[i] = static_cast<char>('0' + i % 64);
        return s;
    }

    // A stream that accepts at most `budget` octets and then
    // completes with `capy::error::canceled` alongside the
    // partial count — the case neither capy::test::stream nor
    // the fuse doubles produce, and the one the consume-before-
    // check discipline exists for.
    struct flaky_write_stream
    {
        std::string data;
        std::size_t budget = 0;

        template<capy::ConstBufferSequence CB>
        auto
        write_some(CB buffers)
        {
            struct awaitable
            {
                flaky_write_stream* self_;
                CB buffers_;

                bool
                await_ready() const noexcept
                {
                    return false;
                }

                bool
                await_suspend(
                    std::coroutine_handle<>,
                    capy::io_env const*) noexcept
                {
                    return false;
                }

                capy::io_result<std::size_t>
                await_resume()
                {
                    auto const total =
                        capy::buffer_size(buffers_);
                    auto const n =
                        (std::min)(self_->budget, total);
                    self_->budget -= n;

                    auto const old = self_->data.size();
                    self_->data.resize(old + n);
                    capy::buffer_copy(
                        capy::make_buffer(
                            self_->data.data() + old, n),
                        buffers_,
                        n);

                    if(n < total)
                        return { capy::error::canceled, n };
                    return { std::error_code(), n };
                }
            };
            return awaitable{ this, buffers };
        }
    };

public:
    void
    testWrite()
    {
        auto req = make_request(5);
        capy::test::write_stream ws;

        capy::test::run_blocking()([&]() -> capy::task<>
        {
            serializer sr(cfg);
            message_writer writer(&ws, &sr);
            sr.start(&req);

            auto [ec1, n] = co_await writer.write(
                capy::const_buffer("hello", 5));
            BOOST_TEST(!ec1);
            BOOST_TEST_EQ(n, 5u);
            BOOST_TEST(!sr.is_done());

            auto [ec2] = co_await writer.write_eof();
            BOOST_TEST(!ec2);
            BOOST_TEST(sr.is_done());
        }());

        BOOST_TEST_EQ(
            ws.data(), std::string(req.buffer()) + "hello");
    }

    void
    testWriteSome()
    {
        // write_some drives the same loop as write; nothing here
        // makes it stop short of the whole input
        auto req = make_request(5);
        capy::test::write_stream ws;

        capy::test::run_blocking()([&]() -> capy::task<>
        {
            serializer sr(cfg);
            message_writer writer(&ws, &sr);
            sr.start(&req);

            auto [ec1, n] = co_await writer.write_some(
                capy::const_buffer("hello", 5));
            BOOST_TEST(!ec1);
            BOOST_TEST_EQ(n, 5u);
            BOOST_TEST(!sr.is_done());

            auto [ec2] = co_await writer.write_eof();
            BOOST_TEST(!ec2);
            BOOST_TEST(sr.is_done());
        }());

        BOOST_TEST_EQ(
            ws.data(), std::string(req.buffer()) + "hello");
    }

    void
    testCommitEof()
    {
        // the body is generated in place and the last commit
        // ends the message
        auto req = make_request();
        capy::test::write_stream ws;

        capy::test::run_blocking()([&]() -> capy::task<>
        {
            serializer sr(cfg);
            message_writer writer(&ws, &sr);
            sr.start(&req);

            capy::mutable_buffer tmp[2];
            auto const n = capy::buffer_copy(
                writer.prepare(tmp),
                capy::const_buffer("hello", 5));
            BOOST_TEST_EQ(n, 5u);

            auto [ec] = co_await writer.commit_eof(n);
            BOOST_TEST(!ec);
            BOOST_TEST(sr.is_done());
        }());

        // the whole body was staged before the header went out,
        // so chunked framing converted to Content-Length
        BOOST_TEST(!req.chunked());
        BOOST_TEST_EQ(req.content_length().value(), 5u);
        BOOST_TEST_EQ(
            ws.data(), std::string(req.buffer()) + "hello");
    }

    void
    testCommitWithoutDrainPressure()
    {
        // A commit that leaves the prepare window large raises
        // no drain pressure, so it does no I/O at all.
        auto req = make_request();
        capy::test::write_stream ws;

        capy::test::run_blocking()([&]() -> capy::task<>
        {
            serializer sr(cfg);
            message_writer writer(&ws, &sr);
            sr.start(&req);

            capy::mutable_buffer tmp[2];
            auto const n = capy::buffer_copy(
                writer.prepare(tmp),
                capy::const_buffer("hello", 5));

            auto [ec1] = co_await writer.commit(n);
            BOOST_TEST(!ec1);
            BOOST_TEST(!sr.should_drain());
            BOOST_TEST(ws.data().empty());

            auto [ec2] = co_await writer.write_eof();
            BOOST_TEST(!ec2);
            BOOST_TEST(sr.is_done());
        }());

        BOOST_TEST_EQ(
            ws.data(), std::string(req.buffer()) + "hello");
    }

    void
    testSerializerError()
    {
        // a framing error surfaces from the drive, with nothing
        // handed to the stream
        auto req = make_request(10);
        capy::test::write_stream ws;

        capy::test::run_blocking()([&]() -> capy::task<>
        {
            serializer sr(cfg);
            message_writer writer(&ws, &sr);
            sr.start(&req);

            auto [ec, n] = co_await writer.write_eof(
                capy::const_buffer("hello", 5));
            BOOST_TEST(ec == error::body_size_mismatch);
            BOOST_TEST_EQ(n, 0u);
            BOOST_TEST(!sr.is_done());
        }());

        BOOST_TEST(ws.data().empty());
    }

    void
    testWriteEofMultipleBuffers()
    {
        std::string const b1 = make_body(20);
        std::string const b2 = make_body(20);
        auto req = make_request(40);
        capy::test::write_stream ws;

        capy::test::run_blocking()([&]() -> capy::task<>
        {
            serializer sr(cfg);
            message_writer writer(&ws, &sr);
            sr.start(&req);

            std::array<capy::const_buffer, 2> bufs{
                capy::make_buffer(b1),
                capy::make_buffer(b2) };
            auto [ec, n] = co_await writer.write_eof(bufs);
            BOOST_TEST(!ec);
            BOOST_TEST_EQ(n, 40u);
            BOOST_TEST(sr.is_done());
        }());

        BOOST_TEST_EQ(
            ws.data(),
            std::string(req.buffer()) + b1 + b2);
    }

    void
    testShortWrites()
    {
        // A stream that transfers one octet per write exercises
        // the drive loop's partial-consume re-materialization
        // end to end; 64 == 0x40.
        std::string const body(cfg.stage_buffer, 'z');
        auto req = make_request();
        capy::test::write_stream ws({}, 1);

        capy::test::run_blocking()([&]() -> capy::task<>
        {
            serializer sr(cfg);
            message_writer writer(&ws, &sr);
            sr.start(&req);

            capy::mutable_buffer tmp[2];
            auto const n = capy::buffer_copy(
                writer.prepare(tmp), capy::make_buffer(body));
            BOOST_TEST_EQ(n, body.size());

            auto [ec1] = co_await writer.commit(n);
            BOOST_TEST(!ec1);

            BOOST_TEST_EQ(ws.data(),
                std::string(req.buffer()) + "40\r\n" + body);

            auto [ec2, m] = co_await writer.write(
                capy::const_buffer("hello", 5));
            BOOST_TEST(!ec2);
            BOOST_TEST_EQ(m, 5u);

            auto [ec3] = co_await writer.write_eof();
            BOOST_TEST(!ec3);
            BOOST_TEST(sr.is_done());
        }());

        std::string expected(req.buffer());
        expected += "40\r\n" + body + "\r\n";
        expected += "5\r\nhello\r\n";
        expected += "0\r\n\r\n";
        BOOST_TEST(req.chunked());
        BOOST_TEST_EQ(ws.data(), expected);
    }

    void
    testAnyBufferSink()
    {
        // the writer drops into the type-erased sink, and the
        // native write path keeps working through the erasure
        std::string const body(cfg.min_direct, 'x');
        auto req = make_request();
        capy::test::write_stream ws;

        capy::test::run_blocking()([&]() -> capy::task<>
        {
            serializer sr(cfg);
            message_writer writer(&ws, &sr);
            sr.start(&req);

            http::any_buffer_sink sink(&writer);

            auto [ec1, n1] = co_await sink.write_some(
                capy::make_buffer(body));
            BOOST_TEST(!ec1);
            BOOST_TEST_EQ(n1, body.size());

            auto [ec2, n2] = co_await sink.write(
                capy::make_buffer(body));
            BOOST_TEST(!ec2);
            BOOST_TEST_EQ(n2, body.size());

            auto [ec3, n3] = co_await sink.write_eof(
                capy::const_buffer("hello", 5));
            BOOST_TEST(!ec3);
            BOOST_TEST_EQ(n3, 5u);
            BOOST_TEST(sr.is_done());
        }());

        std::string expected(req.buffer());
        expected += "10\r\n" + body + "\r\n";
        expected += "10\r\n" + body + "\r\n";
        expected += "5\r\nhello\r\n";
        expected += "0\r\n\r\n";
        BOOST_TEST_EQ(ws.data(), expected);
    }

    void
    testWriteEofManyBuffers()
    {
        // More caller buffers than the descriptor storage of
        // the drive holds: frame() takes what fits, and the
        // remainder is supplied again until the body is done.
        std::string const body = make_body(24);

        // identity
        {
            auto req = make_request(body.size());
            capy::test::write_stream ws;

            capy::test::run_blocking()([&]() -> capy::task<>
            {
                serializer sr(cfg);
                message_writer writer(&ws, &sr);
                sr.start(&req);

                std::array<capy::const_buffer, 24> bufs;
                for(std::size_t i = 0; i != bufs.size(); ++i)
                    bufs[i] = { body.data() + i, 1 };

                auto [ec, n] = co_await writer.write_eof(bufs);
                BOOST_TEST(!ec);
                BOOST_TEST_EQ(n, body.size());
                BOOST_TEST(sr.is_done());
            }());

            BOOST_TEST_EQ(
                ws.data(), std::string(req.buffer()) + body);
        }

        // the drive presents the whole remaining body on every
        // call, so the end flag is never deferred: a chunked
        // message supplied entirely at eof is rewritten to
        // Content-Length although the body spans more
        // descriptors than one frame() call can return
        {
            auto req = make_request();
            capy::test::write_stream ws;

            capy::test::run_blocking()([&]() -> capy::task<>
            {
                serializer sr(cfg);
                message_writer writer(&ws, &sr);
                sr.start(&req);

                std::array<capy::const_buffer, 24> bufs;
                for(std::size_t i = 0; i != bufs.size(); ++i)
                    bufs[i] = { body.data() + i, 1 };

                auto [ec, n] = co_await writer.write_eof(bufs);
                BOOST_TEST(!ec);
                BOOST_TEST_EQ(n, body.size());
                BOOST_TEST(sr.is_done());
            }());

            BOOST_TEST(!req.chunked());
            BOOST_TEST_EQ(
                req.content_length().value_or(0), body.size());
            BOOST_TEST_EQ(
                ws.data(), std::string(req.buffer()) + body);
        }
    }

    void
    testWriteHeader()
    {
        // the expect-100-continue shape: the header goes out
        // on its own, the body follows later
        {
            auto req = make_request(5);
            capy::test::write_stream ws;

            capy::test::run_blocking()([&]() -> capy::task<>
            {
                serializer sr(cfg);
                message_writer writer(&ws, &sr);
                sr.start(&req);

                auto [ec1] = co_await writer.write_header();
                BOOST_TEST(!ec1);
                BOOST_TEST_EQ(
                    ws.data(), std::string(req.buffer()));
                BOOST_TEST(sr.is_header_done());
                BOOST_TEST(!sr.is_done());

                auto [ec2, n] = co_await writer.write_eof(
                    capy::const_buffer("hello", 5));
                BOOST_TEST(!ec2);
                BOOST_TEST_EQ(n, 5u);
                BOOST_TEST(sr.is_done());
            }());

            BOOST_TEST_EQ(
                ws.data(), std::string(req.buffer()) + "hello");
        }

        // sending the header seals the framing: a small body
        // of undeclared size stays chunked
        {
            auto req = make_request();
            capy::test::write_stream ws;

            capy::test::run_blocking()([&]() -> capy::task<>
            {
                serializer sr(cfg);
                message_writer writer(&ws, &sr);
                sr.start(&req);

                auto [ec1] = co_await writer.write_header();
                BOOST_TEST(!ec1);

                auto [ec2, n] = co_await writer.write_eof(
                    capy::const_buffer("hello", 5));
                BOOST_TEST(!ec2);
                BOOST_TEST_EQ(n, 5u);
                BOOST_TEST(sr.is_done());
            }());

            BOOST_TEST(req.chunked());
            BOOST_TEST_EQ(
                ws.data(), std::string(req.buffer()) +
                    "5\r\nhello\r\n0\r\n\r\n");
        }
    }

    void
    testErrorInjection()
    {
        capy::test::fuse f;
        auto const r = f.armed(
            [&](capy::test::fuse&) -> capy::task<>
        {
            std::string const body(cfg.min_direct, 'x');
            auto req = make_request();
            auto [client, server] =
                capy::test::make_stream_pair(f);

            serializer sr(cfg);
            message_writer writer(&client, &sr);
            sr.start(&req);

            if(auto [ec, n] = co_await writer.write(
                capy::make_buffer(body)); ec)
            {
                BOOST_TEST(!sr.is_done());
                co_return;
            }

            if(auto [ec] = co_await writer.write_eof(); ec)
            {
                BOOST_TEST(!sr.is_done());
                co_return;
            }

            BOOST_TEST(sr.is_done());

            std::string expected(req.buffer());
            expected += "10\r\n" + body + "\r\n";
            expected += "0\r\n\r\n";
            BOOST_TEST_EQ(server.data(), expected);
        });
        BOOST_TEST(r.success);
    }

    void
    testCancelResume()
    {
        // A cancelled write completes with an error alongside a
        // partial count. The drive banks the count through
        // consume before it looks at the error, so the returned
        // total is the caller's cursor, and supplying the
        // unconsumed remainder resumes the message. The trailer
        // pins chunked framing, so the seven-octet budget walks
        // cancellation across the header, chunk prefix, body,
        // epilogue, and trailer section; 40 == 0x28.
        std::string const body = make_body(40);
        auto req = make_request();
        fields trailer;
        trailer.set("x-checksum", "abc123");
        flaky_write_stream ws;

        capy::test::run_blocking()([&]() -> capy::task<>
        {
            serializer sr(cfg);
            message_writer writer(&ws, &sr);
            sr.start(&req);
            sr.set_trailer(&trailer);

            std::string_view rem(body);
            for(;;)
            {
                ws.budget = 7;
                auto [ec, n] = co_await writer.write_eof(
                    capy::const_buffer(
                        rem.data(), rem.size()));
                rem.remove_prefix(n);
                if(!ec)
                    break;
                BOOST_TEST(ec == capy::cond::canceled);
                BOOST_TEST(!sr.is_done());
            }
            BOOST_TEST(sr.is_done());
            BOOST_TEST(rem.empty());
        }());

        BOOST_TEST(req.chunked());
        std::string expected(req.buffer());
        expected += "28\r\n" + body + "\r\n";
        expected += "0\r\n";
        expected += std::string(trailer.buffer());
        BOOST_TEST_EQ(ws.data, expected);
    }

    void
    testCancelResumeWrite()
    {
        // Resuming a cancelled write() is compositional: the
        // count already banked through consume is the caller's
        // cursor, and the remainder is re-issued.
        std::string const body = make_body(40);
        auto req = make_request(body.size());
        flaky_write_stream ws;

        capy::test::run_blocking()([&]() -> capy::task<>
        {
            serializer sr(cfg);
            message_writer writer(&ws, &sr);
            sr.start(&req);

            ws.budget = req.buffer().size() + 11;
            auto [ec, n] = co_await writer.write(
                capy::make_buffer(body));
            BOOST_TEST(ec == capy::cond::canceled);
            BOOST_TEST_EQ(n, 11u);
            BOOST_TEST(!sr.is_done());

            ws.budget = std::size_t(-1) / 2;
            auto [ec2, n2] = co_await writer.write(
                capy::make_buffer(
                    std::string_view(body).substr(n)));
            BOOST_TEST(!ec2);
            BOOST_TEST_EQ(n2, body.size() - n);

            auto [ec3] = co_await writer.write_eof();
            BOOST_TEST(!ec3);
            BOOST_TEST(sr.is_done());
        }());

        BOOST_TEST_EQ(
            ws.data, std::string(req.buffer()) + body);
    }

    void
    run()
    {
        testWrite();
        testWriteSome();
        testCommitEof();
        testCommitWithoutDrainPressure();
        testSerializerError();
        testWriteEofMultipleBuffers();
        testWriteEofManyBuffers();
        testShortWrites();
        testAnyBufferSink();
        testWriteHeader();
        testErrorInjection();
        testCancelResume();
        testCancelResumeWrite();
    }
};

TEST_SUITE(message_writer_test, "boost.burl.message_writer");

} // namespace burl
} // namespace boost
