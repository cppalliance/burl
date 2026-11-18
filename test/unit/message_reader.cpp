//
// Copyright (c) 2026 Mohammad Nejati
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

// Test that header file is self-contained.
#include <boost/burl/message_reader.hpp>

#include <boost/burl/response_parser.hpp>

#include <boost/capy/buffers.hpp>
#include <boost/capy/buffers/buffer_copy.hpp>
#include <boost/capy/buffers/make_buffer.hpp>
#include <boost/capy/cond.hpp>
#include <boost/capy/error.hpp>
#include <boost/capy/test/fuse.hpp>
#include <boost/capy/test/read_stream.hpp>
#include <boost/capy/test/run_blocking.hpp>
#include <boost/http/concept/buffer_source.hpp>
#include <boost/http/concept/read_source.hpp>
#include <boost/http/error.hpp>
#include <boost/http/io/any_buffer_source.hpp>

#include <algorithm>
#include <array>
#include <coroutine>
#include <cstddef>
#include <cstdio>
#include <span>
#include <string>
#include <string_view>
#include <tuple>

#include "test_suite.hpp"

namespace boost
{
namespace burl
{

// One type serves all three body-reading concepts.
static_assert(
    capy::ReadStream<message_reader<capy::test::read_stream>>);
static_assert(
    http::ReadSource<message_reader<capy::test::read_stream>>);
static_assert(
    http::BufferSource<message_reader<capy::test::read_stream>>);

class message_reader_test
{
    static std::string
    make_body(std::size_t n)
    {
        std::string s(n, '\0');
        for(std::size_t i = 0; i != n; ++i)
            s[i] = static_cast<char>('0' + i % 64);
        return s;
    }

    // The header of a response which declares its body size.
    static std::string
    make_head(std::size_t cl)
    {
        return
            "HTTP/1.1 200 OK\r\n"
            "Content-Length: " + std::to_string(cl) + "\r\n"
            "\r\n";
    }

    static std::string
    make_chunked_head()
    {
        return
            "HTTP/1.1 200 OK\r\n"
            "Transfer-Encoding: chunked\r\n"
            "\r\n";
    }

    // The body in chunks of at most `size` octets, then the
    // last chunk.
    static std::string
    make_chunks(
        std::string_view body,
        std::size_t size)
    {
        std::string s;
        while(!body.empty())
        {
            auto const part = body.substr(0, size);
            char hex[2 * sizeof(std::size_t) + 1];
            std::snprintf(hex, sizeof(hex), "%zx", part.size());
            s += hex;
            s += "\r\n";
            s += part;
            s += "\r\n";
            body.remove_prefix(part.size());
        }
        s += "0\r\n\r\n";
        return s;
    }

    // The octets a pull returned.
    static std::string
    str(std::span<capy::const_buffer const> data)
    {
        std::string s;
        for(auto const& b : data)
            s.append(static_cast<char const*>(b.data()), b.size());
        return s;
    }

    // One buffer per octet of a 24 octet array.
    static std::array<capy::mutable_buffer, 24>
    split(char* p)
    {
        std::array<capy::mutable_buffer, 24> a;
        for(std::size_t i = 0; i != a.size(); ++i)
            a[i] = { p + i, 1 };
        return a;
    }

    // A stream that delivers at most `budget` octets and then
    // completes with `capy::error::canceled` alongside the
    // partial count — the case neither capy::test::read_stream
    // nor the fuse produce, and the one committing before the
    // error check exists for.
    struct flaky_read_stream
    {
        std::string data;
        std::size_t pos = 0;
        std::size_t budget = 0;

        template<capy::MutableBufferSequence MB>
        auto
        read_some(MB buffers)
        {
            struct awaitable
            {
                flaky_read_stream* self_;
                MB buffers_;

                bool
                await_ready() const noexcept
                {
                    return false;
                }

                bool
                await_suspend(
                    std::coroutine_handle<>,
                    capy::await_context const*) noexcept
                {
                    return false;
                }

                capy::results<std::size_t>
                await_resume()
                {
                    auto const rest = std::string_view(
                        self_->data).substr(self_->pos);
                    auto const total = (std::min)(
                        capy::buffer_size(buffers_), rest.size());
                    if(total == 0)
                    {
                        if(capy::buffers_empty(buffers_))
                            return { std::error_code(), 0 };
                        return { capy::error::eof, 0 };
                    }

                    auto const n =
                        (std::min)(self_->budget, total);
                    self_->budget -= n;
                    self_->pos += n;
                    capy::buffer_copy(
                        buffers_,
                        capy::make_buffer(rest.data(), n));

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
    testReadHeader()
    {
        // delivered whole, and one octet at a time
        for(std::size_t max_read : { std::size_t(-1), std::size_t(1) })
        {
            capy::test::read_stream rs({}, max_read);
            rs.provide(make_head(5) + "hello");

            capy::test::run_blocking()([&]() -> capy::task<>
            {
                response_parser pr(response_parser::config{});
                message_reader reader(&rs, &pr);
                pr.start();

                auto [ec1] = co_await reader.read_header();
                BOOST_TEST(!ec1);
                BOOST_TEST(pr.got_header());
                BOOST_TEST_EQ(pr.get().status_int(), 200);

                // a second call reads nothing
                auto const left = rs.available();
                auto [ec2] = co_await reader.read_header();
                BOOST_TEST(!ec2);
                BOOST_TEST_EQ(rs.available(), left);
            }());

            // reading stops with the header when the stream
            // hands it over alone
            if(max_read == 1)
                BOOST_TEST_EQ(rs.available(), 5u);
        }
    }

    void
    testReadBody()
    {
        // the header is parsed on the way, whatever the framing
        // and however the stream delivers
        std::string const body = make_body(40);
        for(std::string const& msg : {
            make_head(body.size()) + body,
            make_chunked_head() + make_chunks(body, 16) })
        {
            for(std::size_t max_read :
                { std::size_t(-1), std::size_t(1) })
            {
                capy::test::read_stream rs({}, max_read);
                rs.provide(msg);

                capy::test::run_blocking()([&]() -> capy::task<>
                {
                    response_parser pr(response_parser::config{});
                    message_reader reader(&rs, &pr);
                    pr.start();

                    auto [ec, sv] = co_await reader.read_body();
                    BOOST_TEST(!ec);
                    BOOST_TEST_EQ(sv, body);
                    BOOST_TEST(pr.got_header());
                    BOOST_TEST(pr.got_body());
                }());
            }
        }
    }

    void
    testReadBodyOverflow()
    {
        // a body the parser cannot hold in place is refused,
        // and can still be read in pieces
        static constexpr std::string_view head =
            "HTTP/1.1 200 OK\r\n"
            "Content-Length: 40\r\n"
            "\r\n";
        std::string const body = make_body(40);

        // the header fits exactly, which leaves 25 octets for
        // the body
        response_parser::config cfg;
        cfg.hdr_limits.max_fields = 1;
        cfg.hdr_limits.max_size = head.size();
        cfg.in_buffer = 25;

        capy::test::read_stream rs;
        rs.provide(std::string(head) + body);

        capy::test::run_blocking()([&]() -> capy::task<>
        {
            response_parser pr(cfg);
            message_reader reader(&rs, &pr);
            pr.start();

            auto [ec1, sv] = co_await reader.read_body();
            BOOST_TEST(ec1 == http::error::in_place_overflow);
            BOOST_TEST(sv.empty());

            char buf[40];
            auto [ec2, n] = co_await reader.read(
                capy::make_buffer(buf));
            BOOST_TEST(!ec2);
            BOOST_TEST_EQ(std::string_view(buf, n), body);
        }());
    }

    void
    testReadSome()
    {
        std::string const body = make_body(40);

        // out of the parser's buffer: reading the header
        // drained the stream
        {
            capy::test::read_stream rs;
            rs.provide(make_head(body.size()) + body);

            capy::test::run_blocking()([&]() -> capy::task<>
            {
                response_parser pr(response_parser::config{});
                message_reader reader(&rs, &pr);
                pr.start();

                auto [ec1] = co_await reader.read_header();
                BOOST_TEST(!ec1);
                BOOST_TEST_EQ(rs.available(), 0u);

                char buf[64];
                auto [ec2, n2] = co_await reader.read_some(
                    capy::make_buffer(buf));
                BOOST_TEST(!ec2);
                BOOST_TEST_EQ(std::string_view(buf, n2), body);

                // the body is complete
                auto [ec3, n3] = co_await reader.read_some(
                    capy::make_buffer(buf));
                BOOST_TEST(ec3 == capy::cond::eof);
                BOOST_TEST_EQ(n3, 0u);
                BOOST_TEST(pr.got_body());
            }());
        }

        // straight from the stream: the parser holds no body
        // octets, and only what fits the destination is taken
        {
            capy::test::read_stream rs;
            rs.provide(make_head(body.size()));

            capy::test::run_blocking()([&]() -> capy::task<>
            {
                response_parser pr(response_parser::config{});
                message_reader reader(&rs, &pr);
                pr.start();

                auto [ec1] = co_await reader.read_header();
                BOOST_TEST(!ec1);
                rs.provide(body);

                char buf[16];
                auto [ec2, n2] = co_await reader.read_some(
                    capy::make_buffer(buf));
                BOOST_TEST(!ec2);
                BOOST_TEST_EQ(
                    std::string_view(buf, n2),
                    body.substr(0, sizeof(buf)));
                BOOST_TEST_EQ(
                    rs.available(), body.size() - sizeof(buf));
            }());
        }

        // without reading the header first
        {
            capy::test::read_stream rs;
            rs.provide(make_head(5) + "hello");

            capy::test::run_blocking()([&]() -> capy::task<>
            {
                response_parser pr(response_parser::config{});
                message_reader reader(&rs, &pr);
                pr.start();

                char buf[16];
                auto [ec, n] = co_await reader.read_some(
                    capy::make_buffer(buf));
                BOOST_TEST(!ec);
                BOOST_TEST_EQ(std::string_view(buf, n), "hello");
                BOOST_TEST(pr.got_header());
            }());
        }

        // a message without a body
        {
            capy::test::read_stream rs;
            rs.provide(make_head(0));

            capy::test::run_blocking()([&]() -> capy::task<>
            {
                response_parser pr(response_parser::config{});
                message_reader reader(&rs, &pr);
                pr.start();

                char buf[16];
                auto [ec, n] = co_await reader.read_some(
                    capy::make_buffer(buf));
                BOOST_TEST(ec == capy::cond::eof);
                BOOST_TEST_EQ(n, 0u);
                BOOST_TEST(pr.got_body());
            }());
        }
    }

    void
    testRead()
    {
        std::string const body = make_body(40);

        // the destination is filled however the stream delivers
        for(std::size_t max_read :
            { std::size_t(-1), std::size_t(7), std::size_t(1) })
        {
            capy::test::read_stream rs({}, max_read);
            rs.provide(make_head(body.size()) + body);

            capy::test::run_blocking()([&]() -> capy::task<>
            {
                response_parser pr(response_parser::config{});
                message_reader reader(&rs, &pr);
                pr.start();

                char buf[40];
                auto [ec1, n1] = co_await reader.read(
                    capy::make_buffer(buf));
                BOOST_TEST(!ec1);
                BOOST_TEST_EQ(std::string_view(buf, n1), body);

                auto [ec2, n2] = co_await reader.read(
                    capy::make_buffer(buf));
                BOOST_TEST(ec2 == capy::cond::eof);
                BOOST_TEST_EQ(n2, 0u);
            }());
        }

        // a body shorter than the destination ends the read
        // with what there was
        {
            capy::test::read_stream rs;
            rs.provide(make_head(body.size()) + body);

            capy::test::run_blocking()([&]() -> capy::task<>
            {
                response_parser pr(response_parser::config{});
                message_reader reader(&rs, &pr);
                pr.start();

                char buf[64];
                auto [ec, n] = co_await reader.read(
                    capy::make_buffer(buf));
                BOOST_TEST(ec == capy::cond::eof);
                BOOST_TEST_EQ(std::string_view(buf, n), body);
            }());
        }

        // a body longer than the destination is read in parts
        {
            capy::test::read_stream rs({}, 7);
            rs.provide(make_head(body.size()) + body);

            capy::test::run_blocking()([&]() -> capy::task<>
            {
                response_parser pr(response_parser::config{});
                message_reader reader(&rs, &pr);
                pr.start();

                std::string got;
                char buf[16];
                for(int i = 0; i != 2; ++i)
                {
                    auto [ec, n] = co_await reader.read(
                        capy::make_buffer(buf));
                    BOOST_TEST(!ec);
                    BOOST_TEST_EQ(n, sizeof(buf));
                    got.append(buf, n);
                }

                auto [ec, n] = co_await reader.read(
                    capy::make_buffer(buf));
                BOOST_TEST(ec == capy::cond::eof);
                got.append(buf, n);
                BOOST_TEST_EQ(got, body);
            }());
        }
    }

    void
    testManyBuffers()
    {
        // the destination is cut into single octets
        std::string const body = make_body(24);

        // read_some, out of the parser's buffer and then
        // straight from the stream
        for(bool direct : { false, true })
        {
            capy::test::read_stream rs;
            rs.provide(make_head(body.size()));
            if(!direct)
                rs.provide(body);

            capy::test::run_blocking()([&]() -> capy::task<>
            {
                response_parser pr(response_parser::config{});
                message_reader reader(&rs, &pr);
                pr.start();

                auto [ec1] = co_await reader.read_header();
                BOOST_TEST(!ec1);
                if(direct)
                    rs.provide(body);

                char buf[24] = {};
                auto [ec2, n] = co_await reader.read_some(
                    split(buf));
                BOOST_TEST(!ec2);
                BOOST_TEST_EQ(std::string_view(buf, n), body);
            }());
        }

        // read, with stream reads which end inside the
        // sequence
        {
            capy::test::read_stream rs({}, 5);
            rs.provide(make_head(body.size()) + body);

            capy::test::run_blocking()([&]() -> capy::task<>
            {
                response_parser pr(response_parser::config{});
                message_reader reader(&rs, &pr);
                pr.start();

                char buf[24] = {};
                auto [ec, n] = co_await reader.read(split(buf));
                BOOST_TEST(!ec);
                BOOST_TEST_EQ(std::string_view(buf, n), body);
            }());
        }
    }

    void
    testDirectLimit()
    {
        // a read straight from the stream stops at the end of
        // the body, whatever else the stream holds
        std::string const body = make_body(10);
        std::string const next = "HTTP/1.1 204";

        // the end falls inside a buffer, then between the
        // buffers of a sequence
        for(bool many : { false, true })
        {
            capy::test::read_stream rs;
            rs.provide(make_head(body.size()));

            capy::test::run_blocking()([&]() -> capy::task<>
            {
                response_parser pr(response_parser::config{});
                message_reader reader(&rs, &pr);
                pr.start();

                auto [ec1] = co_await reader.read_header();
                BOOST_TEST(!ec1);
                rs.provide(body + next);

                char buf[24] = {};
                std::error_code ec;
                std::size_t n = 0;
                if(many)
                    std::tie(ec, n) = co_await reader.read_some(
                        split(buf));
                else
                    std::tie(ec, n) = co_await reader.read_some(
                        capy::make_buffer(buf));
                BOOST_TEST(!ec);
                BOOST_TEST_EQ(std::string_view(buf, n), body);
                BOOST_TEST(pr.got_body());
            }());

            // the rest is still in the stream
            BOOST_TEST_EQ(rs.available(), next.size());
        }
    }

    void
    testPull()
    {
        std::string const body = make_body(40);

        // the loop of the class documentation, over both
        // framings
        for(std::string const& msg : {
            make_head(body.size()) + body,
            make_chunked_head() + make_chunks(body, 16) })
        {
            for(std::size_t max_read :
                { std::size_t(-1), std::size_t(7) })
            {
                capy::test::read_stream rs({}, max_read);
                rs.provide(msg);

                capy::test::run_blocking()([&]() -> capy::task<>
                {
                    response_parser pr(response_parser::config{});
                    message_reader reader(&rs, &pr);
                    pr.start();

                    std::string got;
                    capy::const_buffer bufs[4];
                    while(got.size() < body.size())
                    {
                        auto [ec, data] = co_await reader.pull(bufs);
                        BOOST_TEST(!ec);
                        BOOST_TEST(!data.empty());
                        if(ec || data.empty())
                            break;
                        got += str(data);
                        reader.consume(capy::buffer_size(data));
                    }
                    BOOST_TEST_EQ(got, body);

                    auto [ec, data] = co_await reader.pull(bufs);
                    BOOST_TEST(ec == capy::cond::eof);
                    BOOST_TEST(data.empty());
                    BOOST_TEST(pr.got_body());
                }());
            }
        }

        // octets which were not consumed are returned again
        {
            capy::test::read_stream rs;
            rs.provide(make_head(5) + "hello");

            capy::test::run_blocking()([&]() -> capy::task<>
            {
                response_parser pr(response_parser::config{});
                message_reader reader(&rs, &pr);
                pr.start();

                capy::const_buffer bufs[4];
                auto [ec1, d1] = co_await reader.pull(bufs);
                BOOST_TEST(!ec1);
                BOOST_TEST_EQ(str(d1), "hello");

                reader.consume(2);
                auto [ec2, d2] = co_await reader.pull(bufs);
                BOOST_TEST(!ec2);
                BOOST_TEST_EQ(str(d2), "llo");

                reader.consume(3);
                auto [ec3, d3] = co_await reader.pull(bufs);
                BOOST_TEST(ec3 == capy::cond::eof);
                BOOST_TEST(d3.empty());
            }());
        }
    }

    void
    testChunked()
    {
        // a chunked body through both copying reads
        std::string const body = make_body(40);
        for(std::size_t max_read :
            { std::size_t(-1), std::size_t(7), std::size_t(1) })
        {
            capy::test::read_stream rs({}, max_read);
            rs.provide(
                make_chunked_head() + make_chunks(body, 16));

            capy::test::run_blocking()([&]() -> capy::task<>
            {
                response_parser pr(response_parser::config{});
                message_reader reader(&rs, &pr);
                pr.start();

                std::string got;
                char buf[40];
                auto [ec1, n1] = co_await reader.read_some(
                    capy::mutable_buffer(buf, 8));
                BOOST_TEST(!ec1);
                BOOST_TEST_GT(n1, 0u);
                got.append(buf, n1);

                auto [ec2, n2] = co_await reader.read(
                    capy::mutable_buffer(buf, body.size() - n1));
                BOOST_TEST(!ec2);
                got.append(buf, n2);
                BOOST_TEST_EQ(got, body);

                // the last chunk ends the body
                auto [ec3, n3] = co_await reader.read_some(
                    capy::make_buffer(buf));
                BOOST_TEST(ec3 == capy::cond::eof);
                BOOST_TEST_EQ(n3, 0u);
                BOOST_TEST(pr.got_body());
            }());

            BOOST_TEST_EQ(rs.available(), 0u);
        }
    }

    void
    testToEof()
    {
        // a body of no declared size ends with the stream; out
        // of the parser's buffer, then straight from the stream
        std::string const body = make_body(40);
        for(bool direct : { false, true })
        {
            capy::test::read_stream rs;
            rs.provide("HTTP/1.1 200 OK\r\n\r\n");
            if(!direct)
                rs.provide(body);

            capy::test::run_blocking()([&]() -> capy::task<>
            {
                response_parser pr(response_parser::config{});
                message_reader reader(&rs, &pr);
                pr.start();

                auto [ec1] = co_await reader.read_header();
                BOOST_TEST(!ec1);
                if(direct)
                    rs.provide(body);

                char buf[64];
                auto [ec2, n2] = co_await reader.read_some(
                    capy::make_buffer(buf));
                BOOST_TEST(!ec2);
                BOOST_TEST_EQ(std::string_view(buf, n2), body);
                BOOST_TEST(!pr.got_body());

                auto [ec3, n3] = co_await reader.read_some(
                    capy::make_buffer(buf));
                BOOST_TEST(ec3 == capy::cond::eof);
                BOOST_TEST_EQ(n3, 0u);
                BOOST_TEST(pr.got_body());
            }());
        }
    }

    void
    testTruncated()
    {
        // the stream ends before the message begins
        {
            capy::test::read_stream rs;

            capy::test::run_blocking()([&]() -> capy::task<>
            {
                response_parser pr(response_parser::config{});
                message_reader reader(&rs, &pr);
                pr.start();

                auto [ec] = co_await reader.read_header();
                BOOST_TEST(ec == http::error::end_of_stream);
                BOOST_TEST(!pr.got_header());
            }());
        }

        // inside the header
        {
            capy::test::read_stream rs;
            rs.provide("HTTP/1.1 200 OK\r\nContent-");

            capy::test::run_blocking()([&]() -> capy::task<>
            {
                response_parser pr(response_parser::config{});
                message_reader reader(&rs, &pr);
                pr.start();

                auto [ec] = co_await reader.read_header();
                BOOST_TEST(ec == http::error::incomplete);
                BOOST_TEST(!pr.got_header());
            }());
        }

        // inside the body: each way of reading it reports what
        // arrived, then the error
        std::string const body = make_body(10);
        std::string const msg = make_head(40) + body;
        {
            capy::test::read_stream rs;
            rs.provide(msg);

            capy::test::run_blocking()([&]() -> capy::task<>
            {
                response_parser pr(response_parser::config{});
                message_reader reader(&rs, &pr);
                pr.start();

                char buf[40];
                auto [ec, n] = co_await reader.read(
                    capy::make_buffer(buf));
                BOOST_TEST(ec == http::error::incomplete);
                BOOST_TEST_EQ(std::string_view(buf, n), body);
                BOOST_TEST(!pr.got_body());
            }());
        }
        {
            capy::test::read_stream rs;
            rs.provide(msg);

            capy::test::run_blocking()([&]() -> capy::task<>
            {
                response_parser pr(response_parser::config{});
                message_reader reader(&rs, &pr);
                pr.start();

                char buf[40];
                auto [ec1, n1] = co_await reader.read_some(
                    capy::make_buffer(buf));
                BOOST_TEST(!ec1);
                BOOST_TEST_EQ(std::string_view(buf, n1), body);

                auto [ec2, n2] = co_await reader.read_some(
                    capy::make_buffer(buf));
                BOOST_TEST(ec2 == http::error::incomplete);
                BOOST_TEST_EQ(n2, 0u);
            }());
        }
        {
            capy::test::read_stream rs;
            rs.provide(msg);

            capy::test::run_blocking()([&]() -> capy::task<>
            {
                response_parser pr(response_parser::config{});
                message_reader reader(&rs, &pr);
                pr.start();

                capy::const_buffer bufs[4];
                auto [ec1, d1] = co_await reader.pull(bufs);
                BOOST_TEST(!ec1);
                BOOST_TEST_EQ(str(d1), body);
                reader.consume(capy::buffer_size(d1));

                auto [ec2, d2] = co_await reader.pull(bufs);
                BOOST_TEST(ec2 == http::error::incomplete);
                BOOST_TEST(d2.empty());
            }());
        }
        {
            capy::test::read_stream rs;
            rs.provide(msg);

            capy::test::run_blocking()([&]() -> capy::task<>
            {
                response_parser pr(response_parser::config{});
                message_reader reader(&rs, &pr);
                pr.start();

                auto [ec, sv] = co_await reader.read_body();
                BOOST_TEST(ec == http::error::incomplete);
                BOOST_TEST(sv.empty());
            }());
        }
    }

    void
    testParserError()
    {
        // a body over the limit is refused from its declared
        // size alone, with nothing more taken from the stream
        {
            std::string const body = make_body(40);
            capy::test::read_stream rs;
            rs.provide(make_head(body.size()));

            capy::test::run_blocking()([&]() -> capy::task<>
            {
                response_parser pr(response_parser::config{});
                message_reader reader(&rs, &pr);
                pr.start();

                auto [ec1] = co_await reader.read_header();
                BOOST_TEST(!ec1);
                pr.set_body_limit(8);
                rs.provide(body);

                char buf[16];
                auto [ec2, n] = co_await reader.read_some(
                    capy::make_buffer(buf));
                BOOST_TEST(ec2 == http::error::body_too_large);
                BOOST_TEST_EQ(n, 0u);
            }());

            BOOST_TEST_EQ(rs.available(), body.size());
        }

        // broken framing surfaces from each way of reading
        std::string const msg =
            make_chunked_head() + "ZZZ\r\nhello\r\n";
        {
            capy::test::read_stream rs;
            rs.provide(msg);

            capy::test::run_blocking()([&]() -> capy::task<>
            {
                response_parser pr(response_parser::config{});
                message_reader reader(&rs, &pr);
                pr.start();

                char buf[16];
                auto [ec1, n1] = co_await reader.read_some(
                    capy::make_buffer(buf));
                BOOST_TEST(ec1 == http::error::bad_payload);
                BOOST_TEST_EQ(n1, 0u);

                auto [ec2, n2] = co_await reader.read(
                    capy::make_buffer(buf));
                BOOST_TEST(ec2 == http::error::bad_payload);
                BOOST_TEST_EQ(n2, 0u);

                capy::const_buffer bufs[4];
                auto [ec3, data] = co_await reader.pull(bufs);
                BOOST_TEST(ec3 == http::error::bad_payload);
                BOOST_TEST(data.empty());

                auto [ec4, sv] = co_await reader.read_body();
                BOOST_TEST(ec4 == http::error::bad_payload);
                BOOST_TEST(sv.empty());
                BOOST_TEST(!pr.got_body());
            }());
        }
    }

    void
    testAnyBufferSource()
    {
        // the reader drops into the type-erased source, and the
        // native read path keeps working through the erasure
        std::string const body = make_body(40);
        capy::test::read_stream rs;
        rs.provide(make_chunked_head() + make_chunks(body, 16));

        capy::test::run_blocking()([&]() -> capy::task<>
        {
            response_parser pr(response_parser::config{});
            message_reader reader(&rs, &pr);
            pr.start();

            http::any_buffer_source src(&reader);

            capy::const_buffer bufs[4];
            auto [ec1, data] = co_await src.pull(bufs);
            BOOST_TEST(!ec1);
            std::string got = str(data).substr(0, 4);
            BOOST_TEST_EQ(got.size(), 4u);
            src.consume(4);

            char buf[40];
            auto [ec2, n2] = co_await src.read_some(
                capy::mutable_buffer(buf, 8));
            BOOST_TEST(!ec2);
            BOOST_TEST_GT(n2, 0u);
            got.append(buf, n2);

            auto [ec3, n3] = co_await src.read(
                capy::mutable_buffer(
                    buf, body.size() - got.size()));
            BOOST_TEST(!ec3);
            got.append(buf, n3);
            BOOST_TEST_EQ(got, body);

            auto [ec4, n4] = co_await src.read_some(
                capy::make_buffer(buf));
            BOOST_TEST(ec4 == capy::cond::eof);
            BOOST_TEST_EQ(n4, 0u);
            BOOST_TEST(pr.got_body());
        }());
    }

    void
    testErrorInjection()
    {
        capy::test::fuse f;
        auto const r = f.armed(
            [&](capy::test::fuse&) -> capy::task<>
        {
            std::string const body = make_body(40);
            capy::test::read_stream rs(f, 7);
            rs.provide(
                make_chunked_head() + make_chunks(body, 16));

            response_parser pr(response_parser::config{});
            message_reader reader(&rs, &pr);
            pr.start();

            if(auto [ec] = co_await reader.read_header(); ec)
            {
                BOOST_TEST(ec == capy::error::test_failure);
                BOOST_TEST(!pr.got_header());
                co_return;
            }

            char buf[40];
            if(auto [ec, n] = co_await reader.read(
                capy::make_buffer(buf)); ec)
            {
                BOOST_TEST(ec == capy::error::test_failure);
                BOOST_TEST_LT(n, body.size());
                BOOST_TEST_EQ(
                    std::string_view(buf, n),
                    body.substr(0, n));
                co_return;
            }
            BOOST_TEST_EQ(
                std::string_view(buf, sizeof(buf)), body);

            auto [ec, n] = co_await reader.read_some(
                capy::make_buffer(buf));
            BOOST_TEST_EQ(n, 0u);
            if(ec == capy::error::test_failure)
            {
                BOOST_TEST(!pr.got_body());
                co_return;
            }
            BOOST_TEST(ec == capy::cond::eof);
            BOOST_TEST(pr.got_body());
        });
        BOOST_TEST(r.success);
    }

    void
    testCancelResume()
    {
        // A cancelled read completes with an error alongside a
        // partial count. The reader hands the count to the
        // parser before it looks at the error, so issuing the
        // operation again resumes the message. A chunked body
        // arrives through the parser's buffer and a sized one
        // straight into the destination; the seven-octet budget
        // walks cancellation across the header and the body of
        // both.
        std::string const body = make_body(40);
        for(std::string const& msg : {
            make_chunked_head() + make_chunks(body, 16),
            make_head(body.size()) + body })
        {
            flaky_read_stream rs{ msg };

            capy::test::run_blocking()([&]() -> capy::task<>
            {
                response_parser pr(response_parser::config{});
                message_reader reader(&rs, &pr);
                pr.start();

                for(int i = 0; i != 100 && !pr.got_header(); ++i)
                {
                    rs.budget = 7;
                    auto [ec] = co_await reader.read_header();
                    if(ec)
                        BOOST_TEST(ec == capy::cond::canceled);
                }
                BOOST_TEST(pr.got_header());

                std::string got;
                for(int i = 0; i != 100 && !pr.got_body(); ++i)
                {
                    rs.budget = 7;
                    char buf[16];
                    auto [ec, n] = co_await reader.read_some(
                        capy::make_buffer(buf));
                    got.append(buf, n);
                    if(ec && ec != capy::cond::eof)
                        BOOST_TEST(ec == capy::cond::canceled);
                }
                BOOST_TEST(pr.got_body());
                BOOST_TEST_EQ(got, body);
            }());

            BOOST_TEST_EQ(rs.pos, msg.size());
        }
    }

    void
    testCancelResumeRead()
    {
        // Resuming a cancelled read() is compositional: the
        // count it returned is the caller's cursor, and the
        // rest of the destination is issued again. The body
        // arrives after the header, so it is read straight
        // into the destination.
        std::string const body = make_body(40);
        std::string const head = make_head(body.size());
        flaky_read_stream rs{ head };

        capy::test::run_blocking()([&]() -> capy::task<>
        {
            response_parser pr(response_parser::config{});
            message_reader reader(&rs, &pr);
            pr.start();

            rs.budget = head.size();
            auto [ec0] = co_await reader.read_header();
            BOOST_TEST(!ec0);
            rs.data += body;

            char buf[40];
            rs.budget = 11;
            auto [ec1, n1] = co_await reader.read(
                capy::make_buffer(buf));
            BOOST_TEST(ec1 == capy::cond::canceled);
            BOOST_TEST_EQ(n1, 11u);
            BOOST_TEST(!pr.got_body());

            rs.budget = std::size_t(-1);
            auto [ec2, n2] = co_await reader.read(
                capy::mutable_buffer(
                    buf + n1, sizeof(buf) - n1));
            BOOST_TEST(!ec2);
            BOOST_TEST_EQ(n2, body.size() - n1);
            BOOST_TEST_EQ(
                std::string_view(buf, sizeof(buf)), body);
        }());
    }

    void
    run()
    {
        testReadHeader();
        testReadBody();
        testReadBodyOverflow();
        testReadSome();
        testRead();
        testManyBuffers();
        testDirectLimit();
        testPull();
        testChunked();
        testToEof();
        testTruncated();
        testParserError();
        testAnyBufferSource();
        testErrorInjection();
        testCancelResume();
        testCancelResumeRead();
    }
};

TEST_SUITE(message_reader_test, "boost.burl.message_reader");

} // namespace burl
} // namespace boost
