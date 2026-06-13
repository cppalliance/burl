//
// Copyright (c) 2026 Mohammad Nejati
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

// Test that header file is self-contained.
#include "src/detail/drain_body.hpp"

#include "test_suite.hpp"

#include <boost/capy/io/any_stream.hpp>
#include <boost/capy/task.hpp>
#include <boost/capy/test/run_blocking.hpp>
#include <boost/capy/test/stream.hpp>
#include <boost/http/response_parser.hpp>

#include <cstdint>
#include <string_view>
#include <system_error>
#include <utility>

namespace boost
{
namespace burl
{
namespace detail
{

class drain_body_test
{
    static std::pair<std::error_code, bool>
    drain(capy::test::stream& client, std::uint64_t limit)
    {
        http::response_parser parser(
            http::make_parser_config(http::parser_config{ false }));
        std::error_code ec;
        capy::test::run_blocking()(
            [&]() -> capy::task<>
            {
                parser.reset();
                parser.start();
                if(auto [rec] = co_await parser.read_header(client); rec)
                {
                    ec = rec;
                    co_return;
                }
                auto [dec] =
                    co_await drain_body(parser, capy::any_stream(&client), limit);
                ec = dec;
            }());
        return { ec, parser.is_complete() };
    }

public:
    void
    testContentLength()
    {
        auto [client, server] = capy::test::make_stream_pair();
        server.provide("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello");

        auto [ec, complete] = drain(client, 1024);

        BOOST_TEST(!ec);
        BOOST_TEST(complete);
    }

    void
    testChunked()
    {
        auto [client, server] = capy::test::make_stream_pair();
        server.provide(
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
            "5\r\nhello\r\n0\r\n\r\n");

        auto [ec, complete] = drain(client, 1024);

        BOOST_TEST(!ec);
        BOOST_TEST(complete);
    }

    void
    run()
    {
        testContentLength();
        testChunked();
    }
};

TEST_SUITE(drain_body_test, "boost.burl.detail.drain_body");

} // namespace detail
} // namespace burl
} // namespace boost
