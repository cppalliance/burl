//
// Copyright (c) 2026 Mohammad Nejati
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

// Test that header file is self-contained.
#include "src/detail/can_reuse_conn.hpp"

#include "test_suite.hpp"

#include <boost/capy/task.hpp>
#include <boost/capy/test/run_blocking.hpp>
#include <boost/capy/test/stream.hpp>
#include <boost/http/response_parser.hpp>

#include <string_view>

namespace boost
{
namespace burl
{
namespace detail
{

class can_reuse_conn_test
{
    static bool
    reusable(std::string_view response)
    {
        auto [client, server] = capy::test::make_stream_pair();
        server.provide(response);

        http::response_parser parser(
            http::make_parser_config(http::parser_config{ false }));
        bool result = false;
        capy::test::run_blocking()(
            [&]() -> capy::task<>
            {
                parser.reset();
                parser.start();
                if(auto [rec] = co_await parser.read_header(client); rec)
                    co_return;
                result = can_reuse_conn(parser);
            }());
        return result;
    }

public:
    void
    testComplete()
    {
        // keep-alive, body fully buffered and parseable
        BOOST_TEST(
            reusable("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"));
    }

    void
    testConnectionClose()
    {
        BOOST_TEST(!reusable(
            "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"));
    }

    void
    testHttp10()
    {
        // HTTP/1.0 is not keep-alive by default
        BOOST_TEST(!reusable("HTTP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n"));
    }

    void
    testIncomplete()
    {
        // keep-alive, but the body never arrives
        BOOST_TEST(!reusable("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n"));
    }

    void
    testNoHeader()
    {
        http::response_parser parser(
            http::make_parser_config(http::parser_config{ false }));
        parser.reset();
        parser.start();
        BOOST_TEST(!can_reuse_conn(parser));
    }

    void
    run()
    {
        testComplete();
        testConnectionClose();
        testHttp10();
        testIncomplete();
        testNoHeader();
    }
};

TEST_SUITE(can_reuse_conn_test, "boost.burl.detail.can_reuse_conn");

} // namespace detail
} // namespace burl
} // namespace boost
