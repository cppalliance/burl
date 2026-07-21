//
// Copyright (c) 2026 Mohammad Nejati
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

// Test that header file is self-contained.
#include <boost/burl/response.hpp>

#include <boost/burl/string.hpp>
#include <boost/burl/test/response_factory.hpp>

#include <boost/capy/read.hpp>

#include "test_suite.hpp"

namespace boost
{
namespace burl
{

using namespace std::chrono_literals;

class response_test
{
public:
    void
    testStatus()
    {
        // 200
        {
            auto r = test::response_factory(http::status::ok)
                .create();
            BOOST_TEST(r.status() == http::status::ok);
            BOOST_TEST_EQ(r.status_int(), 200);
            BOOST_TEST_EQ(r.reason(), "OK");
        }

        // 404
        {
            auto r = test::response_factory(http::status::not_found)
                .create();
            BOOST_TEST(r.status() == http::status::not_found);
            BOOST_TEST_EQ(r.status_int(), 404);
            BOOST_TEST_EQ(r.reason(), "Not Found");
        }
    }

    void
    testOk()
    {
        // 2xx
        {
            auto r = test::response_factory().create();
            BOOST_TEST(r.ok());
        }

        // 3xx
        {
            auto r = test::response_factory(http::status::found).create();
            BOOST_TEST(!r.ok());
        }

        // 4xx
        {
            auto r = test::response_factory(http::status::conflict).create();
            BOOST_TEST(!r.ok());
        }

        // 5xx
        {
            auto r = test::response_factory(http::status::bad_gateway).create();
            BOOST_TEST(!r.ok());
        }
    }

    void
    testRaiseForStatus()
    {
        // 2xx
        {
            auto r = test::response_factory().create();
            BOOST_TEST_NO_THROW(r.raise_for_status());
        }

        // 3xx
        {
            auto r = test::response_factory(http::status::found).create();
            BOOST_TEST_NO_THROW(r.raise_for_status());
        }

        // 4xx
        {
            auto r = test::response_factory(http::status::conflict).create();
            BOOST_TEST_THROWS(
                r.raise_for_status(),
                std::system_error);
        }

        // 5xx
        {
            auto r = test::response_factory(http::status::bad_gateway).create();
            BOOST_TEST_THROWS(
                r.raise_for_status(),
                std::system_error);
        }
    }

    void
    testVersion()
    {
        auto r = test::response_factory({}, http::version::http_1_0)
            .create();
        BOOST_TEST(r.version() == http::version::http_1_0);
    }

    void
    testUrl()
    {
        auto r = test::response_factory()
            .url(urls::url("http://example.com"))
            .create();
        BOOST_TEST_EQ(r.url().buffer(), "http://example.com");
    }

    void
    testContentLength()
    {
        auto r1 = test::response_factory()
            .body({ "x" })
            .create();
        BOOST_TEST_EQ(r1.content_length().value_or(0), 1u);

        // Chunked responses have no determined payload size.
        auto r2 = test::response_factory()
            .chunked(true)
            .body({ "x" })
            .create();
        BOOST_TEST(!r2.content_length().has_value());
    }

    void
    testHeaders()
    {
        auto r = test::response_factory()
            .header(http::field::content_type, "text/plain")
            .header("X-Test", "abc")
            .create();
        BOOST_TEST_EQ(
            r.headers().value_or(http::field::content_type, ""),
            "text/plain");
        BOOST_TEST_EQ(r.headers().value_or("X-Test", ""), "abc");
    }

    void
    testAsView()
    {
        capy::test::run_blocking()([]() -> capy::task<>
        {
            auto r = test::response_factory()
                .body({ "frag1", "frag2", "frag3" })
                .create();

            auto [ec, body] = co_await r.try_as_view();
            BOOST_TEST(!ec);
            BOOST_TEST_EQ(body, "frag1frag2frag3");
        }());
    }

    void
    testAsViewIdempotent()
    {
        capy::test::run_blocking()([]() -> capy::task<>
        {
            auto r = test::response_factory()
                .body({ "abc", "def" })
                .create();

            auto first = co_await r.as_view();
            BOOST_TEST_EQ(first, "abcdef");

            // A second read returns the same buffer without I/O.
            auto second = co_await r.as_view();
            BOOST_TEST_EQ(second, "abcdef");
            BOOST_TEST(first.data() == second.data());
        }());
    }

    void
    testAsViewTruncated()
    {
        capy::test::run_blocking()([]() -> capy::task<>
        {
            // Advertise more than is delivered.
            auto r = test::response_factory()
                .content_length(10)
                .body({ "abc" })
                .create();

            BOOST_TEST_THROWS(
                co_await r.as_view(),
                std::system_error);
        }());
    }

    void
    testAsString()
    {
        capy::test::run_blocking()([]() -> capy::task<>
        {
            auto r = test::response_factory()
                .body({ "frag1", "frag2", "frag3" })
                .create();

            auto body = co_await r.as<std::string>();
            BOOST_TEST_EQ(body, "frag1frag2frag3");
        }());
    }

    void
    testAsStringTruncated()
    {
        capy::test::run_blocking()([]() -> capy::task<>
        {
            auto r = test::response_factory()
                .content_length(64)
                .body({ "paylo" })
                .create();

            BOOST_TEST_THROWS(
                co_await r.as<std::string>(),
                std::system_error);
        }());
    }

    void
    testTimeout()
    {
        corosio::io_context ioc;
        // The body arrives before the timeout
        capy::run_async(ioc.get_executor())([]() -> capy::task<>
        {
            auto r1 = test::response_factory()
                .timeout(10s)
                .body({ "data" })
                .create();

            auto [ec1, b1] = co_await r1.try_as_view();
            BOOST_TEST(!ec1);
            BOOST_TEST_EQ(b1, "data");

            auto r2 = test::response_factory()
                .timeout(10s)
                .body({ "data" })
                .create();

            auto [ec2, b2] = co_await r2.try_as<std::string>();
            BOOST_TEST(!ec2);
            BOOST_TEST_EQ(b2, "data");
        }());
        ioc.run();
    }

    void
    testBufferSource()
    {
        capy::test::run_blocking()([]() -> capy::task<>
        {
            auto r = test::response_factory()
                .body({ "frag1", "frag2", "frag3" })
                .create();

            auto source = r.as_buffer_source();
            std::string out;
            for(;;)
            {
                capy::const_buffer arr[4];
                auto [ec, bufs] = co_await source.pull(arr);
                if(ec)
                {
                    BOOST_TEST_EQ(ec, capy::error::eof);
                    break;
                }
                std::size_t n = 0;
                for(auto const& buf : bufs)
                {
                    out.append(
                        static_cast<char const*>(buf.data()), buf.size());
                    n += buf.size();
                }
                source.consume(n);
            }
            BOOST_TEST_EQ(out, "frag1frag2frag3");
        }());
    }

    void
    testReadSource()
    {
        capy::test::run_blocking()([]() -> capy::task<>
        {
            auto r = test::response_factory()
                .body({ "aa", "bb", "cc" })
                .create();

            auto source = r.as_read_source();
            char buf[16];
            auto [ec, n] = co_await capy::read(
                source, capy::make_buffer(buf));
            BOOST_TEST(ec == capy::cond::eof);
            BOOST_TEST_EQ(buf, std::string_view(buf, n));
        }());
    }

    void
    testMoveConstruct()
    {
        capy::test::run_blocking()([]() -> capy::task<>
        {
            auto r1 = test::response_factory(http::status::not_found)
                .header("X-Test", "v")
                .body({ "hello" })
                .create();

            auto r2 = std::move(r1);
            BOOST_TEST_EQ(r2.status_int(), 404);
            BOOST_TEST_EQ(r2.headers().value_or("X-Test", ""), "v");
            BOOST_TEST_EQ(co_await r2.as_view(), "hello");
        }());
    }

    void
    testMoveAssign()
    {
        capy::test::run_blocking()([]() -> capy::task<>
        {
            auto r1 = test::response_factory(http::status::ok)
                .body({ "first" })
                .create();
            auto r2 = test::response_factory(http::status::not_found)
                .body({ "second" })
                .create();

            r2 = std::move(r1);
            BOOST_TEST(r2.ok());
            BOOST_TEST_EQ(co_await r2.as_view(), "first");

            // A default-constructed response is a valid assignment target.
            response r3;
            r3 = test::response_factory().body({ "third" }).create();
            BOOST_TEST(r3.ok());
            BOOST_TEST_EQ(co_await r3.as_view(), "third");
        }());
    }

    void
    run()
    {
        testStatus();
        testOk();
        testRaiseForStatus();
        testVersion();
        testUrl();
        testContentLength();
        testHeaders();
        testAsView();
        testAsViewIdempotent();
        testAsViewTruncated();
        testAsString();
        testAsStringTruncated();
        testTimeout();
        testBufferSource();
        testReadSource();
        testMoveConstruct();
        testMoveAssign();
    }
};

TEST_SUITE(response_test, "boost.burl.response");

} // namespace burl
} // namespace boost
