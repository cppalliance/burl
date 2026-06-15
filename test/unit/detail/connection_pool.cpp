//
// Copyright (c) 2026 Mohammad Nejati
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

// Test that header file is self-contained.
#include "src/detail/connection_pool.hpp"

#include <boost/capy/delay.hpp>
#include <boost/capy/io/any_stream.hpp>
#include <boost/capy/test/run_blocking.hpp>
#include <boost/capy/test/stream.hpp>
#include <boost/corosio/tls_context.hpp>

#include "scripted_net.hpp"
#include "test_suite.hpp"

namespace boost
{
namespace burl
{
namespace detail
{

using namespace std::chrono_literals;

class connection_pool_test
{
    struct slow_stream
    {
        capy::io_task<std::size_t>
        read_some(auto)
        {
            auto [ec] = co_await capy::delay(1s);
            co_return { ec, {} };
        }

        capy::io_task<std::size_t>
        write_some(auto)
        {
            auto [ec] = co_await capy::delay(1s);
            co_return { ec, {} };
        }
    };

public:
    void
    testOriginKeySeparation()
    {
        scripted_net net;

        urls::url_view const urls[4] =
        {
            "http://example.com",
            "http://example.com:8080",
            "https://example.com",
            "https://a.example.com"
        };

        capy::test::run_blocking()([&]() -> capy::task<>
        {
            auto pool = std::make_shared<connection_pool>(
                co_await capy::this_coro::executor,
                corosio::tls_context(),
                net.config());

            for(auto& u : urls)
            {
                auto [ec, pc] = co_await pool->acquire(u);
                BOOST_TEST(!ec);
                pool->release(std::move(pc));
            }
        }());

        BOOST_TEST_EQ(net.connects(), 4u);
        BOOST_TEST_EQ(net.origins[0], urls[0].buffer());
        BOOST_TEST_EQ(net.origins[1], urls[1].buffer());
        BOOST_TEST_EQ(net.origins[2], urls[2].buffer());
        BOOST_TEST_EQ(net.origins[3], urls[3].buffer());
    }

    void
    testSameOriginReuses()
    {
        scripted_net net;
        urls::url_view url = "http://example.com";

        capy::test::run_blocking()([&]() -> capy::task<>
        {
            auto pool = std::make_shared<connection_pool>(
                co_await capy::this_coro::executor,
                corosio::tls_context(),
                net.config());

            for(int i = 0; i < 3; ++i)
            {
                auto [ec, pc] = co_await pool->acquire(url);
                BOOST_TEST(!ec);
                pool->release(std::move(pc));
            }
        }());

        BOOST_TEST_EQ(net.connects(), 1u);
        BOOST_TEST_EQ(net.origins[0], url.buffer());
    }

    void
    testMaxIdlePerHost()
    {
        scripted_net net;
        urls::url_view url = "http://example.com";

        capy::test::run_blocking()([&]() -> capy::task<>
        {
            auto cfg = net.config();
            cfg.pool_max_idle_per_host = 1;
            auto pool = std::make_shared<connection_pool>(
                co_await capy::this_coro::executor,
                corosio::tls_context(),
                cfg);

            auto [ec1, pc1] = co_await pool->acquire(url);
            BOOST_TEST(!ec1);
            auto [ec2, pc2] = co_await pool->acquire(url);
            BOOST_TEST(!ec2);
            BOOST_TEST_EQ(net.connects(), 2u);

            pool->release(std::move(pc1));
            pool->release(std::move(pc2));

            auto [ec3, pc3] = co_await pool->acquire(url);
            BOOST_TEST(!ec3);
            BOOST_TEST_EQ(net.connects(), 2u);

            auto [ec4, pc4] = co_await pool->acquire(url);
            BOOST_TEST(!ec4);
            BOOST_TEST_EQ(net.connects(), 3u);
        }());
    }

    void
    testIdleTimeout()
    {
        scripted_net net;
        urls::url_view url = "http://example.com";

        capy::test::run_blocking()([&]() -> capy::task<>
        {
            auto cfg = net.config();
            cfg.pool_idle_timeout = 10ms;
            auto pool = std::make_shared<connection_pool>(
                co_await capy::this_coro::executor,
                corosio::tls_context(),
                cfg);

            {
                auto [ec, pc] = co_await pool->acquire(url);
                BOOST_TEST(!ec);
                pool->release(std::move(pc));
            }

            if(auto [ec] = co_await capy::delay(20ms); ec)
                throw std::system_error(ec);

            auto [ec, pc] = co_await pool->acquire(url);
            BOOST_TEST(!ec);
        }());

        BOOST_TEST_EQ(net.connects(), 2u);
    }

    void
    testStaleIdleReuse()
    {
        scripted_net net;
        urls::url_view url = "http://example.com";

        capy::test::run_blocking()([&]() -> capy::task<>
        {
            auto pool = std::make_shared<connection_pool>(
                co_await capy::this_coro::executor,
                corosio::tls_context(),
                net.config());

            {
                auto [ec, pc] = co_await pool->acquire(url);
                BOOST_TEST(!ec);
                pool->release(std::move(pc));
            }

            // Server FINs the idle connection.
            net.server(0).close();

            // TODO: pool should detect the dead idle entry
            auto [ec, pc] = co_await pool->acquire(url);
            BOOST_TEST(!ec);
            // BOOST_TEST_EQ(net.connects(), 2u);
        }());
    }

    void
    testConnectionOutlivesPool()
    {
        scripted_net net;
        urls::url_view url = "http://example.com";

        capy::test::run_blocking()([&]() -> capy::task<>
        {
            auto pool = std::make_shared<connection_pool>(
                co_await capy::this_coro::executor,
                corosio::tls_context(),
                net.config());

            auto [ec, pc] = co_await pool->acquire(url);
            BOOST_TEST(!ec);

            pool.reset(); // pool gone; pc's weak_ptr expires

            // The connection is still fully usable.
            net.server(0).provide("hello");
            char buf[8];
            auto [rec, n] = co_await pc.read_some(
                capy::mutable_buffer(buf, sizeof(buf)));
            BOOST_TEST(!rec);
            BOOST_TEST_EQ(std::string_view(buf, n), "hello");

            // Returning to a dead pool is a safe no-op.
            pc.return_to_pool();
        }());

        BOOST_TEST_EQ(net.connects(), 1u);
    }

    void
    testConnectTimeout()
    {
        client::config cfg;
        cfg.connect_timeout = 10ms;
        cfg.connect_handler = [](urls::url_view) -> capy::io_task<capy::any_stream>
        {
            if(auto [ec] = co_await capy::delay(1s); ec)
            {
                BOOST_TEST_EQ(ec, capy::error::canceled);
                co_return { ec, {} };
            }
            BOOST_TEST_FAIL();
            auto [cli, srv] = capy::test::make_stream_pair();
            co_return { {}, capy::any_stream(std::move(cli)) };
        };

        capy::test::run_blocking()([&]() -> capy::task<>
        {
            auto pool = std::make_shared<connection_pool>(
                co_await capy::this_coro::executor,
                corosio::tls_context(),
                cfg);

            auto [ec, pc] = co_await pool->acquire("http://example.com/");
            BOOST_TEST_EQ(ec, capy::error::timeout);
        }());
    }

    void
    testIoTimeout()
    {
        client::config cfg;
        cfg.io_timeout = 10ms;
        cfg.connect_handler = [](urls::url_view) -> capy::io_task<capy::any_stream>
        {
            co_return { {}, capy::any_stream{ slow_stream{} } };
        };

        capy::test::run_blocking()([&]() -> capy::task<>
        {
            auto pool = std::make_shared<connection_pool>(
                co_await capy::this_coro::executor,
                corosio::tls_context(),
                cfg);

            auto [cec, pc] = co_await pool->acquire("http://example.com/");
            BOOST_TEST(!cec);
    
            char buf[1] = {};

            auto [rec, n1] = co_await pc.read_some(capy::make_buffer(buf));
            BOOST_TEST(rec == capy::error::timeout);
            BOOST_TEST_EQ(n1, 0);

            auto [wec, n2] = co_await pc.write_some(capy::make_buffer(buf));
            BOOST_TEST(wec == capy::error::timeout);
            BOOST_TEST_EQ(n2, 0);
        }());
    }

    void
    run()
    {
        testOriginKeySeparation();
        testSameOriginReuses();
        testMaxIdlePerHost();
        testIdleTimeout();
        testStaleIdleReuse();
        testConnectionOutlivesPool();
        testConnectTimeout();
        testIoTimeout();
    }
};

TEST_SUITE(connection_pool_test, "boost.burl.detail.connection_pool");

} // namespace detail
} // namespace burl
} // namespace boost
