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

#include <boost/capy/buffers.hpp>
#include <boost/capy/buffers/string_dynamic_buffer.hpp>
#include <boost/capy/delay.hpp>
#include <boost/capy/read.hpp>
#include <boost/capy/read_until.hpp>
#include <boost/capy/write.hpp>
#include <boost/capy/ex/run_async.hpp>
#include <boost/capy/io/any_stream.hpp>
#include <boost/capy/test/run_blocking.hpp>
#include <boost/capy/test/stream.hpp>
#include <boost/corosio/io_context.hpp>
#include <boost/corosio/openssl_stream.hpp>
#include <boost/corosio/socket_option.hpp>
#include <boost/corosio/tcp_acceptor.hpp>
#include <boost/corosio/tls_context.hpp>

#include "scripted_net.hpp"
#include "test_suite.hpp"

namespace boost
{
namespace burl
{
namespace detail
{

namespace
{

constexpr char const* server_cert =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIBPjCB8aADAgECAhQyKw1vpx1dMpM1RZvVFSZk8CblDDAFBgMrZXAwFDESMBAG\n"
    "A1UEAwwJbG9jYWxob3N0MCAXDTI2MDYxOTE4MDczMVoYDzIxMjYwNTI2MTgwNzMx\n"
    "WjAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwKjAFBgMrZXADIQD6Ie6FvisdU/00Erdj\n"
    "Kz3XgJ+aVBHnnNwkg2JXScdwvKNTMFEwHQYDVR0OBBYEFMbHkWhq1pG06IKlS0dK\n"
    "VLFb8sQwMB8GA1UdIwQYMBaAFMbHkWhq1pG06IKlS0dKVLFb8sQwMA8GA1UdEwEB\n"
    "/wQFMAMBAf8wBQYDK2VwA0EA5y94Q4N61m5ISAhPt2f80Z/9oU/3sxyOZuovbawi\n"
    "HwYpdjOgATpTJ3ZeuA5tL3rwQ6+ATVR4O43zzGy6bPs2Cw==\n"
    "-----END CERTIFICATE-----\n";

constexpr char const* server_key =
    "-----BEGIN PRIVATE KEY-----\n"
    "MC4CAQAwBQYDK2VwBCIEICAS/dH8KdK3z1Z9ju+7WkYMc35VIhaYsq57d32GdW+l\n"
    "-----END PRIVATE KEY-----\n";

} // namespace

using namespace std::chrono_literals;
using capy::make_buffer;

class connection_pool_test
{
    struct slow_stream
    {
        capy::io_task<std::size_t>
        read_some(auto)
        {
            auto [ec] = co_await capy::delay(10s);
            co_return { ec, {} };
        }

        capy::io_task<std::size_t>
        write_some(auto)
        {
            auto [ec] = co_await capy::delay(10s);
            co_return { ec, {} };
        }
    };

    class loopback_server
    {
        corosio::io_context& ioc_;
        corosio::tcp_acceptor acceptor_{ ioc_ };

    public:
        explicit loopback_server(corosio::io_context& ioc)
            : ioc_{ ioc }
        {
            acceptor_.open();
            acceptor_.set_option(
                corosio::socket_option::reuse_address(true));
            if(auto ec = acceptor_.bind({}))
                throw std::system_error(ec);
            if(auto ec = acceptor_.listen())
                throw std::system_error(ec);
        }

        urls::url
        url(std::string_view scheme) const
        {
            urls::url u;
            u.set_host_ipv4(urls::ipv4_address::loopback());
            u.set_port_number(acceptor_.local_endpoint().port());
            u.set_scheme(scheme);
            return u;
        }

        capy::task<corosio::tcp_socket>
        next()
        {
            corosio::tcp_socket peer{ ioc_ };
            auto [ec] = co_await acceptor_.accept(peer);
            BOOST_TEST(!ec);
            co_return std::move(peer);
        }
    };

    static capy::task<>
    ping(capy::any_stream s)
    {
        auto [wec, wn] = co_await capy::write(
            s, make_buffer("ping", 4));
        BOOST_TEST(!wec);
    
        char buf[4];
        auto [rec, rn] = co_await capy::read(
            s, make_buffer(buf));
        BOOST_TEST(!rec);
        BOOST_TEST_EQ(std::string_view(buf, 4), "pong");
    }

    static capy::task<>
    pong(capy::any_stream s)
    {
        char buf[4];
        auto [rec, rn] = co_await capy::read(
            s, make_buffer(buf));
        BOOST_TEST(!rec);
        BOOST_TEST_EQ(std::string_view(buf, 4), "ping");
        
        auto [wec, wn] = co_await capy::write(
            s, make_buffer("pong", 4));
        BOOST_TEST(!wec);
    }

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
            auto [rec, n] = co_await pc.stream().read_some(
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

            auto [rec, n1] = co_await pc.stream().read_some(
                make_buffer(buf));
            BOOST_TEST(rec == capy::error::timeout);
            BOOST_TEST_EQ(n1, 0);

            auto [wec, n2] = co_await pc.stream().write_some(
                make_buffer(buf));
            BOOST_TEST(wec == capy::error::timeout);
            BOOST_TEST_EQ(n2, 0);
        }());
    }

    void
    testTcpConnectionReuse()
    {
        corosio::io_context ioc;
        loopback_server server{ ioc };

        auto server_task = [&]() -> capy::task<>
        {
            auto s = co_await server.next();
            co_await pong(&s);
            co_await pong(&s);
        };

        auto client_task = [&]() -> capy::task<>
        {
            auto pool = std::make_shared<connection_pool>(
                co_await capy::this_coro::executor,
                corosio::tls_context{},
                client::config{});

            for(auto i : { 0, 1 })
            {
                auto [aec, pc] = co_await pool->acquire(server.url("http"));
                BOOST_TEST(!aec);
                co_await ping(pc.stream());
                pool->release(std::move(pc));
            }
        };

        capy::run_async(ioc.get_executor())(server_task());
        capy::run_async(ioc.get_executor())(client_task());
        ioc.run();
    }

    void
    testTcpConnectionRefused()
    {
        corosio::io_context ioc;

        // Reserve an ephemeral port, then drop the listener.
        urls::url url;
        {
            loopback_server server{ ioc };
            url = server.url("http");
        }

        auto client_task = [&]() -> capy::task<>
        {
            auto pool = std::make_shared<connection_pool>(
                co_await capy::this_coro::executor,
                corosio::tls_context(),
                client::config{});

            auto [aec, pc] = co_await pool->acquire(url);
            BOOST_TEST(aec);
            BOOST_TEST(!static_cast<bool>(pc));
            pool->release(std::move(pc));
        };

        capy::run_async(ioc.get_executor())(client_task());
        ioc.run();
    }

    void
    testTlsConnectionReuse()
    {
        corosio::io_context ioc;
        loopback_server server{ ioc };

        corosio::tls_context tls_ctx;
        BOOST_TEST(!tls_ctx.use_certificate(
            server_cert, corosio::tls_file_format::pem));
        BOOST_TEST(!tls_ctx.use_private_key(
            server_key, corosio::tls_file_format::pem));
        BOOST_TEST(!tls_ctx.set_verify_mode(
            corosio::tls_verify_mode::none));

        auto server_task = [&]() -> capy::task<>
        {
            corosio::openssl_stream s{ co_await server.next(), tls_ctx };
            auto [hec] = co_await s.handshake(
                corosio::openssl_stream::server);
            BOOST_TEST(!hec);

            co_await pong(&s);
            co_await pong(&s);

            // TODO: tls shutdown
        };

        auto client_task = [&]() -> capy::task<>
        {
            auto pool = std::make_shared<connection_pool>(
                co_await capy::this_coro::executor,
                corosio::tls_context{},
                client::config{});

            for(auto i : { 0, 1 })
            {
                auto [aec, pc] = co_await pool->acquire(server.url("https"));
                BOOST_TEST(!aec);
                co_await ping(pc.stream());
                pool->release(std::move(pc));
            }
        };

        capy::run_async(ioc.get_executor())(server_task());
        capy::run_async(ioc.get_executor())(client_task());
        ioc.run();
    }

    void
    testTlsHandshakeFailure()
    {
        corosio::io_context ioc;
        loopback_server server{ ioc };

        auto server_task = [&]() -> capy::task<>
        {
            auto peer = co_await server.next();
            peer.close(); // the client handshake should fail
        };

        auto client_task = [&]() -> capy::task<>
        {
            auto pool = std::make_shared<connection_pool>(
                co_await capy::this_coro::executor,
                corosio::tls_context(),
                client::config{});

            auto [ec, pc] = co_await pool->acquire(server.url("https"));
            BOOST_TEST(ec);
            BOOST_TEST(!static_cast<bool>(pc));
        };

        capy::run_async(ioc.get_executor())(server_task());
        capy::run_async(ioc.get_executor())(client_task());
        ioc.run();
    }

    void
    testSocks5hProxy()
    {
        corosio::io_context ioc;
        loopback_server server{ ioc };

        auto server_task = [&]() -> capy::task<>
        {
            auto s = co_await server.next();

            // socks5h handshake
            {
                // greeting: VER, NMETHODS, METHODS...
                std::uint8_t greeting[3];
                auto [gec, gn] =
                    co_await capy::read(s, make_buffer(greeting));
                BOOST_TEST(!gec);
                BOOST_TEST_EQ(greeting[0], 0x05); // SOCKS5
                BOOST_TEST_EQ(greeting[1], 0x01); // one method
                BOOST_TEST_EQ(greeting[2], 0x00); // no authentication

                // reply: VER, METHOD (no authentication)
                std::uint8_t method[2] = { 0x05, 0x00 };
                auto [mec, mn] = co_await s.write_some(make_buffer(method));
                BOOST_TEST(!mec);

                // request head: VER, CMD, RSV, ATYP, domain length
                std::uint8_t head[5];
                auto [hec, hn] = co_await capy::read(s, make_buffer(head));
                BOOST_TEST(!hec);
                BOOST_TEST_EQ(head[0], 0x05); // SOCKS5
                BOOST_TEST_EQ(head[1], 0x01); // CONNECT
                BOOST_TEST_EQ(head[3], 0x03); // domain name

                // request tail: domain name + port
                char tail[256 + 2];
                auto [tec, tn] = co_await capy::read(
                    s, make_buffer(tail, head[4] + 2u));
                BOOST_TEST(!tec);
                BOOST_TEST_EQ(std::string_view(tail, head[4]), "example.com");
                BOOST_TEST_EQ(tail[head[4]], 0x00); // port hi
                BOOST_TEST_EQ(tail[head[4] + 1], 0x50); // 80

                // reply success: VER, REP, RSV, ATYP, BND.ADDR, BND.PORT
                std::uint8_t reply[10] = {
                    0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0 };
                auto [rec, rn] = co_await s.write_some(make_buffer(reply));
                BOOST_TEST(!rec);
            }

            co_await pong(&s);
            co_await pong(&s);
        };

        auto client_task = [&]() -> capy::task<>
        {
            client::config cfg{};
            cfg.proxy = server.url("socks5h");

            auto pool = std::make_shared<connection_pool>(
                co_await capy::this_coro::executor,
                corosio::tls_context{},
                std::move(cfg));

            for(auto i : { 0, 1 })
            {
                auto [aec, pc] = co_await pool->acquire("http://example.com");
                BOOST_TEST(!aec);
                co_await ping(pc.stream());
                pool->release(std::move(pc));
            }
        };

        capy::run_async(ioc.get_executor())(server_task());
        capy::run_async(ioc.get_executor())(client_task());
        ioc.run();
    }

    void
    testSocks5Proxy()
    {
        corosio::io_context ioc;
        loopback_server server{ ioc };

        auto server_task = [&]() -> capy::task<>
        {
            auto s = co_await server.next();

            // socks5 handshake
            {
                // greeting: VER, NMETHODS, METHODS...
                std::uint8_t greeting[3];
                auto [gec, gn] =
                    co_await capy::read(s, make_buffer(greeting));
                BOOST_TEST(!gec);
                BOOST_TEST_EQ(greeting[0], 0x05); // SOCKS5
                BOOST_TEST_EQ(greeting[1], 0x01); // one method
                BOOST_TEST_EQ(greeting[2], 0x00); // no authentication

                // reply: VER, METHOD (no authentication)
                std::uint8_t method[2] = { 0x05, 0x00 };
                auto [mec, mn] = co_await s.write_some(make_buffer(method));
                BOOST_TEST(!mec);

                // request head: VER, CMD, RSV, ATYP
                std::uint8_t head[4];
                auto [hec, hn] = co_await capy::read(s, make_buffer(head));
                BOOST_TEST(!hec);
                BOOST_TEST_EQ(head[0], 0x05); // SOCKS5
                BOOST_TEST_EQ(head[1], 0x01); // CONNECT
                BOOST_TEST_EQ(head[3], 0x01); // IPv4 (resolved locally)

                // request tail: 4-byte IPv4 address + port
                std::uint8_t tail[6];
                auto [tec, tn] = co_await capy::read(s, make_buffer(tail));
                BOOST_TEST(!tec);
                BOOST_TEST_EQ(tail[0], 0x7F); // 127
                BOOST_TEST_EQ(tail[1], 0x00); // 0
                BOOST_TEST_EQ(tail[2], 0x00); // 0
                BOOST_TEST_EQ(tail[3], 0x01); // 1
                BOOST_TEST_EQ(tail[4], 0x00); // port hi
                BOOST_TEST_EQ(tail[5], 0x50); // 80

                // reply success: VER, REP, RSV, ATYP, BND.ADDR, BND.PORT
                std::uint8_t reply[10] = {
                    0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0 };
                auto [rec, rn] = co_await s.write_some(make_buffer(reply));
                BOOST_TEST(!rec);
            }

            co_await pong(&s);
            co_await pong(&s);
        };

        auto client_task = [&]() -> capy::task<>
        {
            client::config cfg{};
            cfg.proxy = server.url("socks5");

            auto pool = std::make_shared<connection_pool>(
                co_await capy::this_coro::executor,
                corosio::tls_context{},
                std::move(cfg));

            for(auto i : { 0, 1 })
            {
                auto [aec, pc] = co_await pool->acquire("http://127.0.0.1");
                BOOST_TEST(!aec);
                co_await ping(pc.stream());
                pool->release(std::move(pc));
            }
        };

        capy::run_async(ioc.get_executor())(server_task());
        capy::run_async(ioc.get_executor())(client_task());
        ioc.run();
    }

    void
    testHttpProxy()
    {
        corosio::io_context ioc;
        loopback_server server{ ioc };

        auto server_task = [&]() -> capy::task<>
        {
            auto s = co_await server.next();

            // http proxy handshake
            {
                // CONNECT request: read up to the end of the headers
                std::string req;
                auto [rec, rn] = co_await capy::read_until(
                    s, capy::dynamic_buffer(req), "\r\n\r\n");
                BOOST_TEST(!rec);
                BOOST_TEST(req.starts_with(
                    "CONNECT example.com:80 HTTP/1.1\r\n"));

                // reply: tunnel established
                std::string_view resp =
                    "HTTP/1.1 200 Connection established\r\n\r\n";
                auto [wec, wn] = co_await capy::write(s, make_buffer(resp));
                BOOST_TEST(!wec);
            }

            co_await pong(&s);
            co_await pong(&s);
        };

        auto client_task = [&]() -> capy::task<>
        {
            client::config cfg{};
            cfg.proxy = server.url("http");

            auto pool = std::make_shared<connection_pool>(
                co_await capy::this_coro::executor,
                corosio::tls_context{},
                std::move(cfg));

            for(auto i : { 0, 1 })
            {
                auto [aec, pc] = co_await pool->acquire("http://example.com");
                BOOST_TEST(!aec);
                co_await ping(pc.stream());
                pool->release(std::move(pc));
            }
        };

        capy::run_async(ioc.get_executor())(server_task());
        capy::run_async(ioc.get_executor())(client_task());
        ioc.run();
    }

    void
    testUnsupportedProxyScheme()
    {
        corosio::io_context ioc;
        loopback_server server{ ioc };

        for(auto const scheme : { "ftp", "https" })
        {
            capy::run_async(ioc.get_executor())([&]() -> capy::task<>
            {
                client::config cfg;
                cfg.proxy = server.url(scheme);
                auto pool = std::make_shared<connection_pool>(
                    co_await capy::this_coro::executor,
                    corosio::tls_context(),
                    cfg);

                auto [ec, pc] =
                    co_await pool->acquire("http://example.com");
                BOOST_TEST_EQ(ec, error::unsupported_proxy_scheme);
                BOOST_TEST(!pc);
            }());
            ioc.run();
            ioc.restart();
        }
    }

    void
    testUnsupportedUrlScheme()
    {
        scripted_net net;

        capy::test::run_blocking()([&]() -> capy::task<>
        {
            auto pool = std::make_shared<connection_pool>(
                co_await capy::this_coro::executor,
                corosio::tls_context(),
                net.config());

            for(auto const* url : { "ftp://example.com", "ws://example.com" })
            {
                auto [ec, pc] = co_await pool->acquire(url);
                BOOST_TEST_EQ(ec, error::unsupported_url_scheme);
                BOOST_TEST(!pc);
            }
        }());

        BOOST_TEST_EQ(net.connects(), 0u);
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
        testTcpConnectionReuse();
        testTcpConnectionRefused();
        testTlsConnectionReuse();
        testTlsHandshakeFailure();
        testSocks5Proxy();
        testSocks5hProxy();
        testHttpProxy();
        testUnsupportedProxyScheme();
        testUnsupportedUrlScheme();
    }
};

TEST_SUITE(connection_pool_test, "boost.burl.detail.connection_pool");

} // namespace detail
} // namespace burl
} // namespace boost
