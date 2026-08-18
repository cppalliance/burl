//
// Copyright (c) 2026 Mohammad Nejati
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

// Test that header file is self-contained.
#include "src/detail/http_tunnel.hpp"

#include "test_suite.hpp"

#include <boost/burl/error.hpp>

#include <boost/capy/test/fuse.hpp>
#include <boost/capy/test/stream.hpp>


namespace boost
{
namespace burl
{
namespace detail
{

class http_tunnel_test
{
    static std::error_code
    run(
        capy::test::stream& client,
        urls::url_view target,
        urls::url_view proxy)
    {
        std::error_code ret;
        capy::test::run_blocking(
            [&](capy::io_result<> rs){ ret = std::get<0>(rs);})
                (open_http_tunnel(&client, target, proxy));
        return ret;
    }

public:
    void
    testSuccess()
    {
        auto [client, server] = capy::test::make_stream_pair();
        server.provide("HTTP/1.1 200 Connection established\r\n\r\n");

        auto ec = run(
            client,
            "https://example.com",
            "http://proxy:8080");

        BOOST_TEST(!ec);

        auto req = server.data();
        BOOST_TEST(req.starts_with("CONNECT example.com:443 HTTP/1.1\r\n"));
        BOOST_TEST(
            req.find("Host: example.com:443\r\n") != std::string_view::npos);
        BOOST_TEST(
            req.find("Proxy-Connection: keep-alive\r\n") !=
            std::string_view::npos);
        BOOST_TEST(
            req.find("Proxy-Authorization:") == std::string_view::npos);
    }

    void
    testSuccessWithAuth()
    {
        auto [client, server] = capy::test::make_stream_pair();
        server.provide("HTTP/1.1 200 Connection established\r\n\r\n");

        auto ec = run(
            client,
            "https://example.com",
            "http://user:pass@proxy:8080");

        BOOST_TEST(!ec);
        // Basic base64("user:pass")
        BOOST_TEST(
            server.data().find("Proxy-Authorization: Basic dXNlcjpwYXNz\r\n") !=
            std::string_view::npos);
    }

    void
    testSuccessIPv6Target()
    {
        auto [client, server] = capy::test::make_stream_pair();
        server.provide("HTTP/1.1 200 Connection established\r\n\r\n");

        auto ec = run(
            client,
            "https://[2001:db8::1]:8443",
            "http://proxy:8080");

        BOOST_TEST(!ec);

        auto req = server.data();
        // IPv6 literals must stay bracketed in the request-target and Host.
        BOOST_TEST(req.starts_with(
            "CONNECT [2001:db8::1]:8443 HTTP/1.1\r\n"));
        BOOST_TEST(
            req.find("Host: [2001:db8::1]:8443\r\n") !=
            std::string_view::npos);
    }

    void
    testAuthRequired()
    {
        auto [client, server] = capy::test::make_stream_pair();
        server.provide("HTTP/1.1 407 Proxy Authentication Required\r\n\r\n");

        auto ec = run(
            client,
            "https://example.com",
            "http://proxy:8080");

        BOOST_TEST(ec == error::proxy_auth_failed);
    }

    void
    testConnectFailed()
    {
        auto [client, server] = capy::test::make_stream_pair();
        server.provide("HTTP/1.1 403 Forbidden\r\n\r\n");

        auto ec = run(
            client,
            "https://example.com",
            "http://proxy:8080");

        BOOST_TEST(ec == error::proxy_connect_failed);
    }

    void
    testReadError()
    {
        auto [client, server] = capy::test::make_stream_pair();
        server.close(); // eof before any response

        auto ec = run(
            client,
            "https://example.com",
            "http://proxy:8080");

        BOOST_TEST(ec == error::proxy_connect_failed);
    }

    void
    testTransportErrorInjection()
    {
        capy::test::fuse f;
        auto r = f.armed([&](capy::test::fuse&) -> capy::task<>
        {
            auto [client, server] = capy::test::make_stream_pair(f);
            server.provide("HTTP/1.1 200 Connection established\r\n\r\n");

            auto [ec] = co_await open_http_tunnel(
                &client,
                "https://example.com",
                "http://proxy:8080");

            if(ec)
                co_return;

            BOOST_TEST(server.data().starts_with(
                "CONNECT example.com:443 HTTP/1.1\r\n"));
        });
        BOOST_TEST(r.success);
    }

    void
    run()
    {
        testSuccess();
        testSuccessWithAuth();
        testSuccessIPv6Target();
        testAuthRequired();
        testConnectFailed();
        testReadError();
        testTransportErrorInjection();
    }
};

TEST_SUITE(http_tunnel_test, "boost.burl.detail.http_tunnel");

} // namespace detail
} // namespace burl
} // namespace boost
