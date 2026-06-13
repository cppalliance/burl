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
#include <boost/capy/io/any_stream.hpp>
#include <boost/capy/task.hpp>
#include <boost/capy/test/run_blocking.hpp>
#include <boost/capy/test/stream.hpp>
#include <boost/url/parse.hpp>
#include <boost/url/url.hpp>

#include <string_view>
#include <system_error>

namespace boost
{
namespace burl
{
namespace detail
{

class http_tunnel_test
{
    static std::error_code
    run_tunnel(
        capy::test::stream& client,
        std::string_view host,
        std::string_view port,
        urls::url_view proxy)
    {
        std::error_code ec;
        capy::test::run_blocking()(
            [&]() -> capy::task<>
            {
                auto [e] = co_await open_http_tunnel(
                    capy::any_stream(&client), host, port, proxy);
                ec = e;
            }());
        return ec;
    }

public:
    void
    testSuccess()
    {
        auto [client, server] = capy::test::make_stream_pair();
        server.provide("HTTP/1.1 200 Connection established\r\n\r\n");

        auto proxy = urls::parse_uri("http://proxy:8080").value();
        auto ec    = run_tunnel(client, "example.com", "443", proxy);

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

        auto proxy = urls::parse_uri("http://user:pass@proxy:8080").value();
        auto ec    = run_tunnel(client, "example.com", "443", proxy);

        BOOST_TEST(!ec);
        // Basic base64("user:pass")
        BOOST_TEST(
            server.data().find("Proxy-Authorization: Basic dXNlcjpwYXNz\r\n") !=
            std::string_view::npos);
    }

    void
    testAuthRequired()
    {
        auto [client, server] = capy::test::make_stream_pair();
        server.provide("HTTP/1.1 407 Proxy Authentication Required\r\n\r\n");

        auto proxy = urls::parse_uri("http://proxy:8080").value();
        auto ec    = run_tunnel(client, "example.com", "443", proxy);

        BOOST_TEST(ec == error::proxy_auth_failed);
    }

    void
    testConnectFailed()
    {
        auto [client, server] = capy::test::make_stream_pair();
        server.provide("HTTP/1.1 403 Forbidden\r\n\r\n");

        auto proxy = urls::parse_uri("http://proxy:8080").value();
        auto ec    = run_tunnel(client, "example.com", "443", proxy);

        BOOST_TEST(ec == error::proxy_connect_failed);
    }

    void
    testReadError()
    {
        auto [client, server] = capy::test::make_stream_pair();
        server.close(); // eof before any response

        auto proxy = urls::parse_uri("http://proxy:8080").value();
        auto ec    = run_tunnel(client, "example.com", "443", proxy);

        BOOST_TEST(ec == error::proxy_connect_failed);
    }

    void
    run()
    {
        testSuccess();
        testSuccessWithAuth();
        testAuthRequired();
        testConnectFailed();
        testReadError();
    }
};

TEST_SUITE(http_tunnel_test, "boost.burl.detail.http_tunnel");

} // namespace detail
} // namespace burl
} // namespace boost
