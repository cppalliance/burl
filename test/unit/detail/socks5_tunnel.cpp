//
// Copyright (c) 2026 Mohammad Nejati
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

// Test that header file is self-contained.
#include "src/detail/socks5_tunnel.hpp"

#include "test_suite.hpp"

#include <boost/burl/error.hpp>
#include <boost/capy/io/any_stream.hpp>
#include <boost/capy/task.hpp>
#include <boost/capy/test/run_blocking.hpp>
#include <boost/capy/test/stream.hpp>
#include <boost/url/parse.hpp>
#include <boost/url/url.hpp>

#include <initializer_list>
#include <string>
#include <string_view>
#include <system_error>

namespace boost
{
namespace burl
{
namespace detail
{

class socks5_tunnel_test
{
    static std::string
    bytes(std::initializer_list<unsigned char> xs)
    {
        return std::string(xs.begin(), xs.end());
    }

    static std::string
    ipv4_reply()
    {
        return bytes(
            { 0x05, 0x00, 0x00, 0x01, 0x7F, 0x00, 0x00, 0x01, 0x00, 0x50 });
    }

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
                auto [e] = co_await open_socks5_tunnel(
                    capy::any_stream(&client), host, port, proxy);
                ec = e;
            }());
        return ec;
    }

public:
    void
    testSuccessNoAuth()
    {
        auto [client, server] = capy::test::make_stream_pair();
        server.provide(bytes({ 0x05, 0x00 }) + ipv4_reply());

        auto proxy = urls::parse_uri("socks5://proxy:1080").value();
        auto ec    = run_tunnel(client, "example.com", "443", proxy);

        BOOST_TEST(!ec);

        std::string expected = bytes({ 0x05, 0x01, 0x00 }); // greeting, no auth
        expected += bytes({ 0x05, 0x01, 0x00, 0x03, 0x0B }); // connect, domain
        expected += "example.com";
        expected += bytes({ 0x01, 0xBB }); // port 443
        BOOST_TEST(server.data() == expected);
    }

    void
    testSuccessWithAuth()
    {
        auto [client, server] = capy::test::make_stream_pair();
        server.provide(
            bytes({ 0x05, 0x02 }) + // method: username/password
            bytes({ 0x01, 0x00 }) + // auth granted
            ipv4_reply());

        auto proxy = urls::parse_uri("socks5://user:pass@proxy:1080").value();
        auto ec    = run_tunnel(client, "example.com", "443", proxy);

        BOOST_TEST(!ec);

        std::string expected = bytes({ 0x05, 0x02, 0x00, 0x02 }); // greeting
        expected += bytes({ 0x01, 0x04 }) + "user"; // auth: ulen, user
        expected += bytes({ 0x04 }) + "pass";       // plen, pass
        expected += bytes({ 0x05, 0x01, 0x00, 0x03, 0x0B }) + "example.com";
        expected += bytes({ 0x01, 0xBB });
        BOOST_TEST(server.data() == expected);
    }

    void
    testSuccessDomainReply()
    {
        auto [client, server] = capy::test::make_stream_pair();
        server.provide(
            bytes({ 0x05, 0x00 }) +
            bytes({ 0x05, 0x00, 0x00, 0x03, 0x0B }) + // ATYP=domain, len 11
            "example.com" + bytes({ 0x00, 0x50 }));

        auto proxy = urls::parse_uri("socks5://proxy:1080").value();
        auto ec    = run_tunnel(client, "example.com", "443", proxy);

        BOOST_TEST(!ec);
    }

    void
    testUnsupportedVersion()
    {
        auto [client, server] = capy::test::make_stream_pair();
        server.provide(bytes({ 0x04, 0x00 }));

        auto proxy = urls::parse_uri("socks5://proxy:1080").value();
        auto ec    = run_tunnel(client, "example.com", "443", proxy);

        BOOST_TEST(ec == error::proxy_unsupported_version);
    }

    void
    testAuthFailed()
    {
        auto [client, server] = capy::test::make_stream_pair();
        server.provide(bytes({ 0x05, 0x02 }) + bytes({ 0x01, 0x01 }));

        auto proxy = urls::parse_uri("socks5://user:pass@proxy:1080").value();
        auto ec    = run_tunnel(client, "example.com", "443", proxy);

        BOOST_TEST(ec == error::proxy_auth_failed);
    }

    void
    testNoAcceptableMethods()
    {
        auto [client, server] = capy::test::make_stream_pair();
        server.provide(bytes({ 0x05, 0xFF }));

        auto proxy = urls::parse_uri("socks5://proxy:1080").value();
        auto ec    = run_tunnel(client, "example.com", "443", proxy);

        BOOST_TEST(ec == error::proxy_auth_failed);
    }

    void
    testConnectRejected()
    {
        auto [client, server] = capy::test::make_stream_pair();
        server.provide(
            bytes({ 0x05, 0x00 }) + bytes({ 0x05, 0x01, 0x00, 0x01, 0x00 }));

        auto proxy = urls::parse_uri("socks5://proxy:1080").value();
        auto ec    = run_tunnel(client, "example.com", "443", proxy);

        BOOST_TEST(ec == error::proxy_connect_failed);
    }

    void
    run()
    {
        testSuccessNoAuth();
        testSuccessWithAuth();
        testSuccessDomainReply();
        testUnsupportedVersion();
        testAuthFailed();
        testNoAcceptableMethods();
        testConnectRejected();
    }
};

TEST_SUITE(socks5_tunnel_test, "boost.burl.detail.socks5_tunnel");

} // namespace detail
} // namespace burl
} // namespace boost
