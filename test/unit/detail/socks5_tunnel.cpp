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

#include <boost/capy/test/fuse.hpp>
#include <boost/capy/test/stream.hpp>


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
    run(
        capy::test::stream& client,
        urls::url_view target,
        urls::url_view proxy)
    {
        std::error_code ret;
        capy::test::run_blocking(
            [&](capy::io_result<> rs){ ret = std::get<0>(rs);})
                (open_socks5_tunnel(&client, target, proxy));
        return ret;
    }

public:
    void
    testSuccessNoAuth()
    {
        auto [client, server] = capy::test::make_stream_pair();
        server.provide(bytes({ 0x05, 0x00 }) + ipv4_reply());

        auto ec = run(
            client,
            "https://example.com",
            "socks5://proxy:1080");

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

        auto ec = run(
            client,
            "https://example.com",
            "socks5://user:pass@proxy:1080");

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

        auto ec = run(
            client,
            "https://example.com",
            "socks5://proxy:1080");

        BOOST_TEST(!ec);
    }

    void
    testSuccessIPv4Target()
    {
        auto [client, server] = capy::test::make_stream_pair();
        server.provide(bytes({ 0x05, 0x00 }) + ipv4_reply());

        auto ec = run(
            client,
            "https://192.168.0.1",
            "socks5://proxy:1080");

        BOOST_TEST(!ec);

        std::string expected = bytes({ 0x05, 0x01, 0x00 }); // greeting, no auth
        // connect, ATYP=IPv4, address bytes, port 443
        expected += bytes(
            { 0x05, 0x01, 0x00, 0x01, 0xC0, 0xA8, 0x00, 0x01, 0x01, 0xBB });
        BOOST_TEST(server.data() == expected);
    }

    void
    testSuccessIPv6Target()
    {
        auto [client, server] = capy::test::make_stream_pair();
        server.provide(bytes({ 0x05, 0x00 }) + ipv4_reply());

        auto ec = run(
            client,
            "https://[2001:db8::1]",
            "socks5://proxy:1080");

        BOOST_TEST(!ec);

        std::string expected = bytes({ 0x05, 0x01, 0x00 }); // greeting, no auth
        // connect, ATYP=IPv6
        expected += bytes({ 0x05, 0x01, 0x00, 0x04 });
        expected += bytes(
            { 0x20, 0x01, 0x0D, 0xB8, 0x00, 0x00, 0x00, 0x00,
              0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 });
        expected += bytes({ 0x01, 0xBB }); // port 443
        BOOST_TEST(server.data() == expected);
    }

    void
    testUnsupportedVersion()
    {
        auto [client, server] = capy::test::make_stream_pair();
        server.provide(bytes({ 0x04, 0x00 }));

        auto ec = run(
            client,
            "https://example.com",
            "socks5://proxy:1080");

        BOOST_TEST(ec == error::proxy_unsupported_version);
    }

    void
    testAuthFailed()
    {
        auto [client, server] = capy::test::make_stream_pair();
        server.provide(bytes({ 0x05, 0x02 }) + bytes({ 0x01, 0x01 }));

        auto ec = run(
            client,
            "https://example.com",
            "socks5://user:pass@proxy:1080");

        BOOST_TEST(ec == error::proxy_auth_failed);
    }

    void
    testNoAcceptableMethods()
    {
        auto [client, server] = capy::test::make_stream_pair();
        server.provide(bytes({ 0x05, 0xFF }));

        auto ec = run(
            client,
            "https://example.com",
            "socks5://proxy:1080");

        BOOST_TEST(ec == error::proxy_auth_failed);
    }

    void
    testConnectRejected()
    {
        auto [client, server] = capy::test::make_stream_pair();
        server.provide(
            bytes({ 0x05, 0x00 }) + bytes({ 0x05, 0x01, 0x00, 0x01, 0x00 }));

        auto ec = run(
            client,
            "https://example.com",
            "socks5://proxy:1080");

        BOOST_TEST(ec == error::proxy_connect_failed);
    }

    void
    testIPv6Reply()
    {
        auto [client, server] = capy::test::make_stream_pair();
        server.provide(
            bytes({ 0x05, 0x00 }) +
            bytes({ 0x05, 0x00, 0x00, 0x04 }) + // ATYP=IPv6
            std::string(16, '\0') +             // 16-byte address
            bytes({ 0x00, 0x50 }));             // port

        auto ec = run(
            client,
            "https://example.com",
            "socks5://proxy:1080");

        BOOST_TEST(!ec);
    }

    void
    testInvalidAtype()
    {
        auto [client, server] = capy::test::make_stream_pair();
        server.provide(
            bytes({ 0x05, 0x00 }) +
            bytes({ 0x05, 0x00, 0x00, 0x09, 0x00 })); // unknown ATYP 0x09

        auto ec = run(
            client,
            "https://example.com",
            "socks5://proxy:1080");

        BOOST_TEST(ec == error::proxy_connect_failed);
    }

    void
    testTransportErrorInjection()
    {
        capy::test::fuse f;
        auto r = f.armed([&](capy::test::fuse&) -> capy::task<>
        {
            auto [client, server] = capy::test::make_stream_pair(f);
            server.provide(bytes({ 0x05, 0x00 }) + ipv4_reply());

            auto [ec] = co_await open_socks5_tunnel(
                &client,
                "https://example.com",
                "socks5://proxy:1080");

            if(ec)
                co_return;

            std::string expected = bytes({ 0x05, 0x01, 0x00 });
            expected += bytes({ 0x05, 0x01, 0x00, 0x03, 0x0B });
            expected += "example.com";
            expected += bytes({ 0x01, 0xBB });
            BOOST_TEST(server.data() == expected);
        });
        BOOST_TEST(r.success);
    }

    void
    run()
    {
        testSuccessNoAuth();
        testSuccessWithAuth();
        testSuccessDomainReply();
        testSuccessIPv4Target();
        testSuccessIPv6Target();
        testUnsupportedVersion();
        testAuthFailed();
        testNoAcceptableMethods();
        testConnectRejected();
        testIPv6Reply();
        testInvalidAtype();
        testTransportErrorInjection();
    }
};

TEST_SUITE(socks5_tunnel_test, "boost.burl.detail.socks5_tunnel");

} // namespace detail
} // namespace burl
} // namespace boost
