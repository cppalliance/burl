//
// Copyright (c) 2026 Mohammad Nejati
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

// Test that header file is self-contained.
#include <boost/burl/client.hpp>

#include <boost/burl/error.hpp>
#include <boost/burl/string.hpp>

#include <boost/capy/delay.hpp>
#include <boost/capy/ex/system_context.hpp>
#include <boost/capy/ex/this_coro.hpp>
#include <boost/capy/io/any_stream.hpp>
#include <boost/http/brotli/decode.hpp>
#include <boost/http/zlib/inflate.hpp>
#include <boost/capy/task.hpp>
#include <boost/capy/test/fuse.hpp>
#include <boost/capy/test/run_blocking.hpp>
#include <boost/capy/test/stream.hpp>
#include <boost/corosio/tls_context.hpp>
#include <boost/url/url.hpp>

#include "test_suite.hpp"

#include <chrono>
#include <deque>
#include <string>
#include <string_view>
#include <vector>

namespace boost
{
namespace burl
{

using namespace std::chrono_literals;

class client_test
{
    struct fake_net
    {
        capy::test::fuse fuse;
        std::vector<std::string> scripts;
        std::vector<bool> closes; // close srv after providing script N
        std::deque<capy::test::stream> servers;
        std::vector<std::string> origins;

        fake_net() = default;

        explicit fake_net(capy::test::fuse f)
            : fuse(std::move(f))
        {
        }

        client::config
        config()
        {
            client::config cfg;
            cfg.brotli  = false;
            cfg.deflate = false;
            cfg.gzip    = false;
            cfg.connect_handler =
                [this](urls::url_view url) -> capy::io_task<capy::any_stream>
            {
                origins.emplace_back(url.encoded_origin());
                auto [cli, srv] = capy::test::make_stream_pair(fuse);
                auto const n = servers.size();
                if(n < scripts.size() && !scripts[n].empty())
                    srv.provide(scripts[n]);
                if(n < closes.size() && closes[n])
                    srv.close();
                servers.push_back(std::move(srv));
                co_return { {}, capy::any_stream(std::move(cli)) };
            };
            return cfg;
        }

        std::size_t
        connects() const noexcept
        {
            return servers.size();
        }

        capy::test::stream&
        server(std::size_t i)
        {
            return servers.at(i);
        }

        std::string
        written(std::size_t i)
        {
            return std::string(servers.at(i).data());
        }
    };

public:

    void
    testRequestSerialization()
    {
        fake_net net;
        net.scripts = {
            "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n" };

        capy::test::run_blocking()(
            [&]() -> capy::task<>
            {
                client c(
                    co_await capy::this_coro::executor,
                    corosio::tls_context(),
                    net.config());

                auto [ec, r] = co_await c
                    .get("http://example.com/index.html?x=1")
                    .send();
                BOOST_TEST(!ec);
                BOOST_TEST(r.status() == http::status::ok);
            }());

        BOOST_TEST_EQ(
            net.written(0),
            "GET /index.html?x=1 HTTP/1.1\r\n"
            "Host: example.com\r\n"
            "\r\n");
    }

    void
    testEmptyPathBecomesSlash()
    {
        fake_net net;
        net.scripts = {
            "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n" };

        capy::test::run_blocking()(
            [&]() -> capy::task<>
            {
                client c(
                    co_await capy::this_coro::executor,
                    corosio::tls_context(),
                    net.config());
                auto [ec, r] =
                    co_await c.get("http://example.com").send();
                BOOST_TEST(!ec);
            }());

        BOOST_TEST(
            net.written(0).find("GET / HTTP/1.1\r\n") == 0);
        // Default port must not appear in Host.
        BOOST_TEST(
            net.written(0).find("Host: example.com\r\n") !=
            std::string::npos);
    }

    void
    testPostBody()
    {
        fake_net net;
        net.scripts = {
            "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n" };

        capy::test::run_blocking()(
            [&]() -> capy::task<>
            {
                client c(
                    co_await capy::this_coro::executor,
                    corosio::tls_context(),
                    net.config());
                auto [ec, r] = co_await c
                    .post("http://example.com/submit")
                    .body("abc")
                    .send();
                BOOST_TEST(!ec);
            }());

        auto out = net.written(0);
        BOOST_TEST(
            out.find("POST /submit HTTP/1.1\r\n") == 0);
        BOOST_TEST(
            out.find("Content-Length: 3\r\n") != std::string::npos);
        // Body follows the header block.
        BOOST_TEST(
            out.find("\r\n\r\nabc") != std::string::npos);
    }

    void
    testStatusErrorWithReadableBody()
    {
        fake_net net;
        net.scripts = {
            "HTTP/1.1 404 Not Found\r\n"
            "Content-Length: 9\r\n"
            "\r\n"
            "not found" };

        capy::test::run_blocking()(
            [&]() -> capy::task<>
            {
                client c(
                    co_await capy::this_coro::executor,
                    corosio::tls_context(),
                    net.config());

                auto [ec, r] = co_await c
                    .get("http://example.com/missing")
                    .send();

                // Status errors flow as error codes, but the
                // response object is still fully usable: the
                // caller decides whether to read the error body.
                BOOST_TEST(ec == condition::client_error);
                BOOST_TEST(
                    r.status() == http::status::not_found);

                auto [ec2, body] = co_await r.try_as_view();
                BOOST_TEST(!ec2);
                BOOST_TEST_EQ(body, "not found");
            }());
    }

    void
    testRedirectSameOrigin()
    {
        fake_net net;
        net.scripts = {
            // Connection: close forces the second hop onto a
            // fresh pair so each script maps to one connection.
            "HTTP/1.1 302 Found\r\n"
            "Location: /next\r\n"
            "Content-Length: 0\r\n"
            "Connection: close\r\n"
            "\r\n",
            "HTTP/1.1 200 OK\r\n"
            "Content-Length: 5\r\n"
            "\r\n"
            "hello" };

        capy::test::run_blocking()(
            [&]() -> capy::task<>
            {
                client c(
                    co_await capy::this_coro::executor,
                    corosio::tls_context(),
                    net.config());

                auto [ec, r] = co_await c
                    .get("http://example.com/old")
                    .send();
                BOOST_TEST(!ec);
                BOOST_TEST(r.status() == http::status::ok);
                BOOST_TEST_EQ(
                    r.url().buffer(), "http://example.com/next");

                auto [ec2, body] = co_await r.try_as_view();
                BOOST_TEST(!ec2);
                BOOST_TEST_EQ(body, "hello");
            }());

        BOOST_TEST_EQ(net.connects(), 2u);
        BOOST_TEST(
            net.written(1).find("GET /next HTTP/1.1\r\n") == 0);
        // autoreferer defaults to on; same-origin hop carries
        // the originating URL.
        BOOST_TEST(
            net.written(1).find(
                "Referer: http://example.com/old\r\n") !=
            std::string::npos);
    }

    void
    test303MethodChange()
    {
        fake_net net;
        net.scripts = {
            "HTTP/1.1 303 See Other\r\n"
            "Location: /done\r\n"
            "Content-Length: 0\r\n"
            "Connection: close\r\n"
            "\r\n",
            "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n" };

        capy::test::run_blocking()(
            [&]() -> capy::task<>
            {
                client c(
                    co_await capy::this_coro::executor,
                    corosio::tls_context(),
                    net.config());

                auto [ec, r] = co_await c
                    .post("http://example.com/form")
                    .body("a=1")
                    .send();
                BOOST_TEST(!ec);
                BOOST_TEST(r.status() == http::status::ok);
            }());

        BOOST_TEST_EQ(net.connects(), 2u);

        // First hop: POST with body.
        BOOST_TEST(
            net.written(0).find("POST /form HTTP/1.1\r\n") == 0);

        // 303 rewrites to GET and the body and its framing
        // headers must be gone.
        auto out = net.written(1);
        BOOST_TEST(out.find("GET /done HTTP/1.1\r\n") == 0);
        BOOST_TEST(
            out.find("Content-Length") == std::string::npos);
        BOOST_TEST(
            out.find("Content-Type") == std::string::npos);
        BOOST_TEST(out.find("a=1") == std::string::npos);
    }

    void
    testCrossOriginDropsAuthorization()
    {
        fake_net net;
        net.scripts = {
            "HTTP/1.1 302 Found\r\n"
            "Location: http://other.example/x\r\n"
            "Content-Length: 0\r\n"
            "Connection: close\r\n"
            "\r\n",
            "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n" };

        capy::test::run_blocking()(
            [&]() -> capy::task<>
            {
                client c(
                    co_await capy::this_coro::executor,
                    corosio::tls_context(),
                    net.config());

                auto [ec, r] = co_await c
                    .get("http://example.com/login")
                    .header(
                        http::field::authorization,
                        "Bearer sekrit")
                    .send();
                BOOST_TEST(!ec);
            }());

        BOOST_TEST_EQ(net.connects(), 2u);
        BOOST_TEST_EQ(
            net.origins[1], "http://other.example");

        BOOST_TEST(
            net.written(0).find("Authorization: Bearer sekrit") !=
            std::string::npos);
        // Credentials must not leak across origins.
        BOOST_TEST(
            net.written(1).find("Authorization") ==
            std::string::npos);
    }

    void
    testUnrestrictedAuthKeepsAuthorization()
    {
        fake_net net;
        net.scripts = {
            "HTTP/1.1 302 Found\r\n"
            "Location: http://other.example/x\r\n"
            "Content-Length: 0\r\n"
            "Connection: close\r\n"
            "\r\n",
            "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n" };
        capy::test::run_blocking()(
            [&]() -> capy::task<>
            {
                auto cfg = net.config();
                cfg.unrestricted_auth = true;
                client c(
                    co_await capy::this_coro::executor,
                    corosio::tls_context(),
                    cfg);
                auto [ec, r] = co_await c
                    .get("http://example.com/login")
                    .header(
                        http::field::authorization,
                        "Bearer sekrit")
                    .send();
                BOOST_TEST(!ec);
            }());

        BOOST_TEST(
            net.written(1).find("Authorization: Bearer sekrit") !=
            std::string::npos);
    }

    void
    testTooManyRedirects()
    {
        fake_net net;
        auto const hop =
            "HTTP/1.1 302 Found\r\n"
            "Location: /again\r\n"
            "Content-Length: 0\r\n"
            "Connection: close\r\n"
            "\r\n";
        net.scripts = { hop, hop, hop };
        capy::test::run_blocking()(
            [&]() -> capy::task<>
            {
                auto cfg = net.config();
                cfg.maxredirs = 2;
                client c(
                    co_await capy::this_coro::executor,
                    corosio::tls_context(),
                    cfg);
                auto [ec, r] =
                    co_await c.get("http://example.com/").send();
                BOOST_TEST(ec == error::too_many_redirects);
            }());

        // Original request plus maxredirs follows, then stop.
        BOOST_TEST_EQ(net.connects(), 3u);
    }

    void
    testFollowlocationOff()
    {
        fake_net net;
        net.scripts = {
            "HTTP/1.1 302 Found\r\n"
            "Location: /next\r\n"
            "Content-Length: 0\r\n"
            "\r\n" };
        capy::test::run_blocking()(
            [&]() -> capy::task<>
            {
                auto cfg = net.config();
                cfg.followlocation = false;
                client c(
                    co_await capy::this_coro::executor,
                    corosio::tls_context(),
                    cfg);
                auto [ec, r] =
                    co_await c.get("http://example.com/").send();
                // 3xx is not an error condition; the caller
                // gets the redirect response itself.
                BOOST_TEST(!ec);
                BOOST_TEST(r.status() == http::status::found);
            }());

        BOOST_TEST_EQ(net.connects(), 1u);
    }

    void
    testBadRedirectResponse()
    {
        fake_net net;
        net.scripts = {
            // 302 without a usable Location.
            "HTTP/1.1 302 Found\r\n"
            "Content-Length: 0\r\n"
            "\r\n" };

        capy::test::run_blocking()(
            [&]() -> capy::task<>
            {
                client c(
                    co_await capy::this_coro::executor,
                    corosio::tls_context(),
                    net.config());
                auto [ec, r] =
                    co_await c.get("http://example.com/").send();
                BOOST_TEST(ec == error::bad_redirect_response);
            }());
    }

    void
    testKeepAliveReuse()
    {
        fake_net net;
        net.scripts = {
            "HTTP/1.1 200 OK\r\n"
            "Content-Length: 2\r\n"
            "\r\n"
            "ok" };

        capy::test::run_blocking()(
            [&]() -> capy::task<>
            {
                client c(
                    co_await capy::this_coro::executor,
                    corosio::tls_context(),
                    net.config());

                {
                    auto [ec, r] = co_await c
                        .get("http://example.com/a")
                        .send();
                    BOOST_TEST(!ec);
                    auto [ec2, body] = co_await r.try_as_view();
                    BOOST_TEST(!ec2);
                    BOOST_TEST_EQ(body, "ok");
                    // r destroyed here: complete + keep-alive,
                    // so the connection returns to the pool.
                }

                net.server(0).provide(
                    "HTTP/1.1 200 OK\r\n"
                    "Content-Length: 0\r\n"
                    "\r\n");

                auto [ec, r] = co_await c
                    .get("http://example.com/b")
                    .send();
                BOOST_TEST(!ec);
            }());

        // One dial, two requests over it.
        BOOST_TEST_EQ(net.connects(), 1u);
        auto out = net.written(0);
        BOOST_TEST(
            out.find("GET /a HTTP/1.1\r\n") == 0);
        BOOST_TEST(
            out.find("GET /b HTTP/1.1\r\n") != std::string::npos);
    }

    void
    testConnectionCloseNoReuse()
    {
        fake_net net;
        net.scripts = {
            "HTTP/1.1 200 OK\r\n"
            "Content-Length: 2\r\n"
            "Connection: close\r\n"
            "\r\n"
            "ok",
            "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n" };

        capy::test::run_blocking()(
            [&]() -> capy::task<>
            {
                client c(
                    co_await capy::this_coro::executor,
                    corosio::tls_context(),
                    net.config());

                {
                    auto [ec, r] = co_await c
                        .get("http://example.com/a")
                        .send();
                    BOOST_TEST(!ec);
                    auto [ec2, body] = co_await r.try_as_view();
                    BOOST_TEST(!ec2);
                }

                auto [ec, r] = co_await c
                    .get("http://example.com/b")
                    .send();
                BOOST_TEST(!ec);
            }());

        BOOST_TEST_EQ(net.connects(), 2u);
    }

    void
    testUnconsumedBodyNoReuse()
    {
        fake_net net;
        net.scripts = {
            "HTTP/1.1 200 OK\r\n"
            "Content-Length: 1024\r\n"
            "\r\n", // body never arrives in full
            "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n" };

        capy::test::run_blocking()(
            [&]() -> capy::task<>
            {
                client c(
                    co_await capy::this_coro::executor,
                    corosio::tls_context(),
                    net.config());

                {
                    auto [ec, r] = co_await c
                        .get("http://example.com/a")
                        .send();
                    BOOST_TEST(!ec);
                    // Drop r with 1024 unread body bytes
                    // outstanding: dirty, must not be pooled.
                }

                auto [ec, r] = co_await c
                    .get("http://example.com/b")
                    .send();
                BOOST_TEST(!ec);
            }());

        BOOST_TEST_EQ(net.connects(), 2u);
    }

    void
    testExcessBodyBytesSingleResponse()
    {
        fake_net net;
        net.scripts = {
            "HTTP/1.1 200 OK\r\n"
            "Content-Length: 2\r\n"
            "\r\n"
            "okX" }; // one byte past Content-Length
        capy::test::run_blocking()(
            [&]() -> capy::task<>
            {
                client c(
                    co_await capy::this_coro::executor,
                    corosio::tls_context(),
                    net.config());

                auto [ec, r] = co_await c
                    .get("http://example.com/a")
                    .send();
                BOOST_TEST(!ec);

                auto [ec2, body] = co_await r.try_as_view();
                BOOST_TEST(!ec2);
                BOOST_TEST_EQ(body, "ok");
            }());
    }

    void
    testExcessBytesAfterResponse()
    {
        fake_net net;
        net.scripts = {
            "HTTP/1.1 200 OK\r\n"
            "Content-Length: 2\r\n"
            "\r\n"
            "ok"
            "BOGUS-TRAILING-GARBAGE",
            // The next request must go on a fresh connection.
            "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n" };

        capy::test::run_blocking()(
            [&]() -> capy::task<>
            {
                client c(
                    co_await capy::this_coro::executor,
                    corosio::tls_context(),
                    net.config());

                {
                    auto [ec, r] = co_await c
                        .get("http://example.com/a")
                        .send();
                    BOOST_TEST(!ec);
                    auto [ec2, body] = co_await r.try_as_view();
                    BOOST_TEST(!ec2);
                    BOOST_TEST_EQ(body, "ok");
                }

                auto [ec, r] = co_await c
                    .get("http://example.com/b")
                    .send();
                BOOST_TEST(!ec);
                BOOST_TEST(r.status() == http::status::ok);
            }());

        BOOST_TEST_EQ(net.connects(), 2u);
    }

    void
    testCookieRoundTrip()
    {
        fake_net net;
        net.scripts = {
            "HTTP/1.1 200 OK\r\n"
            "Set-Cookie: session=abc123; Path=/\r\n"
            "Content-Length: 0\r\n"
            "Connection: close\r\n"
            "\r\n",
            "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n" };

        capy::test::run_blocking()(
            [&]() -> capy::task<>
            {
                auto cfg = net.config();
                cfg.cookies = true;
                client c(
                    co_await capy::this_coro::executor,
                    corosio::tls_context(),
                    cfg);

                {
                    auto [ec, r] = co_await c
                        .get("http://example.com/set")
                        .send();
                    BOOST_TEST(!ec);
                }

                auto [ec, r] = co_await c
                    .get("http://example.com/get")
                    .send();
                BOOST_TEST(!ec);
            }());

        BOOST_TEST(
            net.written(0).find("Cookie:") == std::string::npos);
        BOOST_TEST(
            net.written(1).find("Cookie: session=abc123\r\n") !=
            std::string::npos);
    }

    void
    testHeadNoBody()
    {
        fake_net net;
        net.scripts = {
            "HTTP/1.1 200 OK\r\n"
            "Content-Length: 100\r\n"
            "\r\n" };

        capy::test::run_blocking()(
            [&]() -> capy::task<>
            {
                client c(
                    co_await capy::this_coro::executor,
                    corosio::tls_context(),
                    net.config());

                auto [ec, r] = co_await c
                    .head("http://example.com/file")
                    .send();
                BOOST_TEST(!ec);
                BOOST_TEST(
                    r.content_length().value_or(0) == 100);

                auto [ec2, body] = co_await r.try_as_view();
                BOOST_TEST(!ec2);
                BOOST_TEST(body.empty());
            }());

        BOOST_TEST(
            net.written(0).find("HEAD /file HTTP/1.1\r\n") == 0);
    }

    void
    testGzipDecode()
    {
#ifdef BOOST_HTTP_HAS_ZLIB
        http::zlib::install_inflate_service(capy::get_system_context());
#else
        return;
#endif

        // gzip("hello world"), mtime=0.
        static char const gz[] =
            "\x1f\x8b\x08\x00\x00\x00\x00\x00\x02\xff\xcb\x48"
            "\xcd\xc9\xc9\x57\x28\xcf\x2f\xca\x49\x01\x00\x85"
            "\x11\x4a\x0d\x0b\x00\x00\x00";
        auto const body = std::string(gz, sizeof(gz) - 1);

        fake_net net;
        net.scripts = { std::string(
            "HTTP/1.1 200 OK\r\n"
            "Content-Encoding: gzip\r\n"
            "Content-Length: " +
            std::to_string(body.size()) +
            "\r\n\r\n" + body) };

        capy::test::run_blocking()(
            [&]() -> capy::task<>
            {
                auto cfg = net.config();
                cfg.gzip = true;
                client c(
                    co_await capy::this_coro::executor,
                    corosio::tls_context(),
                    cfg);

                auto [ec, r] = co_await c
                    .get("http://example.com/z")
                    .send();
                BOOST_TEST(!ec);

                auto [ec2, text] = co_await r.try_as_view();
                BOOST_TEST(!ec2);
                BOOST_TEST_EQ(text, "hello world");
            }());

        BOOST_TEST(
            net.written(0).find("Accept-Encoding: gzip\r\n") !=
            std::string::npos);
    }

    void
    testBrotliDecode()
    {
#ifdef BOOST_HTTP_HAS_BROTLI
        http::brotli::install_decode_service(capy::get_system_context());
#else
        return;
#endif

        // brotli("hello world").
        static char const br[] =
            "\x0b\x05\x80\x68\x65\x6c\x6c\x6f\x20\x77\x6f\x72"
            "\x6c\x64\x03";
        auto const body = std::string(br, sizeof(br) - 1);

        fake_net net;
        net.scripts = { std::string(
            "HTTP/1.1 200 OK\r\n"
            "Content-Encoding: br\r\n"
            "Content-Length: " +
            std::to_string(body.size()) +
            "\r\n\r\n" + body) };

        capy::test::run_blocking()(
            [&]() -> capy::task<>
            {
                auto cfg = net.config();
                cfg.brotli = true;
                client c(
                    co_await capy::this_coro::executor,
                    corosio::tls_context(),
                    cfg);

                auto [ec, r] = co_await c
                    .get("http://example.com/z")
                    .send();
                BOOST_TEST(!ec);

                auto [ec2, text] = co_await r.try_as_view();
                BOOST_TEST(!ec2);
                BOOST_TEST_EQ(text, "hello world");
            }());

        BOOST_TEST(
            net.written(0).find("Accept-Encoding: br\r\n") !=
            std::string::npos);
    }

    void
    testConnectTimeout()
    {
        capy::test::run_blocking()(
            []() -> capy::task<>
            {
                client::config cfg;
                cfg.brotli = cfg.deflate = cfg.gzip = false;
                cfg.connect_timeout = 20ms;
                cfg.connect_handler =
                    [](urls::url_view) -> capy::io_task<capy::any_stream>
                {
                    if(auto [ec] = co_await capy::delay(5s); ec)
                    {
                        BOOST_TEST_EQ(ec, capy::error::canceled);
                        co_return { ec, {} };
                    }

                    auto [cli, srv] = capy::test::make_stream_pair();
                    co_return { {}, capy::any_stream(std::move(cli)) };
                };
                client c(
                    co_await capy::this_coro::executor,
                    corosio::tls_context(),
                    cfg);

                auto [ec, r] = co_await c
                    .get("http://example.com/")
                    .send();
                BOOST_TEST_EQ(ec, capy::error::timeout);
            }());
    }

    void
    testStatusErrorThenTransportErrorOnBody()
    {
        fake_net net;
        net.scripts = {
            "HTTP/1.1 500 Internal Server Error\r\n"
            "Content-Length: 10\r\n"
            "\r\n"
            "1234" };
        net.closes = { true };

        capy::test::run_blocking()(
            [&]() -> capy::task<>
            {
                client c(
                    co_await capy::this_coro::executor,
                    corosio::tls_context(),
                    net.config());

                auto [ec, r] = co_await c
                    .get("http://example.com/err")
                    .send();
                BOOST_TEST(ec == condition::server_error);
                BOOST_TEST(ec.value() == 500);
                BOOST_TEST(
                    r.status() ==
                    http::status::internal_server_error);

                auto [ec2, body] = co_await r.try_as_view();
                BOOST_TEST(ec2); // transport-level truncation
            }());
    }

    void
    testTransportErrorInjection()
    {
        capy::test::fuse f;
        auto r = f.armed(
            [](capy::test::fuse& f) -> capy::task<>
            {
                fake_net net(f);
                net.scripts = {
                    "HTTP/1.1 200 OK\r\n"
                    "Content-Length: 5\r\n"
                    "\r\n"
                    "hello" };

                client c(
                    co_await capy::this_coro::executor,
                    corosio::tls_context(),
                    net.config());

                auto [ec, res] = co_await c
                    .get("http://example.com/")
                    .send();
                if(ec)
                    co_return;

                auto [ec2, body] = co_await res.try_as_view();
                if(ec2)
                    co_return;

                BOOST_TEST(res.status() == http::status::ok);
                BOOST_TEST_EQ(body, "hello");
                BOOST_TEST(
                    net.written(0).starts_with("GET / HTTP/1.1\r\n"));
            });
        BOOST_TEST(r.success);
    }

    void
    testVerbs()
    {
        client c(
            capy::get_system_context().get_executor(),
            corosio::tls_context());
        
        urls::url_view url = "http://example.com";

        auto check = [&](request_builder rb, http::method method)
        {
            auto req = std::move(rb).build();
            BOOST_TEST(req.method == method);
            BOOST_TEST_EQ(req.url.buffer(), url);
        };

        check(c.get(url),     http::method::get);
        check(c.head(url),    http::method::head);
        check(c.post(url),    http::method::post);
        check(c.put(url),     http::method::put);
        check(c.patch(url),   http::method::patch);
        check(c.delete_(url), http::method::delete_);

        // generic
        check(
            c.request(http::method::options, url),
            http::method::options);
    }

    void
    run()
    {
        testRequestSerialization();
        testEmptyPathBecomesSlash();
        testPostBody();
        testStatusErrorWithReadableBody();
        testRedirectSameOrigin();
        test303MethodChange();
        testCrossOriginDropsAuthorization();
        testUnrestrictedAuthKeepsAuthorization();
        testTooManyRedirects();
        testFollowlocationOff();
        testBadRedirectResponse();
        testKeepAliveReuse();
        testConnectionCloseNoReuse();
        testUnconsumedBodyNoReuse();
        testExcessBodyBytesSingleResponse();
        testExcessBytesAfterResponse();
        testCookieRoundTrip();
        testHeadNoBody();
        testGzipDecode();
        testBrotliDecode();
        testConnectTimeout();
        testStatusErrorThenTransportErrorOnBody();
        testTransportErrorInjection();
        testVerbs();
    }
};

TEST_SUITE(client_test, "boost.burl.client");

} // namespace burl
} // namespace boost
