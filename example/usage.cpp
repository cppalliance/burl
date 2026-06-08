//
// Copyright (c) 2025 Vinnie Falco (vinnie dot falco at gmail dot com)
// Copyright (c) 2026 Mohammad Nejati
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

#include <boost/burl.hpp>
#include <boost/capy.hpp>
#include <boost/corosio.hpp>
#include <boost/http/brotli.hpp>
#include <boost/http/zlib.hpp>
#include <boost/json.hpp>
#include <boost/hash2/sha2.hpp>

#include <charconv>
#include <iostream>
#include <iterator>
#include <string_view>

namespace burl    = boost::burl;
namespace capy    = boost::capy;
namespace corosio = boost::corosio;
namespace hash2   = boost::hash2;
namespace http    = boost::http;
namespace json    = boost::json;
namespace urls    = boost::urls;

//==============================================================
// Example 1: Basic GET request
//==============================================================

capy::task<>
basic_get(corosio::tls_context tls_ctx)
{
    burl::client client(co_await capy::this_coro::executor, tls_ctx);

    // Response body as a string
    auto r1 = co_await client.get("https://example.com")
        .as<std::string>();

    std::cout << r1 << '\n';

    // Response body as JSON
    auto r2 = co_await client.get("https://postman-echo.com/get")
        .as<json::value>();

    std::cout << r2 << '\n';
}

//==============================================================
// Example 2: Inspect response status and headers
//==============================================================

capy::task<>
inspect_response(corosio::tls_context tls_ctx)
{
    burl::client client(co_await capy::this_coro::executor, tls_ctx);

    // send() yields the response without reading the body, so the status
    // and headers can be inspected before the body is consumed.
    auto [ec, r] = co_await client.get("https://example.com").send();

    if(ec)
        throw std::system_error(ec);

    std::cout << "status:  " << r.status_int() << '\n';
    std::cout << "reason:  " << r.reason() << '\n';
    std::cout << "headers: " << r.headers() << '\n';
    std::cout << "body:    " << co_await r.as<std::string>() << '\n';
}

//==============================================================
// Example 3: Handle error status codes
//==============================================================

capy::task<>
handle_error_status(corosio::tls_context tls_ctx)
{
    burl::client client(co_await capy::this_coro::executor, tls_ctx);

    try
    {
        auto r1 = co_await client.get("https://example.com/not-found")
            .error_for_status() // Treats 4XX and 5XX status codes as errors
            .as<std::string>();
    }
    catch(std::system_error const&e)
    {
        // HTTP 404 Not Found
        std::cerr << e.what() << '\n';
    }

    // Or inspect the error code instead of throwing
    auto [ec, r2] = co_await client.get("https://example.com/not-found")
        .error_for_status()
        .try_as<std::string>();

    if(ec == burl::condition::client_error)
    {
        // HTTP 404 Not Found
        std::cerr << ec.message() << '\n';
    }
}

//==============================================================
// Example 4: Add query parameters
//==============================================================

capy::task<>
add_query_params(corosio::tls_context tls_ctx)
{
    burl::client client(co_await capy::this_coro::executor, tls_ctx);

    auto r = co_await client.get("https://postman-echo.com/get")
        .query("category", "shoes")
        .query("color", "blue")
        .as<json::object>();

    std::cout << r << '\n';
}

//==============================================================
// Example 5: Set request headers
//==============================================================

capy::task<>
set_headers(corosio::tls_context tls_ctx)
{
    burl::client client(co_await capy::this_coro::executor, tls_ctx);

    // Default headers on the client, sent with every request
    client.headers().set(http::field::user_agent, "BoostBurl/1.0");

    // Per-request headers
    auto r = co_await client.get("https://postman-echo.com/get")
        .header(http::field::accept_language, "da, en-gb;q=0.8, en;q=0.7")
        .header("X-Trace-Id", "abc123")
        .as<json::object>();

    std::cout << r << '\n';
}

//==============================================================
// Example 6: Authentication
//==============================================================

capy::task<>
authenticate(corosio::tls_context tls_ctx)
{
    burl::client client(co_await capy::this_coro::executor, tls_ctx);

    // Default auth, sent with every request
    client.basic_auth("user", "pass");
    // or client.bearer_auth("TOKEN");

    auto r = co_await client.get("https://postman-echo.com/basic-auth")
        .basic_auth("postman", "password") // per-request override
        // or .bearer_auth("TOKEN")
        .error_for_status()
        .as<json::object>();

    std::cout << r << '\n';
}

//==============================================================
// Example 7: POST a string body
//==============================================================

capy::task<>
post_string(corosio::tls_context tls_ctx)
{
    burl::client client(co_await capy::this_coro::executor, tls_ctx);

    auto r = co_await client.post("https://postman-echo.com/post")
        // A string body defaults to Content-Type: text/plain; charset=utf-8
        .body("<note>hi</note>")
        // Override the Content-Type:
        .header(http::field::content_type, "application/xml")
        .error_for_status()
        .as<json::object>();

    std::cout << r << '\n';
}

//==============================================================
// Example 8: POST a JSON body
//==============================================================

capy::task<>
post_json(corosio::tls_context tls_ctx)
{
    burl::client client(co_await capy::this_coro::executor, tls_ctx);

    json::object body({ { "user", "John" }, { "lang", "En" } });
    auto r1 = co_await client.post("https://postman-echo.com/post")
        .body(body)
        .error_for_status()
        .as<json::object>();

    std::cout << r1 << '\n';

    // Or inline
    auto r2 = co_await client.post("https://postman-echo.com/post")
        .body<json::array>({ 1, 2, 3 })
        .error_for_status()
        .as<json::object>();

    std::cout << r2 << '\n';
}

//==============================================================
// Example 9: POST a URL-encoded form
//==============================================================

capy::task<>
post_urlencoded_form(corosio::tls_context tls_ctx)
{
    burl::client client(co_await capy::this_coro::executor, tls_ctx);

    burl::urlencoded_form form;
    form.append("user", "John");
    form.append("lang", "En");

    auto r1 = co_await client.post("https://postman-echo.com/post")
        .body(form)
        .error_for_status()
        .as<json::object>();

    std::cout << r1 << '\n';

    // Or inline
    auto r2 = co_await client.post("https://postman-echo.com/post")
        .body(burl::urlencoded_form()
            .append("user", "John")
            .append("lang", "En"))
        .error_for_status()
        .as<json::object>();

    std::cout << r2 << '\n';
}

//==============================================================
// Example 10: POST a multipart form
//==============================================================

capy::task<>
post_multipart_form(corosio::tls_context tls_ctx)
{
    burl::client client(co_await capy::this_coro::executor, tls_ctx);

    burl::multipart_form form;
    // filename and MIME type are deduced from the path (or can be passed in)
    form.file("attachment", "./crash_report.log");
    form.text("priority", "high");

    auto r1 = co_await client.post("https://postman-echo.com/post")
        .body(form)
        .error_for_status()
        .as<json::object>();

    std::cout << r1 << '\n';

    // Or inline
    auto r2 = co_await client.post("https://postman-echo.com/post")
        .body(burl::multipart_form()
            .file("attachment", "./crash_report.log")
            .text("priority", "high"))
        .error_for_status()
        .as<json::object>();

    std::cout << r2 << '\n';
}

//==============================================================
// Example 11: Upload and download a file
//==============================================================

capy::task<>
upload_and_download_file(corosio::tls_context tls_ctx)
{
    namespace fs = std::filesystem;

    burl::client client(co_await capy::this_coro::executor, tls_ctx);

    fs::path r = co_await client.put("https://postman-echo.com/put")
        .body<fs::path>("./crash_report.log") // Load the request body from a file
        // Override the auto-deduced Content-Type:
        // .header(http::field::content_type, "application/octet-stream")
        .error_for_status()
        .as<fs::path>("./resp.txt"); // Save the response body to a file

    std::cout << "Response body saved to:" << r << '\n';
}

//==============================================================
// Example 12: Stream a response body
//==============================================================

capy::task<>
stream_response(corosio::tls_context tls_ctx)
{
    burl::client client(co_await capy::this_coro::executor, tls_ctx);

    auto [ec, r] = co_await client.get("https://archives.boost.io/"
        "release/1.91.0/source/boost_1_91_0.tar.bz2")
        .error_for_status()
        .send();

    if(ec)
        throw std::system_error(ec);

    // Read the body incrementally instead of buffering it all in memory
    auto source = r.as_buffer_source();
    hash2::sha2_256 hash;
    for(;;)
    {
        capy::const_buffer arr[8];
        auto [ec, bufs] = co_await source.pull(arr);
        if(ec == capy::cond::eof)
            break;
        if(ec)
            throw std::system_error(ec);
        for(auto const& buf : bufs)
        {
            hash.update(buf.data(), buf.size());
            source.consume(buf.size());
        }
    }
    std::cout << "sha256: " << hash.result() << '\n';
}

//==============================================================
// Example 13: Read a response body in place
//==============================================================

capy::task<>
inplace_response_body(corosio::tls_context tls_ctx)
{
    burl::client::config cfg;
    cfg.response_inplace_buffer = 1024 * 1024;

    burl::client client(co_await capy::this_coro::executor, tls_ctx, cfg);

    auto [ec, r] = co_await client.get("https://www.boost.org")
        .error_for_status()
        .send();

    if(ec)
        throw std::system_error(ec);

    // Use the internal inplace buffer for reading the whole body
    // the most efficient method if we know the body always fits.
    std::cout << co_await r.as_view() << '\n';
}

//==============================================================
// Example 14: Set timeouts
//==============================================================

capy::task<>
set_timeouts(corosio::tls_context tls_ctx)
{
    // Client timeouts, applied to every request
    burl::client::config cfg;

    // Connect timeout, including TLS handshake and proxy connect
    cfg.pool.connect_timeout = std::chrono::seconds(30);

    // Per read/write timeout, for detecting unresponsive servers regardless
    // of the request/response size
    cfg.pool.io_timeout = std::chrono::seconds(5);

    // Timeout for the whole operation, including retrieving the response
    cfg.timeout = std::chrono::seconds(60);

    burl::client client(co_await capy::this_coro::executor, tls_ctx, cfg);

    auto r = co_await client.get("https://example.com")
        .timeout(std::chrono::seconds(3)) // per-request override
        .as<std::string>();

    std::cout << r;
}

//==============================================================
// Example 15: Follow redirects
//==============================================================

capy::task<>
follow_redirects(corosio::tls_context tls_ctx)
{
    burl::client::config cfg;

    // Follow redirects (enable by default)
    cfg.followlocation = true;
    cfg.maxredirs = 10;

    burl::client client(co_await capy::this_coro::executor, tls_ctx, cfg);

    auto [ec, r] = co_await client.get("http://boost.org").send();

    if(ec)
        throw std::system_error(ec);

    // Final URL after following redirects, e.g. https://www.boost.org
    std::cout << r.url() << '\n';
}

//==============================================================
// Example 16: Enable cookies
//==============================================================

capy::task<>
enable_cookies(corosio::tls_context tls_ctx)
{
    burl::client::config cfg;

    // Cookies (disabled by default)
    cfg.cookies = true;

    burl::client client(co_await capy::this_coro::executor, tls_ctx, cfg);

    auto r = co_await client.get("https://postman-echo.com/cookies/set?foo=bar")
        .error_for_status()
        .as<std::string>();

    // Print the stored cookies in Netscape format
    std::cout << client.cookie_jar();
}

//==============================================================
// Example 17: Reuse connections with the pool
//==============================================================

capy::task<>
connection_pool(corosio::tls_context tls_ctx)
{
    burl::client::config cfg;
    cfg.pool.idle_timeout = std::chrono::seconds(60);
    cfg.pool.max_idle_per_host = 10;

    burl::client client(co_await capy::this_coro::executor, tls_ctx, cfg);

    auto r1 = co_await client.get("https://www.boost.org")
        .as<std::string>();

    // Reuses the connection established by the first request
    auto r2 = co_await client.get("https://www.boost.org")
        .as<std::string>();
}

//==============================================================
// Example 18: Use a proxy
//==============================================================

capy::task<>
use_proxy(corosio::tls_context tls_ctx)
{
    burl::client::config cfg;
    // SOCKS5 and HTTP proxies are supported
    cfg.pool.proxy = urls::url("socks5h://user:pass@localhost:8080");

    burl::client client(co_await capy::this_coro::executor, tls_ctx, cfg);

    // Sent through the proxy
    auto r = co_await client.get("https://example.com")
        .as<std::string>();

    std::cout << r;
}

//==============================================================
// Example 19: Build a request and execute it later
//==============================================================

capy::task<>
build_and_execute(corosio::tls_context tls_ctx)
{
    burl::client client(co_await capy::this_coro::executor, tls_ctx);

    // build() produces a request that can be stored and executed later
    burl::request req = client.post("https://postman-echo.com/post")
        .header("X-Debug", "1")
        .body("payload")
        .error_for_status()
        .build();

    auto [ec, r] = co_await client.execute(std::move(req));
    if(ec)
        throw std::system_error(ec);

    std::cout << co_await r.as<json::value>() << '\n';
}

int
main(int argc, char* argv[])
{
    using example_fn = capy::task<> (*)(corosio::tls_context);
    constexpr example_fn examples[]{
        &basic_get,
        &inspect_response,
        &handle_error_status,
        &add_query_params,
        &set_headers,
        &authenticate,
        &post_string,
        &post_json,
        &post_urlencoded_form,
        &post_multipart_form,
        &upload_and_download_file,
        &stream_response,
        &inplace_response_body,
        &set_timeouts,
        &follow_redirects,
        &enable_cookies,
        &connection_pool,
        &use_proxy,
        &build_and_execute,
    };

    int index = 0;
    if(argc == 2)
    {
        std::string_view const arg(argv[1]);
        std::from_chars(arg.data(), arg.data() + arg.size(), index);
    }

    if(index < 1 || index > std::size(examples))
    {
        std::cerr << "Usage: " << argv[0] << " <1.." << std::size(examples) << ">\n";
        return 1;
    }

    corosio::io_context ioc;
    corosio::tls_context tls_ctx;

#ifdef BOOST_HTTP_HAS_BROTLI
    http::brotli::install_decode_service(capy::get_system_context());
#endif
#ifdef BOOST_HTTP_HAS_ZLIB
    http::zlib::install_inflate_service(capy::get_system_context());
#endif

    capy::run_async(
        ioc.get_executor(),
        [] {},
        [](std::exception_ptr ep)
        {
            try
            {
                std::rethrow_exception(ep);
            }
            catch(std::system_error const& e)
            {
                std::cerr << "Error category: " << e.code().category().name() << '\n';
                std::cerr << "Error Message:  " << e.code().message() << '\n';
            }
            catch(std::exception const& e)
            {
                std::cerr << "Error: " << e.what() << '\n';
            }
        })(examples[index - 1](tls_ctx));

    ioc.run();
}
