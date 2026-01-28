//
// Copyright (c) 2025 Vinnie Falco (vinnie dot falco at gmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//
// This file demonstrates all API features of boost::burl.
// It is designed to compile and show usage patterns.
//

#include <boost/burl/session.hpp>
#include <boost/capy/ex/run_async.hpp>
#include <boost/corosio/tls/context.hpp>

#include <iostream>
#include <thread>
#include <vector>

namespace burl = boost::burl;
namespace capy = boost::capy;
namespace http = boost::http;
namespace urls = boost::urls;
namespace json = boost::json;
namespace corosio = boost::corosio;

//==============================================================
// Example 1: Basic session setup and GET request
//==============================================================

capy::io_task<> example_simple_get(burl::session& s)
{
    // Simple GET request - body returned as std::string
    auto [ec, r] = co_await s.get("https://api.github.com/users/octocat");
    
    if (ec) {
        std::cerr << "Error: " << ec.message() << "\n";
        co_return ec;
    }
    
    if (r.ok()) {
        std::cout << "Status: " << r.status_int() << " " << r.reason() << "\n";
        std::cout << "Body length: " << r.body.size() << "\n";
        std::cout << r.text() << "\n";
    }
    
    co_return {};
}

//==============================================================
// Example 2: Accessing HTTP response headers
//==============================================================

capy::io_task<> example_headers(burl::session& s)
{
    auto [ec, r] = co_await s.get("https://httpbin.org/headers");
    
    if (ec)
        co_return ec;
    
    // Access headers directly via http::response
    if (r.message.exists(http::field::content_type)) {
        std::cout << "Content-Type: " 
                  << r.message.at(http::field::content_type) << "\n";
    }
    
    // Iterate all headers
    std::cout << "All headers:\n";
    for (auto const& h : r.message) {
        std::cout << "  " << h.name << ": " << h.value << "\n";
    }
    
    co_return {};
}

//==============================================================
// Example 3: Accessing URL components
//==============================================================

capy::io_task<> example_url_components(burl::session& s)
{
    auto [ec, r] = co_await s.get("https://httpbin.org/get?foo=bar&baz=123");
    
    if (ec)
        co_return ec;
    
    // Access URL components via urls::url
    std::cout << "Final URL: " << r.url.buffer() << "\n";
    std::cout << "Scheme: " << r.url.scheme() << "\n";
    std::cout << "Host: " << r.url.host() << "\n";
    std::cout << "Path: " << r.url.path() << "\n";
    
    // Access query parameters
    std::cout << "Query params:\n";
    for (auto param : r.url.params()) {
        std::cout << "  " << param.key << " = " << param.value << "\n";
    }
    
    co_return {};
}

//==============================================================
// Example 4: Building URLs programmatically
//==============================================================

capy::io_task<> example_url_building(burl::session& s)
{
    // Build URL with query parameters
    urls::url url("https://httpbin.org/get");
    url.params().append({"name", "John Doe"});
    url.params().append({"page", "1"});
    url.params().append({"limit", "10"});
    
    auto [ec, r] = co_await s.get(url);
    
    if (ec)
        co_return ec;
    
    std::cout << "Requested: " << url.buffer() << "\n";
    std::cout << "Response: " << r.status_int() << "\n";
    
    co_return {};
}

//==============================================================
// Example 5: POST with JSON body
//==============================================================

capy::io_task<> example_post_json(burl::session& s)
{
    burl::request_options opts;
    opts.json = R"({
        "name": "test",
        "value": 42,
        "active": true
    })";
    
    auto [ec, r] = co_await s.post("https://httpbin.org/post", opts);
    
    if (ec)
        co_return ec;
    
    std::cout << "POST response: " << r.status_int() << "\n";
    std::cout << r.text() << "\n";
    
    co_return {};
}

//==============================================================
// Example 6: Response with JSON parsing
//==============================================================

capy::io_task<> example_json_response(burl::session& s)
{
    // Request with JSON parsing - body is json::value
    auto [ec, r] = co_await s.get(
        "https://api.github.com/users/octocat",
        burl::as_json);
    
    if (ec)
        co_return ec;
    
    if (r.ok()) {
        // r.body is json::value
        std::cout << "Login: " << r.body.at("login").as_string() << "\n";
        std::cout << "ID: " << r.body.at("id").as_int64() << "\n";
    }
    
    co_return {};
}

//==============================================================
// Example 7: Custom type deserialization
//==============================================================

struct GitHubUser
{
    std::string login;
    int id;
    std::string avatar_url;
    std::string type;
};

// Requires BOOST_DESCRIBE_STRUCT or reflection support
// BOOST_DESCRIBE_STRUCT(GitHubUser, (), (login, id, avatar_url, type))

capy::io_task<> example_custom_type(burl::session& s)
{
    // Deserialize response directly into custom type
    auto [ec, r] = co_await s.get(
        "https://api.github.com/users/octocat",
        burl::as_type<GitHubUser>);
    
    if (ec)
        co_return ec;
    
    if (r.ok()) {
        // r.body is GitHubUser
        std::cout << "User: " << r.body.login << "\n";
        std::cout << "ID: " << r.body.id << "\n";
    }
    
    co_return {};
}

//==============================================================
// Example 8: Streaming large responses
//==============================================================

capy::io_task<> example_streaming(burl::session& s)
{
    // Get streaming response for large files
    auto [ec, r] = co_await s.get_streamed(
        "https://httpbin.org/bytes/10000");
    
    if (ec)
        co_return ec;
    
    std::cout << "Status: " << r.status_int() << "\n";
    
    // Read body incrementally
    std::size_t total = 0;
    capy::const_buffer arr[16];
    
    while (true) {
        auto [err, count] = co_await r.body.pull(arr, 16);
        
        if (err) {
            std::cerr << "Read error: " << err.message() << "\n";
            break;
        }
        
        if (count == 0)
            break;  // End of body
        
        // Calculate bytes in this batch
        for (std::size_t i = 0; i < count; ++i)
            total += arr[i].size();
        
        r.body.consume(total);
    }
    
    std::cout << "Downloaded " << total << " bytes\n";
    
    co_return {};
}

//==============================================================
// Example 9: Request with custom headers
//==============================================================

capy::io_task<> example_custom_headers(burl::session& s)
{
    burl::request_options opts;
    opts.headers = http::fields{};
    opts.headers->set(http::field::accept, "application/json");
    opts.headers->set(http::field::user_agent, "MyApp/1.0");
    opts.headers->set("X-Custom-Header", "custom-value");
    
    auto [ec, r] = co_await s.get("https://httpbin.org/headers", opts);
    
    if (ec)
        co_return ec;
    
    std::cout << r.text() << "\n";
    
    co_return {};
}

//==============================================================
// Example 10: Authentication - Basic
//==============================================================

capy::io_task<> example_basic_auth(burl::session& s)
{
    // Set authentication on session
    s.set_auth(std::make_shared<burl::http_basic_auth>("user", "passwd"));
    
    auto [ec, r] = co_await s.get("https://httpbin.org/basic-auth/user/passwd");
    
    if (ec)
        co_return ec;
    
    std::cout << "Auth result: " << r.status_int() << "\n";
    
    co_return {};
}

//==============================================================
// Example 11: Authentication - Bearer token
//==============================================================

capy::io_task<> example_bearer_auth(burl::session& s)
{
    s.set_auth(std::make_shared<burl::http_bearer_auth>("my-api-token"));
    
    auto [ec, r] = co_await s.get("https://httpbin.org/bearer");
    
    if (ec)
        co_return ec;
    
    std::cout << "Bearer auth result: " << r.status_int() << "\n";
    
    co_return {};
}

//==============================================================
// Example 12: Per-request authentication
//==============================================================

capy::io_task<> example_per_request_auth(burl::session& s)
{
    burl::request_options opts;
    opts.auth = std::make_shared<burl::http_basic_auth>("user", "pass");
    
    auto [ec, r] = co_await s.get("https://httpbin.org/basic-auth/user/pass", opts);
    
    if (ec)
        co_return ec;
    
    std::cout << "Result: " << r.status_int() << "\n";
    
    co_return {};
}

//==============================================================
// Example 13: Timeout handling
//==============================================================

capy::io_task<> example_timeout(burl::session& s)
{
    burl::request_options opts;
    opts.timeout = std::chrono::milliseconds{5000};  // 5 second timeout
    
    auto [ec, r] = co_await s.get("https://httpbin.org/delay/3", opts);
    
    if (ec) {
        if (ec == burl::make_error_code(burl::error::timeout))
            std::cout << "Request timed out!\n";
        else
            std::cout << "Error: " << ec.message() << "\n";
        co_return ec;
    }
    
    std::cout << "Completed in " << r.elapsed.count() << "ms\n";
    
    co_return {};
}

//==============================================================
// Example 14: Redirect handling
//==============================================================

capy::io_task<> example_redirects(burl::session& s)
{
    // Default: follows redirects automatically
    auto [ec, r] = co_await s.get("https://httpbin.org/redirect/3");
    
    if (ec)
        co_return ec;
    
    std::cout << "Final URL: " << r.url.buffer() << "\n";
    std::cout << "Redirects followed: " << r.history.size() << "\n";
    
    for (auto const& h : r.history) {
        std::cout << "  -> " << h.status_int() << " " << h.url.buffer() << "\n";
    }
    
    co_return {};
}

//==============================================================
// Example 15: Disable redirects
//==============================================================

capy::io_task<> example_no_redirects(burl::session& s)
{
    burl::request_options opts;
    opts.allow_redirects = false;
    
    auto [ec, r] = co_await s.get("https://httpbin.org/redirect/1", opts);
    
    if (ec)
        co_return ec;
    
    // Should get 302 instead of following redirect
    std::cout << "Status: " << r.status_int() << "\n";
    if (r.is_redirect()) {
        std::cout << "Would redirect to: " 
                  << r.message.at(http::field::location) << "\n";
    }
    
    co_return {};
}

//==============================================================
// Example 16: Error handling with raise_for_status()
//==============================================================

capy::io_task<> example_raise_for_status(burl::session& s)
{
    auto [ec, r] = co_await s.get("https://httpbin.org/status/404");
    
    if (ec)
        co_return ec;
    
    try {
        r.raise_for_status();
        std::cout << "Request succeeded\n";
    }
    catch (burl::http_error const& e) {
        std::cout << "HTTP error: " << e.what() << "\n";
        std::cout << "Status: " << e.status_code() << "\n";
        std::cout << "URL: " << e.url() << "\n";
    }
    
    co_return {};
}

//==============================================================
// Example 17: Cookie handling
//==============================================================

capy::io_task<> example_cookies(burl::session& s)
{
    // First request sets a cookie
    auto [ec1, r1] = co_await s.get("https://httpbin.org/cookies/set/session/abc123");
    
    if (ec1)
        co_return ec1;
    
    // Check cookies in jar
    std::cout << "Cookies in jar: " << s.cookies().size() << "\n";
    for (auto const& c : s.cookies()) {
        std::cout << "  " << c.name << " = " << c.value << "\n";
    }
    
    // Next request automatically sends cookies
    auto [ec2, r2] = co_await s.get("https://httpbin.org/cookies");
    
    if (ec2)
        co_return ec2;
    
    std::cout << "Cookies response: " << r2.text() << "\n";
    
    co_return {};
}

//==============================================================
// Example 18: TLS configuration
//==============================================================

void example_tls_config()
{
    corosio::io_context ioc;
    corosio::tls::context tls_ctx;
    
    // Configure TLS before creating session
    tls_ctx.set_default_verify_paths();
    tls_ctx.set_verify_mode(corosio::tls::verify_mode::peer);
    
    // Or load specific CA file
    // tls_ctx.load_verify_file("/etc/ssl/certs/ca-certificates.crt");
    
    // Client certificate authentication
    // tls_ctx.use_certificate_file("client.crt", corosio::tls::file_format::pem);
    // tls_ctx.use_private_key_file("client.key", corosio::tls::file_format::pem);
    
    burl::session s(ioc, tls_ctx);
    
    std::cout << "TLS context configured\n";
}

//==============================================================
// Example 19: Session default headers
//==============================================================

void example_default_headers()
{
    corosio::io_context ioc;
    corosio::tls::context tls_ctx;
    burl::session s(ioc, tls_ctx);
    
    // Set headers that apply to all requests
    s.headers().set(http::field::user_agent, "MyApp/1.0");
    s.headers().set(http::field::accept, "application/json");
    s.headers().set(http::field::accept_language, "en-US");
    
    // These will be sent with every request
}

//==============================================================
// Example 20: Basic session usage
//==============================================================

void example_basic_session()
{
    corosio::io_context ioc;
    corosio::tls::context tls_ctx;
    
    // Configure TLS
    tls_ctx.set_default_verify_paths();
    
    burl::session s(ioc, tls_ctx);
    
    // Configure session
    s.headers().set(http::field::user_agent, "MyApp/1.0");
    
    // Launch work and run
    // capy::run_async(ioc.get_executor())([&]() -> capy::io_task<> {
    //     auto [ec, r] = co_await s.get("https://example.com");
    //     co_return {};
    // }());
    // ioc.run();
}

//==============================================================
// Example 21: Multi-threaded usage
//==============================================================

void example_multithreaded()
{
    corosio::io_context ioc;
    corosio::tls::context tls_ctx;
    tls_ctx.set_default_verify_paths();
    
    burl::session s(ioc, tls_ctx);
    
    // User runs io_context from multiple threads
    // Note: Caller is responsible for synchronization if needed
    std::vector<std::thread> threads;
    for (int i = 0; i < 4; ++i) {
        threads.emplace_back([&] { ioc.run(); });
    }
    
    for (auto& t : threads) {
        t.join();
    }
}

//==============================================================
// Example 22: All HTTP methods
//==============================================================

capy::io_task<> example_all_methods(burl::session& s)
{
    urls::url_view url("https://httpbin.org/anything");
    
    auto [ec1, r1] = co_await s.get(url);
    auto [ec2, r2] = co_await s.post(url);
    auto [ec3, r3] = co_await s.put(url);
    auto [ec4, r4] = co_await s.patch(url);
    auto [ec5, r5] = co_await s.delete_(url);
    auto [ec6, r6] = co_await s.head(url);
    auto [ec7, r7] = co_await s.options(url);
    
    // Generic request method
    auto [ec8, r8] = co_await s.request(http::method::get, url);
    
    (void)r1; (void)r2; (void)r3; (void)r4;
    (void)r5; (void)r6; (void)r7; (void)r8;
    
    co_return {};
}

//==============================================================
// Main - demonstrates session setup
//==============================================================

int main()
{
    std::cout << "Boost.Burl Usage Examples\n";
    std::cout << "=========================\n\n";
    
    // Basic setup pattern
    corosio::io_context ioc;
    corosio::tls::context tls_ctx;
    tls_ctx.set_default_verify_paths();
    
    burl::session s(ioc, tls_ctx);
    
    // Launch a task
    capy::run_async(ioc.get_executor())([&]() -> capy::io_task<> {
        auto [ec, r] = co_await s.get("https://example.com");
        if (ec) {
            std::cerr << "Error: " << ec.message() << "\n";
        }
        co_return {};
    }());
    
    // Run the event loop
    ioc.run();
    
    // This file demonstrates API usage patterns.
    // The actual implementations are stubs that return not_implemented.
    
    std::cout << "All examples compile successfully.\n";
    std::cout << "Implementation pending in Phase 2.\n";
    
    return 0;
}
