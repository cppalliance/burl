//
// Copyright (c) 2025 Vinnie Falco (vinnie dot falco at gmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

// Unit tests to verify session.hpp compiles correctly

#include <boost/burl/session.hpp>
#include <boost/corosio/tls/context.hpp>

#include <type_traits>

namespace boost {
namespace burl {

//----------------------------------------------------------
// Compilation tests
//----------------------------------------------------------

// session is movable
static_assert(std::is_move_constructible_v<session>);
static_assert(std::is_move_assignable_v<session>);

// session is not copyable
static_assert(!std::is_copy_constructible_v<session>);
static_assert(!std::is_copy_assignable_v<session>);

//----------------------------------------------------------
// Construction tests
//----------------------------------------------------------

void test_construction()
{
    corosio::io_context ioc;
    corosio::tls::context tls_ctx;
    
    session s(ioc, tls_ctx);
    (void)s;
}

//----------------------------------------------------------
// Configuration tests
//----------------------------------------------------------

void test_tls_context_access()
{
    corosio::io_context ioc;
    corosio::tls::context tls_ctx;
    session s(ioc, tls_ctx);
    
    // Non-const access
    corosio::tls::context& ctx = s.tls_context();
    (void)ctx;
    
    // Const access
    session const& cs = s;
    corosio::tls::context const& cctx = cs.tls_context();
    (void)cctx;
}

void test_io_context_access()
{
    corosio::io_context ioc;
    corosio::tls::context tls_ctx;
    session s(ioc, tls_ctx);
    
    corosio::io_context& ref = s.get_io_context();
    (void)ref;
}

void test_headers_access()
{
    corosio::io_context ioc;
    corosio::tls::context tls_ctx;
    session s(ioc, tls_ctx);
    
    // Non-const access
    http::fields& h = s.headers();
    h.set(http::field::user_agent, "Test/1.0");
    
    // Const access
    session const& cs = s;
    http::fields const& ch = cs.headers();
    (void)ch;
}

void test_cookies_access()
{
    corosio::io_context ioc;
    corosio::tls::context tls_ctx;
    session s(ioc, tls_ctx);
    
    // Non-const access
    cookie_jar& jar = s.cookies();
    (void)jar;
    
    // Const access
    session const& cs = s;
    cookie_jar const& cjar = cs.cookies();
    (void)cjar;
}

void test_auth_configuration()
{
    corosio::io_context ioc;
    corosio::tls::context tls_ctx;
    session s(ioc, tls_ctx);
    
    s.set_auth(std::make_shared<http_basic_auth>("user", "pass"));
    s.set_auth(std::make_shared<http_bearer_auth>("token"));
}

void test_verify_configuration()
{
    corosio::io_context ioc;
    corosio::tls::context tls_ctx;
    session s(ioc, tls_ctx);
    
    s.set_verify(verify_config{
        .verify_peer = true,
        .ca_file = "/etc/ssl/certs/ca-certificates.crt"
    });
}

void test_redirects_configuration()
{
    corosio::io_context ioc;
    corosio::tls::context tls_ctx;
    session s(ioc, tls_ctx);
    
    s.set_max_redirects(10);
}

void test_timeout_configuration()
{
    corosio::io_context ioc;
    corosio::tls::context tls_ctx;
    session s(ioc, tls_ctx);
    
    s.set_timeout(std::chrono::milliseconds{5000});
}

//----------------------------------------------------------
// Method signature tests
//----------------------------------------------------------

// These functions verify the method signatures compile correctly.
// They are not meant to be called - the coroutines would need
// to be awaited in a coroutine context.

void test_request_method_signatures()
{
    corosio::io_context ioc;
    corosio::tls::context tls_ctx;
    session s(ioc, tls_ctx);
    
    urls::url_view url("https://example.com");
    request_options opts;
    
    // Basic methods return io_task<response<std::string>>
    auto r1 = s.get(url);
    auto r2 = s.post(url);
    auto r3 = s.put(url);
    auto r4 = s.patch(url);
    auto r5 = s.delete_(url);
    auto r6 = s.head(url);
    auto r7 = s.options(url);
    auto r8 = s.request(http::method::get, url);
    
    (void)r1; (void)r2; (void)r3; (void)r4;
    (void)r5; (void)r6; (void)r7; (void)r8;
}

void test_request_with_options()
{
    corosio::io_context ioc;
    corosio::tls::context tls_ctx;
    session s(ioc, tls_ctx);
    
    urls::url_view url("https://example.com");
    
    request_options opts;
    opts.timeout = std::chrono::milliseconds{1000};
    opts.max_redirects = 5;
    
    auto r = s.get(url, opts);
    (void)r;
}

void test_json_body_signatures()
{
    corosio::io_context ioc;
    corosio::tls::context tls_ctx;
    session s(ioc, tls_ctx);
    
    urls::url_view url("https://example.com/api");
    
    // JSON body returns io_task<response<json::value>>
    auto r1 = s.get(url, as_json);
    auto r2 = s.post(url, as_json);
    
    (void)r1; (void)r2;
}

void test_custom_type_signatures()
{
    corosio::io_context ioc;
    corosio::tls::context tls_ctx;
    session s(ioc, tls_ctx);
    
    urls::url_view url("https://example.com/api");
    
    struct MyType { int x; };
    
    // Custom type returns io_task<response<MyType>>
    auto r1 = s.get(url, as_type<MyType>);
    auto r2 = s.post(url, as_type<MyType>);
    
    (void)r1; (void)r2;
}

void test_streaming_signatures()
{
    corosio::io_context ioc;
    corosio::tls::context tls_ctx;
    session s(ioc, tls_ctx);
    
    urls::url_view url("https://example.com/large-file");
    
    // Streaming returns io_task<streamed_response>
    auto r1 = s.get_streamed(url);
    auto r2 = s.post_streamed(url);
    
    (void)r1; (void)r2;
}

} // namespace burl
} // namespace boost

int main()
{
    // Just verify everything compiles
    return 0;
}
