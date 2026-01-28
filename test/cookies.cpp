//
// Copyright (c) 2025 Vinnie Falco (vinnie dot falco at gmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

// Unit tests to verify cookies.hpp compiles correctly

#include <boost/burl/cookies.hpp>

#include <type_traits>

namespace boost {
namespace burl {

//----------------------------------------------------------
// cookie compilation tests
//----------------------------------------------------------

static_assert(std::is_default_constructible_v<cookie>);
static_assert(std::is_copy_constructible_v<cookie>);
static_assert(std::is_move_constructible_v<cookie>);

void test_cookie_members()
{
    cookie c;
    
    // Access all members
    std::string& name = c.name;
    std::string& value = c.value;
    std::string& domain = c.domain;
    std::string& path = c.path;
    std::optional<std::chrono::system_clock::time_point>& expires = c.expires;
    bool& secure = c.secure;
    bool& http_only = c.http_only;
    cookie::same_site_t& same_site = c.same_site;
    
    (void)name; (void)value; (void)domain; (void)path;
    (void)expires; (void)secure; (void)http_only; (void)same_site;
}

void test_cookie_aggregate_init()
{
    cookie c{
        .name = "session_id",
        .value = "abc123",
        .domain = "example.com",
        .path = "/",
        .expires = std::nullopt,
        .secure = true,
        .http_only = true,
        .same_site = cookie::same_site_t::strict
    };
    (void)c;
}

void test_cookie_is_expired()
{
    cookie c;
    
    // Session cookie (no expiry)
    c.expires = std::nullopt;
    bool expired1 = c.is_expired();
    (void)expired1;
    
    // Expired cookie
    c.expires = std::chrono::system_clock::now() - std::chrono::hours{1};
    bool expired2 = c.is_expired();
    (void)expired2;
    
    // Future cookie
    c.expires = std::chrono::system_clock::now() + std::chrono::hours{1};
    bool expired3 = c.is_expired();
    (void)expired3;
}

void test_cookie_matches()
{
    cookie c{
        .name = "test",
        .value = "value",
        .domain = "example.com",
        .path = "/api",
        .expires = {},
        .secure = true,
        .http_only = false,
        .same_site = cookie::same_site_t::lax
    };
    
    urls::url_view url1("https://example.com/api/users");
    bool match1 = c.matches(url1);
    (void)match1;
    
    urls::url_view url2("http://example.com/api/users");  // Not HTTPS
    bool match2 = c.matches(url2);
    (void)match2;
}

//----------------------------------------------------------
// cookie_jar compilation tests
//----------------------------------------------------------

static_assert(std::is_default_constructible_v<cookie_jar>);
static_assert(std::is_copy_constructible_v<cookie_jar>);
static_assert(std::is_move_constructible_v<cookie_jar>);

void test_cookie_jar_construction()
{
    cookie_jar jar;
    (void)jar;
}

void test_cookie_jar_set()
{
    cookie_jar jar;
    
    cookie c{
        .name = "session",
        .value = "abc123",
        .domain = "example.com",
        .path = "/",
        .expires = {},
        .secure = false,
        .http_only = false,
        .same_site = cookie::same_site_t::lax
    };
    
    jar.set(c);
    jar.set(std::move(c));
}

void test_cookie_jar_set_from_header()
{
    cookie_jar jar;
    urls::url_view url("https://example.com/path");
    
    jar.set_from_header("session=abc123; Path=/; Secure; HttpOnly", url);
}

void test_cookie_jar_get_cookies()
{
    cookie_jar jar;
    urls::url_view url("https://example.com/api");
    
    std::vector<cookie> cookies = jar.get_cookies(url);
    (void)cookies;
}

void test_cookie_jar_get_header()
{
    cookie_jar jar;
    urls::url_view url("https://example.com/api");
    
    std::string header = jar.get_cookie_header(url);
    (void)header;
}

void test_cookie_jar_remove()
{
    cookie_jar jar;
    
    jar.remove("session", "example.com", "/");
    jar.remove("other", "example.com");  // Default path
}

void test_cookie_jar_maintenance()
{
    cookie_jar jar;
    
    jar.remove_expired();
    jar.clear();
}

void test_cookie_jar_size()
{
    cookie_jar jar;
    
    std::size_t size = jar.size();
    bool empty = jar.empty();
    
    (void)size; (void)empty;
}

void test_cookie_jar_iteration()
{
    cookie_jar jar;
    
    for (auto const& c : jar)
    {
        (void)c.name;
        (void)c.value;
    }
}

} // namespace burl
} // namespace boost

int main()
{
    return 0;
}
