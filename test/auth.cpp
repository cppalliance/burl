//
// Copyright (c) 2025 Vinnie Falco (vinnie dot falco at gmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

// Unit tests to verify auth.hpp compiles correctly

#include <boost/burl/auth.hpp>
#include <boost/http/request.hpp>

#include <type_traits>

namespace boost {
namespace burl {

//----------------------------------------------------------
// auth_base compilation tests
//----------------------------------------------------------

// auth_base is abstract (has pure virtual methods)
static_assert(std::is_abstract_v<auth_base>);

// auth_base is polymorphic
static_assert(std::is_polymorphic_v<auth_base>);

//----------------------------------------------------------
// http_basic_auth compilation tests
//----------------------------------------------------------

// http_basic_auth derives from auth_base
static_assert(std::is_base_of_v<auth_base, http_basic_auth>);

// http_basic_auth is not abstract
static_assert(!std::is_abstract_v<http_basic_auth>);

void test_basic_auth_construction()
{
    http_basic_auth auth("username", "password");
    (void)auth;
}

void test_basic_auth_apply()
{
    http_basic_auth auth("user", "pass");
    
    http::request req(http::method::get, "/path");
    auth.apply(req);
    
    // Authorization header should be set
    // (actual value depends on implementation)
}

void test_basic_auth_clone()
{
    http_basic_auth auth("user", "pass");
    
    std::unique_ptr<auth_base> cloned = auth.clone();
    (void)cloned;
}

void test_basic_auth_polymorphism()
{
    std::shared_ptr<auth_base> auth = 
        std::make_shared<http_basic_auth>("user", "pass");
    
    http::request req(http::method::get, "/");
    auth->apply(req);
}

//----------------------------------------------------------
// http_digest_auth compilation tests
//----------------------------------------------------------

// http_digest_auth derives from auth_base
static_assert(std::is_base_of_v<auth_base, http_digest_auth>);

void test_digest_auth_construction()
{
    http_digest_auth auth("username", "password");
    (void)auth;
}

void test_digest_auth_apply()
{
    http_digest_auth auth("user", "pass");
    
    http::request req(http::method::get, "/path");
    auth.apply(req);
}

void test_digest_auth_challenge()
{
    http_digest_auth auth("user", "pass");
    
    // Process a challenge from server
    auth.process_challenge(
        R"(Digest realm="test", nonce="abc123", qop="auth")");
    
    // Next apply() should include digest response
    http::request req(http::method::get, "/path");
    auth.apply(req);
}

void test_digest_auth_clone()
{
    http_digest_auth auth("user", "pass");
    
    std::unique_ptr<auth_base> cloned = auth.clone();
    (void)cloned;
}

//----------------------------------------------------------
// http_bearer_auth compilation tests
//----------------------------------------------------------

// http_bearer_auth derives from auth_base
static_assert(std::is_base_of_v<auth_base, http_bearer_auth>);

void test_bearer_auth_construction()
{
    http_bearer_auth auth("my-token-here");
    (void)auth;
}

void test_bearer_auth_apply()
{
    http_bearer_auth auth("token123");
    
    http::request req(http::method::get, "/api");
    auth.apply(req);
    
    // Should set: Authorization: Bearer token123
}

void test_bearer_auth_clone()
{
    http_bearer_auth auth("token");
    
    std::unique_ptr<auth_base> cloned = auth.clone();
    (void)cloned;
}

} // namespace burl
} // namespace boost

int main()
{
    return 0;
}
