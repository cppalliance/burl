//
// Copyright (c) 2025 Vinnie Falco (vinnie dot falco at gmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

// Unit tests to verify error.hpp compiles correctly

#include <boost/burl/error.hpp>

#include <type_traits>

namespace boost {
namespace burl {

//----------------------------------------------------------
// error enum compilation tests
//----------------------------------------------------------

// error is a scoped enum
static_assert(std::is_enum_v<error>);
static_assert(!std::is_convertible_v<error, int>);

// error is registered as an error_code_enum
static_assert(std::is_error_code_enum<error>::value);

void test_error_values()
{
    // All error values should be accessible
    error e1 = error::success;
    error e2 = error::invalid_url;
    error e3 = error::invalid_scheme;
    error e4 = error::resolve_failed;
    error e5 = error::connection_failed;
    error e6 = error::tls_handshake_failed;
    error e7 = error::timeout;
    error e8 = error::too_many_redirects;
    error e9 = error::body_too_large;
    error e10 = error::invalid_response;
    error e11 = error::connection_closed;
    error e12 = error::cancelled;
    error e13 = error::not_implemented;
    
    (void)e1; (void)e2; (void)e3; (void)e4; (void)e5;
    (void)e6; (void)e7; (void)e8; (void)e9; (void)e10;
    (void)e11; (void)e12; (void)e13;
}

//----------------------------------------------------------
// error_code integration tests
//----------------------------------------------------------

void test_make_error_code()
{
    std::error_code ec = make_error_code(error::timeout);
    
    // Should have a message
    std::string msg = ec.message();
    (void)msg;
    
    // Should reference burl category
    std::error_category const& cat = ec.category();
    (void)cat;
}

void test_error_code_comparison()
{
    std::error_code ec1 = make_error_code(error::timeout);
    std::error_code ec2 = make_error_code(error::timeout);
    std::error_code ec3 = make_error_code(error::cancelled);
    
    bool same = (ec1 == ec2);
    bool diff = (ec1 != ec3);
    
    (void)same; (void)diff;
}

void test_error_category()
{
    std::error_category const& cat = burl_category();
    
    char const* name = cat.name();
    std::string msg = cat.message(static_cast<int>(error::timeout));
    
    (void)name; (void)msg;
}

//----------------------------------------------------------
// http_error exception tests
//----------------------------------------------------------

// http_error derives from std::exception
static_assert(std::is_base_of_v<std::exception, http_error>);

void test_http_error_construction()
{
    http_error err(404, "Not Found", "https://example.com/missing");
    (void)err;
}

void test_http_error_accessors()
{
    http_error err(500, "Internal Server Error", "https://example.com/api");
    
    unsigned short status = err.status_code();
    std::string const& reason = err.reason();
    std::string const& url = err.url();
    char const* what = err.what();
    
    (void)status; (void)reason; (void)url; (void)what;
}

void test_http_error_throwing()
{
    try {
        throw http_error(401, "Unauthorized", "https://api.example.com");
    }
    catch (http_error const& e) {
        (void)e.status_code();
    }
    catch (std::exception const& e) {
        // Also catchable as std::exception
        (void)e.what();
    }
}

} // namespace burl
} // namespace boost

int main()
{
    return 0;
}
