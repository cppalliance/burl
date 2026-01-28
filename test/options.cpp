//
// Copyright (c) 2025 Vinnie Falco (vinnie dot falco at gmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

// Unit tests to verify options.hpp compiles correctly

#include <boost/burl/options.hpp>

#include <type_traits>

namespace boost {
namespace burl {

//----------------------------------------------------------
// verify_config compilation tests
//----------------------------------------------------------

static_assert(std::is_default_constructible_v<verify_config>);

void test_verify_config_default()
{
    verify_config v;
    
    // Check defaults
    bool verify = v.verify_peer;  // true
    std::string& ca_file = v.ca_file;
    std::string& ca_path = v.ca_path;
    std::string& hostname = v.hostname;
    
    (void)verify; (void)ca_file; (void)ca_path; (void)hostname;
}

void test_verify_config_aggregate_init()
{
    verify_config v{
        .verify_peer = false,
        .ca_file = "/path/to/ca.crt",
        .ca_path = "/etc/ssl/certs",
        .hostname = "example.com"
    };
    (void)v;
}

//----------------------------------------------------------
// request_options compilation tests
//----------------------------------------------------------

static_assert(std::is_default_constructible_v<request_options>);

void test_request_options_default()
{
    request_options opts;
    
    // All optionals should be nullopt by default
    bool has_headers = opts.headers.has_value();
    bool has_json = opts.json.has_value();
    bool has_data = opts.data.has_value();
    bool has_timeout = opts.timeout.has_value();
    bool has_max_redirects = opts.max_redirects.has_value();
    bool has_allow_redirects = opts.allow_redirects.has_value();
    bool has_verify = opts.verify.has_value();
    bool has_auth = opts.auth != nullptr;
    
    (void)has_headers; (void)has_json; (void)has_data;
    (void)has_timeout; (void)has_max_redirects;
    (void)has_allow_redirects; (void)has_verify; (void)has_auth;
}

void test_request_options_with_values()
{
    request_options opts;
    
    // Set headers
    opts.headers = http::fields{};
    opts.headers->set(http::field::accept, "application/json");
    
    // Set JSON body
    opts.json = R"({"key": "value"})";
    
    // Set form data
    opts.data = "key=value&foo=bar";
    
    // Set timeout
    opts.timeout = std::chrono::milliseconds{5000};
    
    // Set redirect handling
    opts.max_redirects = 10;
    opts.allow_redirects = true;
    
    // Set verification
    opts.verify = true;
    
    // Set auth
    opts.auth = std::make_shared<http_basic_auth>("user", "pass");
}

} // namespace burl
} // namespace boost

int main()
{
    return 0;
}
