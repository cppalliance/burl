//
// Copyright (c) 2025 Vinnie Falco (vinnie dot falco at gmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

// Unit tests to verify response.hpp compiles correctly

#include <boost/burl/response.hpp>

#include <boost/json/value.hpp>
#include <type_traits>

namespace boost {
namespace burl {

//----------------------------------------------------------
// response<Body> compilation tests
//----------------------------------------------------------

// response is default constructible
static_assert(std::is_default_constructible_v<response<std::string>>);

// response is movable
static_assert(std::is_move_constructible_v<response<std::string>>);
static_assert(std::is_move_assignable_v<response<std::string>>);

// response is copyable
static_assert(std::is_copy_constructible_v<response<std::string>>);
static_assert(std::is_copy_assignable_v<response<std::string>>);

//----------------------------------------------------------
// response member access tests
//----------------------------------------------------------

void test_response_members()
{
    response<std::string> r;
    
    // Direct member access
    http::response& msg = r.message;
    std::string& body = r.body;
    urls::url& url = r.url;
    std::chrono::milliseconds& elapsed = r.elapsed;
    std::vector<response<std::string>>& history = r.history;
    
    (void)msg; (void)body; (void)url; (void)elapsed; (void)history;
}

void test_response_convenience_accessors()
{
    response<std::string> r;
    
    // Convenience accessors
    http::status s = r.status();
    unsigned short si = r.status_int();
    std::string_view reason = r.reason();
    bool ok = r.ok();
    bool redirect = r.is_redirect();
    std::string_view text = r.text();
    
    (void)s; (void)si; (void)reason; (void)ok; (void)redirect; (void)text;
}

void test_raise_for_status()
{
    response<std::string> r;
    
    // This compiles - would throw if status >= 400
    try {
        r.raise_for_status();
    } catch (http_error const&) {
        // Expected for error responses
    }
}

//----------------------------------------------------------
// response with different body types
//----------------------------------------------------------

void test_response_json_body()
{
    response<json::value> r;
    
    // Body is json::value
    json::value& body = r.body;
    (void)body;
    
    // Other members still accessible
    http::response& msg = r.message;
    urls::url& url = r.url;
    (void)msg; (void)url;
}

void test_response_custom_body()
{
    struct MyData {
        int id;
        std::string name;
    };
    
    response<MyData> r;
    
    // Body is MyData
    MyData& body = r.body;
    int& id = body.id;
    std::string& name = body.name;
    (void)id; (void)name;
}

//----------------------------------------------------------
// streamed_response compilation tests
//----------------------------------------------------------

// streamed_response is default constructible
static_assert(std::is_default_constructible_v<streamed_response>);

// streamed_response is movable (any_buffer_source is move-only)
static_assert(std::is_move_constructible_v<streamed_response>);
static_assert(std::is_move_assignable_v<streamed_response>);

// streamed_response is NOT copyable (any_buffer_source is not)
static_assert(!std::is_copy_constructible_v<streamed_response>);
static_assert(!std::is_copy_assignable_v<streamed_response>);

void test_streamed_response_members()
{
    streamed_response r;
    
    // Direct member access
    http::response& msg = r.message;
    capy::any_buffer_source& body = r.body;
    urls::url& url = r.url;
    
    (void)msg; (void)body; (void)url;
}

void test_streamed_response_accessors()
{
    streamed_response r;
    
    // Convenience accessors
    http::status s = r.status();
    unsigned short si = r.status_int();
    std::string_view reason = r.reason();
    bool ok = r.ok();
    bool redirect = r.is_redirect();
    
    (void)s; (void)si; (void)reason; (void)ok; (void)redirect;
}

//----------------------------------------------------------
// string_response alias
//----------------------------------------------------------

void test_string_response_alias()
{
    // string_response is response<std::string>
    static_assert(std::is_same_v<string_response, response<std::string>>);
    
    string_response r;
    std::string& body = r.body;
    (void)body;
}

} // namespace burl
} // namespace boost

int main()
{
    return 0;
}
