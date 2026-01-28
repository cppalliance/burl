//
// Copyright (c) 2025 Vinnie Falco (vinnie dot falco at gmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

#ifndef BOOST_BURL_FWD_HPP
#define BOOST_BURL_FWD_HPP

#include <string>

namespace boost {
namespace burl {

//----------------------------------------------------------
// Core types
//----------------------------------------------------------

class session;

template<class Body = std::string>
struct response;

struct streamed_response;
struct streamed_request;

//----------------------------------------------------------
// Configuration types
//----------------------------------------------------------

struct request_options;
struct verify_config;

//----------------------------------------------------------
// Body tag types
//----------------------------------------------------------

struct as_string_t;
struct as_json_t;

template<class T>
struct as_type_t;

//----------------------------------------------------------
// Cookie types
//----------------------------------------------------------

struct cookie;
class cookie_jar;

//----------------------------------------------------------
// Authentication types
//----------------------------------------------------------

class auth_base;
class http_basic_auth;
class http_digest_auth;

//----------------------------------------------------------
// Error types
//----------------------------------------------------------

enum class error;
class http_error;

} // namespace burl
} // namespace boost

#endif
