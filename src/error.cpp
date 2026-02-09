//
// Copyright (c) 2025 Vinnie Falco (vinnie dot falco at gmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

#include <boost/burl/error.hpp>

namespace boost {
namespace burl {

char const*
error_category::name() const noexcept
{
    return "boost.burl";
}

std::string
error_category::message(int ev) const
{
    switch(static_cast<error>(ev))
    {
    case error::success:            return "success";
    case error::invalid_url:        return "invalid URL";
    case error::invalid_scheme:     return "invalid URL scheme";
    case error::resolve_failed:     return "DNS resolution failed";
    case error::connection_failed:  return "connection failed";
    case error::tls_handshake_failed: return "TLS handshake failed";
    case error::timeout:            return "operation timed out";
    case error::too_many_redirects: return "too many redirects";
    case error::body_too_large:     return "response body too large";
    case error::invalid_response:   return "invalid HTTP response";
    case error::connection_closed:  return "connection closed";
    case error::cancelled:          return "operation cancelled";
    case error::not_implemented:    return "not implemented";
    default:                        return "unknown error";
    }
}

std::error_condition
error_category::default_error_condition(int ev) const noexcept
{
    return std::error_condition(ev, *this);
}

std::error_category const&
burl_category() noexcept
{
    static error_category const cat{};
    return cat;
}

http_error::http_error(
    unsigned short status_code,
    std::string reason,
    std::string url)
    : status_code_(status_code)
    , reason_(std::move(reason))
    , url_(std::move(url))
{
    what_ = std::to_string(status_code_) + " " + reason_ + ": " + url_;
}

} // namespace burl
} // namespace boost
