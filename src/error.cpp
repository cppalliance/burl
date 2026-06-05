//
// Copyright (c) 2026 Mohammad Nejati
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

#include <boost/burl/error.hpp>

#include <boost/http/status.hpp>

namespace boost
{
namespace burl
{

char const*
error_category::name() const noexcept
{
    return "boost.burl";
}

std::string
error_category::message(int ev) const
{
    if(ev >= 400 && ev < 600)
    {
        auto status = static_cast<http::status>(ev);
        return "HTTP " + std::to_string(ev) + " " +
            std::string(http::to_string(status));
    }

    switch(static_cast<error>(ev))
    {
    case error::unsupported_url_scheme:
        return "unsupported URL scheme";
    case error::too_many_redirects:
        return "too many redirects";
    case error::bad_redirect_response:
        return "bad redirect response";
    case error::file_changed:
        return "file size changed during read";
    case error::unsupported_proxy_scheme:
        return "unsupported proxy scheme";
    case error::proxy_connect_failed:
        return "proxy could not connect to the target";
    case error::proxy_auth_failed:
        return "proxy authentication failed";
    case error::proxy_unsupported_version:
        return "unsupported proxy protocol version";
    default:
        return "unknown error";
    }
}

std::error_condition
error_category::default_error_condition(int ev) const noexcept
{
    if(ev >= 400 && ev < 500)
        return condition::client_error;
    if(ev >= 500 && ev < 600)
        return condition::server_error;
    return std::error_condition(ev, *this);
}

//----------------------------------------------------------

char const*
condition_category::name() const noexcept
{
    return "boost.burl.condition";
}

std::string
condition_category::message(int ev) const
{
    switch(static_cast<condition>(ev))
    {
    case condition::client_error:
        return "HTTP client error";
    case condition::server_error:
        return "HTTP server error";
    default:
        return "unknown condition";
    }
}

//----------------------------------------------------------

std::error_category const&
burl_category() noexcept
{
    static error_category const cat{};
    return cat;
}

std::error_category const&
burl_condition_category() noexcept
{
    static condition_category const cat{};
    return cat;
}

} // namespace burl
} // namespace boost
