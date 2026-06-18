//
// Copyright (c) 2026 Mohammad Nejati
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

#include "effective_port.hpp"

namespace boost
{
namespace burl
{
namespace detail
{

std::string_view
effective_port(const urls::url_view& url) noexcept
{
    if(url.has_port())
        return url.port();

    if(url.scheme() == "https")
        return "443";

    if(url.scheme() == "http")
        return "80";

    if(url.scheme() == "socks5" || url.scheme() == "socks5h")
        return "1080";

    return {};
}

} // namespace detail
} // namespace burl
} // namespace boost
