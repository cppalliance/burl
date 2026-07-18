//
// Copyright (c) 2021 Vinnie Falco (vinnie.falco@gmail.com)
// Copyright (c) 2026 Mohammad Nejati
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

#include <boost/burl/response_head_base.hpp>

#include "detail/except.hpp"

#include <cstring>

namespace boost
{
namespace burl
{

namespace
{
char buf[] = "HTTP/1.1 200 OK\r\n\r\n";
} // namespace

response_head_base::
response_head_base() noexcept
    : response_head_base(buf, 0, 2, 17)
{
}

void
response_head_base::
set_start_line(
    unsigned short si,
    std::string_view reason,
    http::version v)
{
    if(si < 100 || si > 999)
        detail::throw_invalid_argument("invalid status code");
    auto const vs = http::to_string(v);
    auto* dest = splice_prefix_(
        0,
        prefix_,
        15 + reason.size(),
        { 13, reason });
    std::memcpy(dest, vs.data(), 8);
    dest[8]  = ' ';
    dest[9]  = static_cast<char>('0' + si / 100);
    dest[10] = static_cast<char>('0' + (si / 10) % 10);
    dest[11] = static_cast<char>('0' + si % 10);
    dest[12] = ' ';
    dest[13 + reason.size()] = '\r';
    dest[14 + reason.size()] = '\n';
    set_version_(v);
    res_.status_int_ = si;
    res_.status_     = http::int_to_status(si);
}

void
response_head_base::
set_version(http::version v)
{
    detach_();
    auto const s = http::to_string(v);
    std::memcpy(base_(), s.data(), 8);
    set_version_(v);
}

} // namespace burl
} // namespace boost
