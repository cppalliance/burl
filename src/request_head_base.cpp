//
// Copyright (c) 2021 Vinnie Falco (vinnie.falco@gmail.com)
// Copyright (c) 2026 Mohammad Nejati
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

#include <boost/burl/request_head_base.hpp>

#include <cstring>

namespace boost
{
namespace burl
{

namespace
{
char buf[] = "GET / HTTP/1.1\r\n\r\n";
} // namespace

request_head_base::
request_head_base() noexcept
    : request_head_base(buf, 0, 2, 16)
{
}

void
request_head_base::
set_method_(
    std::string_view s,
    http::method m)
{
    BOOST_ASSERT(!s.empty());
    splice_prefix_(0, req_.method_len_, s.size(), { 0, s });
    req_.method_     = m;
    req_.method_len_ = static_cast<std::uint16_t>(s.size());
}

void
request_head_base::
set_start_line_(
    std::string_view ms,
    http::method m,
    std::string_view t,
    http::version v)
{
    BOOST_ASSERT(!ms.empty());
    BOOST_ASSERT(!t.empty());
    auto const vs = http::to_string(v);
    auto* dest = splice_prefix_(
        0,
        prefix_,
        ms.size() + 1 + t.size() + 1 + 8 + 2,
        { 0, ms },
        { ms.size() + 1, t });
    dest += ms.size();
    *dest++ = ' ';
    dest += t.size();
    *dest++ = ' ';
    std::memcpy(dest, vs.data(), 8);
    dest += 8;
    *dest++ = '\r';
    *dest   = '\n';
    req_.method_     = m;
    req_.method_len_ = static_cast<std::uint16_t>(ms.size());
    req_.target_len_ = static_cast<std::uint16_t>(t.size());
    set_version_(v);
}

void
request_head_base::
set_target(std::string_view s)
{
    BOOST_ASSERT(!s.empty());
    splice_prefix_(
        req_.method_len_ + 1,
        req_.target_len_,
        s.size(),
        { 0, s });
    req_.target_len_ = static_cast<std::uint16_t>(s.size());
}

void
request_head_base::
set_version(http::version v)
{
    detach_();
    auto const s = http::to_string(v);
    std::memcpy(buf_ - 10, s.data(), 8);
    set_version_(v);
}

void
request_head_base::
set_expect_100_continue(bool b)
{
    if(b)
        set(http::field::expect, "100-continue");
    else
        erase(http::field::expect);
}

} // namespace burl
} // namespace boost
