//
// Copyright (c) 2026 Mohammad Nejati
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

#include <boost/burl/detail/circular_buffer.hpp>

#include "util.hpp"

#include <boost/assert.hpp>

#include <algorithm>
#include <cstring>

namespace boost
{
namespace burl
{
namespace detail
{

bool
circular_buffer::
empty() const noexcept
{
    return len == 0;
}

bool
circular_buffer::
full() const noexcept
{
    return len == cap;
}

bool
circular_buffer::
wrapped() const noexcept
{
    return pos + len > cap;
}

std::size_t
circular_buffer::
size() const noexcept
{
    return len;
}

std::array<capy::const_buffer, 2>
circular_buffer::
data() const noexcept
{
    if(!wrapped())
        return { { { ptr + pos, len }, { ptr, 0 } } };
    return { { { ptr + pos, cap - pos },
        { ptr, len - (cap - pos) } } };
}

capy::const_buffer
circular_buffer::
first(std::size_t n) const noexcept
{
    auto const k = wrapped() ? cap - pos : len;
    return { ptr + pos, clamp(k, n) };
}

std::array<capy::mutable_buffer, 2>
circular_buffer::
prepare() const noexcept
{
    std::size_t w = pos + len;
    if(w >= cap)
        w -= cap;
    std::size_t const free = cap - len;
    if(w + free <= cap)
        return { { { ptr + w, free }, { ptr, 0 } } };
    return { { { ptr + w, cap - w },
        { ptr, free - (cap - w) } } };
}

void
circular_buffer::
commit(std::size_t n) noexcept
{
    if(n > cap - len)
        n = cap - len;
    len += n;
}

void
circular_buffer::
consume(std::size_t n) noexcept
{
    if(n > len)
        n = len;
    pos += n;
    if(pos >= cap)
        pos -= cap;
    len -= n;
}

void
circular_buffer::
reset(char* p) noexcept
{
    BOOST_ASSERT(p <= ptr + cap);
    cap = static_cast<std::size_t>((ptr + cap) - p);
    ptr = p;
    pos = 0;
    len = 0;
}

void
circular_buffer::
shed(std::size_t n) noexcept
{
    BOOST_ASSERT(pos == 0);
    BOOST_ASSERT(n <= len);
    ptr += n;
    cap -= n;
    len -= n;
}

void
circular_buffer::
slide(char* p) noexcept
{
    BOOST_ASSERT(pos == 0);
    BOOST_ASSERT(p <= ptr);
    std::memmove(p, ptr, len);
    cap += static_cast<std::size_t>(ptr - p);
    ptr = p;
}

char*
circular_buffer::
linearize(char* floor) noexcept
{
    BOOST_ASSERT(floor <= ptr);
    char* p = floor;
    if(len != 0 && !wrapped())
    {
        p = ptr + pos;
    }
    else if(len != 0)
    {
        auto const bufs = data();
        auto const* a = static_cast<char const*>(bufs[0].data());
        auto an       = bufs[0].size();
        auto const* b = static_cast<char const*>(bufs[1].data());
        auto const bn = bufs[1].size();
        char* base    = floor;
        do
        {
            auto* bp = (std::min)(base + an, const_cast<char*>(a) - bn);
            b = static_cast<char const*>(std::memmove(bp, b, bn));
            auto chunk_a = static_cast<std::size_t>(b - base);
            std::memcpy(base, a, chunk_a);
            an   -= chunk_a;
            base += chunk_a;
            a    += chunk_a;
        } while(an);
    }
    cap = static_cast<std::size_t>((ptr + cap) - p);
    ptr = p;
    pos = 0;
    return p;
}

} // namespace detail
} // namespace burl
} // namespace boost
