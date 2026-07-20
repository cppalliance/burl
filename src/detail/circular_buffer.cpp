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
    if(pos + len <= cap)
        return { { { ptr + pos, len }, { ptr, 0 } } };
    return { { { ptr + pos, cap - pos },
        { ptr, len - (cap - pos) } } };
}

capy::const_buffer
circular_buffer::
first(std::size_t n) const noexcept
{
    auto const k = (pos + len <= cap) ? len : cap - pos;
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

} // namespace detail
} // namespace burl
} // namespace boost
