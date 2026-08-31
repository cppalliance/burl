//
// Copyright (c) 2026 Mohammad Nejati
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

#include <boost/burl/detail/flat_buffer.hpp>

#include <boost/assert.hpp>

namespace boost
{
namespace burl
{
namespace detail
{

bool
flat_buffer::
empty() const noexcept
{
    return len == 0;
}

bool
flat_buffer::
full() const noexcept
{
    return len == cap;
}

std::size_t
flat_buffer::
size() const noexcept
{
    return len;
}

std::size_t
flat_buffer::
capacity() const noexcept
{
    return cap - pos - len;
}

capy::const_buffer
flat_buffer::
data() const noexcept
{
    return { ptr + pos, len };
}

capy::mutable_buffer
flat_buffer::
prepare() const noexcept
{
    return { ptr + pos + len, cap - pos - len };
}

void
flat_buffer::
commit(std::size_t n) noexcept
{
    BOOST_ASSERT(n <= capacity());
    len += n;
}

void
flat_buffer::
consume(std::size_t n) noexcept
{
    BOOST_ASSERT(n <= len);
    pos += n;
    len -= n;
    if(len == 0)
        pos = 0;
}

void
flat_buffer::
clear() noexcept
{
    pos = 0;
    len = 0;
}

} // namespace detail
} // namespace burl
} // namespace boost
