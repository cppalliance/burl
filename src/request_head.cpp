//
// Copyright (c) 2021 Vinnie Falco (vinnie.falco@gmail.com)
// Copyright (c) 2026 Mohammad Nejati
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

#include <boost/burl/request_head.hpp>

#include <utility>

namespace boost
{
namespace burl
{

request_head::
request_head() noexcept
    : request_head_base()
{
}

request_head::
~request_head()
{
    release_();
}

request_head::
request_head(request_head&& other) noexcept
    : request_head()
{
    swap_(other);
}

request_head::
request_head(request_head_base const& other)
    : request_head()
{
    request_head_base::operator=(other);
}

request_head::
request_head(request_head const& other)
    : request_head(static_cast<request_head_base const&>(other))
{
}

request_head&
request_head::
operator=(request_head&& other) noexcept
{
    request_head tmp(std::move(other));
    swap_(tmp);
    return *this;
}

request_head&
request_head::
operator=(request_head_base const& other)
{
    request_head_base::operator=(other);
    return *this;
}

request_head&
request_head::
operator=(request_head const& other)
{
    return *this = static_cast<request_head_base const&>(other);
}

void
request_head::
swap(request_head& other) noexcept
{
    swap_(other);
}

void
request_head::
reserve(
    std::size_t bytes,
    std::size_t count)
{
    reserve_(bytes, count);
}

void
request_head::
shrink_to_fit()
{
    shrink_to_fit_();
}

} // namespace burl
} // namespace boost
