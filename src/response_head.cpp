//
// Copyright (c) 2021 Vinnie Falco (vinnie.falco@gmail.com)
// Copyright (c) 2026 Mohammad Nejati
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

#include <boost/burl/response_head.hpp>

#include <utility>

namespace boost
{
namespace burl
{

response_head::
response_head() noexcept
    : response_head_base()
{
}

response_head::
~response_head()
{
    release_();
}

response_head::
response_head(response_head&& other) noexcept
    : response_head()
{
    swap_(other);
}

response_head::
response_head(response_head_base const& other)
    : response_head()
{
    response_head_base::operator=(other);
}

response_head::
response_head(response_head const& other)
    : response_head(static_cast<response_head_base const&>(other))
{
}

response_head&
response_head::
operator=(response_head&& other) noexcept
{
    response_head tmp(std::move(other));
    swap_(tmp);
    return *this;
}

response_head&
response_head::
operator=(response_head_base const& other)
{
    response_head_base::operator=(other);
    return *this;
}

response_head&
response_head::
operator=(response_head const& other)
{
    return *this = static_cast<response_head_base const&>(other);
}

void
response_head::
swap(response_head& other) noexcept
{
    swap_(other);
}

void
response_head::
reserve(
    std::size_t bytes,
    std::size_t count)
{
    reserve_(bytes, count);
}

void
response_head::
shrink_to_fit()
{
    shrink_to_fit_();
}

} // namespace burl
} // namespace boost
