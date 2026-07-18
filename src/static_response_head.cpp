//
// Copyright (c) 2021 Vinnie Falco (vinnie.falco@gmail.com)
// Copyright (c) 2026 Mohammad Nejati
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

#include <boost/burl/static_response_head.hpp>

namespace boost
{
namespace burl
{

static_response_head::
static_response_head(
    char* storage,
    std::size_t n)
    : response_head_base()
{
    init_static_(storage, n);
}

static_response_head::
static_response_head(static_response_head&& other) noexcept
    : response_head_base()
{
    swap_(other);
}

static_response_head&
static_response_head::
operator=(response_head_base const& other)
{
    response_head_base::operator=(other);
    return *this;
}

static_response_head&
static_response_head::
operator=(static_response_head const& other)
{
    return *this = static_cast<response_head_base const&>(other);
}

} // namespace burl
} // namespace boost
