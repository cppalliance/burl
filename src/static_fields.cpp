//
// Copyright (c) 2021 Vinnie Falco (vinnie.falco@gmail.com)
// Copyright (c) 2026 Mohammad Nejati
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

#include <boost/burl/static_fields.hpp>

namespace boost
{
namespace burl
{

static_fields::
static_fields(
    char* storage,
    std::size_t n)
    : fields_base()
{
    init_static_(storage, n);
}

static_fields::
static_fields(static_fields&& other) noexcept
    : fields_base()
{
    swap_(other);
}

static_fields&
static_fields::
operator=(static_fields const& other)
{
    return *this = static_cast<fields_base const&>(other);
}

static_fields&
static_fields::
operator=(fields_base const& other)
{
    if(this != &other)
        assign_(other, 0);
    return *this;
}

} // namespace burl
} // namespace boost
