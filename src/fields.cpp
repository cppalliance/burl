//
// Copyright (c) 2021 Vinnie Falco (vinnie.falco@gmail.com)
// Copyright (c) 2026 Mohammad Nejati
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

#include <boost/burl/fields.hpp>

#include <utility>

namespace boost
{
namespace burl
{

fields::
fields() noexcept
    : fields_base()
{
}

fields::
~fields()
{
    release_();
}

fields::
fields(fields&& other) noexcept
    : fields()
{
    swap_(other);
}

fields::
fields(fields_base const& other)
    : fields()
{
    assign_(other, 0);
}

fields::
fields(fields const& other)
    : fields(static_cast<fields_base const&>(other))
{
}

fields::
fields(std::initializer_list<field_view> init)
    : fields()
{
    append(init);
}

fields&
fields::
operator=(fields&& other) noexcept
{
    fields tmp(std::move(other));
    swap_(tmp);
    return *this;
}

fields&
fields::
operator=(fields_base const& other)
{
    if(this != &other)
        assign_(other, 0);
    return *this;
}

fields&
fields::
operator=(fields const& other)
{
    return *this = static_cast<fields_base const&>(other);
}

void
fields::
swap(fields& other) noexcept
{
    swap_(other);
}

void
fields::
reserve(
    std::size_t bytes,
    std::size_t count)
{
    reserve_(bytes, count);
}

void
fields::
shrink_to_fit()
{
    if(count_ == 0)
    {
        // release the allocation entirely
        fields tmp;
        swap_(tmp);
        return;
    }
    shrink_to_fit_();
}

} // namespace burl
} // namespace boost
