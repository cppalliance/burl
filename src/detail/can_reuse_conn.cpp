//
// Copyright (c) 2026 Mohammad Nejati
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

#include "can_reuse_conn.hpp"

namespace boost
{
namespace burl
{
namespace detail
{

bool
can_reuse_conn(response_parser& parser) noexcept
{
    if(!parser.got_header())
        return false;

    if(!parser.get().keep_alive())
        return false;

    if(!parser.got_body())
        return false;

    if(parser.has_buffered_data())
        return false;

    return true;
}

} // namespace detail
} // namespace burl
} // namespace boost
