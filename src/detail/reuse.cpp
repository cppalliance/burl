//
// Copyright (c) 2026 Mohammad Nejati
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

#include "reuse.hpp"

namespace boost
{
namespace burl
{
namespace detail
{

bool
can_reuse_conn(http::response_parser& parser) noexcept
{
    if(!parser.got_header())
        return false;

    if(!parser.get().keep_alive())
        return false;

    if(!parser.is_complete())
    {
        // The rest of the message may already sit in the
        // parser's buffer; parsing it needs no I/O and makes
        // the connection reusable.
        try
        {
            system::error_code ec;
            parser.parse(ec);
        }
        catch(...)
        {
        }
    }

    return parser.is_complete();
}

} // namespace detail
} // namespace burl
} // namespace boost
