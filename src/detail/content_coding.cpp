//
// Copyright (c) 2026 Mohammad Nejati
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

#include "content_coding.hpp"

#include <boost/core/detail/string_view.hpp>
#include <boost/http/rfc/token_rule.hpp>
#include <boost/url/grammar/ci_string.hpp>
#include <boost/url/grammar/parse.hpp>

namespace boost
{
namespace burl
{
namespace detail
{

http::content_coding
content_coding(fields_base const& headers) noexcept
{
    using enum http::content_coding;
    using urls::grammar::ci_is_equal;

    auto const it = headers.find(http::field::content_encoding);
    if(it == headers.end())
        return identity;

    if(auto rv = urls::grammar::parse(
        it->value, http::token_rule))
    {
        if(ci_is_equal(*rv, "identity"))
            return identity;
        if(ci_is_equal(*rv, "deflate"))
            return deflate;
        if(ci_is_equal(*rv, "gzip"))
            return gzip;
        if(ci_is_equal(*rv, "br"))
            return br;
        if(ci_is_equal(*rv, "zstd"))
            return zstd;
    }

    return unknown;
}

} // namespace detail
} // namespace burl
} // namespace boost
