//
// Copyright (c) 2026 Mohammad Nejati
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

#include "redirect.hpp"

#include <boost/http/field.hpp>
#include <boost/url/parse.hpp>

namespace boost
{
namespace burl
{
namespace detail
{

is_redirect_result
is_redirect(
    http::status status,
    const client::config& cfg) noexcept
{
    // The specifications do not intend for 301 and 302
    // redirects to change the HTTP method, but most
    // user agents do change the method in practice.
    switch(status)
    {
    case http::status::moved_permanently:
        return { true, !cfg.post301 };
    case http::status::found:
        return { true, !cfg.post302 };
    case http::status::see_other:
        return { true, !cfg.post303 };
    case http::status::temporary_redirect:
    case http::status::permanent_redirect:
        return { true, false };
    default:
        return { false, false };
    }
}

urls::url
resolve_location(
    fields_base const& response,
    const urls::url_view& base)
{
    auto it = response.find(http::field::location);
    if(it != response.end())
    {
        auto rs = urls::parse_uri_reference(it->value);
        if(rs.has_value())
        {
            urls::url url;
            urls::resolve(base, rs.value(), url);
            // RFC 9110, Section 10.2.2: a Location without a
            // fragment inherits the fragment of the target URI.
            if(!url.has_fragment() && base.has_fragment())
                url.set_encoded_fragment(base.encoded_fragment());
            return url;
        }
    }
    return {};
}

} // namespace detail
} // namespace burl
} // namespace boost
