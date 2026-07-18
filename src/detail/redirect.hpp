//
// Copyright (c) 2026 Mohammad Nejati
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

#ifndef BOOST_BURL_SRC_DETAIL_REDIRECT_HPP
#define BOOST_BURL_SRC_DETAIL_REDIRECT_HPP

#include <boost/burl/client.hpp>
#include <boost/burl/fields_base.hpp>

#include <boost/http/status.hpp>
#include <boost/url/url.hpp>
#include <boost/url/url_view.hpp>

namespace boost
{
namespace burl
{
namespace detail
{

struct is_redirect_result
{
    bool is_redirect        = false;
    bool need_method_change = false;
};

is_redirect_result
is_redirect(
    http::status status,
    const client::config& cfg) noexcept;

urls::url
resolve_location(
    fields_base const& response,
    const urls::url_view& base);

} // namespace detail
} // namespace burl
} // namespace boost

#endif
