//
// Copyright (c) 2026 Mohammad Nejati
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

#ifndef BOOST_BURL_SRC_DETAIL_EFFECTIVE_PORT_HPP
#define BOOST_BURL_SRC_DETAIL_EFFECTIVE_PORT_HPP

#include <boost/url/url_view.hpp>

#include <string_view>

namespace boost
{
namespace burl
{
namespace detail
{

std::string_view
effective_port(const urls::url_view& url) noexcept;

} // namespace detail
} // namespace burl
} // namespace boost

#endif
