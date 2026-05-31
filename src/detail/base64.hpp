//
// Copyright (c) 2026 Mohammad Nejati
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

#ifndef BOOST_BURL_SRC_DETAIL_BASE64_HPP
#define BOOST_BURL_SRC_DETAIL_BASE64_HPP

#include <string>
#include <string_view>

namespace boost
{
namespace burl
{
namespace detail
{

void
base64_encode(std::string& dest, std::string_view src);

} // namespace detail
} // namespace burl
} // namespace boost

#endif
