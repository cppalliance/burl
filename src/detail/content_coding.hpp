//
// Copyright (c) 2026 Mohammad Nejati
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

#ifndef BOOST_BURL_SRC_DETAIL_CONTENT_CODING_HPP
#define BOOST_BURL_SRC_DETAIL_CONTENT_CODING_HPP

#include <boost/burl/fields_base.hpp>

#include <boost/http/metadata.hpp>

namespace boost
{
namespace burl
{
namespace detail
{

http::content_coding
content_coding(fields_base const& headers) noexcept;

} // namespace detail
} // namespace burl
} // namespace boost

#endif
