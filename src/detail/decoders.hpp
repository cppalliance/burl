//
// Copyright (c) 2026 Mohammad Nejati
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

#ifndef BOOST_BURL_SRC_DETAIL_DECODERS_HPP
#define BOOST_BURL_SRC_DETAIL_DECODERS_HPP

#include <boost/burl/detail/decoder.hpp>

#include <boost/http/metadata.hpp>

#include <memory>

namespace boost
{
namespace burl
{
namespace detail
{

std::unique_ptr<decoder>
make_decoder(http::content_coding coding);

} // namespace detail
} // namespace burl
} // namespace boost

#endif
