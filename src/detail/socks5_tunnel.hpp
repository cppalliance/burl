//
// Copyright (c) 2026 Mohammad Nejati
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

#ifndef BOOST_BURL_SRC_DETAIL_SOCKS5_TUNNEL_HPP
#define BOOST_BURL_SRC_DETAIL_SOCKS5_TUNNEL_HPP

#include <boost/capy/io/any_stream.hpp>
#include <boost/capy/io_task.hpp>
#include <boost/url/url_view.hpp>

#include <string_view>

namespace boost
{
namespace burl
{
namespace detail
{

capy::io_task<>
open_socks5_tunnel(
    capy::any_stream stream,
    std::string_view target_host,
    std::string_view target_port,
    urls::url_view proxy);

} // namespace detail
} // namespace burl
} // namespace boost

#endif
