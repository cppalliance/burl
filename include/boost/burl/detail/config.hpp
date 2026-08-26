//
// Copyright (c) 2026 Mohammad Nejati
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

#ifndef BOOST_BURL_DETAIL_CONFIG_HPP
#define BOOST_BURL_DETAIL_CONFIG_HPP

#include <boost/config.hpp>
#include <stdint.h>

namespace boost
{

namespace burl
{

//------------------------------------------------

#if (defined(BOOST_BURL_DYN_LINK) || defined(BOOST_ALL_DYN_LINK)) &&           \
    !defined(BOOST_BURL_STATIC_LINK)
#if defined(BOOST_BURL_SOURCE)
#define BOOST_BURL_DECL BOOST_SYMBOL_EXPORT
#define BOOST_BURL_BUILD_DLL
#else
#define BOOST_BURL_DECL BOOST_SYMBOL_IMPORT
#endif
#endif // shared lib

#ifndef BOOST_BURL_DECL
#define BOOST_BURL_DECL
#endif

#if defined(__MINGW32__)
#define BOOST_BURL_SYMBOL_VISIBLE BOOST_BURL_DECL
#else
#define BOOST_BURL_SYMBOL_VISIBLE BOOST_SYMBOL_VISIBLE
#endif

#if !defined(BOOST_BURL_SOURCE) && !defined(BOOST_ALL_NO_LIB) &&               \
    !defined(BOOST_BURL_NO_LIB)
#define BOOST_LIB_NAME boost_burl
#if defined(BOOST_ALL_DYN_LINK) || defined(BOOST_BURL_DYN_LINK)
#define BOOST_DYN_LINK
#endif
#include <boost/config/auto_link.hpp>
#endif

} // burl

} // boost

#endif
