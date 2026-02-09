//
// Copyright (c) 2025 Vinnie Falco (vinnie dot falco at gmail dot com)
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

namespace boost {

namespace burl {

//------------------------------------------------

# if (defined(BOOST_BURL_DYN_LINK) || defined(BOOST_ALL_DYN_LINK)) && !defined(BOOST_BURL_STATIC_LINK)
#  if defined(BOOST_BURL_SOURCE)
#   define BOOST_BURL_DECL        BOOST_SYMBOL_EXPORT
#   define BOOST_BURL_BUILD_DLL
#  else
#   define BOOST_BURL_DECL        BOOST_SYMBOL_IMPORT
#  endif
# endif // shared lib

# ifndef  BOOST_BURL_DECL
#  define BOOST_BURL_DECL
# endif

#if defined(__MINGW32__)
    #define BOOST_BURL_SYMBOL_VISIBLE BOOST_BURL_DECL
#else
    #define BOOST_BURL_SYMBOL_VISIBLE BOOST_SYMBOL_VISIBLE
#endif

# if !defined(BOOST_BURL_SOURCE) && !defined(BOOST_ALL_NO_LIB) && !defined(BOOST_BURL_NO_LIB)
#  define BOOST_LIB_NAME boost_burl
#  if defined(BOOST_ALL_DYN_LINK) || defined(BOOST_BURL_DYN_LINK)
#   define BOOST_DYN_LINK
#  endif
#  include <boost/config/auto_link.hpp>
# endif

//------------------------------------------------

// Add source location to error codes
#ifdef BOOST_BURL_NO_SOURCE_LOCATION
# define BOOST_BURL_ERR(ev) (::boost::system::error_code(ev))
# define BOOST_BURL_RETURN_EC(ev) return (ev)
#else
# define BOOST_BURL_ERR(ev) ( \
    ::boost::system::error_code( (ev), [] { \
    static constexpr auto loc((BOOST_CURRENT_LOCATION)); \
    return &loc; }()))
# define BOOST_BURL_RETURN_EC(ev)                                  \
    do {                                                                 \
        static constexpr auto loc ## __LINE__((BOOST_CURRENT_LOCATION)); \
        return ::boost::system::error_code((ev), &loc ## __LINE__);      \
    } while(0)
#endif

} // burl

} // boost

#endif
