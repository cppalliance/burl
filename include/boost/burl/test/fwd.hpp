//
// Copyright (c) 2026 Mohammad Nejati
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

#ifndef BOOST_BURL_TEST_FWD_HPP
#define BOOST_BURL_TEST_FWD_HPP

namespace boost
{
namespace burl
{

/** Test infrastructure for exercising burl in isolation.

    These facilities synthesize genuine @ref response
    objects and the connections that back them, so that
    body conversions, status handling, and framing can
    be tested without standing up a client or server.

    @see @ref response_factory.
*/
namespace test
{

class response_factory;

} // namespace test
} // namespace burl
} // namespace boost

#endif
