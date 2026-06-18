//
// Copyright (c) 2026 Mohammad Nejati
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

// Test that header file is self-contained.
#include "src/detail/effective_port.hpp"

#include "test_suite.hpp"

namespace boost
{
namespace burl
{
namespace detail
{

class effective_port_test
{
public:
    void
    testExplicitPort()
    {
        BOOST_TEST_EQ(effective_port("http://example.com:8080"), "8080");
        BOOST_TEST_EQ(effective_port("ftp://example.com:21"), "21");
        BOOST_TEST_EQ(effective_port("http://example.com:80"), "80");
    }

    void
    testDefaultPort()
    {
        BOOST_TEST_EQ(effective_port("http://example.com"), "80");
        BOOST_TEST_EQ(effective_port("https://example.com"), "443");
        BOOST_TEST_EQ(effective_port("socks5://example.com"), "1080");
        BOOST_TEST_EQ(effective_port("socks5h://example.com"), "1080");
    }

    void
    testUnknownScheme()
    {
        BOOST_TEST_EQ(effective_port("ftp://example.com"), "");
        BOOST_TEST_EQ(effective_port("ws://example.com"), "");
    }

    void
    run()
    {
        testExplicitPort();
        testDefaultPort();
        testUnknownScheme();
    }
};

TEST_SUITE(effective_port_test, "boost.burl.detail.effective_port");

} // namespace detail
} // namespace burl
} // namespace boost
