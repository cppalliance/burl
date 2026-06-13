//
// Copyright (c) 2026 Mohammad Nejati
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

// Test that header file is self-contained.
#include "src/detail/base64.hpp"

#include "test_suite.hpp"

#include <string>
#include <string_view>

namespace boost
{
namespace burl
{
namespace detail
{

class base64_test
{
    static std::string
    encode(std::string_view src)
    {
        std::string dest;
        base64_encode(dest, src);
        return dest;
    }

public:
    void
    testVectors()
    {
        // RFC 4648 test vectors
        BOOST_TEST_EQ(encode(""), "");
        BOOST_TEST_EQ(encode("f"), "Zg==");
        BOOST_TEST_EQ(encode("fo"), "Zm8=");
        BOOST_TEST_EQ(encode("foo"), "Zm9v");
        BOOST_TEST_EQ(encode("foob"), "Zm9vYg==");
        BOOST_TEST_EQ(encode("fooba"), "Zm9vYmE=");
        BOOST_TEST_EQ(encode("foobar"), "Zm9vYmFy");
    }

    void
    testAlphabet()
    {
        // exercises the '+' (index 62) and '/' (index 63) characters
        BOOST_TEST_EQ(encode(std::string_view("\xFB\xFF\xFF", 3)), "+///");
        BOOST_TEST_EQ(encode(std::string_view("\xFF\xFF\xFF", 3)), "////");
    }

    void
    testAppends()
    {
        // The encoding is appended to the destination.
        std::string dest = "Basic ";
        base64_encode(dest, "user:pass");
        BOOST_TEST_EQ(dest, "Basic dXNlcjpwYXNz");
    }

    void
    run()
    {
        testVectors();
        testAlphabet();
        testAppends();
    }
};

TEST_SUITE(base64_test, "boost.burl.detail.base64");

} // namespace detail
} // namespace burl
} // namespace boost
