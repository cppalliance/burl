//
// Copyright (c) 2026 Mohammad Nejati
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

// Test that header file is self-contained.
#include <boost/burl/detail/buffers_prefix.hpp>

#include <boost/capy/buffers.hpp>

#include <array>
#include <cstddef>
#include <iterator>
#include <string>
#include <vector>

#include "test_suite.hpp"

namespace boost
{
namespace burl
{
namespace detail
{

static_assert(capy::MutableBufferSequence<
    buffers_prefix<std::array<capy::mutable_buffer, 2>>>);
static_assert(capy::ConstBufferSequence<
    buffers_prefix<std::array<capy::const_buffer, 2>>>);
static_assert(! capy::MutableBufferSequence<
    buffers_prefix<std::array<capy::const_buffer, 2>>>);
static_assert(capy::MutableBufferSequence<
    buffers_prefix<capy::mutable_buffer>>);
static_assert(std::bidirectional_iterator<
    buffers_prefix<std::vector<capy::const_buffer>>::const_iterator>);

class buffers_prefix_test
{
    char const* const text_ = "abcdefghij";

    capy::const_buffer
    at(
        std::size_t pos,
        std::size_t n) const noexcept
    {
        return { text_ + pos, n };
    }

    // The bytes a sequence yields, in order.
    template<class BS>
    static
    std::string
    str(BS const& bs)
    {
        std::string s;
        for(capy::const_buffer b : bs)
            s.append(static_cast<char const*>(b.data()), b.size());
        return s;
    }

    // The same, walking backwards from the end.
    template<class BS>
    static
    std::string
    rstr(BS const& bs)
    {
        std::string s;
        auto it = bs.end();
        while(it != bs.begin())
        {
            capy::const_buffer const b = *--it;
            s.insert(0, static_cast<char const*>(b.data()), b.size());
        }
        return s;
    }

    template<class BS>
    static
    std::size_t
    count(BS const& bs)
    {
        return std::size_t(std::distance(bs.begin(), bs.end()));
    }

public:
    void
    testWhole()
    {
        std::array<capy::const_buffer, 3> const a{
            at(0, 3), at(3, 3), at(6, 4) };

        // as many bytes as the sequence holds, and more
        for(std::size_t n : { std::size_t(10), std::size_t(11),
            std::size_t(-1) })
        {
            buffers_prefix const p(a, n);
            BOOST_TEST_EQ(count(p), 3);
            BOOST_TEST_EQ(str(p), "abcdefghij");
            BOOST_TEST_EQ(rstr(p), "abcdefghij");
        }
    }

    void
    testCut()
    {
        std::array<capy::const_buffer, 3> const a{
            at(0, 3), at(3, 3), at(6, 4) };

        // every length, inside a buffer and on a boundary
        for(std::size_t n = 0; n <= 10; ++n)
        {
            buffers_prefix const p(a, n);
            BOOST_TEST_EQ(str(p), std::string(text_, n));
            BOOST_TEST_EQ(rstr(p), std::string(text_, n));
            BOOST_TEST_EQ(capy::buffer_size(p), n);
        }

        {
            // ends inside a buffer: that buffer is shortened
            buffers_prefix const p(a, 5);
            BOOST_TEST_EQ(count(p), 2);
            capy::const_buffer const b = *std::next(p.begin());
            BOOST_TEST(b.data() == text_ + 3);
            BOOST_TEST_EQ(b.size(), 2);
        }
        {
            // ends on a boundary: no empty tail
            buffers_prefix const p(a, 6);
            BOOST_TEST_EQ(count(p), 2);
        }
        {
            buffers_prefix const p(a, 0);
            BOOST_TEST(p.begin() == p.end());
        }

        // the sequence is left as it was
        BOOST_TEST_EQ(str(a), "abcdefghij");
    }

    void
    testEmpty()
    {
        {
            std::vector<capy::const_buffer> const v;
            buffers_prefix const p(v, 5);
            BOOST_TEST(p.begin() == p.end());
        }
        {
            // only empty buffers
            std::array<capy::const_buffer, 2> const a{
                at(0, 0), at(1, 0) };
            buffers_prefix const p(a, 5);
            BOOST_TEST_EQ(capy::buffer_size(p), 0);
        }
    }

    void
    testEmptyBuffers()
    {
        // empty buffers take none of the bytes
        std::array<capy::const_buffer, 5> const a{
            at(0, 0), at(0, 4), at(4, 0), at(4, 2), at(6, 0) };
        {
            buffers_prefix const p(a, 5);
            BOOST_TEST_EQ(str(p), "abcde");
            BOOST_TEST_EQ(rstr(p), "abcde");
        }
        {
            buffers_prefix const p(a, 4);
            BOOST_TEST_EQ(str(p), "abcd");
            BOOST_TEST_EQ(rstr(p), "abcd");
        }
        {
            buffers_prefix const p(a, 100);
            BOOST_TEST_EQ(str(p), "abcdef");
        }
    }

    void
    testSingleBuffer()
    {
        auto const b = at(0, 5);
        {
            buffers_prefix const p(b, 3);
            BOOST_TEST_EQ(count(p), 1);
            BOOST_TEST_EQ(str(p), "abc");
            BOOST_TEST_EQ(rstr(p), "abc");
        }
        {
            buffers_prefix const p(b, 9);
            BOOST_TEST_EQ(str(p), "abcde");
        }
        {
            buffers_prefix const p(b, 0);
            BOOST_TEST(p.begin() == p.end());
        }
    }

    void
    testMutable()
    {
        char buf[6] = {};
        std::array<capy::mutable_buffer, 2> const a{
            capy::mutable_buffer(buf, 3),
            capy::mutable_buffer(buf + 3, 3) };
        buffers_prefix const p(a, 4);
        capy::mutable_buffer const b = *std::next(p.begin());
        BOOST_TEST(b.data() == buf + 3);
        BOOST_TEST_EQ(b.size(), 1);
    }

    void
    run()
    {
        testWhole();
        testCut();
        testEmpty();
        testEmptyBuffers();
        testSingleBuffer();
        testMutable();
    }
};

TEST_SUITE(
    buffers_prefix_test,
    "boost.burl.detail.buffers_prefix");

} // namespace detail
} // namespace burl
} // namespace boost
