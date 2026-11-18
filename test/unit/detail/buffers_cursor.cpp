//
// Copyright (c) 2026 Mohammad Nejati
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

// Test that header file is self-contained.
#include <boost/burl/detail/buffers_cursor.hpp>

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
    buffers_cursor<std::array<capy::mutable_buffer, 2>>>);
static_assert(capy::ConstBufferSequence<
    buffers_cursor<std::array<capy::const_buffer, 2>>>);
static_assert(! capy::MutableBufferSequence<
    buffers_cursor<std::array<capy::const_buffer, 2>>>);
static_assert(capy::MutableBufferSequence<
    buffers_cursor<capy::mutable_buffer>>);
static_assert(std::bidirectional_iterator<
    buffers_cursor<std::vector<capy::const_buffer>>::const_iterator>);

class buffers_cursor_test
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

public:
    void
    testWhole()
    {
        std::array<capy::const_buffer, 3> const a{
            at(0, 3), at(3, 3), at(6, 4) };
        buffers_cursor const c(a);
        BOOST_TEST_EQ(str(c), "abcdefghij");
        BOOST_TEST_EQ(rstr(c), "abcdefghij");
        BOOST_TEST_EQ(capy::buffer_size(c), 10);
        BOOST_TEST_EQ(std::distance(c.begin(), c.end()), 3);
    }

    void
    testConsume()
    {
        std::array<capy::const_buffer, 3> const a{
            at(0, 3), at(3, 3), at(6, 4) };
        buffers_cursor c(a);

        // inside the first buffer
        c.consume(1);
        BOOST_TEST_EQ(str(c), "bcdefghij");
        BOOST_TEST_EQ(rstr(c), "bcdefghij");
        BOOST_TEST_EQ(std::distance(c.begin(), c.end()), 3);

        // up to a boundary: the spent buffer is gone
        c.consume(2);
        BOOST_TEST_EQ(str(c), "defghij");
        BOOST_TEST_EQ(std::distance(c.begin(), c.end()), 2);

        // across a boundary
        c.consume(4);
        BOOST_TEST_EQ(str(c), "hij");
        BOOST_TEST_EQ(rstr(c), "hij");
        BOOST_TEST_EQ(capy::buffer_size(c), 3);

        c.consume(0);
        BOOST_TEST_EQ(str(c), "hij");

        // past the end
        c.consume(100);
        BOOST_TEST_EQ(str(c), "");
        BOOST_TEST_EQ(capy::buffer_size(c), 0);
        BOOST_TEST(c.begin() == c.end());

        c.consume(1);
        BOOST_TEST(c.begin() == c.end());
    }

    void
    testEmptyBuffers()
    {
        std::array<capy::const_buffer, 4> const a{
            at(0, 0), at(0, 2), at(2, 0), at(2, 3) };
        buffers_cursor c(a);
        BOOST_TEST_EQ(str(c), "abcde");

        c.consume(2);
        BOOST_TEST_EQ(str(c), "cde");
        c.consume(3);
        BOOST_TEST_EQ(capy::buffer_size(c), 0);

        std::vector<capy::const_buffer> const v;
        buffers_cursor c2(v);
        BOOST_TEST(c2.begin() == c2.end());
        c2.consume(1);
        BOOST_TEST(c2.begin() == c2.end());
    }

    void
    testSingleBuffer()
    {
        auto const b = at(0, 5);
        buffers_cursor c(b);
        BOOST_TEST_EQ(str(c), "abcde");
        c.consume(3);
        BOOST_TEST_EQ(str(c), "de");
        BOOST_TEST_EQ(rstr(c), "de");
        c.consume(2);
        BOOST_TEST(c.begin() == c.end());
    }

    void
    testMutable()
    {
        char buf[6] = {};
        std::array<capy::mutable_buffer, 2> const a{
            capy::mutable_buffer(buf, 3),
            capy::mutable_buffer(buf + 3, 3) };
        buffers_cursor c(a);
        c.consume(4);
        capy::mutable_buffer const b = *c.begin();
        BOOST_TEST(b.data() == buf + 4);
        BOOST_TEST_EQ(b.size(), 2);
    }

    void
    testPrefix()
    {
        // what message_reader does for a direct read
        std::array<capy::const_buffer, 3> const a{
            at(0, 3), at(3, 3), at(6, 4) };
        buffers_cursor c(a);
        c.consume(4);
        BOOST_TEST_EQ(str(buffers_prefix(c, 10)), "efghij");
        BOOST_TEST_EQ(rstr(buffers_prefix(c, 10)), "efghij");
        BOOST_TEST_EQ(str(buffers_prefix(c, 3)), "efg");
        BOOST_TEST_EQ(rstr(buffers_prefix(c, 3)), "efg");
    }

    void
    run()
    {
        testWhole();
        testConsume();
        testEmptyBuffers();
        testSingleBuffer();
        testMutable();
        testPrefix();
    }
};

TEST_SUITE(
    buffers_cursor_test,
    "boost.burl.detail.buffers_cursor");

} // namespace detail
} // namespace burl
} // namespace boost
