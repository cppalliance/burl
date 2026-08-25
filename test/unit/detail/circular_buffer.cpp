//
// Copyright (c) 2026 Mohammad Nejati
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

// Test that header file is self-contained.
#include <boost/burl/detail/circular_buffer.hpp>

#include <boost/capy/buffers/buffer_copy.hpp>
#include <boost/capy/buffers/make_buffer.hpp>

#include <string>
#include <string_view>

#include "test_suite.hpp"

namespace boost
{
namespace burl
{
namespace detail
{

class circular_buffer_test
{
    static
    std::string
    str(std::array<capy::const_buffer, 2> const& bufs)
    {
        std::string s;
        for(auto b : bufs)
            s.append(static_cast<char const*>(b.data()), b.size());
        return s;
    }

    static
    std::string
    str(capy::const_buffer b)
    {
        return { static_cast<char const*>(b.data()), b.size() };
    }

    // Writes through prepare/commit, like a stream read would.
    static
    void
    put(circular_buffer& cb, std::string_view s)
    {
        auto const n = capy::buffer_copy(
            cb.prepare(), capy::make_buffer(s.data(), s.size()));
        BOOST_TEST_EQ(n, s.size());
        cb.commit(n);
    }

public:
    void
    testEmpty()
    {
        char store[8];
        circular_buffer cb{ store, sizeof(store) };

        BOOST_TEST(cb.empty());
        BOOST_TEST(!cb.full());
        BOOST_TEST(!cb.wrapped());
        BOOST_TEST_EQ(cb.size(), 0);
        BOOST_TEST(str(cb.data()).empty());
        BOOST_TEST_EQ(cb.first(5).size(), 0);

        auto const pb = cb.prepare();
        BOOST_TEST_EQ(pb[0].size(), sizeof(store));
        BOOST_TEST_EQ(pb[1].size(), 0);
    }

    void
    testFillAndDrain()
    {
        char store[8];
        circular_buffer cb{ store, sizeof(store) };

        put(cb, "hello");
        BOOST_TEST(!cb.empty());
        BOOST_TEST_EQ(cb.size(), 5);
        BOOST_TEST(str(cb.data()) == "hello");

        // first clamps to the smaller of n and what is contiguous
        BOOST_TEST(str(cb.first(3)) == "hel");
        BOOST_TEST(str(cb.first(100)) == "hello");

        cb.consume(2);
        BOOST_TEST(str(cb.data()) == "llo");

        // over-commit saturates at capacity
        cb.commit(100);
        BOOST_TEST(cb.full());
        BOOST_TEST_EQ(cb.size(), sizeof(store));

        // over-consume saturates at empty
        cb.consume(100);
        BOOST_TEST(cb.empty());
        BOOST_TEST_EQ(cb.size(), 0);
    }

    void
    testWrapAround()
    {
        char store[8];
        circular_buffer cb{ store, sizeof(store) };

        put(cb, "abcdefgh");
        BOOST_TEST(cb.full());
        cb.consume(6);

        // the free region is contiguous at the front
        put(cb, "XYZ");
        BOOST_TEST(cb.wrapped());
        BOOST_TEST_EQ(cb.size(), 5);
        BOOST_TEST(str(cb.data()) == "ghXYZ");

        // first serves only the tail segment of a wrapped buffer
        BOOST_TEST(str(cb.first(100)) == "gh");
        BOOST_TEST(str(cb.first(1)) == "g");

        // consuming past the end wraps the read position
        cb.consume(4);
        BOOST_TEST(!cb.wrapped());
        BOOST_TEST(str(cb.data()) == "Z");
        cb.consume(1);
        BOOST_TEST(cb.empty());
    }

    void
    testPrepare()
    {
        char store[8];
        circular_buffer cb{ store, sizeof(store) };

        // prepare_one is always the first prepare region
        auto check = [&](
            std::size_t off, std::size_t n0, std::size_t n1)
        {
            auto const pb = cb.prepare();
            BOOST_TEST_EQ(pb[0].data(), store + off);
            BOOST_TEST_EQ(pb[0].size(), n0);
            BOOST_TEST_EQ(pb[1].size(), n1);
            if(n1 != 0)
                BOOST_TEST_EQ(pb[1].data(), store);
            auto const mb = cb.prepare_one();
            BOOST_TEST_EQ(mb.data(), pb[0].data());
            BOOST_TEST_EQ(mb.size(), pb[0].size());
        };

        // empty: the whole store, in one region
        check(0, 8, 0);

        // contents at the front: the free region is
        // the contiguous tail
        put(cb, "abcde");
        check(5, 3, 0);

        // contents in the middle: the free region is split
        // around the end of the store
        cb.consume(2);
        check(5, 3, 2);

        // the write position lands exactly on the end:
        // the free region is contiguous at the front
        put(cb, "fgh");
        BOOST_TEST(!cb.wrapped());
        check(0, 2, 0);

        // wrapped contents: the free region is contiguous
        // between the write and read positions
        put(cb, "X");
        BOOST_TEST(cb.wrapped());
        check(1, 1, 0);

        // full: nothing to prepare
        put(cb, "Y");
        BOOST_TEST(cb.full());
        check(2, 0, 0);
        BOOST_TEST_EQ(cb.prepare_one().size(), 0);
        BOOST_TEST(str(cb.data()) == "cdefghXY");
    }

    void
    testReset()
    {
        char store[8];
        circular_buffer cb{ store, sizeof(store) };
        put(cb, "abcdefgh");

        // rebasing to an interior pointer discards the contents
        // and shrinks the capacity to what lies above it
        cb.reset(store + 2);
        BOOST_TEST(cb.empty());
        BOOST_TEST_EQ(cb.ptr, store + 2);
        BOOST_TEST_EQ(cb.cap, sizeof(store) - 2);

        put(cb, "XYZ");
        BOOST_TEST(str(cb.data()) == "XYZ");
    }

    void
    testShedAndSlide()
    {
        char store[8];
        circular_buffer cb{ store, sizeof(store) };
        put(cb, "hello");

        // shed gives up the leading octets and the region they
        // occupy
        cb.shed(2);
        BOOST_TEST_EQ(cb.ptr, store + 2);
        BOOST_TEST_EQ(cb.cap, sizeof(store) - 2);
        BOOST_TEST(str(cb.data()) == "llo");

        // slide moves the contents down and reclaims the region
        cb.slide(store);
        BOOST_TEST_EQ(cb.ptr, store);
        BOOST_TEST_EQ(cb.cap, sizeof(store));
        BOOST_TEST(str(cb.data()) == "llo");
    }

    void
    testLinearizeEmpty()
    {
        char store[8];
        circular_buffer cb{ store + 4, 4 };

        // an empty buffer rebases to the floor and reclaims the
        // whole region
        auto* p = cb.linearize(store);
        BOOST_TEST_EQ(p, store);
        BOOST_TEST_EQ(cb.ptr, store);
        BOOST_TEST_EQ(cb.cap, sizeof(store));
        BOOST_TEST(cb.empty());
    }

    void
    testLinearizeStraight()
    {
        char store[8];
        circular_buffer cb{ store, sizeof(store) };
        put(cb, "abcde");
        cb.consume(2);

        // contiguous contents stay put: only the base moves up
        // to them
        auto* p = cb.linearize(store);
        BOOST_TEST_EQ(p, store + 2);
        BOOST_TEST_EQ(cb.ptr, store + 2);
        BOOST_TEST_EQ(cb.cap, sizeof(store) - 2);
        BOOST_TEST_EQ(cb.pos, 0);
        BOOST_TEST(str(cb.data()) == "cde");
    }

    void
    testLinearizeWrapped()
    {
        char store[8];
        circular_buffer cb{ store, sizeof(store) };
        put(cb, "abcdefgh");
        cb.consume(6);
        put(cb, "XYZ");
        BOOST_TEST(cb.wrapped());

        // wrapped contents are rotated down to the floor
        auto* p = cb.linearize(store);
        BOOST_TEST_EQ(p, store);
        BOOST_TEST_EQ(cb.ptr, store);
        BOOST_TEST_EQ(cb.cap, sizeof(store));
        BOOST_TEST_EQ(cb.pos, 0);
        BOOST_TEST(!cb.wrapped());
        BOOST_TEST(str(cb.data()) == "ghXYZ");
        BOOST_TEST(str(cb.first(100)) == "ghXYZ");
    }

    void
    testLinearizeWrappedOverlap()
    {
        // the two segments overlap both source and destination;
        // the rotation has to proceed in more than one step
        char store[8];
        circular_buffer cb{ store, sizeof(store) };
        put(cb, "abcdefgh");
        cb.consume(5);
        put(cb, "XYZ");
        BOOST_TEST(cb.wrapped());
        BOOST_TEST_EQ(cb.size(), 6);

        auto* p = cb.linearize(store);
        BOOST_TEST_EQ(p, store);
        BOOST_TEST(str(cb.data()) == "fghXYZ");
    }

    void
    testLinearizeWrappedLongFront()
    {
        // the wrapped-around segment is longer than the tail one
        char store[8];
        circular_buffer cb{ store, sizeof(store) };
        put(cb, "abcdefgh");
        cb.consume(7);
        put(cb, "UVWXY");
        BOOST_TEST(cb.wrapped());
        BOOST_TEST_EQ(cb.size(), 6);

        auto* p = cb.linearize(store);
        BOOST_TEST_EQ(p, store);
        BOOST_TEST(str(cb.data()) == "hUVWXY");
    }

    void
    testLinearizeWrappedBelowBase()
    {
        // room below the buffer: the rotation lands at the floor
        // and the capacity grows by the reclaimed region
        char store[12];
        circular_buffer cb{ store + 4, 8 };
        put(cb, "abcdefgh");
        cb.consume(6);
        put(cb, "XYZ");
        BOOST_TEST(cb.wrapped());

        auto* p = cb.linearize(store);
        BOOST_TEST_EQ(p, store);
        BOOST_TEST_EQ(cb.ptr, store);
        BOOST_TEST_EQ(cb.cap, sizeof(store));
        BOOST_TEST(str(cb.data()) == "ghXYZ");
    }

    void
    testLinearizeFullWrapped()
    {
        // full and wrapped with no room below: the segments
        // cannot leapfrog and the contents rotate in place
        char store[8];
        circular_buffer cb{ store, sizeof(store) };
        put(cb, "abcdefgh");
        cb.consume(3);
        put(cb, "XYZ");
        BOOST_TEST(cb.full());
        BOOST_TEST(cb.wrapped());

        auto* p = cb.linearize(store);
        BOOST_TEST_EQ(p, store);
        BOOST_TEST_EQ(cb.ptr, store);
        BOOST_TEST_EQ(cb.cap, sizeof(store));
        BOOST_TEST_EQ(cb.pos, 0);
        BOOST_TEST(cb.full());
        BOOST_TEST(!cb.wrapped());
        BOOST_TEST(str(cb.data()) == "defghXYZ");
    }

    void
    testLinearizeFullWrappedBelowBase()
    {
        // full and wrapped with room below: the leapfrog lands
        // at the floor and the capacity grows
        char store[12];
        circular_buffer cb{ store + 4, 8 };
        put(cb, "abcdefgh");
        cb.consume(3);
        put(cb, "XYZ");
        BOOST_TEST(cb.full());
        BOOST_TEST(cb.wrapped());

        auto* p = cb.linearize(store);
        BOOST_TEST_EQ(p, store);
        BOOST_TEST_EQ(cb.ptr, store);
        BOOST_TEST_EQ(cb.cap, sizeof(store));
        BOOST_TEST_EQ(cb.pos, 0);
        BOOST_TEST(str(cb.data()) == "defghXYZ");
    }

    void
    testLinearizeWrappedManyRounds()
    {
        // the gap is too small for the leapfrog: the contents
        // rotate in place instead, and the room below the
        // buffer stays unreclaimed
        char store[21];
        circular_buffer cb{ store + 1, 20 };
        put(cb, "abcdefghijklmnopqrst");
        cb.consume(3);
        put(cb, "XYZ");
        BOOST_TEST(cb.full());
        BOOST_TEST(cb.wrapped());

        auto* p = cb.linearize(store);
        BOOST_TEST_EQ(p, store + 1);
        BOOST_TEST_EQ(cb.ptr, store + 1);
        BOOST_TEST_EQ(cb.cap, 20);
        BOOST_TEST_EQ(cb.pos, 0);
        BOOST_TEST(!cb.wrapped());
        BOOST_TEST(str(cb.data()) == "defghijklmnopqrstXYZ");
    }

    void
    run()
    {
        testEmpty();
        testFillAndDrain();
        testWrapAround();
        testPrepare();
        testReset();
        testShedAndSlide();
        testLinearizeEmpty();
        testLinearizeStraight();
        testLinearizeWrapped();
        testLinearizeWrappedOverlap();
        testLinearizeWrappedLongFront();
        testLinearizeWrappedBelowBase();
        testLinearizeFullWrapped();
        testLinearizeFullWrappedBelowBase();
        testLinearizeWrappedManyRounds();
    }
};

TEST_SUITE(
    circular_buffer_test,
    "boost.burl.detail.circular_buffer");

} // namespace detail
} // namespace burl
} // namespace boost
