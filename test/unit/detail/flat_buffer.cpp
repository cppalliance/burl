//
// Copyright (c) 2026 Mohammad Nejati
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

// Test that header file is self-contained.
#include <boost/burl/detail/flat_buffer.hpp>

#include <boost/capy/buffers/buffer_copy.hpp>
#include <boost/capy/buffers/make_buffer.hpp>

#include <string>
#include <string_view>
#include <utility>

#include "test_suite.hpp"

namespace boost
{
namespace burl
{
namespace detail
{

class flat_buffer_test
{
    static
    std::string
    str(capy::const_buffer b)
    {
        return { static_cast<char const*>(b.data()), b.size() };
    }

    // Writes through prepare/commit, like a stream read would.
    static
    void
    put(flat_buffer& fb, std::string_view s)
    {
        auto const n = capy::buffer_copy(
            fb.prepare(), capy::make_buffer(s.data(), s.size()));
        BOOST_TEST_EQ(n, s.size());
        fb.commit(n);
    }

public:
    void
    testEmpty()
    {
        char store[8];
        flat_buffer fb{ store, sizeof(store) };

        BOOST_TEST(fb.empty());
        BOOST_TEST_EQ(fb.size(), 0);
        BOOST_TEST_EQ(fb.capacity(), sizeof(store));
        BOOST_TEST(str(fb.data()).empty());

        // an empty run still reports its base, which is what a
        // caller writing below the read cursor needs
        BOOST_TEST_EQ(fb.data().data(), store);
        BOOST_TEST_EQ(fb.prepare().data(), store);
        BOOST_TEST_EQ(fb.prepare().size(), sizeof(store));
    }

    void
    testFillAndDrain()
    {
        char store[8];
        flat_buffer fb{ store, sizeof(store) };

        put(fb, "abcd");
        BOOST_TEST(!fb.empty());
        BOOST_TEST_EQ(fb.size(), 4);
        BOOST_TEST_EQ(fb.capacity(), 4);
        BOOST_TEST_EQ(str(fb.data()), "abcd");

        fb.consume(1);
        BOOST_TEST_EQ(str(fb.data()), "bcd");
        BOOST_TEST_EQ(fb.pos, 1);

        fb.consume(3);
        BOOST_TEST(fb.empty());
        BOOST_TEST_EQ(fb.pos, 0);   // rewound
        BOOST_TEST_EQ(fb.capacity(), sizeof(store));
    }

    void
    testNoCompaction()
    {
        // Consumed octets are not reclaimed until the rewind:
        // capacity shrinks while the run is alive, so the space
        // below the read cursor stays where the caller left it.
        char store[8];
        flat_buffer fb{ store, sizeof(store) };

        put(fb, "abcdef");
        fb.consume(4);
        BOOST_TEST_EQ(fb.size(), 2);
        BOOST_TEST_EQ(fb.capacity(), 2);        // not 6
        BOOST_TEST_EQ(fb.data().data(), store + 4);
        BOOST_TEST_EQ(fb.prepare().data(), store + 6);

        // the four consumed octets are still addressable below
        // the cursor, and still hold what was written
        BOOST_TEST_EQ(
            std::string(store, 4), "abcd");

        put(fb, "gh");
        BOOST_TEST_EQ(str(fb.data()), "efgh");
        BOOST_TEST_EQ(fb.capacity(), 0);

        fb.consume(4);
        BOOST_TEST_EQ(fb.capacity(), sizeof(store));
    }

    void
    testPartialCommit()
    {
        char store[4];
        flat_buffer fb{ store, sizeof(store) };

        auto const n = capy::buffer_copy(
            fb.prepare(), capy::make_buffer("abcdef", 6));
        BOOST_TEST_EQ(n, 4);   // capped by capacity
        fb.commit(n);
        BOOST_TEST_EQ(str(fb.data()), "abcd");
        BOOST_TEST_EQ(fb.capacity(), 0);
        BOOST_TEST_EQ(fb.prepare().size(), 0);
    }

    void
    testClear()
    {
        char store[8];
        flat_buffer fb{ store, sizeof(store) };

        put(fb, "abcd");
        fb.consume(2);

        // the region survives, the contents do not
        fb.clear();
        BOOST_TEST(fb.empty());
        BOOST_TEST_EQ(fb.pos, 0);
        BOOST_TEST_EQ(fb.capacity(), sizeof(store));
        BOOST_TEST_EQ(fb.data().data(), store);
    }

    void
    testSwap()
    {
        // Two regions exchanging roles keep their own storage,
        // which is how a caller can tell them apart afterwards.
        char a[8];
        char b[4];
        flat_buffer x{ a, sizeof(a) };
        flat_buffer y{ b, sizeof(b) };

        put(x, "abcd");
        std::swap(x, y);

        BOOST_TEST_EQ(x.ptr, b);
        BOOST_TEST_EQ(x.cap, sizeof(b));
        BOOST_TEST(x.empty());
        BOOST_TEST_EQ(str(y.data()), "abcd");
    }

    void
    run()
    {
        testEmpty();
        testFillAndDrain();
        testNoCompaction();
        testPartialCommit();
        testClear();
        testSwap();
    }
};

TEST_SUITE(
    flat_buffer_test,
    "boost.burl.detail.flat_buffer");

} // namespace detail
} // namespace burl
} // namespace boost
