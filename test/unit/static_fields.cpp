//
// Copyright (c) 2026 Mohammad Nejati
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

// Test that header file is self-contained.
#include <boost/burl/static_fields.hpp>

#include <boost/burl/fields.hpp>
#include <boost/burl/request_head.hpp>

#include "test_suite.hpp"

#include <stdexcept>
#include <string>
#include <type_traits>
#include <utility>

namespace boost
{
namespace burl
{

// The container behavior shared with the owning
// container is covered by the fields tests, and the
// fixed-storage mechanics by the static_request_head
// tests. These tests cover the fields-specific surface.

static_assert(std::is_nothrow_move_constructible_v<static_fields>);
static_assert(! std::is_copy_constructible_v<static_fields>);

class static_fields_test
{
public:
    void
    testDefault()
    {
        alignas(4) char buf[64];
        static_fields f(buf, sizeof(buf));
        BOOST_TEST_EQ(f.buffer(), "\r\n");
        BOOST_TEST(f.empty());
        BOOST_TEST_EQ(f.capacity_in_bytes(), 64u);
        BOOST_TEST_EQ(f.buffer().data(), &buf[0]);
    }

    void
    testTooSmall()
    {
        alignas(4) char buf[8];
        // the storage must hold at least the empty
        // field section
        BOOST_TEST_THROWS(
            static_fields(buf, 1),
            std::length_error);
        // an exact fit leaves no free capacity
        static_fields f(buf + 2, 2);
        BOOST_TEST_EQ(f.buffer(), "\r\n");
        BOOST_TEST_EQ(f.capacity_in_bytes(), 2u);
        BOOST_TEST_THROWS(
            f.append("X", "*"),
            std::length_error);
    }

    void
    testFieldCapacity()
    {
        // the capacity is fixed: appends beyond it throw
        // and leave the contents unchanged
        alignas(4) char buf[64];
        static_fields f(buf, sizeof(buf));
        for(int i = 0; i < 3; ++i)
            f.append("T", "*");
        auto const before = std::string(f.buffer());
        BOOST_TEST_THROWS(
            f.append("T", "*"),
            std::length_error);
        BOOST_TEST_EQ(f.buffer(), before);
        // free space released by an erase is reusable
        f.erase(f.begin());
        f.append("T", "*");
        BOOST_TEST_EQ(f.buffer(), before);

        // a bulk append is all-or-nothing: when the
        // list does not fit, nothing is appended
        f.erase(f.begin());
        BOOST_TEST_THROWS(
            f.append({ { "T", "*" }, { "T", "*" } }),
            std::length_error);
        f.append({ { "T", "*" } });
        BOOST_TEST_EQ(f.buffer(), before);
    }

    void
    testCopyAssign()
    {
        fields src = {
            { http::field::host, "example.com" },
            { "T", "*" },
        };

        alignas(4) char buf[128];
        static_fields f(buf, sizeof(buf));
        f = src;
        BOOST_TEST_EQ(f.buffer(), src.buffer());
        BOOST_TEST(f.buffer().data() != src.buffer().data());
        BOOST_TEST(
            f.buffer().data() >= buf &&
            f.buffer().data() < buf + sizeof(buf));

        // assigning a default-constructed container
        // copies into the fixed storage instead of
        // adopting the shared read-only buffer
        f = fields();
        BOOST_TEST_EQ(f.buffer(), "\r\n");
        BOOST_TEST(
            f.buffer().data() >= buf &&
            f.buffer().data() < buf + sizeof(buf));
        f.append("T", "*");
        BOOST_TEST_EQ(f.buffer(), "T: *\r\n\r\n");

        // assigning a message header copies only the
        // field section; the start line is discarded
        request_head req;
        req.set(http::field::host, "example.com");
        f = req;
        BOOST_TEST_EQ(f.buffer(), "Host: example.com\r\n\r\n");

        // static to static
        alignas(4) char buf2[64];
        static_fields f2(buf2, sizeof(buf2));
        f2 = f;
        BOOST_TEST_EQ(f2.buffer(), f.buffer());
        BOOST_TEST(f2.buffer().data() != f.buffer().data());

        // self-assignment
        auto const& fr = f2;
        f2 = fr;
        BOOST_TEST_EQ(f2.buffer(), f.buffer());
    }

    void
    testCopyAssignOverflow()
    {
        // a copy that does not fit throws and leaves the
        // contents unchanged
        fields big;
        big.set("X", std::string(200, 'x'));

        alignas(4) char buf[32];
        static_fields f(buf, sizeof(buf));
        f.append("T", "*");
        BOOST_TEST_THROWS(f = big, std::length_error);
        BOOST_TEST_EQ(f.buffer(), "T: *\r\n\r\n");
    }

    void
    testMove()
    {
        alignas(4) char buf[64];
        static_fields f1(buf, sizeof(buf));
        f1.append("T", "*");
        auto const* p = f1.buffer().data();
        static_fields f2(std::move(f1));
        BOOST_TEST_EQ(f2.buffer(), "T: *\r\n\r\n");
        BOOST_TEST_EQ(f2.buffer().data(), p);
        BOOST_TEST_EQ(f2.capacity_in_bytes(), 64u);
        // the moved-from object no longer refers to the
        // storage; modifiers and assignment throw
        BOOST_TEST(f1.buffer().data() != p);
        BOOST_TEST_EQ(f1.buffer(), "\r\n");
        BOOST_TEST_EQ(f1.capacity_in_bytes(), 0u);
        BOOST_TEST_THROWS(
            f1.append("T", "*"),
            std::length_error);
        BOOST_TEST_THROWS(f1 = f2, std::length_error);
    }

    void
    run()
    {
        testDefault();
        testTooSmall();
        testFieldCapacity();
        testCopyAssign();
        testCopyAssignOverflow();
        testMove();
    }
};

TEST_SUITE(static_fields_test, "boost.burl.static_fields");

} // namespace burl
} // namespace boost
