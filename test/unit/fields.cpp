//
// Copyright (c) 2026 Mohammad Nejati
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

// Test that header file is self-contained.
#include <boost/burl/fields.hpp>

#include <boost/burl/request_head.hpp>

#include "test_suite.hpp"

#include <iterator>
#include <ranges>
#include <sstream>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <utility>

namespace boost
{
namespace burl
{

static_assert(std::is_nothrow_swappable_v<fields>);
static_assert(std::random_access_iterator<fields::iterator>);
static_assert(std::ranges::random_access_range<fields>);
static_assert(std::forward_iterator<fields::subrange::iterator>);
static_assert(std::ranges::forward_range<fields::subrange>);

class fields_test
{
public:
    void
    testDefault()
    {
        fields f;
        BOOST_TEST(f.empty());
        BOOST_TEST_EQ(f.size(), 0u);
        BOOST_TEST_EQ(f.buffer(), "\r\n");
        BOOST_TEST_EQ(f.capacity_in_bytes(), 0u);
        BOOST_TEST(f.begin() == f.end());
        BOOST_TEST(f.find(http::field::host) == f.end());
        BOOST_TEST(f.find("Host") == f.end());
        BOOST_TEST_EQ(f.count("Host"), 0u);
        BOOST_TEST_EQ(f.count(http::field::host), 0u);
        BOOST_TEST(!f.contains("Host"));
        BOOST_TEST(!f.contains(http::field::host));
        BOOST_TEST(f.find_all(http::field::host).empty());
        BOOST_TEST(f.find_all("Host").empty());
        BOOST_TEST_EQ(f.value_or(http::field::host, "?"), "?");

        // clear and shrink_to_fit on a default
        // container are no-ops
        f.clear();
        f.shrink_to_fit();
        BOOST_TEST_EQ(f.buffer(), "\r\n");
        BOOST_TEST_EQ(f.capacity_in_bytes(), 0u);

        // all default containers share the static buffer
        fields g;
        BOOST_TEST_EQ(
            static_cast<void const*>(f.buffer().data()),
            static_cast<void const*>(g.buffer().data()));

        // default subrange
        fields::subrange sr;
        BOOST_TEST(sr.empty());
        BOOST_TEST(sr.begin() == sr.end());
    }

    void
    testAppend()
    {
        fields f;
        f.append(http::field::host, "example.com");
        f.append("User-Agent", "burl");
        f.append("X-Custom", "1");
        f.append(http::field::accept, "");
        BOOST_TEST_EQ(f.size(), 4u);
        BOOST_TEST(!f.empty());
        BOOST_TEST_EQ(
            f.buffer(),
            "Host: example.com\r\n"
            "User-Agent: burl\r\n"
            "X-Custom: 1\r\n"
            "Accept: \r\n"
            "\r\n");

        BOOST_TEST_EQ(f.begin()[0].name, "Host");
        BOOST_TEST_EQ(f.begin()[0].value, "example.com");
        BOOST_TEST(f.begin()[0].id == http::field::host);

        // a known name inserted as a string resolves its id
        BOOST_TEST(f.begin()[1].id == http::field::user_agent);
        BOOST_TEST(f.find(http::field::user_agent) != f.end());

        BOOST_TEST_EQ(static_cast<std::uint8_t>(f.begin()[2].id), 0);
        BOOST_TEST_EQ(f.begin()[3].value, "");

        // lookups are case-insensitive
        BOOST_TEST(f.find("hOsT") != f.end());
        BOOST_TEST_EQ(f.find("x-custom")->value, "1");
        BOOST_TEST_EQ(f.value_or(http::field::host, "?"), "example.com");
        BOOST_TEST_EQ(f.value_or("USER-AGENT", "?"), "burl");
        BOOST_TEST_EQ(f.value_or("missing", "?"), "?");
        BOOST_TEST(f.contains("X-CUSTOM"));

        // verbatim storage of degenerate names
        fields g;
        g.append("", "v");
        BOOST_TEST_EQ(g.buffer(), ": v\r\n\r\n");
        BOOST_TEST_EQ(g.begin()[0].name, "");
        BOOST_TEST(g.find("") == g.begin());
    }

    void
    testAppendList()
    {
        fields f;
        f.append("X", "0");
        f.append({
            { http::field::host, "example.com" },
            { "User-Agent", "burl" },
            { "X-Custom", "1" },
        });
        BOOST_TEST_EQ(
            f.buffer(),
            "X: 0\r\n"
            "Host: example.com\r\n"
            "User-Agent: burl\r\n"
            "X-Custom: 1\r\n"
            "\r\n");
        BOOST_TEST(f.begin()[1].id == http::field::host);
        // a known name inserted as a string resolves its id
        BOOST_TEST(f.begin()[2].id == http::field::user_agent);

        // an empty list is a no-op; a default
        // container performs no allocation
        fields g;
        g.append({});
        BOOST_TEST_EQ(g.buffer(), "\r\n");
        BOOST_TEST_EQ(g.capacity_in_bytes(), 0u);

        // an oversized element leaves the container
        // unchanged, even when preceded by valid ones
        auto const before = std::string(f.buffer());
        BOOST_TEST_THROWS(
            f.append({
                { "T", "*" },
                { std::string(fields::max_name_size + 1, 'x'), "v" },
            }),
            std::length_error);
        BOOST_TEST_EQ(f.buffer(), before);
        BOOST_TEST_THROWS(
            f.append({
                { "T", "*" },
                { "V", std::string(fields::max_value_size + 1, 'x') },
            }),
            std::length_error);
        BOOST_TEST_EQ(f.buffer(), before);
    }

    void
    testFindFrom()
    {
        fields f = {
            { http::field::set_cookie, "a=1" },
            { http::field::content_type, "text/html" },
            { http::field::set_cookie, "b=2" },
            { "X-Dup", "x" },
            { "Y-Dup", "y" }, // same length, different name
            { "X-Dup", "z" },
        };

        auto it = f.find(http::field::set_cookie);
        BOOST_TEST_EQ(it->value, "a=1");
        it = f.find(std::next(it), http::field::set_cookie);
        BOOST_TEST_EQ(it->value, "b=2");
        it = f.find(std::next(it), http::field::set_cookie);
        BOOST_TEST(it == f.end());

        it = f.find("x-dup");
        BOOST_TEST_EQ(it->value, "x");
        it = f.find(std::next(it), "x-dup");
        BOOST_TEST_EQ(it->value, "z");

        BOOST_TEST_EQ(f.count(http::field::set_cookie), 2u);
        BOOST_TEST_EQ(f.count("SET-COOKIE"), 2u);
        BOOST_TEST_EQ(f.count("X-DUP"), 2u);
        BOOST_TEST_EQ(f.count("y-dup"), 1u);
        BOOST_TEST_EQ(f.count(http::field::host), 0u);
    }

    void
    testFindAll()
    {
        fields f = {
            { http::field::set_cookie, "a" },
            { http::field::content_type, "t" },
            { http::field::set_cookie, "b" },
            { "X-Tok", "1" },
            { http::field::range, "r" }, // known, same length as X-Tok
            { "Y-Tok", "no" },           // unknown, same length
            { "x-tok", "2" },            // case-variant duplicate
            { http::field::set_cookie, "c" },
        };

        std::string s;
        for(auto sv : f.find_all(http::field::set_cookie))
        {
            s.append(sv);
            s.push_back(';');
        }
        BOOST_TEST_EQ(s, "a;b;c;");

        // unknown names must skip known fields and
        // reject same-length unknown names
        s.clear();
        for(auto sv : f.find_all("X-Tok"))
        {
            s.append(sv);
            s.push_back(';');
        }
        BOOST_TEST_EQ(s, "1;2;");

        // find_all with a string of a known name
        s.clear();
        for(auto sv : f.find_all("set-cookie"))
        {
            s.append(sv);
            s.push_back(';');
        }
        BOOST_TEST_EQ(s, "a;b;c;");

        BOOST_TEST(f.find_all("nope").empty());
        BOOST_TEST(f.find_all(http::field::host).empty());
    }

    void
    testSet()
    {
        fields f = {
            { http::field::accept, "1" },
            { http::field::host, "a" },
            { http::field::accept, "2" },
            { http::field::accept, "3" },
        };

        // replaces the first in place, erases the rest
        f.set(http::field::accept, "final");
        BOOST_TEST_EQ(f.size(), 2u);
        BOOST_TEST_EQ(f.begin()[0].name, "Accept");
        BOOST_TEST_EQ(f.begin()[0].value, "final");
        BOOST_TEST_EQ(f.begin()[1].name, "Host");
        BOOST_TEST_EQ(f.buffer(), "Accept: final\r\nHost: a\r\n\r\n");

        // set on an absent field appends
        f.set(http::field::user_agent, "u");
        BOOST_TEST_EQ(f.size(), 3u);
        BOOST_TEST_EQ(f.begin()[2].name, "User-Agent");

        // by name, case-insensitive
        f.set("HOST", "b");
        BOOST_TEST_EQ(f.begin()[1].value, "b");
        BOOST_TEST_EQ(f.count(http::field::host), 1u);

        // longer, shorter, and equal-length replacement
        f.set(http::field::host, "muchlongervalue.example.com");
        BOOST_TEST_EQ(f.begin()[1].value, "muchlongervalue.example.com");
        BOOST_TEST_EQ(f.begin()[2].value, "u");
        f.set(http::field::host, "x");
        BOOST_TEST_EQ(f.begin()[1].value, "x");
        BOOST_TEST_EQ(f.begin()[2].value, "u");
        f.set(http::field::host, "y");
        BOOST_TEST_EQ(
            f.buffer(), "Accept: final\r\nHost: y\r\nUser-Agent: u\r\n\r\n");

        // set by unknown name replaces case-variant duplicates
        f.append("X-Trace", "1");
        f.append("x-trace", "2");
        f.set("X-TRACE", "3");
        BOOST_TEST_EQ(f.count("x-trace"), 1u);
        BOOST_TEST_EQ(f.find("X-Trace")->value, "3");
    }

    void
    testInsert()
    {
        fields f = {
            { http::field::host, "h" },
            { http::field::accept, "a" },
        };

        auto it = f.insert(f.begin(), http::field::user_agent, "u");
        BOOST_TEST(it == f.begin());
        BOOST_TEST_EQ(it->name, "User-Agent");

        it = f.insert(f.begin() + 2, "X-Mid", "m");
        BOOST_TEST_EQ((*it).value, "m");
        BOOST_TEST_EQ(
            f.buffer(),
            "User-Agent: u\r\nHost: h\r\nX-Mid: m\r\nAccept: a\r\n\r\n");

        it = f.insert(f.end(), "X-End", "e");
        BOOST_TEST_EQ(f.size(), 5u);
        BOOST_TEST_EQ(f.begin()[4].name, "X-End");
        BOOST_TEST(it == f.end() - 1);
    }

    void
    testErase()
    {
        fields f = {
            { http::field::accept, "1" },
            { http::field::host, "h" },
            { http::field::accept, "2" },
            { "X-A", "x" },
            { "x-a", "y" },
        };

        auto it = f.erase(f.begin());
        BOOST_TEST_EQ(it->name, "Host");
        BOOST_TEST_EQ(f.size(), 4u);

        BOOST_TEST_EQ(f.erase(http::field::accept), 1u);
        BOOST_TEST_EQ(f.erase("X-A"), 2u);
        BOOST_TEST_EQ(f.size(), 1u);
        BOOST_TEST_EQ(f.erase("missing"), 0u);
        BOOST_TEST_EQ(f.erase(http::field::accept), 0u);
        BOOST_TEST_EQ(f.buffer(), "Host: h\r\n\r\n");

        f.erase(f.begin());
        BOOST_TEST(f.empty());
        BOOST_TEST_EQ(f.buffer(), "\r\n");
        BOOST_TEST(f.capacity_in_bytes() > 0);
    }

    void
    testEraseAll()
    {
        // erase-all compacts in a single pass
        fields f = {
            { http::field::set_cookie, "a" },
            { http::field::host, "h" },
            { http::field::set_cookie, "bb" },
            { "X-K", "1" },
            { http::field::set_cookie, "ccc" },
        };
        BOOST_TEST_EQ(f.erase(http::field::set_cookie), 3u);
        BOOST_TEST_EQ(f.buffer(), "Host: h\r\nX-K: 1\r\n\r\n");
        BOOST_TEST_EQ(f.size(), 2u);
        BOOST_TEST(f.begin()[0].id == http::field::host);
        BOOST_TEST_EQ(f.begin()[1].name, "X-K");

        // unknown-name erase: case variants match, a
        // known name of equal length does not
        f.append("X-Del", "1");
        f.append(http::field::range, "r");
        f.append("x-del", "2");
        BOOST_TEST_EQ(f.erase("X-DEL"), 2u);
        BOOST_TEST_EQ(f.buffer(), "Host: h\r\nX-K: 1\r\nRange: r\r\n\r\n");

        // erasing every field leaves the empty section
        BOOST_TEST_EQ(f.erase("host"), 1u);
        BOOST_TEST_EQ(f.erase("x-k"), 1u);
        BOOST_TEST_EQ(f.erase(http::field::range), 1u);
        BOOST_TEST_EQ(f.buffer(), "\r\n");
        BOOST_TEST(f.empty());
    }

    // The fields which drive framing metadata in
    // message heads carry no semantics here: a plain
    // container stores and removes them like any
    // other field.
    void
    testSpecialFields()
    {
        fields f;
        f.set(http::field::connection, "close");
        f.append(http::field::content_length, "42");
        f.insert(
            f.begin(), http::field::transfer_encoding, "chunked");
        f.set(http::field::expect, "100-continue");
        f.append(http::field::upgrade, "h2c");
        BOOST_TEST_EQ(
            f.buffer(),
            "Transfer-Encoding: chunked\r\n"
            "Connection: close\r\n"
            "Content-Length: 42\r\n"
            "Expect: 100-continue\r\n"
            "Upgrade: h2c\r\n"
            "\r\n");
        BOOST_TEST_EQ(f.erase(http::field::transfer_encoding), 1u);
        BOOST_TEST_EQ(f.erase(http::field::content_length), 1u);
        BOOST_TEST_EQ(f.size(), 3u);
    }

    void
    testAt()
    {
        fields f = {
            { http::field::host, "h" },
            { "X-A", "1" },
        };
        BOOST_TEST_EQ(f.at(http::field::host), "h");
        BOOST_TEST_EQ(f.at("HOST"), "h");
        BOOST_TEST_EQ(f.at("x-a"), "1");
        BOOST_TEST_THROWS(f.at(http::field::age), std::out_of_range);
        BOOST_TEST_THROWS(f.at("missing"), std::out_of_range);
    }

    void
    testSetIterator()
    {
        fields f = {
            { http::field::host, "h" },
            { "X-A", "1" },
            { "X-A", "2" },
        };

        // only the addressed field changes; no dedup
        auto it = f.find(std::next(f.find("X-A")), "X-A");
        f.set(it, "two");
        BOOST_TEST_EQ(f.begin()[2].value, "two");
        BOOST_TEST_EQ(f.begin()[1].value, "1");
        BOOST_TEST_EQ(f.count("x-a"), 2u);

        // growing and shrinking a value in place
        f.reserve(128, 8);
        f.set(f.begin(), "a-considerably-longer-host-name");
        BOOST_TEST_EQ(f.begin()[0].value, "a-considerably-longer-host-name");
        BOOST_TEST_EQ(f.begin()[2].value, "two");
        f.set(f.begin(), "s");
        BOOST_TEST_EQ(f.begin()[0].value, "s");
        BOOST_TEST_EQ(f.buffer(), "Host: s\r\nX-A: 1\r\nX-A: two\r\n\r\n");
    }

    void
    testFindLast()
    {
        fields f = {
            { http::field::set_cookie, "a" },
            { "X-A", "1" },
            { http::field::set_cookie, "b" },
            { "x-a", "2" },
        };

        auto it = f.find_last(f.end(), http::field::set_cookie);
        BOOST_TEST_EQ(it->value, "b");
        it = f.find_last(it, http::field::set_cookie);
        BOOST_TEST_EQ(it->value, "a");
        BOOST_TEST(f.find_last(it, http::field::set_cookie) == f.end());

        it = f.find_last(f.end(), "X-A");
        BOOST_TEST_EQ(it->value, "2");
        it = f.find_last(it, "X-A");
        BOOST_TEST_EQ(it->value, "1");
        BOOST_TEST(f.find_last(it, "X-A") == f.end());

        BOOST_TEST(f.find_last(f.begin(), "x-a") == f.end());
        BOOST_TEST(f.find_last(f.end(), "nope") == f.end());
        BOOST_TEST(f.find_last(f.end(), http::field::host) == f.end());

        fields g;
        BOOST_TEST(g.find_last(g.end(), http::field::host) == g.end());
    }

    void
    testReverseIterators()
    {
        fields f = {
            { "A", "1" },
            { "B", "2" },
            { "C", "3" },
        };

        std::string s;
        for(auto it = f.rbegin(); it != f.rend(); ++it)
        {
            s.append((*it).name);
            s.push_back(';');
        }
        BOOST_TEST_EQ(s, "C;B;A;");
        BOOST_TEST_EQ(f.rend() - f.rbegin(), 3);
        BOOST_TEST_EQ((*(f.rbegin() + 2)).name, "A");

        fields g;
        BOOST_TEST(g.rbegin() == g.rend());
    }

    void
    testCopyMove()
    {
        fields a = {
            { http::field::host, "h" },
            { "X-C", "c" },
        };

        fields b(a);
        BOOST_TEST_EQ(b.buffer(), a.buffer());
        BOOST_TEST(b.buffer().data() != a.buffer().data());

        fields c(std::move(a));
        BOOST_TEST_EQ(c.buffer(), b.buffer());

        // moved-from equals a default-constructed container
        BOOST_TEST(a.empty());
        BOOST_TEST_EQ(a.buffer(), "\r\n");
        BOOST_TEST_EQ(a.capacity_in_bytes(), 0u);
        a.append(http::field::accept, "r");
        BOOST_TEST_EQ(a.size(), 1u);

        fields d;
        d = b;
        BOOST_TEST_EQ(d.buffer(), b.buffer());
        d = fields();
        BOOST_TEST(d.empty());
        BOOST_TEST_EQ(d.capacity_in_bytes(), 0u);

        // copying an empty container allocates nothing
        fields e(d);
        BOOST_TEST_EQ(e.capacity_in_bytes(), 0u);

        // self-assignment
        auto& br = b;
        b        = br;
        BOOST_TEST_EQ(b.size(), 2u);
        b = std::move(br);
        BOOST_TEST_EQ(b.size(), 2u);

        // assigning empty over non-empty keeps capacity
        fields g = { { "A", "1" } };
        auto const cap = g.capacity_in_bytes();
        g              = d;
        BOOST_TEST(g.empty());
        BOOST_TEST_EQ(g.buffer(), "\r\n");
        BOOST_TEST_EQ(g.capacity_in_bytes(), cap);

        // assigning into sufficient capacity reuses it
        fields h;
        h.reserve(256, 8);
        auto const* p = h.buffer().data();
        h             = b;
        BOOST_TEST_EQ(h.buffer(), b.buffer());
        BOOST_TEST_EQ(
            static_cast<void const*>(h.buffer().data()),
            static_cast<void const*>(p));

        // an empty source which still owns storage behaves
        // like an empty value: an owning target keeps its
        // capacity, a default target acquires storage for
        // the empty field section
        fields src = { { "A", "1" } };
        src.clear();
        fields k;
        k = src;
        BOOST_TEST(k.empty());
        BOOST_TEST_EQ(k.buffer(), "\r\n");
        BOOST_TEST(k.capacity_in_bytes() > 0);
        fields m = { { "B", "2" }, { "C", "3" } };
        auto const mcap = m.capacity_in_bytes();
        m = src;
        BOOST_TEST(m.empty());
        BOOST_TEST_EQ(m.buffer(), "\r\n");
        BOOST_TEST_EQ(m.capacity_in_bytes(), mcap);
    }

    void
    testSwap()
    {
        {
            fields a = { { http::field::host, "a" } };
            fields b = {
                { http::field::host, "b" },
                { "X-C", "c" },
            };
            auto const acap = a.capacity_in_bytes();
            auto const bcap = b.capacity_in_bytes();
            // a view follows the contents into the
            // other container
            auto const av = a.begin()[0].value;

            a.swap(b);
            BOOST_TEST_EQ(a.size(), 2u);
            BOOST_TEST_EQ(a.buffer(),
                "Host: b\r\n"
                "X-C: c\r\n"
                "\r\n");
            BOOST_TEST_EQ(a.capacity_in_bytes(), bcap);
            BOOST_TEST_EQ(b.size(), 1u);
            BOOST_TEST_EQ(b.buffer(), "Host: a\r\n\r\n");
            BOOST_TEST_EQ(b.capacity_in_bytes(), acap);
            BOOST_TEST_EQ(av, "a");
            BOOST_TEST_EQ(
                static_cast<void const*>(av.data()),
                static_cast<void const*>(
                    b.begin()[0].value.data()));

            // both containers remain usable
            a.append("X-A", "1");
            b.append("X-B", "2");
            BOOST_TEST_EQ(a.size(), 3u);
            BOOST_TEST_EQ(b.size(), 2u);
        }

        // ADL and std::swap find the hidden friend
        {
            fields a = { { "A", "1" } };
            fields b = { { "B", "2" } };
            swap(a, b);
            BOOST_TEST_EQ(a.buffer(), "B: 2\r\n\r\n");
            std::swap(a, b);
            BOOST_TEST_EQ(a.buffer(), "A: 1\r\n\r\n");
        }

        // swapping with a default container transfers the
        // allocation and the shared static buffer
        {
            fields a = { { "A", "1" } };
            fields b;
            auto const acap = a.capacity_in_bytes();
            a.swap(b);
            BOOST_TEST(a.empty());
            BOOST_TEST_EQ(a.buffer(), "\r\n");
            BOOST_TEST_EQ(a.capacity_in_bytes(), 0u);
            BOOST_TEST_EQ(b.buffer(), "A: 1\r\n\r\n");
            BOOST_TEST_EQ(b.capacity_in_bytes(), acap);

            // the container which received the static
            // buffer allocates on its next modification
            a.append("X-A", "2");
            BOOST_TEST_EQ(a.buffer(), "X-A: 2\r\n\r\n");
        }

        // two default containers
        {
            fields a;
            fields b;
            a.swap(b);
            BOOST_TEST_EQ(a.buffer(), "\r\n");
            BOOST_TEST_EQ(a.capacity_in_bytes(), 0u);
            BOOST_TEST_EQ(b.buffer(), "\r\n");
            BOOST_TEST_EQ(b.capacity_in_bytes(), 0u);
        }

        // self-swap has no effect
        {
            fields a = { { "A", "1" } };
            auto& ar = a;
            a.swap(ar);
            BOOST_TEST_EQ(a.size(), 1u);
            BOOST_TEST_EQ(a.buffer(), "A: 1\r\n\r\n");
        }
    }

    void
    testFromFieldsBase()
    {
        // the conversion is explicit: turning a view into an
        // owning container allocates, and dropping a header's
        // start line should be deliberate
        static_assert(
            std::is_constructible_v<fields, fields_base const&>);
        static_assert(
            ! std::is_convertible_v<fields_base const&, fields>);

        // an owning header is a fields_base carrying a start
        // line; converting to fields copies only the fields
        request_head h;
        h.set_target("/orig");
        h.append(http::field::host, "example.com");
        h.append("X-A", "1");
        h.append("X-A", "2");

        fields f{ static_cast<fields_base const&>(h) };
        BOOST_TEST_EQ(
            f.buffer(),
            "Host: example.com\r\n"
            "X-A: 1\r\n"
            "X-A: 2\r\n"
            "\r\n");
        BOOST_TEST(f.buffer().find("GET") == std::string_view::npos);
        BOOST_TEST_EQ(f.count("X-A"), 2u);
        // independent storage; field ids survive the copy
        BOOST_TEST(f.buffer().data() != h.buffer().data());
        BOOST_TEST(f.begin()[0].id == http::field::host);

        // mutating the source leaves the copy intact
        h.set_target("/changed");
        h.set(http::field::host, "other.com");
        BOOST_TEST_EQ(f.at(http::field::host), "example.com");

        // copying an empty header allocates nothing
        request_head e;
        fields ef{ static_cast<fields_base const&>(e) };
        BOOST_TEST(ef.empty());
        BOOST_TEST_EQ(ef.capacity_in_bytes(), 0u);

        // a plain fields is also a fields_base (no prefix)
        fields src = { { "A", "1" } };
        fields ff{ static_cast<fields_base const&>(src) };
        BOOST_TEST_EQ(ff.buffer(), src.buffer());
    }

    void
    testAssignFieldsBase()
    {
        request_head h;
        h.append(http::field::host, "example.com");
        h.append("X-A", "1");

        // assignment drops the prior contents and the start line
        fields f = { { "Old", "v" } };
        f = static_cast<fields_base const&>(h);
        BOOST_TEST_EQ(
            f.buffer(),
            "Host: example.com\r\n"
            "X-A: 1\r\n"
            "\r\n");
        BOOST_TEST(! f.contains("Old"));

        // assigning an empty header clears
        request_head e;
        f = static_cast<fields_base const&>(e);
        BOOST_TEST(f.empty());
        BOOST_TEST_EQ(f.buffer(), "\r\n");

        // self-assignment through a fields_base reference
        fields g = { { "A", "1" }, { "B", "2" } };
        fields_base const& gb = g;
        g = gb;
        BOOST_TEST_EQ(g.size(), 2u);
        BOOST_TEST_EQ(g.buffer(), "A: 1\r\nB: 2\r\n\r\n");
    }

    void
    testCapacity()
    {
        fields f;
        f.reserve(4096, 64);
        auto const cap = f.capacity_in_bytes();
        BOOST_TEST(cap >= 4096 + 64 * 12);

        auto const* p = f.buffer().data();
        for(int i = 0; i < 64; ++i)
            f.append("X-Header-Name", "some-value-here");
        BOOST_TEST_EQ(f.size(), 64u);

        // no reallocation happened
        BOOST_TEST_EQ(f.capacity_in_bytes(), cap);
        BOOST_TEST_EQ(
            static_cast<void const*>(f.buffer().data()),
            static_cast<void const*>(p));

        f.shrink_to_fit();
        BOOST_TEST(f.capacity_in_bytes() < cap);
        BOOST_TEST_EQ(f.size(), 64u);
        BOOST_TEST_EQ(f.begin()[63].name, "X-Header-Name");
        BOOST_TEST_EQ(f.begin()[63].value, "some-value-here");

        // clear keeps the allocation
        auto const cap2 = f.capacity_in_bytes();
        f.clear();
        BOOST_TEST(f.empty());
        BOOST_TEST_EQ(f.buffer(), "\r\n");
        BOOST_TEST_EQ(f.capacity_in_bytes(), cap2);

        // shrinking an empty container releases it
        f.shrink_to_fit();
        BOOST_TEST_EQ(f.capacity_in_bytes(), 0u);
        BOOST_TEST_EQ(f.buffer(), "\r\n");

        // no-op reserve
        fields g;
        g.reserve(0, 0);
        BOOST_TEST_EQ(g.capacity_in_bytes(), 0u);
        g.reserve(2, 0);
        BOOST_TEST_EQ(g.capacity_in_bytes(), 0u);
    }

    void
    testSelfReference()
    {
        // arguments viewing the container remain valid
        fields f;
        f.append(http::field::host, "example.com");

        // growth path: the old buffer is read
        f.append("X-Copy", f.begin()[0].value);
        BOOST_TEST_EQ(f.begin()[1].value, "example.com");

        // in-place, source before the insertion point
        f.reserve(1024, 16);
        f.append("X-Copy2", f.begin()[0].value);
        BOOST_TEST_EQ(f.begin()[2].value, "example.com");

        // in-place, source shifted by the insertion
        f.insert(f.begin(), "X-First", f.begin()[1].value);
        BOOST_TEST_EQ(f.begin()[0].name, "X-First");
        BOOST_TEST_EQ(f.begin()[0].value, "example.com");

        // self-referenced name; the id still resolves
        f.insert(f.begin(), f.begin()[1].name, "n");
        BOOST_TEST_EQ(f.begin()[0].name, "Host");
        BOOST_TEST(f.begin()[0].id == http::field::host);

        // set from a substring of the field's own value
        fields g;
        g.append(http::field::host, "www.example.com");
        g.set(http::field::host, g.begin()[0].value.substr(4));
        BOOST_TEST_EQ(g.begin()[0].value, "example.com");

        // set from a later field's value: shrinking
        g.append("X-Tail", "tail-value");
        g.set(http::field::host, g.begin()[1].value);
        BOOST_TEST_EQ(g.begin()[0].value, "tail-value");
        BOOST_TEST_EQ(g.begin()[1].value, "tail-value");

        // set from a later field's value: growing
        g.append("X-Long", "a-much-longer-value-than-before");
        g.set(http::field::host, g.begin()[2].value);
        BOOST_TEST_EQ(g.begin()[0].value, "a-much-longer-value-than-before");
        BOOST_TEST_EQ(g.begin()[2].value, "a-much-longer-value-than-before");
        BOOST_TEST_EQ(g.begin()[1].value, "tail-value");

        // set from a later field's value: equal length
        g.set("X-Tail", "value-tail");
        g.set(http::field::host, g.begin()[1].value);
        BOOST_TEST_EQ(g.begin()[0].value, "value-tail");
    }

    void
    testIterators()
    {
        fields f = {
            { "A", "1" },
            { "B", "2" },
            { "C", "3" },
        };

        auto it = f.begin();
        BOOST_TEST_EQ((*it).name, "A");
        BOOST_TEST_EQ(it->name, "A");
        BOOST_TEST_EQ(it[2].name, "C");
        BOOST_TEST_EQ((it + 2)->name, "C");
        BOOST_TEST_EQ((2 + it)->name, "C");

        auto it2 = f.end();
        BOOST_TEST_EQ(it2 - it, 3);
        --it2;
        BOOST_TEST_EQ(it2->name, "C");
        it2 -= 1;
        BOOST_TEST_EQ(it2->name, "B");
        it2 = it2 - 1;
        BOOST_TEST(it2 == f.begin());
        BOOST_TEST(it < f.end());
        BOOST_TEST(f.end() > it);
        BOOST_TEST(it <= f.begin());
        BOOST_TEST(it >= f.begin());

        it++;
        it--;
        BOOST_TEST(it == f.begin());
        BOOST_TEST(it != f.end());

        std::string s;
        for(auto r : f)
        {
            s.append(r.name);
            s.push_back('=');
            s.append(r.value);
            s.push_back(';');
        }
        BOOST_TEST_EQ(s, "A=1;B=2;C=3;");

        // default-constructed iterators compare equal
        fields::iterator d1;
        fields::iterator d2;
        BOOST_TEST(d1 == d2);
    }

    void
    testBig()
    {
        fields f;
        std::string expected;
        for(int i = 0; i < 200; ++i)
        {
            auto const name  = "X-Field-" + std::to_string(i);
            auto const value = "v" + std::to_string(i * 7);
            f.append(name, value);
            expected += name + ": " + value + "\r\n";
        }
        expected += "\r\n";
        BOOST_TEST_EQ(f.size(), 200u);
        BOOST_TEST_EQ(f.buffer(), expected);

        for(int i = 0; i < 200; ++i)
        {
            auto const name = "x-field-" + std::to_string(i);
            auto it         = f.find(name);
            BOOST_TEST(it != f.end());
            BOOST_TEST_EQ(it->value, "v" + std::to_string(i * 7));
        }

        // erase every other field
        for(int i = 0; i < 200; i += 2)
            BOOST_TEST_EQ(f.erase("X-Field-" + std::to_string(i)), 1u);
        BOOST_TEST_EQ(f.size(), 100u);

        expected.clear();
        for(int i = 1; i < 200; i += 2)
            expected += "X-Field-" + std::to_string(i) + ": v" +
                std::to_string(i * 7) + "\r\n";
        expected += "\r\n";
        BOOST_TEST_EQ(f.buffer(), expected);

        // erase by iterator until empty
        while(!f.empty())
            f.erase(f.begin());
        BOOST_TEST_EQ(f.buffer(), "\r\n");
    }

    void
    testLimits()
    {
        fields f = { { "X-A", "1" } };
        std::string const big_name(fields::max_name_size + 1, 'a');
        std::string const big_value(fields::max_value_size + 1, 'b');

        BOOST_TEST_THROWS(f.append(big_name, "v"), std::length_error);
        BOOST_TEST_THROWS(f.append("X-B", big_value), std::length_error);
        BOOST_TEST_THROWS(
            f.append(http::field::host, big_value), std::length_error);
        BOOST_TEST_THROWS(
            f.insert(f.begin(), big_name, "v"), std::length_error);
        BOOST_TEST_THROWS(f.set(f.begin(), big_value), std::length_error);
        BOOST_TEST_THROWS(f.set("X-A", big_value), std::length_error);
        BOOST_TEST_THROWS(
            f.set(http::field::host, big_value), std::length_error);

        // failed operations leave the container unchanged
        BOOST_TEST_EQ(f.buffer(), "X-A: 1\r\n\r\n");

        // impossible reservations; exhausting the total
        // buffer size is not tested, as reaching it would
        // have to allocate it
        fields h;
        BOOST_TEST_THROWS(
            h.reserve(fields::max_buffer_size + 1, 0),
            std::length_error);
        BOOST_TEST_THROWS(
            h.reserve(std::size_t(-1), 0),
            std::length_error);
        BOOST_TEST_THROWS(
            h.reserve(0, std::size_t(-1)),
            std::length_error);
        // the table is not counted against the head
        // limit; the field count has a limit of its own
        BOOST_TEST_THROWS(
            h.reserve(0, fields::max_field_count + 1),
            std::length_error);
        BOOST_TEST_EQ(h.capacity_in_bytes(), 0u);
        BOOST_TEST_EQ(h.buffer(), "\r\n");

        // the field which would exceed that count is
        // refused, rather than wrapping it
        fields g;
        g.reserve(
            5 * fields::max_field_count + 2,
            fields::max_field_count);
        for(std::size_t i = 0; i < fields::max_field_count; ++i)
            g.append("a", "");
        BOOST_TEST_EQ(g.size(), fields::max_field_count);
        BOOST_TEST_THROWS(g.append("a", ""), std::length_error);
        BOOST_TEST_THROWS(
            g.insert(g.begin(), "a", ""), std::length_error);
        BOOST_TEST_EQ(g.size(), fields::max_field_count);
    }

    void
    testInitializerList()
    {
        // empty list
        {
            fields f = {};
            BOOST_TEST_EQ(f.buffer(), "\r\n");
            BOOST_TEST_EQ(f.capacity_in_bytes(), 0u);
        }

        // mixed constants and strings
        {
            fields f = {
                { http::field::host, "example.com" },
                { "X-Request-Id", "42" },
                { http::field::accept, "text/html" },
                { "aCCEPT", "text/plain" },
                { "X-Empty", "" },
            };
            BOOST_TEST_EQ(f.size(), 5u);
            BOOST_TEST_EQ(
                f.buffer(),
                "Host: example.com\r\n"
                "X-Request-Id: 42\r\n"
                "Accept: text/html\r\n"
                "aCCEPT: text/plain\r\n"
                "X-Empty: \r\n"
                "\r\n");

            // string names resolve to constants
            BOOST_TEST(f.begin()[0].id == http::field::host);
            BOOST_TEST(f.begin()[3].id == http::field::accept);
            BOOST_TEST_EQ(
                static_cast<std::uint8_t>(f.begin()[1].id), 0);
            BOOST_TEST_EQ(f.count(http::field::accept), 2u);

            // a single exact-fit allocation
            fields g;
            g.reserve(f.buffer().size(), f.size());
            BOOST_TEST_EQ(f.capacity_in_bytes(), g.capacity_in_bytes());
        }

        // assignment through a temporary
        {
            fields f;
            f.append("X-Old", "1");
            f = { { http::field::age, "0" } };
            BOOST_TEST_EQ(f.buffer(), "Age: 0\r\n\r\n");
        }

        // elements copied from another container
        {
            fields f = {
                { http::field::host, "example.com" },
                { "X-Request-Id", "42" },
            };
            fields g = { f.begin()[0], f.begin()[1] };
            BOOST_TEST_EQ(g.buffer(), f.buffer());
            BOOST_TEST(g.begin()[0].id == http::field::host);
            BOOST_TEST_EQ(
                static_cast<std::uint8_t>(g.begin()[1].id), 0);
        }

        // limits are enforced
        {
            std::string const big_value(
                fields::max_value_size + 1, 'b');
            BOOST_TEST_THROWS(
                (fields{ { "X-B", big_value } }),
                std::length_error);
        }
    }

    void
    testOstream()
    {
        fields f;
        std::ostringstream os;
        os << f;
        BOOST_TEST_EQ(os.str(), "");

        f.append(http::field::host, "example.com");
        f.append("X-Custom", "v");
        os << f;
        BOOST_TEST_EQ(os.str(),
            "Host: example.com\n"
            "X-Custom: v\n");
    }

    void
    run()
    {
        testDefault();
        testAppend();
        testAppendList();
        testFindFrom();
        testFindAll();
        testSet();
        testInsert();
        testErase();
        testEraseAll();
        testSpecialFields();
        testAt();
        testSetIterator();
        testFindLast();
        testReverseIterators();
        testCopyMove();
        testSwap();
        testFromFieldsBase();
        testAssignFieldsBase();
        testCapacity();
        testSelfReference();
        testIterators();
        testBig();
        testLimits();
        testInitializerList();
        testOstream();
    }
};

TEST_SUITE(fields_test, "boost.burl.fields");

} // namespace burl
} // namespace boost
