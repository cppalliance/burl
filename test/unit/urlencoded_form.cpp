//
// Copyright (c) 2026 Mohammad Nejati
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

// Test that header file is self-contained.
#include <boost/burl/urlencoded_form.hpp>

#include <boost/burl/any_request_body.hpp>
#include <boost/burl/conversion.hpp>

#include <boost/capy/io/any_buffer_sink.hpp>
#include <boost/capy/task.hpp>
#include <boost/capy/test/buffer_sink.hpp>
#include <boost/capy/test/fuse.hpp>

#include "test_suite.hpp"

#include <string_view>
#include <utility>

namespace boost
{
namespace burl
{

struct urlencoded_form_test
{
    static void
    check(urlencoded_form form, std::string_view expected)
    {
        auto body =
            tag_invoke(body_from_tag<urlencoded_form>{}, std::move(form));

        BOOST_TEST(body.has_value());

        auto ct = body.content_type();
        BOOST_TEST(ct.has_value());
        BOOST_TEST_EQ(ct.value(), "application/x-www-form-urlencoded");

        auto cl = body.content_length();
        BOOST_TEST(cl.has_value());
        BOOST_TEST_EQ(cl.value(), expected.size());

        BOOST_TEST(
            capy::test::fuse().armed(
                [&](capy::test::fuse& f) -> capy::task<void>
                {
                    capy::test::buffer_sink bs(f);
                    capy::any_buffer_sink sink(&bs);

                    auto [ec] = co_await body.write(sink);
                    if(ec)
                        co_return;

                    BOOST_TEST_EQ(bs.data(), expected);
                }));
    }

    void
    testEmpty()
    {
        check(urlencoded_form(), "");
    }

    void
    testAppend()
    {
        urlencoded_form form;

        // append returns *this for chaining.
        auto& ref = form.append("user", "John");
        BOOST_TEST_EQ(&ref, &form);

        form.append("lang", "En");
        check(std::move(form), "user=John&lang=En");
    }

    void
    testInitializerList()
    {
        check(
            urlencoded_form({ { "user", "John" }, { "lang", "En" } }),
            "user=John&lang=En");
    }

    void
    testEncoding()
    {
        // Spaces are encoded as '+'.
        check(
            urlencoded_form({ { "full name", "John Doe" } }),
            "full+name=John+Doe");

        // Reserved characters are percent-encoded in both name and value.
        check(urlencoded_form({ { "a&b", "c=d" } }), "a%26b=c%3Dd");

        // Unreserved characters pass through unchanged.
        check(
            urlencoded_form({ { "a-b_c.d~e", "AZaz09" } }), "a-b_c.d~e=AZaz09");

        // Multiple fields are joined with '&'.
        check(
            urlencoded_form({ { "k1", "v 1" }, { "k2", "v/2" } }),
            "k1=v+1&k2=v%2F2");
    }

    void
    run()
    {
        testEmpty();
        testAppend();
        testInitializerList();
        testEncoding();
    }
};

TEST_SUITE(urlencoded_form_test, "boost.burl.urlencoded_form");

} // namespace burl
} // namespace boost
