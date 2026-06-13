//
// Copyright (c) 2026 Mohammad Nejati
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

// Test that header file is self-contained.
#include "src/detail/redirect.hpp"

#include "test_suite.hpp"

#include <boost/http/field.hpp>
#include <boost/http/response.hpp>
#include <boost/http/status.hpp>
#include <boost/url/url.hpp>
#include <boost/url/url_view.hpp>

#include <string>
#include <string_view>

namespace boost
{
namespace burl
{
namespace detail
{

class redirect_test
{
    static std::string
    resolve(std::string_view location, urls::url_view base)
    {
        http::response response;
        response.set(http::field::location, location);
        return resolve_location(response, base).buffer();
    }

public:
    void
    testNonRedirect()
    {
        client::config cfg;
        for(auto status :
            { http::status::ok,
              http::status::not_found,
              http::status::internal_server_error })
        {
            auto r = is_redirect(status, cfg);
            BOOST_TEST(!r.is_redirect);
            BOOST_TEST(!r.need_method_change);
        }
    }

    void
    testKeepMethod()
    {
        client::config cfg;
        for(auto status :
            { http::status::temporary_redirect,
              http::status::permanent_redirect })
        {
            auto r = is_redirect(status, cfg);
            BOOST_TEST(r.is_redirect);
            BOOST_TEST(!r.need_method_change);
        }
    }

    void
    testChangeMethod()
    {
        client::config cfg;
        for(auto status :
            { http::status::moved_permanently,
              http::status::found,
              http::status::see_other })
        {
            auto r = is_redirect(status, cfg);
            BOOST_TEST(r.is_redirect);
            BOOST_TEST(r.need_method_change);
        }
    }

    void
    testPost301()
    {
        client::config cfg;
        cfg.post301 = true;

        BOOST_TEST(
            !is_redirect(http::status::moved_permanently, cfg)
                 .need_method_change);
        BOOST_TEST(is_redirect(http::status::found, cfg).need_method_change);
        BOOST_TEST(
            is_redirect(http::status::see_other, cfg).need_method_change);
    }

    void
    testPost302()
    {
        client::config cfg;
        cfg.post302 = true;

        BOOST_TEST(
            is_redirect(http::status::moved_permanently, cfg)
                .need_method_change);
        BOOST_TEST(!is_redirect(http::status::found, cfg).need_method_change);
        BOOST_TEST(
            is_redirect(http::status::see_other, cfg).need_method_change);
    }

    void
    testPost303()
    {
        client::config cfg;
        cfg.post303 = true;

        BOOST_TEST(
            is_redirect(http::status::moved_permanently, cfg)
                .need_method_change);
        BOOST_TEST(is_redirect(http::status::found, cfg).need_method_change);
        BOOST_TEST(
            !is_redirect(http::status::see_other, cfg).need_method_change);
    }

    void
    testResolveAbsolute()
    {
        BOOST_TEST_EQ(
            resolve("http://b.test/y", "http://a.test/dir/page"),
            "http://b.test/y");
    }

    void
    testResolveRelative()
    {
        BOOST_TEST_EQ(
            resolve("other", "http://a.test/dir/page"),
            "http://a.test/dir/other");
        BOOST_TEST_EQ(
            resolve("/abs", "http://a.test/dir/page"),
            "http://a.test/abs");
    }

    void
    testResolveNoLocation()
    {
        http::response response;
        BOOST_TEST(
            resolve_location(response, "http://a.test/").empty());
    }

    void
    testResolveInvalid()
    {
        BOOST_TEST(resolve("h ttp://bad", "http://a.test/").empty());
    }

    void
    testResolveFragment()
    {
        BOOST_TEST_EQ(
            resolve("/other", "http://a.test/page#sec"),
            "http://a.test/other#sec");

        BOOST_TEST_EQ(
            resolve("/other#own", "http://a.test/page#sec"),
            "http://a.test/other#own");
    }

    void
    run()
    {
        testNonRedirect();
        testKeepMethod();
        testChangeMethod();
        testPost301();
        testPost302();
        testPost303();
        testResolveAbsolute();
        testResolveRelative();
        testResolveNoLocation();
        testResolveInvalid();
        testResolveFragment();
    }
};

TEST_SUITE(redirect_test, "boost.burl.detail.redirect");

} // namespace detail
} // namespace burl
} // namespace boost
