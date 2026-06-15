//
// Copyright (c) 2026 Mohammad Nejati
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

// Test that header file is self-contained.
#include <boost/burl/error.hpp>

#include "test_suite.hpp"

namespace boost
{
namespace burl
{

struct error_test
{
    void
    testCategoryNames()
    {
        BOOST_TEST_EQ(
            std::string_view{ burl_category().name() },
            "boost.burl");
        BOOST_TEST_EQ(
            std::string_view{ burl_condition_category().name() },
            "boost.burl.condition");
    }

    void
    testErrorMessages()
    {
        auto msg = [](error e) { return make_error_code(e).message(); };

        BOOST_TEST_EQ(
            msg(error::unsupported_url_scheme),
            "unsupported URL scheme");
        BOOST_TEST_EQ(
            msg(error::too_many_redirects),
            "too many redirects");
        BOOST_TEST_EQ(
            msg(error::bad_redirect_response),
            "bad redirect response");
        BOOST_TEST_EQ(
            msg(error::file_changed),
            "file size changed during read");
        BOOST_TEST_EQ(
            msg(error::unsupported_proxy_scheme),
            "unsupported proxy scheme");
        BOOST_TEST_EQ(
            msg(error::proxy_connect_failed),
            "proxy could not connect to the target");
        BOOST_TEST_EQ(
            msg(error::proxy_auth_failed),
            "proxy authentication failed");
        BOOST_TEST_EQ(
            msg(error::proxy_unsupported_version),
            "unsupported proxy protocol version");

        BOOST_TEST_EQ(
            std::error_code(9999, burl_category()).message(),
            "unknown error");

        BOOST_TEST_EQ(
            &make_error_code(error::file_changed).category(),
            &burl_category());
    }

    void
    testHttpStatusMessages()
    {
        // Values in [400, 600) render as "HTTP <n> <reason>".
        BOOST_TEST_EQ(
            std::error_code(404, burl_category()).message(),
            "HTTP 404 Not Found");
        BOOST_TEST_EQ(
            std::error_code(500, burl_category()).message(),
            "HTTP 500 Internal Server Error");
    }

    void
    testConditions()
    {
        // 4xx codes map to client_error
        BOOST_TEST(
            std::error_code(404, burl_category()) == condition::client_error);
        BOOST_TEST(
            std::error_code(451, burl_category()) == condition::client_error);
        BOOST_TEST(
            !(std::error_code(404, burl_category()) == condition::server_error));

        // 5xx codes map to server_error
        BOOST_TEST(
            std::error_code(500, burl_category()) == condition::server_error);
        BOOST_TEST(
            std::error_code(503, burl_category()) == condition::server_error);
        BOOST_TEST(
            !(std::error_code(500, burl_category()) == condition::client_error));

        // a named code maps to neither condition.
        auto ec = make_error_code(error::too_many_redirects);
        BOOST_TEST(!(ec == condition::client_error));
        BOOST_TEST(!(ec == condition::server_error));
    }

    void
    testConditionMessages()
    {
        BOOST_TEST_EQ(
            make_error_condition(condition::client_error).message(),
            "HTTP client error");
        BOOST_TEST_EQ(
            make_error_condition(condition::server_error).message(),
            "HTTP server error");
        BOOST_TEST_EQ(
            std::error_condition(9999, burl_condition_category()).message(),
            "unknown condition");
    }

    void
    run()
    {
        testCategoryNames();
        testConditionMessages();
        testErrorMessages();
        testHttpStatusMessages();
        testConditions();
    }
};

TEST_SUITE(error_test, "boost.burl.error");

} // namespace burl
} // namespace boost
