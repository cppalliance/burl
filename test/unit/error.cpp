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

#include <string>
#include <system_error>

namespace boost
{
namespace burl
{

struct error_test
{
    void
    testCategoryNames()
    {
        BOOST_TEST(std::string(burl_category().name()) == "boost.burl");
        BOOST_TEST(
            std::string(burl_condition_category().name()) ==
            "boost.burl.condition");
    }

    void
    testMessages()
    {
        BOOST_TEST_EQ(
            make_error_code(error::unsupported_url_scheme).message(),
            "unsupported URL scheme");
        BOOST_TEST_EQ(
            make_error_code(error::too_many_redirects).message(),
            "too many redirects");
        BOOST_TEST_EQ(
            make_error_code(error::bad_redirect_response).message(),
            "bad redirect response");
        BOOST_TEST_EQ(
            make_error_code(error::file_changed).message(),
            "file size changed during read");
        BOOST_TEST_EQ(
            make_error_code(error::proxy_auth_failed).message(),
            "proxy authentication failed");

        // The code carries the burl category.
        BOOST_TEST_EQ(
            &make_error_code(error::file_changed).category(), &burl_category());
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
    }

    void
    run()
    {
        testCategoryNames();
        testMessages();
        testHttpStatusMessages();
        testConditions();
        testConditionMessages();
    }
};

TEST_SUITE(error_test, "boost.burl.error");

} // namespace burl
} // namespace boost
