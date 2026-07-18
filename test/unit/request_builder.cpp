//
// Copyright (c) 2026 Mohammad Nejati
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

// Test that header file is self-contained.
#include <boost/burl/request_builder.hpp>

#include <boost/burl/client.hpp>
#include <boost/burl/string.hpp>

#include <boost/capy/ex/system_context.hpp>
#include <boost/corosio/tls_context.hpp>
#include <boost/http/field.hpp>
#include <boost/http/method.hpp>
#include <boost/url/url.hpp>

#include "test_suite.hpp"

#include <chrono>
#include <string>
#include <utility>

namespace boost
{
namespace burl
{

using namespace std::chrono_literals;

class request_builder_test
{
    client
    make_client()
    {
        return client(
            capy::get_system_context().get_executor(),
            corosio::tls_context());
    }

public:
    void
    testBuild()
    {
        auto c = make_client();

        auto req = c.request(
            http::method::put, "http://example.com/path?x=1").build();

        BOOST_TEST(req.method == http::method::put);
        BOOST_TEST_EQ(req.url.buffer(), "http://example.com/path?x=1");
        BOOST_TEST(req.headers.begin() == req.headers.end());
        BOOST_TEST(!req.body.has_value());
        BOOST_TEST(!req.options.timeout.has_value());
        BOOST_TEST(!req.options.followlocation.has_value());
    }

    void
    testQuery()
    {
        auto c = make_client();

        // A single parameter is appended to a URL without a query.
        BOOST_TEST_EQ(
            c.get("http://example.com/path")
                .query("category", "shoes")
                .build()
                .url.buffer(),
            "http://example.com/path?category=shoes");

        // Successive calls append, joined with '&'.
        BOOST_TEST_EQ(
            c.get("http://example.com/path")
                .query("category", "shoes")
                .query("color", "blue")
                .build()
                .url.buffer(),
            "http://example.com/path?category=shoes&color=blue");

        // Parameters are appended after any already present in the URL.
        BOOST_TEST_EQ(
            c.get("http://example.com/path?x=1")
                .query("y", "2")
                .build()
                .url.buffer(),
            "http://example.com/path?x=1&y=2");

        // The key and value are encoded; spaces become '+' and reserved
        // characters are percent-encoded.
        BOOST_TEST_EQ(
            c.get("http://example.com/path")
                .query("full name", "a&b")
                .build()
                .url.buffer(),
            "http://example.com/path?full+name=a%26b");
    }

    void
    testHeaderField()
    {
        auto c = make_client();

        auto req = c.get("http://example.com")
            .header(http::field::accept_language, "en")
            .build();
        BOOST_TEST(req.headers.contains(http::field::accept_language));
        BOOST_TEST_EQ(req.headers.at(http::field::accept_language), "en");

        // Setting the same field again replaces the previous value.
        auto req2 = c.get("http://example.com")
            .header(http::field::accept_language, "en")
            .header(http::field::accept_language, "fr")
            .build();
        BOOST_TEST_EQ(req2.headers.count(http::field::accept_language), 1u);
        BOOST_TEST_EQ(req2.headers.at(http::field::accept_language), "fr");
    }

    void
    testHeaderName()
    {
        auto c = make_client();

        auto req = c.get("http://example.com")
            .header("X-Debug", "1")
            .build();
        BOOST_TEST(req.headers.contains("X-Debug"));
        BOOST_TEST_EQ(req.headers.at("X-Debug"), "1");

        // Setting the same name again replaces the previous value.
        auto req2 = c.get("http://example.com")
            .header("X-Debug", "1")
            .header("X-Debug", "2")
            .build();
        BOOST_TEST_EQ(req2.headers.count("X-Debug"), 1u);
        BOOST_TEST_EQ(req2.headers.at("X-Debug"), "2");
    }

    void
    testBasicAuth()
    {
        auto c = make_client();

        auto req = c.get("http://example.com")
            .basic_auth("user", "pass")
            .build();
        BOOST_TEST_EQ(
            req.headers.at(http::field::authorization),
            "Basic dXNlcjpwYXNz");
    }

    void
    testBearerAuth()
    {
        auto c = make_client();

        auto req = c.get("http://example.com")
            .bearer_auth("sekrit")
            .build();
        BOOST_TEST_EQ(
            req.headers.at(http::field::authorization),
            "Bearer sekrit");
    }

    void
    testTimeout()
    {
        auto c = make_client();

        auto req = c.get("http://example.com")
            .timeout(5s)
            .build();
        BOOST_TEST(req.options.timeout.has_value());
        BOOST_TEST(req.options.timeout.value() == 5s);
    }

    void
    testFollowlocation()
    {
        auto c = make_client();

        auto req = c.get("http://example.com")
            .followlocation(false)
            .build();
        BOOST_TEST(req.options.followlocation.has_value());
        BOOST_TEST_EQ(req.options.followlocation.value(), false);

        auto req2 = c.get("http://example.com")
            .followlocation(true)
            .build();
        BOOST_TEST(req2.options.followlocation.has_value());
        BOOST_TEST_EQ(req2.options.followlocation.value(), true);
    }

    void
    testBody()
    {
        auto c = make_client();

        // The value is converted to a body via tag_invoke.
        auto req = c.post("http://example.com")
            .body(std::string("payload"))
            .build();
        BOOST_TEST(req.body.has_value());
        auto ct = req.body.content_type();
        BOOST_TEST(ct.has_value());
        BOOST_TEST_EQ(ct.value(), "text/plain; charset=utf-8");
        auto cl = req.body.content_length();
        BOOST_TEST(cl.has_value());
        BOOST_TEST_EQ(cl.value(), 7u);

        // The any_request_body overload takes ownership of an existing body.
        auto body =
            tag_invoke(body_from_tag<std::string>{}, std::string("other"));
        auto req2 = c.post("http://example.com")
            .body(std::move(body))
            .build();
        BOOST_TEST(req2.body.has_value());
        BOOST_TEST(req2.body.content_length().value() == 5u);
    }

    void
    testChaining()
    {
        auto c = make_client();

        auto req = c.post("http://example.com/post")
            .query("category", "shoes")
            .header(http::field::accept, "application/json")
            .header("X-Debug", "1")
            .bearer_auth("sekrit")
            .timeout(30s)
            .followlocation(false)
            .body(std::string("payload"))
            .build();

        BOOST_TEST(req.method == http::method::post);
        BOOST_TEST_EQ(req.url.buffer(), "http://example.com/post?category=shoes");
        BOOST_TEST_EQ(req.headers.at(http::field::accept), "application/json");
        BOOST_TEST_EQ(req.headers.at("X-Debug"), "1");
        BOOST_TEST_EQ(
            req.headers.at(http::field::authorization), "Bearer sekrit");
        BOOST_TEST(req.options.timeout.value() == 30s);
        BOOST_TEST_EQ(req.options.followlocation.value(), false);
        BOOST_TEST(req.body.has_value());
    }

    void
    run()
    {
        testBuild();
        testQuery();
        testHeaderField();
        testHeaderName();
        testBasicAuth();
        testBearerAuth();
        testTimeout();
        testFollowlocation();
        testBody();
        testChaining();
    }
};

TEST_SUITE(request_builder_test, "boost.burl.request_builder");

} // namespace burl
} // namespace boost
