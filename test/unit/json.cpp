//
// Copyright (c) 2026 Mohammad Nejati
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

// Test that header file is self-contained.
#include <boost/burl/json.hpp>

#include <boost/burl/test/response_factory.hpp>

#include <boost/capy/test/run_blocking.hpp>
#include <boost/json/serialize.hpp>

#include "body_test.hpp"
#include "test_suite.hpp"

namespace boost
{
namespace burl
{

class json_test
{
    static void
    check(any_request_body const& body, json::value const& v)
    {
        BOOST_TEST(body.has_value());
        BOOST_TEST(!body.content_length().has_value());
        BOOST_TEST_EQ(body.content_type().value_or(""), "application/json");
        check_body(body, json::serialize(v));
    }

public:
    void
    testFromValue()
    {
        json::value v = { { "key", "value" }, { "n", 42 } };
        check(tag_invoke(body_from_tag<json::value>{}, v), v);
    }

    void
    testFromObject()
    {
        json::object v = { { "a", 1 }, { "b", "two" } };
        check(tag_invoke(body_from_tag<json::object>{}, v), v);
    }

    void
    testFromArray()
    {
        json::array v = { 1, 2, 3 };
        check(tag_invoke(body_from_tag<json::array>{}, v), v);
    }

    void
    testFromString()
    {
        json::string v = { "a string value" };
        check(tag_invoke(body_from_tag<json::string>{}, v), v);
    }

    void
    testFromNull()
    {
        json::value v = { nullptr };
        check(tag_invoke(body_from_tag<json::value>{}, v), v);
    }

    void
    testToValue()
    {
        capy::test::run_blocking()([&]() -> capy::task<>
        {
            auto r = test::response_factory()
                .body({ R"({ "key" : "value" })" })
                .create();
            auto [ec, v] = co_await r.try_as<json::value>();
            BOOST_TEST(!ec);
            BOOST_TEST_EQ(v, (json::value{{ "key", "value" }}));
        }());

        // Malformed
        capy::test::run_blocking()([&]() -> capy::task<>
        {
            auto r = test::response_factory()
                .body({"Malformed"})
                .create();
            auto [ec, v] = co_await r.try_as<json::value>();
            BOOST_TEST(ec);
            BOOST_TEST_EQ(v, json::value{});
        }());

        // Truncated
        capy::test::run_blocking()([&]() -> capy::task<>
        {
            auto r = test::response_factory()
                .content_length(64)
                .body({ R"({ "key" : "value" })" })
                .create();
            auto [ec, v] = co_await r.try_as<json::value>();
            BOOST_TEST_EQ(ec, http::error::incomplete);
            BOOST_TEST_EQ(v, json::value{});
        }());
    }

    void
    testToObject()
    {
        capy::test::run_blocking()([&]() -> capy::task<>
        {
            auto r = test::response_factory()
                .body({ R"({ "key" : "value" })" })
                .create();
            auto [ec, v] = co_await r.try_as<json::object>();
            BOOST_TEST(!ec);
            BOOST_TEST_EQ(v, (json::object{{ "key", "value" }}));
        }());

        capy::test::run_blocking()([&]() -> capy::task<>
        {
            auto r = test::response_factory()
                .body({ R"(["item1", "item2"])" }) // array
                .create();
            auto [ec, v] = co_await r.try_as<json::object>();
            BOOST_TEST(ec);
            BOOST_TEST_EQ(v, json::object{});
        }());
    }

    void
    testToArray()
    {
        capy::test::run_blocking()([&]() -> capy::task<>
        {
            auto r = test::response_factory()
                .body({ R"(["item1", "item2"])" })
                .create();
            auto [ec, v] = co_await r.try_as<json::array>();
            BOOST_TEST(!ec);
            BOOST_TEST_EQ(v, (json::array{ "item1", "item2" }));
        }());

        capy::test::run_blocking()([&]() -> capy::task<>
        {
            auto r = test::response_factory()
                .body({ R"({ "key" : "value" })" }) // object
                .create();
            auto [ec, v] = co_await r.try_as<json::array>();
            BOOST_TEST(ec);
            BOOST_TEST_EQ(v, json::array{});
        }());
    }

    void
    testToString()
    {
        capy::test::run_blocking()([&]() -> capy::task<>
        {
            auto r = test::response_factory()
                .body({ R"("string")" })
                .create();
            auto [ec, v] = co_await r.try_as<json::string>();
            BOOST_TEST(!ec);
            BOOST_TEST_EQ(v, (json::string{ "string" }));
        }());

        capy::test::run_blocking()([&]() -> capy::task<>
        {
            auto r = test::response_factory()
                .body({ R"({ "key" : "value" })" }) // object
                .create();
            auto [ec, v] = co_await r.try_as<json::string>();
            BOOST_TEST(ec);
            BOOST_TEST_EQ(v, json::string{});
        }());
    }

    void
    testTransportErrorInjection()
    {
        capy::test::fuse f;
        test::response_factory factory;
        factory.body({ "{ \"key\"", " : \"value\" }" });

        auto r = f.armed([&](capy::test::fuse&) -> capy::task<>
        {
            auto r = factory.create(f);

            auto [ec, v] = co_await r.try_as<json::value>();
            if(ec)
                co_return;
    
            BOOST_TEST_EQ(v, (json::value{{ "key", "value" }}));
        });
        BOOST_TEST(r.success);
    }

    void
    run()
    {
        testFromValue();
        testFromObject();
        testFromArray();
        testFromString();
        testFromNull();
        testToValue();
        testToObject();
        testToArray();
        testToString();
        testTransportErrorInjection();
    }
};

TEST_SUITE(json_test, "boost.burl.json");

} // namespace burl
} // namespace boost
