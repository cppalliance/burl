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

#include <boost/burl/any_request_body.hpp>
#include <boost/burl/conversion.hpp>

#include "body_test.hpp"
#include "test_suite.hpp"

#include <boost/json/array.hpp>
#include <boost/json/object.hpp>
#include <boost/json/serialize.hpp>
#include <boost/json/string.hpp>
#include <boost/json/value.hpp>

#include <string>

namespace boost
{
namespace burl
{

struct json_test
{
    static void
    check_json(any_request_body const& body, json::value const& jv)
    {
        BOOST_TEST(body.has_value());

        auto ct = body.content_type();
        BOOST_TEST(ct.has_value());
        BOOST_TEST_EQ(ct.value(), "application/json");

        BOOST_TEST(!body.content_length().has_value());

        check_body(body, json::serialize(jv));
    }

    void
    testValue()
    {
        json::value jv = { { "key", "value" }, { "n", 42 } };
        auto body = tag_invoke(body_from_tag<json::value>{}, jv);
        check_json(body, jv);
    }

    void
    testObject()
    {
        json::object obj;
        obj["a"] = 1;
        obj["b"] = "two";
        auto body = tag_invoke(body_from_tag<json::object>{}, obj);
        check_json(body, json::value(obj));
    }

    void
    testArray()
    {
        json::array arr = { 1, 2, 3 };
        auto body = tag_invoke(body_from_tag<json::array>{}, arr);
        check_json(body, json::value(arr));
    }

    void
    testString()
    {
        json::string str = "a string value";
        auto body = tag_invoke(body_from_tag<json::string>{}, str);
        check_json(body, json::value(str));
    }

    void
    testNull()
    {
        json::value jv = nullptr;
        auto body = tag_invoke(body_from_tag<json::value>{}, jv);
        check_json(body, jv);
    }

    void
    run()
    {
        testValue();
        testObject();
        testArray();
        testString();
        testNull();
    }
};

TEST_SUITE(json_test, "boost.burl.json");

} // namespace burl
} // namespace boost
