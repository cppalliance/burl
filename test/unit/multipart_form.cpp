//
// Copyright (c) 2026 Mohammad Nejati
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

// Test that header file is self-contained.
#include <boost/burl/multipart_form.hpp>

#include <boost/burl/any_request_body.hpp>
#include <boost/burl/conversion.hpp>

#include "body_test.hpp"
#include "test_suite.hpp"

#include <string>
#include <string_view>
#include <utility>

namespace boost
{
namespace burl
{

struct multipart_form_test
{
    static constexpr std::string_view ct_prefix =
        "multipart/form-data; boundary=";

    static std::string
    boundary_of(any_request_body const& body)
    {
        auto ct = body.content_type();
        BOOST_TEST(ct.has_value());
        BOOST_TEST(std::string_view(ct.value()).starts_with(ct_prefix));
        return ct.value().substr(ct_prefix.size());
    }

    static std::string
    part(
        std::string_view boundary,
        std::string_view name,
        std::string_view value,
        std::string_view filename = {},
        std::string_view content_type = {})
    {
        std::string s = "--";
        s += boundary;
        s += "\r\nContent-Disposition: form-data; name=\"";
        s += name;
        s += "\"";
        if(!filename.empty())
        {
            s += "; filename=\"";
            s += filename;
            s += "\"";
        }
        s += "\r\n";
        if(!content_type.empty())
        {
            s += "Content-Type: ";
            s += content_type;
            s += "\r\n";
        }
        s += "\r\n";
        s += value;
        s += "\r\n";
        return s;
    }

    static void
    check(any_request_body const& body, std::string_view expected)
    {
        auto cl = body.content_length();
        BOOST_TEST(cl.has_value());
        BOOST_TEST_EQ(cl.value(), expected.size());

        check_body(body, expected);
    }

    void
    testEmpty()
    {
        // A form with no parts serializes to just the closing boundary.
        auto body =
            tag_invoke(body_from_tag<multipart_form>{}, multipart_form());

        auto boundary = boundary_of(body);
        auto expected = "--" + boundary + "--\r\n";

        check(body, expected);
    }

    void
    testTextPart()
    {
        multipart_form form;

        // text() returns *this for chaining.
        auto& ref = form.text("field", "value");
        BOOST_TEST_EQ(&ref, &form);

        auto body =
            tag_invoke(body_from_tag<multipart_form>{}, std::move(form));

        auto boundary = boundary_of(body);
        auto expected =
            part(boundary, "field", "value") + "--" + boundary + "--\r\n";

        check(body, expected);
    }

    void
    testTextPartContentType()
    {
        multipart_form form;
        form.text("greeting", "hello", "text/plain");

        auto body =
            tag_invoke(body_from_tag<multipart_form>{}, std::move(form));

        auto boundary = boundary_of(body);
        auto expected =
            part(boundary, "greeting", "hello", {}, "text/plain") +
            "--" + boundary + "--\r\n";

        check(body, expected);
    }

    void
    testMultipleParts()
    {
        multipart_form form;
        form.text("user", "John").text("lang", "En", "text/plain");

        auto body =
            tag_invoke(body_from_tag<multipart_form>{}, std::move(form));

        auto boundary = boundary_of(body);
        auto expected =
            part(boundary, "user", "John") +
            part(boundary, "lang", "En", {}, "text/plain") + "--" + boundary +
            "--\r\n";

        check(body, expected);
    }

    void
    testEmptyValue()
    {
        // An empty value still emits the part header and the trailing CRLF.
        multipart_form form;
        form.text("token", "");

        auto body =
            tag_invoke(body_from_tag<multipart_form>{}, std::move(form));

        auto boundary = boundary_of(body);
        auto expected =
            part(boundary, "token", "") + "--" + boundary + "--\r\n";

        check(body, expected);
    }

    void
    testFilePart()
    {
        std::string contents = "a\nb\nc\n";
        temp_file tmp(contents);

        multipart_form form;

        // file() returns *this for chaining
        auto& ref = form.file("doc", tmp.path, "report.txt", "text/plain");
        BOOST_TEST_EQ(&ref, &form);

        auto body =
            tag_invoke(body_from_tag<multipart_form>{}, std::move(form));

        auto boundary = boundary_of(body);

        auto expected =
            part(boundary, "doc", contents, "report.txt", "text/plain")
            + "--" + boundary + "--\r\n";

        auto cl = body.content_length();
        BOOST_TEST(cl.has_value());
        BOOST_TEST_EQ(cl.value(), expected.size());

        capy::test::buffer_sink bs;
        capy::any_buffer_sink sink(&bs);

        auto ec = drive_body(body, sink);
        BOOST_TEST(!ec);
        BOOST_TEST_EQ(bs.data(), expected);
    }

    void
    check_deduced(std::string_view extension, std::string_view expected_ct)
    {
        std::string contents = "a\nb\nc\n";
        temp_file tmp(contents, extension);

        multipart_form form;
        form.file("doc", tmp.path);

        auto body =
            tag_invoke(body_from_tag<multipart_form>{}, std::move(form));

        auto boundary = boundary_of(body);
        auto expected =
            part(
                boundary,
                "doc",
                contents,
                tmp.path.filename().string(),
                expected_ct) +
            "--" + boundary + "--\r\n";

        auto cl = body.content_length();
        BOOST_TEST(cl.has_value());
        BOOST_TEST_EQ(cl.value(), expected.size());

        capy::test::buffer_sink bs;
        capy::any_buffer_sink sink(&bs);

        auto ec = drive_body(body, sink);
        BOOST_TEST(!ec);
        BOOST_TEST_EQ(bs.data(), expected);
    }

    void
    testFilePartDeduced()
    {
        check_deduced(".txt", "text/plain; charset=UTF-8");
        check_deduced(".png", "image/png");

        // fall back to octet-stream.
        check_deduced(".zzz", "application/octet-stream");
        check_deduced("", "application/octet-stream");
    }

    void
    testMixedParts()
    {
        std::string contents = "a\nb\nc\n";
        temp_file tmp(contents);

        multipart_form form;
        form.text("priority", "high")
            .file("attachment", tmp.path, "crash.log", "text/plain");

        auto body =
            tag_invoke(body_from_tag<multipart_form>{}, std::move(form));

        auto boundary = boundary_of(body);

        auto expected =
            part(boundary, "priority", "high") +
            part(boundary, "attachment", contents, "crash.log", "text/plain") +
            "--" + boundary + "--\r\n";

        auto cl = body.content_length();
        BOOST_TEST(cl.has_value());
        BOOST_TEST_EQ(cl.value(), expected.size());

        capy::test::buffer_sink bs;
        capy::any_buffer_sink sink(&bs);

        auto ec = drive_body(body, sink);
        BOOST_TEST(!ec);
        BOOST_TEST_EQ(bs.data(), expected);
    }

    void
    run()
    {
        testEmpty();
        testTextPart();
        testTextPartContentType();
        testMultipleParts();
        testEmptyValue();
        testFilePart();
        testFilePartDeduced();
        testMixedParts();
    }
};

TEST_SUITE(multipart_form_test, "boost.burl.multipart_form");

} // namespace burl
} // namespace boost
