//
// Copyright (c) 2026 Mohammad Nejati
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

// Test that header file is self-contained.
#include <boost/burl/file.hpp>

#include <boost/burl/any_request_body.hpp>
#include <boost/burl/conversion.hpp>

#include "body_test.hpp"
#include "test_suite.hpp"

#include <exception>
#include <filesystem>
#include <string>

namespace boost
{
namespace burl
{

struct file_test
{
    void
    testFileBody()
    {
        std::string contents = "a\nb\nc\n";
        temp_file tmp(contents, ".txt");

        auto body =
            tag_invoke(body_from_tag<std::filesystem::path>{}, tmp.path);

        BOOST_TEST(body.has_value());

        auto ct = body.content_type();
        BOOST_TEST(ct.has_value());
        BOOST_TEST_EQ(ct.value(), "text/plain; charset=UTF-8");

        auto cl = body.content_length();
        BOOST_TEST(cl.has_value());
        BOOST_TEST_EQ(cl.value(), contents.size());

        capy::test::buffer_sink bs;
        capy::any_buffer_sink sink(&bs);
        auto ec = drive_body(body, sink);
        BOOST_TEST(!ec);
        BOOST_TEST_EQ(bs.data(), contents);
    }

    void
    testMissingFile()
    {
        BOOST_TEST_THROWS(
            tag_invoke(
                body_from_tag<fs::path>{},
                "./does_not_exist"),
                std::exception);
    }

    static void
    check_content_type(std::string_view extension, std::string_view expected)
    {
        temp_file tmp("data", extension);
        auto body =
            tag_invoke(body_from_tag<std::filesystem::path>{}, tmp.path);
        BOOST_TEST(body.has_value());
        BOOST_TEST_EQ(body.content_type().value(), expected);
    }

    void
    testContentTypeDeduction()
    {
        check_content_type(".txt", "text/plain; charset=UTF-8");
        check_content_type(".json", "application/json; charset=UTF-8");
        check_content_type(".html", "text/html; charset=UTF-8");
        check_content_type(".png", "image/png");

        // fall back to octet-stream.
        check_content_type(".zzz", "application/octet-stream");
        check_content_type("", "application/octet-stream");
    }

    void
    run()
    {
        testFileBody();
        testContentTypeDeduction();
        testMissingFile();
    }
};

TEST_SUITE(file_test, "boost.burl.file");

} // namespace burl
} // namespace boost
