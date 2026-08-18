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

#include <boost/burl/test/response_factory.hpp>

#include "body_test.hpp"
#include "temp_file.hpp"
#include "test_suite.hpp"

#include <fstream>

namespace boost
{
namespace burl
{

namespace fs = std::filesystem;

class file_test
{
    static std::string
    read_file(fs::path const& path)
    {
        std::ifstream ifs(path, std::ios::binary);
        return std::string(
            std::istreambuf_iterator<char>(ifs),
            std::istreambuf_iterator<char>());
    }

public:
    void
    testFromFile()
    {
        std::string contents = "a\nb\nc\n";
        temp_file tmp(contents, ".txt");

        auto body =
            tag_invoke(body_from_tag<fs::path>{}, tmp.path);

        BOOST_TEST(body.has_value());

        auto ct = body.content_type();
        BOOST_TEST(ct.has_value());
        BOOST_TEST_EQ(ct.value(), "text/plain; charset=UTF-8");

        auto cl = body.content_length();
        BOOST_TEST(cl.has_value());
        BOOST_TEST_EQ(cl.value(), contents.size());

        check_io_body(body, contents);
    }

    void
    testFromFileMissingFile()
    {
        BOOST_TEST_THROWS(
            tag_invoke(
                body_from_tag<fs::path>{},
                "./does_not_exist"),
                std::exception);
    }

    void
    testFromFileContentTypeDeduction()
    {
        const auto check = [](std::string_view ext, std::string_view exp)
        {
            temp_file tmp("data", ext);
            auto body =
                tag_invoke(body_from_tag<fs::path>{}, tmp.path);
            BOOST_TEST(body.has_value());
            BOOST_TEST_EQ(body.content_type().value(), exp);
        };

        check(".txt", "text/plain; charset=UTF-8");
        check(".json", "application/json; charset=UTF-8");
        check(".html", "text/html; charset=UTF-8");
        check(".png", "image/png");

        // fall back to octet-stream.
        check(".zzz", "application/octet-stream");
        check("", "application/octet-stream");
    }

    void
    testToFile()
    {
        temp_file dest("");
        fs::remove(dest.path);

        auto r = test::response_factory()
            .body({ "frag1", "frag2", "frag3" })
            .create();

        corosio::io_context ioc;
        capy::run_async(
            ioc.get_executor(),
            [&](capy::io_result<fs::path> res)
            {
                BOOST_TEST(!get<0>(res));
                BOOST_TEST_EQ(get<1>(res), dest.path);
                BOOST_TEST_EQ(read_file(dest.path), "frag1frag2frag3");
            })(r.try_as<fs::path>(dest.path));
        ioc.run();
    }

    void
    testToFileExistingFile()
    {
        temp_file dest("original contents");

        auto r = test::response_factory()
            .body({ "replacement" })
            .create();

        corosio::io_context ioc;
        capy::run_async(
            ioc.get_executor(),
            [&](capy::io_result<fs::path> res)
            {
                BOOST_TEST(get<0>(res));
                BOOST_TEST_EQ(get<1>(res), "");
                BOOST_TEST_EQ(read_file(dest.path), "original contents");
            })(r.try_as<fs::path>(dest.path));
        ioc.run();
    }

    void
    testToFileTruncated()
    {
        temp_file dest("");
        fs::remove(dest.path);

        auto r = test::response_factory()
            .content_length(64)
            .body({ "Payl" })
            .create();

        corosio::io_context ioc;
        capy::run_async(
            ioc.get_executor(),
            [&](capy::io_result<fs::path> res)
            {
                BOOST_TEST_EQ(get<0>(res), http::error::incomplete);
                BOOST_TEST_EQ(get<1>(res), dest.path);
                BOOST_TEST_EQ(read_file(dest.path), "Payl");
            })(r.try_as<fs::path>(dest.path));
        ioc.run();
    }

    void
    run()
    {
        testFromFile();
        testFromFileMissingFile();
        testFromFileContentTypeDeduction();
        testToFile();
        testToFileExistingFile();
        testToFileTruncated();
    }
};

TEST_SUITE(file_test, "boost.burl.file");

} // namespace burl
} // namespace boost
