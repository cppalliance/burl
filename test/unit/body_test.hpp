//
// Copyright (c) 2026 Mohammad Nejati
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

#ifndef BOOST_BURL_TEST_UNIT_BODY_TEST_HPP
#define BOOST_BURL_TEST_UNIT_BODY_TEST_HPP

#include <boost/burl/any_request_body.hpp>

#include <boost/capy/ex/run_async.hpp>
#include <boost/capy/io/any_buffer_sink.hpp>
#include <boost/capy/task.hpp>
#include <boost/capy/test/buffer_sink.hpp>
#include <boost/capy/test/fuse.hpp>
#include <boost/corosio/io_context.hpp>

#include "test_suite.hpp"

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <string>
#include <string_view>
#include <system_error>

namespace boost
{
namespace burl
{

namespace fs = std::filesystem;

struct temp_file
{
    fs::path path;

    temp_file(
        std::string_view contents,
        std::string_view extension = {})
    {
        path = fs::temp_directory_path() /
            ("burl_test_" +
                std::to_string(std::rand()) +
                std::string(extension));

        std::ofstream ofs(path, std::ios::binary);
        ofs.write(
            contents.data(),
            static_cast<std::streamsize>(contents.size()));
    }

    ~temp_file()
    {
        std::error_code ec;
        fs::remove(path, ec);
    }

    temp_file(temp_file const&) = delete;
    temp_file&
    operator=(temp_file const&) = delete;
};

inline void
check_body(
    any_request_body const& body,
    std::string_view expected)
{
    BOOST_TEST(body.has_value());

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

inline std::error_code
drive_body(
    any_request_body const& body,
    capy::any_buffer_sink& sink)
{
    corosio::io_context ioc;
    std::error_code ret;

    capy::run_async(
        ioc.get_executor(),
        [&](capy::io_result<> res) { ret = res.ec; })(body.write(sink));
    ioc.run();
    return ret;
}

} // namespace burl
} // namespace boost

#endif
