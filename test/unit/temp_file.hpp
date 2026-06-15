//
// Copyright (c) 2026 Mohammad Nejati
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

#ifndef BOOST_BURL_TEST_UNIT_TEMP_FILE_HPP
#define BOOST_BURL_TEST_UNIT_TEMP_FILE_HPP

#include <filesystem>
#include <fstream>
#include <string_view>

namespace boost
{
namespace burl
{

struct temp_file
{
    std::filesystem::path path;

    temp_file(
        std::string_view contents,
        std::string_view extension = {})
    {
        path = std::filesystem::temp_directory_path() /
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
        std::filesystem::remove(path, ec);
    }

    temp_file(temp_file const&) = delete;
    temp_file&
    operator=(temp_file const&) = delete;
};

} // namespace burl
} // namespace boost

#endif
