//
// Copyright (c) 2026 Mohammad Nejati
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

#ifndef BOOST_BURL_SRC_DETAIL_SEND_FILE_HPP
#define BOOST_BURL_SRC_DETAIL_SEND_FILE_HPP

#include <boost/capy/io_task.hpp>

#include <cstdint>
#include <filesystem>

namespace boost
{
namespace capy
{
class any_buffer_sink;
} // namespace capy

namespace burl
{
namespace detail
{

// Read exactly `size` bytes of `path` and write them into `sink`. Fails
// with error::file_changed if the file no longer holds `size` bytes.
capy::io_task<>
send_file(
    capy::any_buffer_sink& sink,
    std::filesystem::path const& path,
    std::uint64_t size);

} // namespace detail
} // namespace burl
} // namespace boost

#endif
