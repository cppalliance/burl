//
// Copyright (c) 2026 Mohammad Nejati
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

#ifndef BOOST_BURL_SRC_DETAIL_UTIL_HPP
#define BOOST_BURL_SRC_DETAIL_UTIL_HPP

#include <cstddef>
#include <filesystem>
#include <limits>
#include <string_view>
#include <optional>

namespace boost
{
namespace burl
{

class response;

namespace detail
{

template<class UInt>
std::size_t
clamp(
    UInt x,
    std::size_t limit = (std::numeric_limits<std::size_t>::max)()) noexcept
{
    if(x >= limit)
        return limit;
    return static_cast<std::size_t>(x);
}

std::optional<std::string>
extract_filename_form_content_disposition(std::string_view sv);

// Resolve the destination path for writing a response body. If `dest` is a
// directory, derive a filename from the Content-Disposition header, falling
// back to the URL's last path segment, then to "index.html". Otherwise `dest`
// is returned unchanged.
std::filesystem::path
resolve_dest(response& resp, std::filesystem::path dest);

} // namespace detail
} // namespace burl
} // namespace boost

#endif
