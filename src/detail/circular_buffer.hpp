//
// Copyright (c) 2026 Mohammad Nejati
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

#ifndef BOOST_BURL_SRC_DETAIL_CIRCULAR_BUFFER_HPP
#define BOOST_BURL_SRC_DETAIL_CIRCULAR_BUFFER_HPP

#include <boost/capy/buffers.hpp>

#include <array>
#include <cstddef>

namespace boost
{
namespace burl
{
namespace detail
{

struct circular_buffer
{
    char* ptr = nullptr;
    std::size_t cap = 0;
    std::size_t pos = 0;
    std::size_t len = 0;

    bool
    empty() const noexcept;

    std::size_t
    size() const noexcept;

    std::array<capy::const_buffer, 2>
    data() const noexcept;

    std::array<capy::mutable_buffer, 2>
    prepare() const noexcept;

    void
    commit(std::size_t n) noexcept;

    void
    consume(std::size_t n) noexcept;
};

} // namespace detail
} // namespace burl
} // namespace boost

#endif
