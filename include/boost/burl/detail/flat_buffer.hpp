//
// Copyright (c) 2026 Mohammad Nejati
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

#ifndef BOOST_BURL_DETAIL_FLAT_BUFFER_HPP
#define BOOST_BURL_DETAIL_FLAT_BUFFER_HPP

#include <boost/capy/buffers.hpp>

#include <cstddef>

namespace boost
{
namespace burl
{
namespace detail
{

struct flat_buffer
{
    char* ptr = nullptr;
    std::size_t cap = 0;
    std::size_t pos = 0;
    std::size_t len = 0;

    bool
    empty() const noexcept;

    bool
    full() const noexcept;

    std::size_t
    size() const noexcept;

    std::size_t
    capacity() const noexcept;

    capy::const_buffer
    data() const noexcept;

    capy::mutable_buffer
    prepare() const noexcept;

    void
    commit(std::size_t n) noexcept;

    void
    consume(std::size_t n) noexcept;

    void
    clear() noexcept;
};

} // namespace detail
} // namespace burl
} // namespace boost

#endif
