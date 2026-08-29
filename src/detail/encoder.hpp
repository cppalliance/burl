//
// Copyright (c) 2026 Mohammad Nejati
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

#ifndef BOOST_BURL_SRC_DETAIL_ENCODER_HPP
#define BOOST_BURL_SRC_DETAIL_ENCODER_HPP

#include <boost/burl/encoder_config.hpp>

#include <boost/capy/buffers.hpp>
#include <boost/http/metadata.hpp>

#include <cstddef>
#include <memory>
#include <system_error>

namespace boost
{
namespace burl
{
namespace detail
{

struct encoder
{
    struct result
    {
        std::size_t consumed;
        std::size_t produced;
        std::error_code ec;
    };

    virtual ~encoder() = default;

    virtual result
    process(
        capy::mutable_buffer out,
        capy::const_buffer in,
        bool more) = 0;
};

std::unique_ptr<encoder>
make_encoder(
    http::content_coding coding,
    encoder_config const& cfg);

} // namespace detail
} // namespace burl
} // namespace boost

#endif
