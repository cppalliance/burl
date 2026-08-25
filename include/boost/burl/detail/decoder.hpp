//
// Copyright (c) 2026 Mohammad Nejati
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

#ifndef BOOST_BURL_DETAIL_DECODER_HPP
#define BOOST_BURL_DETAIL_DECODER_HPP

#include <boost/capy/buffers.hpp>

#include <cstddef>
#include <system_error>

namespace boost
{
namespace burl
{
namespace detail
{

// A content decoder, transforming the payload
// octets as they arrive.
struct decoder
{
    struct result
    {
        // The number of input octets consumed.
        std::size_t consumed;

        // The number of output octets produced.
        std::size_t produced;

        // The error, if any. Set to `capy::error::eof`
        // once the decoder has produced the complete
        // output.
        std::error_code ec;
    };

    virtual ~decoder() = default;

    // Transform payload octets. `more` is false when
    // `in` ends the payload.
    virtual result
    process(
        capy::mutable_buffer out,
        capy::const_buffer in,
        bool more) = 0;
};

} // namespace detail
} // namespace burl
} // namespace boost

#endif
