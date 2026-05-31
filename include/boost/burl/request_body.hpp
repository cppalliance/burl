//
// Copyright (c) 2026 Mohammad Nejati
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

#ifndef BOOST_BURL_REQUEST_BODY_HPP
#define BOOST_BURL_REQUEST_BODY_HPP

#include <boost/burl/detail/config.hpp>

#include <boost/capy/io/any_buffer_sink.hpp>
#include <boost/capy/io_task.hpp>

#include <concepts>
#include <cstdint>
#include <optional>
#include <string>

namespace boost
{
namespace burl
{

/** Concept for a request body.

    A type satisfies `RequestBody` if it can describe and stream the payload of
    a request. The three members are:

    @li `content_type()` returns the value for the `Content-Type` header, or
        an empty `optional` when no `Content-Type` should be sent.
    @li `content_length()` returns the body size in bytes if known ahead of
        time, or an empty `optional` when the body must be sent with chunked
        transfer encoding.
    @li `write(sink)` serializes the body to `sink` incrementally. It writes
        the body bytes but does not signal end-of-stream; the caller finalizes
        the sink once the body has been written.

    @see
        @ref any_request_body,
        @ref body_from_tag.
*/
template<typename T>
concept RequestBody = requires(T const& t, capy::any_buffer_sink& sink) {
    { t.content_type() } -> std::same_as<std::optional<std::string>>;
    { t.content_length() } -> std::same_as<std::optional<std::uint64_t>>;
    { t.write(sink) } -> std::same_as<capy::io_task<>>;
};

} // namespace burl
} // namespace boost

#endif
