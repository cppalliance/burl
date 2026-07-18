//
// Copyright (c) 2021 Vinnie Falco (vinnie.falco@gmail.com)
// Copyright (c) 2026 Mohammad Nejati
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

#ifndef BOOST_BURL_STATIC_REQUEST_HEAD_HPP
#define BOOST_BURL_STATIC_REQUEST_HEAD_HPP

#include <boost/burl/detail/config.hpp>
#include <boost/burl/request_head_base.hpp>

#include <cstddef>

namespace boost
{
namespace burl
{

/** A static container for an HTTP request header.

    This container builds a request header in an
    externally provided buffer with fixed capacity,
    and performs no allocations during its lifetime.
    Modifiers throw `std::length_error` when the
    storage is exhausted.

    A newly constructed object holds the default
    request line ("GET / HTTP/1.1") and no fields;
    the request line and fields are filled in through
    the inherited @ref request_head_base interface.

    The caller is responsible for ensuring that the
    lifetime of the storage extends until the header
    is destroyed.

    @par Example
    @code
    char buf[256];
    static_request_head h(buf, sizeof(buf));

    h.set_start_line(http::method::get, "/");
    h.set(http::field::host, "example.com");

    assert(h.buffer() ==
        "GET / HTTP/1.1\r\n"
        "Host: example.com\r\n"
        "\r\n");
    @endcode

    @see
        @ref request_head,
        @ref request_head_base.
*/
class static_request_head : public request_head_base
{
public:
    /** Constructor.

        The header uses the given storage and holds
        the default request line and no fields.

        @par Exception Safety
        Strong guarantee.

        @throw std::length_error
        The storage cannot accommodate the default
        request line.

        @param storage The storage to use.

        @param n The size of the storage.
    */
    BOOST_BURL_DECL
    static_request_head(
        char* storage,
        std::size_t n);

    /** Constructor (deleted).
    */
    static_request_head(
        static_request_head const&) = delete;

    /** Constructor.

        The newly constructed object refers to the
        storage of `other`, which is left in a valid
        but unspecified state where the only safe
        operation is destruction: it no longer refers
        to the storage, and modifiers and assignment
        throw `std::length_error`.

        @par Complexity
        Constant.

        @param other The header to move from.
    */
    BOOST_BURL_DECL
    static_request_head(
        static_request_head&& other) noexcept;

    /** Assignment.

        The contents are replaced with a copy of
        `other`. The storage is retained.

        @par Complexity
        Linear in `other.buffer().size()`.

        @par Exception Safety
        Strong guarantee.

        @throw std::length_error
        The storage cannot accommodate the contents
        of `other`.

        @param other The header to copy.

        @return A reference to this object.
    */
    BOOST_BURL_DECL
    static_request_head&
    operator=(static_request_head const& other);

    /** Assignment.

        The contents are replaced with a copy of
        `other`, which may be an owning
        @ref request_head or a header produced by
        @ref head_parser. The storage is retained.

        @par Complexity
        Linear in `other.buffer().size()`.

        @par Exception Safety
        Strong guarantee.

        @throw std::length_error
        The storage cannot accommodate the contents
        of `other`.

        @param other The header to copy.

        @return A reference to this object.
    */
    BOOST_BURL_DECL
    static_request_head&
    operator=(request_head_base const& other);

    /** Return the storage size needed for a header.

        Returns the size of a storage which holds a
        head of `size` bytes and the lookup table of
        `count` fields.

        @par Example
        @code
        char buf[
            static_request_head::bytes_needed(1024, 32)];

        static_request_head h(buf, sizeof(buf));
        @endcode

        @param size The size of the head, from the
        request line through the final empty line.

        @param count The number of fields.
    */
    static constexpr
    std::size_t
    bytes_needed(
        std::size_t size,
        std::size_t count) noexcept
    {
        if(size < 18)
            size = 18; // "GET / HTTP/1.1\r\n\r\n"

        return size + count * sizeof(entry) +
            alignof(entry) - 1;
    }
};

} // namespace burl
} // namespace boost

#endif
