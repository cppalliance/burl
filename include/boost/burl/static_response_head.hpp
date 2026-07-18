//
// Copyright (c) 2021 Vinnie Falco (vinnie.falco@gmail.com)
// Copyright (c) 2026 Mohammad Nejati
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

#ifndef BOOST_BURL_STATIC_RESPONSE_HEAD_HPP
#define BOOST_BURL_STATIC_RESPONSE_HEAD_HPP

#include <boost/burl/detail/config.hpp>
#include <boost/burl/response_head_base.hpp>

#include <cstddef>

namespace boost
{
namespace burl
{

/** A static container for an HTTP response header.

    This container builds a response header in an
    externally provided buffer with fixed capacity,
    and performs no allocations during its lifetime.
    Modifiers throw `std::length_error` when the
    storage is exhausted.

    A newly constructed object holds the default
    status line ("HTTP/1.1 200 OK") and no fields;
    the status line and fields are filled in through
    the inherited @ref response_head_base interface.

    The caller is responsible for ensuring that the
    lifetime of the storage extends until the header
    is destroyed.

    @par Example
    @code
    char buf[256];
    static_response_head h(buf, sizeof(buf));

    h.set_start_line(http::status::not_found);
    h.set(http::field::content_type, "text/html");

    assert(h.buffer() ==
        "HTTP/1.1 404 Not Found\r\n"
        "Content-Type: text/html\r\n"
        "\r\n");
    @endcode

    @see
        @ref response_head,
        @ref response_head_base.
*/
class static_response_head : public response_head_base
{
public:
    /** Constructor.

        The header uses the given storage and holds
        the default status line and no fields.

        @par Exception Safety
        Strong guarantee.

        @throw std::length_error
        The storage cannot accommodate the default
        status line.

        @param storage The storage to use.

        @param n The size of the storage.
    */
    BOOST_BURL_DECL
    static_response_head(
        char* storage,
        std::size_t n);

    /** Constructor (deleted).
    */
    static_response_head(
        static_response_head const&) = delete;

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
    static_response_head(
        static_response_head&& other) noexcept;

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
    static_response_head&
    operator=(static_response_head const& other);

    /** Assignment.

        The contents are replaced with a copy of
        `other`, which may be an owning
        @ref response_head or a header produced by
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
    static_response_head&
    operator=(response_head_base const& other);

    /** Return the storage size needed for a header.

        Returns the size of a storage which holds a
        head of `size` bytes and the lookup table of
        `count` fields.

        @par Example
        @code
        char buf[
            static_response_head::bytes_needed(1024, 32)];

        static_response_head h(buf, sizeof(buf));
        @endcode

        @param size The size of the head, from the
        status line through the final empty line.

        @param count The number of fields.
    */
    static constexpr
    std::size_t
    bytes_needed(
        std::size_t size,
        std::size_t count) noexcept
    {
        if(size < 19)
            size = 19; // "HTTP/1.1 200 OK\r\n\r\n"

        return size + count * sizeof(entry) +
            alignof(entry) - 1;
    }

};

} // namespace burl
} // namespace boost

#endif
