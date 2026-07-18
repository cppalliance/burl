//
// Copyright (c) 2021 Vinnie Falco (vinnie.falco@gmail.com)
// Copyright (c) 2026 Mohammad Nejati
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

#ifndef BOOST_BURL_STATIC_FIELDS_HPP
#define BOOST_BURL_STATIC_FIELDS_HPP

#include <boost/burl/detail/config.hpp>
#include <boost/burl/fields_base.hpp>

#include <cstddef>

namespace boost
{
namespace burl
{

/** A static container of HTTP fields.

    This container holds a sequence of HTTP fields
    in an externally provided buffer with fixed
    capacity, and performs no allocations during its
    lifetime. Modifiers throw `std::length_error`
    when the storage is exhausted.

    A newly constructed container is empty;
    @ref buffer returns "\r\n". Fields are filled in
    through the inherited @ref fields_base interface.

    The caller is responsible for ensuring that the
    lifetime of the storage extends until the
    container is destroyed.

    @par Example
    @code
    char buf[256];
    static_fields f(buf, sizeof(buf));

    f.set(http::field::host, "example.com");

    assert(f.buffer() ==
        "Host: example.com\r\n"
        "\r\n");
    @endcode

    @see
        @ref fields,
        @ref fields_base.
*/
class static_fields : public fields_base
{
public:
    /** Constructor.

        The container uses the given storage and
        holds no fields.

        @par Exception Safety
        Strong guarantee.

        @throw std::length_error
        The storage cannot accommodate the empty
        field section.

        @param storage The storage to use.

        @param n The size of the storage.
    */
    BOOST_BURL_DECL
    static_fields(
        char* storage,
        std::size_t n);

    /** Constructor (deleted).
    */
    static_fields(
        static_fields const&) = delete;

    /** Constructor.

        The newly constructed object refers to the
        storage of `other`, which is left in a valid
        but unspecified state where the only safe
        operation is destruction: it no longer refers
        to the storage, and modifiers and assignment
        throw `std::length_error`.

        @par Complexity
        Constant.

        @param other The container to move from.
    */
    BOOST_BURL_DECL
    static_fields(
        static_fields&& other) noexcept;

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

        @param other The fields to copy.

        @return A reference to this object.
    */
    BOOST_BURL_DECL
    static_fields&
    operator=(static_fields const& other);

    /** Assignment.

        The contents are replaced with a copy of the
        field section of `other`. When `other` is a
        message header, only its fields are copied;
        the start line is discarded. The storage is
        retained.

        @par Complexity
        Linear in `other.buffer().size()`.

        @par Exception Safety
        Strong guarantee.

        @throw std::length_error
        The storage cannot accommodate the contents
        of `other`.

        @param other The fields to copy.

        @return A reference to this object.
    */
    BOOST_BURL_DECL
    static_fields&
    operator=(fields_base const& other);

    /** Return the storage size needed for a header.

        Returns the size of a storage which holds a
        field section of `size` bytes and the lookup
        table of `count` fields.

        @par Example
        @code
        char buf[
            static_fields::bytes_needed(1024, 32)];

        static_fields f(buf, sizeof(buf));
        @endcode

        @param size The size of the field section,
        including the final empty line.

        @param count The number of fields.
    */
    static constexpr
    std::size_t
    bytes_needed(
        std::size_t size,
        std::size_t count) noexcept
    {
        if(size < 2)
            size = 2; // "\r\n"

        return size + count * sizeof(entry) +
            alignof(entry) - 1;
    }
};

} // namespace burl
} // namespace boost

#endif
