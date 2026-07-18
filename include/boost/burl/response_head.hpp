//
// Copyright (c) 2021 Vinnie Falco (vinnie.falco@gmail.com)
// Copyright (c) 2026 Mohammad Nejati
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

#ifndef BOOST_BURL_RESPONSE_HEAD_HPP
#define BOOST_BURL_RESPONSE_HEAD_HPP

#include <boost/burl/detail/config.hpp>
#include <boost/burl/response_head_base.hpp>

#include <cstddef>

namespace boost
{
namespace burl
{

/** A dynamic container for an HTTP response header.

    This container builds a response header in a single
    allocation which grows as needed, mirroring
    @ref fields for the field section while adding the
    status line. It owns its storage and never runs
    out of room.

    A default-constructed object holds the default
    status line ("HTTP/1.1 200 OK") and no fields;
    the status line and fields are filled in through
    the inherited @ref response_head_base interface.
    Like @ref fields, a default-constructed object is a
    non-owning view over a shared buffer and does not
    allocate until it is first modified.

    @ref message_head_base::buffer returns the complete
    header bytes ready for the wire.

    @see
        @ref static_response_head,
        @ref response_head_base.
*/
class response_head : public response_head_base
{
public:
    /** Constructor.

        The header holds the default status line and
        no fields. No allocation is performed until the
        header is first modified.

        @par Exception Safety
        No-throw guarantee.
    */
    BOOST_BURL_DECL
    response_head() noexcept;

    /** Destructor.

        Releases the allocation. All views obtained
        from the header are invalidated.
    */
    BOOST_BURL_DECL
    ~response_head();

    /** Constructor.

        The container acquires ownership of the
        contents of `other`, which is left in a
        valid but unspecified state and must not be
        used except to be destroyed or assigned to.

        @par Complexity
        Constant.
    */
    BOOST_BURL_DECL
    response_head(response_head&& other) noexcept;

    /** Constructor.

        The contents of `other` are copied into an
        exact-fit allocation.

        @par Complexity
        Linear in `other.buffer().size()`.

        @par Exception Safety
        Strong guarantee. Calls to allocate may throw.
    */
    BOOST_BURL_DECL
    response_head(response_head const& other);

    /** Constructor.

        The contents of `other` are copied into an
        exact-fit allocation, taking ownership of a
        header that may otherwise refer to external
        storage, such as the one produced by
        @ref head_parser.

        The conversion is lossless and implicit: an
        owning @ref response_head carries exactly the
        state of a @ref response_head_base.

        @par Complexity
        Linear in `other.buffer().size()`.

        @par Exception Safety
        Strong guarantee. Calls to allocate may throw.

        @param other The header to copy.
    */
    BOOST_BURL_DECL
    response_head(response_head_base const& other);

    /** Constructor.

        The header holds a status line with the given
        status code and version, and no fields. The
        reason-phrase is set to the standard text for
        the status code.

        @par Exception Safety
        Strong guarantee. Calls to allocate may throw.

        @throw std::length_error
        The storage cannot accommodate the status line.

        @param sc The status code. Must have an
        integer value in [100, 999].

        @param v The version.
    */
    explicit
    response_head(
        http::status sc,
        http::version v =
            http::version::http_1_1)
        : response_head()
    {
        set_start_line(sc, v);
    }

    /** Assignment.

        The container acquires ownership of the
        contents of `other`, which is left in a
        valid but unspecified state. The previous
        contents are released.

        @par Complexity
        Constant.
    */
    BOOST_BURL_DECL
    response_head&
    operator=(response_head&& other) noexcept;

    /** Assignment.

        The contents are replaced with a copy of
        `other`.

        @par Complexity
        Linear in `other.buffer().size()`.

        @par Exception Safety
        Strong guarantee. Calls to allocate may throw.
    */
    BOOST_BURL_DECL
    response_head&
    operator=(response_head const& other);

    /** Assignment.

        The contents are replaced with a copy of
        `other`, taking ownership of a header that
        may otherwise refer to external storage.

        @par Complexity
        Linear in `other.buffer().size()`.

        @par Exception Safety
        Strong guarantee. Calls to allocate may throw.

        @param other The header to copy.
    */
    BOOST_BURL_DECL
    response_head&
    operator=(response_head_base const& other);

    /** Swap the contents.

        The contents of the two headers are
        exchanged. No allocation occurs and no
        bytes are copied.

        Views obtained from either header remain
        valid; they follow the contents into the
        other header. Iterators are invalidated: an
        iterator stays bound to the header it was
        obtained from, which now holds different
        fields.

        If `this == &other`, this function call has
        no effect.

        @par Complexity
        Constant.

        @par Exception Safety
        No-throw guarantee.

        @param other The header to swap with.
    */
    BOOST_BURL_DECL
    void
    swap(response_head& other) noexcept;

    /** Swap the contents.

        The contents of the two headers are
        exchanged. No allocation occurs and no
        bytes are copied.

        If `&v0 == &v1`, this function call has no
        effect.

        @par Effects
        @code
        v0.swap(v1);
        @endcode

        @par Complexity
        Constant.

        @par Exception Safety
        No-throw guarantee.

        @param v0 The first header to swap.

        @param v1 The second header to swap.

        @see @ref response_head::swap
    */
    friend
    void
    swap(
        response_head& v0,
        response_head& v1) noexcept
    {
        v0.swap(v1);
    }

    /** Reserve storage.

        Ensures the field section can grow to `bytes`
        bytes and the number of fields to `count`
        without reallocating. Has no effect if the
        current allocation is already sufficient.

        The status line shares the allocation with the
        field section, so a status line larger than the
        one currently stored may still reallocate.

        All views are invalidated when a reallocation
        occurs.

        @par Exception Safety
        Strong guarantee. Calls to allocate may throw.

        @throw std::length_error
        `bytes` exceeds @ref max_buffer_size, or
        `count` exceeds @ref max_field_count.

        @param bytes The serialized field-section size,
        as returned by `fields_base::buffer().size()`.

        @param count The number of fields.
    */
    BOOST_BURL_DECL
    void
    reserve(
        std::size_t bytes,
        std::size_t count);

    /** Remove excess capacity.

        All views are invalidated when a reallocation
        occurs.

        @par Exception Safety
        Strong guarantee. Calls to allocate may throw.
    */
    BOOST_BURL_DECL
    void
    shrink_to_fit();

private:
    bool
    static_() const noexcept override
    {
        return false;
    }
};

} // namespace burl
} // namespace boost

#endif
