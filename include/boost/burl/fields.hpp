//
// Copyright (c) 2021 Vinnie Falco (vinnie.falco@gmail.com)
// Copyright (c) 2026 Mohammad Nejati
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

#ifndef BOOST_BURL_FIELDS_HPP
#define BOOST_BURL_FIELDS_HPP

#include <boost/burl/detail/config.hpp>
#include <boost/burl/fields_base.hpp>

#include <initializer_list>

namespace boost
{
namespace burl
{

/** A dynamic container of HTTP fields.

    This container owns a sequence of HTTP fields in
    a single allocation which grows as needed.

    A default-constructed container refers to a static
    two-byte buffer holding the final "\r\n" and does
    not allocate.

    @see @ref fields_base for the shared observers,
    lookup functions, and modifiers.
*/
class fields : public fields_base
{
public:
    //--------------------------------------------
    //
    // Special members
    //
    //--------------------------------------------

    /** Constructor.

        The container is empty and does not
        allocate; @ref buffer returns "\r\n".

        @par Postconditions
        @code
        this->capacity_in_bytes() == 0
        @endcode

        @par Complexity
        Constant.
    */
    BOOST_BURL_DECL
    fields() noexcept;

    /** Destructor.

        Any allocated memory is released. All
        iterators, references, and views obtained
        from the container are invalidated.

        @par Complexity
        Constant.
    */
    BOOST_BURL_DECL
    ~fields();

    /** Constructor.

        The container acquires ownership of the
        contents of `other`, which is left in its
        default-constructed state. Views obtained
        from `other` remain valid; its iterators
        are invalidated.

        @par Postconditions
        @code
        other.capacity_in_bytes() == 0
        @endcode

        @par Complexity
        Constant.
    */
    BOOST_BURL_DECL
    fields(fields&& other) noexcept;

    /** Constructor.

        The contents of `other` are copied into
        an exact-fit allocation. No allocation
        occurs when `other` is empty.

        @par Complexity
        Linear in `other.buffer().size()`.

        @par Exception Safety
        Strong guarantee.
        Calls to allocate may throw.
    */
    BOOST_BURL_DECL
    fields(fields const& other);

    /** Constructor.

        The field section of `other` is copied into
        an exact-fit allocation. When `other` is a
        message header, only its fields are copied;
        the start line is discarded. No allocation
        occurs when `other` is empty.

        This constructor is `explicit`: converting a
        non-owning view into an owning container
        allocates, and discarding a header's start
        line should be deliberate.

        @par Complexity
        Linear in `other.buffer().size()`.

        @par Exception Safety
        Strong guarantee.
        Calls to allocate may throw.

        @param other The fields to copy.
    */
    BOOST_BURL_DECL
    explicit
    fields(fields_base const& other);

    /** Constructor.

        The container is constructed with a copy
        of the fields in `init`, equivalent to
        calling @ref append for each element in
        order. Duplicate names are allowed and
        their relative order is preserved.

        The storage is allocated exactly once.
        No allocation occurs when `init` is
        empty.

        @par Example
        @code
        fields f = {
            { http::field::host, "example.com" },
            { "X-Request-Id", "42" },
        };
        @endcode

        @par Complexity
        Linear in the total size of the names
        and values in `init`.

        @par Exception Safety
        Strong guarantee.
        Calls to allocate may throw.
        Exception thrown if a size limit would be
        exceeded.

        @throw std::length_error
        A size limit would be exceeded; see
        @ref max_name_size, @ref max_value_size,
        and @ref max_buffer_size.

        @param init The fields to insert.
    */
    BOOST_BURL_DECL
    fields(std::initializer_list<field_view> init);

    /** Assignment.

        The container acquires ownership of the
        contents of `other`, which is left in its
        default-constructed state. The previous
        contents are destroyed.

        @par Complexity
        Constant.
    */
    BOOST_BURL_DECL
    fields&
    operator=(fields&& other) noexcept;

    /** Assignment.

        The contents are replaced with a copy of
        `other`. The existing allocation is reused
        when it is large enough.

        @par Complexity
        Linear in `other.buffer().size()`.

        @par Exception Safety
        Strong guarantee.
        Calls to allocate may throw.
    */
    BOOST_BURL_DECL
    fields&
    operator=(fields const& other);

    /** Assignment.

        The contents are replaced with a copy of the
        field section of `other`. When `other` is a
        message header, only its fields are copied;
        the start line is discarded.

        @par Complexity
        Linear in `other.buffer().size()`.

        @par Exception Safety
        Strong guarantee.
        Calls to allocate may throw.

        @param other The fields to copy.
    */
    BOOST_BURL_DECL
    fields&
    operator=(fields_base const& other);

    /** Swap the contents.

        The contents of the two containers are
        exchanged. No allocation occurs and no
        bytes are copied.

        Views obtained from either container remain
        valid; they follow the contents into the
        other container. Iterators are invalidated:
        an iterator stays bound to the container it
        was obtained from, which now holds different
        fields.

        If `this == &other`, this function call has
        no effect.

        @par Complexity
        Constant.

        @par Exception Safety
        No-throw guarantee.

        @param other The container to swap with.
    */
    BOOST_BURL_DECL
    void
    swap(fields& other) noexcept;

    /** Swap the contents.

        The contents of the two containers are
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

        @param v0 The first container to swap.

        @param v1 The second container to swap.

        @see @ref fields::swap
    */
    friend
    void
    swap(
        fields& v0,
        fields& v1) noexcept
    {
        v0.swap(v1);
    }

    //--------------------------------------------
    //
    // Capacity
    //
    //--------------------------------------------

    /** Reserve storage.

        This function ensures that @ref buffer
        can grow to `bytes` bytes, and the
        number of fields to `count`, without
        a reallocation. Has no effect if the
        current capacity is already sufficient.

        All references and views are invalidated
        when a reallocation occurs.

        @par Exception Safety
        Strong guarantee.
        Calls to allocate may throw.
        Exception thrown if a size limit would be
        exceeded.

        @throw std::length_error
        `bytes` exceeds @ref max_buffer_size, or
        `count` exceeds @ref max_field_count.

        @param bytes The serialized size in bytes.

        @param count The number of fields.
    */
    BOOST_BURL_DECL
    void
    reserve(
        std::size_t bytes,
        std::size_t count);

    /** Remove excess capacity.

        An empty container releases its
        allocation entirely.

        All references and views are invalidated
        when a reallocation occurs.

        @par Exception Safety
        Strong guarantee.
        Calls to allocate may throw.
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
