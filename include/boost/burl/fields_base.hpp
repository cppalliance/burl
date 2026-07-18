//
// Copyright (c) 2021 Vinnie Falco (vinnie.falco@gmail.com)
// Copyright (c) 2026 Mohammad Nejati
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

#ifndef BOOST_BURL_FIELDS_BASE_HPP
#define BOOST_BURL_FIELDS_BASE_HPP

#include <boost/burl/detail/config.hpp>

#include <boost/assert.hpp>
#include <boost/http/field.hpp>

#include <compare>
#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <iosfwd>
#include <iterator>
#include <string_view>

namespace boost
{
namespace burl
{

/** Mixin for HTTP fields.

    This type provides the observers, lookup
    functions, and modifiers shared by every
    container of HTTP fields. The fields are held in
    storage supplied by the derived container, where
    each field is a `name: value` line terminated by
    CRLF and the sequence ends with the final empty
    line. This wire form is available from
    @ref buffer.

    Fields are kept in insertion order, and more than
    one field may have the same name. When a name
    matches a known field, the corresponding constant
    is stored with it regardless of how the field was
    added; lookups by id compare constants and never
    examine the stored names, while lookups by string
    compare names case-insensitively.

    Names and values are stored verbatim: no
    normalization, folding, or validation is
    performed. Modifiers throw `std::length_error`
    when the storage cannot grow, or when a size
    limit would be exceeded; see @ref max_name_size,
    @ref max_value_size, @ref max_field_count, and
    @ref max_buffer_size.

    Iterators refer to positions, while views refer
    to characters in the storage. Each modifier
    documents which iterators and views it
    invalidates.

    Users cannot construct, copy, or destroy objects
    of this type: they are obtained by reference from
    a derived container. This makes the type useful
    for writing algorithms which operate on any
    container of fields:

    @code
    void print_host( fields_base const& f )
    {
        std::cout << f.value_or(
            http::field::host, "(none)" );
    }
    @endcode

    @see
        @ref fields,
        @ref static_fields,
        @ref message_head_base.
*/
class fields_base
{
public:
    //--------------------------------------------
    //
    // Types
    //
    //--------------------------------------------

    /** A view to an HTTP field.

        Objects of this type are returned when
        dereferencing an iterator. The views are
        invalidated when the underlying container
        is modified.

        They are also formed implicitly from the
        elements of an initializer list when
        constructing a @ref fields container; the
        field name may be given as a string or as
        a field constant:

        @code
        fields f = {
            { http::field::host, "example.com" },
            { "X-Request-Id", "42" },
        };
        @endcode

        The caller is responsible for ensuring
        that the lifetime of the viewed characters
        extends until the view is no longer
        referenced.
    */
    struct field_view
    {
        /// A view to the field name, as stored
        std::string_view name;

        /// A view to the field value
        std::string_view value;

        /// The field name constant
        http::field id;

        /** Constructor.

            @param name_ The field name.

            @param value_ The field value.
        */
        field_view(
            std::string_view name_,
            std::string_view value_) noexcept
            : name(name_)
            , value(value_)
            , id(unknown_field)
        {
        }

        /** Constructor.

            @param id_ The field name constant.

            @param value_ The field value.
        */
        field_view(
            http::field id_,
            std::string_view value_) noexcept
            : name(http::to_string(id_))
            , value(value_)
            , id(id_)
        {
            BOOST_ASSERT(id_ != unknown_field);
        }

    private:
        friend class fields_base;

        field_view(
            std::string_view name_,
            std::string_view value_,
            http::field id_) noexcept
            : name(name_)
            , value(value_)
            , id(id_)
        {
        }
    };

    /** A random-access iterator to HTTP fields.

        Dereferencing returns a @ref field_view by
        value; the views it holds point into the
        container.

        The iterator is invalidated when the
        underlying container is modified.
    */
    class iterator
    {
        fields_base const* f_ = nullptr;
        std::uint16_t i_ = 0;

        friend class fields_base;

        iterator(
            fields_base const* f,
            std::uint16_t i) noexcept
            : f_(f)
            , i_(i)
        {
        }

    public:
        using value_type        = fields_base::field_view;
        using reference         = fields_base::field_view;
        using difference_type   = std::ptrdiff_t;
        using pointer           = void;
        using iterator_category = std::input_iterator_tag;
        using iterator_concept  = std::random_access_iterator_tag;

        /// Proxy returned by `operator->`
        struct arrow
        {
            fields_base::field_view ref;

            fields_base::field_view const*
            operator->() const noexcept
            {
                return &ref;
            }
        };

        iterator() = default;

        reference
        operator*() const noexcept
        {
            return f_->ref_(i_);
        }

        arrow
        operator->() const noexcept
        {
            return arrow{ f_->ref_(i_) };
        }

        reference
        operator[](difference_type n) const noexcept
        {
            return f_->ref_(
                static_cast<std::uint16_t>(i_ + n));
        }

        iterator&
        operator++() noexcept
        {
            ++i_;
            return *this;
        }

        iterator
        operator++(int) noexcept
        {
            auto it = *this;
            ++i_;
            return it;
        }

        iterator&
        operator--() noexcept
        {
            --i_;
            return *this;
        }

        iterator
        operator--(int) noexcept
        {
            auto it = *this;
            --i_;
            return it;
        }

        iterator&
        operator+=(difference_type n) noexcept
        {
            i_ = static_cast<std::uint16_t>(i_ + n);
            return *this;
        }

        iterator&
        operator-=(difference_type n) noexcept
        {
            i_ = static_cast<std::uint16_t>(i_ - n);
            return *this;
        }

        friend iterator
        operator+(
            iterator it,
            difference_type n) noexcept
        {
            it += n;
            return it;
        }

        friend iterator
        operator+(
            difference_type n,
            iterator it) noexcept
        {
            it += n;
            return it;
        }

        friend iterator
        operator-(
            iterator it,
            difference_type n) noexcept
        {
            it -= n;
            return it;
        }

        friend difference_type
        operator-(
            iterator const& a,
            iterator const& b) noexcept
        {
            return static_cast<difference_type>(a.i_) -
                static_cast<difference_type>(b.i_);
        }

        bool
        operator==(iterator const& other) const noexcept = default;

        std::strong_ordering
        operator<=>(iterator const& other) const noexcept
        {
            BOOST_ASSERT(f_ == other.f_);
            return i_ <=> other.i_;
        }
    };

    /// @copydoc iterator
    using const_iterator = iterator;

    /** A reverse random-access iterator to HTTP fields.
     */
    using reverse_iterator = std::reverse_iterator<iterator>;

    /// @copydoc reverse_iterator
    using const_reverse_iterator = reverse_iterator;

    /** A forward range of values for all matching fields.

        Objects of this type are returned by
        @ref find_all. Dereferencing an iterator
        returns the field value as a
        `std::string_view`.

        Advancing skips fields whose name differs;
        when the fields are known, only field ids
        are compared and the field names are never
        touched.

        The range is invalidated when the
        underlying container is modified.
    */
    class subrange
    {
        fields_base const* f_ = nullptr;
        std::uint16_t i_ = 0;

        friend class fields_base;

        subrange(
            fields_base const* f,
            std::uint16_t i) noexcept
            : f_(f)
            , i_(i)
        {
        }

    public:
        /// A forward iterator over the values
        class iterator
        {
            fields_base const* f_ = nullptr;
            std::uint16_t i_ = 0;

            friend class subrange;

            iterator(
                fields_base const* f,
                std::uint16_t i) noexcept
                : f_(f)
                , i_(i)
            {
            }

        public:
            using value_type        = std::string_view;
            using reference         = std::string_view;
            using difference_type   = std::ptrdiff_t;
            using pointer           = void;
            using iterator_category = std::input_iterator_tag;
            using iterator_concept  = std::forward_iterator_tag;

            iterator() = default;

            std::string_view
            operator*() const noexcept
            {
                return f_->ref_(i_).value;
            }

            BOOST_BURL_DECL
            iterator&
            operator++() noexcept;

            iterator
            operator++(int) noexcept
            {
                auto it = *this;
                ++*this;
                return it;
            }

            bool
            operator==(iterator const& other) const noexcept = default;
        };

        /// @copydoc iterator
        using const_iterator = iterator;

        /// The type of each element
        using value_type = std::string_view;

        /** Constructor.

            Default-constructed subranges are empty.
        */
        subrange() = default;

        /// Return an iterator to the beginning
        iterator
        begin() const noexcept
        {
            return iterator(f_, i_);
        }

        /// Return an iterator to the end
        iterator
        end() const noexcept
        {
            return iterator(f_, f_ ? f_->count_ : 0);
        }

        /// Return true if the range is empty
        bool
        empty() const noexcept
        {
            return f_ == nullptr || i_ == f_->count_;
        }
    };

    /** The type of each element.

        This is an alias for @ref field_view:
        elements are views, and copying one does
        not copy the underlying characters.
    */
    using value_type = field_view;

    /// The type used to represent sizes
    using size_type = std::size_t;

    /// The type used to represent iterator distances
    using difference_type = std::ptrdiff_t;

    /// Maximum allowed name size
    static constexpr std::size_t max_name_size = 65535;

    /// Maximum allowed value size
    static constexpr std::size_t max_value_size = 65535;

    /// Maximum allowed number of fields
    static constexpr std::size_t max_field_count = 65535;

    /// Maximum allowed size of the header
    static constexpr std::size_t max_buffer_size = 0x7FFFFFFF;

    /// Maximum allowed size of the start line
    static constexpr std::size_t max_start_line_size = 65535;

    /** Return the size of the storage space, in bytes.

        @par Complexity
        Constant.
    */
    std::size_t
    capacity_in_bytes() const noexcept
    {
        return std::size_t(end_ - base_());
    }

    //--------------------------------------------
    //
    // Observers
    //
    //--------------------------------------------

    /** Return a string view representing the field section.

        The returned view references every field
        line followed by the final empty line:

        @code
        "Host: example.com\r\nAccept: text/html\r\n\r\n"
        @endcode

        Header containers provide their own
        @ref message_head_base::buffer which additionally
        includes the start line.

        The view is invalidated when the container
        is modified.

        @par Complexity
        Constant.
    */
    std::string_view
    buffer() const noexcept
    {
        return { buf_, size_ };
    }

    /** Format the fields to an output stream.

        Each field is written as `name: value`
        followed by a newline:

        @code
        "Host: example.com\nAccept: text/html\n"
        @endcode

        This form is for diagnostics; the wire
        form is available from @ref buffer.

        @par Complexity
        Linear in `f.buffer().size()`.

        @par Exception Safety
        Basic guarantee.

        @return A reference to the output stream.

        @param os The output stream to write to.

        @param f The container to write.
    */
    friend
    BOOST_BURL_DECL
    std::ostream&
    operator<<(
        std::ostream& os,
        fields_base const& f);

    /** Return the number of fields in the container.

        @par Complexity
        Constant.
    */
    std::size_t
    size() const noexcept
    {
        return count_;
    }

    /** Return true if the container has no fields.

        @par Complexity
        Constant.
    */
    bool
    empty() const noexcept
    {
        return count_ == 0;
    }

    /** Return an iterator to the beginning.
     */
    iterator
    begin() const noexcept
    {
        return iterator(this, 0);
    }

    /** Return an iterator to the end.
     */
    iterator
    end() const noexcept
    {
        return iterator(this, count_);
    }

    /** Return a reverse iterator to the beginning.
     */
    reverse_iterator
    rbegin() const noexcept
    {
        return reverse_iterator(end());
    }

    /** Return a reverse iterator to the end.
     */
    reverse_iterator
    rend() const noexcept
    {
        return reverse_iterator(begin());
    }

    //--------------------------------------------
    //
    // Lookup
    //
    //--------------------------------------------

    /** Return an iterator to the matching element if it exists.

        If more than one field with the specified
        name exists, the first field defined by
        insertion order is returned.

        @par Complexity
        Linear in `this->size()`.

        @return An iterator to the field, or
        @ref end if no field matches.

        @param id The field name constant.
    */
    iterator
    find(http::field id) const noexcept
    {
        return iterator(this, find_(0, id));
    }

    /** Return an iterator to the matching element if it exists.

        If more than one field with the specified
        name exists, the first field defined by
        insertion order is returned. The comparison
        is case-insensitive.

        If `name` refers to a known field, it is
        faster to call @ref find with a field id
        instead of a string.

        @par Complexity
        Linear in `this->size()`.

        @return An iterator to the field, or
        @ref end if no field matches.

        @param name The field name.
    */
    iterator
    find(std::string_view name) const noexcept
    {
        return iterator(this, find_(0, name));
    }

    /** Return an iterator to the matching element if it exists.

        The search starts at `from` and runs
        forwards.

        @par Complexity
        Linear in `this->size()`.

        @return An iterator to the field, or
        @ref end if no field matches.

        @param from The position to begin the
        search from. This can be `end()`.

        @param id The field name constant.
    */
    iterator
    find(
        iterator from,
        http::field id) const noexcept
    {
        BOOST_ASSERT(from.f_ == this);
        return iterator(this, find_(from.i_, id));
    }

    /** Return an iterator to the matching element if it exists.

        The search starts at `from` and runs
        forwards. The comparison is
        case-insensitive.

        If `name` refers to a known field, it is
        faster to call @ref find with a field id
        instead of a string.

        @par Complexity
        Linear in `this->size()`.

        @return An iterator to the field, or
        @ref end if no field matches.

        @param from The position to begin the
        search from. This can be `end()`.

        @param name The field name.
    */
    iterator
    find(
        iterator from,
        std::string_view name) const noexcept
    {
        BOOST_ASSERT(from.f_ == this);
        return iterator(this, find_(from.i_, name));
    }

    /** Return an iterator to the last matching element if it exists.

        The search runs backwards, beginning with
        the field immediately preceding `before`.

        @par Complexity
        Linear in `this->size()`.

        @return An iterator to the field, or
        @ref end if no field matches.

        @param before One past the position to
        begin the search from. This can be `end()`.

        @param id The field name constant.
    */
    iterator
    find_last(
        iterator before,
        http::field id) const noexcept
    {
        BOOST_ASSERT(before.f_ == this);
        return iterator(this, find_last_(before.i_, id));
    }

    /** Return an iterator to the last matching element if it exists.

        The search runs backwards, beginning with
        the field immediately preceding `before`.
        The comparison is case-insensitive.

        If `name` refers to a known field, it is
        faster to call @ref find_last with a field
        id instead of a string.

        @par Complexity
        Linear in `this->size()`.

        @return An iterator to the field, or
        @ref end if no field matches.

        @param before One past the position to
        begin the search from. This can be `end()`.

        @param name The field name.
    */
    iterator
    find_last(
        iterator before,
        std::string_view name) const noexcept
    {
        BOOST_ASSERT(before.f_ == this);
        return iterator(this, find_last_(before.i_, name));
    }

    /** Return a forward range containing values for all matching fields.

        @par Complexity
        Constant; advancing the iterators of the
        returned range is linear in `this->size()`.

        @param id The field name constant.
    */
    subrange
    find_all(http::field id) const noexcept
    {
        return subrange(this, find_(0, id));
    }

    /** Return a forward range containing values for all matching fields.

        If `name` refers to a known field, it is
        faster to call @ref find_all with a field
        id instead of a string.

        @par Complexity
        Constant; advancing the iterators of the
        returned range is linear in `this->size()`.

        @param name The field name.
    */
    subrange
    find_all(std::string_view name) const noexcept
    {
        return subrange(this, find_(0, name));
    }

    /** Return the value of a field or a default if missing.

        If more than one field with the specified
        name exists, the value of the first field
        defined by insertion order is returned.

        @par Complexity
        Linear in `this->size()`.

        @param id The field name constant.

        @param s The value to be returned if the
        field does not exist.
    */
    std::string_view
    value_or(
        http::field id,
        std::string_view s) const noexcept
    {
        auto const i = find_(0, id);
        if(i != count_)
            return ref_(i).value;
        return s;
    }

    /** Return the value of a field or a default if missing.

        If more than one field with the specified
        name exists, the value of the first field
        defined by insertion order is returned.

        If `name` refers to a known field, it is
        faster to call @ref value_or with a field
        id instead of a string.

        @par Complexity
        Linear in `this->size()`.

        @param name The field name.

        @param s The value to be returned if the
        field does not exist.
    */
    std::string_view
    value_or(
        std::string_view name,
        std::string_view s) const noexcept
    {
        auto const i = find_(0, name);
        if(i != count_)
            return ref_(i).value;
        return s;
    }

    /** Return the value of a field, or throw an exception.

        If more than one field with the specified
        name exists, the value of the first field
        defined by insertion order is returned.

        @par Complexity
        Linear in `this->size()`.

        @par Exception Safety
        Strong guarantee.

        @throw std::out_of_range
        Field is not found.

        @param id The field name constant.
    */
    BOOST_BURL_DECL
    std::string_view
    at(http::field id) const;

    /** Return the value of a field, or throw an exception.

        If more than one field with the specified
        name exists, the value of the first field
        defined by insertion order is returned.

        If `name` refers to a known field, it is
        faster to call @ref at with a field id
        instead of a string.

        @par Complexity
        Linear in `this->size()`.

        @par Exception Safety
        Strong guarantee.

        @throw std::out_of_range
        Field is not found.

        @param name The field name.
    */
    BOOST_BURL_DECL
    std::string_view
    at(std::string_view name) const;

    /** Return the number of matching fields.

        @par Complexity
        Linear in `this->size()`.

        @param id The field name constant.
    */
    BOOST_BURL_DECL
    std::size_t
    count(http::field id) const noexcept;

    /** Return the number of matching fields.

        If `name` refers to a known field, it is
        faster to call @ref count with a field id
        instead of a string.

        @par Complexity
        Linear in `this->size()`.

        @param name The field name.
    */
    BOOST_BURL_DECL
    std::size_t
    count(std::string_view name) const noexcept;

    /** Return true if a field exists.

        @par Complexity
        Linear in `this->size()`.

        @param id The field name constant.
    */
    bool
    contains(http::field id) const noexcept
    {
        return find_(0, id) != count_;
    }

    /** Return true if a field exists.

        If `name` refers to a known field, it is
        faster to call @ref contains with a field
        id instead of a string.

        @par Complexity
        Linear in `this->size()`.

        @param name The field name.
    */
    bool
    contains(std::string_view name) const noexcept
    {
        return find_(0, name) != count_;
    }

    //--------------------------------------------
    //
    // Modifiers
    //
    //--------------------------------------------

    /** Append a field.

        This function appends a new field using
        the canonical name of `id`. Existing
        fields with the same name are not changed.

        The value is stored verbatim.

        All references and views are invalidated.
        No iterators are invalidated.

        @par Example
        @code
        f.append( http::field::user_agent, "Boost" );
        @endcode

        @par Complexity
        Linear in `to_string( id ).size() + value.size()`,
        amortized.

        @par Exception Safety
        Strong guarantee.
        Exception thrown if the storage cannot
        grow, or if a size limit would be
        exceeded.

        @throw std::length_error
        The storage cannot accommodate the field;
        see @ref max_name_size, @ref max_value_size,
        @ref max_field_count, and @ref max_buffer_size.

        @param id The field name constant.

        @param value The field value.
    */
    void
    append(
        http::field id,
        std::string_view value)
    {
        BOOST_ASSERT(id != unknown_field);
        insert_(
            count_,
            static_cast<std::uint16_t>(id),
            http::to_string(id),
            value);
    }

    /** Append a field.

        This function appends a new field.
        Existing fields with the same name are not
        changed.

        The name and value are stored verbatim.
        When `name` equals a known field name, the
        corresponding field constant is stored
        with it, and subsequent lookups by id
        succeed regardless of how the field was
        added.

        All references and views are invalidated.
        No iterators are invalidated.

        @par Example
        @code
        f.append( "User-Agent", "Boost" );
        @endcode

        @par Complexity
        Linear in `name.size() + value.size()`,
        amortized.

        @par Exception Safety
        Strong guarantee.
        Exception thrown if the storage cannot
        grow, or if a size limit would be
        exceeded.

        @throw std::length_error
        The storage cannot accommodate the field;
        see @ref max_name_size, @ref max_value_size,
        @ref max_field_count, and @ref max_buffer_size.

        @param name The field name.

        @param value The field value.
    */
    void
    append(
        std::string_view name,
        std::string_view value)
    {
        insert_(count_, resolve_(name), name, value);
    }

    /** Append fields.

        This function appends the fields in `init`
        in order, as if by calling @ref append for
        each element. Existing fields with the same
        names are not changed.

        The names and values are stored verbatim.

        All references and views are invalidated.
        No iterators are invalidated.

        @par Example
        @code
        f.append({
            { http::field::host, "example.com" },
            { "User-Agent", "Boost" } });
        @endcode

        @par Complexity
        Linear in the total size of the names and
        values in `init`.

        @par Exception Safety
        Strong guarantee.
        Exception thrown if the storage cannot
        grow, or if a size limit would be
        exceeded.

        @throw std::length_error
        The storage cannot accommodate the fields;
        see @ref max_name_size, @ref max_value_size,
        @ref max_field_count, and @ref max_buffer_size.

        @param init The fields to append.
    */
    BOOST_BURL_DECL
    void
    append(std::initializer_list<field_view> init);

    /** Insert a field.

        If a matching field with the same name
        exists, it is not replaced. Instead, an
        additional field is inserted using the
        canonical name of `id`.

        The value is stored verbatim.

        All references and views are invalidated, as
        are iterators at or after `before`.

        @par Example
        @code
        f.insert( f.begin(), http::field::user_agent, "Boost" );
        @endcode

        @par Complexity
        Linear in `to_string( id ).size() + value.size()`
        plus the size of the fields after `before`.

        @par Exception Safety
        Strong guarantee.
        Exception thrown if the storage cannot
        grow, or if a size limit would be
        exceeded.

        @throw std::length_error
        The storage cannot accommodate the field;
        see @ref max_name_size, @ref max_value_size,
        @ref max_field_count, and @ref max_buffer_size.

        @return An iterator to the newly inserted field.

        @param before Position to insert before.

        @param id The field name constant.

        @param value The field value.
    */
    iterator
    insert(
        iterator before,
        http::field id,
        std::string_view value)
    {
        BOOST_ASSERT(before.f_ == this);
        BOOST_ASSERT(id != unknown_field);
        return iterator(
            this,
            insert_(
                before.i_,
                static_cast<std::uint16_t>(id),
                http::to_string(id),
                value));
    }

    /** Insert a field.

        If a matching field with the same name
        exists, it is not replaced. Instead, an
        additional field with the same name is
        inserted.

        The name and value are stored verbatim.
        When `name` equals a known field name, the
        corresponding field constant is stored
        with it, and subsequent lookups by id
        succeed regardless of how the field was
        added.

        All references and views are invalidated, as
        are iterators at or after `before`.

        @par Example
        @code
        f.insert( f.begin(), "User-Agent", "Boost" );
        @endcode

        @par Complexity
        Linear in `name.size() + value.size()`
        plus the size of the fields after `before`.

        @par Exception Safety
        Strong guarantee.
        Exception thrown if the storage cannot
        grow, or if a size limit would be
        exceeded.

        @throw std::length_error
        The storage cannot accommodate the field;
        see @ref max_name_size, @ref max_value_size,
        @ref max_field_count, and @ref max_buffer_size.

        @return An iterator to the newly inserted field.

        @param before Position to insert before.

        @param name The field name.

        @param value The field value.
    */
    iterator
    insert(
        iterator before,
        std::string_view name,
        std::string_view value)
    {
        BOOST_ASSERT(before.f_ == this);
        return iterator(this, insert_(before.i_, resolve_(name), name, value));
    }

    /** Set a field value.

        Uses the given value to overwrite the
        current one in the field pointed to by
        the iterator. No other fields are
        affected.

        The value is stored verbatim.

        All references and views are invalidated.
        No iterators are invalidated.

        @par Complexity
        Linear in `this->buffer().size()`.

        @par Exception Safety
        Strong guarantee.
        Exception thrown if the storage cannot
        grow, or if a size limit would be
        exceeded.

        @throw std::length_error
        The storage cannot accommodate the value;
        see @ref max_value_size and
        @ref max_buffer_size.

        @param it The iterator to the field. Must
        be dereferenceable.

        @param value The field value.
    */
    void
    set(
        iterator it,
        std::string_view value)
    {
        BOOST_ASSERT(it.f_ == this);
        BOOST_ASSERT(it.i_ < count_);
        replace_value_(it.i_, value);
    }

    /** Set a field value, removing duplicates.

        The container is modified to contain
        exactly one field with the specified id
        set to the given value: if a matching
        field exists, its value is replaced in
        place and the remaining duplicates are
        removed; otherwise the field is appended.

        The value is stored verbatim.

        All references and views are invalidated.
        Iterators at or after the first removed
        duplicate are invalidated; if there are no
        duplicates, no iterators are invalidated.

        @par Postconditions
        @code
        this->count( id ) == 1 && this->at( id ) == value
        @endcode

        @par Complexity
        Linear in `this->buffer().size()`.

        @par Exception Safety
        Strong guarantee.
        Exception thrown if the storage cannot
        grow, or if a size limit would be
        exceeded.

        @throw std::length_error
        The storage cannot accommodate the value;
        see @ref max_value_size and
        @ref max_buffer_size.

        @param id The field name constant.

        @param value The field value.
    */
    BOOST_BURL_DECL
    void
    set(
        http::field id,
        std::string_view value);

    /** Set a field value, removing duplicates.

        The container is modified to contain
        exactly one field with the specified name
        set to the given value: if a matching
        field exists, its value is replaced in
        place and the remaining duplicates are
        removed; otherwise the field is appended.
        The comparison is case-insensitive.

        The name and value are stored verbatim.

        All references and views are invalidated.
        Iterators at or after the first removed
        duplicate are invalidated; if there are no
        duplicates, no iterators are invalidated.

        @par Postconditions
        @code
        this->count( name ) == 1 && this->at( name ) == value
        @endcode

        @par Complexity
        Linear in `this->buffer().size()`.

        @par Exception Safety
        Strong guarantee.
        Exception thrown if the storage cannot
        grow, or if a size limit would be
        exceeded.

        @throw std::length_error
        The storage cannot accommodate the field;
        see @ref max_name_size, @ref max_value_size,
        @ref max_field_count, and @ref max_buffer_size.

        @param name The field name.

        @param value The field value.
    */
    BOOST_BURL_DECL
    void
    set(
        std::string_view name,
        std::string_view value);

    /** Erase all matching fields.

        This removes all fields whose name
        constant is equal to `id`.

        If any fields are erased, all references and
        views are invalidated, as are iterators at or
        after the first erased field. Otherwise,
        nothing is invalidated.

        @par Complexity
        Linear in `this->buffer().size()`.

        @return The number of fields erased.

        @param id The field name constant.
    */
    BOOST_BURL_DECL
    std::size_t
    erase(http::field id) noexcept;

    /** Erase all matching fields.

        This removes all fields with a matching
        name, using a case-insensitive comparison.

        If any fields are erased, all references and
        views are invalidated, as are iterators at or
        after the first erased field. Otherwise,
        nothing is invalidated.

        If `name` refers to a known field, it is
        faster to call @ref erase with a field id
        instead of a string.

        @par Complexity
        Linear in `this->buffer().size()`.

        @return The number of fields erased.

        @param name The field name.
    */
    BOOST_BURL_DECL
    std::size_t
    erase(std::string_view name) noexcept;

    /** Erase a field.

        This removes the field pointed to by
        `pos`.

        All references and views are invalidated, as
        are iterators at or after `pos`.

        @par Complexity
        Linear in the size of the fields after
        `pos`.

        @return An iterator to one past the
        removed element.

        @param pos The iterator to the element to
        erase. Must be dereferenceable.
    */
    iterator
    erase(iterator pos) noexcept
    {
        BOOST_ASSERT(pos.f_ == this);
        BOOST_ASSERT(pos.i_ < count_);
        erase_at_(pos.i_);
        return iterator(this, pos.i_);
    }

    /** Erase all fields.

        The start line of header containers is
        preserved. The capacity is unchanged.

        All iterators, references, and views are
        invalidated.

        @par Postconditions
        @code
        this->size() == 0
        @endcode

        @par Complexity
        Constant.
    */
    BOOST_BURL_DECL
    void
    clear() noexcept;

protected:
    struct entry
    {
        std::uint32_t of;
        std::uint16_t id;
        std::uint16_t nn;
        std::uint16_t ws;
        std::uint16_t vn;
    };

    struct piece
    {
        std::size_t at;
        std::string_view src;
    };

    BOOST_BURL_DECL
    fields_base() noexcept;

    fields_base(
        char* base,
        std::size_t cap,
        std::uint32_t size,
        std::uint16_t count,
        std::uint16_t prefix = 0) noexcept
        : buf_(base + prefix)
        , end_(base + cap)
        , size_(size)
        , count_(count)
        , prefix_(prefix)
    {
    }

    fields_base(fields_base const&) = default;

    BOOST_BURL_DECL
    fields_base&
    operator=(fields_base const& other);

    ~fields_base() = default;

    BOOST_BURL_DECL
    void
    swap_(fields_base& other) noexcept;

    virtual
    bool
    static_() const noexcept
    {
        return true;
    }

    virtual
    void
    on_clear_() noexcept
    {
    }

    virtual
    void
    on_special_(http::field) noexcept
    {
    }

    char*
    base_() const noexcept
    {
        return buf_ - prefix_;
    }

    void
    detach_()
    {
        if(default_())
            realloc_(table_space_(count_) + size_ + prefix_);
    }

    BOOST_BURL_DECL
    void
    release_() noexcept;

    BOOST_BURL_DECL
    void
    init_static_(
        char* storage,
        std::size_t n);

    BOOST_BURL_DECL
    char*
    splice_prefix_(
        std::uint32_t pos,
        std::uint32_t old_n,
        std::size_t new_n,
        piece p0 = {},
        piece p1 = {});

    BOOST_BURL_DECL
    void
    assign_(
        fields_base const& other,
        std::uint16_t prefix);

    BOOST_BURL_DECL
    void
    reserve_(
        std::size_t bytes,
        std::size_t count);

    BOOST_BURL_DECL
    void
    shrink_to_fit_();

    entry&
    ent_(std::uint16_t i) const noexcept
    {
        return ent_(tab_(), i);
    }

    BOOST_BURL_DECL
    static std::uint16_t
    resolve_(std::string_view name) noexcept;

    static
    constexpr
    std::size_t
    table_space_(std::size_t count) noexcept
    {
        return sizeof(entry) * count;
    }

    /*
        +------------+--------+------+-----------------------------+
        | start line | fields | free | entry[count-1] ... entry[0] |
        +------------+--------+------+-----------------------------+
        ^            ^        ^                                    ^
        |            buf      buf + size                         end
        buf - prefix
    */

    char* buf_;
    char* end_;
    std::uint32_t size_;
    std::uint16_t count_;
    std::uint16_t prefix_;

private:
    struct alloc;

    void
    adopt_(alloc& a) noexcept;

    constexpr static http::field unknown_field =
        static_cast<http::field>(0);

    bool
    default_() const noexcept
    {
        return end_ == base_();
    }

    bool
    owns_() const noexcept
    {
        return ! default_() && ! static_();
    }

    entry*
    tab_() const noexcept
    {
        return reinterpret_cast<entry*>(end_);
    }

    static entry&
    ent_(
        entry* t,
        std::uint16_t i) noexcept
    {
        return *(t - 1 - static_cast<std::ptrdiff_t>(i));
    }

    field_view
    ref_(std::uint16_t i) const noexcept
    {
        auto const& e = ent_(i);
        return
        {
            { buf_ + e.of, e.nn },
            { buf_ + e.of + e.nn + e.ws, e.vn },
            static_cast<http::field>(e.id)
        };
    }

    std::uint32_t
    line_len_(std::uint16_t i) const noexcept
    {
        auto const of = ent_(i).of;
        if(i + 1 == count_)
            return size_ - 2 - of;
        return ent_(i + 1).of - of;
    }

    char*
    splice_fields_(
        std::uint32_t pos,
        std::uint32_t old_n,
        std::size_t new_n,
        std::uint16_t added,
        piece p0,
        piece p1);

    char*
    splice_(
        std::uint32_t pos,
        std::uint32_t old_n,
        std::size_t new_n,
        std::uint16_t added,
        piece p0,
        piece p1);

    BOOST_BURL_DECL
    void
    realloc_(std::size_t total);

    static void
    fill_(
        char* g,
        piece const& p0,
        piece const& p1) noexcept;

    BOOST_BURL_DECL
    std::uint16_t
    find_(
        std::uint16_t from,
        http::field id) const noexcept;

    BOOST_BURL_DECL
    std::uint16_t
    find_(
        std::uint16_t from,
        std::string_view name) const noexcept;

    BOOST_BURL_DECL
    std::uint16_t
    find_last_(
        std::uint16_t before,
        http::field id) const noexcept;

    BOOST_BURL_DECL
    std::uint16_t
    find_last_(
        std::uint16_t before,
        std::string_view name) const noexcept;

    void
    notify_(std::uint16_t id) noexcept;

    BOOST_BURL_DECL
    std::uint16_t
    insert_(
        std::uint16_t i,
        std::uint16_t id,
        std::string_view name,
        std::string_view value);

    BOOST_BURL_DECL
    void
    replace_value_(
        std::uint16_t i,
        std::string_view value);

    BOOST_BURL_DECL
    void
    erase_at_(std::uint16_t i) noexcept;

    template<class Match>
    std::uint16_t
    erase_all_(
        std::uint16_t i,
        std::uint16_t id,
        Match const& match) noexcept;

    std::uint16_t
    erase_all_(
        std::uint16_t i,
        std::uint16_t id) noexcept;

    std::uint16_t
    erase_all_(
        std::uint16_t i,
        std::string_view name) noexcept;

    void
    erase_dups_(std::uint16_t i) noexcept;
};

} // namespace burl
} // namespace boost

#endif
