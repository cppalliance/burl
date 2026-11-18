//
// Copyright (c) 2026 Mohammad Nejati
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

#ifndef BOOST_BURL_DETAIL_BUFFERS_CURSOR_HPP
#define BOOST_BURL_DETAIL_BUFFERS_CURSOR_HPP

#include <boost/capy/buffers.hpp>

#include <cstddef>
#include <iterator>
#include <utility>

namespace boost
{
namespace burl
{
namespace detail
{

/** The unconsumed bytes of a buffer sequence.

    The cursor is itself a buffer sequence over
    the bytes not yet consumed, so it can be passed
    wherever the whole remainder is needed. Only
    the first buffer it yields is shortened.

    It refers to the sequence it was constructed
    from, which must outlive it. @ref consume
    invalidates its iterators.

    @tparam BS The sequence type.
*/
template<capy::ConstBufferSequence BS>
class buffers_cursor
{
    using iter_type = decltype(capy::buffer_sequence_begin(
        std::declval<BS const&>()));

public:
    using value_type = capy::buffer_type<BS>;

    class const_iterator
    {
        friend buffers_cursor;

        iter_type it_{};
        iter_type first_{};
        std::size_t skip_ = 0;

        const_iterator(
            iter_type it,
            iter_type first,
            std::size_t skip) noexcept
            : it_(it)
            , first_(first)
            , skip_(skip)
        {
        }

    public:
        using iterator_category = std::bidirectional_iterator_tag;
        using value_type = buffers_cursor::value_type;
        using difference_type = std::ptrdiff_t;
        using pointer = value_type const*;
        using reference = value_type;

        const_iterator() = default;

        value_type
        operator*() const noexcept
        {
            value_type b(*it_);
            if(it_ == first_)
                b += skip_;
            return b;
        }

        const_iterator&
        operator++() noexcept
        {
            ++it_;
            return *this;
        }

        const_iterator
        operator++(int) noexcept
        {
            auto t = *this;
            ++it_;
            return t;
        }

        const_iterator&
        operator--() noexcept
        {
            --it_;
            return *this;
        }

        const_iterator
        operator--(int) noexcept
        {
            auto t = *this;
            --it_;
            return t;
        }

        bool
        operator==(const_iterator const& other) const noexcept
        {
            return it_ == other.it_;
        }
    };

    /** Constructor.

        @param bs The sequence to consume. It must
        outlive the cursor.
    */
    explicit
    buffers_cursor(BS const& bs) noexcept
        : first_(capy::buffer_sequence_begin(bs))
        , last_(capy::buffer_sequence_end(bs))
    {
    }

    buffers_cursor(BS const&&) = delete;

    const_iterator
    begin() const noexcept
    {
        return { first_, first_, skip_ };
    }

    const_iterator
    end() const noexcept
    {
        return { last_, first_, skip_ };
    }

    /** Remove bytes from the front.

        @param n The number of bytes to remove;
        at most all of them are.
    */
    void
    consume(std::size_t n) noexcept
    {
        while(n != 0 && first_ != last_)
        {
            auto const avail =
                value_type(*first_).size() - skip_;
            if(n < avail)
            {
                skip_ += n;
                return;
            }
            n -= avail;
            ++first_;
            skip_ = 0;
        }
    }

private:
    iter_type first_;
    iter_type last_;
    std::size_t skip_ = 0;
};

} // namespace detail
} // namespace burl
} // namespace boost

#endif
