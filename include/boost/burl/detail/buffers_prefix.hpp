//
// Copyright (c) 2026 Mohammad Nejati
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

#ifndef BOOST_BURL_DETAIL_BUFFERS_PREFIX_HPP
#define BOOST_BURL_DETAIL_BUFFERS_PREFIX_HPP

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

/** The leading bytes of a buffer sequence.

    The prefix is itself a buffer sequence over at
    most a given number of bytes from the front of
    another. Only the last buffer it yields is
    shortened.

    It refers to the sequence it was constructed
    from, which must outlive it.

    @tparam BS The sequence type.
*/
template<capy::ConstBufferSequence BS>
class buffers_prefix
{
    using iter_type = decltype(capy::buffer_sequence_begin(
        std::declval<BS const&>()));

public:
    using value_type = capy::buffer_type<BS>;

    class const_iterator
    {
        friend buffers_prefix;

        iter_type it_{};
        iter_type back_{};
        std::size_t size_ = 0;

        const_iterator(
            iter_type it,
            iter_type back,
            std::size_t size) noexcept
            : it_(it)
            , back_(back)
            , size_(size)
        {
        }

    public:
        using iterator_category = std::bidirectional_iterator_tag;
        using value_type = buffers_prefix::value_type;
        using difference_type = std::ptrdiff_t;
        using pointer = value_type const*;
        using reference = value_type;

        const_iterator() = default;

        value_type
        operator*() const noexcept
        {
            value_type b(*it_);
            if(it_ == back_)
                b = value_type(b.data(), size_);
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

        @param bs The sequence to view. It must
        outlive the prefix.

        @param max_bytes The most bytes the prefix
        covers.
    */
    buffers_prefix(
        BS const& bs,
        std::size_t max_bytes) noexcept
        : first_(capy::buffer_sequence_begin(bs))
        , last_(first_)
    {
        auto const end = capy::buffer_sequence_end(bs);
        while(last_ != end && max_bytes != 0)
        {
            auto const n = value_type(*last_).size();
            if(n >= max_bytes)
            {
                back_ = last_++;
                size_ = max_bytes;
                return;
            }
            max_bytes -= n;
            ++last_;
        }
        back_ = last_;
    }

    buffers_prefix(
        BS const&&,
        std::size_t) = delete;

    const_iterator
    begin() const noexcept
    {
        return { first_, back_, size_ };
    }

    const_iterator
    end() const noexcept
    {
        return { last_, back_, size_ };
    }

private:
    iter_type first_;
    iter_type last_;

    // the buffer to shorten and its size, or
    // last_ if the prefix ends with the sequence
    iter_type back_{};
    std::size_t size_ = 0;
};

} // namespace detail
} // namespace burl
} // namespace boost

#endif
