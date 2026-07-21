//
// Copyright (c) 2026 Mohammad Nejati
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

#ifndef BOOST_BURL_TEST_DETAIL_BUFFER_CONNECTION_HPP
#define BOOST_BURL_TEST_DETAIL_BUFFER_CONNECTION_HPP

#include <boost/burl/detail/connection_pool.hpp>

#include <boost/capy/buffers/buffer_copy.hpp>
#include <boost/capy/buffers/make_buffer.hpp>
#include <boost/capy/error.hpp>
#include <boost/capy/io_task.hpp>
#include <boost/capy/test/fuse.hpp>
#include <boost/capy/buffers/buffer_slice.hpp>

#include <cstddef>
#include <string>
#include <vector>

namespace boost
{
namespace burl
{
namespace test
{
namespace detail
{

class buffer_connection final : public burl::detail::connection
{
    std::string head_;
    std::vector<std::string> chunks_;
    capy::test::fuse fuse_;
    std::size_t head_pos_ = 0;
    std::size_t idx_ = 0;
    std::size_t pos_ = 0;

public:
    buffer_connection(
        std::vector<std::string> chunks,
        capy::test::fuse fuse,
        std::string head = {})
        : head_(std::move(head))
        , chunks_(std::move(chunks))
        , fuse_(std::move(fuse))
    {
    }

    bool
    is_open() const noexcept override
    {
        return true;
    }

    // capy::io_task<>
    // shutdown() override
    // {
    //     co_return {};
    // }

private:
    capy::io_task<std::size_t>
    do_read_some(std::span<capy::mutable_buffer const> bufs) override
    {
        if(head_pos_ < head_.size())
        {
            auto const b = capy::make_buffer(head_);
            auto const n = capy::buffer_copy(
                bufs, capy::buffer_slice(b, head_pos_));
            head_pos_ += n;
            co_return { {}, n };
        }

        if(auto ec = fuse_.maybe_fail())
            co_return { ec, 0 };

        if(idx_ >= chunks_.size())
            co_return { capy::error::eof, 0 };

        auto const b = capy::make_buffer(chunks_[idx_]);
        auto const n = capy::buffer_copy(
            bufs, capy::buffer_slice(b, pos_));
        pos_ += n;
        if(pos_ == b.size())
        {
            ++idx_;
            pos_ = 0;
        }
        co_return { {}, n };
    }

    capy::io_task<std::size_t>
    do_write_some(std::span<capy::const_buffer const>) override
    {
        co_return { capy::error::eof, 0 };
    }
};

} // namespace detail
} // namespace test
} // namespace burl
} // namespace boost

#endif
