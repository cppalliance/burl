//
// Copyright (c) 2026 Mohammad Nejati
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

#ifndef BOOST_BURL_SRC_DETAIL_SERIALIZER_HPP
#define BOOST_BURL_SRC_DETAIL_SERIALIZER_HPP

#include <boost/http/request_base.hpp>

#include <boost/capy/buffers.hpp>
#include <boost/capy/buffers/buffer_copy.hpp>
#include <boost/capy/buffers/buffer_param.hpp>
#include <boost/capy/buffers/buffer_slice.hpp>
#include <boost/capy/io/any_write_stream.hpp>
#include <boost/capy/io_task.hpp>

namespace boost
{
namespace burl
{
namespace detail
{

class serializer
{
public:
    struct config
    {
        std::size_t buffer_size = 64 * 1024;
        std::size_t min_prepare = 32 * 1024;
        std::size_t min_direct  =  8 * 1024;
    };

    serializer(
        capy::any_write_stream& stream,
        http::request_base& req)
        : serializer(stream, req, {})
    {
    }

    serializer(
        capy::any_write_stream& stream,
        http::request_base& req,
        config cfg);

    ~serializer();

    bool
    is_done() const noexcept
    {
        return done_;
    }

    template<capy::ConstBufferSequence Buffers>
    capy::io_task<std::size_t>
    write_some(Buffers buffers)
    {
        auto const avail = capy::buffer_size(buffers);

        if(avail < cfg_.min_direct)
        {
            if(avail >= capacity())
                if(auto [ec, _] = co_await drain({}, false); ec)
                    co_return { ec, 0 };
            auto n = capy::buffer_copy(writable(), buffers);
            avail_ += n;
            co_return { {}, n };
        }

        capy::const_buffer_param<Buffers> bp(buffers);
        co_return co_await drain(bp.data(), false);
    }

    template<capy::ConstBufferSequence Buffers>
    capy::io_task<std::size_t>
    write(Buffers buffers)
    {
        auto const avail = capy::buffer_size(buffers);
        auto slice = capy::buffer_slice(buffers);
        std::size_t written = 0;
        while(written < avail)
        {
            auto [ec, n] = co_await write_some(slice.data());
            written += n;
            if(ec)
                co_return { ec, written };
            slice.remove_prefix(n);
        }
        co_return { {}, avail };
    }

    template<capy::ConstBufferSequence Buffers>
    capy::io_task<std::size_t>
    write_eof(Buffers buffers)
    {
        decide_framing(capy::buffer_size(buffers));

        capy::const_buffer_param<Buffers> bp(buffers);

        if(!bp.more())
            co_return co_await drain(bp.data(), true);

        auto [ec1, n] = co_await write(buffers);
        if(ec1)
            co_return { ec1, n };
        auto [ec2, _] = co_await drain({}, true);
        co_return { ec2, n };
    }

    capy::io_task<>
    write_eof();

    std::span<capy::mutable_buffer>
    prepare(std::span<capy::mutable_buffer> dest);

    capy::io_task<>
    commit(std::size_t n);

    capy::io_task<>
    commit_eof(std::size_t n);

private:
    std::size_t
    capacity() const noexcept
    {
        return cfg_.buffer_size - avail_;
    }

    capy::mutable_buffer
    writable() const noexcept
    {
        return { storage_ + avail_, capacity() };
    }

    void
    decide_framing(std::size_t remaining) noexcept;

    capy::io_task<std::size_t>
    drain(
        std::span<capy::const_buffer const> tail,
        bool eof);

    // TODO: replace this with capy's version
    capy::io_task<std::size_t>
    write_at_least(
        std::span<capy::const_buffer> buffers,
        std::size_t bytes);

    capy::const_buffer
    chunk_frame(std::size_t tail_size) noexcept;

    static constexpr std::size_t margin = 24;

    capy::any_write_stream& stream_;
    http::request_base& req_;
    config cfg_;
    unsigned char* storage_;
    std::uint64_t total_body_ = 0;
    std::size_t avail_ = 0;
    bool hdr_sent_ = false;
    bool done_ = false;
};

} // namespace detail
} // namespace burl
} // namespace boost

#endif
