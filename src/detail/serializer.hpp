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

#include <boost/burl/error.hpp>

#include <boost/capy/buffers/buffer_copy.hpp>
#include <boost/capy/buffers/buffer_param.hpp>
#include <boost/capy/io/any_write_stream.hpp>
#include <boost/capy/io_task.hpp>
#include <boost/capy/write.hpp>
#include <boost/http/message_base.hpp>

namespace boost
{
namespace burl
{
namespace detail
{

class serializer
{
public:
    struct encoder
    {
        struct result
        {
            std::size_t consumed;
            std::size_t produced;
            std::error_code ec;
        };

        virtual ~encoder() = default;

        virtual result
        process(
            capy::mutable_buffer out,
            capy::const_buffer in,
            bool eof) = 0;
    };

    struct config
    {
        std::size_t out_buffer  = 64 * 1024;
        std::size_t min_prepare =  4 * 1024;
        std::size_t direct_thr  =  2 * 1024;
        std::size_t enc_buffer  =  8 * 1024;
        std::size_t enc_thr     =  4 * 1024;
    };

    serializer(
        config const& cfg,
        capy::any_write_stream* stream = nullptr);

    serializer(serializer&& other) noexcept;

    serializer&
    operator=(serializer&& other) noexcept;

    serializer(const serializer&) = delete;

    serializer&
    operator=(const serializer&) = delete;

    ~serializer();

    bool
    is_done() const noexcept
    {
        return done_;
    }

    capy::any_write_stream*
    stream() const noexcept
    {
        return stream_;
    }

    http::message_base*
    message() const noexcept
    {
        return msg_;
    }

    void
    reset(
        capy::any_write_stream* stream,
        http::message_base* msg,
        encoder* enc = nullptr,
        bool head = false) noexcept;

    void
    reset(
        http::message_base* msg,
        encoder* enc = nullptr,
        bool head = false) noexcept
    {
        BOOST_ASSERT(stream_);
        reset(stream_, msg, enc, head);
    }

    template<capy::ConstBufferSequence Buffers>
    capy::io_task<std::size_t>
    write_some(Buffers buffers);

    template<capy::ConstBufferSequence Buffers>
    capy::io_task<std::size_t>
    write(Buffers buffers);

    template<capy::ConstBufferSequence Buffers>
    capy::io_task<std::size_t>
    write_eof(Buffers buffers);

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
    capacity() const noexcept;

    capy::mutable_buffer
    do_prepare() noexcept;

    void
    do_commit(std::size_t n) noexcept;

    bool
    should_coalesce(std::size_t avail) const noexcept;

    void
    finalize(std::size_t remaining) noexcept;

    void
    decide_framing(std::size_t remaining) noexcept;

    capy::io_task<std::size_t>
    process(
        std::span<capy::const_buffer const> tail,
        bool eof);

    capy::io_task<std::size_t>
    encode(
        std::span<capy::const_buffer const> tail,
        bool eof);

    capy::io_task<std::size_t>
    flush(
        std::span<capy::const_buffer const> tail,
        bool eof);

    // TODO: replace this with capy's version
    capy::io_task<std::size_t>
    write_at_least(
        std::span<capy::const_buffer const> buffers,
        std::size_t bytes);

    static constexpr std::size_t margin = 24;

    capy::any_write_stream* stream_;
    http::message_base* msg_ = nullptr;
    encoder* enc_ = nullptr;
    std::size_t min_prepare_;
    std::size_t direct_thr_;
    std::size_t enc_thr_;
    unsigned char* out_;
    std::size_t out_cap_;
    std::size_t out_len_ = 0;
    unsigned char* in_;
    std::size_t in_cap_;
    std::size_t in_len_ = 0;
    std::uint64_t total_body_ = 0;
    bool head_ = false;
    bool enc_started_ = false;
    bool hdr_sent_ = false;
    bool done_ = false;
};

template<capy::ConstBufferSequence Buffers>
capy::io_task<std::size_t>
serializer::
write_some(Buffers buffers)
{
    auto const avail = capy::buffer_size(buffers);
    if(should_coalesce(avail))
    {
        do_commit(capy::buffer_copy(do_prepare(), buffers));
        co_return { {}, avail };
    }
    co_return co_await process(
        capy::buffer_param(buffers).data(), false);
}

template<capy::ConstBufferSequence Buffers>
capy::io_task<std::size_t>
serializer::
write(Buffers buffers)
{
    return capy::write(*this, std::move(buffers));
}

template<capy::ConstBufferSequence Buffers>
capy::io_task<std::size_t>
serializer::
write_eof(Buffers buffers)
{
    finalize(capy::buffer_size(buffers));
    capy::buffer_param bp(buffers);
    std::size_t sum = 0;
    for(;;)
    {
        bool eof = !bp.more();
        auto [ec, n] = co_await process(bp.data(), eof);
        sum += n;
        bp.consume(n);
        if(ec || eof)
            co_return { ec, sum };
    }
}

} // namespace detail
} // namespace burl
} // namespace boost

#endif
