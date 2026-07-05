//
// Copyright (c) 2026 Mohammad Nejati
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

#include "serializer.hpp"

#include <boost/assert.hpp>
#include <boost/capy/cond.hpp>
#include <boost/capy/buffers/make_buffer.hpp>

namespace boost
{
namespace burl
{
namespace detail
{

serializer::
serializer(
    capy::any_write_stream* stream,
    http::message_base* msg,
    encoder* enc,
    config cfg)
    : stream_(stream)
    , msg_(msg)
    , enc_(enc)
    , cfg_(cfg)
    , buf_(new unsigned char[
        cfg_.buffer_size +
        (enc ? enc->buffer_size : 0) + margin] + margin)
{
}

serializer::
serializer(serializer&& other) noexcept
    : stream_(other.stream_)
    , msg_(other.msg_)
    , enc_(other.enc_)
    , cfg_(other.cfg_)
    , buf_(other.buf_)
    , out_len_(other.out_len_)
    , in_len_(other.in_len_)
    , total_body_(other.total_body_)
    , enc_started_(other.enc_started_)
    , shifted_(other.shifted_)
    , hdr_sent_(other.hdr_sent_)
    , done_(other.done_)
{
    other.buf_ = nullptr;
}

serializer&
serializer::
operator=(serializer&& other) noexcept
{
    if(this == &other)
        return *this;
    this->~serializer();
    return *new(this) serializer(std::move(other));
}

serializer::
~serializer()
{
    if(buf_)
        delete[](buf_ -
            (shifted_ ? cfg_.buffer_size : 0) - margin);
}

bool
serializer::
is_done() const noexcept
{
    return done_;
}

capy::io_task<>
serializer::
write_eof()
{
    return commit_eof(0);
}

std::span<capy::mutable_buffer>
serializer::
prepare(std::span<capy::mutable_buffer> dest)
{
    if(dest.empty() || capacity() == 0)
        return dest.first(0);
    dest[0] = do_prepare();
    return dest.first(1);
}

capy::io_task<>
serializer::
commit(std::size_t n)
{
    BOOST_ASSERT(n <= capacity());
    do_commit(n);
    if(capacity() >= cfg_.min_prepare)
        co_return {};
    auto [ec, _] = co_await process({}, false);
    co_return { ec };
}

capy::io_task<>
serializer::
commit_eof(std::size_t n)
{
    BOOST_ASSERT(n <= capacity());
    do_commit(n);
    finalize(0);
    auto [ec, _] = co_await process({}, true);
    co_return { ec };
}

std::size_t
serializer::
capacity() const noexcept
{
    if(enc_)
        return enc_->buffer_size - in_len_;

    return cfg_.buffer_size - out_len_;
}

capy::mutable_buffer
serializer::
do_prepare() noexcept
{
    if(enc_)
        return { buf_ + cfg_.buffer_size + in_len_,
            enc_->buffer_size - in_len_ };

    return { buf_ + out_len_,
        cfg_.buffer_size - out_len_ };
}

void
serializer::
do_commit(std::size_t n) noexcept
{
    if(enc_)
        in_len_ += n;
    else
        out_len_ += n;
}

bool
serializer::
can_coalesce(std::size_t avail) const noexcept
{
    if(avail > capacity())
        return false;
    if(enc_)
        return !enc_started_ && avail + in_len_ < enc_->threshold;
    return avail < cfg_.direct_thr;
}

void
serializer::
finalize(std::size_t remaining) noexcept
{
    if(enc_)
    {
        if(enc_started_)
            return;

        if(remaining + in_len_ >= enc_->threshold)
            return;

        msg_->erase(http::field::content_encoding);
        enc_ = nullptr;
        out_len_ = in_len_;
        buf_ += cfg_.buffer_size;
        shifted_ = true;
    }
    decide_framing(remaining);
}

void
serializer::
decide_framing(std::size_t remaining) noexcept
{
    if(!msg_->chunked() || hdr_sent_)
        return;

    BOOST_ASSERT(total_body_ == 0);
    msg_->erase(http::field::transfer_encoding);
    msg_->set_content_length(out_len_ + remaining);
}

capy::io_task<std::size_t>
serializer::
process(
    std::span<capy::const_buffer const> tail,
    bool eof)
{
    if(enc_)
        return encode(tail, eof);
    return flush(tail, eof);
}

capy::io_task<std::size_t>
serializer::
encode(
    std::span<capy::const_buffer const> tail,
    bool eof)
{
    std::size_t n = 0;
    std::size_t consumed = 0;
    capy::const_buffer in = { buf_ + cfg_.buffer_size, in_len_ };
    for(;;)
    {
        if(in.size() == 0)
        {
            if(n != tail.size())
                in = tail[n++];
            else if(!eof)
                co_return { {}, consumed };
        }

        if(cfg_.buffer_size - out_len_ == 0)
        {
            if(auto [ec, _] = co_await flush({}, false); ec)
                co_return { ec, consumed };
        }

        capy::mutable_buffer out =
            { buf_ + out_len_, cfg_.buffer_size - out_len_ };

        auto r = enc_->process(
            out, in, eof && n == tail.size());
        enc_started_ = true;
        out_len_ += r.produced;
        in += r.consumed;
        if(in_len_ != 0)
            in_len_ -= r.consumed;
        else
            consumed += r.consumed;

        if(r.ec)
        {
            if(r.ec == capy::cond::eof)
            {
                decide_framing(0);
                auto [ec, _] = co_await flush({}, true);
                co_return { ec, consumed };
            }
            else
            {
                co_return { r.ec, consumed };
            }
        }

        if(!eof && consumed != 0)
            co_return { {}, consumed };
    }
}

capy::io_task<std::size_t>
serializer::
flush(
    std::span<capy::const_buffer const> tail,
    bool eof)
{
    auto const tail_size = capy::buffer_size(tail);
    auto const chunked = msg_->chunked();
    BOOST_ASSERT(eof || out_len_ + tail_size != 0);
    BOOST_ASSERT(tail.size() <= capy::detail::max_iovec_);

    capy::const_buffer vec[capy::detail::max_iovec_ + 3];
    std::size_t n = 0;
    std::size_t sum = 0;
    auto const append = [&](capy::const_buffer b)
    {
        vec[n++] = b;
        sum += b.size();
    };

    if(!hdr_sent_)
        append(capy::make_buffer(msg_->buffer()));

    if(chunked)
    {
        append(chunk_frame(tail_size));
    }
    else
    {
        auto const declared =
            msg_->payload() == http::payload::size
                ? msg_->payload_size() : 0;
        auto const produced = total_body_ + out_len_ + tail_size;

        if(produced > declared || (eof && produced != declared))
            co_return { error::body_size_mismatch, 0 };

        if(out_len_ != 0)
            append({ buf_, out_len_ });
    }

    auto const owned = sum;

    for(auto& b : tail)
        append(b);

    if(chunked && eof)
        append({ "\r\n0\r\n\r\n", out_len_ || tail_size ? 7u : 2u });

    auto const need = chunked || eof ? sum : owned + (tail_size != 0);
    auto [ec, written] = co_await write_at_least({ vec, n }, need);
    if(ec)
        co_return { ec, 0 };

    auto const consumed = (std::min)(written - owned, tail_size);
    total_body_ += out_len_ + consumed;
    out_len_ = 0;
    hdr_sent_ = true;
    done_ = eof;
    co_return { {}, consumed };
}

capy::io_task<std::size_t>
serializer::
write_at_least(
    std::span<capy::const_buffer const> buffers,
    std::size_t bytes)
{
    BOOST_ASSERT(bytes <= capy::buffer_size(buffers));
    auto slice = capy::buffer_slice(buffers);
    std::size_t written = 0;
    while(written < bytes)
    {
        auto [ec, n] = co_await stream_->
            write_some(slice.data());
        written += n;
        if(ec && written < bytes)
            co_return { ec, written };
        slice.remove_prefix(n);
    }
    co_return { {}, written };
}

capy::const_buffer
serializer::
chunk_frame(std::size_t tail_size) noexcept
{
    static constexpr char hex[] = "0123456789abcdef";
    auto s = out_len_ + tail_size;
    auto p = buf_;

    *--p = '\n';
    *--p = '\r';

    do
    {
        *--p = hex[s & 0xF];
        s >>= 4;
    } while(s != 0);

    // prev chunk's CRLF
    if(total_body_ != 0)
    {
        *--p = '\n';
        *--p = '\r';
    }

    return { p, static_cast<std::size_t>(
        buf_ - p) + out_len_ };
}

} // namespace detail
} // namespace burl
} // namespace boost
