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
#include <boost/capy/buffers/make_buffer.hpp>
#include <boost/capy/cond.hpp>
#include <boost/capy/write_at_least.hpp>

#include <cstring>
#include <utility>

namespace boost
{
namespace burl
{
namespace detail
{

serializer::
serializer(config const& cfg, capy::any_write_stream* stream)
    : stream_(stream)
    , min_prepare_(cfg.min_prepare)
    , direct_thr_(cfg.direct_thr)
    , enc_thr_(cfg.enc_thr)
    , out_(new unsigned char[
        cfg.out_buffer + cfg.enc_buffer + margin] + margin)
    , out_cap_(cfg.enc_buffer)
    , in_(out_)
    , in_cap_(cfg.out_buffer)
{
}

serializer::
serializer(serializer&& other) noexcept
    : stream_(other.stream_)
    , msg_(other.msg_)
    , enc_(other.enc_)
    , min_prepare_(other.min_prepare_)
    , direct_thr_(other.direct_thr_)
    , enc_thr_(other.enc_thr_)
    , out_(other.out_)
    , out_cap_(other.out_cap_)
    , out_len_(other.out_len_)
    , in_(other.in_)
    , in_cap_(other.in_cap_)
    , in_len_(other.in_len_)
    , total_body_(other.total_body_)
    , head_(other.head_)
    , enc_started_(other.enc_started_)
    , hdr_sent_(other.hdr_sent_)
    , done_(other.done_)
{
    other.out_ = nullptr;
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
    if(out_)
        delete[](out_ - margin);
}

void
serializer::
reset(
    capy::any_write_stream* stream,
    http::message_base* msg,
    encoder* enc,
    bool head) noexcept
{
    if(head)
        enc = nullptr;

    if(!enc == (in_ != out_))
    {
        std::swap(in_cap_, out_cap_);
        in_ = enc ? out_ + out_cap_ : out_;
    }

    stream_ = stream;
    msg_ = msg;
    enc_ = enc;
    in_len_ = 0;
    out_len_ = 0;
    total_body_ = 0;
    head_ = head;
    enc_started_ = false;
    hdr_sent_ = false;
    done_ = false;
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
    if(capacity() >= min_prepare_)
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
    return in_cap_ - in_len_;
}

capy::mutable_buffer
serializer::
do_prepare() noexcept
{
    return { in_ + in_len_, in_cap_ - in_len_ };
}

void
serializer::
do_commit(std::size_t n) noexcept
{
    in_len_ += n;
}

bool
serializer::
should_coalesce(std::size_t avail) const noexcept
{
    if(avail > capacity())
        return false;
    if(enc_)
        return !enc_started_ && avail + in_len_ < enc_thr_;
    return avail < direct_thr_;
}

void
serializer::
finalize(std::size_t remaining) noexcept
{
    if(head_)
        return;

    if(enc_)
    {
        if(enc_started_)
            return;

        if(remaining + in_len_ >= enc_thr_)
            return;

        msg_->erase(http::field::content_encoding);
        enc_ = nullptr;
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
    msg_->set_content_length((enc_ ? out_len_ : in_len_) + remaining);
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
    capy::const_buffer in = { in_, in_len_ };
    for(;;)
    {
        if(in.size() == 0)
        {
            if(n != tail.size())
                in = tail[n++];
            else if(!eof)
                co_return { {}, consumed };
        }

        if(out_len_ == out_cap_)
        {
            if(auto [ec, _] = co_await flush({}, false); ec)
                co_return { ec, consumed };
        }

        auto r = enc_->process(
            { out_ + out_len_, out_cap_ - out_len_ },
            in,
            eof && n == tail.size());

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
    auto const buf = enc_ ? out_ : in_;
    auto& len = enc_ ? out_len_ : in_len_;
    auto const tail_len = capy::buffer_size(tail);
    auto const chunked = msg_->chunked() && !head_;
    BOOST_ASSERT(eof || len + tail_len != 0);
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
        static constexpr char hex[] = "0123456789abcdef";
        auto s = len + tail_len;
        auto p = buf;

        *--p = '\n';
        *--p = '\r';

        do
        {
            *--p = hex[s & 0xF];
            s >>= 4;
        } while(s != 0);

        // prev chunk's CRLF
        if(total_body_)
        {
            *--p = '\n';
            *--p = '\r';
        }

        append({ p, static_cast<std::size_t>(buf - p) + len });
    }
    else
    {
        auto const decl = [&]()-> std::uint64_t
        {
            if(head_ || msg_->payload() != http::payload::size)
                return 0;
            return msg_->payload_size();
        }();
        auto const prod = total_body_ + len + tail_len;

        if(prod > decl || (eof && prod != decl))
            co_return { error::body_size_mismatch, 0 };

        if(len != 0)
            append({ buf, len });
    }

    auto const owned = sum;

    for(auto& b : tail)
        append(b);

    if(chunked && eof)
        append({ "\r\n0\r\n\r\n", len || tail_len ? 7u : 2u });

    auto const need = chunked || eof ? sum : owned + !!tail_len;
    auto [ec, written] = co_await capy::write_at_least(
        *stream_, std::span{ vec, n }, need);
    if(ec)
        co_return { ec, 0 };

    auto const consumed = (std::min)(written - owned, tail_len);
    total_body_ += len + consumed;
    len = 0;
    hdr_sent_ = true;
    done_ = eof;
    co_return { {}, consumed };
}

} // namespace detail
} // namespace burl
} // namespace boost
