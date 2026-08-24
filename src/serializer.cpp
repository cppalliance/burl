//
// Copyright (c) 2026 Mohammad Nejati
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

#include <boost/burl/error.hpp>
#include <boost/burl/serializer.hpp>

#include "detail/util.hpp"

#include <boost/assert.hpp>
#include <boost/capy/buffers/buffer_copy.hpp>
#include <boost/capy/buffers/make_buffer.hpp>
#include <boost/capy/cond.hpp>
#include <boost/url/grammar/ci_string.hpp>

#include <algorithm>
#include <utility>

namespace boost
{
namespace burl
{

// assert relying facts
static_assert(
    fields_base::max_buffer_size <=
        (std::numeric_limits<std::uint32_t>::max)());

using http::payload;
using detail::clamp;

namespace
{

capy::const_buffer
suffix(capy::const_buffer buf, std::size_t n) noexcept
{
    return {
        static_cast<char const*>(buf.data()) + n,
        buf.size() - n
    };
}

} // namespace

serializer::
serializer(config const& cfg)
    : buf_(new char[margin + cfg.stage_buffer + cfg.enc_buffer])
    , min_prepare_(cfg.min_prepare)
    , min_direct_(cfg.min_direct)
    , enc_threshold_(cfg.enc_threshold)
    , stage_{ buf_.get() + margin, cfg.stage_buffer }
    , enc_out_{ buf_.get() + margin, cfg.enc_buffer }
{
}

void
serializer::
start(
    message_head_base* msg,
    encoder* enc,
    bool head) noexcept
{
    BOOST_ASSERT(msg != nullptr);

    if(head)
        enc = nullptr;

    msg_ = msg;
    enc_ = enc;
    trailer_ = nullptr;

    if((enc != nullptr) != (stage_.ptr != enc_out_.ptr))
    {
        std::swap(stage_.cap, enc_out_.cap);
        stage_.ptr = enc_out_.ptr + (enc ? enc_out_.cap : 0);
    }

    stage_.clear();
    enc_out_.clear();

    header_offset_ = 0;
    tail_offset_ = 0;
    input_framed_ = 0;
    input_digested_ = 0;
    prefix_rem_ = 0;
    payload_ = head ? payload::none : msg->payload();
    crlf_owed_ = false;
    enc_started_ = false;
    sealed_ = false;
    done_ = false;
    owed_ = [&]() -> std::uint64_t
    {
        switch(payload_)
        {
        case payload::none:
        case payload::chunked:
            return 0;
        case payload::to_eof:
            return std::uint64_t(-1);
        default:
            return msg->content_length().value_or(0);
        }
    }();
}

std::span<capy::mutable_buffer>
serializer::
prepare(std::span<capy::mutable_buffer> dest)
{
    BOOST_ASSERT(msg_ != nullptr);
    BOOST_ASSERT(!sealed_);
    if(dest.empty() || stage_.capacity() == 0)
        return dest.first(0);
    dest[0] = stage_.prepare();
    return dest.first(1);
}

void
serializer::
commit(std::size_t n) noexcept
{
    BOOST_ASSERT(msg_ != nullptr);
    BOOST_ASSERT(!sealed_);
    stage_.commit(n);
}

bool
serializer::
chunked_() const noexcept
{
    return payload_ == payload::chunked;
}

bool
serializer::
to_eof_() const noexcept
{
    return payload_ == payload::to_eof;
}

bool
serializer::
should_coalesce_(std::size_t avail) const noexcept
{
    if(avail > stage_.capacity())
        return false;
    if(enc_)
        return !enc_started_ &&
            avail + stage_.len < enc_threshold_;
    return avail < min_direct_;
}

detail::flat_buffer&
serializer::
buffered_() noexcept
{
    return enc_out_.empty() ? stage_ : enc_out_;
}

capy::const_buffer
serializer::
epilogue_buf_() const noexcept
{
    static constexpr char s[] =
        "\r\n" "0\r\n" "\r\n";
    std::size_t const skip = crlf_owed_ ? 0 : 2;
    std::size_t const drop = trailer_   ? 2 : 0;
    return { s + skip, sizeof(s) - 1 - skip - drop };
}

capy::const_buffer
serializer::
trailer_buf_() const noexcept
{
    if(trailer_)
        return capy::make_buffer(trailer_->buffer());
    return {};
}

bool
serializer::
settled_() const noexcept
{
    if(msg_->buffer().size() != header_offset_)
        return false;

    if(input_framed_ != 0)
        return false;

    if(!stage_.empty() || !enc_out_.empty())
        return false;

    if( chunked_() &&
        tail_offset_ !=
            epilogue_buf_().size() +
                trailer_buf_().size())
        return false;

    return owed_ == 0;
}

void
serializer::
open_chunk_(std::uint64_t s) noexcept
{
    BOOST_ASSERT(prefix_rem_ == 0);
    BOOST_ASSERT(owed_ == 0);
    BOOST_ASSERT(s != 0);

    auto const p0 = buffered_().ptr + buffered_().pos;
    auto p = p0;

    *--p = '\n';
    *--p = '\r';

    static constexpr char hex[] = "0123456789abcdef";
    auto v = s;
    do
    {
        *--p = hex[v & 0xF];
        v >>= 4;
    } while(v != 0);

    // prev chunk's CRLF
    if(crlf_owed_)
    {
        *--p = '\n';
        *--p = '\r';
    }
    crlf_owed_ = true;

    prefix_rem_ = static_cast<std::uint8_t>(p0 - p);
    owed_ = s;
}

void
serializer::
decide_framing_(std::uint64_t total) noexcept
{
    if(header_offset_ != 0 || trailer_)
        return;
    if(payload_ == payload::chunked || payload_ == payload::to_eof)
    {
        msg_->set_content_length(total);
        payload_ = payload::size;
        owed_ = total;
    }
}

void
serializer::
encode_(source& src, system::error_code& ec)
{
    auto feed = [&](
        capy::const_buffer in, bool more)
    {
        auto const r = enc_->process(
            enc_out_.prepare(), in, more);
        enc_started_ = true;
        enc_out_.commit(r.produced);
        if(r.ec == capy::cond::eof)
        {
            decide_framing_(enc_out_.size());
            if(to_eof_())
                owed_ = enc_out_.size();
            enc_ = nullptr;
        }
        else if(r.ec)
        {
            ec = r.ec;
        }
        return r.consumed;
    };

    // staged input drains first
    while(!stage_.empty())
    {
        if(enc_out_.capacity() == 0)
            return;
        auto const more = !sealed_ || src.remain != 0;
        stage_.consume(feed(stage_.data(), more));
        if(ec.failed() || !enc_)
            return;
    }

    // the supplied buffers
    for(auto cur = src.next(); cur.size() != 0;)
    {
        if(enc_out_.capacity() == 0)
            return;
        auto const n = feed(
            cur, !sealed_ || src.remain != 0);
        cur += n;
        input_digested_ += n;
        if(ec.failed() || !enc_)
            return;
        if(cur.size() == 0)
            cur = src.next();
    }

    // finish the stream
    while(sealed_)
    {
        if(enc_out_.capacity() == 0)
            return;
        feed({}, false);
        if(ec.failed() || !enc_)
            return;
    }
}

bool
serializer::
ingest_(
    source& src,
    bool more,
    system::error_code& ec)
{
    auto const sealing = !more && !sealed_;

    if(chunked_())
    {
        if(sealed_ && !enc_ && src.remain != 0)
        {
            ec = make_error_code(
                std::errc::invalid_argument);
            return false;
        }
    }
    else if(!enc_)
    {
        auto const have = std::uint64_t(src.remain) +
            stage_.size() + enc_out_.size();
        if( have > owed_ ||
            (!to_eof_() && sealing && have < owed_))
        {
            if(to_eof_())
                ec = make_error_code(
                    std::errc::invalid_argument);
            else
                ec = error::body_size_mismatch;
            return false;
        }
    }

    if(sealing)
        sealed_ = true;

    if(sealed_)
    {
        auto const total = stage_.size() + src.remain;
        if( enc_ && !enc_started_ && header_offset_ == 0 &&
            total < enc_threshold_)
        {
            msg_->erase(http::field::content_encoding);
            enc_ = nullptr;
        }
        if(!enc_)
        {
            decide_framing_(total);
            if(to_eof_() && sealing)
                owed_ = total;
        }
    }

    // small inputs are coalesced into the stage
    if( !sealed_ && src.remain != 0 &&
        should_coalesce_(src.remain))
    {
        input_digested_ = src.remain;
        for(auto b = src.next(); b.size() != 0;
            b = src.next())
            stage_.commit(capy::buffer_copy(
                stage_.prepare(), b));
        if(enc_)
            return false;
    }
    else if(enc_)
    {
        encode_(src, ec);
        if(ec)
        {
            enc_  = nullptr;
            done_ = true;
            return false;
        }

        auto const finished = (enc_ == nullptr);
        auto const encoded  = enc_out_.size();
        if(!chunked_() && !to_eof_())
        {
            if(encoded > owed_ || (finished && encoded != owed_))
            {
                done_ = true;
                ec = error::body_size_mismatch;
                return false;
            }
        }
        auto const flush = finished || enc_out_.capacity() == 0;
        if(flush && encoded != 0 && chunked_())
            open_chunk_(encoded);
        return flush;
    }

    auto const flush = src.remain != 0 || sealed_ ||
        should_drain() || stage_.pos != 0;
    if(flush && chunked_())
    {
        auto const s = buffered_().size() + src.remain;
        if(s != 0)
            open_chunk_(s);
    }
    return flush;
}

std::span<capy::const_buffer const>
serializer::
gather_(
    std::span<capy::const_buffer> dest,
    source& src,
    bool flush_body,
    bool flush_header) noexcept
{
    std::size_t n = 0;

    // returns false when dest is exhausted
    auto const push = [&](capy::const_buffer b)
    {
        if(b.size() == 0)
            return true;
        if(n == dest.size())
            return false;
        dest[n++] = b;
        return true;
    };

    // [header]
    if(flush_header)
        push(suffix(capy::make_buffer(
            msg_->buffer()), header_offset_));

    // [CRLF + prefix][buffered]
    auto const& buffered = buffered_();
    auto buffered_take = std::uint64_t(buffered.size());
    if(chunked_())
        buffered_take = (std::min)(buffered_take, owed_);
    else if(!flush_body)
        buffered_take = 0;
    push({ buffered.ptr + buffered.pos - prefix_rem_,
        prefix_rem_ + std::size_t(buffered_take) });

    // [supplied body]
    auto const quota = owed_ - buffered_take;
    auto const supplied = src.remain;
    std::size_t placed = 0;
    if(!enc_)
    {
        while(placed != quota)
        {
            auto const b = src.next();
            if(b.size() == 0)
                break;
            auto const k = clamp(quota - placed, b.size());
            if(!push({ b.data(), k }))
                break;
            placed += k;
        }
    }
    input_framed_ = placed;

    // [epilogue][trailer]
    if( sealed_ && !enc_ && chunked_() &&
        buffered.size() + supplied == owed_ &&
        placed == supplied)
    {
        auto const eb = epilogue_buf_();
        auto const tb = trailer_buf_();
        auto const k  = clamp(tail_offset_, eb.size());
        push(suffix(eb, k));
        push(suffix(tb, tail_offset_ - k));
    }

    return { dest.data(), n };
}

std::span<capy::const_buffer const>
serializer::
frame_(
    std::span<capy::const_buffer> dest,
    source& src,
    bool more,
    system::error_code& ec)
{
    BOOST_ASSERT(msg_ != nullptr);

    ec = {};

    if(done_ && !settled_())
    {
        ec = make_error_code(
            std::errc::state_not_recoverable);
        return {};
    }

    BOOST_ASSERT(input_digested_ == 0);

    auto const drain_call = (src.remain == 0);

    bool flush_body = true;
    if(owed_ == 0 || !chunked_())
    {
        flush_body = ingest_(src, more, ec);
        if(ec)
            return {};
    }

    auto const out = gather_(
        dest, src, flush_body, flush_body || drain_call);

    if(out.empty() && !dest.empty() && !done_)
    {
        if(!more && owed_ != 0)
        {
            if(to_eof_() || chunked_())
                ec = make_error_code(
                    std::errc::invalid_argument);
            else
                ec = error::body_size_mismatch;
        }
        else if(sealed_)
        {
            done_ = settled_();
        }
    }

    return out;
}

std::size_t
serializer::
consume(std::size_t n) noexcept
{
    // [header]
    {
        auto const k = clamp(
            n, msg_->buffer().size() - header_offset_);
        header_offset_ += static_cast<std::uint32_t>(k);
        n -= k;
    }

    // [CRLF + prefix]
    {
        auto const k = clamp(n, prefix_rem_);
        prefix_rem_ -= static_cast<std::uint8_t>(k);
        n -= k;
    }

    // [buffered]
    {
        auto& buffered = buffered_();
        auto const rem = clamp(owed_, buffered.size());
        auto const k = clamp(n, rem);
        buffered.consume(k);
        owed_ -= k;
        n -= k;
    }

    // [supplied body]
    std::size_t input_taken;
    {
        auto const k = clamp(n, input_framed_);
        input_framed_ -= k;
        owed_ -= k;
        input_taken = k;
        n -= k;
    }

    // [epilogue][trailer]
    if(sealed_ && chunked_())
    {
        auto const total = epilogue_buf_().size() +
            trailer_buf_().size();
        auto const k = clamp(n, total - tail_offset_);
        tail_offset_ += static_cast<std::uint32_t>(k);
        n -= k;
    }

    BOOST_ASSERT(n == 0);

    if(sealed_ && !done_)
        done_ = settled_();

    auto const r = input_taken + input_digested_;
    input_digested_ = 0;
    return r;
}

} // namespace burl
} // namespace boost
