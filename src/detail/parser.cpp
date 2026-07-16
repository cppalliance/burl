//
// Copyright (c) 2026 Mohammad Nejati
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

#include <boost/burl/detail/parser.hpp>

#include "util.hpp"

#include <boost/assert.hpp>
#include <boost/capy/error.hpp>
#include <boost/capy/buffers/make_buffer.hpp>
#include <boost/capy/buffers/front.hpp>
#include <boost/url/grammar/error.hpp>
#include <boost/url/grammar/hexdig_chars.hpp>

#include <cstring>
#include <new>
#include <type_traits>
#include <utility>

namespace boost
{
namespace burl
{
namespace detail
{

using http::error::bad_payload;
using http::error::body_too_large;
using http::error::in_place_overflow;
using http::error::incomplete;
using http::error::need_data;
using http::condition::need_more_input;

using header  = http::detail::header;
using payload = http::payload;

namespace
{

class chained_sequence
{
    char const* pos_;
    char const* end_;
    char const* begin_b_;
    char const* end_b_;

public:
    chained_sequence(std::array<capy::const_buffer, 2> const& cbp)
        : pos_(static_cast<char const*>(cbp[0].data()))
        , end_(pos_ + cbp[0].size())
        , begin_b_(static_cast<char const*>(cbp[1].data()))
        , end_b_(begin_b_ + cbp[1].size())
    {
    }

    chained_sequence(char const* p, std::size_t n)
        : pos_(p)
        , end_(p + n)
        , begin_b_(end_)
        , end_b_(end_)
    {
    }

    char const*
    next() noexcept
    {
        ++pos_;
        // most frequently taken branch
        if(pos_ < end_)
            return pos_;

        // bring the second range
        if(begin_b_ != end_b_)
        {
            pos_ = begin_b_;
            end_ = end_b_;
            begin_b_ = end_b_;
            return pos_;
        }

        // undo the increament
        pos_ = end_;
        return nullptr;
    }

    void
    advance(std::size_t n) noexcept
    {
        auto const a = static_cast<std::size_t>(end_ - pos_);
        if(n < a)
        {
            pos_ += n;
            return;
        }
        // exhaust the first range and continue into the second
        n -= a;
        pos_     = begin_b_ + n;
        end_     = end_b_;
        begin_b_ = end_b_;
    }

    bool
    empty() const noexcept
    {
        return pos_ == end_;
    }

    char
    value() const noexcept
    {
        return *pos_;
    }

    char const *
    pos() const noexcept
    {
        return pos_;
    }

    std::size_t
    size() const noexcept
    {
        return (end_ - pos_) + (end_b_ - begin_b_);
    }

    std::array<capy::const_buffer, 2>
    prefix(std::size_t n) const noexcept
    {
        auto const a  = static_cast<std::size_t>(end_ - pos_);
        auto const b  = static_cast<std::size_t>(end_b_ - begin_b_);
        auto const na = n < a ? n : a;
        auto const nb = n - na < b ? n - na : b;
        return { { { pos_, na }, { begin_b_, nb } } };
    }
};

std::error_code
skip_to_eol(chained_sequence& cs) noexcept
{
    while(!cs.empty())
    {
        if(cs.value() == '\r')
        {
            if(!cs.next())
                break;
            if(cs.value() != '\n')
                return bad_payload;
            cs.next();
            return {};
        }
        cs.next();
    }
    return need_data;
}

std::error_code
parse_chunk_header(
    chained_sequence& cs,
    std::uint64_t& size) noexcept
{
    for(auto const start = cs.size();;)
    {
        if(cs.empty())
            return need_data;
        auto const n = urls::grammar::hexdig_value(cs.value());
        if(n < 0)
        {
            if(start == cs.size())
                return bad_payload;
            // skip chunk header's exts
            return skip_to_eol(cs);
        }
        // at least 4 significant bits are free
        if(size > (std::numeric_limits<std::uint64_t>::max)() >> 4)
            return bad_payload;
        size = (size << 4) | static_cast<std::uint64_t>(n);
        cs.next();
    }
}

std::error_code
skip_trailer(chained_sequence& cs) noexcept
{
    for(;;)
    {
        if(cs.empty())
            return need_data;
        if(cs.value() == '\r')
        {
            if(!cs.next())
                return need_data;
            if(cs.value() != '\n')
                return bad_payload;
            cs.next();
            return {};
        }
        // skip to the end of the field
        if(auto ec = skip_to_eol(cs); ec)
            return ec;
    }
}

std::error_code
skip_crlf(chained_sequence& cs) noexcept
{
    if(cs.size() < 2)
        return need_data;
    if(cs.value() != '\r' || *cs.next() != '\n')
        return bad_payload;
    cs.next();
    return {};
}

std::span<capy::const_buffer>
collect(
    std::span<capy::const_buffer> dest,
    std::array<capy::const_buffer, 2> const& src,
    std::size_t at_most = std::size_t(-1)) noexcept
{
    std::size_t n = 0;
    for(auto b : src)
    {
        auto const take = clamp(b.size(), at_most);
        if(take == 0 || n == dest.size())
            break;
        at_most -= take;
        dest[n++] = { b.data(), take };
    }
    return dest.first(n);
}

void
move_leftovers(
    char* base,
    std::array<capy::const_buffer, 2> const& bufs) noexcept
{
    auto const* a = static_cast<char const*>(bufs[0].data());
    auto an       = bufs[0].size();
    auto const* b = static_cast<char const*>(bufs[1].data());
    auto const bn = bufs[1].size();
    if(bn == 0)
    {
        std::memmove(base, a, an);
        return;
    }
    do
    {
        auto* bp = (std::min)(base + an, const_cast<char*>(a) - bn);
        b = static_cast<char const*>(std::memmove(bp, b, bn));
        auto chunk_a = static_cast<std::size_t>(b - base);
        std::memcpy(base, a, chunk_a);
        an   -= chunk_a;
        base += chunk_a;
        a    += chunk_a;
    } while(an);
}

auto
prefix(
    auto buf,
    std::size_t n) noexcept -> decltype(buf)
{
    return { buf.data(), clamp(buf.size(), n) };
};

} // namespace

struct parser::chunk_fn
{
    void* obj_;
    capy::io_result<std::size_t> (*invoke_)(
        void*, capy::const_buffer, bool);

    template<class F>
    chunk_fn(F&& f) noexcept
        : obj_(std::addressof(f))
        , invoke_(
            [](void* obj, capy::const_buffer b, bool last)
                -> capy::io_result<std::size_t>
            {
                return (*static_cast<
                    std::remove_reference_t<F>*>(obj))(b, last);
            })
    {
    }

    capy::io_result<std::size_t>
    operator()(capy::const_buffer b, bool last) const
    {
        return invoke_(obj_, b, last);
    }
};

parser::
parser(
    config const& cfg,
    http::detail::kind kind,
    capy::any_read_stream stream)
    : hdr_limits_(cfg.hdr_limits)
    , stream_(std::move(stream))
    , body_limit_(cfg.body_limit)
{
    constexpr auto align = alignof(header::entry);
    auto const h_cap = hdr_limits_.valid_space_needed() +
        align * ((cfg.in_buffer + align - 1) / align);
    auto* const p = static_cast<char*>(::operator new(
        sizeof(http::static_response) + h_cap + cfg.dec_buffer));
    in_  = { p + sizeof(http::static_response), h_cap - table_reserve() };
    out_ = { in_.ptr + h_cap, cfg.dec_buffer };
    if(kind == http::detail::kind::request)
        h_.reset(reinterpret_cast<header*>(
            ::new(static_cast<void*>(p))
                http::static_request(in_.ptr, h_cap)));
    else
        h_.reset(reinterpret_cast<header*>(
            ::new(static_cast<void*>(p))
                http::static_response(in_.ptr, h_cap)));
}

bool
parser::
got_header() const noexcept
{
    return got_header_;
}

bool
parser::
got_body() const noexcept
{
    return got_body_;
}

bool
parser::
has_buffered_data() const noexcept
{
    switch(payload_)
    {
    case payload::chunked:
        return in_.size() > chunk_rem_;
    case payload::size:
        return in_.size() > payload_rem();
    case payload::to_eof:
        return false;
    default:
        return !in_.empty();
    }
}

std::size_t
parser::
raw_limit_rem() const noexcept
{
    BOOST_ASSERT(!dec_);
    if(body_limit_ <= transferred_)
        return 0;
    return clamp(body_limit_ - transferred_);
}

std::size_t
parser::
dec_limit_rem() const noexcept
{
    BOOST_ASSERT(dec_);
    if(body_limit_ <= decoded_)
        return 0;
    return clamp(body_limit_ - decoded_);
}

bool
parser::
payload_sized() const noexcept
{
    return payload_ == payload::size;
}

std::size_t
parser::
payload_rem() const noexcept
{
    BOOST_ASSERT(payload_sized());
    return clamp(h_->md.payload_size - transferred_);
}

std::size_t
parser::
table_reserve() const noexcept
{
    return header::table_space(
        hdr_limits_.max_fields);
}

void
parser::
start(bool head)
{
    BOOST_ASSERT(!started_ || got_body_);

    if(payload_sized() && got_body_)
        in_.consume(payload_rem());

    auto* const base =
        reinterpret_cast<char*>(h_.get())
            + sizeof(http::static_response);
    move_leftovers(base, in_.data());
    in_  = { base, static_cast<std::size_t>(
        out_.ptr - base) - table_reserve(), 0, in_.size() };
    out_ = { out_.ptr, out_.cap };

    *h_ = header{ http::detail::empty{ h_->kind } };
    h_->buf  = in_.ptr;
    h_->cbuf = in_.ptr;
    h_->cap  = in_.cap + table_reserve();

    dec_         = nullptr;
    chunk_rem_   = 0;
    transferred_ = 0;
    decoded_     = 0;
    dec_err_     = {};
    payload_     = payload::none;
    head_        = head;
    started_     = true;
    got_header_  = false;
    got_body_    = false;
    mid_chunk_   = false;
    fin_chunk_   = false;
}

void
parser::
reset(capy::any_read_stream stream) noexcept
{
    auto* const base =
        reinterpret_cast<char*>(h_.get())
            + sizeof(http::static_response);
    in_  = { base, static_cast<std::size_t>(
        out_.ptr - base) - table_reserve() };
    out_ = { out_.ptr, out_.cap };

    stream_      = std::move(stream);
    dec_         = nullptr;
    chunk_rem_   = 0;
    transferred_ = 0;
    decoded_     = 0;
    dec_err_     = {};
    payload_     = payload::none;
    head_        = false;
    started_     = false;
    got_header_  = false;
    got_body_    = false;
    mid_chunk_   = false;
    fin_chunk_   = false;
    eof_         = false;
}

capy::io_task<>
parser::refill()
{
    if(eof_)
        co_return { incomplete };
    if(in_.full())
        co_return { in_place_overflow };
    auto [ec, n] = co_await stream_.read_some(in_.prepare());
    in_.commit(n);
    if(payload_sized() && payload_rem() <= in_.size())
        got_body_ = true;
    if(ec)
    {
        if(ec == capy::cond::eof)
        {
            eof_ = true;
            if(payload_ == payload::to_eof)
                got_body_ = true;
            co_return {};
        }
        co_return ec;
    }
    co_return {};
}

std::error_code
parser::
walk_chunks(chunk_fn f, bool dry)
{
    chained_sequence cs = in_.data();
    std::uint64_t size  = chunk_rem_;

    if(fin_chunk_)
    {
        // from flatten_chunks
        auto const b = prefix(
            in_.data()[0], clamp(chunk_rem_));
        auto const [ec, n] = f(b, true);
        if(!dry)
        {
            in_.consume(n);
            chunk_rem_   -= n;
            transferred_ += n;
        }
        return ec;
    }

    if(mid_chunk_)
        goto invoke;

loop:
    if(auto ec = parse_chunk_header(cs, size); ec)
        return ec;

    // final chunk
    if(size == 0)
    {
        if(auto ec = skip_trailer(cs); ec)
            return ec;
        got_body_ = true;
        if(!dry)
        {
            fin_chunk_ = true;
            in_.consume(in_.size() - cs.size());
        }
        return f({}, true).ec;
    }

invoke:
    for(const auto& b : cs.prefix(clamp(size)))
    {
        if(b.size() == 0)
            break;
        auto const [ec, n] = f(b, false);
        cs.advance(n);
        size -= n;
        if(!dry)
        {
            in_.consume(in_.size() - cs.size());
            chunk_rem_   = size;
            transferred_ += n;
            mid_chunk_   = true;
        }
        if(ec || n < b.size())
            return ec;
    }

    if(auto ec = skip_crlf(cs); ec)
        return ec;

    goto loop;
}

std::error_code
parser::
flatten_chunks()
{
    if(fin_chunk_)
        return {};

    BOOST_ASSERT(in_.pos == 0);

    std::size_t flat = clamp(chunk_rem_, in_.len);
    char const* keep = in_.ptr + flat;
    chained_sequence cs(keep, in_.len - flat);

    auto bail = [&](std::error_code ec)
    {
        auto const tail = static_cast<std::size_t>(
            in_.ptr + in_.len - keep);
        std::memmove(in_.ptr + flat, keep, tail);
        in_.len = flat + tail;
        return ec;
    };

    for(;;)
    {
        if(mid_chunk_)
        {
            if(auto ec = skip_crlf(cs); ec)
                return bail(ec);
        }

        std::uint64_t size = 0;
        if(auto ec = parse_chunk_header(cs, size); ec)
            return bail(ec);

        if(size == 0)
        {
            if(auto ec = skip_trailer(cs); ec)
                return bail(ec);
            got_body_  = true;
            fin_chunk_ = true;
            keep = cs.pos();
            return bail({});
        }

        if(size > in_.cap - flat)
            return bail(in_place_overflow);

        chunk_rem_ = flat + size;
        mid_chunk_ = true;

        auto const n = clamp(size, cs.size());
        std::memmove(in_.ptr + flat, cs.pos(), n);
        flat += n;
        cs.advance(n);
        keep = cs.pos();
        if(n < size)
            return bail(need_data);
    }
}

capy::io_task<>
parser::
read_header()
{
    BOOST_ASSERT(started_);

    if(got_header_)
        co_return {};

    for(;;)
    {
        system::error_code ec;
        h_->parse(in_.size(), hdr_limits_, ec);
        if(ec)
        {
            if(ec != need_more_input)
                co_return { ec };
            if(eof_ && in_.empty())
                co_return { http::error::end_of_stream };
            if(auto [rec] = co_await refill(); rec)
                co_return rec;
            continue;
        }

        // TODO: resize out_ based on payload and decoder
        in_.ptr += h_->size;
        in_.len -= h_->size;
        in_.cap -= h_->size;

        payload_ = head_ ? payload::none : h_->md.payload;
        got_header_ = true;    

        switch(payload_)
        {
        case payload::error:
            co_return { bad_payload };
        case payload::none:
            got_body_ = true;
            break;
        case payload::size:
            if(payload_rem() <= in_.size())
                got_body_ = true;
            break;
        case payload::chunked:
            break;
        case payload::to_eof:
            if(eof_)
                got_body_ = true;
            break;
        }
        co_return {};
    }
}

void
parser::
set_decoder(decoder* dec) noexcept
{
    BOOST_ASSERT(transferred_ == 0);
    dec_ = dec;
}

void
parser::
set_body_limit(std::uint64_t n) noexcept
{
    body_limit_ = n;
}

capy::io_task<std::string_view>
parser::
read_body()
{
    if(auto [ec] = co_await read_header(); ec)
        co_return { ec, {} };

    if(dec_)
    {
        if(decoded_ != out_.size())
            co_return { incomplete, {} };
        for(;;)
        {
            if(out_.full())
                co_return { in_place_overflow, {} };
            auto [ec, n] = co_await decode_some(out_.prepare());
            out_.commit(n);
            if(ec)
            {
                if(ec == capy::cond::eof)
                    co_return { {}, { out_.ptr, out_.len } };
                co_return { ec, {} };
            }
        }
    }

    if(transferred_ != 0)
        co_return { incomplete, {} };

    switch(payload_)
    {
    case payload::error:
    case payload::none:
    {
        co_return { {}, {} };
    }
    case payload::chunked:
    {
        for(;;)
        {
            if(chunk_rem_ > raw_limit_rem())
                co_return { body_too_large, {} };
            if(fin_chunk_)
                co_return { {}, { in_.ptr, clamp(chunk_rem_) } };
            if(auto ec = flatten_chunks(); ec)
            {
                if(ec != need_more_input)
                    co_return { ec, {} };
                if(auto [fec] = co_await refill(); fec)
                    co_return { fec, {} };
            }
        }
    }
    case payload::size:
    {
        auto const rem = payload_rem();
        if(rem > raw_limit_rem())
            co_return { body_too_large, {} };
        for(;;)
        {
            if(got_body_)
                co_return { {}, { in_.ptr, clamp(in_.len, rem) } };
            if(auto [fec] = co_await refill(); fec)
                co_return { fec, {} };
        }
    }
    case payload::to_eof:
    {
        for(;;)
        {
            if(in_.size() > raw_limit_rem())
                co_return { body_too_large, {} };
            if(got_body_)
                co_return { {}, { in_.ptr, in_.len } };
            if(auto [fec] = co_await refill(); fec)
                co_return { fec, {} };
        }
    }
    }
}

http::static_response const&
parser::
get_response() const
{
    BOOST_ASSERT(h_);
    return reinterpret_cast<
        http::static_response const&>(*h_);
}

http::static_request const&
parser::
get_request() const
{
    BOOST_ASSERT(h_);
    return reinterpret_cast<
        http::static_request const&>(*h_);
}

capy::io_task<std::size_t>
parser::
decode_some(
    std::span<capy::mutable_buffer const> buffers)
{
    if(capy::buffer_empty(buffers))
        co_return { {}, 0 };

    auto slice = capy::buffer_slice(buffers);
    std::size_t prod = 0;
    auto decode =
    [&](capy::const_buffer in, bool last)
        -> capy::io_result<std::size_t>
    {
        if(dec_err_)
        {
            if(dec_err_ == capy::cond::eof)
            {
                if(!last || in.size() != 0)
                    return { bad_payload, 0 };
            }
            return { dec_err_, 0 };
        }
        std::size_t cons = 0;
        for(;;)
        {
            auto const out = capy::front(slice.data());
            if(out.size() == 0)
                return { {}, cons };
            auto const lim = dec_limit_rem();
            if(lim == 0)
                return { body_too_large, cons };
            auto const r = dec_->process(
                prefix(out, lim), in, last);
            in += r.consumed;
            cons += r.consumed;
            transferred_ += r.consumed;
            prod += r.produced;
            decoded_ += r.produced;
            slice.remove_prefix(r.produced);
            if(r.ec)
            {
                dec_err_ = r.ec;
                return { {}, cons };
            }
            if(r.produced == 0 && r.consumed == 0)
            {
                dec_err_ = error::decode_error;
                return { {}, cons };
            }
            if(in.size() == 0)
                return { {}, cons };
        }
    };

    switch(payload_)
    {
    case payload::error:
    case payload::none:
    {
        co_return { capy::error::eof, 0 };
    }
    case payload::chunked:
    {
        for(;;)
        {
            auto ec = walk_chunks(decode);
            if(prod != 0)
                co_return { {}, prod };
            if(ec != need_more_input)
                co_return { ec, 0 };
            if(auto [fec] = co_await refill(); fec)
                co_return { fec, 0 };
        }
    }
    case payload::size:
    case payload::to_eof:
    {
        for(;;)
        {
            auto const rem = payload_sized() ? payload_rem() : in_.size();
            auto const in  = prefix(in_.data()[0], rem);
            if(in.size() == 0 && !got_body_)
            {
                if(auto [fec] = co_await refill(); fec)
                    co_return { fec, 0 };
                continue;
            }
            auto [ec, cons] = decode(in, got_body_ && in.size() == rem);
            in_.consume(cons);
            if(prod != 0)
                co_return { {}, prod };
            if(ec)
                co_return { ec, 0 };
        }
    }
    }
}

capy::io_task<std::size_t>
parser::
do_read_some(
    std::span<capy::mutable_buffer const> buffers)
{
    if(auto [ec] = co_await read_header(); ec)
        co_return { ec, 0 };

    if(dec_)
    {
        if(!out_.empty())
        {
            auto const n = capy::buffer_copy(buffers, out_.data());
            out_.consume(n);
            co_return { {}, n };
        }
        co_return co_await decode_some(buffers);
    }

    auto copy = [&](std::size_t at_most)
    {
        auto const n = capy::buffer_copy(
            buffers, in_.data(), at_most);
        in_.consume(n);
        transferred_ += n;
        return n;
    };

    switch(payload_)
    {
    case payload::error:
    case payload::none:
    {
        co_return { capy::error::eof, 0 };
    }
    case payload::chunked:
    {
        for(;;)
        {
            std::size_t read = 0;
            std::size_t lim = raw_limit_rem();
            auto slice = capy::buffer_slice(buffers);
            auto ec = walk_chunks(
            [&](capy::const_buffer b, bool)
                -> capy::io_result<std::size_t>
            {
                auto const take = clamp(b.size(), lim);
                lim -= take;
                auto const n = capy::buffer_copy(
                    slice.data(), b, take);
                read += n;
                slice.remove_prefix(n);
                if(take < b.size())
                    return { body_too_large, n };
                return { {}, n };

            });
            if(read != 0)
                co_return { {}, read };
            if(ec == need_more_input)
            {
                if(auto [fec] = co_await refill(); fec)
                    co_return { fec, 0 };
                continue;
            }
            else if(ec)
                co_return { ec, 0 };
            BOOST_ASSERT(got_body_);
            co_return { capy::error::eof, 0 };
        }
    }
    case payload::size:
    {
        auto const rem = payload_rem();
        if(rem == 0)
            co_return { capy::error::eof, 0 };
        auto const lim = raw_limit_rem();
        if(lim == 0)
            co_return { body_too_large, 0 };
        if(!in_.empty())
            co_return { {}, copy(clamp(rem, lim)) };
        if(eof_)
            co_return { incomplete, 0 };
        auto [ec, n] = co_await stream_.read_some(
            capy::buffer_slice(buffers, 0, clamp(rem, lim)).data());
        transferred_ += n;
        if(n == rem)
            got_body_ = true;
        if(ec == capy::cond::eof)
        {
            eof_ = true;
            if(n != rem)
                co_return { incomplete, n };
        }
        co_return { ec, n };
    }
    case payload::to_eof:
    {
        if(eof_)
            co_return { capy::error::eof, 0 };
        auto const lim = raw_limit_rem();
        if(lim == 0)
            co_return { body_too_large, 0 };
        if(!in_.empty())
            co_return { {}, copy(lim) };
        auto [ec, n] = co_await stream_.read_some(
            capy::buffer_slice(buffers, 0, lim).data());
        transferred_ += n;
        if(ec == capy::cond::eof)
        {
            eof_ = true;
            got_body_ = true;
        }
        co_return { ec, n };
    }
    }
}

capy::io_task<std::span<capy::const_buffer>>
parser::
pull(std::span<capy::const_buffer> dest)
{
    if(auto [ec] = co_await read_header(); ec)
        co_return { ec, {} };

    if(dec_)
    {
        if(!out_.empty())
            co_return { {}, collect(dest, out_.data()) };
        auto [ec, n] = co_await decode_some(out_.prepare());
        out_.commit(n);
        if(ec && n == 0)
            co_return { ec, {} };
        co_return { {}, collect(dest, out_.data()) };
    }

    switch(payload_)
    {
    case payload::error:
    case payload::none:
    {
        co_return { capy::error::eof, {} };
    }
    case payload::chunked:
    {
        for(;;)
        {
            std::size_t n = 0;
            std::size_t lim = raw_limit_rem();
            if(lim == 0)
                co_return { body_too_large, {} };
            auto ec = walk_chunks(
            [&](capy::const_buffer b, bool last)
                -> capy::io_result<std::size_t>
            {
                if(last && b.size() == 0)
                    return { capy::error::eof, 0 };
                auto const take = clamp(b.size(), lim);
                if(take == 0 || n == dest.size())
                    return { {}, 0 };
                lim -= take;
                dest[n++] = { b.data(), take };
                return { {}, take };
            },
            true);
            if(n != 0)
                co_return { {}, dest.first(n) };
            if(ec != need_more_input)
            {
                if(ec == capy::error::eof)
                    consume(0); // chunk trailer
                co_return { ec, {} };
            }
            if(auto [fec] = co_await refill(); fec)
                co_return { fec, {} };
        }
    }
    case payload::size:
    {
        auto const rem = payload_rem();
        auto const lim = raw_limit_rem();
        if(rem == 0)
            co_return { capy::error::eof, {} };
        if(lim == 0)
            co_return { body_too_large, {} };
        for(;;)
        {
            if(!in_.empty())
                co_return { {}, collect(
                    dest, in_.data(), clamp(rem, lim)) };
            if(auto [fec] = co_await refill(); fec)
                co_return { fec, {} };
        }
    }
    case payload::to_eof:
    {
        auto const lim = raw_limit_rem();
        if(lim == 0)
            co_return { body_too_large, {} };
        for(;;)
        {
            if(!in_.empty())
                co_return { {}, collect(dest, in_.data(), lim) };
            if(eof_)
                co_return { capy::error::eof, {} };
            if(auto [fec] = co_await refill(); fec)
                co_return { fec, {} };
        }
    }
    }
}

void
parser::
consume(std::size_t n) noexcept
{
    if(dec_)
        return out_.consume(n);

    switch(payload_)
    {
    case payload::chunked:
        walk_chunks(
        [&](capy::const_buffer b, bool)
            -> capy::io_result<std::size_t>
        {
            auto const take = clamp(b.size(), n);
            n -= take;
            return { {}, take };
        });
        return;
    default:
        in_.consume(n);
        transferred_ += n;
        return;
    }
}

} // namespace detail
} // namespace burl
} // namespace boost
