//
// Copyright (c) 2026 Mohammad Nejati
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

#include <boost/burl/parser.hpp>

#include <boost/burl/error.hpp>

#include "detail/grammar.hpp"
#include "detail/util.hpp"

#include <boost/assert.hpp>
#include <boost/capy/buffers/buffer_copy.hpp>
#include <boost/capy/buffers/consuming_buffers.hpp>
#include <boost/capy/cond.hpp>
#include <boost/capy/error.hpp>
#include <boost/capy/io_result.hpp>
#include <boost/url/grammar/error.hpp>
#include <boost/url/grammar/hexdig_chars.hpp>

#include <cstring>
#include <limits>
#include <type_traits>

namespace boost
{
namespace burl
{

using detail::clamp;
using detail::parse_field;
using detail::parse_limited;
using detail::distance;

using http::condition::need_more_input;
using http::error::bad_payload;
using http::error::body_too_large;
using http::error::end_of_stream;
using http::error::in_place_overflow;
using http::error::incomplete;
using http::error::need_data;
using http::error::field_size_limit;

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
    auto const start = cs.size();
    while(!cs.empty())
    {
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
    return need_data;
}

std::error_code
skip_trailer(chained_sequence& cs) noexcept
{
    while(!cs.empty())
    {
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
    return need_data;
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

auto
prefix(auto buf, std::size_t n) noexcept
    -> decltype(buf)
{
    return { buf.data(), clamp(buf.size(), n) };
};

auto
first(auto const& bs) noexcept
    -> decltype(*begin(bs))
{
    for(auto b : bs)
        if(b.size() != 0)
            return b;
    return {};
}

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
    bool is_req)
    : body_limit_(cfg.body_limit)
{
    auto const h_cap = head_parser::bytes_needed(
        cfg.hdr_limits, cfg.in_buffer);
    buf_ = std::make_unique_for_overwrite<char[]>(
        h_cap + cfg.dec_buffer);
    hp_  = { is_req, buf_.get(), h_cap, cfg.hdr_limits };
    in_  = { buf_.get(), static_cast<std::size_t>(
        hp_.ceiling() - buf_.get()) };
    out_ = { buf_.get() + h_cap, cfg.dec_buffer };
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
    return in_.size() > rem_ + trailer_extent();
}

std::array<capy::const_buffer, 2>
parser::
buffered_data() const noexcept
{
    return in_.data();
}

std::error_code
parser::
need_more() const noexcept
{
    if(eof_)
        return incomplete;
    if(in_.full())
        return in_place_overflow;
    return need_data;
}

std::size_t
parser::
trailer_extent() const noexcept
{
    if(!fin_chunk_)
        return 0;
    chained_sequence cs(in_.data());
    cs.advance(clamp(rem_));
    auto const t0 = cs.size();
    BOOST_VERIFY(! skip_trailer(cs));
    return t0 - cs.size();
}

void
parser::
start(bool head)
{
    BOOST_ASSERT(!started_ || got_body_);

    in_.consume(
        clamp(rem_) + trailer_extent());
    hp_.reset(
        in_.linearize(buf_.get()));

    dec_        = nullptr;
    rem_        = 0;
    limit_rem_  = body_limit_;
    dec_err_    = {};
    payload_    = payload::none;
    head_       = head;
    started_    = true;
    got_header_ = false;
    got_body_   = false;
    mid_chunk_  = false;
    fin_chunk_  = false;
}

void
parser::
reset() noexcept
{
    hp_.reset(buf_.get());
    in_.reset(buf_.get());

    rem_        = 0;
    payload_    = payload::none;
    started_    = false;
    got_header_ = false;
    got_body_   = false;
    fin_chunk_  = false;
    eof_        = false;
}

std::array<capy::mutable_buffer, 2>
parser::
prepare() noexcept
{
    return in_.prepare();
}

void
parser::
commit(std::size_t n) noexcept
{
    in_.commit(n);
    if(payload_ == payload::size && rem_ <= in_.size())
        got_body_ = true;
}

void
parser::
commit_eof() noexcept
{
    eof_ = true;
    if(payload_ == payload::to_eof)
        got_body_ = true;
}

std::size_t
parser::
direct_capacity() const noexcept
{
    if(dec_ || eof_ || !in_.empty())
        return 0;

    switch(payload_)
    {
    case payload::size:
        if(rem_ > limit_rem_)
            return 0;
        return clamp(rem_);
    case payload::to_eof:
        return clamp(limit_rem_);
    default:
        return 0;
    }
}

void
parser::
commit_direct(std::size_t n) noexcept
{
    rem_ -= n;
    limit_rem_ -= n;
    if(payload_ == payload::size && rem_ == 0)
        got_body_ = true;
}

std::error_code
parser::
walk_chunks(chunk_fn f, bool dry)
{
    chained_sequence cs = in_.data();
    std::uint64_t size  = rem_;

    if(fin_chunk_)
    {
        // from flatten_chunks
        auto const b = in_.first(clamp(rem_));
        auto const [ec, n] = f(b, true);
        if(!dry)
        {
            in_.consume(n);
            rem_ -= n;
            if(!dec_)
                limit_rem_ -= n;
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
        auto const t0 = cs.size(); // trailer start
        if(auto ec = skip_trailer(cs); ec)
            return ec;
        got_body_ = true;
        if(!dry)
        {
            fin_chunk_ = true;
            in_.consume(in_.size() - t0);
        }
        return std::get<0>(f({}, true));
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
            rem_       = size;
            mid_chunk_ = true;
            if(!dec_)
                limit_rem_ -= n;
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

    std::size_t flat = clamp(rem_, in_.len);
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
            auto const t0 = cs.pos(); // trailer start
            if(auto ec = skip_trailer(cs); ec)
                return bail(ec);
            got_body_  = true;
            fin_chunk_ = true;
            keep = t0;
            return bail({});
        }

        if(size > in_.cap - flat)
            return bail(in_place_overflow);

        rem_       = flat + size;
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

void
parser::
parse_header(system::error_code& ec)
{
    BOOST_ASSERT(started_);

    ec = {};

    if(got_header_)
        return;

    for(;;)
    {
        hp_.parse(in_.size(), ec);
        if(ec == in_place_overflow && in_.ptr != buf_.get())
        {
            in_.slide(buf_.get());
            hp_.rebase(buf_.get());
            continue;
        }
        break;
    }
    if(ec)
    {
        if(ec != need_more_input)
            return;
        if(eof_)
        {
            if(in_.empty())
                ec = end_of_stream;
            else
                ec = incomplete;
            return;
        }
        ec = need_data;
        return;
    }

    auto const& h = hp_.message_head();
    got_header_   = true;
    payload_      = head_ ? payload::none : h.payload();

    auto const head_size = h.buffer().size();

    switch(payload_)
    {
    case payload::error:
        ec = bad_payload;
        return;
    case payload::none:
        got_body_ = true;
        break;
    case payload::size:
        rem_ = h.content_length().value_or(0);
        if(rem_ <= in_.size() - head_size)
            got_body_ = true;
        break;
    case payload::chunked:
        break;
    case payload::to_eof:
        rem_ = std::uint64_t(-1);
        if(eof_)
            got_body_ = true;
        break;
    }

    if(!got_body_)
    {
        in_.slide(buf_.get());
        hp_.rebase(buf_.get());
    }

    in_.shed(head_size);
}

void
parser::
set_decoder(decoder* dec) noexcept
{
    dec_ = dec;
}

void
parser::
set_body_limit(std::uint64_t n) noexcept
{
    auto const transferred = body_limit_ - limit_rem_;
    limit_rem_  = n > transferred ? n - transferred : 0;
    body_limit_ = n;
}

std::string_view
parser::
flatten_body(system::error_code& ec)
{
    parse_header(ec);
    if(ec)
        return {};

    if(dec_)
    {
        for(;;)
        {
            if(out_.full())
            {
                ec = in_place_overflow;
                break;
            }
            auto pb = out_.prepare();
            auto const n = decode_some(pb, ec);
            out_.commit(n);
            if(ec == capy::cond::eof)
            {
                ec = {};
                break;
            }
            if(ec)
                break;
        }
        return { out_.linearize(out_.ptr), out_.len };
    }

    switch(payload_)
    {
    case payload::chunked:
    {
        in_.linearize(in_.ptr);
        for(;;)
        {
            if(rem_ > limit_rem_)
            {
                ec = body_too_large;
                break;
            }
            if(fin_chunk_)
                break;
            if(auto fec = flatten_chunks(); fec)
            {
                if(fec != need_more_input)
                    ec = fec;
                else
                    ec = need_more();
                break;
            }
        }
        return { in_.ptr, clamp(rem_, in_.len) };
    }
    case payload::size:
    {
        if(rem_ > limit_rem_)
            ec = body_too_large;
        else if(!got_body_)
            ec = need_more();
        return { in_.linearize(in_.ptr), clamp(rem_, in_.len) };
    }
    case payload::to_eof:
    {
        if(in_.size() > limit_rem_)
            ec = body_too_large;
        else if(!got_body_)
            ec = need_more();
        return { in_.linearize(in_.ptr), in_.len };
    }
    default:
        return {};
    }
}

burl::response_head_base const&
parser::
get_response() const
{
    return hp_.response_head();
}

burl::request_head_base const&
parser::
get_request() const
{
    return hp_.request_head();
}

std::size_t
parser::
decode_some(
    std::span<capy::mutable_buffer const> buffers,
    system::error_code& ec)
{
    if(capy::buffer_empty(buffers))
        return 0;

    auto outbufs = capy::consuming_buffers(buffers);
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
            auto const out = first(outbufs.data());
            if(out.size() == 0)
                return { std::error_code(), cons };
            auto const lim = clamp(limit_rem_);
            auto const r = dec_->process(
                prefix(out, lim), in, !last);
            in += r.consumed;
            cons += r.consumed;
            prod += r.produced;
            limit_rem_ -= r.produced;
            outbufs.consume(r.produced);
            if(r.ec)
            {
                dec_err_ = r.ec;
                return { std::error_code(), cons };
            }
            if(r.produced == 0 && r.consumed == 0)
            {
                if(lim == 0)
                    return { body_too_large, cons };
                dec_err_ = bad_payload;
                return { std::error_code(), cons };
            }
            if(in.size() == 0)
                return { std::error_code(), cons };
        }
    };

    switch(payload_)
    {
    case payload::chunked:
    {
        auto const wec = walk_chunks(decode);
        if(prod != 0)
            return prod;
        if(wec != need_more_input)
            ec = wec;
        else
            ec = need_more();
        return 0;
    }
    case payload::size:
    case payload::to_eof:
    {
        for(;;)
        {
            auto const in = in_.first(clamp(rem_));
            if(in.size() == 0 && !got_body_)
            {
                ec = need_more();
                return 0;
            }
            auto [dec_ec, cons] = decode(
                in, got_body_ && in.size() == clamp(rem_, in_.size()));
            in_.consume(cons);
            rem_ -= cons;
            if(prod != 0)
                return prod;
            if(dec_ec)
            {
                ec = dec_ec;
                return 0;
            }
        }
    }
    default:
    {
        ec = capy::error::eof;
        return 0;
    }
    }
}

std::size_t
parser::
read_some(
    std::span<capy::mutable_buffer const> buffers,
    system::error_code& ec)
{
    parse_header(ec);
    if(ec)
        return 0;

    if(dec_)
    {
        if(!out_.empty())
        {
            auto const n = capy::buffer_copy(
                buffers, out_.data());
            out_.consume(n);
            return n;
        }
        return decode_some(buffers, ec);
    }

    auto copy = [&](std::size_t at_most)
    {
        auto const n = capy::buffer_copy(
            buffers, in_.data(), at_most);
        in_.consume(n);
        rem_ -= n;
        limit_rem_ -= n;
        return n;
    };

    switch(payload_)
    {
    case payload::chunked:
    {
        std::size_t read = 0;
        std::size_t lim = clamp(limit_rem_);
        auto outbufs = capy::consuming_buffers(buffers);
        auto const wec = walk_chunks(
        [&](capy::const_buffer b, bool)
            -> capy::io_result<std::size_t>
        {
            auto const take = clamp(b.size(), lim);
            lim -= take;
            auto const n = capy::buffer_copy(
                outbufs.data(), b, take);
            read += n;
            outbufs.consume(n);
            if(take < b.size())
                return { body_too_large, n };
            return { std::error_code(), n };
        });
        if(read != 0)
            return read;
        if(wec == need_more_input)
        {
            ec = need_more();
            return 0;
        }
        if(wec)
        {
            ec = wec;
            return 0;
        }
        BOOST_ASSERT(got_body_);
        ec = capy::error::eof;
        return 0;
    }
    case payload::size:
    {
        if(rem_ != 0)
        {
            if(rem_ > limit_rem_)
            {
                ec = body_too_large;
                return 0;
            }
            if(!in_.empty())
                return copy(clamp(rem_));
        }
        if(got_body_)
        {
            ec = capy::error::eof;
            return 0;
        }
        ec = need_more();
        return 0;
    }
    case payload::to_eof:
    {
        if(!in_.empty())
        {
            if(limit_rem_ == 0)
            {
                ec = body_too_large;
                return 0;
            }
            return copy(clamp(limit_rem_));
        }
        if(got_body_)
        {
            ec = capy::error::eof;
            return 0;
        }
        ec = need_more();
        return 0;
    }
    default:
    {
        ec = capy::error::eof;
        return 0;
    }
    }
}

std::span<capy::const_buffer>
parser::
pull(
    std::span<capy::const_buffer> dest,
    system::error_code& ec)
{
    parse_header(ec);
    if(ec)
        return {};

    if(dec_)
    {
        if(!out_.empty())
            return collect(dest, out_.data());
        auto pb = out_.prepare();
        auto const n = decode_some(pb, ec);
        out_.commit(n);
        if(ec && n == 0)
            return {};
        ec = {};
        return collect(dest, out_.data());
    }

    switch(payload_)
    {
    case payload::chunked:
    {
        std::size_t n = 0;
        std::size_t lim = clamp(limit_rem_);
        auto const wec = walk_chunks(
        [&](capy::const_buffer b, bool)
            -> capy::io_result<std::size_t>
        {
            if(b.size() == 0)
                return { capy::error::eof, 0 };
            if(n == dest.size())
                return { std::error_code(), 0 };
            if(lim == 0)
                return { body_too_large, 0 };
            auto const take = clamp(b.size(), lim);
            lim -= take;
            dest[n++] = { b.data(), take };
            return { std::error_code(), take };
        },
        true);
        if(n != 0)
            return dest.first(n);
        if(wec != need_more_input)
        {
            if(wec == capy::error::eof)
            {
                // finish the framing, retain the trailer
                consume(0);
            }
            ec = wec;
            return {};
        }
        ec = need_more();
        return {};
    }
    case payload::size:
    {
        if(rem_ != 0)
        {
            if(rem_ > limit_rem_)
            {
                ec = body_too_large;
                return {};
            }
            if(!in_.empty())
                return collect(dest, in_.data(), clamp(rem_));
        }
        if(got_body_)
        {
            ec = capy::error::eof;
            return {};
        }
        ec = need_more();
        return {};
    }
    case payload::to_eof:
    {
        if(!in_.empty())
        {
            if(limit_rem_ == 0)
            {
                ec = body_too_large;
                return {};
            }
            return collect(dest, in_.data(), clamp(limit_rem_));
        }
        if(got_body_)
        {
            ec = capy::error::eof;
            return {};
        }
        ec = need_more();
        return {};
    }
    default:
    {
        ec = capy::error::eof;
        return {};
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
            return { std::error_code(), take };
        });
        return;
    default:
        in_.consume(n);
        rem_ -= n;
        limit_rem_ -= n;
        return;
    }
}

void
parser::
parse_trailer(
    fields_base& f,
    system::error_code& ec)
{
    ec = {};

    if(payload_ != payload::chunked)
        return;

    if(!fin_chunk_)
    {
        ec = incomplete;
        return;
    }

    char const* it  = in_.ptr + in_.pos + clamp(rem_);
    char const* end = in_.ptr + clamp(in_.pos + in_.len, in_.cap);

    while(it != end && *it != '\r')
    {
        auto const it0 = it;
        std::string_view name, value;
        parse_limited(
            [&name, &value](auto& it, auto end, auto& ec)
            {
                parse_field(it, end, name, value, ec);
            },
            it,
            end,
            hp_.limits().max_field + 1u, // 1u for obs lookahead,
            field_size_limit,
            ec);
        if(ec)
        {
            if(ec == need_data)
            {
                BOOST_ASSERT(in_.wrapped());
                auto const off = distance(it0, in_.ptr + in_.pos);
                in_.linearize(in_.ptr);
                it  = in_.ptr + off;
                end = in_.ptr + in_.len;
                ec  = {};
                continue;
            }
            return;
        }
        f.append(name, value);
    }
}

} // namespace burl
} // namespace boost
