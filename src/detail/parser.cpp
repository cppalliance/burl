//
// Copyright (c) 2026 Mohammad Nejati
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

#include "parser.hpp"

#include <boost/assert.hpp>
#include <boost/capy/error.hpp>
#include <boost/capy/buffers/make_buffer.hpp>
#include <boost/capy/buffers/front.hpp>
#include <boost/url/grammar/error.hpp>
#include <boost/url/grammar/hexdig_chars.hpp>

#include <new>
#include <utility>

namespace boost
{
namespace burl
{
namespace detail
{

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
    is_empty() const noexcept
    {
        return pos_ == end_;
    }

    char
    value() const noexcept
    {
        return *pos_;
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

std::span<capy::const_buffer>
collect(
    std::span<capy::const_buffer> dest,
    std::array<capy::const_buffer, 2> const& src) noexcept
{
    std::size_t n = 0;
    for(auto const& b : src)
        if(b.size() != 0 && n != dest.size())
            dest[n++] = b;
    return dest.first(n);
}

} // namespace

parser::
parser(
    config const& cfg,
    http::detail::kind kind,
    capy::any_read_stream* stream)
    : hdr_limits_(cfg.hdr_limits)
    , stream_(stream)
{
    auto* const p = static_cast<char*>(::operator new(
        sizeof(http::static_response) + cfg.in_buffer + cfg.dec_buffer));
    in_  = { p + sizeof(http::static_response), cfg.in_buffer };
    out_ = { in_.ptr + cfg.in_buffer, cfg.dec_buffer };
    if(kind == http::detail::kind::request)
        h_.reset(reinterpret_cast<http::detail::header*>(
            ::new(static_cast<void*>(p))
                http::static_request(in_.ptr, in_.cap)));
    else
        h_.reset(reinterpret_cast<http::detail::header*>(
            ::new(static_cast<void*>(p))
                http::static_response(in_.ptr, in_.cap)));
}

bool
parser::
got_header() const noexcept
{
    return got_header_;
}

bool
parser::
is_complete() const noexcept
{
    return state_ == state::complete;
}

void
parser::
start(bool head)
{
    // TODO
    BOOST_ASSERT(state_ == state::start);

    *h_ = http::detail::header{ http::detail::empty{ h_->kind } };
    h_->buf  = in_.ptr;
    h_->cbuf = in_.ptr;
    h_->cap  = in_.cap;

    head_ = head;

    state_ = state::header;
}

void
parser::
reset(capy::any_read_stream* stream) noexcept
{
    auto* const in_ptr =
        reinterpret_cast<char*>(h_.get()) + sizeof(http::static_response);
    in_  = { in_ptr, static_cast<std::size_t>(out_.ptr - in_ptr) };
    out_ = { out_.ptr, out_.cap };

    stream_     = stream;
    dec_        = nullptr;
    chunk_rem_  = 0;
    total_body_ = 0;
    state_      = state::start;
    head_       = false;
    got_header_ = false;
    mid_chunk_  = false;
    eof_        = false;
}

capy::io_task<>
parser::fill_in()
{
    if(eof_)
        co_return { http::error::incomplete };
    auto [ec, n] = co_await stream_->read_some(in_.prepare());
    in_.commit(n);
    if(ec == capy::cond::eof)
    {
        eof_ = true;
        ec.clear();
    }
    co_return ec;
}

std::error_code
parser::
iterate_chunks(
    compat::function_ref<capy::io_result<std::size_t>(
        capy::const_buffer, bool)> f,
    bool dry)
{
    using error = http::error;
    
    chained_sequence cs = in_.data();
    std::uint64_t len   = chunk_rem_;

    auto skip_to_eol = [&]() -> std::error_code
    {
        while(!cs.is_empty())
        {
            if(cs.value() == '\r')
            {
                if(!cs.next())
                    break;
                if(cs.value() != '\n')
                    return error::bad_payload;
                cs.next();
                return {};
            }
            cs.next();
        }
        return error::need_data;
    };

    auto commit = [&]() mutable
    {
        if(dry)
            return;
        in_.consume(in_.size() - cs.size());
        mid_chunk_ = true;
        chunk_rem_ = len;
    };

    if(len != 0 || mid_chunk_)
        goto invoke;

loop:
    // chunk header
    for(auto hdr_start = cs.size();;)
    {
        if(cs.is_empty())
            return error::need_data;
        auto n = urls::grammar::hexdig_value(cs.value());
        if(n < 0)
        {
            if(hdr_start == cs.size())
                return error::bad_payload;
            break;
        }
        // at least 4 significant bits are free
        if(len > (std::numeric_limits<std::uint64_t>::max)() >> 4)
            return error::bad_payload;
        len = (len << 4) | static_cast<std::uint64_t>(n);
        cs.next();
    }

    // skip chunk exts
    if(auto ec = skip_to_eol(); ec)
        return ec;

    // final chunk
    if(len == 0)
    {
        // skip trailer headers
        for(;;)
        {
            if(cs.is_empty())
                return error::need_data;
            if(cs.value() == '\r')
            {
                if(!cs.next())
                    return error::need_data;
                if(cs.value() != '\n')
                    return error::bad_payload;
                cs.next();
                break;
            }
            // skip to the end of the field
            if(auto ec = skip_to_eol(); ec)
                return ec;
        }
        auto const [ec, n] = f({}, true);
        return ec;
    }

invoke:
    for(const auto& b : cs.prefix(len))
    {
        if(b.size() == 0)
            break;
        auto const [ec, n] = f(b, false);
        cs.advance(n);
        len -= n;
        if(ec || n < b.size())
        {
            commit();
            return ec;
        }
    }

    commit();

    // CRLF
    if(cs.size() < 2)
        return error::need_data;
    if(cs.value() != '\r' || *cs.next() != '\n')
        return error::bad_payload;
    cs.next();

    goto loop;
}

capy::io_task<>
parser::
read_header()
{
    BOOST_ASSERT(state_ > state::start);

    if(got_header_)
        co_return {};

    for(;;)
    {
        if(auto [ec] = co_await fill_in(); ec)
            co_return ec;
        system::error_code ec;
        h_->parse(in_.size(), hdr_limits_, ec);
        if(ec)
        {
            if(ec == http::condition::need_more_input)
            {
                if(!eof_)
                    continue;
                // TODO
                co_return { http::error::incomplete };
            }
            // TODO
            co_return { ec };
        }

        in_.ptr += h_->size;
        in_.len -= h_->size;
        in_.cap -= h_->size;
        got_header_ = true;

        if(h_->md.payload == http::payload::none || head_)
            state_ = state::complete;
        else
            state_ = state::body;

        co_return {};
    }
}

void
parser::
set_decoder(decoder* dec) noexcept
{
    dec_ = dec;
}

http::static_response const&
parser::
get_response() const
{
    if(!got_header_)
        http::detail::throw_logic_error();

    return reinterpret_cast<http::static_response const&>(*h_);
}

http::static_request const&
parser::
get_request() const
{
    if(!got_header_)
        http::detail::throw_logic_error();

    return reinterpret_cast<http::static_request const&>(*h_);
}

capy::io_task<std::size_t>
parser::
decode_some(
    std::span<capy::mutable_buffer const> buffers)
{
    std::size_t read = 0;

    if(capy::buffer_empty(buffers)) // TOOD: necessary?
        co_return { {}, 0 };

    auto slice = capy::buffer_slice(buffers);
    if(h_->md.transfer_encoding.is_chunked)
    {
        do
        {  
            auto ec = iterate_chunks(
            [&](capy::const_buffer b, bool final)
                -> capy::io_result<std::size_t>
            {
                std::size_t consumed = 0;
                do
                {
                    auto r = dec_->process(
                        capy::front(slice.data()), b, final);
                    read += r.produced;
                    slice.remove_prefix(r.produced);
                    consumed += r.consumed;
                    total_body_ += r.consumed;
                    b += r.consumed;
                    if(r.ec)
                        return { r.ec, consumed };
                } while(b.size() &&
                    !capy::buffer_empty(slice.data()));
                return { {}, consumed };
            });
            if(ec)
            {
                if(ec == capy::cond::eof)
                {
                    state_ = state::complete;
                    break;
                }
                else if(ec == http::condition::need_more_input)
                {
                    if(read != 0)
                        break;
                    if(auto [ec] = co_await fill_in(); ec)
                        co_return { ec, read };
                }
                else
                {
                    co_return { ec, read };
                }
            }
        } while(read == 0);
    }
    else
    {
        do
        {
            if(in_.empty())
            {
                if(read != 0)
                    break;
                if(auto [ec] = co_await fill_in(); ec)
                    co_return { ec, read };
            }
            auto const last = (total_body_ == h_->md.payload_size); 
            auto r = dec_->process(
                capy::front(slice.data()), in_.data()[0], last);
            read += r.produced;
            slice.remove_prefix(r.produced);
            total_body_ += r.consumed;
            in_.consume(r.consumed);
            if(r.ec)
            {
                if(r.ec == capy::cond::eof)
                {
                    if(total_body_ != h_->md.payload_size)
                        co_return { http::error::bad_payload, read };
                    state_ = state::complete;
                }
                co_return { r.ec, read };
            }
        } while(read == 0);
    }

    if(state_ == state::complete)
        co_return { capy::error::eof, read };

    co_return { {}, read };
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
            if(state_ == state::complete && out_.empty())
                co_return { capy::error::eof, n };
            co_return { {}, n };
        }
        else
        {
            co_return co_await decode_some(buffers);
        }
    }
    else if(h_->md.transfer_encoding.is_chunked)
    {
        for(;;)
        {
            std::size_t read = 0;
            auto slice = capy::buffer_slice(buffers);
            auto ec = iterate_chunks(
            [&](capy::const_buffer b, bool final)
                -> capy::io_result<std::size_t>
            {
                auto n = capy::buffer_copy(slice.data(), b);
                read += n;
                total_body_ += n;
                slice.remove_prefix(n);
                if(final)
                {
                    state_ = state::complete;
                    return { capy::error::eof , n };
                }
                return { {} , n };
            });
            if(ec)
            {
                if(ec == http::condition::need_more_input)
                {
                    if(read != 0)
                        co_return { {}, read };
                    if(auto [ec] = co_await fill_in(); ec)
                        co_return { ec, read };
                }
                else
                {
                    co_return { ec, read };
                }
            }
            if(read != 0)
                co_return { {}, read };
        };
    }
    else
    {
        if(!in_.empty())
        {
            auto n = capy::buffer_copy(buffers, in_.data());
            in_.consume(n);
            total_body_ += n;
            if(h_->md.payload_size == total_body_)
            {
                state_ = state::complete;
                co_return { capy::error::eof, n };
            }
            co_return { {}, n };
        }
        else
        {
            auto rem = h_->md.payload_size - total_body_;
            auto slice = capy::buffer_slice(buffers, 0, rem);
            auto [ec, n] = co_await stream_->read_some(slice.data());
            total_body_ += n;
            if(h_->md.payload_size == total_body_)
            {
                state_ = state::complete;
                co_return { capy::error::eof, n };
            }
            if(ec)
            {
                if(ec != capy::cond::eof)
                {
                    // TODO
                    co_return { ec, {}};
                }
                eof_ = true;
            }
            co_return { {}, n };
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
        if(out_.empty())
        {
            if(state_ == state::complete)
                co_return { capy::error::eof, {} }; 
            auto [ec, n] = co_await decode_some(out_.prepare());
            out_.commit(n);
            if(ec)
            {
                if(ec != capy::cond::eof)
                    co_return { ec, {} };
            }
        }
        co_return { {}, collect(dest, out_.data()) };
    }

    if(state_ == state::complete)
        co_return { capy::error::eof, {} }; 

    if(h_->md.transfer_encoding.is_chunked)
    {
        std::size_t n = 0;
        do
        {
            auto ec = iterate_chunks(
            [&](capy::const_buffer b, bool final)
                -> capy::io_result<std::size_t>
            {
                if(b.size() != 0 && dest.size() != n)
                {
                    dest[n++] = b;
                    return { {} , b.size() };
                }
                if(final && n == 0)
                    return { capy::error::eof , 0 };
                return { {}, 0 };
            },
            true);
            if(ec)
            {
                if(ec == http::condition::need_more_input)
                {
                    if(n != 0)
                        break;
                    if(auto [ec] = co_await fill_in(); ec)
                        co_return { ec, dest.first(n) };
                }
                else
                {
                    co_return { ec, dest.first(n) };
                }
            }
        } while(n == 0);
        co_return { {}, dest.first(n) };
    }
    else
    {
        if(in_.empty())
        {
            if(state_ == state::complete)
                co_return { capy::error::eof, {} }; 
            if(auto [ec] = co_await fill_in(); ec)
                co_return { ec, {} };
        }
        co_return { {}, collect(dest, in_.data()) };
    }
}

void
parser::
consume(std::size_t n) noexcept
{
    if(dec_)
    {
        out_.consume(n);
    }
    else if(h_->md.transfer_encoding.is_chunked)
    {
        auto ec = iterate_chunks(
        [&](capy::const_buffer b, bool final)
            -> capy::io_result<std::size_t>
        {
            auto const k = n < b.size() ? n : b.size();
            n -= k;
            if(final)
                state_ = state::complete;
            return { {} , k };
        });
    }
    else
    {
        in_.consume(n);
        total_body_ +=n;
        if(h_->md.payload_size == total_body_)
            state_ = state::complete;
    }
}

} // namespace detail
} // namespace burl
} // namespace boost
