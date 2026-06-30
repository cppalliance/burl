//
// Copyright (c) 2026 Mohammad Nejati
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

#include "serializer.hpp"

#include <boost/burl/error.hpp>

#include <boost/capy/buffers/make_buffer.hpp>
#include <boost/assert.hpp>

namespace boost
{
namespace burl
{
namespace detail
{

serializer::serializer(
    capy::any_write_stream& stream,
    http::request_base& req,
    config cfg)
    : stream_(stream)
    , req_(req)
    , cfg_(cfg)
    , storage_(new unsigned char[cfg_.buffer_size + margin] + margin)
{
    BOOST_ASSERT(
        req_.chunked() || req_.payload() == http::payload::size);
}

serializer::~serializer()
{
    delete[](storage_ - margin);
}

capy::io_task<>
serializer::write_eof()
{
    return commit_eof(0);
}

std::span<capy::mutable_buffer>
serializer::prepare(std::span<capy::mutable_buffer> dest)
{
    if(dest.empty() || capacity() == 0)
        return dest.first(0);
    dest[0] = writable();
    return dest.first(1);
}

capy::io_task<>
serializer::commit(std::size_t n)
{
    BOOST_ASSERT(n <= capacity());
    avail_ += n;
    if(capacity() >= cfg_.min_prepare)
        co_return {};
    auto [ec, _] = co_await drain({}, false);
    co_return { ec };
}

capy::io_task<>
serializer::commit_eof(std::size_t n)
{
    BOOST_ASSERT(n <= capacity());
    avail_ += n;
    decide_framing(0);
    auto [ec, _] = co_await drain({}, true);
    co_return { ec };
}

void
serializer::decide_framing(std::size_t remaining) noexcept
{
    if(!req_.chunked() || hdr_sent_)
        return;

    BOOST_ASSERT(total_body_ == 0);
    req_.erase(http::field::transfer_encoding);
    req_.set_content_length(avail_ + remaining);
}

capy::io_task<std::size_t>
serializer::drain(
    std::span<capy::const_buffer const> tail,
    bool eof)
{
    auto const tail_size = capy::buffer_size(tail);
    auto const chunked   = req_.chunked();

    BOOST_ASSERT(eof || avail_ + tail_size != 0);

    capy::const_buffer vec[capy::detail::max_iovec_ + 3];
    std::size_t n   = 0;
    std::size_t sum = 0;

    if(!hdr_sent_)
    {
        vec[n++] = capy::make_buffer(req_.buffer());
        sum += req_.buffer().size();
    }

    if(chunked)
    {
        auto const buf = chunk_frame(tail_size);
        vec[n++] = buf;
        sum += buf.size();
    }
    else
    {
        auto const declared =
            req_.payload() == http::payload::size
                ? req_.payload_size() : 0;
        auto const produced = total_body_ + avail_ + tail_size;

        if(produced > declared || (eof && produced != declared))
            co_return { error::body_size_mismatch, 0 };

        if(avail_ != 0)
        {
            vec[n++] = { storage_, avail_ };
            sum += avail_;
        }
    }

    auto const owned = sum;

    sum += tail_size;
    for(auto const& b : tail)
        vec[n++] = b;

    if(chunked && eof)
    {
        std::size_t const term = avail_ || tail_size ? 7 : 2;
        vec[n++] = { "\r\n0\r\n\r\n", term };
        sum += term;
    }

    auto const need = chunked || eof ? sum : owned + bool(tail_size); 
    auto [ec, written] = co_await write_at_least({ vec, n }, need);
    if(ec)
        co_return { ec, 0 };

    auto const consumed = (std::min)(written - owned, tail_size);
    total_body_ += avail_ + consumed;
    avail_ = 0;
    hdr_sent_ = true;
    done_ = eof;
    co_return { {}, consumed };
}

capy::io_task<std::size_t>
serializer::write_at_least(
    std::span<capy::const_buffer> buffers,
    std::size_t bytes)
{
    BOOST_ASSERT(bytes <= capy::buffer_size(buffers));
    auto slice = capy::buffer_slice(buffers);
    std::size_t written = 0;
    while(written < bytes)
    {
        auto [ec, n] = co_await stream_.write_some(slice.data());
        written += n;
        if(ec && written < bytes)
            co_return { ec, written };
        slice.remove_prefix(n);
    }
    co_return { {}, written };
}

capy::const_buffer
serializer::chunk_frame(std::size_t tail_size) noexcept
{
    static constexpr char hex[] = "0123456789ABCDEF";

    auto size = avail_ + tail_size;
    auto* p = storage_;

    *--p = '\n';
    *--p = '\r';

    do
    {
        *--p = hex[size & 0xF];
        size >>= 4;
    } while(size != 0);

    // previous chunk's CRLF
    if(total_body_ != 0)
    {
        *--p = '\n';
        *--p = '\r';
    }

    return { p, static_cast<std::size_t>(storage_ - p) + avail_ };
}

} // namespace detail
} // namespace burl
} // namespace boost
