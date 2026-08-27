//
// Copyright (c) 2026 Mohammad Nejati
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/cppalliance/burl
//

#include "decoder.hpp"

#include <boost/capy/error.hpp>
#include <boost/capy/ex/system_context.hpp>
#include <boost/http/brotli/decode.hpp>
#include <boost/http/zlib/error.hpp>
#include <boost/http/zlib/flush.hpp>
#include <boost/http/zlib/inflate.hpp>
#include <boost/http/zlib/stream.hpp>
#include <boost/http/zstd/decompress.hpp>
#include <boost/http/zstd/types.hpp>

#include <cstdint>
#include <limits>
#include <new>
#include <system_error>

namespace boost
{
namespace burl
{
namespace detail
{

namespace
{

class zlib_decoder final
    : public decoder
{
    http::zlib::inflate_service& svc_;
    http::zlib::stream strm_ = {};

public:
    // window_bits: 15 for zlib/deflate, 15 + 16 for gzip.
    zlib_decoder(
        http::zlib::inflate_service& svc,
        int window_bits)
        : svc_(svc)
    {
        if(svc_.init2(strm_, window_bits) !=
            static_cast<int>(http::zlib::error::ok))
            throw std::bad_alloc();
    }

    ~zlib_decoder() override
    {
        svc_.inflate_end(strm_);
    }

    result
    process(
        capy::mutable_buffer out,
        capy::const_buffer in,
        bool more) override
    {
        strm_.next_in = static_cast<unsigned char*>(
            const_cast<void*>(in.data()));
        strm_.avail_in = saturate(in.size());
        strm_.next_out =
            static_cast<unsigned char*>(out.data());
        strm_.avail_out = saturate(out.size());

        auto const rs = static_cast<http::zlib::error>(
            svc_.inflate(
                strm_,
                more ? http::zlib::no_flush
                     : http::zlib::finish));

        auto const ec = [&]() -> std::error_code
        {
            if(rs == http::zlib::error::stream_end)
                return capy::error::eof;
            if(rs != http::zlib::error::ok &&
                rs != http::zlib::error::buf_err)
                return rs;
            return {};
        }();

        return {
            .consumed = saturate(in.size()) - strm_.avail_in,
            .produced = saturate(out.size()) - strm_.avail_out,
            .ec       = ec };
    }

    static
    unsigned
    saturate(std::size_t n) noexcept
    {
        constexpr auto max =
            (std::numeric_limits<unsigned>::max)();
        if(n >= max)
            return max;
        return static_cast<unsigned>(n);
    }
};

class brotli_decoder final
    : public decoder
{
    http::brotli::decode_service& svc_;
    http::brotli::decoder_state* state_;

public:
    explicit
    brotli_decoder(http::brotli::decode_service& svc)
        : svc_(svc)
        , state_(svc.create_instance(
              nullptr, nullptr, nullptr))
    {
        if(!state_)
            throw std::bad_alloc();
    }

    ~brotli_decoder() override
    {
        svc_.destroy_instance(state_);
    }

    result
    process(
        capy::mutable_buffer out,
        capy::const_buffer in,
        bool) override
    {
        auto* next_in = static_cast<std::uint8_t const*>(in.data());
        auto available_in = in.size();
        auto* next_out = static_cast<std::uint8_t*>(out.data());
        auto available_out = out.size();

        auto const rs = svc_.decompress_stream(
            state_,
            &available_in,
            &next_in,
            &available_out,
            &next_out,
            nullptr);

        auto const ec = [&]() -> std::error_code
        {
            if(svc_.is_finished(state_))
                return capy::error::eof;
            if(rs == http::brotli::decoder_result::error)
                return svc_.get_error_code(state_);
            return {};
        }();

        return {
            .consumed = in.size() - available_in,
            .produced = out.size() - available_out,
            .ec       = ec };
    }
};

class zstd_decoder final
    : public decoder
{
    http::zstd::decompress_service& svc_;
    http::zstd::dctx* ctx_;
    // A payload is a sequence of frames (RFC 8878
    // Section 3.1.1); it ends at a frame boundary.
    bool at_boundary_ = true;

public:
    explicit
    zstd_decoder(http::zstd::decompress_service& svc)
        : svc_(svc)
        , ctx_(svc.create_dctx())
    {
        if(!ctx_)
            throw std::bad_alloc();
    }

    ~zstd_decoder() override
    {
        svc_.free_dctx(ctx_);
    }

    result
    process(
        capy::mutable_buffer out,
        capy::const_buffer in,
        bool more) override
    {
        http::zstd::in_buffer in_buf{ in.data(), in.size(), 0 };
        http::zstd::out_buffer out_buf{ out.data(), out.size(), 0 };

        auto const rs =
            svc_.decompress_stream(ctx_, out_buf, in_buf);

        auto const ec = [&]() -> std::error_code
        {
            if(svc_.is_error(rs))
                return svc_.get_error_code(rs);
            // zero marks the end of a frame; decoding
            // resumes on the next one, skippable
            // frames included
            if(rs == 0)
                at_boundary_ = true;
            else if(in_buf.pos != 0)
                at_boundary_ = false;
            if(!more && in_buf.pos == in_buf.size && at_boundary_)
                return capy::error::eof;
            return {};
        }();

        return {
            .consumed = in_buf.pos,
            .produced = out_buf.pos,
            .ec       = ec };
    }
};

} // namespace

std::unique_ptr<decoder>
make_decoder(http::content_coding coding)
{
    auto const& ctx = capy::get_system_context();
    switch(coding)
    {
    case http::content_coding::deflate:
        if(auto* svc = ctx.find_service<
            http::zlib::inflate_service>())
            return std::make_unique<zlib_decoder>(*svc, 15);
        break;
    case http::content_coding::gzip:
        if(auto* svc = ctx.find_service<
            http::zlib::inflate_service>())
            return std::make_unique<zlib_decoder>(*svc, 15 + 16);
        break;
    case http::content_coding::br:
        if(auto* svc = ctx.find_service<
            http::brotli::decode_service>())
            return std::make_unique<brotli_decoder>(*svc);
        break;
    case http::content_coding::zstd:
        if(auto* svc = ctx.find_service<
            http::zstd::decompress_service>())
            return std::make_unique<zstd_decoder>(*svc);
        break;
    default:
        break;
    }
    return nullptr;
}

} // namespace detail
} // namespace burl
} // namespace boost
